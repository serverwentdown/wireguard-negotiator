package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/serverwentdown/wireguard-negotiator/lib"
	"github.com/urfave/cli/v2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"gopkg.in/ini.v1"
)

var ErrNoAddressesFound = fmt.Errorf("No address found on the interface")

var CmdServer = &cli.Command{
	Name:  "server",
	Usage: "Start the wireguard-negotiator server",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "interface",
			Aliases: []string{"i"},
			Value:   "wg0",
			Usage:   "An existing WireGuard interface to manage",
		},
		&cli.StringFlag{
			Name:        "config",
			Aliases:     []string{"c"},
			Value:       "",
			DefaultText: "/etc/wireguard/<interface>.conf",
			Usage:       "Path to the existing WireGuard configuration file. WARNING: wireguard-negotiator will remove any comments in the file",
		},
		&cli.StringFlag{
			Name:     "endpoint",
			Aliases:  []string{"e"},
			Value:    "",
			Required: true,
			Usage:    "Set the endpoint address",
		},
		&cli.StringFlag{
			Name:    "listen",
			Aliases: []string{"l"},
			Value:   ":8080",
			Usage:   "Listen on this address",
		},
		&cli.BoolFlag{
			Name:    "interactive",
			Aliases: []string{"I"},
			Usage:   "Enable interactive prompt before accepting new peers",
		},
		&cli.BoolFlag{
			Name:    "bin",
			Aliases: []string{"B"},
			Usage:   "Serve the current wireguard-negotiator binary file upon GET request to /",
		},
	},
	Action: runServer,
}

type request struct {
	publicKey string
	ip        net.IP
}

func runServer(ctx *cli.Context) error {
	inter := ctx.String("interface")
	config := ctx.String("config")
	if !ctx.IsSet("config") {
		config = "/etc/wireguard/" + inter + ".conf"
	}
	endpoint := ctx.String("endpoint")
	listen := ctx.String("listen")
	interactive := ctx.Bool("interactive")

	// Obtain the network interface
	interf, err := net.InterfaceByName(inter)
	if err != nil {
		return err
	}

	// Obtain the server's public key
	serverPublicKey, err := configReadInterfacePublicKey(config)
	if err != nil {
		return err
	}

	// TODO: Define this allocation method
	// TODO: Include allocation behaviour in README
	terribleCounterThatShouldNotExist := 1
	interfAddrs, err := interf.Addrs()
	if err != nil {
		return err
	}

	// Obtain interface address for use in allocation
	var interfIPNet *net.IPNet
	if len(interfAddrs) < 1 {
		return ErrNoAddressesFound
	}
	_, interfIPNet, err = net.ParseCIDR(interfAddrs[0].String())

	// Set up interactive stuff
	lineReader := bufio.NewReader(os.Stdin)
	if !interactive {
		lineReader = nil
	}

	addQueue := make(chan request, 0)
	go adder(addQueue, inter, config)

	gateQueue := make(chan request, 0)
	go gater(gateQueue, addQueue, lineReader)

	// TODO: Rate limiting

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "GET":
			bin, err := os.Executable()
			if err != nil {
				w.WriteHeader(500)
				return
			}
			file, err := os.Open(bin)
			if err != nil {
				w.WriteHeader(500)
				return
			}
			_, err = io.Copy(w, file)
			if err != nil {
				log.Println("WARNING: Write binary executable to response failed")
				return
			}
		default:
			w.WriteHeader(405)
		}
	})
	http.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "POST":
			publicKey := r.PostFormValue("PublicKey")
			// TODO: Ensure public key is new
			// TODO: Validate public key
			if len(publicKey) == 0 {
				w.WriteHeader(400)
				return
			}

			// Assign an IP address
			terribleCounterThatShouldNotExist += 1
			ip := incrementIP(interfIPNet.IP, terribleCounterThatShouldNotExist)
			if !interfIPNet.Contains(ip) {
				log.Println("WARNING: Ran out of addresses to allocate")
				w.WriteHeader(500)
				return
			}

			// Enqueue request into the gate
			req := request{
				ip:        ip,
				publicKey: publicKey,
			}

			// Wait for flush of configuration
			gateQueue <- req

			// Produce configuration to client
			ipNet := &net.IPNet{
				IP:   ip,
				Mask: interfIPNet.Mask,
			}
			netIPNet := &net.IPNet{
				IP:   interfIPNet.IP.Mask(interfIPNet.Mask),
				Mask: interfIPNet.Mask,
			}
			resp := lib.PeerConfigResponse{
				[]string{ipNet.String()},
				[]string{netIPNet.String()},
				serverPublicKey,
				endpoint,
				25,
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(resp)
		default:
			w.WriteHeader(405)
		}
	})

	server := &http.Server{
		Addr:    listen,
		Handler: http.DefaultServeMux,
	}

	// Shutdown notifier
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
		<-sigint
		close(gateQueue)
		close(addQueue)
		if err := server.Shutdown(context.Background()); err != nil {
			log.Printf("Server shutdown error: %v\n", err)
		}
	}()

	log.Printf("Server listening on %v\n", listen)

	return server.ListenAndServe()
}

func adder(queue chan request, inter string, config string) {
	// Write requests to config and add peer
	for {
		select {
		case req, ok := <-queue:
			if !ok {
				break
			}
			err := configAddPeer(config, req)
			if err != nil {
				log.Println(err)
				continue
			}
			err = interAddPeer(inter, req, config)
			if err != nil {
				log.Println(err)
				continue
			}
		}
	}
}

func gater(queue chan request, result chan request, lineReader *bufio.Reader) {
	// Receive requests and prompt the admin
	for {
		select {
		case req, ok := <-queue:
			if !ok {
				return
			}
			fmt.Println(req.ip.String(), req.publicKey)

			done := false
			allowed := false

			if lineReader == nil {
				done = true
				allowed = true
			}

			for !done {
				fmt.Print("Allow? (y/n) ")
				line, err := lineReader.ReadString('\n')
				if err != nil {
					log.Println(err)
					return
				}

				switch line[:len(line)-1] {
				case "y", "yes":
					done = true
					allowed = true
				case "n", "no":
					done = true
					allowed = false
				}
			}

			if allowed {
				result <- req
			}
		}
	}
}

func configAddPeer(config string, req request) error {
	// For every request, open the config file again and rewrite it. Acceptable
	// because this happens infrequently

	// Preferably in the future, treat the configuration as a database

	// For now, append to the config file
	cfg := ini.Empty()
	sec, _ := cfg.NewSection("Peer")
	publicKey := sec.Key("PublicKey")
	// TODO: Validation is needed
	publicKey.SetValue(req.publicKey)
	allowedIPs := sec.Key("AllowedIPs")
	allowedHost := ipToIPNetWithHostMask(req.ip)
	allowedIPs.SetValue((&allowedHost).String())

	f, err := os.OpenFile(config, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("opening %s failed: %w", config, err)
	}
	_, err = cfg.WriteTo(f)
	if err != nil {
		return fmt.Errorf("writing to %s failed: %w", config, err)
	}
	return nil
}

func configReadInterfacePublicKey(config string) (string, error) {
	cfg, err := ini.Load(config)
	if err != nil {
		return "", fmt.Errorf("read interface public key failed: %w", err)
	}

	b64PrivateKey := cfg.Section("Interface").Key("PrivateKey").String()
	wgPrivateKey, err := wgtypes.ParseKey(b64PrivateKey)
	if err != nil {
		return "", fmt.Errorf("read interface public key failed: %w", err)
	}
	wgPublicKey := wgPrivateKey.PublicKey()
	return wgPublicKey.String(), nil
}

func interAddPeer(inter string, req request, config string) error {
	// For every request, dynamically add the peer to the interface

	// For now, simply run one fixed command to reread from the config file
	cmd := exec.Command("wg", "setconf", inter, config)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("wq setconf failed: %w", err)
	}
	return nil
}

func ipToIPNetWithHostMask(ip net.IP) net.IPNet {
	if ip4 := ip.To4(); ip4 != nil {
		return net.IPNet{
			IP:   ip,
			Mask: net.CIDRMask(32, 32),
		}
	}
	return net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(128, 128),
	}
}

func incrementIP(ip net.IP, inc int) net.IP {
	result := make(net.IP, len(ip))
	copy(result, ip)

	for i := len(ip) - 1; i >= 0; i-- {
		remainder := inc % 256
		overflow := int(result[i])+remainder > 255

		result[i] += byte(remainder)
		if overflow {
			inc += 256
		}
		inc /= 256
	}
	return result
}
