package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

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
			Usage:       "Path to the existing WireGuard configuration file",
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

	addQueue := make(chan request, 1)
	go adder(addQueue, inter, config)

	gateQueue := make(chan request, 1)
	go gater(gateQueue, addQueue)

	// TODO: Rate limiting

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
			resp := struct {
				InterfaceIPs                []string
				AllowedIPs                  []string
				PublicKey                   string
				Endpoint                    string
				PersistentKeepaliveInterval int
			}{
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

func gater(queue chan request, result chan request) {
	// Receive requests and prompt the admin
	for {
		select {
		case req, ok := <-queue:
			if !ok {
				break
			}
			// For now, accept all
			log.Println(req.ip.String(), req.publicKey)
			result <- req
		}
	}
}

func configAddPeer(config string, req request) error {
	// For every request, we'll just open the config file again and rewrite it
	// We don't need to optimise this because it happens infrequently

	// Preferably in the future, we treat the configuration as a database

	// For now, we append to the config file
	cfg := ini.Empty()
	sec, _ := cfg.NewSection("Peer")
	publicKey := sec.Key("PublicKey")
	// TODO: Do we need validation?
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
	// For every request, we also need to dynamically add the peer to the interface

	// For now, we simply run one fixed command to reread from the config file
	cmd := exec.Command("wg", "setconf", inter, config)
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("wq setconf failed: %w", err)
	}
	return nil
}

// Helpers

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
