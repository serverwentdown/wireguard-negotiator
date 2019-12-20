package cmd

import (
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"

	"github.com/urfave/cli/v2"
	"gopkg.in/ini.v1"
)

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
			Usage:       "Path to the WireGuard configuration file",
		},
		&cli.StringFlag{
			Name:    "endpoint",
			Aliases: []string{"e"},
			Value:   "",
			Usage:   "Set the endpoint address",
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
	interf, err := net.InterfaceByName(inter)
	if err != nil {
		log.Fatal(err)
	}
	config := ctx.String("config")
	if !ctx.IsSet("config") {
		config = "/etc/wireguard/" + inter + ".conf"
	}
	endpoint := ctx.String("endpoint")
	if !ctx.IsSet("endpoint") {
		log.Fatal("Please specify endpoint with -endpoint")
	}
	listen := ctx.String("listen")

	// Obtain the server's public key
	serverPublicKey := configReadInterfacePublicKey(config)

	terribleCounterThatShouldNotExist := 1
	interfAddrs, err := interf.Addrs()
	if err != nil {
		log.Fatal(err)
	}
	// TODO: Define this allocation method
	// TODO: Include allocation behaviour in README
	var interfIPNet *net.IPNet
	if len(interfAddrs) < 1 {
		log.Fatal("No address found on the interface")
	}
	_, interfIPNet, err = net.ParseCIDR(interfAddrs[0].String())

	addQueue := make(chan request)
	go adder(addQueue, inter, config)

	gateQueue := make(chan request)
	go gater(gateQueue, addQueue)

	// TODO: Rate limiting

	http.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {
		publicKey := r.PostFormValue("public_key")
		// TODO: Ensure public key is new
		// Assign an IP address
		terribleCounterThatShouldNotExist += 1
		ip := incrementIP(interfIPNet.IP, terribleCounterThatShouldNotExist)
		if !interfIPNet.Contains(ip) {
			log.Fatal("Ran out of IP addresses to allocate")
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
		resp := struct {
			interfaceIP    string `json:"interface_ip"`
			peerAllowedIPs string `json:"peer_allowed_ips"`
			peerPublicKey  string `json:"peer_public_key"`
			peerEndpoint   string `json:"peer_endpoint"`
		}{
			ipNet.String(),
			interfIPNet.IP.Mask(interfIPNet.Mask),
			"",
			"",
		}
	})

	http.ListenAndServe(listen, nil)

	return nil
}

func adder(queue chan request, inter string, config string) {
	// Write requests to config and add peer
	for req := range queue {
		configAddPeer(config, req)
		interAddPeer(inter, req, config)
	}
}

func gater(queue chan request, result chan request) {
	// Receive requests and prompt the admin
	for req := range queue {
		// For now, accept all
		log.Println(req)
		result <- req
	}
}

func configAddPeer(config string, req request) {
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
	allowedIPs.AddShadow((&allowedHost).String())

	f, err := os.OpenFile(config, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}
	_, err = cfg.WriteTo(f)
	if err != nil {
		log.Fatal(err)
	}
}

func configReadInterfacePublicKey(config string) string {
	cfg, err := ini.Load(config)
	if err != nil {
		log.Fatal("Failed to read interface public key")
	}

	return cfg.Section("Interface").Key("PrivateKey")
}

func interAddPeer(inter string, req request, config string) {
	// For every request, we also need to dynamically add the peer to the interface

	// For now, we simply run one fixed command to reread from the config file
	cmd := exec.Command("wg", "setconf", inter, config)
	err := cmd.Run()
	if err != nil {
		log.Println(err)
	}
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

func incrementIP(ip net.IP) net.IP {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
