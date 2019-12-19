package cmd

import (
	"log"
	"net"
	"net/http"
	"os"

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
	listen := ctx.String("listen")

	addQueue := make(chan request)
	go adder(addQueue, inter, config)

	gateQueue := make(chan request)
	go gater(gateQueue, addQueue)

	// TODO: Rate limiting

	http.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
		// Produce the public key
	})

	http.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {
		// Ensure public key is new
		// Assign an IP address
		// Enqueue request into the gate
		// Wait for flush of configuration
		// Produce configuration to client
	})

	log.Println(inter)
	log.Println(config)
	log.Println(listen)

	return nil
}

func adder(queue chan request, inter string, config string) {
	// Write requests to config and add peer
	for req := range queue {
		configAddPeer(config, req)
		interAddPeer(inter, req)
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

func interAddPeer(inter string, req request) {

}
