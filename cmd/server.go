package cmd

import (
	"log"

	"github.com/urfave/cli/v2"
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

func runServer(ctx *cli.Context) error {
	inter := ctx.String("interface")
	config := ctx.String("config")
	if !ctx.IsSet("config") {
		config = "/etc/wireguard/" + inter + ".conf"
	}
	listen := ctx.String("listen")

	// TODO: Rate limiting

	http.HandleFunc("/pub", func(w http.ResponseWriter, r *http.Request) {
		// Produce the public key
	})

	http.HandleFunc("/request", func(w http.ResponseWriter, r *http.Request) {
		// Ensure public key is new
		// Assign an IP address
		// Enqueue request into the gate
		// Wait for flush of configuration
	})

	log.Println(inter)
	log.Println(config)
	log.Println(listen)

	return nil
}