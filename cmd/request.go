package cmd

import (
	"log"

	"github.com/serverwentdown/wireguard-negotiator/lib"
	"github.com/urfave/cli/v2"
)

var CmdRequest = &cli.Command{
	Name:   "request",
	Usage:  "Set up local WireGuard",
	Action: runRequest,
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "interface",
			Aliases: []string{"i"},
			Value:   "wg0",
			Usage:   "Name for new WireGuard interface",
		},
		&cli.StringFlag{
			Name:        "config",
			Aliases:     []string{"c"},
			Value:       "",
			DefaultText: "/etc/wireguard/<interface>.conf",
			Usage:       "Path to the WireGuard configuration file",
		},
		&cli.StringFlag{
			Name:  "type",
			Value: "none",
			Usage: "Select network interface backend. Currently only none and networkd are implemented",
		},
	},
}

func runRequest(ctx *cli.Context) error {
	inter := ctx.String("interface")
	config := ctx.String("config")
	if !ctx.IsSet("config") {
		config = "/etc/wireguard/" + inter + ".conf"
	}
	netBackend := ctx.String("type")

	client := lib.NewClient(ctx.String("server"), ctx.Bool("insecure"))

	log.Println(inter)
	log.Println(config)
	log.Println(netBackend)
	log.Println(client)

	return nil
}
