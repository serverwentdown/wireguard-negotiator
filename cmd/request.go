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
			Name:        "none",
			Aliases:     []string{"c"},
			Value:       "",
			DefaultText: "/etc/wireguard/<interface>.conf",
			Usage:       "Path to save a WireGuard configuration file",
		},
		&cli.StringFlag{
			Name:        "networkd",
			Aliases:     []string{"n"},
			Value:       "",
			DefaultText: "/etc/systemd/network/<interface>.netdev",
			Usage:       "Path to save a networkd configuration file",
		},
		&cli.StringFlag{
			Name:    "type",
			Aliases: []string{"t"},
			Value:   "networkd",
			Usage:   "Select network interface backend. Currently only networkd is implemented",
		},
		&cli.StringFlag{
			Name:     "server",
			Aliases:  []string{"s"},
			Usage:    "wireguard-negotiator server URL",
			Required: true,
			EnvVars:  []string{"WGN_SERVER_URL"},
		},
		&cli.BoolFlag{
			Name:    "insecure",
			Usage:   "Disable TLS verification",
			EnvVars: []string{"WGN_SERVER_INSECURE"},
		},
	},
}

func runRequest(ctx *cli.Context) error {
	inter := ctx.String("interface")
	netBackend := ctx.String("type")
	noneConfig := ctx.String("none")
	if !ctx.IsSet("none") {
		noneConfig = "/etc/wireguard/" + inter + ".conf"
	}
	networkdConfig := ctx.String("networkd")
	if !ctx.IsSet("networkd") {
		networkdConfig = "/etc/systemd/network/" + inter + ".netdev"
	}

	client := lib.NewClient(ctx.String("server"), ctx.Bool("insecure"))

	log.Println(inter)
	log.Println(netBackend)
	log.Println(noneConfig)
	log.Println(networkdConfig)
	log.Println(client)

	return nil
}
