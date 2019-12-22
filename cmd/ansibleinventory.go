package cmd

import (
	"log"

	"github.com/urfave/cli/v2"
)

var CmdAnsibleInventory = &cli.Command{
	Name:  "ansible-inventory",
	Usage: "Dump WireGuard configuration as Ansible inventory",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "interface",
			Aliases: []string{"i"},
			Value:   "wg0",
			Usage:   "Read default configuration path for the interface",
		},
		&cli.StringFlag{
			Name:        "config",
			Aliases:     []string{"c"},
			Value:       "",
			DefaultText: "/etc/wireguard/<interface>.conf",
			Usage:       "Path to the existing WireGuard configuration file",
		},
	},
	Action: runAnsibleInventory,
}

func runAnsibleInventory(ctx *cli.Context) error {
	inter := ctx.String("interface")
	config := ctx.String("config")
	if !ctx.IsSet("config") {
		config = "/etc/wireguard/" + inter + ".conf"
	}

	log.Println(config)

	return nil
}
