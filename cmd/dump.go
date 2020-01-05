package cmd

import (
	"bytes"
	"fmt"
	"os"

	"github.com/serverwentdown/wireguard-negotiator/lib"
	"github.com/urfave/cli/v2"
)

var CmdDump = &cli.Command{
	Name:  "dump",
	Usage: "Dump WireGuard configuration as a list of IPs, useful for Ansible inventories. Dumps only the first address in allowedIP, taking into account the mask",
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
	Action: runDump,
}

func runDump(ctx *cli.Context) error {
	inter := ctx.String("interface")
	config := ctx.String("config")
	if !ctx.IsSet("config") {
		config = "/etc/wireguard/" + inter + ".conf"
	}

	// Open config
	file, err := os.Open(config)
	defer file.Close()
	if err != nil {
		return err
	}

	// Read configuration
	device, _, err := lib.ReadConfig(file)
	if err != nil {
		return err
	}

	empty4 := []byte{0, 0, 0, 0}
	empty6 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	// Dump hosts by first allowedIPs
	for _, peer := range device.Peers {
		fmt.Printf("# %v\n", peer.PublicKey)

		dumped := false
		// Choose the first non-zero host address
		for _, allowedIP := range peer.AllowedIPs {
			ip4, ip6 := allowedIP.IP.To4(), allowedIP.IP.To16()
			if bytes.Equal(ip4, empty4) {
				continue
			}
			if bytes.Equal(ip6, empty6) {
				continue
			}
			// Assume the first host in the network is the same as the given IP
			// Dump the IP
			fmt.Println(allowedIP.IP.String())
			dumped = true
			break
		}
		if !dumped {
			fmt.Println("# no address found")
		}
	}

	return nil
}
