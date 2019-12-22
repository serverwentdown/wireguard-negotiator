package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"text/template"

	"github.com/serverwentdown/wireguard-negotiator/lib"
	"github.com/urfave/cli/v2"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var ErrTypeNotValid = fmt.Errorf("network interface backend type not valid")

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
			DefaultText: "/etc/systemd/network/<interface>",
			Usage:       "Path to save networkd configuration. Appends .netdev and .network extensions",
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
	/*
		noneConfig := ctx.String("none")
		if !ctx.IsSet("none") {
			noneConfig = "/etc/wireguard/" + inter + ".conf"
		}
	*/
	networkdConfig := ctx.String("networkd")
	if !ctx.IsSet("networkd") {
		networkdConfig = "/etc/systemd/network/" + inter
	}

	client := lib.NewClient(ctx.String("server"), ctx.Bool("insecure"))

	// Generate the private key and public key
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return err
	}
	publicKey := privateKey.PublicKey()

	// Ensure that given files can be opened
	var netdevFile, networkFile *os.File
	switch netBackend {
	case "networkd":
		netdevFile, err = os.OpenFile(networkdConfig+".netdev", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return fmt.Errorf("opening %s failed: %w", networkdConfig+".netdev", err)
		}
		networkFile, err = os.OpenFile(networkdConfig+".network", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return fmt.Errorf("opening %s failed: %w", networkdConfig+".network", err)
		}
	default:
		return fmt.Errorf("%w: %s", ErrTypeNotValid, netBackend)
	}

	// Perform the request
	peerConfigResponse, err := client.Request(publicKey.String())
	if err != nil {
		return err
	}
	config := interfaceAndPeerConfig{
		peerConfigResponse,
		privateKey.String(),
		inter,
	}

	// Generate configuration
	switch netBackend {
	case "networkd":
		err = configureNetworkd(config, netdevFile, networkFile)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("%w: %s", ErrTypeNotValid, netBackend)
	}

	return nil
}

type interfaceAndPeerConfig struct {
	lib.PeerConfigResponse
	PrivateKey    string
	InterfaceName string
}

const networkdNetdevTemplate = `
[NetDev]
Name = {{.InterfaceName}}
Kind = wireguard
Description = WireGuard {{.InterfaceName}} generated with wireguard-negotiator

[WireGuard]
PrivateKey = {{.PrivateKey}}

[WireGuardPeer]
PublicKey = {{.PublicKey}}
AllowedIPs = {{range $i, $a := .AllowedIPs}}{{if gt $i 0}}, {{end}}{{.}}{{end}}
Endpoint = {{.Endpoint}}
PersistentKeepalive = {{.PersistentKeepalive}}
`

const networkdNetworkTemplate = `
[Match]
Name = {{.InterfaceName}}

[Network]
{{range $i, $a := .InterfaceIPs}}
Address = {{.}}
{{end}}
`

func configureNetworkd(config interfaceAndPeerConfig, netdevFile *os.File, networkFile *os.File) error {
	// For ease of maintenance, just render a textual template
	netdevTemplate := template.Must(template.New("networkd-netdev").Parse(networkdNetdevTemplate))
	networkTemplate := template.Must(template.New("networkd-network").Parse(networkdNetworkTemplate))

	err := netdevTemplate.Execute(netdevFile, config)
	if err != nil {
		return fmt.Errorf("netdev template: %w", err)
	}
	err = networkTemplate.Execute(networkFile, config)
	if err != nil {
		return fmt.Errorf("network template: %w", err)
	}

	// For now, simply run one fixed command to reread from the config file
	cmd := exec.Command("systemctl", "restart", "systemd-networkd")
	err = cmd.Run()
	if err != nil {
		return fmt.Errorf("systemctl restart systemd-networkd failed: %w", err)
	}
	return nil
}
