// wireguard-negotiator is a tool to exchange WireGuard keys over HTTP(S).
package main // import "github.com/serverwentdown/wireguard-negotiator"

import (
	"log"
	"os"

	"github.com/serverwentdown/wireguard-negotiator/cmd"
	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "wireguard-negotiator",
		Usage: "Exchange WireGuard keys over HTTP(S)",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "server",
				Aliases: []string{"s"},
				Usage:   "wireguard-negotiator server URL",
				EnvVars: []string{"WGN_SERVER_URL"},
			},
			&cli.BoolFlag{
				Name:    "insecure",
				Usage:   "Disable TLS verification",
				EnvVars: []string{"WGN_SERVER_INSECURE"},
			},
		},
		Commands: []*cli.Command{
			cmd.CmdServer,
			cmd.CmdList,
			cmd.CmdApprove,
			cmd.CmdRequest,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}