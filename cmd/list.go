package cmd

import (
	//"github.com/serverwentdown/wireguard-negotiator/lib"
	"github.com/urfave/cli/v2"
)

var CmdList = &cli.Command{
	Name:   "list",
	Usage:  "List all pending negotiations",
	Action: runList,
}

func runList(ctx *cli.Context) error {
	//client := lib.NewClient(ctx.String("server"), ctx.Bool("insecure"))
	return nil
}
