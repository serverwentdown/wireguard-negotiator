package cmd

import (
	//"github.com/serverwentdown/wireguard-negotiator/lib"
	"github.com/urfave/cli/v2"
)

var CmdApprove = &cli.Command{
	Name:   "approve",
	Usage:  "Approve pending negotiations",
	Action: runApprove,
}

func runApprove(ctx *cli.Context) error {
	//client := lib.NewClient(ctx.String("server"), ctx.Bool("insecure"))
	return nil
}
