//go:build !windows
// +build !windows

package commands

import (
	"github.com/rancher/machine/libmachine"
	"github.com/rancher/machine/libmachine/util"
)

func cmdScp(c CommandLine, api libmachine.API) error {
	hostArgs, _ := util.SplitArgs(c.Args())
	if len(hostArgs) != 2 {
		c.ShowHelp()
		return errWrongNumberArguments
	}

	src := hostArgs[0]
	dest := hostArgs[1]

	hostInfoLoader := &storeHostInfoLoader{api}

	cmd, err := getScpCmd(src, dest, c.Bool("recursive"), c.Bool("delta"), c.Bool("quiet"), hostInfoLoader)
	if err != nil {
		return err
	}

	return runCmdWithStdIo(*cmd)
}
