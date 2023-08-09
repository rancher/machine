package commands

import (
	"fmt"
	"strings"
	"syscall"

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

	// Default argument escaping is not valid for scp.exe with quoted arguments, so we do it ourselves
	// see golang/go#15566
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	cmd.SysProcAttr.CmdLine = fmt.Sprintf("%s %s", cmd.Path, strings.Join(cmd.Args, " "))

	return runCmdWithStdIo(*cmd)
}
