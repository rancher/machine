package commands

import (
	"fmt"

	"github.com/rancher/machine/libmachine"
	"github.com/rancher/machine/libmachine/state"
	"github.com/rancher/machine/libmachine/util"
)

type errStateInvalidForSSH struct {
	HostName string
}

func (e errStateInvalidForSSH) Error() string {
	return fmt.Sprintf("Error: Cannot run SSH command: Host %q is not running", e.HostName)
}

func cmdSSH(c CommandLine, api libmachine.API) error {
	// Check for help flag -- Needed due to SkipFlagParsing
	hostArgs, _ := util.SplitArgs(c.Args())
	var firstArg string
	tailArgs := []string{}
	if len(hostArgs) > 0 {
		firstArg = hostArgs[0]
		tailArgs = hostArgs[1:]
	}

	if firstArg == "-help" || firstArg == "--help" || firstArg == "-h" {
		c.ShowHelp()
		return nil
	}

	target, err := targetHost(c, api, hostArgs)
	if err != nil {
		return err
	}

	host, err := api.Load(target)
	if err != nil {
		return err
	}

	currentState, err := host.Driver.GetState()
	if err != nil {
		return err
	}

	if currentState != state.Running {
		return errStateInvalidForSSH{host.Name}
	}

	client, err := host.CreateSSHClient()
	if err != nil {
		return err
	}

	return client.Shell(tailArgs...)
}
