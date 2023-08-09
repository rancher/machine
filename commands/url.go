package commands

import (
	"fmt"

	"github.com/rancher/machine/libmachine"
	"github.com/rancher/machine/libmachine/util"
)

func cmdURL(c CommandLine, api libmachine.API) error {
	hostArgs, _ := util.SplitArgs(c.Args())
	if len(hostArgs) > 1 {
		return ErrExpectedOneMachine
	}

	target, err := targetHost(api, hostArgs)
	if err != nil {
		return err
	}

	host, err := api.Load(target)
	if err != nil {
		return err
	}

	url, err := host.URL()
	if err != nil {
		return err
	}

	fmt.Println(url)

	return nil
}
