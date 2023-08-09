package commands

import (
	"fmt"
	"strings"

	"github.com/rancher/machine/libmachine"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/state"
	"github.com/rancher/machine/libmachine/util"
)

type notFoundError string

func (nf notFoundError) Error() string {
	return string(nf)
}

func cmdStatus(c CommandLine, api libmachine.API) error {
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

	currentState, err := host.Driver.GetState()
	if err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "not found") {
			return fmt.Errorf("error getting state for host %s: %s", host.Name, err)
		}

		currentState = state.NotFound
		err = notFoundError(fmt.Sprintf("%v not found", host.Name))
	}

	log.Info(currentState)

	return err
}
