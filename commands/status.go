package commands

import (
	"fmt"
	"strings"

	"github.com/rancher/machine/libmachine"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/state"
)

type notFoundError string

func (nf notFoundError) Error() string {
	return string(nf)
}

func cmdStatus(c CommandLine, api libmachine.API) error {
	if len(c.Args()) > 1 {
		return ErrExpectedOneMachine
	}

	target, err := targetHost(c, api)
	if err != nil {
		return err
	}

	host, err := api.Load(target)
	if err != nil {
		return err
	}

	// Save any host configuration that may have changed before returning.
	defer func() {
		if saveErr := api.Save(host); saveErr != nil {
			log.Warnf("error saving updated host configuration: %v", saveErr)
		}
	}()

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
