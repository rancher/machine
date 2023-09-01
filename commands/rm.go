package commands

import (
	"errors"
	"fmt"
	"strings"

	"github.com/rancher/machine/libmachine"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcnerror"
)

func cmdRm(c CommandLine, api libmachine.API) error {
	if len(c.Args()) == 0 {
		c.ShowHelp()
		return ErrNoMachineSpecified
	}

	log.Info(fmt.Sprintf("About to remove %s", strings.Join(c.Args(), ", ")))
	log.Warn("WARNING: This action will delete both local reference and remote instance.")

	force := c.Bool("force")
	confirm := c.Bool("y")
	var errorOccurred []string

	if !userConfirm(confirm, force) {
		return nil
	}

	for _, hostName := range c.Args() {
		err := removeRemoteMachine(hostName, api)
		if err != nil {
			if _, ok := err.(mcnerror.ErrHostDoesNotExist); !ok {
				errorOccurred = collectError(fmt.Sprintf("Error removing host %q: %s", hostName, err), force, errorOccurred)
			} else {
				log.Infof("Machine config for %s does not exists, so nothing to do...", hostName)
			}
		}

		if err == nil || force {
			removeErr := removeLocalMachine(hostName, api)
			if removeErr != nil {
				errorOccurred = collectError(fmt.Sprintf("Can't remove \"%s\"", hostName), force, errorOccurred)
			} else {
				log.Infof("Successfully removed %s", hostName)
			}
		}
	}

	if len(errorOccurred) > 0 && !force {
		return errors.New(strings.Join(errorOccurred, "\n"))
	}

	return nil
}

func userConfirm(confirm bool, force bool) bool {
	if confirm || force {
		return true
	}

	sure, err := confirmInput(fmt.Sprintf("Are you sure?"))
	if err != nil {
		return false
	}

	return sure
}

func removeRemoteMachine(hostName string, api libmachine.API) error {
	currentHost, loaderr := api.Load(hostName)
	if loaderr != nil {
		return loaderr
	}

	err := currentHost.Driver.Remove()
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "not found") {
		return err
	}

	return nil
}

func removeLocalMachine(hostName string, api libmachine.API) error {
	exist, _ := api.Exists(hostName)
	if !exist {
		return errors.New(hostName + " does not exist.")
	}
	return api.Remove(hostName)
}

func collectError(message string, force bool, errorOccurred []string) []string {
	if force {
		log.Error(message)
	}
	return append(errorOccurred, message)
}
