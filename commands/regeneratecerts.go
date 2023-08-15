package commands

import (
	"errors"
	"time"

	"github.com/rancher/machine/libmachine"
	"github.com/rancher/machine/libmachine/auth"
	"github.com/rancher/machine/libmachine/cert"
	"github.com/rancher/machine/libmachine/log"
)

func cmdRegenerateCerts(c CommandLine, api libmachine.API) error {
	if !c.Bool("force") {
		ok, err := confirmInput("Regenerate TLS machine certs?  Warning: this is irreversible.")
		if err != nil {
			return err
		}

		if !ok {
			return nil
		}
	}

	log.Infof("Regenerating TLS certificates")

	if c.Bool("client-certs") {
		return runAction("configureAllAuth", c, api)
	}
	return runAction("configureAuth", c, api)
}

type authOptionsProvider interface {
	AuthOptions() *auth.Options
}

func cmdRegenerateBaseCerts(c CommandLine, api libmachine.API) error {
	if !c.Bool("force") {
		ok, err := confirmInput("Regenerate base TLS certificates?  Warning: this is irreversible.")
		if err != nil {
			return err
		}

		if !ok {
			return nil
		}
	}

	log.Infof("Regenerating base TLS certificates")

	aop, ok := api.(authOptionsProvider)
	if !ok {
		return errors.New("can't typecast API to authOptionsProvider")
	}

	regenerateBeforeHours := c.Int("regenerate-before")
	regenerateWindow := time.Duration(-1*regenerateBeforeHours) * time.Hour

	return cert.BootstrapCertificatesWithRegenerationWindow(aop.AuthOptions(), regenerateWindow)
}
