package drivers

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcnutils"
	"github.com/rancher/machine/libmachine/ssh"
)

const (
	DefaultSSHAttempts      = 60
	DefaultSSHRetryInverval = 3
)

func GetSSHClientFromDriver(d Driver) (ssh.Client, error) {
	address, err := d.GetSSHHostname()
	if err != nil {
		return nil, err
	}

	port, err := d.GetSSHPort()
	if err != nil {
		return nil, err
	}

	var auth *ssh.Auth
	if d.GetSSHKeyPath() == "" {
		auth = &ssh.Auth{}
	} else {
		auth = &ssh.Auth{
			Keys: []string{d.GetSSHKeyPath()},
		}
	}

	client, err := ssh.NewClient(d.GetSSHUsername(), address, port, auth)
	return client, err

}

func RunSSHCommandFromDriver(d Driver, command string) (string, error) {
	client, err := GetSSHClientFromDriver(d)
	if err != nil {
		return "", err
	}

	log.Debugf("About to run SSH command:\n%s", command)

	output, err := client.Output(command)
	log.Debugf("SSH cmd err, output: %v: %s", err, output)
	if err != nil {
		return "", fmt.Errorf(`ssh command error: command: %s err: %v output: %s`, command, err, output)
	}

	return output, nil
}

func sshAvailableFunc(d Driver) func() bool {
	return func() bool {
		log.Debug("Getting to WaitForSSH function...")
		if _, err := RunSSHCommandFromDriver(d, "exit 0"); err != nil {
			log.Debugf("Error getting ssh command 'exit 0' : %s", err)
			return false
		}
		return true
	}
}

func WaitForSSH(d Driver) error {
	// Try to dial SSH for sshRetryInterval seconds before timing out.
	var maxAttempts int
	var retryInterval int
	var err error

	if maxAttemptsStr, envVarPresent := os.LookupEnv("MACHINE_SSH_ATTEMPTS"); envVarPresent {
		if maxAttempts, err = strconv.Atoi(maxAttemptsStr); err != nil {
			log.Errorf("Value '%s' from environment variable MACHINE_SSH_ATTEMPTS could not be parsed, "+
				"setting default value (%d)",
				maxAttemptsStr, DefaultSSHAttempts)
			maxAttempts = DefaultSSHAttempts
		}
	} else {
		maxAttempts = DefaultSSHAttempts
	}

	if retryIntervalStr, envVarPresent := os.LookupEnv("MACHINE_SSH_RETRY_INTERVAL"); envVarPresent {
		if retryInterval, err = strconv.Atoi(retryIntervalStr); err != nil {
			log.Errorf("Value '%s' from environment variable MACHINE_SSH_RETRY_INTERVAL could not be parsed, "+
				"setting default value (%d)",
				retryIntervalStr, DefaultSSHRetryInverval)
			retryInterval = DefaultSSHRetryInverval
		}
	} else {
		retryInterval = DefaultSSHRetryInverval
	}

	interval := time.Duration(retryInterval * int(time.Second))
	log.Infof("Waiting for SSH to become available (maximum attempts: %d, interval between attempts: %s)",
		maxAttempts, interval.String())
	if err := mcnutils.WaitForSpecific(sshAvailableFunc(d), maxAttempts, interval); err != nil {
		return fmt.Errorf("Too many retries waiting for SSH to be available.  Last error: %s", err)
	}
	return nil
}
