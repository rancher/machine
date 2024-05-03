package drivers

import (
	"fmt"
	"time"

	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/ssh"
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

// WaitForSSH tries to run `exit 0` on the host machine using the driver. It will retry up to
// 60 times with 3 seconds in between each attempt. If the command still errors after the final
// attempt, the error will be returned.
func WaitForSSH(d Driver) error {
	var lastErr error
	for i := 0; i < 60; i++ {
		log.Debug("Getting to WaitForSSH function...")
		if _, lastErr = RunSSHCommandFromDriver(d, "exit 0"); lastErr == nil {
			return nil
		}

		log.Debugf("Error getting SSH command 'exit 0' : %s", lastErr)
		time.Sleep(3 * time.Second)
	}

	return fmt.Errorf("Too many retries waiting for SSH to be available. Last error: %w", lastErr)
}
