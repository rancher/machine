package provision

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rancher/machine/libmachine/auth"
	"github.com/rancher/machine/libmachine/cert"
	"github.com/rancher/machine/libmachine/engine"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcnutils"
	"github.com/rancher/machine/libmachine/provision/serviceaction"
)

type DockerOptions struct {
	EngineOptions     string
	EngineOptionsPath string
}

func installDockerGeneric(p Provisioner, baseURL string) error {
	if strings.EqualFold(baseURL, "none") {
		log.Info("Skipping Docker installation")
		return nil
	}
	// install docker - until cloudinit we use ubuntu everywhere so we
	// just install it using the docker repos
	log.Infof("Installing Docker from: %s", baseURL)
	if output, err := p.SSHCommand(fmt.Sprintf("if ! type docker; then curl -sSL %s | sh -; fi", baseURL)); err != nil {
		return fmt.Errorf("Error installing Docker: %s", output)
	}

	return nil
}

func makeDockerOptionsDir(p Provisioner) error {
	dockerDir := p.GetDockerOptionsDir()
	if _, err := p.SSHCommand(fmt.Sprintf("sudo mkdir -p %s", dockerDir)); err != nil {
		return err
	}

	return nil
}

func setRemoteAuthOptions(p Provisioner) auth.Options {
	dockerDir := p.GetDockerOptionsDir()
	authOptions := p.GetAuthOptions()

	// due to windows clients, we cannot use filepath.Join as the paths
	// will be mucked on the linux hosts
	authOptions.CaCertRemotePath = path.Join(dockerDir, "ca.pem")
	authOptions.ServerCertRemotePath = path.Join(dockerDir, "server.pem")
	authOptions.ServerKeyRemotePath = path.Join(dockerDir, "server-key.pem")

	return authOptions
}

func ConfigureAuth(p Provisioner) error {
	var (
		err error
	)

	driver := p.GetDriver()
	machineName := driver.GetMachineName()
	authOptions := p.GetAuthOptions()
	swarmOptions := p.GetSwarmOptions()
	org := mcnutils.GetUsername() + "." + machineName
	bits := 2048

	ip, err := driver.GetIP()
	if err != nil {
		return err
	}

	log.Info("Copying certs to the local machine directory...")

	if err := mcnutils.CopyFile(authOptions.CaCertPath, filepath.Join(authOptions.StorePath, "ca.pem")); err != nil {
		return fmt.Errorf("Copying ca.pem to machine dir failed: %s", err)
	}

	if err := mcnutils.CopyFile(authOptions.ClientCertPath, filepath.Join(authOptions.StorePath, "cert.pem")); err != nil {
		return fmt.Errorf("Copying cert.pem to machine dir failed: %s", err)
	}

	if err := mcnutils.CopyFile(authOptions.ClientKeyPath, filepath.Join(authOptions.StorePath, "key.pem")); err != nil {
		return fmt.Errorf("Copying key.pem to machine dir failed: %s", err)
	}

	// The Host IP is always added to the certificate's SANs list
	hosts := append(authOptions.ServerCertSANs, ip, "localhost")
	log.Debugf("generating server cert: %s ca-key=%s private-key=%s org=%s san=%s",
		authOptions.ServerCertPath,
		authOptions.CaCertPath,
		authOptions.CaPrivateKeyPath,
		org,
		hosts,
	)

	// TODO: Switch to passing just authOptions to this func
	// instead of all these individual fields
	err = cert.GenerateCert(&cert.Options{
		Hosts:       hosts,
		CertFile:    authOptions.ServerCertPath,
		KeyFile:     authOptions.ServerKeyPath,
		CAFile:      authOptions.CaCertPath,
		CAKeyFile:   authOptions.CaPrivateKeyPath,
		Org:         org,
		Bits:        bits,
		SwarmMaster: swarmOptions.Master,
	})

	if err != nil {
		return fmt.Errorf("error generating server cert: %s", err)
	}

	if err := p.Service("docker", serviceaction.Stop); err != nil {
		return err
	}

	if _, err := p.SSHCommand(`if [ ! -z "$(ip link show docker0)" ]; then sudo ip link delete docker0; fi`); err != nil {
		return err
	}

	// upload certs and configure TLS auth
	caCert, err := os.ReadFile(authOptions.CaCertPath)
	if err != nil {
		return err
	}

	serverCert, err := os.ReadFile(authOptions.ServerCertPath)
	if err != nil {
		return err
	}
	serverKey, err := os.ReadFile(authOptions.ServerKeyPath)
	if err != nil {
		return err
	}

	log.Info("Copying certs to the remote machine...")

	// printf will choke if we don't pass a format string because of the
	// dashes, so that's the reason for the '%%s'
	certTransferCmdFmt := "printf '%%s' '%s' | sudo tee %s"

	// These ones are for Jessie and Mike <3 <3 <3
	if _, err := p.SSHCommand(fmt.Sprintf(certTransferCmdFmt, string(caCert), authOptions.CaCertRemotePath)); err != nil {
		return err
	}

	if _, err := p.SSHCommand(fmt.Sprintf(certTransferCmdFmt, string(serverCert), authOptions.ServerCertRemotePath)); err != nil {
		return err
	}

	if _, err := p.SSHCommand(fmt.Sprintf(certTransferCmdFmt, string(serverKey), authOptions.ServerKeyRemotePath)); err != nil {
		return err
	}

	dockerURL, err := driver.GetURL()
	if err != nil {
		return err
	}
	u, err := url.Parse(dockerURL)
	if err != nil {
		return err
	}
	dockerPort := engine.DefaultPort
	parts := strings.Split(u.Host, ":")
	if len(parts) == 2 {
		dPort, err := strconv.Atoi(parts[1])
		if err != nil {
			return err
		}
		dockerPort = dPort
	}

	dkrcfg, err := p.GenerateDockerOptions(dockerPort)
	if err != nil {
		return err
	}

	log.Info("Setting Docker configuration on the remote daemon...")

	if _, err = p.SSHCommand(fmt.Sprintf("sudo mkdir -p %s && printf %%s \"%s\" | sudo tee %s", path.Dir(dkrcfg.EngineOptionsPath), dkrcfg.EngineOptions, dkrcfg.EngineOptionsPath)); err != nil {
		return err
	}

	if err := p.Service("docker", serviceaction.Restart); err != nil {
		return err
	}

	return WaitForDocker(p, dockerPort)
}

func matchNetstatOut(reDaemonListening, netstatOut string) bool {
	// TODO: I would really prefer this be a Scanner directly on
	// the STDOUT of the executed command than to do all the string
	// manipulation hokey-pokey.
	//
	// TODO: Unit test this matching.
	for _, line := range strings.Split(netstatOut, "\n") {
		match, err := regexp.MatchString(reDaemonListening, line)
		if err != nil {
			log.Warnf("Regex warning: %s", err)
		}
		if match && line != "" {
			return true
		}
	}

	return false
}

func decideStorageDriver(p Provisioner, defaultDriver, suppliedDriver string) (string, error) {
	if suppliedDriver != "" {
		return suppliedDriver, nil
	}
	bestSuitedDriver := ""

	defer func() {
		if bestSuitedDriver != "" {
			log.Debugf("No storagedriver specified, using %s\n", bestSuitedDriver)
		}
	}()

	if defaultDriver != DefaultStorageDriver {
		bestSuitedDriver = defaultDriver
	} else {
		remoteFilesystemType, err := getFilesystemType(p, "/var/lib")
		if err != nil {
			return "", err
		}
		if remoteFilesystemType == "btrfs" {
			bestSuitedDriver = "btrfs"
		} else {
			bestSuitedDriver = DefaultStorageDriver
		}
	}
	return bestSuitedDriver, nil

}

func getFilesystemType(p Provisioner, directory string) (string, error) {
	statCommandOutput, err := p.SSHCommand("stat -f -c %T " + directory)
	if err != nil {
		err = fmt.Errorf("Error looking up filesystem type: %s", err)
		return "", err
	}

	fstype := strings.TrimSpace(statCommandOutput)
	return fstype, nil
}

func checkDaemonUp(p Provisioner, dockerPort int) func() bool {
	reDaemonListening := fmt.Sprintf(":%d\\s+.*:.*", dockerPort)
	return func() bool {
		// HACK: Check netstat's output to see if anyone's listening on the Docker API port.
		netstatOut, err := p.SSHCommand("if ! type netstat 1>/dev/null; then ss -tln; else netstat -tln; fi")
		if err != nil {
			log.Warnf("Error running SSH command: %s", err)
			return false
		}

		return matchNetstatOut(reDaemonListening, netstatOut)
	}
}

// waitForCloudInit runs `cloud-init status --wait` on the node in order to wait for the node to be ready before
// continuing execution.
// it also swallows the "bad" exit code that can be returned but is in reality just alerting us that there were benign
// errors during cloud-init: https://docs.cloud-init.io/en/24.1/explanation/failure_states.html#recoverable-failure
func waitForCloudInit(p Provisioner) error {
	_, err := p.SSHCommand(`sudo bash -c 'cloud-init status --wait >/dev/null || if [ $? == 2 ]; then true ; fi'`)
	if err != nil {
		return fmt.Errorf("failed to wait for cloud-init: %w", err)
	}
	return nil
}

func WaitForDocker(p Provisioner, dockerPort int) error {
	if err := mcnutils.WaitForSpecific(checkDaemonUp(p, dockerPort), 10, 3*time.Second); err != nil {
		return NewErrDaemonAvailable(err)
	}

	return nil
}

// DockerClientVersion returns the version of the Docker client on the host
// that ssh is connected to, e.g. "1.12.1".
func DockerClientVersion(ssh SSHCommander) (string, error) {
	// `docker version --format {{.Client.Version}}` would be preferable, but
	// that fails if the server isn't running yet.
	//
	// output is expected to be something like
	//
	//     Docker version 1.12.1, build 7a86f89
	output, err := ssh.SSHCommand("docker --version")
	if err != nil {
		return "", err
	}

	words := strings.Fields(output)
	if len(words) < 3 || words[0] != "Docker" || words[1] != "version" {
		return "", fmt.Errorf("DockerClientVersion: cannot parse version string from %q", output)
	}

	return strings.TrimRight(words[2], ","), nil
}

func waitForLockAptGetUpdate(ssh SSHCommander) error {
	return waitForLock(ssh, "sudo apt-get update")
}

func waitForLock(ssh SSHCommander, cmd string) error {
	var sshErr error
	err := mcnutils.WaitFor(func() bool {
		_, sshErr = ssh.SSHCommand(cmd)
		if sshErr != nil {
			if strings.Contains(sshErr.Error(), "Could not get lock") {
				sshErr = nil
				return false
			}
			return true
		}
		return true
	})
	if sshErr != nil {
		return fmt.Errorf("Error running %q: %s", cmd, sshErr)
	}
	if err != nil {
		return fmt.Errorf("Failed to obtain lock: %s", err)
	}
	return nil
}
