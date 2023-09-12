package provision

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"text/template"

	"github.com/rancher/machine/libmachine/auth"
	"github.com/rancher/machine/libmachine/drivers"
	"github.com/rancher/machine/libmachine/engine"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcnutils"
	"github.com/rancher/machine/libmachine/provision/pkgaction"
	"github.com/rancher/machine/libmachine/provision/serviceaction"
	"github.com/rancher/machine/libmachine/swarm"
)

var (
	ErrUnknownYumOsRelease = errors.New("unknown OS for Yum repository")
	engineConfigTemplate   = `[Service]
ExecStart=
ExecStart=/usr/bin/dockerd -H tcp://0.0.0.0:{{.DockerPort}} -H unix:///var/run/docker.sock --storage-driver {{.EngineOptions.StorageDriver}} --tlsverify --tlscacert {{.AuthOptions.CaCertRemotePath}} --tlscert {{.AuthOptions.ServerCertRemotePath}} --tlskey {{.AuthOptions.ServerKeyRemotePath}} {{ range .EngineOptions.Labels }}--label {{.}} {{ end }}{{ range .EngineOptions.InsecureRegistry }}--insecure-registry {{.}} {{ end }}{{ range .EngineOptions.RegistryMirror }}--registry-mirror {{.}} {{ end }}{{ range .EngineOptions.ArbitraryFlags }}--{{.}} {{ end }}
Environment={{range .EngineOptions.Env}}{{ printf "%q" . }} {{end}}
`
	majorVersionRE = regexp.MustCompile(`^(\d+)(\..*)?`)
)

type PackageListInfo struct {
	OsRelease        string
	OsReleaseVersion string
}

func init() {
	Register("RedHat", &RegisteredProvisioner{
		New: func(d drivers.Driver) Provisioner {
			return NewRedHatProvisioner("rhel", d)
		},
	})
}

func NewRedHatProvisioner(osReleaseID string, d drivers.Driver) *RedHatProvisioner {
	systemdProvisioner := NewSystemdProvisioner(osReleaseID, d)
	systemdProvisioner.SSHCommander = RedHatSSHCommander{Driver: d}
	return &RedHatProvisioner{
		systemdProvisioner,
	}
}

type RedHatProvisioner struct {
	SystemdProvisioner
}

func (provisioner *RedHatProvisioner) String() string {
	return "redhat"
}

func (provisioner *RedHatProvisioner) SetHostname(hostname string) error {
	// we have to have SetHostname here as well to use the RedHat provisioner
	// SSHCommand to add the tty allocation
	if _, err := provisioner.SSHCommand(fmt.Sprintf(
		"sudo hostname %s && echo %q | sudo tee /etc/hostname",
		hostname,
		hostname,
	)); err != nil {
		return err
	}

	if _, err := provisioner.SSHCommand(fmt.Sprintf(
		"if grep -xq 127.0.1.1.* /etc/hosts; then sudo sed -i 's/^127.0.1.1.*/127.0.1.1 %s/g' /etc/hosts; else echo '127.0.1.1 %s' | sudo tee -a /etc/hosts; fi",
		hostname,
		hostname,
	)); err != nil {
		return err
	}

	return nil
}

func (provisioner *RedHatProvisioner) Package(name string, action pkgaction.PackageAction) error {
	var packageAction string

	switch action {
	case pkgaction.Install:
		packageAction = "install"
	case pkgaction.Remove:
		packageAction = "remove"
	case pkgaction.Purge:
		packageAction = "remove"
	case pkgaction.Upgrade:
		packageAction = "upgrade"
	}

	command := fmt.Sprintf("sudo -E yum %s -y %s", packageAction, name)

	if _, err := provisioner.SSHCommand(command); err != nil {
		return err
	}

	return nil
}

func (provisioner *RedHatProvisioner) dockerDaemonResponding() bool {
	log.Debug("checking docker daemon")

	if out, err := provisioner.SSHCommand("sudo docker version"); err != nil {
		log.Warnf("Error getting SSH command to check if the daemon is up: %s", err)
		log.Debugf("'sudo docker version' output:\n%s", out)
		return false
	}

	// The daemon is up if the command worked.  Carry on.
	return true
}

func (provisioner *RedHatProvisioner) disableNetworkManagerSetupService8dot4() error {
	// the service nm-cloud-setup.service and nm-cloud-setup.timer are seen on RHEL 8.4 and 8.6
	if provisioner.OsReleaseInfo.ID != "rhel" {
		return nil
	}

	log.Debug("Patching NetworkManager")
	cmd := "sudo systemctl is-enabled %s; if [ $? -eq 0 ]; then sudo systemctl disable %s && touch /tmp/rancher-machine-reboot; else echo 0; fi"
	for _, service := range []string{"nm-cloud-setup.timer", "nm-cloud-setup.service"} {
		if _, err := provisioner.SSHCommand(fmt.Sprintf(cmd, service, service)); err != nil {
			return err
		}
	}

	// ignore errors here because the SSH connection will close
	provisioner.SSHCommand("[ -f /tmp/rancher-machine-reboot ] && rm -f /tmp/rancher-machine-reboot && sudo reboot")

	log.Debug("NetworkManager patched, waiting for machine to reboot...")
	return drivers.WaitForSSH(provisioner.Driver)
}

func (provisioner *RedHatProvisioner) Provision(swarmOptions swarm.Options, authOptions auth.Options, engineOptions engine.Options) error {
	provisioner.SwarmOptions = swarmOptions
	provisioner.AuthOptions = authOptions
	provisioner.EngineOptions = engineOptions
	swarmOptions.Env = engineOptions.Env

	if err := provisioner.disableNetworkManagerSetupService8dot4(); err != nil {
		return err
	}

	// set default storage driver for redhat
	storageDriver, err := decideStorageDriver(provisioner, DefaultStorageDriver, engineOptions.StorageDriver)
	if err != nil {
		return err
	}
	provisioner.EngineOptions.StorageDriver = storageDriver

	if err := provisioner.SetHostname(provisioner.Driver.GetMachineName()); err != nil {
		return err
	}

	for _, pkg := range provisioner.Packages {
		log.Debugf("installing base package: name=%s", pkg)
		if err := provisioner.Package(pkg, pkgaction.Install); err != nil {
			return err
		}
	}

	if err := installDockerGeneric(provisioner, provisioner.EngineOptions.InstallURL); err != nil {
		return err
	} else if err == nil {
		if err := provisioner.Service("docker", serviceaction.Restart); err != nil {
			return err
		}
		if err := provisioner.Service("docker", serviceaction.Enable); err != nil {
			return err
		}
	}

	if err := mcnutils.WaitFor(provisioner.dockerDaemonResponding); err != nil {
		return err
	}

	if err := makeDockerOptionsDir(provisioner); err != nil {
		return err
	}

	provisioner.AuthOptions = setRemoteAuthOptions(provisioner)

	if err := ConfigureAuth(provisioner); err != nil {
		return err
	}

	err = configureSwarm(provisioner, swarmOptions, provisioner.AuthOptions)
	return err
}

func (provisioner *RedHatProvisioner) GenerateDockerOptions(dockerPort int) (*DockerOptions, error) {
	var (
		engineCfg  bytes.Buffer
		configPath = provisioner.DaemonOptionsFile
	)

	driverNameLabel := fmt.Sprintf("provider=%s", provisioner.Driver.DriverName())
	provisioner.EngineOptions.Labels = append(provisioner.EngineOptions.Labels, driverNameLabel)

	// systemd / redhat will not load options if they are on newlines
	// instead, it just continues with a different set of options; yeah...
	t, err := template.New("engineConfig").Parse(engineConfigTemplate)
	if err != nil {
		return nil, err
	}

	engineConfigContext := EngineConfigContext{
		DockerPort:       dockerPort,
		AuthOptions:      provisioner.AuthOptions,
		EngineOptions:    provisioner.EngineOptions,
		DockerOptionsDir: provisioner.DockerOptionsDir,
	}

	t.Execute(&engineCfg, engineConfigContext)

	daemonOptsDir := configPath
	return &DockerOptions{
		EngineOptions:     engineCfg.String(),
		EngineOptionsPath: daemonOptsDir,
	}, nil
}
