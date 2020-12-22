package provision

import (
	"github.com/rancher/machine/libmachine/auth"
	"github.com/rancher/machine/libmachine/drivers"
	"github.com/rancher/machine/libmachine/engine"
	"github.com/rancher/machine/libmachine/provision/pkgaction"
	"github.com/rancher/machine/libmachine/provision/serviceaction"
	"github.com/rancher/machine/libmachine/swarm"
)

// NoDockerInstall ensures that docker will not be installed when provisioning the machine
func NoDockerInstall() {
	SetDetector(noOpDetector{})
}

type noOpDetector struct{}

func (np noOpDetector) DetectProvisioner(d drivers.Driver) (Provisioner, error) {
	return &noOpProvisioner{
		GenericProvisioner{
			SSHCommander: noOpSSHCommander{},
			Packages: []string{
				"curl",
			},
			Driver: d,
		},
	}, nil
}

type noOpProvisioner struct {
	GenericProvisioner
}

func (n *noOpProvisioner) String() string {
	return "no-op"
}

func (n *noOpProvisioner) Package(_ string, _ pkgaction.PackageAction) error {
	return nil
}

func (n *noOpProvisioner) Provision(_ swarm.Options, _ auth.Options, _ engine.Options) error {
	return nil
}

func (n *noOpProvisioner) Service(_ string, _ serviceaction.ServiceAction) error {
	return nil
}

func (n *noOpProvisioner) CompatibleWithHost() bool {
	return true
}

type noOpSSHCommander struct{}

func (noOp noOpSSHCommander) SSHCommand(_ string) (string, error) {
	return "", nil
}
