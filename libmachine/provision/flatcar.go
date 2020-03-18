package provision

import (
	"github.com/rancher/machine/libmachine/drivers"
)

func init() {
	Register("Flatcar", &RegisteredProvisioner{
		New: NewFlatcarProvisioner,
	})
}

func NewFlatcarProvisioner(d drivers.Driver) Provisioner {
	return &FlatcarProvisioner{
		NewCoreOSProvisioner("flatcar", d),
	}
}

type FlatcarProvisioner struct {
	*CoreOSProvisioner
}

func (provisioner *FlatcarProvisioner) String() string {
	return "flatcar"
}
