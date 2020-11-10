package provision

import (
	"github.com/rancher/machine/libmachine/drivers"
)

func init() {
	Register("Amazon", &RegisteredProvisioner{
		New: NewAmazonProvisioner,
	})
}

func NewAmazonProvisioner(d drivers.Driver) Provisioner {
	return &AmazonProvisioner{
		NewRedHatProvisioner("amzn", d),
	}
}

type AmazonProvisioner struct {
	*RedHatProvisioner
}

func (provisioner *AmazonProvisioner) String() string {
	return "amazon"
}
