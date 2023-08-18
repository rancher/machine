package noop

import (
	"encoding/json"
	"fmt"
	neturl "net/url"
	"os"

	"github.com/rancher/machine/libmachine/drivers"
	rpcdriver "github.com/rancher/machine/libmachine/drivers/rpc"
	"github.com/rancher/machine/libmachine/mcnflag"
	"github.com/rancher/machine/libmachine/state"
)

const driverName = "noop"

// Driver is a noop driver that does nothing.
type Driver struct {
	*drivers.BaseDriver
	URL   string
	state state.State
}

func NewDriver(hostName, storePath string) *Driver {
	return &Driver{
		BaseDriver: &drivers.BaseDriver{
			MachineName: hostName,
			StorePath:   storePath,
		},
		state: state.Running,
	}
}

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "url",
			Value:  "",
			EnvVar: "URL",
		},
	}
}

func (d *Driver) Create() error {
	d.state = state.Running
	return nil
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return driverName
}

func (d *Driver) GetIP() (string, error) {
	return d.IPAddress, nil
}

func (d *Driver) GetSSHHostname() (string, error) {
	return "", nil
}

func (d *Driver) GetSSHKeyPath() string {
	return ""
}

func (d *Driver) GetSSHPort() (int, error) {
	return 0, nil
}

func (d *Driver) GetSSHUsername() string {
	return ""
}

func (d *Driver) GetURL() (string, error) {
	return d.URL, nil
}

func (d *Driver) GetState() (state.State, error) {
	return d.state, nil
}

func (d *Driver) Kill() error {
	println("kill called")
	d.state = state.Stopped
	return nil
}

func (d *Driver) Remove() error {
	return nil
}

func (d *Driver) Restart() error {
	return nil
}

// UnmarshalJSON loads driver config from JSON.
func (d *Driver) UnmarshalJSON(data []byte) error {
	// Unmarshal driver config into an aliased type to prevent infinite recursion on UnmarshalJSON.
	type targetDriver Driver
	target := targetDriver{}
	if err := json.Unmarshal(data, &target); err != nil {
		return fmt.Errorf("error unmarshalling driver config from JSON: %w", err)
	}

	*d = Driver(target)

	// Make sure to reload values that are subject to change from envvars and os.Args.
	driverOpts := rpcdriver.GetDriverOpts(d.GetCreateFlags(), os.Args)
	if _, ok := driverOpts.Values["url"]; ok {
		d.URL = driverOpts.String("url")
	}

	return nil
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.URL = flags.String("url")
	u, err := neturl.Parse(d.URL)
	if err != nil {
		return err
	}

	d.IPAddress = u.Host
	return nil
}

func (d *Driver) Start() error {
	return nil
}

func (d *Driver) Stop() error {
	return nil
}
