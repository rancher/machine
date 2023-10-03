package vmwarevsphere

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/rancher/machine/libmachine/drivers"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalJSON(t *testing.T) {
	driver := NewDriver("", "").(*Driver)

	// Unmarhsal driver configuration from JSON, envvars, and args.
	assert.NoError(t, os.Setenv("VSPHERE_SSH_USER", "test username"))
	assert.NoError(t, os.Setenv("VSPHERE_SSH_PASSWORD", "test pw"))
	os.Args = append(os.Args, []string{"--vmwarevsphere-vcenter", "test vcenter"}...)
	os.Args = append(os.Args, []string{"--vmwarevsphere-username", "test user"}...)
	os.Args = append(os.Args, []string{"--vmwarevsphere-password", "test password"}...)

	driverBytes, err := json.Marshal(driver)
	assert.NoError(t, err)
	assert.NoError(t, json.Unmarshal(driverBytes, driver))

	// Make sure that config has been pulled in from envvars and args.
	assert.Equal(t, "test username", driver.SSHUser)
	assert.Equal(t, "test pw", driver.SSHPassword)
	assert.Equal(t, "test vcenter", driver.IP)
	assert.Equal(t, "test user", driver.Username)
	assert.Equal(t, "test password", driver.Password)
}

func TestSetConfigFromFlags(t *testing.T) {
	driver := NewDriver("default", "path")

	checkFlags := &drivers.CheckDriverOptions{
		FlagsValues: map[string]interface{}{},
		CreateFlags: driver.GetCreateFlags(),
	}

	err := driver.SetConfigFromFlags(checkFlags)

	assert.NoError(t, err)
	assert.Empty(t, checkFlags.InvalidFlags)
}
