package vmwarefusion

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
	assert.NoError(t, os.Setenv("FUSION_SSH_USER", "test SSH user"))
	os.Args = append(os.Args, []string{"--vmwarefusion-ssh-password", "test SSH pw"}...)

	driverBytes, err := json.Marshal(driver)
	assert.NoError(t, err)
	assert.NoError(t, json.Unmarshal(driverBytes, driver))

	// Make sure that config has been pulled in from envvars and args.
	assert.Equal(t, "test SSH user", driver.SSHUser)
	assert.Equal(t, "test SSH pw", driver.SSHPassword)
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
