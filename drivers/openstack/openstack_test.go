package openstack

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
	assert.NoError(t, os.Setenv("OS_AUTH_URL", "test auth URL"))
	assert.NoError(t, os.Setenv("OS_USER_ID", "test user ID"))
	os.Args = append(os.Args, []string{"--openstack-username", "test username"}...)
	os.Args = append(os.Args, []string{"--openstack-password", "test pw"}...)

	driverBytes, err := json.Marshal(driver)
	assert.NoError(t, err)
	assert.NoError(t, json.Unmarshal(driverBytes, driver))

	// Make sure that config has been pulled in from envvars and args.
	assert.Equal(t, "test auth URL", driver.AuthUrl)
	assert.Equal(t, "test user ID", driver.UserId)
	assert.Equal(t, "test username", driver.Username)
	assert.Equal(t, "test pw", driver.Password)
}

func TestSetConfigFromFlags(t *testing.T) {
	driver := NewDriver("default", "path")

	checkFlags := &drivers.CheckDriverOptions{
		FlagsValues: map[string]interface{}{
			"openstack-auth-url":  "http://url",
			"openstack-username":  "user",
			"openstack-password":  "pwd",
			"openstack-tenant-id": "ID",
			"openstack-flavor-id": "ID",
			"openstack-image-id":  "ID",
		},
		CreateFlags: driver.GetCreateFlags(),
	}

	err := driver.SetConfigFromFlags(checkFlags)

	assert.NoError(t, err)
	assert.Empty(t, checkFlags.InvalidFlags)
}
