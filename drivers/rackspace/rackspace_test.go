package rackspace

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
	assert.NoError(t, os.Setenv("OS_USERNAME", "test username"))
	os.Args = append(os.Args, []string{"--rackspace-api-key", "test API key"}...)

	driverBytes, err := json.Marshal(driver)
	assert.NoError(t, err)
	assert.NoError(t, json.Unmarshal(driverBytes, driver))

	// Make sure that config has been pulled in from envvars and args.
	assert.Equal(t, "test username", driver.Username)
	assert.Equal(t, "test API key", driver.APIKey)
}

func TestSetConfigFromFlags(t *testing.T) {
	driver := NewDriver("default", "path")

	checkFlags := &drivers.CheckDriverOptions{
		FlagsValues: map[string]interface{}{
			"rackspace-region":        "REGION",
			"rackspace-username":      "user",
			"rackspace-api-key":       "KEY",
			"rackspace-endpoint-type": "publicURL",
		},
		CreateFlags: driver.GetCreateFlags(),
	}

	err := driver.SetConfigFromFlags(checkFlags)

	assert.NoError(t, err)
	assert.Empty(t, checkFlags.InvalidFlags)
}
