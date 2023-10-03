package softlayer

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"

	"github.com/rancher/machine/commands/commandstest"
	"github.com/rancher/machine/commands/mcndirs"
	"github.com/rancher/machine/libmachine/drivers"
	"github.com/stretchr/testify/assert"
)

const (
	testStoreDir          = ".store-test"
	machineTestName       = "test-host"
	machineTestCaCert     = "test-cert"
	machineTestPrivateKey = "test-key"
)

func cleanup() error {
	return os.RemoveAll(testStoreDir)
}

func getTestStorePath() (string, error) {
	tmpDir, err := ioutil.TempDir("", "machine-test-")
	if err != nil {
		return "", err
	}
	mcndirs.BaseDir = tmpDir
	return tmpDir, nil
}

func getDefaultTestDriverFlags() *commandstest.FakeFlagger {
	return &commandstest.FakeFlagger{
		Data: map[string]interface{}{
			"name":                   "test",
			"url":                    "unix:///var/run/docker.sock",
			"softlayer-api-key":      "12345",
			"softlayer-user":         "abcdefg",
			"softlayer-api-endpoint": "https://api.softlayer.com/rest/v3",
			"softlayer-image":        "MY_TEST_IMAGE",
		},
	}
}

func getTestDriver() (*Driver, error) {
	storePath, err := getTestStorePath()
	if err != nil {
		return nil, err
	}
	defer cleanup()

	d := NewDriver(machineTestName, storePath)
	d.SetConfigFromFlags(getDefaultTestDriverFlags())
	drv := d.(*Driver)
	return drv, nil
}

func TestUnmarshalJSON(t *testing.T) {
	driver := NewDriver("", "").(*Driver)

	// Unmarhsal driver configuration from JSON, envvars, and args.
	assert.NoError(t, os.Setenv("SOFTLAYER_API_ENDPOINT", "test API endpoint"))
	os.Args = append(os.Args, []string{"--softlayer-user", "test user"}...)
	os.Args = append(os.Args, []string{"--softlayer-api-key", "test API key"}...)

	driverBytes, err := json.Marshal(driver)
	assert.NoError(t, err)
	assert.NoError(t, json.Unmarshal(driverBytes, driver))

	// Make sure that config has been pulled in from envvars and args.
	assert.Equal(t, "test API endpoint", driver.Client.Endpoint)
	assert.Equal(t, "test user", driver.Client.User)
	assert.Equal(t, "test API key", driver.Client.ApiKey)
}

func TestSetConfigFromFlagsSetsImage(t *testing.T) {
	d, err := getTestDriver()

	if assert.NoError(t, err) {
		assert.Equal(t, "MY_TEST_IMAGE", d.deviceConfig.Image)
	}
}

func TestHostnameDefaultsToMachineName(t *testing.T) {
	d, err := getTestDriver()
	if assert.NoError(t, err) {
		assert.Equal(t, machineTestName, d.deviceConfig.Hostname)
	}
}

func TestSetConfigFromFlags(t *testing.T) {
	driver := NewDriver("default", "path")

	checkFlags := &drivers.CheckDriverOptions{
		FlagsValues: map[string]interface{}{
			"softlayer-api-key":      "KEY",
			"softlayer-user":         "user",
			"softlayer-api-endpoint": "ENDPOINT",
			"softlayer-domain":       "DOMAIN",
			"softlayer-region":       "REGION",
		},
		CreateFlags: driver.GetCreateFlags(),
	}

	err := driver.SetConfigFromFlags(checkFlags)

	assert.NoError(t, err)
	assert.Empty(t, checkFlags.InvalidFlags)
}
