package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// You can put your rancher-machine CLI tests here. Please make sure not to write tests that rely on any specific
// outputs from commands to stdout or stderr. This test suite is not intended as a means of testing command-line
// output, but rather as a means of ensuring that core rancher-machine commands can run and invoke a driver without
// issue. It is strongly recommended that you use the "noop" driver for these tests, as this test suite is not
// supposed to be used to test driver-specific logic.
//
// See TestMain for information about how to invoke these tests.

func TestCreate_DriverHelp(t *testing.T) {
	assertSuccess(t, "create --driver noop -h")
	assertSuccess(t, "create -d noop --help")
}

func TestCreateAndRm(t *testing.T) {
	// Create a new host with a custom URL.
	name := newHostName(t)
	assertSuccess(t, "create --driver noop --url https://test.com "+name)

	// Load and validate host info from config.json.
	host := loadHost(t, name)
	assert.Equal(t, name, host.Name)
	assert.Equal(t, "noop", host.DriverName)
	url, err := host.URL()
	assert.NoError(t, err)
	assert.Equal(t, "https://test.com", url)

	// Remove the host.
	assertSuccess(t, "rm "+name)
}

func TestCreateAndRm_UpdateConfig(t *testing.T) {
	// Create a new host with a custom URL.
	name := newHostName(t)
	assertSuccess(t, "create --driver noop --url https://test.com "+name)

	// Remove the host with a new URL.
	assertSuccess(t, "rm --update-config --url https://new-url.com "+name)
}

func TestCreateAndKill_UpdateConfig(t *testing.T) {
	// Create a new host with a custom URL.
	name := newHostName(t)
	assertSuccess(t, "create --driver noop --url https://test.com "+name)

	// Kill the host with a new URL.
	assertSuccess(t, "kill --update-config --url https://new-url.com "+name)

	// Load and validate host URL from config.json.
	host := loadHost(t, name)
	url, err := host.URL()
	assert.NoError(t, err)
	assert.Equal(t, "https://new-url.com", url)
}

func TestCreateAndStatus_UpdateConfig(t *testing.T) {
	// Create the host with a custom URL.
	name := newHostName(t)
	assertSuccess(t, "create -d noop --url https://test.com "+name)

	// Check the host status with a new URL.
	assertSuccess(t, "status --update-config --url https://new-url.com "+name)

	// Load and validate host URL from config.json.
	host := loadHost(t, name)
	url, err := host.URL()
	assert.NoError(t, err)
	assert.Equal(t, "https://new-url.com", url)
}

func TestCreate_InvalidDriver(t *testing.T) {
	// Try to create a host with an invalid driver.
	name := newHostName(t)
	assertFail(t, "create -d invalid-driver "+name)
}

func TestCreateAndInspect(t *testing.T) {
	// Create and inspect a host.
	name := newHostName(t)
	assertSuccess(t, "create --driver noop --url https://test.com "+name)
	assertSuccess(t, "inspect "+name)
}
