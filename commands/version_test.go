package commands

import (
	"bytes"
	"errors"
	"testing"

	"github.com/rancher/machine/commands/commandstest"
	"github.com/rancher/machine/libmachine/auth"
	"github.com/rancher/machine/libmachine/host"
	"github.com/rancher/machine/libmachine/libmachinetest"
	"github.com/rancher/machine/libmachine/mcndockerclient"
	"github.com/stretchr/testify/assert"
)

func TestCmdVersion(t *testing.T) {
	commandLine := &commandstest.FakeCommandLine{}
	api := &libmachinetest.FakeAPI{}

	err := cmdVersion(commandLine, api)

	assert.True(t, commandLine.VersionShown)
	assert.NoError(t, err)
}

func TestCmdVersionTooManyNames(t *testing.T) {
	commandLine := &commandstest.FakeCommandLine{
		CliArgs: []string{"machine1", "machine2"},
	}
	api := &libmachinetest.FakeAPI{}

	err := cmdVersion(commandLine, api)

	assert.EqualError(t, err, "Error: Expected one machine name as an argument")
}

func TestCmdVersionNotFound(t *testing.T) {
	commandLine := &commandstest.FakeCommandLine{
		CliArgs: []string{"unknown"},
	}
	api := &libmachinetest.FakeAPI{}

	err := cmdVersion(commandLine, api)

	assert.EqualError(t, err, `Docker machine "unknown" does not exist. Use "docker-machine ls" to list machines. Use "docker-machine create" to add a new one.`)
}

func TestCmdVersionOnHost(t *testing.T) {
	defer func(versioner mcndockerclient.DockerVersioner) { mcndockerclient.CurrentDockerVersioner = versioner }(mcndockerclient.CurrentDockerVersioner)
	mcndockerclient.CurrentDockerVersioner = &mcndockerclient.FakeDockerVersioner{Version: "1.9.1"}

	commandLine := &commandstest.FakeCommandLine{
		CliArgs: []string{"machine"},
	}
	api := &libmachinetest.FakeAPI{
		Hosts: []*host.Host{
			{
				Name: "machine",
				HostOptions: &host.Options{
					AuthOptions: &auth.Options{},
				},
			},
		},
	}

	out := &bytes.Buffer{}
	err := printVersion(commandLine, api, out)

	assert.NoError(t, err)
	assert.Equal(t, "1.9.1\n", out.String())
}

func TestCmdVersionFailure(t *testing.T) {
	defer func(versioner mcndockerclient.DockerVersioner) { mcndockerclient.CurrentDockerVersioner = versioner }(mcndockerclient.CurrentDockerVersioner)
	mcndockerclient.CurrentDockerVersioner = &mcndockerclient.FakeDockerVersioner{Err: errors.New("connection failure")}

	commandLine := &commandstest.FakeCommandLine{
		CliArgs: []string{"machine"},
	}
	api := &libmachinetest.FakeAPI{
		Hosts: []*host.Host{
			{
				Name: "machine",
				HostOptions: &host.Options{
					AuthOptions: &auth.Options{},
				},
			},
		},
	}

	out := &bytes.Buffer{}
	err := printVersion(commandLine, api, out)

	assert.EqualError(t, err, "connection failure")
}
