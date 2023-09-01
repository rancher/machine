package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rancher/machine/drivers/none"
	"github.com/rancher/machine/libmachine/host"
	"github.com/stretchr/testify/assert"
)

var (
	// testDataPath is the directory in which commands run during tests should place any files they create. This should
	// be set in TestMain.
	testDataPath string

	// logCommandOutput indicates whether to log command stdout and stderr if a test fails. This should be set in
	// TestMain.
	logCommandOutput bool

	// logCommandOutputOnFail indicates whether to log command stdout and stderr if a test fails. This should be set in
	// TestMain.
	logCommandOutputOnFail bool

	// executablePath is the path to the rancher-machine binary to be executed in tests.
	executablePath string
)

// TestMain tests up and runs all tests in this package. The tests can be invoked as follows:
//
//  1. Build the rancher-machine binary that you'd like to test.
//
//  2. Run the tests. Note that the -v flag should be set on the "go test" command to ensure that go test doesn't
//     swallow all command output.
//
//     If you want to test the binary at path/to/binary, logging all command output from tests:
//     $ go test -v ./... -args -log -exec-path path/to/binary
//
//     If you want to run the rancher-machine binary in the default location (./rancher-machine) with default logging
//     (only log on failure):
//     $ go test -v ./...
func TestMain(m *testing.M) {
	// Check if we should log command output.
	//
	// Testing with all command logging enabled (-v required so go test doesn't capture output):
	//
	// 		$ go test -v ./... -args -log -exec-path path/to/rancher-machine
	//
	// Testing with only command logging on test failure (-v required so go test doesn't capture output):
	//
	//		$ go test -v ./... -args -log-fail -exec-path path/to/rancher-machine
	flag.BoolVar(
		&logCommandOutput,
		"log",
		false,
		"Log all command stdout and stderr in tests (default: false)",
	)
	flag.BoolVar(
		&logCommandOutputOnFail,
		"log-fail",
		true,
		"Log all command stdout and stderr on test failures (default: true)",
	)
	flag.StringVar(
		&executablePath,
		"exec-path",
		"./rancher-machine",
		"Path to the rancher-machine binary to test (default: ./rancher-machine)",
	)
	flag.Parse()

	// Get the current working directory.
	curDir, err := os.Getwd()
	if err != nil {
		fmt.Printf("error getting working directory: %v", err)
		os.Exit(1)
	}

	// Make sure that the rancher-machine binary is available in the current directory as it is invoked in tests.
	stat, err := os.Stat(executablePath)
	if err != nil || stat.IsDir() || !stat.Mode().IsRegular() {
		fmt.Printf(
			"invalid test executable %s: %v\n%s",
			executablePath,
			err,
			"Use flag -exec-path to specify the path to the rancher-machine binary you want to test.",
		)
		os.Exit(1)
	}

	// If a test data directory already exists, clear it.
	testDataPath = filepath.Join(curDir, "test-data")
	if err = os.RemoveAll(testDataPath); err != nil {
		fmt.Printf("error removing direcotry %s: %v", testDataPath, err)
		os.Exit(1)
	}

	// Create a directory for temporary test data.
	if err = os.MkdirAll(testDataPath, 0750); err != nil {
		fmt.Printf("error creating direcotry %s: %v", testDataPath, err)
		os.Exit(1)
	}

	// Run the test suite.
	os.Exit(m.Run())
}

// assertSuccess runs the rancher-machine binary with the given args and asserts that it succeeds.
func assertSuccess(t *testing.T, args string) {
	testCmd(t, args, false)
}

// assertSuccess runs the rancher-machine binary with the given args and asserts that it fails.
func assertFail(t *testing.T, args string) {
	testCmd(t, args, true)
}

// testCmd runs the "./rancher-machine" command with the given args in a subprocess. If expectFail is true, it will
// assert that the command invocation fails. Otherwise, it will assert that it succeeds.
func testCmd(t *testing.T, args string, expectFail bool) {
	// Create the command from the given args.
	cmd := exec.Command(executablePath, strings.Split(args, " ")...)

	// Set machine storage path to the test data path. This way, the command will write all its output files to that
	// path instead of muddying up the host.
	cmd.Env = append(cmd.Env, fmt.Sprintf("MACHINE_STORAGE_PATH=%s", testDataPath))

	// Run the command and get all its output from stdout and stderr.
	output, err := cmd.CombinedOutput()

	// Log command output, if necessary.
	if logCommandOutput && len(output) > 0 {
		t.Log(string(output))
	}

	// Check the command result matches what we expected.
	if err != nil && !expectFail {
		// Log command output, if necessary (only do this if we haven't logged it already).
		if !logCommandOutput && logCommandOutputOnFail && len(output) > 0 {
			t.Log(string(output))
		}

		// For debugging purposes, it's helpful to distinguish errors in the command itself from other things like
		// IO errors that prevented the command from running properly in the first place.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Errorf("command failed: %v", exitErr)
		} else {
			t.Errorf("error waiting for command to execute: %v", err)
		}
	} else if err == nil && expectFail {
		// Log command output, if necessary (only do this if we haven't logged it already).
		if !logCommandOutput && logCommandOutputOnFail && len(output) > 0 {
			t.Log(string(output))
		}

		t.Error("expected command to fail, but it succeeded")
	}
}

// newHostName creates a new host name from the test name. This is useful for debugging.
func newHostName(t *testing.T) string {
	return strings.ReplaceAll(t.Name(), "_", "-")
}

// loadHost loads host data from the test data directory.
func loadHost(t *testing.T, name string) *host.Host {
	file, err := os.Open(filepath.Join(testDataPath, "machines", name, "config.json"))
	assert.NoError(t, err, "error opening machine config file")

	h := host.Host{
		Driver: none.NewDriver("", ""),
	}
	assert.NoError(t, json.NewDecoder(file).Decode(&h), "error decoding machine config from JSON")

	return &h
}
