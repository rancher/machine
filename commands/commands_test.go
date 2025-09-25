package commands

import (
	"errors"
	"flag"
	"strings"
	"testing"

	"github.com/rancher/machine/commands/commandstest"
	"github.com/rancher/machine/drivers/fakedriver"
	"github.com/rancher/machine/libmachine"
	"github.com/rancher/machine/libmachine/crashreport"
	"github.com/rancher/machine/libmachine/host"
	"github.com/rancher/machine/libmachine/hosttest"
	"github.com/rancher/machine/libmachine/mcnerror"
	"github.com/rancher/machine/libmachine/provision"
	"github.com/rancher/machine/libmachine/state"
	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli"
)

func TestGetFlagValue(t *testing.T) {
	for _, tt := range []struct {
		args        []string
		flagShort   string
		flagLong    string
		envVar      string
		expectValue string
		expectOk    bool
	}{
		{
			args:        strings.Split("--driver none myhost --url https://test.com", " "),
			flagShort:   "--url",
			flagLong:    "-u",
			expectValue: "https://test.com",
			expectOk:    true,
		},
		{
			args:      strings.Split("myhost --url https://test.com", " "),
			flagShort: "--driver",
			flagLong:  "-d",
		},
		{
			args:      strings.Split("create -f", " "),
			flagShort: "--force",
			flagLong:  "-f",
			expectOk:  true,
		},
	} {
		value, ok := getFlagValue(tt.args, tt.flagLong, tt.flagShort, tt.envVar)
		assert.Equal(t, tt.expectValue, value)
		assert.Equal(t, tt.expectOk, ok)
	}
}

func TestRunActionForeachMachine(t *testing.T) {
	defer provision.SetDetector(&provision.StandardDetector{})
	provision.SetDetector(&provision.FakeDetector{
		Provisioner: provision.NewNetstatProvisioner(),
	})

	// Assume a bunch of machines in randomly started or
	// stopped states.
	machines := []*host.Host{
		{
			Name:       "foo",
			DriverName: "fakedriver",
			Driver: &fakedriver.Driver{
				MockState: state.Running,
			},
		},
		{
			Name:       "bar",
			DriverName: "fakedriver",
			Driver: &fakedriver.Driver{
				MockState: state.Stopped,
			},
		},
		{
			Name: "baz",
			// Ssh, don't tell anyone but this
			// driver only _thinks_ it's named
			// virtualbox...  (to test serial actions)
			// It's actually FakeDriver!
			DriverName: "virtualbox",
			Driver: &fakedriver.Driver{
				MockState: state.Stopped,
			},
		},
		{
			Name:       "spam",
			DriverName: "virtualbox",
			Driver: &fakedriver.Driver{
				MockState: state.Running,
			},
		},
		{
			Name:       "eggs",
			DriverName: "fakedriver",
			Driver: &fakedriver.Driver{
				MockState: state.Stopped,
			},
		},
		{
			Name:       "ham",
			DriverName: "fakedriver",
			Driver: &fakedriver.Driver{
				MockState: state.Running,
			},
		},
	}

	runActionForeachMachine("start", machines)

	for _, machine := range machines {
		machineState, _ := machine.Driver.GetState()

		assert.Equal(t, state.Running, machineState)
	}

	runActionForeachMachine("stop", machines)

	for _, machine := range machines {
		machineState, _ := machine.Driver.GetState()

		assert.Equal(t, state.Stopped, machineState)
	}
}

func TestPrintIPEmptyGivenLocalEngine(t *testing.T) {
	stdoutGetter := commandstest.NewStdoutGetter()
	defer stdoutGetter.Stop()

	host, _ := hosttest.GetDefaultTestHost()
	err := printIP(host)()

	assert.NoError(t, err)
	assert.Equal(t, "\n", stdoutGetter.Output())
}

func TestPrintIPPrintsGivenRemoteEngineIpv4(t *testing.T) {
	stdoutGetter := commandstest.NewStdoutGetter()
	defer stdoutGetter.Stop()

	host, _ := hosttest.GetDefaultTestHost()
	host.Driver = &fakedriver.Driver{
		MockState: state.Running,
		MockIP:    "1.2.3.4",
	}
	err := printIP(host)()

	assert.NoError(t, err)
	assert.Equal(t, "1.2.3.4\n", stdoutGetter.Output())
}
func TestPrintIPPrintsGivenRemoteEngineIpv6(t *testing.T) {
	stdoutGetter := commandstest.NewStdoutGetter()
	defer stdoutGetter.Stop()

	host, _ := hosttest.GetDefaultTestHost()
	host.Driver = &fakedriver.Driver{
		MockState: state.Running,
		MockIPv6:  "2001:db8:85a3::8a2e:370:7334",
	}
	err := printIP(host)()

	assert.NoError(t, err)
	assert.Equal(t, "2001:db8:85a3::8a2e:370:7334\n", stdoutGetter.Output())

}

func TestConsolidateError(t *testing.T) {
	cases := []struct {
		inputErrs   []error
		expectedErr error
	}{
		{
			inputErrs: []error{
				errors.New("Couldn't remove host 'bar'"),
			},
			expectedErr: errors.New("Couldn't remove host 'bar'"),
		},
		{
			inputErrs: []error{
				errors.New("Couldn't remove host 'bar'"),
				errors.New("Couldn't remove host 'foo'"),
			},
			expectedErr: errors.New("Couldn't remove host 'bar'\nCouldn't remove host 'foo'"),
		},
	}

	for _, c := range cases {
		assert.Equal(t, c.expectedErr, consolidateErrs(c.inputErrs))
	}
}

type MockCrashReporter struct {
	sent bool
}

func (m *MockCrashReporter) Send(err crashreport.CrashError) error {
	m.sent = true
	return nil
}

func TestSendCrashReport(t *testing.T) {
	defer func(fnOsExit func(code int)) { osExit = fnOsExit }(osExit)
	osExit = func(code int) {}

	defer func(factory func(baseDir string, apiKey string) crashreport.CrashReporter) {
		crashreport.NewCrashReporter = factory
	}(crashreport.NewCrashReporter)

	tests := []struct {
		description string
		err         error
		sent        bool
	}{
		{
			description: "Should send crash error",
			err: crashreport.CrashError{
				Cause:      errors.New("BUG"),
				Command:    "command",
				Context:    "context",
				DriverName: "virtualbox",
			},
			sent: true,
		},
		{
			description: "Should not send standard error",
			err:         errors.New("BUG"),
			sent:        false,
		},
	}

	for _, test := range tests {
		mockCrashReporter := &MockCrashReporter{}
		crashreport.NewCrashReporter = func(baseDir string, apiKey string) crashreport.CrashReporter {
			return mockCrashReporter
		}

		command := func(commandLine CommandLine, api libmachine.API) error {
			return test.err
		}

		context := cli.NewContext(cli.NewApp(), &flag.FlagSet{}, nil)
		runCommand(command)(context)

		assert.Equal(t, test.sent, mockCrashReporter.sent, test.description)
	}
}

func TestReturnExitCode1onError(t *testing.T) {
	command := func(commandLine CommandLine, api libmachine.API) error {
		return errors.New("foo is not bar")
	}

	exitCode := checkErrorCodeForCommand(command)

	assert.Equal(t, 1, exitCode)
}

func TestReturnExitCode3onErrorDuringPreCreate(t *testing.T) {
	command := func(commandLine CommandLine, api libmachine.API) error {
		return crashreport.CrashError{
			Cause: mcnerror.ErrDuringPreCreate{
				Cause: errors.New("foo is not bar"),
			},
		}
	}

	exitCode := checkErrorCodeForCommand(command)

	assert.Equal(t, 3, exitCode)
}

func checkErrorCodeForCommand(command func(commandLine CommandLine, api libmachine.API) error) int {
	var setExitCode int

	originalOSExit := osExit

	defer func() {
		osExit = originalOSExit
	}()

	osExit = func(code int) {
		setExitCode = code
	}

	context := cli.NewContext(cli.NewApp(), &flag.FlagSet{}, nil)
	runCommand(command)(context)

	return setExitCode
}
