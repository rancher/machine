package commands

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/rancher/machine/commands/mcndirs"
	"github.com/rancher/machine/libmachine"
	"github.com/rancher/machine/libmachine/crashreport"
	"github.com/rancher/machine/libmachine/drivers"
	"github.com/rancher/machine/libmachine/host"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcnerror"
	"github.com/rancher/machine/libmachine/mcnutils"
	"github.com/rancher/machine/libmachine/persist"
	"github.com/rancher/machine/libmachine/ssh"
	"github.com/urfave/cli"
)

const (
	defaultMachineName = "default"
)

var (
	ErrHostLoad           = errors.New("All specified hosts had errors loading their configuration")
	ErrNoDefault          = fmt.Errorf("Error: No machine name(s) specified and no %q machine exists", defaultMachineName)
	ErrNoMachineSpecified = errors.New("Error: Expected to get one or more machine names as arguments")
	ErrExpectedOneMachine = errors.New("Error: Expected one machine name as an argument")
	ErrTooManyArguments   = errors.New("Error: Too many arguments given")

	osExit = func(code int) { os.Exit(code) }

	// We have to declare the "update-config" flag in two different ways because of limitations in the CLI library
	// we're using.
	updateConfigGenericFlag = cli.GenericFlag{
		Name: "update-config",
	}
	updateConfigBoolFlag = cli.BoolFlag{
		Name: "update-config",
	}
)

// cmdHandler is a function that handles a command.
type cmdHandler func(CommandLine, libmachine.API) error

// CommandLine contains all the information passed to the commands on the command line.
type CommandLine interface {
	ShowHelp()

	ShowVersion()

	Application() *cli.App

	Args() cli.Args

	IsSet(name string) bool

	Bool(name string) bool

	Int(name string) int

	String(name string) string

	StringSlice(name string) []string

	GlobalString(name string) string

	FlagNames() (names []string)

	Generic(name string) interface{}
}

type contextCommandLine struct {
	*cli.Context
}

func (c *contextCommandLine) ShowHelp() {
	cli.ShowCommandHelp(c.Context, c.Command.Name)
}

func (c *contextCommandLine) ShowVersion() {
	cli.ShowVersion(c.Context)
}

func (c *contextCommandLine) Application() *cli.App {
	return c.App
}

// targetHost returns a specific host name if one is indicated by the first CLI
// arg, or the default host name if no host is specified.
func targetHost(c CommandLine, api libmachine.API) (string, error) {
	if len(c.Args()) == 0 {
		defaultExists, err := api.Exists(defaultMachineName)
		if err != nil {
			return "", fmt.Errorf("Error checking if host %q exists: %s", defaultMachineName, err)
		}

		if defaultExists {
			return defaultMachineName, nil
		}

		return "", ErrNoDefault
	}

	return c.Args()[0], nil
}

func runAction(actionName string, c CommandLine, api libmachine.API) error {
	var (
		hostsToLoad []string
	)

	// If user did not specify a machine name explicitly, use the 'default'
	// machine if it exists.  This allows short form commands such as
	// 'docker-machine stop' for convenience.
	if len(c.Args()) == 0 {
		target, err := targetHost(c, api)
		if err != nil {
			return err
		}

		hostsToLoad = []string{target}
	} else {
		hostsToLoad = c.Args()
	}

	hosts, hostsInError := persist.LoadHosts(api, hostsToLoad)

	if len(hostsInError) > 0 {
		errs := []error{}
		for _, err := range hostsInError {
			errs = append(errs, err)
		}
		return consolidateErrs(errs)
	}

	if len(hosts) == 0 {
		return ErrHostLoad
	}

	if errs := runActionForeachMachine(actionName, hosts); len(errs) > 0 {
		return consolidateErrs(errs)
	}

	for _, h := range hosts {
		if err := api.Save(h); err != nil {
			return fmt.Errorf("Error saving host to store: %s", err)
		}
	}

	return nil
}

func runCommand(command func(commandLine CommandLine, api libmachine.API) error) func(context *cli.Context) {
	return func(context *cli.Context) {
		api := libmachine.NewClient(context.GlobalString("storage-path"), mcndirs.GetMachineCertDir())
		defer api.Close()

		if context.GlobalBool("native-ssh") {
			api.SSHClientType = ssh.Native
		}
		api.GithubAPIToken = context.GlobalString("github-api-token")

		// TODO (nathanleclaire): These should ultimately be accessed
		// through the libmachine client by the rest of the code and
		// not through their respective modules.  For now, however,
		// they are also being set the way that they originally were
		// set to preserve backwards compatibility.
		mcndirs.BaseDir = context.GlobalString("storage-path")
		mcnutils.GithubAPIToken = api.GithubAPIToken
		ssh.SetDefaultClient(api.SSHClientType)

		secretName, secretNamespace := context.GlobalString("secret-name"), context.GlobalString("secret-namespace")
		if secretName != "" {
			secretStore, err := persist.NewSecretStore(api.Store, secretName, secretNamespace, context.GlobalString("kubeconfig"))
			if err != nil {
				log.Error(err)
				osExit(1)
				return
			}

			api.Store = secretStore
		}

		if err := command(&contextCommandLine{context}, api); err != nil {
			log.Error(err)

			if crashErr, ok := err.(crashreport.CrashError); ok {
				crashReporter := crashreport.NewCrashReporter(mcndirs.GetBaseDir(), context.GlobalString("bugsnag-api-token"))
				crashReporter.Send(crashErr)

				if _, ok := crashErr.Cause.(mcnerror.ErrDuringPreCreate); ok {
					osExit(3)
					return
				}
			} else if _, ok := err.(notFoundError); ok {
				osExit(4)
				return
			}

			osExit(1)
			return
		}
	}
}

func confirmInput(msg string) (bool, error) {
	fmt.Printf("%s (y/n): ", msg)

	var resp string
	_, err := fmt.Scanln(&resp)
	if err != nil {
		return false, err
	}

	confirmed := strings.Index(strings.ToLower(resp), "y") == 0
	return confirmed, nil
}

var Commands = []cli.Command{
	{
		Name:   "active",
		Usage:  "Print which machine is active",
		Action: runCommand(cmdActive),
		Flags: []cli.Flag{
			cli.IntFlag{
				Name:  "timeout, t",
				Usage: fmt.Sprintf("Timeout in seconds, default to %ds", activeDefaultTimeout),
				Value: activeDefaultTimeout,
			},
		},
	},
	{
		Name:        "config",
		Usage:       "Print the connection config for machine",
		Description: "Argument is a machine name.",
		Action:      runCommand(cmdConfig),
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "swarm",
				Usage: "Display the Swarm config instead of the Docker daemon",
			},
		},
	},
	{
		Flags:       SharedCreateFlags,
		Name:        "create",
		Usage:       "Create a machine",
		Description: fmt.Sprintf("Run '%s create --driver name --help' to include the create flags for that driver in the help text.", os.Args[0]),
		Action: runCommand(withDriverFlags("create", false, &cli.GenericFlag{
			Name:   "driver, d",
			EnvVar: "MACHINE_DRIVER",
		}, cmdCreate)),
		SkipFlagParsing: true,
	},
	{
		Name:        "env",
		Usage:       "Display the commands to set up the environment for the Docker client",
		Description: "Argument is a machine name.",
		Action:      runCommand(cmdEnv),
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "swarm",
				Usage: "Display the Swarm config instead of the Docker daemon",
			},
			cli.StringFlag{
				Name:  "shell",
				Usage: "Force environment to be configured for a specified shell: [fish, cmd, powershell, tcsh, emacs], default is auto-detect",
			},
			cli.BoolFlag{
				Name:  "unset, u",
				Usage: "Unset variables instead of setting them",
			},
			cli.BoolFlag{
				Name:  "no-proxy",
				Usage: "Add machine IP to NO_PROXY environment variable",
			},
		},
	},
	{
		Name:        "inspect",
		Usage:       "Inspect information about a machine",
		Description: "Argument is a machine name.",
		Action:      runCommand(cmdInspect),
		Flags: []cli.Flag{
			cli.StringFlag{
				Name:  "format, f",
				Usage: "Format the output using the given go template.",
				Value: "",
			},
		},
	},
	{
		Name:        "ip",
		Usage:       "Get the IP address of a machine",
		Description: "Argument(s) are one or more machine names.",
		Action:      runCommand(cmdIP),
	},
	{
		Name:            "kill",
		Usage:           "Kill a machine",
		Description:     "Argument(s) are one or more machine names.",
		Action:          runCommand(withDriverFlags("kill", true, &updateConfigGenericFlag, cmdKill)),
		Flags:           []cli.Flag{updateConfigBoolFlag},
		SkipFlagParsing: true,
	},
	{
		Name:   "ls",
		Usage:  "List machines",
		Action: runCommand(cmdLs),
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "quiet, q",
				Usage: "Enable quiet mode",
			},
			cli.StringSliceFlag{
				Name:  "filter",
				Usage: "Filter output based on conditions provided",
				Value: &cli.StringSlice{},
			},
			cli.IntFlag{
				Name:  "timeout, t",
				Usage: fmt.Sprintf("Timeout in seconds, default to %ds", lsDefaultTimeout),
				Value: lsDefaultTimeout,
			},
			cli.StringFlag{
				Name:  "format, f",
				Usage: "Pretty-print machines using a Go template",
			},
		},
	},
	{
		Name:            "provision",
		Usage:           "Re-provision existing machines",
		Action:          runCommand(withDriverFlags("provision", true, &updateConfigGenericFlag, cmdProvision)),
		Flags:           []cli.Flag{updateConfigBoolFlag},
		SkipFlagParsing: true,
	},
	{
		Name:        "regenerate-certs",
		Usage:       "Regenerate TLS Certificates for a machine",
		Description: "Argument(s) are one or more machine names.",
		Action:      runCommand(cmdRegenerateCerts),
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "force, f",
				Usage: "Force rebuild and do not prompt",
			},
			cli.BoolFlag{
				Name:  "client-certs",
				Usage: "Also regenerate client certificates and CA.",
			},
		},
	},
	{
		Name:        "restart",
		Usage:       "Restart a machine",
		Description: "Argument(s) are one or more machine names.",
		Action:      runCommand(cmdRestart),
	},
	{
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "force, f",
				Usage: "Remove local configuration even if machine cannot be removed, also implies an automatic yes (`-y`)",
			},
			cli.BoolFlag{
				Name:  "y",
				Usage: "Assumes automatic yes to proceed with remove, without prompting further user confirmation",
			},
			updateConfigBoolFlag,
		},
		Name:            "rm",
		Usage:           "Remove a machine",
		Description:     "Argument(s) are one or more machine names.",
		Action:          runCommand(withDriverFlags("rm", true, &updateConfigGenericFlag, cmdRm)),
		SkipFlagParsing: true,
	},
	{
		Name:            "ssh",
		Usage:           "Log into or run a command on a machine with SSH.",
		Description:     "Arguments are [machine-name] [command]",
		Action:          runCommand(cmdSSH),
		SkipFlagParsing: true,
	},
	{
		Name:        "scp",
		Usage:       "Copy files between machines",
		Description: "Arguments are [[user@]machine:][path] [[user@]machine:][path].",
		Action:      runCommand(cmdScp),
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "recursive, r",
				Usage: "Copy files recursively (required to copy directories)",
			},
			cli.BoolFlag{
				Name:  "delta, d",
				Usage: "Reduce amount of data sent over network by sending only the differences (uses rsync)",
			},
			cli.BoolFlag{
				Name:  "quiet, q",
				Usage: "Disables the progress meter as well as warning and diagnostic messages from ssh",
			},
		},
	},
	{
		Name:        "mount",
		Usage:       "Mount or unmount a directory from a machine with SSHFS.",
		Description: "Arguments are [machine:][path] [mountpoint]",
		Action:      runCommand(cmdMount),
		Flags: []cli.Flag{
			cli.BoolFlag{
				Name:  "unmount, u",
				Usage: "Unmount instead of mount",
			},
		},
	},
	{
		Name:        "start",
		Usage:       "Start a machine",
		Description: "Argument(s) are one or more machine names.",
		Action:      runCommand(cmdStart),
	},
	{
		Name:            "status",
		Usage:           "Get the status of a machine",
		Description:     "Argument is a machine name.",
		Action:          runCommand(withDriverFlags("status", true, &updateConfigGenericFlag, cmdStatus)),
		Flags:           []cli.Flag{updateConfigBoolFlag},
		SkipFlagParsing: true,
	},
	{
		Name:        "stop",
		Usage:       "Stop a machine",
		Description: "Argument(s) are one or more machine names.",
		Action:      runCommand(cmdStop),
	},
	{
		Name:        "upgrade",
		Usage:       "Upgrade a machine to the latest version of Docker",
		Description: "Argument(s) are one or more machine names.",
		Action:      runCommand(cmdUpgrade),
	},
	{
		Name:            "url",
		Usage:           "Get the URL of a machine",
		Description:     "Argument is a machine name.",
		Action:          runCommand(withDriverFlags("url", true, &updateConfigGenericFlag, cmdURL)),
		Flags:           []cli.Flag{updateConfigBoolFlag},
		SkipFlagParsing: true,
	},
	{
		Name:   "version",
		Usage:  "Show the Docker Machine version or a machine docker version",
		Action: runCommand(cmdVersion),
	},
}

func printIP(h *host.Host) func() error {
	return func() error {
		// preference: IPv4 address, then IPv6 address
		ip, err := h.Driver.GetIP()
		if err != nil {
			log.Warnf("Error getting IPv4 address: %s", err)
			log.Debug("Getting IPv6 address")
			ip, err = h.Driver.GetIPv6()
			if err != nil {
				return fmt.Errorf("error getting IPv6 address: %s", err)
			}
		}

		fmt.Println(ip)

		return nil
	}
}

// machineCommand maps the command name to the corresponding machine command.
// We run commands concurrently and communicate back an error if there was one.
func machineCommand(actionName string, host *host.Host, errorChan chan<- error) {
	// TODO: These actions should have their own type.
	commands := map[string](func() error){
		"configureAuth":    host.ConfigureAuth,
		"configureAllAuth": host.ConfigureAllAuth,
		"start":            host.Start,
		"stop":             host.Stop,
		"restart":          host.Restart,
		"kill":             host.Kill,
		"upgrade":          host.Upgrade,
		"ip":               printIP(host),
		"provision":        host.Provision,
	}

	log.Debugf("command=%s machine=%s", actionName, host.Name)

	errorChan <- commands[actionName]()
}

// runActionForeachMachine will run the command across multiple machines
func runActionForeachMachine(actionName string, machines []*host.Host) []error {
	var (
		numConcurrentActions = 0
		errorChan            = make(chan error)
		errs                 = []error{}
	)

	for _, machine := range machines {
		numConcurrentActions++
		go machineCommand(actionName, machine, errorChan)
	}

	// TODO: We should probably only do 5-10 of these
	// at a time, since otherwise cloud providers might
	// rate limit us.
	for i := 0; i < numConcurrentActions; i++ {
		if err := <-errorChan; err != nil {
			errs = append(errs, err)
		}
	}

	close(errorChan)

	return errs
}

func consolidateErrs(errs []error) error {
	finalErr := ""
	for _, err := range errs {
		finalErr = fmt.Sprintf("%s\n%s", finalErr, err)
	}

	return errors.New(strings.TrimSpace(finalErr))
}

// withDriverFlags wraps the given command `handler` with the given name with a handler that will look for
// driver-specific flags and parse them before executing the command handler. If `fromExistingHost` is true, the wrapper
// function will try to look up driver flags using an existing host named in a command-line argument. Otherwise, the
// wrapper will try to look up driver flags using either the driver named in the `--driver` flag or the `MACHINE_DRIVER`
// ennvar.
func withDriverFlags(
	cmdName string,
	fromExistingHost bool,
	requiredFlag *cli.GenericFlag,
	handler cmdHandler,
) cmdHandler {
	return func(c CommandLine, api libmachine.API) error {
		// If a required flag was specified, we need to make sure its value is set (either via envvars or CLI flags)
		// before attempting to load driver config. If it is not set anywhere, we don't load driver config.
		if requiredFlag != nil {
			// Handle cases where flag names contain comma-separated long and short versions.
			flagNameParts := strings.SplitN(requiredFlag.Name, ",", 2)
			flagLong := "--" + strings.TrimSpace(flagNameParts[0])
			flagShort := ""
			if len(flagNameParts) > 1 {
				flagShort = "-" + strings.TrimSpace(flagNameParts[1])
			}

			if _, ok := getFlagValue(c.Args(), flagLong, flagShort, requiredFlag.EnvVar); !ok {
				return updateAndRunCommand(c, cmdName, nil, handler)
			}
		}

		// To determine what driver flags we need to parse, we'll either get the driver name from an existing host or
		// from the --driver flag or MACHINE_DRIVER envvar.
		var driverName string
		if fromExistingHost {
			// The host name should be the last argument because the CLI library doesn't allow options after arguments.
			hostName := c.Args()[len(c.Args())-1]
			h, err := api.Load(hostName)
			if err != nil {
				return fmt.Errorf("error loading host %s: %w", hostName, err)
			}

			driverName = h.DriverName
		} else {
			var ok bool
			if driverName, ok = getFlagValue(c.Args(), "--driver", "-d", "MACHINE_DRIVER"); !ok {
				driverName = "virtualbox"
			}
		}

		// If the driver is still not defined, we'll assume it's not available because it wasn't specified and just run
		// the command.
		if driverName == "" {
			return updateAndRunCommand(c, cmdName, nil, handler)
		}

		// Create a new empty host object with the driver. Unfortunately, this is the only way of getting driver args
		// at the moment.
		rawDriver, err := json.Marshal(&drivers.BaseDriver{MachineName: "temp-driver-loader"})
		if err != nil {
			return fmt.Errorf("error marshalling base driver: %w", err)
		}

		h, err := api.NewHost(driverName, rawDriver)
		if err != nil {
			return err
		}

		// Convert driver flags into CLI flags.
		driverFlags := h.Driver.GetCreateFlags()
		driverCLIFlags, err := convertMcnFlagsToCliFlags(driverFlags)
		if err != nil {
			return fmt.Errorf("error converting driver flags to CLI flags: %w", err)
		}

		return updateAndRunCommand(c, cmdName, driverCLIFlags, handler)
	}
}

// updateAndRunCommand add the given driver-specific flags to the command with the given name and reruns the CLI app
// to execute the given handler function.
func updateAndRunCommand(c CommandLine, cmdName string, flags []cli.Flag, handler cmdHandler) error {
	// Get a pointer to the current command being executed. This has to be done by accessing the `Commands` slice
	// directly, again, because of problems with the CLI library we're using.
	for i := range c.Application().Commands {
		cmd := &c.Application().Commands[i]
		if cmd.HasName(cmdName) {
			cmd.Flags = append(cmd.Flags, flags...)
			cmd.SkipFlagParsing = false
			cmd.Action = runCommand(handler)
			sort.Sort(ByFlagName(cmd.Flags))

			// Re-run the CLI app to the new flags are parsed and the handler command gets executed.
			return c.Application().Run(os.Args)
		}
	}

	return fmt.Errorf("command not found: %s", cmdName)
}

// getFlagValue returns the value associated with the given flag and true if the flag was found in the arguments or
// envvars, or an empty string and false otherwise.
func getFlagValue(args []string, long, short, envvar string) (string, bool) {
	if value, ok := os.LookupEnv(envvar); ok {
		return value, true
	}

	for i, arg := range args {
		flagParts := strings.SplitN(arg, "=", 2)
		if flagParts[0] == long || flagParts[0] == short {
			// If the flag has multiple parts separated by "=", return everything in the flag to the right of "=".
			if len(flagParts) > 1 {
				return flagParts[1], true
			}

			// At this point we know the flag is either a simple boolean flag, or its value is the next arg.
			if len(args) > i+1 && !strings.HasPrefix(args[i+1], "-") {
				return args[i+1], true
			}

			return "", true
		}
	}

	return "", false
}
