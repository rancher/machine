package exoscale

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	exov2 "github.com/exoscale/egoscale/v2"
	"github.com/rancher/machine/libmachine/drivers"
	rpcdriver "github.com/rancher/machine/libmachine/drivers/rpc"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcnflag"
	"github.com/rancher/machine/libmachine/mcnutils"
	"github.com/rancher/machine/libmachine/ssh"
	"github.com/rancher/machine/libmachine/state"
)

// Driver is the struct compatible with github.com/rancher/machine/libmachine/drivers.Driver interface
type Driver struct {
	*drivers.BaseDriver
	URL                  string
	APIKey               string `json:"ApiKey"`
	APISecretKey         string `json:"ApiSecretKey"`
	InstanceType         string
	DiskSize             int64
	Image                string
	SecurityGroups       []string
	AntiAffinityGroups   []string
	AvailabilityZone     string
	SSHKey               string
	ExoSSHKey            *exov2.SSHKey
	PublicKey            string
	UserDataFile         string
	UserData             []byte
	ID                   string `json:"Id"`
}

const (
    defaultAPIEndpoint       = "https://api-ch-dk-2.exoscale.ch/v2"
	defaultInstanceType      = "Small"
	defaultDiskSize          = 50
	defaultImage             = "Linux Ubuntu 24.04 LTS 64-bit"
	defaultAvailabilityZone  = "CH-DK-2"
	defaultSSHUser           = "root"
	defaultSecurityGroup     = "rancher-machine"
	defaultCloudInit         = `#cloud-config
manage_etc_hosts: localhost
`
)

// GetCreateFlags registers the flags this driver adds to
// "docker hosts create"
func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			EnvVar: "EXOSCALE_ENDPOINT",
			Name:   "exoscale-url",
			Value:  defaultAPIEndpoint,
			Usage:  "exoscale API endpoint",
		},
		mcnflag.StringFlag{
			EnvVar: "EXOSCALE_API_KEY",
			Name:   "exoscale-api-key",
			Usage:  "exoscale API key",
		},
		mcnflag.StringFlag{
			EnvVar: "EXOSCALE_API_SECRET",
			Name:   "exoscale-api-secret-key",
			Usage:  "exoscale API secret key",
		},
		mcnflag.StringFlag{
			EnvVar: "EXOSCALE_INSTANCE_TYPE",
			Name:   "exoscale-instance-type",
			Value:  defaultInstanceType,
			Usage:  "exoscale instance type (Small, Medium, Large, ...)",
		},
		mcnflag.IntFlag{
			EnvVar: "EXOSCALE_DISK_SIZE",
			Name:   "exoscale-disk-size",
			Value:  defaultDiskSize,
			Usage:  "exoscale disk size (10, 50, 100, 200, 400)",
		},
		mcnflag.StringFlag{
			EnvVar: "EXOSCALE_IMAGE",
			Name:   "exoscale-image",
			Value:  defaultImage,
			Usage:  "exoscale image template",
		},
		mcnflag.StringSliceFlag{
			EnvVar: "EXOSCALE_SECURITY_GROUP",
			Name:   "exoscale-security-group",
			Value:  []string{defaultSecurityGroup},
			Usage:  "exoscale security group",
		},
		mcnflag.StringFlag{
			EnvVar: "EXOSCALE_AVAILABILITY_ZONE",
			Name:   "exoscale-availability-zone",
			Value:  defaultAvailabilityZone,
			Usage:  "exoscale availability zone",
		},
		mcnflag.StringFlag{
			EnvVar: "EXOSCALE_SSH_USER",
			Name:   "exoscale-ssh-user",
			Value:  "",
			Usage:  "name of the ssh user",
		},
		mcnflag.StringFlag{
			EnvVar: "EXOSCALE_SSH_KEY",
			Name:   "exoscale-ssh-key",
			Value:  "",
			Usage:  "path to the SSH user private key",
		},
		mcnflag.StringFlag{
			EnvVar: "EXOSCALE_USERDATA",
			Name:   "exoscale-userdata",
			Usage:  "path to file with cloud-init user-data",
		},
		mcnflag.StringSliceFlag{
			EnvVar: "EXOSCALE_ANTI_AFFINITY_GROUP",
			Name:   "exoscale-anti-affinity-group",
			Value:  []string{},
			Usage:  "exoscale anti affinity group",
		},
	}
}

// NewDriver creates a Driver with the specified machineName and storePath.
func NewDriver(machineName, storePath string) drivers.Driver {
	return &Driver{
		InstanceType:     defaultInstanceType,
		DiskSize:         defaultDiskSize,
		Image:            defaultImage,
		AvailabilityZone: defaultAvailabilityZone,
		BaseDriver: &drivers.BaseDriver{
			MachineName: machineName,
			StorePath:   storePath,
		},
	}
}

// GetSSHHostname returns the hostname to use with SSH
func (d *Driver) GetSSHHostname() (string, error) {
	return d.GetIP()
}

// GetSSHUsername returns the username to use with SSH
func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		name := strings.ToLower(d.Image)

		if strings.Contains(name, "ubuntu") {
			return "ubuntu"
		}
		if strings.Contains(name, "centos") {
			return "centos"
		}
		if strings.Contains(name, "redhat") {
			return "cloud-user"
		}
		if strings.Contains(name, "fedora") {
			return "fedora"
		}
		if strings.Contains(name, "coreos") {
			return "core"
		}
		if strings.Contains(name, "debian") {
			return "debian"
		}
        if strings.Contains(name, "rocky") {
			return "rockylinux"
		}
		return defaultSSHUser
	}

	return d.SSHUser
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return "exoscale"
}

// UnmarshalJSON loads driver config from JSON. This function is used by the RPCServerDriver that wraps
// all drivers as a means of populating an already-initialized driver with new configuration.
// See `RPCServerDriver.SetConfigRaw`.
func (d *Driver) UnmarshalJSON(data []byte) error {
	// Unmarshal driver config into an aliased type to prevent infinite recursion on UnmarshalJSON.
	type targetDriver Driver

	// Copy data from `d` to `target` before unmarshalling. This will ensure that already-initialized values
	// from `d` that are left untouched during unmarshal (like functions) are preserved.
	target := targetDriver(*d)

	if err := json.Unmarshal(data, &target); err != nil {
		return fmt.Errorf("error unmarshalling driver config from JSON: %w", err)
	}

	// Copy unmarshalled data back to `d`.
	*d = Driver(target)

	// Make sure to reload values that are subject to change from envvars and os.Args.
	driverOpts := rpcdriver.GetDriverOpts(d.GetCreateFlags(), os.Args)
	if _, ok := driverOpts.Values["exoscale-api-key"]; ok {
		d.APIKey = driverOpts.String("exoscale-api-key")
	}

	if _, ok := driverOpts.Values["exoscale-api-secret-key"]; ok {
		d.APISecretKey = driverOpts.String("exoscale-api-secret-key")
	}

	return nil
}

//TODO: Check api endpoint ?? !!
// SetConfigFromFlags configures the driver with the object that was returned
// by RegisterCreateFlags
func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.URL = flags.String("exoscale-url")
	d.APIKey = flags.String("exoscale-api-key")
	d.APISecretKey = flags.String("exoscale-api-secret-key")
	d.InstanceType = flags.String("exoscale-instance-type")
	d.DiskSize = int64(flags.Int("exoscale-disk-size"))
	d.Image = flags.String("exoscale-image")
	d.SecurityGroups = flags.StringSlice("exoscale-security-group")
	d.AntiAffinityGroups = flags.StringSlice("exoscale-anti-affinity-group")
	d.AvailabilityZone = strings.ToLower(flags.String("exoscale-availability-zone"))
	d.SSHUser = flags.String("exoscale-ssh-user")
	d.SSHKey = flags.String("exoscale-ssh-key")
	d.UserDataFile = flags.String("exoscale-userdata")
	d.UserData = []byte(defaultCloudInit)
	d.SetSwarmConfigFromFlags(flags)

	if d.APIKey == "" || d.APISecretKey == "" {
		return errors.New("missing an API key (--exoscale-api-key) or API secret key (--exoscale-api-secret-key)")
	}

    // Mandatory AvailabilityZone
    if d.AvailabilityZone == "" {
        return errors.New("missing AvailabilityZone (--exoscale-availability-zone)")
    }

    // Mandatory Endpoint URl
    if d.URL == "" {
        return errors.New("missing URL (--exoscale-URL)")
    }

    // The zone must be in the endpoint url as the url have the following format
    // https://api-<zone>.exoscale.com/v2
    if !strings.Contains(d.URL, d.AvailabilityZone) {
        return errors.New("Your Availability Zone doesn't match with the endpoint URL")
    }

	return nil
}

// PreCreateCheck allows for pre-create operations to make sure a driver is
// ready for creation
func (d *Driver) PreCreateCheck() error {
    client, err := exov2.NewClient(d.APIKey, d.APISecretKey, exov2.ClientOptWithAPIEndpoint(d.URL))
	if err != nil {
        return fmt.Errorf("Error initializing new client %s", err)
	}


    // Check that the user-data file exists
	if d.UserDataFile != "" {
		if _, err := os.Stat(d.UserDataFile); os.IsNotExist(err) {
			return fmt.Errorf("user-data file %s could not be found", d.UserDataFile)
		}
	}

    // Check that the Exoscale zone exists
	zones, err := client.ListZones(context.TODO())
	if err != nil {
		return fmt.Errorf("Error getting the list of zones: %s", err)
	}

	found := false
	for _, zone := range zones {
		log.Debugf("Zone: %s", zone)
		if zone == d.AvailabilityZone {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("Availability zone %v doesn't exist", d.AvailabilityZone)
	}

	return nil
}

// GetURL returns a Docker compatible host URL for connecting to this host
// e.g tcp://10.1.2.3:2376
func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}

	ip, err := d.GetIP()
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, "2376")), nil
}

// GetState returns a github.com/machine/libmachine/state.State representing the state of the host (running, stopped, etc.)
func (d *Driver) GetState() (state.State, error) {
    client, err := exov2.NewClient(d.APIKey, d.APISecretKey, exov2.ClientOptWithAPIEndpoint(d.URL))
	if err != nil {
        return state.Error, err
	}

    instance, err := client.GetInstance(context.TODO(), d.AvailabilityZone, d.ID)

	if err != nil {
		return state.Error, err
	}

    log.Debugf("Instance with State %s", *instance.State)

	switch *instance.State {
	case "starting":
		return state.Starting, nil
	case "running":
		return state.Running, nil
	case "stopping":
		return state.Running, nil
	case "stopped":
		return state.Stopped, nil
	case "destroyed":
		return state.Stopped, nil
	case "expunging":
		return state.Stopped, nil
	case "migrating":
		return state.Paused, nil
	case "error":
		return state.Error, nil
	case "unknown":
		return state.Error, nil
	case "shutdowned":
		return state.Stopped, nil
	}
	return state.None, nil
}

// TODO
func (d *Driver) createDefaultSecurityGroup(group string) (*exov2.SecurityGroup, error) {
	client, err := exov2.NewClient(d.APIKey, d.APISecretKey, exov2.ClientOptWithAPIEndpoint(d.URL))
	if err != nil {
        return nil, err
	}

    var description *string
    *description = "created by rancher-machine"

	sg, err := client.CreateSecurityGroup(context.TODO(), d.AvailabilityZone, &exov2.SecurityGroup{
		Name:        &group,
		Description: description,
	})
	if err != nil {
		return nil, err
	}

// 	cidrList := []exov2.CIDR{
// 		*exov2.MustParseCIDR("0.0.0.0/0"),
// 		*exov2.MustParseCIDR("::/0"),
// 	}
//
// 	requests := []exov2.AuthorizeSecurityGroupIngress{
// 		{
// 			SecurityGroupID: sg.ID,
// 			Description:     "SSH",
// 			CIDRList:        cidrList,
// 			Protocol:        "TCP",
// 			StartPort:       22,
// 			EndPort:         22,
// 		},
// 		{
// 			SecurityGroupID: sg.ID,
// 			Description:     "Ping",
// 			CIDRList:        []exov2.CIDR{*exov2.MustParseCIDR("0.0.0.0/0")},
// 			Protocol:        "ICMP",
// 			IcmpType:        8,
// 			IcmpCode:        0,
// 		},
// 		{
// 			SecurityGroupID: sg.ID,
// 			Description:     "Ping6",
// 			CIDRList:        []exov2.CIDR{*exov2.MustParseCIDR("::/0")},
// 			Protocol:        "ICMPv6",
// 			IcmpType:        128,
// 			IcmpCode:        0,
// 		},
// 		{
// 			SecurityGroupID: sg.ID,
// 			Description:     "Docker",
// 			CIDRList:        cidrList,
// 			Protocol:        "TCP",
// 			StartPort:       2376,
// 			EndPort:         2377,
// 		},
// 		{
// 			SecurityGroupID: sg.ID,
// 			Description:     "Legacy Standalone Swarm",
// 			CIDRList:        cidrList,
// 			Protocol:        "TCP",
// 			StartPort:       3376,
// 			EndPort:         3377,
// 		},
// 		{
// 			SecurityGroupID: sg.ID,
// 			Description:     "Communication among nodes",
// 			Protocol:        "TCP",
// 			StartPort:       7946,
// 			EndPort:         7946,
// 			UserSecurityGroupList: []exov2.UserSecurityGroup{
// 				sg.UserSecurityGroup(),
// 			},
// 		},
// 		{
// 			SecurityGroupID: sg.ID,
// 			Description:     "Communication among nodes",
// 			Protocol:        "UDP",
// 			StartPort:       7946,
// 			EndPort:         7946,
// 			UserSecurityGroupList: []exov2.UserSecurityGroup{
// 				sg.UserSecurityGroup(),
// 			},
// 		},
// 		{
// 			SecurityGroupID: sg.ID,
// 			Description:     "Overlay network traffic",
// 			Protocol:        "UDP",
// 			StartPort:       4789,
// 			EndPort:         4789,
// 			UserSecurityGroupList: []exov2.UserSecurityGroup{
// 				sg.UserSecurityGroup(),
// 			},
// 		},
// 	}
//
// 	for _, req := range requests {
// 		_, err := cs.RequestWithContext(context.TODO(), &req)
// 		if err != nil {
// 			return nil, err
// 		}
// 	}

	return sg, nil
}

func (d *Driver) createDefaultAntiAffinityGroup(group string) (*exov2.AntiAffinityGroup, error) {
	client, err := exov2.NewClient(d.APIKey, d.APISecretKey, exov2.ClientOptWithAPIEndpoint(d.URL))
	if err != nil {
        return nil, err
	}

    var description *string
    *description = "created by rancher-machine"

	ag, err := client.CreateAntiAffinityGroup(context.TODO(), d.AvailabilityZone, &exov2.AntiAffinityGroup{
		Name:        &group,
		Description: description,
	})
	if err != nil {
		return nil, err
	}

	return ag, nil
}

// Create creates the VM instance acting as the docker host
func (d *Driver) Create() error {
    log.Infof("Getting cloud init data...")

	cloudInit, err := d.getCloudInit()
	if err != nil {
		return err
	}

	log.Infof("Querying exoscale for the requested parameters...")

	client, err := exov2.NewClient(d.APIKey, d.APISecretKey, exov2.ClientOptWithAPIEndpoint(d.URL))
	if err != nil {
        return err
	}

	// Image
	template := exov2.Template{}
	templates, err := client.ListTemplates(context.TODO(), d.AvailabilityZone)
	if err != nil {
		return err
	}

	image := strings.ToLower(d.Image)
	re := regexp.MustCompile(`^Linux (?P<name>.+?) (?P<version>[0-9.]+)\b`)

	for _, tpl := range templates {

		// Keep only 10GiB images
		if *tpl.Size>>30 != 10 {
			continue
		}

		fullname := strings.ToLower(*tpl.Name)
		if image == fullname {
			template = *tpl
			break
		}

		submatch := re.FindStringSubmatch(*tpl.Name)
		if len(submatch) > 0 {
			name := strings.Replace(strings.ToLower(submatch[1]), " ", "-", -1)
			version := submatch[2]
			shortname := fmt.Sprintf("%s-%s", name, version)

			if image == shortname {
				template = *tpl
				break
			}
		}
	}

	if template.ID == nil {
		return fmt.Errorf("Unable to find image %v", d.Image)
	}

	// Reading the username from the template
	if *template.DefaultUser != "" {
		d.SSHUser = *template.DefaultUser
	}
	log.Debugf("Image %v(10) = %s (%s)", d.Image, *template.ID, d.SSHUser)

	// Instance Type UUID
	var instance_type *exov2.InstanceType
	instance_types, err := client.ListInstanceTypes(context.TODO(), d.AvailabilityZone)
	if err != nil {
		return err
	}

    for _, inst_type := range instance_types {

        log.Debugf("List InstanceType %s", *inst_type.Size)

		fullname := strings.ToLower(*inst_type.Size)
		if fullname == strings.ToLower(d.InstanceType) {
			instance_type = inst_type
			break
		}
	}

	if instance_type.ID == nil {
			fmt.Errorf("Unable to find the %s type", d.InstanceType)
	}

	log.Debugf("instance_type ID of %v = %s", d.InstanceType, *instance_type.ID)

	// Security groups
	sgs := make([]string, 0, len(d.SecurityGroups))
	for _, group := range d.SecurityGroups {
		if group == "" {
			continue
		}

        var sg *exov2.SecurityGroup

        // List all security groups to find the one with the given name
        securityGroups, err := client.ListSecurityGroups(context.TODO(), d.AvailabilityZone)
        if err != nil {
            return fmt.Errorf("failed to list security groups: %w", err)
        }

		for _, existingSG := range securityGroups {
            if *existingSG.Name == group {
                sg = existingSG
                break
            }
        }

        	// If sg is nil, the security group does not exist
        if sg == nil {
            log.Infof("Security group %v does not exist. Creating it...", group)
            securityGroup, errCreate := d.createDefaultSecurityGroup(group)
            if errCreate != nil {
                return errCreate
            }
            sg = securityGroup
        }

        log.Debugf("Security group %v = %s", group, *sg.ID)
        sgs = append(sgs, *sg.ID)
	}

	// Anti Affinity Groups
	ags := make([]string, 0, len(d.AntiAffinityGroups))
	for _, group := range d.AntiAffinityGroups {
		if group == "" {
			continue
		}

        var ag *exov2.AntiAffinityGroup

        // List all security groups to find the one with the given name
        antiAffinityGroups, err := client.ListAntiAffinityGroups(context.TODO(), d.AvailabilityZone)
        if err != nil {
            return fmt.Errorf("failed to list anti affinity groups: %w", err)
        }

		for _, existingAAG := range antiAffinityGroups {
            if *existingAAG.Name == group {
                ag = existingAAG
                break
            }
        }

        	// If sg is nil, the security group does not exist
        if ag == nil {
            log.Infof("Anti Affinity group %v does not exist. Creating it...", group)
            antiAffinityGroup, errCreate := d.createDefaultAntiAffinityGroup(group)
            if errCreate != nil {
                return errCreate
            }
            ag = antiAffinityGroup
        }

        log.Debugf("Anti Affinity group %v = %s", group, *ag.ID)
        ags = append(ags, *ag.ID)
	}

	// Creeate or import SSH Key at GetSSHKeyPath()
	if d.SSHKey == "" {
		log.Infof("Generate an SSH keypair...")
		if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
			return fmt.Errorf("SSH Key pair creation failed %s", err)
		}
	} else {
		sshKey := d.SSHKey
		if strings.HasPrefix(sshKey, "~/") {
			usr, _ := user.Current()
			sshKey = filepath.Join(usr.HomeDir, sshKey[2:])
		} else {
			var errA error
			if sshKey, errA = filepath.Abs(sshKey); errA != nil {
				return errA
			}
		}

		// Copying the private key into docker-machine
		if errCopy := mcnutils.CopyFile(sshKey, d.GetSSHKeyPath()); errCopy != nil {
			return fmt.Errorf("Unable to copy SSH file: %s", errCopy)
		}
		if errChmod := os.Chmod(d.GetSSHKeyPath(), 0600); errChmod != nil {
			return fmt.Errorf("Unable to set permissions on the SSH file: %s", errChmod)
		}
	}

    // Register SSH Key into Exoscale
    pubKey, errR := ioutil.ReadFile(d.GetSSHKeyPath() + ".pub")
    if errR != nil {
        return fmt.Errorf("Cannot read SSH public key %s", errR)
    }

    exo_ssh_key_registered, err := client.RegisterSSHKey(context.TODO(), d.AvailabilityZone, fmt.Sprintf("rancher-machine-%s", d.MachineName), string(pubKey))
    if err != nil {
        return fmt.Errorf("Cannot register the SSH public key into Exoscale %s", err)
    }

    d.ExoSSHKey = exo_ssh_key_registered

	log.Infof("Spawn exoscale host...")
	log.Debugf("Using the following cloud-init file:")
	log.Debugf("%s", string(cloudInit))

	// Base64 encode the userdata
	d.UserData = cloudInit
	encodedUserData := base64.StdEncoding.EncodeToString(d.UserData)

    log.Infof("Creating %s...", d.MachineName)
    // TODO Add Elastic IP
	instance, err := client.CreateInstance(context.TODO(), d.AvailabilityZone, &exov2.Instance{
	    AntiAffinityGroupIDs: &ags,
	    DiskSize:             &d.DiskSize,
        InstanceTypeID:       instance_type.ID,
        Name:                 &d.MachineName,
        SSHKey:               d.ExoSSHKey.Name,
        SecurityGroupIDs:     &sgs,
        TemplateID:           template.ID,
        UserData:             &encodedUserData,
	})

	if err != nil {
		return fmt.Errorf("Failed to deploy machine %s", err)
	}

	IPAddress := instance.PublicIPAddress
	if IPAddress != nil {
		d.IPAddress = IPAddress.String()
	}
	d.ID = *instance.ID
	log.Infof("IP Address: %v, SSH User: %v", d.IPAddress, d.GetSSHUsername())

	// Destroy the SSH key from Exoscale
	if d.ExoSSHKey != nil {
		if err := drivers.WaitForSSH(d); err != nil {
			return err
		}

		if err := client.DeleteSSHKey(context.TODO(), d.AvailabilityZone, d.ExoSSHKey); err != nil {
			return err
		}
		d.ExoSSHKey = nil
	}

	return nil
}

// Start starts the existing instance.
func (d *Driver) Start() error {
	client, err := exov2.NewClient(d.APIKey, d.APISecretKey, exov2.ClientOptWithAPIEndpoint(d.URL))
	if err != nil {
		return err
	}

	// Create an instance object with the ID
	instance := &exov2.Instance{
		ID: &d.ID,
	}

	// Start the instance
	if err := client.StartInstance(context.TODO(), d.AvailabilityZone, instance); err != nil {
		return err
	}

	return nil
}

// Stop stops the existing VM instance.
func (d *Driver) Stop() error {
	client, err := exov2.NewClient(d.APIKey, d.APISecretKey, exov2.ClientOptWithAPIEndpoint(d.URL))
	if err != nil {
        return err
	}

	// Create an instance object with the ID
	instance := &exov2.Instance{
		ID: &d.ID,
	}

    // Stop the instance
	if err := client.StopInstance(context.TODO(), d.AvailabilityZone, instance); err != nil {
			return err
	}

    return nil
}

// Restart reboots the existing VM instance.
func (d *Driver) Restart() error {
	client, err := exov2.NewClient(d.APIKey, d.APISecretKey, exov2.ClientOptWithAPIEndpoint(d.URL))
	if err != nil {
        return err
	}

	// Create an instance object with the ID
	instance := &exov2.Instance{
		ID: &d.ID,
	}

    // Reboot the instance
	if err := client.RebootInstance(context.TODO(), d.AvailabilityZone, instance); err != nil {
			return err
	}

    return nil
}

// Kill stops a host forcefully (same as Stop)
func (d *Driver) Kill() error {
	return d.Stop()
}

// TODO
// Remove destroys the VM instance and the associated SSH key.
func (d *Driver) Remove() error {
	client, err := exov2.NewClient(d.APIKey, d.APISecretKey, exov2.ClientOptWithAPIEndpoint(d.URL))
	if err != nil {
        return err
	}

	// Destroy the SSH key from Exoscale
	if d.ExoSSHKey != nil {
		if err := drivers.WaitForSSH(d); err != nil {
			return err
		}

		if err := client.DeleteSSHKey(context.TODO(), d.AvailabilityZone, d.ExoSSHKey); err != nil {
			return err
		}
		d.ExoSSHKey = nil
	}

	// Destroy the virtual machine
	if d.ID != "" {
        // Create an instance object with the ID
        instance := &exov2.Instance{
            ID: &d.ID,
        }
		if err := client.DeleteInstance(context.TODO(), d.AvailabilityZone, instance); err != nil {
			return err
		}
	}

	log.Infof("The Anti-Affinity group and Security group were not removed")

	return nil
}

// TODO
// Build a cloud-init user data string that will install and run
// docker.
func (d *Driver) getCloudInit() ([]byte, error) {
	var err error
	if d.UserDataFile != "" {
		d.UserData, err = ioutil.ReadFile(d.UserDataFile)
	}

	return d.UserData, err
}
