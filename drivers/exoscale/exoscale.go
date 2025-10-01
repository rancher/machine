package exoscale

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"

	v3 "github.com/exoscale/egoscale/v3"
	"github.com/exoscale/egoscale/v3/credentials"
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
	URL              string
	APIKey           string `json:"ApiKey"`
	APISecretKey     string `json:"ApiSecretKey"`
	InstanceProfile  string
	DiskSize         int64
	Image            string
	SecurityGroups   []string
	AffinityGroups   []string
	AvailabilityZone string
	SSHKey           string
	KeyPair          string
	Password         string
	PublicKey        string
	UserDataFile     string
	UserData         []byte
	ID               v3.UUID `json:"Id"`
}

const (
	// defaultAPIEndpoint       = "https://api.exoscale.ch/compute"
	defaultInstanceProfile  = "Small"
	defaultDiskSize         = 50
	defaultImage            = "Linux Ubuntu 24.04 LTS 64-bit"
	defaultAvailabilityZone = "CH-DK-2"
	defaultSSHUser          = "root"
	defaultSecurityGroup    = "docker-machine"
	defaultCloudInit        = `#cloud-config
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
			EnvVar: "EXOSCALE_INSTANCE_PROFILE",
			Name:   "exoscale-instance-profile",
			Value:  defaultInstanceProfile,
			Usage:  "exoscale instance profile (Small, Medium, Large, ...)",
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
			EnvVar: "EXOSCALE_AFFINITY_GROUP",
			Name:   "exoscale-affinity-group",
			Value:  []string{},
			Usage:  "exoscale affinity group",
		},
	}
}

// NewDriver creates a Driver with the specified machineName and storePath.
func NewDriver(machineName, storePath string) drivers.Driver {
	return &Driver{
		InstanceProfile:  defaultInstanceProfile,
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

// SetConfigFromFlags configures the driver with the object that was returned
// by RegisterCreateFlags
func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.URL = flags.String("exoscale-url")
	d.APIKey = flags.String("exoscale-api-key")
	d.APISecretKey = flags.String("exoscale-api-secret-key")
	d.InstanceProfile = flags.String("exoscale-instance-profile")
	d.DiskSize = int64(flags.Int("exoscale-disk-size"))
	d.Image = flags.String("exoscale-image")
	d.SecurityGroups = flags.StringSlice("exoscale-security-group")
	d.AffinityGroups = flags.StringSlice("exoscale-affinity-group")
	d.AvailabilityZone = flags.String("exoscale-availability-zone")
	d.SSHUser = flags.String("exoscale-ssh-user")
	d.SSHKey = flags.String("exoscale-ssh-key")
	d.UserDataFile = flags.String("exoscale-userdata")
	d.UserData = []byte(defaultCloudInit)
	d.SetSwarmConfigFromFlags(flags)

	// if d.URL == "" {
	// d.URL = defaultAPIEndpoint
	// }
	if d.APIKey == "" || d.APISecretKey == "" {
		return errors.New("missing an API key (--exoscale-api-key) or API secret key (--exoscale-api-secret-key)")
	}

	return nil
}

// PreCreateCheck allows for pre-create operations to make sure a driver is
// ready for creation
func (d *Driver) PreCreateCheck() error {
	if d.UserDataFile != "" {
		if _, err := os.Stat(d.UserDataFile); os.IsNotExist(err) {
			return fmt.Errorf("user-data file %s could not be found", d.UserDataFile)
		}
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

func (d *Driver) client() (*v3.Client, error) {
	return v3.NewClient(credentials.NewStaticCredentials(d.APIKey, d.APISecretKey))
}

func (d *Driver) getInstance() (*v3.Instance, error) {
	cs, err := d.client()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	return cs.GetInstance(ctx, d.ID)
}

// GetState returns a github.com/machine/libmachine/state.State representing the state of the host (running, stopped, etc.)
func (d *Driver) GetState() (state.State, error) {
	vm, err := d.getInstance()
	if err != nil {
		return state.Error, err
	}
	switch vm.State {
	case "Starting":
		return state.Starting, nil
	case "Running":
		return state.Running, nil
	case "Stopping":
		return state.Running, nil
	case "Stopped":
		return state.Stopped, nil
	case "Destroyed":
		return state.Stopped, nil
	case "Expunging":
		return state.Stopped, nil
	case "Migrating":
		return state.Paused, nil
	case "Error":
		return state.Error, nil
	case "Unknown":
		return state.Error, nil
	case "Shutdowned":
		return state.Stopped, nil
	}
	return state.None, nil
}

func (d *Driver) createDefaultSecurityGroup(ctx context.Context, sgName string) (v3.UUID, error) {
	cs, err := d.client()
	if err != nil {
		return "", err
	}

	op, err := cs.CreateSecurityGroup(ctx,
		v3.CreateSecurityGroupRequest{
			Name:        sgName,
			Description: "created by docker-machine",
		})
	if err != nil {
		return "", err
	}

	res, err := cs.Wait(ctx, op, v3.OperationStateSuccess)
	if err != nil {
		return "", err
	}

	cidrList := []string{
		"0.0.0.0/0",
		"::/0",
	}

	// TODO specify either a source SecurityGroup or source Network
	requests := []v3.AddRuleToSecurityGroupRequest{
		{
			Description: "SSH",
			Protocol:    "TCP",
			StartPort:   22,
			EndPort:     22,
		},
		{
			Description: "Ping",
			Network:     "0.0.0.0/0",
			Protocol:    "ICMP",
			ICMP: &v3.AddRuleToSecurityGroupRequestICMP{
				Type: v3.Int64(8),
				Code: v3.Int64(0),
			},
		},
		{
			Description: "Ping6",
			Network:     "::/0",
			Protocol:    "ICMPv6",
			ICMP: &v3.AddRuleToSecurityGroupRequestICMP{
				Type: v3.Int64(128),
				Code: v3.Int64(0),
			},
		},
		{
			Description: "Docker",
			Protocol:    "TCP",
			StartPort:   2376,
			EndPort:     2377,
		},
		{
			Description: "Legacy Standalone Swarm",
			Protocol:    "TCP",
			StartPort:   3376,
			EndPort:     3377,
		},
		{
			Description: "Communication among nodes",
			Protocol:    "TCP",
			StartPort:   7946,
			EndPort:     7946,
			// TODO
			// UserSecurityGroupList: []egoscale.UserSecurityGroup{
			// 	sg.UserSecurityGroup(),
			// },
		},
		{
			Description: "Communication among nodes",
			Protocol:    "UDP",
			StartPort:   7946,
			EndPort:     7946,
			// UserSecurityGroupList: []egoscale.UserSecurityGroup{
			// 	sg.UserSecurityGroup(),
			// },
		},
		{
			Description: "Overlay network traffic",
			Protocol:    "UDP",
			StartPort:   4789,
			EndPort:     4789,
			// UserSecurityGroupList: []egoscale.UserSecurityGroup{
			// 	sg.UserSecurityGroup(),
			// },
		},
	}

	sgID := res.Reference.ID
	for _, req := range requests {
		req.FlowDirection = v3.AddRuleToSecurityGroupRequestFlowDirectionIngress
		req.SecurityGroup = &v3.SecurityGroupResource{
			ID:         sgID,
			Name:       sgName,
			Visibility: v3.SecurityGroupResourceVisibilityPrivate,
		}

		if req.Network != "" {
			err := addRuleToSG(ctx, cs, sgID, req)
			if err != nil {
				return "", err
			}
		} else {
			for _, cidr := range cidrList {
				req.Network = cidr

				err := addRuleToSG(ctx, cs, sgID, req)
				if err != nil {
					return "", err
				}
			}
		}
	}

	return res.ID, nil
}

func addRuleToSG(ctx context.Context, cs *v3.Client, sgID v3.UUID, req v3.AddRuleToSecurityGroupRequest) error {
	op, err := cs.AddRuleToSecurityGroup(ctx, sgID, req)
	if err != nil {
		return err
	}

	_, err = cs.Wait(ctx, op, v3.OperationStateSuccess)
	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) createDefaultAffinityGroup(ctx context.Context, agName string) (v3.UUID, error) {
	cs, err := d.client()
	if err != nil {
		return "", err
	}

	resp, err := cs.CreateAntiAffinityGroup(ctx, v3.CreateAntiAffinityGroupRequest{
		Name:        agName,
		Description: "created by docker-machine",
	})
	if err != nil {
		return "", err
	}

	op, err := cs.Wait(ctx, resp)
	if err != nil {
		return "", err
	}

	return op.Reference.ID, nil
}

// Create creates the VM instance acting as the docker host
func (d *Driver) Create() error {
	cloudInit, err := d.getCloudInit()
	if err != nil {
		return err
	}

	log.Infof("Querying exoscale for the requested parameters...")
	client, err := d.client()
	if err != nil {
		return err
	}

	ctx := context.Background()
	zones, err := client.ListZones(ctx)
	if err != nil {
		return err
	}

	zone, err := zones.FindZone(d.AvailabilityZone)
	if err != nil {
		return err
	}

	log.Debugf("Availability zone %v = %s", d.AvailabilityZone, zone)
	client = client.WithEndpoint(zone.APIEndpoint)

	// Image
	templates, err := client.ListTemplates(ctx)
	if err != nil {
		return err
	}

	template := v3.Template{}

	image := strings.ToLower(d.Image)
	re := regexp.MustCompile(`^Linux (?P<name>.+?) (?P<version>[0-9.]+)\b`)

	for _, tpl := range templates.Templates {
		// Keep only 10GiB images
		if tpl.Size>>30 != 10 {
			continue
		}

		fullname := strings.ToLower(tpl.Name)
		if image == fullname {
			template = tpl
			break
		}

		submatch := re.FindStringSubmatch(tpl.Name)
		if len(submatch) > 0 {
			name := strings.ReplaceAll(strings.ToLower(submatch[1]), " ", "-")
			version := submatch[2]
			shortname := fmt.Sprintf("%s-%s", name, version)

			if image == shortname {
				template = tpl
				break
			}
		}
	}
	if template.ID == "" {
		return fmt.Errorf("Unable to find image %v", d.Image)
	}

	// Reading the username from the template
	if template.DefaultUser == "" {
		d.SSHUser = template.DefaultUser
	}
	log.Debugf("Image %v(10) = %s (%s)", d.Image, template.ID, d.SSHUser)

	// Profile UUID
	instTypes, err := client.ListInstanceTypes(ctx)
	if err != nil {
		return err
	}

	instType, err := instTypes.FindInstanceTypeByIdOrFamilyAndSize(d.InstanceProfile)
	if err != nil {
		return err
	}

	log.Debugf("Profile %v = %s", d.InstanceProfile, instType)

	// Security groups
	sgs := make([]v3.SecurityGroup, 0, len(d.SecurityGroups))
	for _, sgName := range d.SecurityGroups {
		if sgName == "" {
			continue
		}

		sglist, err := client.ListSecurityGroups(ctx)
		if err != nil {
			return err
		}

		var found *v3.SecurityGroup
		for _, elem := range sglist.SecurityGroups {
			if string(elem.Name) == sgName {
				found = &elem
			}
		}

		var sgID v3.UUID
		if found == nil {
			log.Infof("Security group %v does not exist. Creating it...", sgName)
			newSGID, err := d.createDefaultSecurityGroup(ctx, sgName)
			if err != nil {
				return err
			}

			sgID = newSGID
		} else {
			sgID = found.ID
		}

		log.Debugf("Security group %v = %s", sgName, sgID)
		sgs = append(sgs, v3.SecurityGroup{
			ID: sgID,
		})
	}

	// Affinity Groups
	ags := make([]v3.AntiAffinityGroup, 0, len(d.AffinityGroups))
	for _, group := range d.AffinityGroups {
		if group == "" {
			continue
		}
		var agID v3.UUID
		agList, err := client.ListAntiAffinityGroups(ctx)
		if err != nil {
			return err
		}

		var found *v3.AntiAffinityGroup
		for _, elem := range agList.AntiAffinityGroups {
			if string(elem.Name) == group {
				found = &elem
			}
		}

		if found == nil {
			log.Infof("Affinity Group %v does not exist, create it", group)
			newAGID, err := d.createDefaultAffinityGroup(ctx, group)
			if err != nil {
				return err
			}
			agID = newAGID
		} else {
			agID = found.ID
		}

		log.Debugf("Affinity group %v = %s", group, agID)
		ags = append(ags, v3.AntiAffinityGroup{
			ID: agID,
		})
	}

	// SSH key pair
	if d.SSHKey == "" {
		keyPairName := fmt.Sprintf("docker-machine-%s", d.MachineName)
		log.Infof("Generate an SSH keypair...")

		err = ssh.GenerateSSHKey(d.GetSSHKeyPath())
		if err != nil {
			return err
		}

		pubKeyPath := d.ResolveStorePath("id_rsa.pub")
		pubKey, err := os.ReadFile(pubKeyPath)
		if err != nil {
			return err
		}

		op, err := client.RegisterSSHKey(ctx, v3.RegisterSSHKeyRequest{
			Name:      keyPairName,
			PublicKey: string(pubKey),
		})
		if err != nil {
			return fmt.Errorf("SSH Key pair creation failed %s", err)
		}

		_, err = client.Wait(ctx, op, v3.OperationStateSuccess)
		if err != nil {
			return fmt.Errorf("SSH Key pair creation failed %s", err)
		}

		d.KeyPair = keyPairName
	} else {
		log.Infof("Importing SSH key from %s", d.SSHKey)

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

		// Sending the SSH public key through the cloud-init config
		pubKey, errR := os.ReadFile(sshKey + ".pub")
		if errR != nil {
			return fmt.Errorf("Cannot read SSH public key %s", errR)
		}

		sshAuthorizedKeys := `
ssh_authorized_keys:
- `
		cloudInit = bytes.Join([][]byte{cloudInit, []byte(sshAuthorizedKeys), pubKey}, []byte(""))

		// Copying the private key into docker-machine
		if errCopy := mcnutils.CopyFile(sshKey, d.GetSSHKeyPath()); errCopy != nil {
			return fmt.Errorf("Unable to copy SSH file: %s", errCopy)
		}
		if errChmod := os.Chmod(d.GetSSHKeyPath(), 0600); errChmod != nil {
			return fmt.Errorf("Unable to set permissions on the SSH file: %s", errChmod)
		}
	}

	sshKey, err := client.GetSSHKey(ctx, d.KeyPair)
	if err != nil {
		return err
	}

	log.Infof("Spawn exoscale host...")
	log.Debugf("Using the following cloud-init file:")
	log.Debugf("%s", string(cloudInit))

	// Base64 encode the userdata
	d.UserData = cloudInit
	encodedUserData := base64.StdEncoding.EncodeToString(d.UserData)

	op, err := client.CreateInstance(ctx, v3.CreateInstanceRequest{
		Template:           &template,
		Ipv6Enabled:        v3.Bool(true),
		DiskSize:           d.DiskSize,
		InstanceType:       &instType,
		UserData:           encodedUserData,
		Name:               d.MachineName,
		SSHKeys:            []v3.SSHKey{*sshKey},
		SecurityGroups:     sgs,
		AntiAffinityGroups: ags,
	})
	if err != nil {
		return err
	}

	log.Infof("Deploying %s...", d.MachineName)

	res, err := client.Wait(ctx, op, v3.OperationStateSuccess)
	if err != nil {
		return err
	}

	vm, err := client.GetInstance(ctx, res.Reference.ID)
	if err != nil {
		return err
	}

	IPAddress := vm.PublicIP
	if IPAddress != nil {
		d.IPAddress = IPAddress.String()
	}
	d.ID = vm.ID
	log.Infof("IP Address: %v, SSH User: %v", d.IPAddress, d.GetSSHUsername())

	if *vm.Template.PasswordEnabled {
		res, err := client.RevealInstancePassword(ctx, vm.ID)
		if err != nil {
			return err
		}

		d.Password = res.Password
	}

	// Destroy the SSH key from CloudStack
	if d.KeyPair != "" {
		if err := drivers.WaitForSSH(d); err != nil {
			return err
		}

		op, err := client.DeleteSSHKey(ctx, d.KeyPair)
		if err != nil {
			return err
		}

		_, err = client.Wait(ctx, op, v3.OperationStateSuccess)
		if err != nil {
			return err
		}

		d.KeyPair = ""
	}

	return nil
}

// Start starts the existing VM instance.
func (d *Driver) Start() error {
	cs, err := d.client()
	if err != nil {
		return err
	}

	ctx := context.Background()
	op, err := cs.StartInstance(ctx, d.ID, v3.StartInstanceRequest{})
	_, err = cs.Wait(ctx, op, v3.OperationStateSuccess)

	return err
}

// Stop stops the existing VM instance.
func (d *Driver) Stop() error {
	cs, err := d.client()
	if err != nil {
		return err
	}

	ctx := context.Background()
	op, err := cs.StopInstance(ctx, d.ID)
	_, err = cs.Wait(ctx, op, v3.OperationStateSuccess)

	return err
}

// Restart reboots the existing VM instance.
func (d *Driver) Restart() error {
	cs, err := d.client()
	if err != nil {
		return err
	}

	ctx := context.Background()
	op, err := cs.RebootInstance(ctx, d.ID)
	_, err = cs.Wait(ctx, op, v3.OperationStateSuccess)

	return err
}

// Kill stops a host forcefully (same as Stop)
func (d *Driver) Kill() error {
	return d.Stop()
}

// Remove destroys the VM instance and the associated SSH key.
func (d *Driver) Remove() error {
	client, err := d.client()
	if err != nil {
		return err
	}

	ctx := context.Background()

	// Destroy the SSH key from CloudStack
	if d.KeyPair != "" {
		op, err := client.DeleteSSHKey(ctx, d.KeyPair)
		if err != nil {
			return err
		}

		_, err = client.Wait(ctx, op, v3.OperationStateSuccess)
		if err != nil {
			return err
		}
	}

	// Destroy the virtual machine
	if d.ID != "" {
		op, err := client.DeleteInstance(ctx, d.ID)
		if err != nil {
			return err
		}

		_, err = client.Wait(ctx, op, v3.OperationStateSuccess)
		if err != nil {
			return err
		}
	}

	log.Infof("The Anti-Affinity group and Security group were not removed")

	return nil
}

// Build a cloud-init user data string that will install and run
// docker.
func (d *Driver) getCloudInit() ([]byte, error) {
	var err error
	if d.UserDataFile != "" {
		d.UserData, err = os.ReadFile(d.UserDataFile)
	}

	return d.UserData, err
}
