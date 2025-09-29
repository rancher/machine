package amazonec2

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/rancher/machine/drivers/driverutil"
	"github.com/rancher/machine/libmachine/drivers"
	rpcdriver "github.com/rancher/machine/libmachine/drivers/rpc"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/machine/libmachine/mcnflag"
	"github.com/rancher/machine/libmachine/mcnutils"
	"github.com/rancher/machine/libmachine/ssh"
	"github.com/rancher/machine/libmachine/state"
	"github.com/rancher/machine/version"
)

const (
	driverName                  = "amazonec2"
	ipRange                     = "0.0.0.0/0"
	ipv6Range                   = "::/0"
	machineSecurityGroupName    = "rancher-nodes"
	machineTag                  = "rancher-nodes"
	defaultAmiId                = "ami-c60b90d1"
	defaultRegion               = "us-east-1"
	defaultInstanceType         = "t2.micro"
	defaultRootSize             = 16
	defaultVolumeType           = "gp2"
	defaultZone                 = "a"
	defaultSecurityGroup        = machineSecurityGroupName
	defaultSSHUser              = "ubuntu"
	defaultSpotPrice            = "0.50"
	defaultBlockDurationMinutes = 0
	charset                     = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	ec2VolumeResource           = "volume"
	ec2NetworkInterfaceResource = "network-interface"
	ec2InstanceResource         = "instance"
	description                 = "managed by rancher-machine"
)

const (
	keypairNotFoundCode             = "InvalidKeyPair.NotFound"
	spotInstanceRequestNotFoundCode = "InvalidSpotInstanceRequestID.NotFound"
)

var (
	dockerPort                           int64 = 2376
	swarmPort                            int64 = 3376
	kubeApiPort                          int64 = 6443
	httpPort                             int64 = 80
	sshPort                              int64 = 22
	rancherWebhookPort                   int64 = 8443
	httpsPort                            int64 = 443
	supervisorPort                       int64 = 9345 // rke2 supervisor
	nodeExporter                         int64 = 9796
	etcdPorts                                  = []int64{2379, 2380}
	clusterManagerPorts                        = []int64{6443, 6443}
	vxlanPorts                                 = []int64{4789, 4789}
	typhaPorts                                 = []int64{5473, 5473}
	flannelPorts                               = []int64{8472, 8472}
	otherKubePorts                             = []int64{10250, 10252}
	kubeProxyPorts                             = []int64{10256, 10256}
	nodePorts                                  = []int64{30000, 32767}
	calicoPort                           int64 = 179 // calico additional port: https://docs.tigera.io/calico/latest/getting-started/openstack/requirements#network-requirements
	errorNoPrivateSSHKey                       = errors.New("using --amazonec2-keypair-name also requires --amazonec2-ssh-keypath")
	errorMissingCredentials                    = errors.New("amazonec2 driver requires AWS credentials configured with the --amazonec2-access-key and --amazonec2-secret-key options, environment variables, ~/.aws/credentials, or an instance role")
	errorNoVPCIdFound                          = errors.New("amazonec2 driver requires either the --amazonec2-subnet-id or --amazonec2-vpc-id option or an AWS Account with a default vpc-id")
	errorNoSubnetsFound                        = errors.New("the desired subnet could not be located in this region. Please check if '--amazonec2-subnet-id' or AWS_SUBNET_ID is configured correctly")
	errorDisableSSLWithoutCustomEndpoint       = errors.New("using --amazonec2-insecure-transport also requires --amazonec2-endpoint")
	errorReadingUserData                       = errors.New("unable to read --amazonec2-userdata file")
	errorInvalidValueForHTTPToken              = errors.New("httpToken must be either optional or required")
	errorInvalidValueForHTTPEndpoint           = errors.New("httpEndpoint must be either enabled or disabled")
	errorInvalidValueForHTTPProtocolIpv6       = errors.New("httpProtocolIpv6 must be either enabled or disabled")
	errorInvalidValueForIpv6AddressCount       = errors.New("ipv6AddressCount must be greater than zero when Ipv6AddressOnly is true")
)

type Driver struct {
	*drivers.BaseDriver
	clientFactory         func() Ec2Client
	awsCredentialsFactory func() awsCredentials
	Id                    string
	AccessKey             string
	SecretKey             string
	SessionToken          string
	Region                string
	AMI                   string
	SSHKeyID              int
	// ExistingKey keeps track of whether the key was created by us or we used an existing one. If an existing one was used, we shouldn't delete it when the machine is deleted.
	ExistingKey      bool
	KeyName          string
	InstanceId       string
	InstanceType     string
	OS               string
	PrivateIPAddress string

	// NB: SecurityGroupId expanded from single value to slice on 26 Feb 2016 - we maintain both for host storage backwards compatibility.
	SecurityGroupId  string
	SecurityGroupIds []string

	// NB: SecurityGroupName expanded from single value to slice on 26 Feb 2016 - we maintain both for host storage backwards compatibility.
	SecurityGroupName  string
	SecurityGroupNames []string

	SecurityGroupReadOnly   bool
	OpenPorts               []string
	Tags                    string
	ReservationId           string
	DeviceName              string
	RootSize                int64
	VolumeType              string
	IamInstanceProfile      string
	VpcId                   string
	SubnetId                string
	Zone                    string
	keyPath                 string
	RequestSpotInstance     bool
	SpotPrice               string
	BlockDurationMinutes    int64
	PrivateIPOnly           bool
	UsePrivateIP            bool
	UseEbsOptimizedInstance bool
	Monitoring              bool
	SSHPrivateKeyPath       string
	RetryCount              int
	Endpoint                string
	DisableSSL              bool
	UserDataFile            string
	EncryptEbsVolume        bool
	spotInstanceRequestId   string
	kmsKeyId                *string
	bdmList                 []*ec2.BlockDeviceMapping
	// Metadata Options
	HttpEndpoint string
	HttpTokens   string

	// Enables or disables the IPv6 endpoint for the instance metadata service.
	// Options: enabled, disabled
	HttpProtocolIpv6 string

	// Indicates whether the instance’s first assigned IPv6 address is set as the primary IPv6 address.
	// Enable this option if the instance requires a stable, persistent IPv6 address.
	// This option does not affect whether IPv6 addresses are assigned to the instance.
	// For more information, see EnablePrimaryIpv6 on
	// https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RunInstances.html
	EnablePrimaryIpv6 bool

	// The number of IPv6 addresses to assign to the network interface.
	// It must be greater than zero when Ipv6AddressOnly is true
	Ipv6AddressCount int64

	// Indicates whether the instance has only IPv6 address.
	// Useful when the VPC or subnet is configured as IPv6-only.
	Ipv6AddressOnly bool
}

func (d *Driver) GetCreateFlags() []mcnflag.Flag {
	return []mcnflag.Flag{
		mcnflag.StringFlag{
			Name:   "amazonec2-access-key",
			Usage:  "AWS Access Key",
			EnvVar: "AWS_ACCESS_KEY_ID",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-secret-key",
			Usage:  "AWS Secret Key",
			EnvVar: "AWS_SECRET_ACCESS_KEY",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-session-token",
			Usage:  "AWS Session Token",
			EnvVar: "AWS_SESSION_TOKEN",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-ami",
			Usage:  "AWS machine image",
			EnvVar: "AWS_AMI",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-region",
			Usage:  "AWS region",
			Value:  defaultRegion,
			EnvVar: "AWS_DEFAULT_REGION",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-vpc-id",
			Usage:  "AWS VPC id",
			EnvVar: "AWS_VPC_ID",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-zone",
			Usage:  "AWS zone for instance (i.e. a,b,c,d,e)",
			Value:  defaultZone,
			EnvVar: "AWS_ZONE",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-subnet-id",
			Usage:  "AWS VPC subnet id",
			EnvVar: "AWS_SUBNET_ID",
		},
		mcnflag.BoolFlag{
			Name:   "amazonec2-security-group-readonly",
			Usage:  "Skip adding default rules to security groups",
			EnvVar: "AWS_SECURITY_GROUP_READONLY",
		},
		mcnflag.StringSliceFlag{
			Name:   "amazonec2-security-group",
			Usage:  "AWS VPC security group",
			Value:  []string{defaultSecurityGroup},
			EnvVar: "AWS_SECURITY_GROUP",
		},
		mcnflag.StringSliceFlag{
			Name:  "amazonec2-open-port",
			Usage: "Make the specified port number accessible from the Internet",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-tags",
			Usage:  "AWS Tags (e.g. key1,value1,key2,value2)",
			EnvVar: "AWS_TAGS",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-instance-type",
			Usage:  "AWS instance type",
			Value:  defaultInstanceType,
			EnvVar: "AWS_INSTANCE_TYPE",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-device-name",
			Usage:  "AWS root device name",
			EnvVar: "AWS_DEVICE_NAME",
		},
		mcnflag.IntFlag{
			Name:   "amazonec2-root-size",
			Usage:  "AWS root disk size (in GB)",
			Value:  defaultRootSize,
			EnvVar: "AWS_ROOT_SIZE",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-volume-type",
			Usage:  "Amazon EBS volume type",
			Value:  defaultVolumeType,
			EnvVar: "AWS_VOLUME_TYPE",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-iam-instance-profile",
			Usage:  "AWS IAM Instance Profile",
			EnvVar: "AWS_INSTANCE_PROFILE",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-ssh-user",
			Usage:  "Set the name of the ssh user",
			Value:  defaultSSHUser,
			EnvVar: "AWS_SSH_USER",
		},
		mcnflag.BoolFlag{
			Name:  "amazonec2-request-spot-instance",
			Usage: "Set this flag to request spot instance",
		},
		mcnflag.StringFlag{
			Name:  "amazonec2-spot-price",
			Usage: "AWS spot instance bid price (in dollar)",
			Value: defaultSpotPrice,
		},
		mcnflag.IntFlag{
			Name:  "amazonec2-block-duration-minutes",
			Usage: "AWS spot instance duration in minutes (60, 120, 180, 240, 300, or 360)",
			Value: defaultBlockDurationMinutes,
		},
		mcnflag.BoolFlag{
			Name:  "amazonec2-private-address-only",
			Usage: "Only use a private IP address",
		},
		mcnflag.BoolFlag{
			Name:  "amazonec2-use-private-address",
			Usage: "Force the usage of private IP address",
		},
		mcnflag.BoolFlag{
			Name:  "amazonec2-monitoring",
			Usage: "Set this flag to enable CloudWatch monitoring",
		},
		mcnflag.BoolFlag{
			Name:  "amazonec2-use-ebs-optimized-instance",
			Usage: "Create an EBS optimized instance",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-ssh-keypath",
			Usage:  "SSH Key for Instance",
			EnvVar: "AWS_SSH_KEYPATH",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-keypair-name",
			Usage:  "AWS keypair to use; requires --amazonec2-ssh-keypath",
			EnvVar: "AWS_KEYPAIR_NAME",
		},
		mcnflag.IntFlag{
			Name:  "amazonec2-retries",
			Usage: "Set retry count for recoverable failures (use -1 to disable)",
			Value: 5,
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-endpoint",
			Usage:  "Optional endpoint URL (hostname only or fully qualified URI)",
			Value:  "",
			EnvVar: "AWS_ENDPOINT",
		},
		mcnflag.BoolFlag{
			Name:   "amazonec2-insecure-transport",
			Usage:  "Disable SSL when sending requests",
			EnvVar: "AWS_INSECURE_TRANSPORT",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-userdata",
			Usage:  "path to file with cloud-init user data",
			EnvVar: "AWS_USERDATA",
		},
		mcnflag.BoolFlag{
			Name:   "amazonec2-encrypt-ebs-volume",
			Usage:  "Encrypt the EBS volume using the AWS Managed CMK",
			EnvVar: "AWS_ENCRYPT_EBS_VOLUME",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-kms-key",
			Usage:  "Custom KMS key using the AWS Managed CMK",
			EnvVar: "AWS_KMS_KEY",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-http-endpoint",
			Usage:  "Enables or disables the HTTP metadata endpoint on your instances",
			EnvVar: "AWS_HTTP_ENDPOINT",
		},
		mcnflag.StringFlag{
			Name:   "amazonec2-http-tokens",
			Usage:  "The state of token usage for your instance metadata requests.",
			EnvVar: "AWS_HTTP_TOKENS",
		},
		mcnflag.StringFlag{
			Name: "amazonec2-http-protocol-ipv6",
			Usage: "Enables or disables the IPv6 endpoint for the instance metadata service." +
				" Options: enabled, disabled (default).",
			EnvVar: "AWS_HTTP_PROTOCOL_IPV6",
			Value:  "disabled",
		},
		mcnflag.IntFlag{
			Name: "amazonec2-ipv6-address-count",
			Usage: "The number of IPv6 addresses to assign to the network interface (default: 0)." +
				" Must be greater than zero when amazonec2-ipv6-address-only is true.",
			EnvVar: "AWS_IPV6_ADDRESS_COUNT",
			Value:  0,
		},
		mcnflag.BoolFlag{
			Name: "amazonec2-enable-primary-ipv6",
			Usage: "Indicates whether the first IPv6 address assigned to the instance should be marked as the primary IPv6 address." +
				" Enable this option if the instance requires a stable, non-changing IPv6 address." +
				" This option does not affect whether IPv6 addresses are assigned to the instance.",
			EnvVar: "AWS_ENABLE_PRIMARY_IPV6",
		},
		mcnflag.BoolFlag{
			Name: "amazonec2-ipv6-address-only",
			Usage: "Indicates whether the instance has only IPv6 address. Useful when the VPC or subnet is configured as IPv6-only." +
				" When set to true, the instance will have IPv6 as its sole address." +
				" When set to true, amazonec2-ipv6-address-count must be greater than zero.",
			EnvVar: "AWS_IPV6_ADDRESS_ONLY",
		},
	}
}

func NewDriver(hostName, storePath string) *Driver {
	id := generateId()
	driver := &Driver{
		Id:                   id,
		AMI:                  defaultAmiId,
		Region:               defaultRegion,
		InstanceType:         defaultInstanceType,
		RootSize:             defaultRootSize,
		Zone:                 defaultZone,
		SecurityGroupNames:   []string{defaultSecurityGroup},
		SpotPrice:            defaultSpotPrice,
		BlockDurationMinutes: defaultBlockDurationMinutes,
		BaseDriver: &drivers.BaseDriver{
			SSHUser:     defaultSSHUser,
			MachineName: hostName,
			StorePath:   storePath,
		},
	}

	driver.clientFactory = driver.buildClient
	driver.awsCredentialsFactory = driver.buildCredentials

	return driver
}

func (d *Driver) buildClient() Ec2Client {
	config := aws.NewConfig()
	alogger := AwsLogger()
	config = config.WithRegion(d.Region)
	config = config.WithCredentials(d.awsCredentialsFactory().Credentials())
	config = config.WithLogger(alogger)
	config = config.WithLogLevel(aws.LogDebugWithHTTPBody)
	config = config.WithMaxRetries(d.RetryCount)
	if d.Endpoint != "" {
		config = config.WithEndpoint(d.Endpoint)
		config = config.WithDisableSSL(d.DisableSSL)
	}
	// use AWS dual stack endpoint to support both IPv6 and IPv4
	config.UseDualStackEndpoint = endpoints.DualStackEndpointStateEnabled
	return ec2.New(session.New(config))
}

func (d *Driver) buildCredentials() awsCredentials {
	return NewAWSCredentials(d.AccessKey, d.SecretKey, d.SessionToken)
}

func (d *Driver) getClient() Ec2Client {
	return d.clientFactory()
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
	if _, ok := driverOpts.Values["amazonec2-access-key"]; ok {
		d.AccessKey = driverOpts.String("amazonec2-access-key")
	}

	if _, ok := driverOpts.Values["amazonec2-secret-key"]; ok {
		d.SecretKey = driverOpts.String("amazonec2-secret-key")
	}

	return nil
}

func (d *Driver) SetConfigFromFlags(flags drivers.DriverOptions) error {
	d.Endpoint = flags.String("amazonec2-endpoint")

	region, err := validateAwsRegion(flags.String("amazonec2-region"))
	if err != nil && d.Endpoint == "" {
		return err
	}

	image := flags.String("amazonec2-ami")
	if len(image) == 0 {
		image = regionDetails[region].AmiId
	}

	d.AccessKey = flags.String("amazonec2-access-key")
	d.SecretKey = flags.String("amazonec2-secret-key")
	d.SessionToken = flags.String("amazonec2-session-token")
	d.Region = region
	d.AMI = image
	d.RequestSpotInstance = flags.Bool("amazonec2-request-spot-instance")
	d.SpotPrice = flags.String("amazonec2-spot-price")
	d.BlockDurationMinutes = int64(flags.Int("amazonec2-block-duration-minutes"))
	d.InstanceType = flags.String("amazonec2-instance-type")
	d.VpcId = flags.String("amazonec2-vpc-id")
	d.SubnetId = flags.String("amazonec2-subnet-id")
	d.SecurityGroupNames = flags.StringSlice("amazonec2-security-group")
	d.SecurityGroupReadOnly = flags.Bool("amazonec2-security-group-readonly")
	d.Tags = flags.String("amazonec2-tags")
	zone := flags.String("amazonec2-zone")
	d.Zone = zone[:]
	d.DeviceName = flags.String("amazonec2-device-name")
	d.RootSize = int64(flags.Int("amazonec2-root-size"))
	d.VolumeType = flags.String("amazonec2-volume-type")
	d.IamInstanceProfile = flags.String("amazonec2-iam-instance-profile")
	d.SSHUser = flags.String("amazonec2-ssh-user")
	d.SSHPort = 22
	d.PrivateIPOnly = flags.Bool("amazonec2-private-address-only")
	d.UsePrivateIP = flags.Bool("amazonec2-use-private-address")
	d.Ipv6AddressOnly = flags.Bool("amazonec2-ipv6-address-only")
	d.Ipv6AddressCount = int64(flags.Int("amazonec2-ipv6-address-count"))
	d.EnablePrimaryIpv6 = flags.Bool("amazonec2-enable-primary-ipv6")
	d.Monitoring = flags.Bool("amazonec2-monitoring")
	d.UseEbsOptimizedInstance = flags.Bool("amazonec2-use-ebs-optimized-instance")
	d.SSHPrivateKeyPath = flags.String("amazonec2-ssh-keypath")
	d.KeyName = flags.String("amazonec2-keypair-name")
	d.ExistingKey = flags.String("amazonec2-keypair-name") != ""
	d.SetSwarmConfigFromFlags(flags)
	d.RetryCount = flags.Int("amazonec2-retries")
	d.OpenPorts = flags.StringSlice("amazonec2-open-port")
	d.UserDataFile = flags.String("amazonec2-userdata")
	d.EncryptEbsVolume = flags.Bool("amazonec2-encrypt-ebs-volume")

	httpEndpoint := flags.String("amazonec2-http-endpoint")
	if httpEndpoint != "" {
		if httpEndpoint != "disabled" && httpEndpoint != "enabled" {
			return errorInvalidValueForHTTPEndpoint
		}
		d.HttpEndpoint = httpEndpoint
	}

	httpTokens := flags.String("amazonec2-http-tokens")
	if httpTokens != "" {
		if httpTokens != "optional" && httpTokens != "required" {
			return errorInvalidValueForHTTPToken
		}
		d.HttpTokens = httpTokens
	}

	httpProtocolIpv6 := flags.String("amazonec2-http-protocol-ipv6")
	if httpProtocolIpv6 != "" {
		if httpProtocolIpv6 != "disabled" && httpProtocolIpv6 != "enabled" {
			return errorInvalidValueForHTTPProtocolIpv6
		}
		d.HttpProtocolIpv6 = httpProtocolIpv6
	}

	if d.Ipv6AddressOnly && d.Ipv6AddressCount < 1 {
		return errorInvalidValueForIpv6AddressCount
	}

	kmskeyid := flags.String("amazonec2-kms-key")
	if kmskeyid != "" {
		d.kmsKeyId = aws.String(kmskeyid)
	}

	d.DisableSSL = flags.Bool("amazonec2-insecure-transport")

	if d.DisableSSL && d.Endpoint == "" {
		return errorDisableSSLWithoutCustomEndpoint
	}

	if d.KeyName != "" && d.SSHPrivateKeyPath == "" {
		return errorNoPrivateSSHKey
	}

	_, err = d.awsCredentialsFactory().Credentials().Get()
	if err != nil {
		return errorMissingCredentials
	}

	if d.VpcId == "" {
		d.VpcId, err = d.getDefaultVPCId()
		if err != nil {
			log.Warnf("Couldn't determine your account Default VPC ID : %q", err)
		}
	}

	if d.SubnetId == "" && d.VpcId == "" {
		return errorNoVPCIdFound
	}

	if d.SubnetId != "" && d.VpcId != "" {
		subnetFilter := []*ec2.Filter{
			{
				Name:   aws.String("subnet-id"),
				Values: []*string{&d.SubnetId},
			},
		}

		subnets, err := d.getClient().DescribeSubnets(&ec2.DescribeSubnetsInput{
			Filters: subnetFilter,
		})
		if err != nil {
			return err
		}

		if subnets == nil || len(subnets.Subnets) == 0 {
			return errorNoSubnetsFound
		}

		if *subnets.Subnets[0].VpcId != d.VpcId {
			return fmt.Errorf("SubnetId: %s does not belong to VpcId: %s", d.SubnetId, d.VpcId)
		}
	}

	if d.isSwarmMaster() {
		u, err := url.Parse(d.SwarmHost)
		if err != nil {
			return fmt.Errorf("error parsing swarm host: %s", err)
		}

		parts := strings.Split(u.Host, ":")
		port, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return err
		}

		swarmPort = port
	}

	return nil
}

// DriverName returns the name of the driver
func (d *Driver) DriverName() string {
	return driverName
}

func (d *Driver) checkSubnet() error {
	regionZone := d.getRegionZone()
	if d.SubnetId == "" {
		filters := []*ec2.Filter{
			{
				Name:   aws.String("availability-zone"),
				Values: []*string{&regionZone},
			},
			{
				Name:   aws.String("vpc-id"),
				Values: []*string{&d.VpcId},
			},
		}

		subnets, err := d.getClient().DescribeSubnets(&ec2.DescribeSubnetsInput{
			Filters: filters,
		})
		if err != nil {
			return err
		}

		if len(subnets.Subnets) == 0 {
			return fmt.Errorf("unable to find a subnet in the zone: %s", regionZone)
		}

		d.SubnetId = *subnets.Subnets[0].SubnetId

		// try to find default
		if len(subnets.Subnets) > 1 {
			for _, subnet := range subnets.Subnets {
				if subnet.DefaultForAz != nil && *subnet.DefaultForAz {
					d.SubnetId = *subnet.SubnetId
					break
				}
			}
		}
	}

	return nil
}

func (d *Driver) checkAMI() error {
	// Check if image exists
	images, err := d.getClient().DescribeImages(&ec2.DescribeImagesInput{
		ImageIds: []*string{&d.AMI},
	})
	if err != nil {
		return err
	}
	if len(images.Images) == 0 {
		return fmt.Errorf("AMI %s not found on region %s", d.AMI, d.getRegionZone())
	}

	// Select the right device name, if not provided
	if d.DeviceName == "" {
		d.DeviceName = *images.Images[0].RootDeviceName
	}

	// store bdm list && update size and encryption settings
	d.bdmList = images.Images[0].BlockDeviceMappings

	return nil
}

func (d *Driver) PreCreateCheck() error {
	if err := d.checkSubnet(); err != nil {
		return err
	}

	if err := d.checkAMI(); err != nil {
		return err
	}

	return nil
}

func (d *Driver) instanceIpAvailable() bool {
	switch {
	case d.Ipv6AddressOnly:
		// IPv6-only mode
		return d.checkIPv6()
	case d.Ipv6AddressCount >= 1:
		// Dual-stack mode
		hasIPv6 := d.checkIPv6()
		hasIPv4 := d.checkIPv4()
		return hasIPv6 && hasIPv4
	default:
		// IPv4-only mode
		return d.checkIPv4()
	}
}

func (d *Driver) checkIPv6() bool {
	ipv6, err := d.GetIPv6()
	if err != nil {
		log.Debugf("Error fetching IPv6 address: %s", err.Error())
	}
	if ipv6 == "" {
		return false
	}

	d.IPv6Address = ipv6
	log.Debugf("Get the IPv6 address: %q", d.IPv6Address)
	return true
}

func (d *Driver) checkIPv4() bool {
	ip, err := d.GetIP()
	if err != nil {
		log.Debugf("Error fetching IPv4 address: %s", err.Error())
	}
	if ip == "" {
		return false
	}

	d.IPAddress = ip
	log.Debugf("Get the IPv4 address: %q", d.IPAddress)
	return true
}

func makePointerSlice(stackSlice []string) []*string {
	pointerSlice := []*string{}
	for i := range stackSlice {
		pointerSlice = append(pointerSlice, &stackSlice[i])
	}
	return pointerSlice
}

// Support migrating single string Driver fields to slices.
func migrateStringToSlice(value string, values []string) (result []string) {
	if value != "" {
		result = append(result, value)
	}
	result = append(result, values...)
	return
}

func (d *Driver) securityGroupNames() (ids []string) {
	return migrateStringToSlice(d.SecurityGroupName, d.SecurityGroupNames)
}

func (d *Driver) securityGroupIds() (ids []string) {
	return migrateStringToSlice(d.SecurityGroupId, d.SecurityGroupIds)
}

func (d *Driver) Base64UserData() (userdata string, err error) {
	if d.UserDataFile != "" {
		buf, ioerr := os.ReadFile(d.UserDataFile)
		if ioerr != nil {
			log.Warnf("Failed to read user data file %q: %s", d.UserDataFile, ioerr)
			err = errorReadingUserData
			return
		}
		userdata = base64.StdEncoding.EncodeToString(buf)
	}
	return
}

func (d *Driver) Create() error {
	// PreCreateCheck has already been called

	if err := d.innerCreate(); err != nil {
		log.Warnf("Error encountered during instance creation: %s", err.Error())
		// cleanup partially created resources
		if removalErr := d.Remove(); removalErr != nil {
			return removalErr
		}
		return err
	}

	return nil
}

func (d *Driver) innerCreate() error {
	log.Infof("Launching instance...")

	if err := d.createKeyPair(); err != nil {
		return fmt.Errorf("unable to create key pair: %s", err)
	}

	if err := d.configureSecurityGroups(d.securityGroupNames()); err != nil {
		return err
	}

	var userdata string
	if b64, err := d.Base64UserData(); err != nil {
		return err
	} else {
		userdata = b64
	}

	bdmList := d.updateBDMList()

	associatePublicIpAddress := !d.PrivateIPOnly
	if d.Ipv6AddressOnly {
		// We cannot assign public IPv4 address in IPv6-only subnet
		associatePublicIpAddress = false
	}

	netSpecs := []*ec2.InstanceNetworkInterfaceSpecification{{
		DeviceIndex:              aws.Int64(0), // eth0
		Groups:                   makePointerSlice(d.securityGroupIds()),
		SubnetId:                 &d.SubnetId,
		AssociatePublicIpAddress: aws.Bool(associatePublicIpAddress),
		PrimaryIpv6:              aws.Bool(d.EnablePrimaryIpv6),
		Ipv6AddressCount:         aws.Int64(d.Ipv6AddressCount),
	}}

	regionZone := d.getRegionZone()
	log.Debugf("Launching instance in subnet %s", d.SubnetId)

	var instance *ec2.Instance
	if d.RequestSpotInstance {
		req := ec2.RunInstancesInput{
			ImageId:  &d.AMI,
			MinCount: aws.Int64(1),
			MaxCount: aws.Int64(1),
			Placement: &ec2.Placement{
				AvailabilityZone: &regionZone,
			},
			KeyName:           &d.KeyName,
			InstanceType:      &d.InstanceType,
			NetworkInterfaces: netSpecs,
			Monitoring:        &ec2.RunInstancesMonitoringEnabled{Enabled: aws.Bool(d.Monitoring)},
			IamInstanceProfile: &ec2.IamInstanceProfileSpecification{
				Name: &d.IamInstanceProfile,
			},
			EbsOptimized:        &d.UseEbsOptimizedInstance,
			BlockDeviceMappings: bdmList,
			UserData:            &userdata,
			MetadataOptions:     &ec2.InstanceMetadataOptionsRequest{},
			InstanceMarketOptions: &ec2.InstanceMarketOptionsRequest{
				MarketType: aws.String(ec2.MarketTypeSpot),
				SpotOptions: &ec2.SpotMarketOptions{
					MaxPrice:         &d.SpotPrice,
					SpotInstanceType: aws.String(ec2.SpotInstanceTypeOneTime),
				},
			},
		}

		if d.HttpEndpoint != "" {
			req.MetadataOptions.HttpEndpoint = aws.String(d.HttpEndpoint)
		}

		if d.HttpTokens != "" {
			req.MetadataOptions.HttpTokens = aws.String(d.HttpTokens)
		}

		if d.HttpProtocolIpv6 != "" {
			req.MetadataOptions.HttpProtocolIpv6 = aws.String(d.HttpProtocolIpv6)
		}

		if d.BlockDurationMinutes != 0 {
			req.InstanceMarketOptions.SpotOptions.BlockDurationMinutes = &d.BlockDurationMinutes
		}
		res, err := d.getClient().RunInstances(&req)
		if err != nil {
			return fmt.Errorf("error request spot instance: %s", err)
		}
		d.spotInstanceRequestId = *res.Instances[0].SpotInstanceRequestId

		log.Info("Waiting for spot instance...")
		for i := 0; i < 3; i++ {
			// AWS eventual consistency means we could not have SpotInstanceRequest ready yet
			err = d.getClient().WaitUntilSpotInstanceRequestFulfilled(&ec2.DescribeSpotInstanceRequestsInput{
				SpotInstanceRequestIds: []*string{&d.spotInstanceRequestId},
			})
			if err != nil {
				if awsErr, ok := err.(awserr.Error); ok {
					if awsErr.Code() == spotInstanceRequestNotFoundCode {
						time.Sleep(5 * time.Second)
						continue
					}
				}
				return fmt.Errorf("error fulfilling spot request: %v", err)
			}
			break
		}
		log.Infof("Created spot instance request %v", d.spotInstanceRequestId)
		// resolve instance id
		for i := 0; i < 3; i++ {
			// Even though the waiter succeeded, eventual consistency means we could
			// get a describe output that does not include this information. Try a
			// few times just in case
			var resolvedSpotInstance *ec2.DescribeSpotInstanceRequestsOutput
			resolvedSpotInstance, err = d.getClient().DescribeSpotInstanceRequests(&ec2.DescribeSpotInstanceRequestsInput{
				SpotInstanceRequestIds: []*string{&d.spotInstanceRequestId},
			})
			if err != nil {
				// Unexpected; no need to retry
				return fmt.Errorf("error describing previously made spot instance request: %v", err)
			}
			maybeInstanceId := resolvedSpotInstance.SpotInstanceRequests[0].InstanceId
			if maybeInstanceId != nil {
				var instances *ec2.DescribeInstancesOutput
				instances, err = d.getClient().DescribeInstances(&ec2.DescribeInstancesInput{
					InstanceIds: []*string{maybeInstanceId},
				})
				if err != nil {
					// Retry if we get an id from spot instance but EC2 doesn't recognize it yet; see above, eventual consistency possible
					continue
				}
				instance = instances.Reservations[0].Instances[0]
				err = nil
				break
			}
			time.Sleep(5 * time.Second)
		}

		if err != nil {
			return fmt.Errorf("error resolving spot instance to real instance: %v", err)
		}
	} else {
		log.Debug("Building tags for instance creation")
		resourceTags := d.buildResourceTags([]string{
			ec2InstanceResource, // required
			ec2VolumeResource,   // EBS volume
			ec2NetworkInterfaceResource,
		})
		req := ec2.RunInstancesInput{
			ImageId:  &d.AMI,
			MinCount: aws.Int64(1),
			MaxCount: aws.Int64(1),
			Placement: &ec2.Placement{
				AvailabilityZone: &regionZone,
			},
			KeyName:           &d.KeyName,
			InstanceType:      &d.InstanceType,
			NetworkInterfaces: netSpecs,
			Monitoring:        &ec2.RunInstancesMonitoringEnabled{Enabled: aws.Bool(d.Monitoring)},
			IamInstanceProfile: &ec2.IamInstanceProfileSpecification{
				Name: &d.IamInstanceProfile,
			},
			EbsOptimized:        &d.UseEbsOptimizedInstance,
			BlockDeviceMappings: bdmList,
			UserData:            &userdata,
			MetadataOptions:     &ec2.InstanceMetadataOptionsRequest{},
			TagSpecifications:   resourceTags,
		}

		if d.HttpEndpoint != "" {
			req.MetadataOptions.HttpEndpoint = aws.String(d.HttpEndpoint)
		}

		if d.HttpTokens != "" {
			req.MetadataOptions.HttpTokens = aws.String(d.HttpTokens)
		}

		if d.HttpProtocolIpv6 != "" {
			req.MetadataOptions.HttpProtocolIpv6 = aws.String(d.HttpProtocolIpv6)
		}

		res, err := d.getClient().RunInstances(&req)

		if err != nil {
			return fmt.Errorf("error launching instance: %s", err)
		}
		instance = res.Instances[0]
	}

	if instance == nil {
		return fmt.Errorf("instance is not found in the clients response")
	}

	d.InstanceId = *instance.InstanceId

	log.Debug("Waiting for ip address to become available")
	if err := mcnutils.WaitFor(d.instanceIpAvailable); err != nil {
		return err
	}

	if instance.PrivateIpAddress != nil {
		d.PrivateIPAddress = *instance.PrivateIpAddress
	}

	log.Debug("Waiting for instance to be in the running state")
	if err := d.waitForInstance(); err != nil {
		return err
	}

	if d.RequestSpotInstance {
		// tags for spot instances should be added
		// after the instance has been created and
		// transitioned into a 'running' state. The spot-instance
		// is created by an internal AWS process after accepting
		// the spot-instance-request, so tags cannot be supplied
		// within the request
		if err := d.configureTags(instance); err != nil {
			return err
		}
	}

	log.Debugf("Created instance ID %s, Public IPv4 address %s, Private IPv4 address %s, IPv6 address %s",
		d.InstanceId,
		d.IPAddress,
		d.PrivateIPAddress,
		d.IPv6Address,
	)

	return nil
}

// configureTags will add tags to the instance after
// it has been created and transitioned into 'running'.
func (d *Driver) configureTags(instance *ec2.Instance) error {
	tags := append(buildEC2Tags(d.Tags), &ec2.Tag{
		Key:   aws.String("Name"),
		Value: &d.MachineName,
	})
	// ensure the EBS volume and Network Interface
	// created for an instance receive the supplied tags
	resources := make([]*string, 0, len(instance.BlockDeviceMappings)+len(instance.NetworkInterfaces)+1) // + 1 for instanceID
	resources = append(resources, &d.InstanceId)
	for _, blockDeviceMapping := range instance.BlockDeviceMappings {
		resources = append(resources, blockDeviceMapping.Ebs.VolumeId)
	}
	for _, networkInterface := range instance.NetworkInterfaces {
		resources = append(resources, networkInterface.NetworkInterfaceId)
	}
	_, err := d.getClient().CreateTags(&ec2.CreateTagsInput{
		Resources: resources,
		Tags:      tags,
	})
	return err
}

func (d *Driver) GetURL() (string, error) {
	if err := drivers.MustBeRunning(d); err != nil {
		return "", err
	}
	var ip string
	var err error

	switch {
	case d.Ipv6AddressOnly:
		// IPv6-only mode
		if ip, err = d.GetIPv6(); err != nil {
			return "", err
		}
	case d.Ipv6AddressCount >= 1:
		// Dual-stack mode
		// preference: IPv4 address, then IPv6 address
		if ip, err = d.GetIP(); err != nil {
			log.Warnf("Error getting IPv4 address: %s", err)
			log.Debug("Getting IPv6 address")
			ip, err = d.GetIPv6()
			if err != nil {
				return "", err
			}
		}
	default:
		// IPv4-only mode
		if ip, err = d.GetIP(); err != nil {
			return "", err
		}
	}

	if ip == "" {
		return "", nil
	}

	return fmt.Sprintf("tcp://%s", net.JoinHostPort(ip, fmt.Sprintf("%d", dockerPort))), nil
}

func (d *Driver) GetIP() (string, error) {
	inst, err := d.getInstance()
	if err != nil {
		return "", err
	}

	if d.PrivateIPOnly {
		if inst.PrivateIpAddress == nil {
			return "", fmt.Errorf("no private IPv4 address for instance %v", *inst.InstanceId)
		}
		return *inst.PrivateIpAddress, nil
	}

	if d.UsePrivateIP {
		if inst.PrivateIpAddress == nil {
			return "", fmt.Errorf("no private IPv4 address for instance %v", *inst.InstanceId)
		}
		return *inst.PrivateIpAddress, nil
	}

	if inst.PublicIpAddress == nil {
		return "", fmt.Errorf("no public IPv4 address for instance %v", *inst.InstanceId)
	}
	return *inst.PublicIpAddress, nil
}

func (d *Driver) GetIPv6() (string, error) {
	if d.Ipv6AddressCount == 0 {
		log.Warn("Attempting to get IPv6 address when Ipv6AddressCount is zero, please check your configuration")
	}
	inst, err := d.getInstance()
	if err != nil {
		return "", err
	}

	if inst.Ipv6Address == nil {
		return "", fmt.Errorf("no IPv6 address for instance %v", *inst.InstanceId)
	}
	return *inst.Ipv6Address, nil
}

func (d *Driver) GetState() (state.State, error) {
	inst, err := d.getInstance()
	if err != nil {
		return state.Error, err
	}
	switch *inst.State.Name {
	case ec2.InstanceStateNamePending:
		return state.Starting, nil
	case ec2.InstanceStateNameRunning:
		return state.Running, nil
	case ec2.InstanceStateNameStopping:
		return state.Stopping, nil
	case ec2.InstanceStateNameShuttingDown:
		return state.Stopping, nil
	case ec2.InstanceStateNameStopped:
		return state.Stopped, nil
	case ec2.InstanceStateNameTerminated:
		return state.Error, fmt.Errorf("valid machine %v not found", d.MachineName)
	default:
		log.Warnf("Unrecognized instance state: %v", *inst.State.Name)
		return state.Error, nil
	}
}

func (d *Driver) GetSSHHostname() (string, error) {
	// TODO: use @nathanleclaire retry func here (ehazlett)
	switch {
	case d.Ipv6AddressOnly:
		// IPv6-only mode
		return d.GetIPv6()
	case d.Ipv6AddressCount >= 1:
		// Dual-stack mode
		// preference: IPv4 address, then IPv6 address
		if ip, err := d.GetIP(); err != nil {
			log.Warnf("Error getting IPv4 address: %s", err)
			log.Debug("Getting IPv6 address")
			return d.GetIPv6()
		} else {
			return ip, nil
		}

	default:
		// IPv4-only mode
		return d.GetIP()
	}
}

func (d *Driver) GetSSHUsername() string {
	if d.SSHUser == "" {
		d.SSHUser = defaultSSHUser
	}

	return d.SSHUser
}

func (d *Driver) Start() error {
	_, err := d.getClient().StartInstances(&ec2.StartInstancesInput{
		InstanceIds: []*string{&d.InstanceId},
	})
	if err != nil {
		return err
	}

	return d.waitForInstance()
}

func (d *Driver) Stop() error {
	_, err := d.getClient().StopInstances(&ec2.StopInstancesInput{
		InstanceIds: []*string{&d.InstanceId},
		Force:       aws.Bool(false),
	})
	return err
}

func (d *Driver) Restart() error {
	_, err := d.getClient().RebootInstances(&ec2.RebootInstancesInput{
		InstanceIds: []*string{&d.InstanceId},
	})
	return err
}

func (d *Driver) Kill() error {
	_, err := d.getClient().StopInstances(&ec2.StopInstancesInput{
		InstanceIds: []*string{&d.InstanceId},
		Force:       aws.Bool(true),
	})
	return err
}

func (d *Driver) Remove() error {
	multierr := mcnutils.MultiError{
		Errs: []error{},
	}

	if err := d.terminate(); err != nil {
		multierr.Errs = append(multierr.Errs, err)
	}

	// In case of failure waiting for a SpotInstance, we must cancel the unfulfilled request, otherwise an instance may be created later.
	// If the instance was created, terminating it will be enough for canceling the SpotInstanceRequest
	if d.RequestSpotInstance && d.spotInstanceRequestId != "" {
		if err := d.cancelSpotInstanceRequest(); err != nil {
			multierr.Errs = append(multierr.Errs, err)
		}
	}

	if !d.ExistingKey {
		if err := d.deleteKeyPair(); err != nil && !strings.Contains(err.Error(), "not found") {
			multierr.Errs = append(multierr.Errs, err)
		}
	}

	if len(multierr.Errs) == 0 {
		return nil
	}

	return multierr
}

func (d *Driver) cancelSpotInstanceRequest() error {
	// NB: Canceling a Spot instance request does not terminate running Spot instances associated with the request
	_, err := d.getClient().CancelSpotInstanceRequests(&ec2.CancelSpotInstanceRequestsInput{
		SpotInstanceRequestIds: []*string{&d.spotInstanceRequestId},
	})

	return err
}

func (d *Driver) getInstance() (*ec2.Instance, error) {
	instances, err := d.getClient().DescribeInstances(&ec2.DescribeInstancesInput{
		InstanceIds: []*string{&d.InstanceId},
	})
	if err != nil {
		return nil, err
	}
	if len(instances.Reservations) == 0 || len(instances.Reservations[0].Instances) == 0 {
		return nil, fmt.Errorf("instance %v not found", d.InstanceId)
	}
	return instances.Reservations[0].Instances[0], nil
}

func (d *Driver) instanceIsRunning() bool {
	st, err := d.GetState()
	if err != nil {
		log.Debug(err)
	}
	if st == state.Running {
		return true
	}
	return false
}

func (d *Driver) waitForInstance() error {
	if err := mcnutils.WaitFor(d.instanceIsRunning); err != nil {
		return err
	}

	return nil
}

func (d *Driver) createKeyPair() error {
	keyPath := ""

	if d.SSHPrivateKeyPath == "" {
		log.Debugf("Creating New SSH Key")
		if err := ssh.GenerateSSHKey(d.GetSSHKeyPath()); err != nil {
			return err
		}
		keyPath = d.GetSSHKeyPath()
	} else {
		log.Debugf("Using SSHPrivateKeyPath: %s", d.SSHPrivateKeyPath)
		if err := mcnutils.CopyFile(d.SSHPrivateKeyPath, d.GetSSHKeyPath()); err != nil {
			return err
		}
		if d.KeyName != "" {
			log.Debugf("Using existing EC2 key pair: %s", d.KeyName)
			return nil
		}
		if err := mcnutils.CopyFile(d.SSHPrivateKeyPath+".pub", d.GetSSHKeyPath()+".pub"); err != nil {
			return err
		}
		keyPath = d.SSHPrivateKeyPath
	}

	publicKey, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		return err
	}

	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 5)
	for i := range b {
		b[i] = charset[r.Intn(len(charset))]
	}
	keyName := d.MachineName + "-" + string(b)

	log.Debugf("Creating key pair: %s", keyName)
	_, err = d.getClient().ImportKeyPair(&ec2.ImportKeyPairInput{
		KeyName:           &keyName,
		PublicKeyMaterial: publicKey,
	})
	if err != nil {
		return err
	}
	d.KeyName = keyName
	return nil
}

func (d *Driver) terminate() error {
	if d.InstanceId == "" {
		log.Warn("Missing instance ID, this is likely due to a failure during machine creation")
		return nil
	}

	log.Debugf("Terminating instance: %s", d.InstanceId)
	_, err := d.getClient().TerminateInstances(&ec2.TerminateInstancesInput{
		InstanceIds: []*string{&d.InstanceId},
	})

	if err != nil {
		if strings.HasPrefix(err.Error(), "unknown instance") ||
			strings.HasPrefix(err.Error(), "InvalidInstanceID.NotFound") {
			log.Warn("Remote instance does not exist, proceeding with removing local reference")
			return nil
		}

		return fmt.Errorf("unable to terminate instance: %s", err)
	}
	return nil
}

func (d *Driver) isSwarmMaster() bool {
	return d.SwarmMaster
}

func (d *Driver) securityGroupAvailableFunc(id string) func() bool {
	return func() bool {

		securityGroup, err := d.getClient().DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
			GroupIds: []*string{&id},
		})
		if err == nil && len(securityGroup.SecurityGroups) > 0 {
			return true
		} else if err == nil {
			log.Debugf("No security group with id %v found", id)
			return false
		}
		log.Debug(err)
		return false
	}
}

// buildResourceTags accepts a list of AWS resources that should be tagged
// upon creation of the EC2 instance. Driver.Tags will be applied to all resources
// supplied, except for the ec2InstanceResource which will also have the
// MachineName added as a tag.
//
// NB: The ec2InstanceResource must be passed for the EC2 instance to have a name.
func (d *Driver) buildResourceTags(resources []string) []*ec2.TagSpecification {
	tags := buildEC2Tags(d.Tags)
	if len(tags) == 0 {
		resource := ec2InstanceResource
		return []*ec2.TagSpecification{{
			ResourceType: &resource,
			Tags: []*ec2.Tag{{
				Key:   aws.String("Name"),
				Value: &d.MachineName,
			}},
		}}
	}

	tagSpecs := make([]*ec2.TagSpecification, 0, len(resources)+1)
	for i := range resources {
		var instanceTags []*ec2.Tag
		if resources[i] == ec2InstanceResource {
			// append instance name
			instanceTags = append(instanceTags, &ec2.Tag{
				Key:   aws.String("Name"),
				Value: &d.MachineName,
			})
		}
		tagSpecs = append(tagSpecs, &ec2.TagSpecification{
			ResourceType: &resources[i],
			Tags:         append(tags, instanceTags...),
		})
	}
	return tagSpecs
}

func (d *Driver) configureSecurityGroups(groupNames []string) error {
	if len(groupNames) == 0 {
		log.Debugf("No security groups to configure in %s", d.VpcId)
		return nil
	}

	log.Debugf("Configuring security groups in %s", d.VpcId)
	v := version.Version

	filters := []*ec2.Filter{
		{
			Name:   aws.String("group-name"),
			Values: makePointerSlice(groupNames),
		},
		{
			Name:   aws.String("vpc-id"),
			Values: []*string{&d.VpcId},
		},
	}

	groups, err := d.getClient().DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
		Filters: filters,
	})
	if err != nil {
		return err
	}

	var groupsByName = make(map[string]*ec2.SecurityGroup)
	for _, securityGroup := range groups.SecurityGroups {
		groupsByName[*securityGroup.GroupName] = securityGroup
	}

	for _, groupName := range groupNames {
		var group *ec2.SecurityGroup
		securityGroup, ok := groupsByName[groupName]
		if ok {
			log.Debugf("Found existing security group (%s) in %s", groupName, d.VpcId)
			group = securityGroup
		} else {
			log.Debugf("Creating security group (%s) in %s", groupName, d.VpcId)
			groupResp, err := d.getClient().CreateSecurityGroup(&ec2.CreateSecurityGroupInput{
				GroupName:   aws.String(groupName),
				Description: aws.String("Rancher Nodes"),
				VpcId:       aws.String(d.VpcId),
			})
			if err != nil && !strings.Contains(err.Error(), "already exists") {
				return err
			} else if err != nil {
				filters := []*ec2.Filter{
					{
						Name:   aws.String("group-name"),
						Values: []*string{aws.String(groupName)},
					},
					{
						Name:   aws.String("vpc-id"),
						Values: []*string{&d.VpcId},
					},
				}
				groups, err := d.getClient().DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
					Filters: filters,
				})
				if err != nil {
					return err
				}
				if len(groups.SecurityGroups) == 0 {
					return errors.New("can't find security group")
				}
				group = groups.SecurityGroups[0]
			}

			// Manually translate into the security group construct
			if group == nil {
				group = &ec2.SecurityGroup{
					GroupId:   groupResp.GroupId,
					VpcId:     aws.String(d.VpcId),
					GroupName: aws.String(groupName),
				}
			}

			_, err = d.getClient().CreateTags(&ec2.CreateTagsInput{
				Tags: []*ec2.Tag{
					{
						Key:   aws.String(machineTag),
						Value: aws.String(v),
					},
				},
				Resources: []*string{group.GroupId},
			})
			if err != nil && !strings.Contains(err.Error(), "already exists") {
				return fmt.Errorf("can't create tag for security group. err: %v", err)
			}

			// set Tag to group manually so that we know the group has rancher-nodes tag
			group.Tags = []*ec2.Tag{
				{
					Key:   aws.String(machineTag),
					Value: aws.String(v),
				},
			}

			// wait until created (dat eventual consistency)
			log.Debugf("Waiting for group (%s) to become available", *group.GroupId)
			if err := mcnutils.WaitFor(d.securityGroupAvailableFunc(*group.GroupId)); err != nil {
				return err
			}
		}
		d.SecurityGroupIds = append(d.SecurityGroupIds, *group.GroupId)

		ingressPerms, err := d.ingressPermissions(group)
		if err != nil {
			return err
		}

		if len(ingressPerms) > 0 {
			log.Debugf("Adding the following ingress rules to the security group %s: %v", groupName, ingressPerms)
			_, err := d.getClient().AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
				GroupId:       group.GroupId,
				IpPermissions: ingressPerms,
			})
			if err != nil {
				if strings.Contains(err.Error(), "already exists") {
					log.Debugf("Skip updating the security group due to: %s", err.Error())
				} else {
					return err
				}
			}
		}

		egressPerms, err := d.egressPermissions(group)
		if err != nil {
			return err
		}
		if len(egressPerms) > 0 {
			log.Debugf("Adding the following engress rules to the security group %s: %v", groupName, egressPerms)
			_, err = d.getClient().AuthorizeSecurityGroupEgress(&ec2.AuthorizeSecurityGroupEgressInput{
				GroupId:       group.GroupId,
				IpPermissions: egressPerms,
			})
			if err != nil {
				if strings.Contains(err.Error(), "already exists") {
					log.Debugf("Skip updating the security group due to: %s", err.Error())
				} else {
					return err
				}
			}
		}
	}

	return nil
}

func (d *Driver) ingressPermissions(group *ec2.SecurityGroup) ([]*ec2.IpPermission, error) {
	if d.SecurityGroupReadOnly {
		log.Debugf("Skip checking ingress permission configuration on security group %s", *group.GroupName)
		return nil, nil
	}

	hasV4Inbound := map[string]struct{}{}
	hasV6Inbound := map[string]struct{}{}
	hasGroupRule := map[string]struct{}{}

	// check existing rules
	for _, p := range group.IpPermissions {
		if p == nil || p.FromPort == nil || p.IpProtocol == nil {
			continue
		}
		key := fmt.Sprintf("%d/%s", *p.FromPort, *p.IpProtocol)
		// v4
		if len(p.IpRanges) > 0 {
			hasV4Inbound[key] = struct{}{}
		}
		// v6
		if len(p.Ipv6Ranges) > 0 {
			hasV6Inbound[key] = struct{}{}
		}
		if len(p.UserIdGroupPairs) > 0 {
			hasGroupRule[key] = struct{}{}
		}
	}

	var inboundPerms []*ec2.IpPermission

	// Helper for dual-stack internet-facing rules
	addDualStack := func(proto string, from, to int64) {
		key := fmt.Sprintf("%d/%s", from, proto)
		// IPv4
		if _, ok := hasV4Inbound[key]; !ok {
			inboundPerms = append(inboundPerms,
				newIpPermission(proto, from, to,
					[]*ec2.IpRange{{CidrIp: aws.String(ipRange), Description: aws.String(description)}},
					nil))
		}
		// IPv6
		if _, ok := hasV6Inbound[key]; !ok {
			inboundPerms = append(inboundPerms,
				newIpPermission(proto, from, to, nil,
					[]*ec2.Ipv6Range{{CidrIpv6: aws.String(ipv6Range), Description: aws.String(description)}}))
		}
	}

	// Helper for group-based rules
	addGroupRule := func(proto string, from, to int64) {
		key := fmt.Sprintf("%d/%s", from, proto)
		if _, ok := hasGroupRule[key]; !ok {
			inboundPerms = append(inboundPerms,
				newIpPermission(proto, from, to, nil, nil,
					&ec2.UserIdGroupPair{GroupId: group.GroupId, Description: aws.String(description)}))
		}
	}

	// Rules for rancher-nodes security group
	if *group.GroupName == defaultSecurityGroup && hasTagKey(group.Tags, machineSecurityGroupName) {
		// dual-stack ports
		addDualStack("tcp", sshPort, sshPort)
		addDualStack("tcp", dockerPort, dockerPort)
		addDualStack("tcp", rancherWebhookPort, rancherWebhookPort)
		addDualStack("tcp", kubeApiPort, kubeApiPort)
		addDualStack("tcp", httpPort, httpPort)
		addDualStack("tcp", httpsPort, httpsPort)
		addDualStack("tcp", nodePorts[0], nodePorts[1])
		addDualStack("udp", nodePorts[0], nodePorts[1])

		// group-pair rules
		addGroupRule("tcp", supervisorPort, supervisorPort)
		addGroupRule("tcp", etcdPorts[0], etcdPorts[1])
		addGroupRule("tcp", typhaPorts[0], typhaPorts[1])
		addGroupRule("tcp", otherKubePorts[0], otherKubePorts[1])
		addGroupRule("tcp", kubeProxyPorts[0], kubeProxyPorts[1])
		addGroupRule("tcp", nodeExporter, nodeExporter)
		addGroupRule("tcp", calicoPort, calicoPort)
		addGroupRule("udp", vxlanPorts[0], vxlanPorts[1])
		addGroupRule("udp", flannelPorts[0], flannelPorts[1])
	}

	// Custom open ports from configuration
	for _, p := range d.OpenPorts {
		port, protocol := driverutil.SplitPortProto(p)
		portNum, err := strconv.ParseInt(port, 10, 0)
		if err != nil {
			return nil, fmt.Errorf("invalid port number %s: %s", port, err)
		}
		addDualStack(protocol, portNum, portNum)
	}

	if len(inboundPerms) > 0 {
		log.Debugf("Configuring security group %s ingress rules for IPv4 %s and IPv6 %s", *group.GroupName, ipRange, ipv6Range)
	}
	return inboundPerms, nil
}

func (d *Driver) egressPermissions(group *ec2.SecurityGroup) ([]*ec2.IpPermission, error) {
	if d.SecurityGroupReadOnly || *group.GroupName != defaultSecurityGroup || !hasTagKey(group.Tags, machineSecurityGroupName) {
		log.Debugf("Skipping egress permission configuration on security group %s", *group.GroupName)
		return nil, nil
	}

	hasV4Outbound := false
	hasV6Outbound := false

	// check existing egress rules
	for _, p := range group.IpPermissionsEgress {
		if p == nil || p.IpProtocol == nil || *p.IpProtocol != "-1" {
			continue
		}
		for _, v := range p.IpRanges {
			if v != nil && v.CidrIp != nil && *v.CidrIp == ipRange {
				hasV4Outbound = true
			}
		}
		for _, v := range p.Ipv6Ranges {
			if v != nil && v.CidrIpv6 != nil && *v.CidrIpv6 == ipv6Range {
				hasV6Outbound = true
			}
		}
	}

	var outboundPerms []*ec2.IpPermission

	// IPv4 "allow all"
	if !hasV4Outbound {
		outboundPerms = append(outboundPerms, &ec2.IpPermission{
			IpProtocol: aws.String("-1"),
			IpRanges:   []*ec2.IpRange{{CidrIp: aws.String(ipRange)}},
		})
	}

	// IPv6 "allow all"
	if !hasV6Outbound {
		outboundPerms = append(outboundPerms, &ec2.IpPermission{
			IpProtocol: aws.String("-1"),
			Ipv6Ranges: []*ec2.Ipv6Range{{CidrIpv6: aws.String(ipv6Range)}},
		})
	}

	if len(outboundPerms) > 0 {
		log.Debugf("Configuring security group %s egress for IPv4 %s and IPv6 %s", *group.GroupName, ipRange, ipv6Range)
	}
	return outboundPerms, nil
}

// newIpPermission builds a new IpPermission with optional ranges and group pairs
func newIpPermission(proto string, from, to int64, v4 []*ec2.IpRange, v6 []*ec2.Ipv6Range, groups ...*ec2.UserIdGroupPair) *ec2.IpPermission {
	return &ec2.IpPermission{
		IpProtocol:       aws.String(proto),
		FromPort:         aws.Int64(from),
		ToPort:           aws.Int64(to),
		IpRanges:         v4,
		Ipv6Ranges:       v6,
		UserIdGroupPairs: groups,
	}
}

func (d *Driver) deleteKeyPair() error {
	if d.KeyName == "" {
		log.Warn("Missing key pair name, this is likely due to a failure during machine creation")
		return nil
	}

	log.Debugf("Deleting key pair: %s", d.KeyName)

	var deleteInput ec2.DeleteKeyPairInput
	instance, err := d.getInstance()
	if err != nil {
		// do not return err as we may have generated a key
		// but failed to create an instance. We still want to
		// delete the key that we have stored locally
		log.Infof("Could not retrieve EC2 instance while attempting key-pair deletion, will attempt to delete locally stored key %s", d.KeyName)
		deleteInput.KeyName = &d.KeyName
	} else {
		// if we get an instance we should delete the
		// returned key pair as it may have been changed
		// outside of machine.
		deleteInput.KeyName = instance.KeyName
	}

	_, err = d.getClient().DeleteKeyPair(&deleteInput)
	if err != nil {
		return err
	}

	return nil
}

func (d *Driver) getDefaultVPCId() (string, error) {
	output, err := d.getClient().DescribeAccountAttributes(&ec2.DescribeAccountAttributesInput{})
	if err != nil {
		return "", err
	}

	for _, attribute := range output.AccountAttributes {
		if *attribute.AttributeName == "default-vpc" {
			return *attribute.AttributeValues[0].AttributeValue, nil
		}
	}

	return "", errors.New("no default-vpc attribute")
}

func (d *Driver) getRegionZone() string {
	if d.Endpoint == "" {
		return d.Region + d.Zone
	}
	return d.Zone
}

// buildEC2Tags accepts a string of tagGroups (in the format of 'key1,value1,key2,value2')
// and returns a slice of ec2.Tags which can be applied to various ec2 resources.
func buildEC2Tags(tagGroups string) []*ec2.Tag {
	if tagGroups == "" {
		return []*ec2.Tag{}
	}

	t := strings.Split(tagGroups, ",")
	if len(t)%2 != 0 {
		fmt.Printf("Tags are not key value in pairs. %d elements found\n\n", len(t))
	}

	tags := make([]*ec2.Tag, 0, len(t)/2)
	for i := 0; i < len(t)-1; i += 2 {
		tags = append(tags, &ec2.Tag{
			Key:   &t[i],
			Value: &t[i+1],
		})
	}

	return tags
}

func generateId() string {
	rb := make([]byte, 10)
	_, err := rand.Read(rb)
	if err != nil {
		log.Warnf("Unable to generate id: %s", err)
	}

	h := md5.New()
	if _, err := io.WriteString(h, string(rb)); err != nil {
		return ""
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func hasTagKey(tags []*ec2.Tag, key string) bool {
	for _, tag := range tags {
		if *tag.Key == key {
			return true
		}
	}
	return false
}

func (d *Driver) updateBDMList() []*ec2.BlockDeviceMapping {
	var bdmList []*ec2.BlockDeviceMapping

	for _, bdm := range d.bdmList {
		if bdm.Ebs != nil {
			if *bdm.DeviceName == d.DeviceName {
				bdm.Ebs.VolumeSize = aws.Int64(d.RootSize)
				bdm.Ebs.VolumeType = aws.String(d.VolumeType)
			}
			bdm.Ebs.DeleteOnTermination = aws.Bool(true)
			bdm.Ebs.KmsKeyId = d.kmsKeyId
			bdm.Ebs.Encrypted = aws.Bool(d.EncryptEbsVolume)
			bdmList = append(bdmList, bdm)
		}
	}

	return bdmList
}
