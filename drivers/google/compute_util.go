package google

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/rancher/machine/drivers/driverutil"
	"github.com/rancher/machine/libmachine/log"
	"github.com/rancher/wrangler/v3/pkg/name"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	raw "google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

// ComputeUtil is used to wrap the raw GCE API code and store common parameters.
type ComputeUtil struct {
	zone                       string
	instanceName               string
	userName                   string
	project                    string
	diskTypeURL                string
	address                    string
	network                    string
	subnetwork                 string
	preemptible                bool
	useInternalIP              bool
	useInternalIPOnly          bool
	service                    *raw.Service
	zoneURL                    string
	globalURL                  string
	SwarmMaster                bool
	SwarmHost                  string
	openPorts                  []string
	externalFirewallRulePrefix string
	internalFirewallRulePrefix string
}

const (
	apiURL                       = "https://www.googleapis.com/compute/v1/projects/"
	externalFirewallRuleSuffix   = "external-rancher-node"
	internalFirewallRuleSuffix   = "internal-rancher-nodes"
	externalFirewallRuleLabelKey = "rancher-external-fw-rule"
	internalFirewallRuleLabelKey = "rancher-internal-fw-rule"
)

// NewComputeUtil creates and initializes a ComputeUtil.
func newComputeUtil(driver *Driver) (*ComputeUtil, error) {
	ctx := context.Background()
	var client *http.Client

	if driver.Auth != "" {
		jsonCreds, err := base64.StdEncoding.DecodeString(driver.Auth)
		if err != nil {
			// attempt to read the credentials as plain text
			jsonCreds = []byte(driver.Auth)
		}
		creds, err := google.CredentialsFromJSON(ctx, jsonCreds, raw.ComputeScope)
		if err != nil {
			return nil, fmt.Errorf("failed to parse provided credentials: %w", err)
		}
		client = oauth2.NewClient(ctx, creds.TokenSource)
	} else {
		var err error
		log.Warn("Using default client to authenticate with GCP")
		client, err = google.DefaultClient(ctx, raw.ComputeScope)
		if err != nil {
			return nil, err
		}
	}

	service, err := raw.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	return &ComputeUtil{
		zone:                       driver.Zone,
		instanceName:               driver.MachineName,
		userName:                   driver.SSHUser,
		project:                    driver.Project,
		diskTypeURL:                driver.DiskType,
		address:                    driver.Address,
		network:                    driver.Network,
		subnetwork:                 driver.Subnetwork,
		preemptible:                driver.Preemptible,
		useInternalIP:              driver.UseInternalIP,
		useInternalIPOnly:          driver.UseInternalIPOnly,
		service:                    service,
		zoneURL:                    apiURL + driver.Project + "/zones/" + driver.Zone,
		globalURL:                  apiURL + driver.Project + "/global",
		SwarmMaster:                driver.SwarmMaster,
		SwarmHost:                  driver.SwarmHost,
		openPorts:                  driver.OpenPorts,
		externalFirewallRulePrefix: driver.ExternalFirewallRulePrefix,
		internalFirewallRulePrefix: driver.InternalFirewallRulePrefix,
	}, nil
}

func (c *ComputeUtil) diskName() string {
	return c.instanceName + "-disk"
}

func (c *ComputeUtil) diskType() string {
	return apiURL + c.project + "/zones/" + c.zone + "/diskTypes/" + c.diskTypeURL
}

// disk returns the persistent disk attached to the vm.
func (c *ComputeUtil) disk() (*raw.Disk, error) {
	return c.service.Disks.Get(c.project, c.zone, c.diskName()).Do()
}

// deleteDisk deletes the persistent disk.
func (c *ComputeUtil) deleteDisk() error {
	disk, _ := c.disk()
	if disk == nil {
		return nil
	}

	log.Infof("Deleting disk.")
	op, err := c.service.Disks.Delete(c.project, c.zone, c.diskName()).Do()
	if err != nil {
		return err
	}

	log.Infof("Waiting for disk to delete.")
	return c.waitForRegionalOp(op.Name)
}

// staticAddress returns the external static IP address.
func (c *ComputeUtil) staticAddress() (string, error) {
	// is the address a name?
	isName, err := regexp.MatchString("[a-z]([-a-z0-9]*[a-z0-9])?", c.address)
	if err != nil {
		return "", err
	}

	if !isName {
		return c.address, nil
	}

	// resolve the address by name
	externalAddress, err := c.service.Addresses.Get(c.project, c.region(), c.address).Do()
	if err != nil {
		return "", err
	}

	return externalAddress.Address, nil
}

func (c *ComputeUtil) region() string {
	return c.zone[:len(c.zone)-2]
}

func (c *ComputeUtil) externalFirewallRule() (*raw.Firewall, error) {
	return c.service.Firewalls.Get(c.project, c.externalFirewallRuleName()).Do()
}

func (c *ComputeUtil) internalFirewallRule() (*raw.Firewall, error) {
	return c.service.Firewalls.Get(c.project, c.internalFirewallRuleName()).Do()
}

func (c *ComputeUtil) externalFirewallRuleName() string {
	return name.SafeConcatName(c.externalFirewallRulePrefix, externalFirewallRuleSuffix)
}

func (c *ComputeUtil) internalFirewallRuleName() string {
	return name.SafeConcatName(c.internalFirewallRulePrefix, internalFirewallRuleSuffix)
}

func missingOpenedPorts(rule *raw.Firewall, ports []string) map[string][]string {
	missing := map[string][]string{}
	opened := map[string]bool{}

	for _, allowed := range rule.Allowed {
		for _, allowedPort := range allowed.Ports {
			opened[allowedPort+"/"+allowed.IPProtocol] = true
		}
	}

	for _, p := range ports {
		port, proto := driverutil.SplitPortProto(p)
		if !opened[port+"/"+proto] {
			missing[proto] = append(missing[proto], port)
		}
	}
	if len(missing) > 0 {
		log.Warnf("found missing ports for firewall rule '%s': %v", rule.Name, missing)
	}
	return missing
}

func (c *ComputeUtil) portsUsed() ([]string, error) {
	var ports []string

	if c.SwarmMaster {
		u, err := url.Parse(c.SwarmHost)
		if err != nil {
			return nil, fmt.Errorf("error authorizing port for swarm: %s", err)
		}

		swarmPort := strings.Split(u.Host, ":")[1]
		ports = append(ports, swarmPort+"/tcp")
	}
	for _, p := range c.openPorts {
		port, proto := driverutil.SplitPortProto(p)
		ports = append(ports, port+"/"+proto)
	}

	return ports, nil
}

// openInternalFirewallPorts configures a firewall rule for internal VPC network access only.
func (c *ComputeUtil) openInternalFirewallPorts(d *Driver) error {

	expectedPorts := []string{
		"8443",
		"179",
		"5473",
		"10256",
		"10250",
		"10251",
		"10252",
		"6443",
		"2379",
		"2380",
		"4789",
		"2376",
		"9345",
		"9796",
		"8472/udp",
		"4789/udp",
	}

	create := false
	rule, _ := c.internalFirewallRule()
	if rule == nil {
		log.Infof("Creating internal firewall rule '%s'", c.internalFirewallRuleName())
		create = true
		rule = &raw.Firewall{
			Name:        c.internalFirewallRuleName(),
			Description: "rancher-machine managed internal firewall rule",
			Allowed:     []*raw.FirewallAllowed{},
			SourceTags:  []string{c.internalFirewallRuleName()},
			TargetTags:  []string{c.internalFirewallRuleName()},
			Network:     c.globalURL + "/networks/" + d.Network,
		}
	}

	missingPorts := missingOpenedPorts(rule, expectedPorts)
	if len(missingPorts) == 0 {
		log.Debugf("Do not need to update internal firewall rule '%s' as all ports are configured", rule.Name)
		return nil
	}

	for proto, ports := range missingPorts {
		rule.Allowed = append(rule.Allowed, &raw.FirewallAllowed{
			IPProtocol: proto,
			Ports:      ports,
		})
	}

	var err error
	var op *raw.Operation

	if create {
		log.Infof("Creating new internal firewall rule '%s'", rule.Name)
		op, err = c.service.Firewalls.Insert(c.project, rule).Do()
	} else {
		log.Infof("Updating existing internal firewall rule '%s'", rule.Name)
		op, err = c.service.Firewalls.Update(c.project, c.internalFirewallRuleName(), rule).Do()
	}

	if err != nil {
		return err
	}

	return c.waitForGlobalOp(op.Name)
}

// openPublicFirewallPorts configures the firewall to open ports publicly.
func (c *ComputeUtil) openPublicFirewallPorts(d *Driver) error {
	create := false
	rule, _ := c.externalFirewallRule()
	if rule == nil {
		create = true
		rule = &raw.Firewall{
			Name:         c.externalFirewallRuleName(),
			Description:  "rancher-machine managed external firewall rule",
			Allowed:      []*raw.FirewallAllowed{},
			SourceRanges: []string{"0.0.0.0/0"},
			SourceTags:   []string{c.externalFirewallRuleName()},
			TargetTags:   []string{c.externalFirewallRuleName()},
			Network:      c.globalURL + "/networks/" + d.Network,
		}
	}

	portsUsed, err := c.portsUsed()
	if err != nil {
		return err
	}

	missingPorts := missingOpenedPorts(rule, portsUsed)
	if len(missingPorts) == 0 {
		log.Infof("Do not need to update external firewall rule '%s' as all ports are configured", rule.Name)
		return nil
	}
	for proto, ports := range missingPorts {
		rule.Allowed = append(rule.Allowed, &raw.FirewallAllowed{
			IPProtocol: proto,
			Ports:      ports,
		})
	}

	var op *raw.Operation
	if create {
		log.Infof("Creating new external firewall rule '%s'", rule.Name)
		op, err = c.service.Firewalls.Insert(c.project, rule).Do()
	} else {
		log.Infof("Updating existing external firewall rule '%s'", rule.Name)
		op, err = c.service.Firewalls.Update(c.project, c.externalFirewallRuleName(), rule).Do()
	}
	if err != nil {
		return err
	}

	return c.waitForGlobalOp(op.Name)
}

// CleanUpFirewallRule attempts to remove a network firewall rule if no VMs are currently associated with that rule.
// It expects that VMs utilizing this rule have been appropriately labeled with the provided label key,
// and that the value of that key equals the name of the provided raw.Firewall.
func (c *ComputeUtil) CleanUpFirewallRule(rule *raw.Firewall, labelKey string) error {
	if rule == nil {
		return fmt.Errorf("firewall rule cannot be nil")
	}

	log.Infof("Attempting to remove rancher-machine managed firewall rule '%s'", rule.Name)
	log.Infof("Checking if any instances are still using this rule...")

	filter := fmt.Sprintf("labels.%s=%s", labelKey, rule.Name)
	inst, err := c.service.Instances.List(c.project, c.zone).Filter(filter).Do()
	if err != nil {
		return fmt.Errorf("failed to list instances associated with the firewall rule '%s': %w", rule.Name, err)
	}

	if len(inst.Items) != 0 {
		log.Infof("%d instances are still using the firewall rule '%s', skipping deletion", len(inst.Items), rule.Name)
		return nil
	}

	log.Infof("Removing rancher-machine managed firewall rule '%s' from project as no instances are using it", rule.Name)
	op, err := c.service.Firewalls.Delete(c.project, rule.Name).Do()
	if err != nil {
		return fmt.Errorf("failed to remove rancher-machine managed firewall rule '%s': %w", rule.Name, err)
	}

	return c.waitForGlobalOp(op.Name)
}

// instance retrieves the instance.
func (c *ComputeUtil) instance() (*raw.Instance, error) {
	return c.service.Instances.Get(c.project, c.zone, c.instanceName).Do()
}

// createInstance creates a GCE VM instance.
func (c *ComputeUtil) createInstance(d *Driver) error {
	log.Infof("Creating instance")

	var net string
	if strings.Contains(d.Network, "/networks/") {
		net = d.Network
	} else {
		net = c.globalURL + "/networks/" + d.Network
	}

	instance := &raw.Instance{
		Name:        c.instanceName,
		Description: "rancher-machine provisioned virtual machine",
		MachineType: c.zoneURL + "/machineTypes/" + d.MachineType,
		Disks: []*raw.AttachedDisk{
			{
				Boot:       true,
				AutoDelete: true,
				Type:       "PERSISTENT",
				Mode:       "READ_WRITE",
			},
		},
		NetworkInterfaces: []*raw.NetworkInterface{
			{
				Network: net,
			},
		},
		Tags: &raw.Tags{
			Items: parseTags(d, c),
		},
		Labels: parseLabels(d.Labels),
		ServiceAccounts: []*raw.ServiceAccount{
			{
				Email:  "default",
				Scopes: strings.Split(d.Scopes, ","),
			},
		},
		Scheduling: &raw.Scheduling{
			Preemptible: c.preemptible,
		},
	}

	// This is a workaround to a known issue in the GCE API which prevents the standard .List() function from filtering
	// instances based off of network tags https://issuetracker.google.com/issues/143463446#comment9,
	// instead we use a label which equals the name of the generated firewall rule.
	if len(d.OpenPorts) > 0 {
		instance.Labels[externalFirewallRuleLabelKey] = c.externalFirewallRuleName()
	}

	if c.internalFirewallRulePrefix != "" {
		instance.Labels[internalFirewallRuleLabelKey] = c.internalFirewallRuleName()
	}

	if strings.Contains(c.subnetwork, "/subnetworks/") {
		instance.NetworkInterfaces[0].Subnetwork = c.subnetwork
	} else if c.subnetwork != "" {
		instance.NetworkInterfaces[0].Subnetwork = "projects/" + c.project + "/regions/" + c.region() + "/subnetworks/" + c.subnetwork
	}

	if !c.useInternalIPOnly {
		cfg := &raw.AccessConfig{
			Type: "ONE_TO_ONE_NAT",
		}
		instance.NetworkInterfaces[0].AccessConfigs = append(instance.NetworkInterfaces[0].AccessConfigs, cfg)
	}

	if c.address != "" {
		staticAddress, err := c.staticAddress()
		if err != nil {
			return err
		}

		instance.NetworkInterfaces[0].AccessConfigs[0].NatIP = staticAddress
	}

	disk, err := c.disk()
	if disk == nil || err != nil {
		instance.Disks[0].InitializeParams = &raw.AttachedDiskInitializeParams{
			DiskName:    c.diskName(),
			SourceImage: "https://www.googleapis.com/compute/v1/projects/" + d.MachineImage,
			// The maximum supported disk size is 1000GB, the cast should be fine.
			DiskSizeGb: int64(d.DiskSize),
			DiskType:   c.diskType(),
		}
	} else {
		instance.Disks[0].Source = c.zoneURL + "/disks/" + c.instanceName + "-disk"
	}

	op, err := c.service.Instances.Insert(c.project, c.zone, instance).Do()
	if err != nil {
		return err
	}

	if err = c.waitForRegionalOp(op.Name); err != nil {
		return err
	}

	instance, err = c.instance()
	if err != nil {
		return err
	}

	return c.uploadSSHKeyAndUserdata(instance, d.GetSSHKeyPath(), d.Userdata)
}

// configureInstance configures an existing instance for use with Docker Machine.
func (c *ComputeUtil) configureInstance(d *Driver) error {
	instance, err := c.instance()
	if err != nil {
		return err
	}

	if len(d.OpenPorts) > 0 {
		if err := c.addFirewallTag(instance); err != nil {
			return err
		}
	}

	return c.uploadSSHKeyAndUserdata(instance, d.GetSSHKeyPath(), d.Userdata)
}

// addFirewallTag adds a tag to the instance to match the firewall rule.
func (c *ComputeUtil) addFirewallTag(instance *raw.Instance) error {
	tags := instance.Tags
	for _, tag := range tags.Items {
		if tag == c.externalFirewallRuleName() {
			return nil
		}
	}

	tags.Items = append(tags.Items, c.externalFirewallRuleName())

	op, err := c.service.Instances.SetTags(c.project, c.zone, instance.Name, tags).Do()
	if err != nil {
		return err
	}

	return c.waitForRegionalOp(op.Name)
}

// uploadSSHKeyUserdata updates the instance metadata with the given ssh key and userdata.
func (c *ComputeUtil) uploadSSHKeyAndUserdata(instance *raw.Instance, sshKeyPath, userdata string) error {
	log.Infof("Uploading SSH Key and userdata")

	sshKey, err := os.ReadFile(sshKeyPath + ".pub")
	if err != nil {
		return err
	}

	metaDataValue := fmt.Sprintf("%s:%s %s\n", c.userName, strings.TrimSpace(string(sshKey)), c.userName)
	metadata := &raw.Metadata{
		Fingerprint: instance.Metadata.Fingerprint,
		Items: []*raw.MetadataItems{
			{
				Key:   "sshKeys",
				Value: &metaDataValue,
			},
		},
	}

	if userdata != "" {
		metadata.Items = append(metadata.Items, &raw.MetadataItems{
			Key:   "user-data",
			Value: &userdata,
		})
	}

	op, err := c.service.Instances.SetMetadata(c.project, c.zone, c.instanceName, metadata).Do()

	return c.waitForRegionalOp(op.Name)
}

// parseTags computes the tags for the instance.
func parseTags(d *Driver, c *ComputeUtil) []string {
	var tags []string

	if d.Tags != "" {
		tags = append(tags, strings.Split(d.Tags, ",")...)
	}

	var foundInternal, foundExternal bool
	for _, tag := range tags {
		if tag == c.externalFirewallRulePrefix {
			foundExternal = true
		} else if tag == c.internalFirewallRulePrefix {
			foundInternal = true
		}
	}

	if !foundInternal && c.internalFirewallRulePrefix != "" {
		tags = append(tags, c.internalFirewallRuleName())
	}

	if !foundExternal && len(d.OpenPorts) > 0 {
		tags = append(tags, c.externalFirewallRuleName())
	}

	return tags
}

// parseLabels computes the labels for an instance. It expects labels to be in the
// form of 'key1,value1,key2,value2'. Any keys which are not followed by a value are dropped,
// (e.g. 'key1,value1,key2') but all previous keys will be properly returned.
func parseLabels(labels string) map[string]string {
	m := make(map[string]string)
	if labels == "" {
		return m
	}

	allTags := strings.Split(labels, ",")
	if len(allTags)%2 != 0 {
		fmt.Printf("Tags are not in key value pairs. %d elements found\n", len(allTags))
	}

	for i := 0; i < len(allTags)-1; i += 2 {
		m[allTags[i]] = allTags[i+1]
	}

	return m
}

// deleteInstance deletes the instance, leaving the persistent disk.
func (c *ComputeUtil) deleteInstance() error {
	log.Infof("Deleting instance.")
	op, err := c.service.Instances.Delete(c.project, c.zone, c.instanceName).Do()
	if err != nil {
		return err
	}

	log.Infof("Waiting for instance to delete.")
	return c.waitForRegionalOp(op.Name)
}

// stopInstance stops the instance.
func (c *ComputeUtil) stopInstance() error {
	op, err := c.service.Instances.Stop(c.project, c.zone, c.instanceName).Do()
	if err != nil {
		return err
	}

	log.Infof("Waiting for instance to stop.")
	return c.waitForRegionalOp(op.Name)
}

// startInstance starts the instance.
func (c *ComputeUtil) startInstance() error {
	op, err := c.service.Instances.Start(c.project, c.zone, c.instanceName).Do()
	if err != nil {
		return err
	}

	log.Infof("Waiting for instance to start.")
	return c.waitForRegionalOp(op.Name)
}

// waitForOp waits for the operation to finish.
func (c *ComputeUtil) waitForOp(opGetter func() (*raw.Operation, error)) error {
	for {
		op, err := opGetter()
		if err != nil {
			return err
		}

		log.Debugf("Operation %q status: %s", op.Name, op.Status)
		if op.Status == "DONE" {
			if op.Error != nil {
				return fmt.Errorf("Operation error: %v", *op.Error.Errors[0])
			}
			break
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

// waitForRegionalOp waits for the regional operation to finish.
func (c *ComputeUtil) waitForRegionalOp(name string) error {
	return c.waitForOp(func() (*raw.Operation, error) {
		return c.service.ZoneOperations.Get(c.project, c.zone, name).Do()
	})
}

// waitForGlobalOp waits for the global operation to finish.
func (c *ComputeUtil) waitForGlobalOp(name string) error {
	return c.waitForOp(func() (*raw.Operation, error) {
		return c.service.GlobalOperations.Get(c.project, name).Do()
	})
}

// ip retrieves and returns the external IP address of the instance.
func (c *ComputeUtil) ip() (string, error) {
	instance, err := c.service.Instances.Get(c.project, c.zone, c.instanceName).Do()
	if err != nil {
		return "", unwrapGoogleError(err)
	}

	nic := instance.NetworkInterfaces[0]
	if c.useInternalIP {
		return nic.NetworkIP, nil
	}
	return nic.AccessConfigs[0].NatIP, nil
}

func unwrapGoogleError(err error) error {
	if googleErr, ok := err.(*googleapi.Error); ok {
		return errors.New(googleErr.Message)
	}

	return err
}

func isNotFound(err error) bool {
	googleErr, ok := err.(*googleapi.Error)
	if !ok {
		return false
	}

	if googleErr.Code == http.StatusNotFound {
		return true
	}

	return false
}
