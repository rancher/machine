package vmwarevsphere

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/rancher/machine/libmachine/log"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
	"gopkg.in/yaml.v2"
)

const (
	isoName     = "user-data.iso"
	isoDir      = "cloudinit"
	mkisofsName = "mkisofs"
)

func (d *Driver) cloudInit(vm *object.VirtualMachine) error {
	if d.CreationType == creationTypeLegacy {
		return d.cloudInitGuestInfo(vm)
	}

	if err := d.createCloudInitIso(); err != nil {
		return err
	}

	ds, err := d.getVmDatastore(vm)
	if err != nil {
		return err
	}

	err = d.uploadCloudInitIso(vm, d.datacenter, ds)
	if err != nil {
		return err
	}

	return d.mountCloudInitIso(vm, d.datacenter, ds)
}

func (d *Driver) cloudInitGuestInfo(vm *object.VirtualMachine) error {
	if d.CloudInit != "" {
		var opts []types.BaseOptionValue
		if _, err := url.ParseRequestURI(d.CloudInit); err == nil {
			log.Infof("setting guestinfo.cloud-init.data.url to %s\n", d.CloudInit)
			opts = append(opts, &types.OptionValue{
				Key:   "guestinfo.cloud-init.config.url",
				Value: d.CloudInit,
			})
		} else {
			if _, err := os.Stat(d.CloudInit); err == nil {
				if value, err := ioutil.ReadFile(d.CloudInit); err == nil {
					log.Infof("setting guestinfo.cloud-init.data to encoded content of %s\n", d.CloudInit)
					encoded := base64.StdEncoding.EncodeToString(value)
					opts = append(opts, &types.OptionValue{
						Key:   "guestinfo.cloud-init.config.data",
						Value: encoded,
					})
					opts = append(opts, &types.OptionValue{
						Key:   "guestinfo.cloud-init.data.encoding",
						Value: "base64",
					})
				}
			}
		}
		return d.applyOpts(vm, opts)
	}

	return nil
}

func (d *Driver) uploadCloudInitIso(vm *object.VirtualMachine, dc *object.Datacenter, ds *object.Datastore) error {
	log.Infof("Uploading %s", isoName)
	path, err := d.getVmFolder(vm)
	if err != nil {
		return err
	}

	p := soap.DefaultUpload
	c, err := d.getSoapClient()
	if err != nil {
		return err
	}

	dsurl := ds.NewURL(filepath.Join(path, isoName))
	if err = c.Client.UploadFile(d.getCtx(), d.ResolveStorePath(filepath.Join(isoDir, isoName)), dsurl, &p); err != nil {
		return err
	}

	return nil
}

func (d *Driver) removeCloudInitIso(vm *object.VirtualMachine, dc *object.Datacenter, ds *object.Datastore) error {
	log.Infof("Removing %s", isoName)
	c, err := d.getSoapClient()
	if err != nil {
		return err
	}

	path, err := d.getVmFolder(vm)
	if err != nil {
		return err
	}

	m := object.NewFileManager(c.Client)
	task, err := m.DeleteDatastoreFile(d.getCtx(), ds.Path(filepath.Join(path, isoName)), dc)
	if err != nil {
		return err
	}

	if err = task.Wait(d.getCtx()); err != nil {
		if types.IsFileNotFound(err) {
			// already deleted, ignore error
			return nil
		}

		return err
	}

	return nil
}

func (d *Driver) createCloudInitIso() error {
	log.Infof("Creating cloud-init.iso")
	//d.CloudConfig stat'ed and loaded in flag load.
	sshkey, err := ioutil.ReadFile(d.publicSSHKeyPath())
	if err != nil {
		return err
	}

	userdatacontent, err := d.addSSHUserToYaml(string(sshkey))
	if err != nil {
		return err
	}

	perm := os.FileMode(0700)
	isoDir := d.ResolveStorePath(isoDir)
	dataDir := filepath.Join(isoDir, "data")
	userdata := filepath.Join(dataDir, "user-data")
	metadata := filepath.Join(dataDir, "meta-data")

	err = os.MkdirAll(dataDir, perm)
	if err != nil {
		return err
	}

	writeYaml := fmt.Sprintf("#cloud-config\n%s", userdatacontent)
	if err = ioutil.WriteFile(userdata, []byte(writeYaml), perm); err != nil {
		return err
	}

	md := []byte(fmt.Sprintf("local-hostname: %s\n", d.MachineName))
	if err = ioutil.WriteFile(metadata, md, perm); err != nil {
		return err
	}

	// validate that our files are present in the isoDir before creating the ISO
	for filename, filepath := range map[string]string{"user-data": userdata, "meta-data": metadata} {
		_, err = os.Stat(filepath)
		if err != nil {
			return fmt.Errorf("error: %s found when verifying that %s file was present for machine %s", err, filename, d.MachineName)
		}
	}

	err = os.Chdir(filepath.Join(d.StorePath, "machines", d.MachineName))
	if err != nil {
		return err
	}

	diskImg := filepath.Join(isoDir, isoName)

	// making iso
	// iso-level 1 ensures that files may only consist of one section and filenames are restricted to 8.3 characters.
	// this maintains backwards compatibility with the previous go-diskfs method of creating ISOs
	path, err := binaryPathLookup(mkisofsName)
	if err != nil {
		return fmt.Errorf("createCloudInitIso: path lookup for %s failed: %v", mkisofsName, err)
	}

	isoArgs := []string{"-J", "-r", "-hfs", "-iso-level", "1", "-V", "cidata", "-output",
		fmt.Sprintf("%s", diskImg), "-graft-points", fmt.Sprintf("%s", dataDir)}
	iso := exec.Command(path, isoArgs...)
	iso.Env = []string{
		"PATH=" + os.Getenv("PATH"),
	}
	iso.Stdout = os.Stdout
	iso.Stderr = os.Stderr
	err = iso.Start()
	if err != nil {
		return fmt.Errorf("createCloudInitIso: mkisofs command failed to start with error %v", err)
	}
	log.Debugf("createCloudInitIso: Waiting for mkisofs command to finish...")
	err = iso.Wait()
	if err != nil {
		return fmt.Errorf("createCloudInitIso: mkisofs command failed to complete with error: %v", err)
	}
	log.Debugf("createCloudInitIso: mkisofs command successfully finished")
	return nil
}

func (d *Driver) mountCloudInitIso(vm *object.VirtualMachine, dc *object.Datacenter, dss *object.Datastore) error {
	log.Debugf("Mounting cloudinit %s", isoName)
	devices, err := vm.Device(d.getCtx())
	if err != nil {
		return err
	}

	ide, err := devices.FindIDEController("")
	if err != nil {
		return err
	}

	var add []types.BaseVirtualDevice
	cdrom, err := devices.CreateCdrom(ide)
	if err != nil {
		return err
	}

	path, err := d.getVmFolder(vm)
	if err != nil {
		return err
	}

	add = append(add, devices.InsertIso(cdrom, dss.Path(filepath.Join(path, isoName))))
	return vm.AddDevice(d.getCtx(), add...)
}

// addSSHUserToYaml parses user, group, and sshkey params that are passed in
// and appends them to the existing cloud-config (cloudInit) userdata file
// there is OS specific logic for linux and windows
// Windows leverages cloudbase-init as cloudinit is unsupported on Windows
// https://cloudbase-init.readthedocs.io/en/latest/
func (d *Driver) addSSHUserToYaml(sshkey string) (string, error) {
	var (
		sshUser     = d.SSHUser
		group       = d.SSHUserGroup
		yamlcontent = d.CloudConfig
	)
	cf := make(map[interface{}]interface{})
	if err := yaml.Unmarshal([]byte(yamlcontent), &cf); err != nil {
		return "", err
	}

	commonUser := map[interface{}]interface{}{
		"name":        sshUser,
		"lock_passwd": true,
		"groups":      group,
		"ssh_authorized_keys": []string{
			sshkey,
		},
	}

	switch d.OS {
	default:
		log.Debug("[addSSHUserToYaml] Adding linux ssh user to cloud-init")
		// implements https://github.com/canonical/cloud-init/blob/master/cloudinit/config/cc_users_groups.py#L28-L71
		// technically not in the spec, see this code for context
		// https://github.com/canonical/cloud-init/blob/master/cloudinit/distros/__init__.py#L394-L397
		commonUser["sudo"] = "ALL=(ALL) NOPASSWD:ALL"
		commonUser["create_groups"] = false
		commonUser["no_user_group"] = true

	// Administrator is the default ssh user on Windows Server 2019/2022
	// This implements cloudbase-init for Windows VMs as cloud-init doesn't support Windows
	// https://cloudbase-init.readthedocs.io/en/latest/
	// On Windows, primary_group and groups are concatenated.
	case WindowsMachineOS:
		log.Debug("[addSSHUserToYaml] Adding windows ssh user to cloud-init")
		commonUser["inactive"] = false
	}

	if val, ok := cf["users"]; ok {
		u := val.([]interface{})
		cf["users"] = append(u, commonUser)
	} else {
		users := make([]interface{}, 1)
		users[0] = commonUser
		cf["users"] = users
	}

	if val, ok := cf["groups"]; ok {
		g := val.([]interface{})
		var exists = false
		for _, v := range g {
			if y, _ := v.(string); y == group {
				exists = true
			}
		}
		if !exists {
			cf["groups"] = append(g, group)
		}
	} else {
		g := make([]interface{}, 1)
		g[0] = group
		cf["groups"] = g
	}

	yaml, err := yaml.Marshal(cf)
	if err != nil {
		return "", err
	}
	return string(yaml), nil
}

func binaryPathLookup(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("binaryPathLookup: error returned when trying to find [%s] executable: [%v]", name, err)
	}
	return path, nil
}
