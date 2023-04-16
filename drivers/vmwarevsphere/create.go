package vmwarevsphere

import (
	"fmt"
	"path/filepath"

	"github.com/rancher/machine/libmachine/log"
	"github.com/vmware/govmomi/find"
	"github.com/vmware/govmomi/object"
	"github.com/vmware/govmomi/vapi/library"
	vapifinder "github.com/vmware/govmomi/vapi/library/finder"
	"github.com/vmware/govmomi/vapi/vcenter"
	"github.com/vmware/govmomi/vim25/mo"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/vim25/types"
)

// preCreate creates a soap client and then fetches defaults
// for datacenter, hostsystem, and resourcepool
func (d *Driver) preCreate() error {
	c, err := d.getSoapClient()
	if err != nil {
		return err
	}

	d.finder = find.NewFinder(c.Client, true)

	d.datacenter, err = d.finder.DatacenterOrDefault(d.getCtx(), d.Datacenter)
	if err != nil {
		return err
	}
	log.Infof("Using datacenter %s", d.datacenter.InventoryPath)
	d.finder.SetDatacenter(d.datacenter)
	for _, netName := range d.Networks {
		net, err := d.finder.NetworkOrDefault(d.getCtx(), netName)
		if err != nil {
			return err
		}
		d.networks[netName] = net
		log.Infof("Using network %s", net.GetInventoryPath())
	}

	if d.HostSystem != "" {
		var err error
		d.hostsystem, err = d.finder.HostSystemOrDefault(d.getCtx(), d.HostSystem)
		if err != nil {
			return err
		}
		log.Infof("Using hostsystem %s", d.hostsystem.InventoryPath)
	}

	if d.Pool != "" {
		// Find specified Resource Pool
		d.resourcepool, err = d.finder.ResourcePool(d.getCtx(), d.Pool)
		if err != nil {
			return err
		}
	} else if d.HostSystem != "" {
		// Pick default Resource Pool for Host System
		d.resourcepool, err = d.hostsystem.ResourcePool(d.getCtx())
		if err != nil {
			return err
		}
	} else {
		// Pick the default Resource Pool for the Datacenter.
		d.resourcepool, err = d.finder.DefaultResourcePool(d.getCtx())
		if err != nil {
			return err
		}
	}
	log.Infof("Using ResourcePool %s", d.resourcepool.InventoryPath)
	return nil
}

// postCreate adds additional VM configuration,
// parses, applies, and creates the cloudInit ISO
// and adds tags and custom attributes
func (d *Driver) postCreate(vm *object.VirtualMachine) error {
	if err := d.addConfigParams(vm); err != nil {
		return err
	}

	if err := d.cloudInit(vm); err != nil {
		return err
	}

	if err := d.addTags(vm); err != nil {
		return err
	}

	if err := d.addCustomAttributes(vm); err != nil {
		return err
	}

	return d.Start()
}

// createLegacy provisions a legacy vSphere VM
// legacy Windows VMs are not supported
func (d *Driver) createLegacy() error {
	c, err := d.getSoapClient()
	if err != nil {
		return err
	}

	spec := types.VirtualMachineConfigSpec{
		Name:       d.MachineName,
		GuestId:    "otherLinux64Guest",
		NumCPUs:    int32(d.CPU),
		MemoryMB:   int64(d.Memory),
		VAppConfig: d.getVAppConfig(),
	}

	scsi, err := object.SCSIControllerTypes().CreateSCSIController("pvscsi")
	if err != nil {
		return err
	}

	spec.DeviceChange = append(spec.DeviceChange, &types.VirtualDeviceConfigSpec{
		Operation: types.VirtualDeviceConfigSpecOperationAdd,
		Device:    scsi,
	})

	folder, err := d.findFolder()
	if err != nil {
		return err
	}

	ds, err := d.getDatastore(&spec)
	if err != nil {
		return err
	}

	spec.Files = &types.VirtualMachineFileInfo{
		VmPathName: fmt.Sprintf("[%s]", ds.Name()),
	}

	task, err := folder.CreateVM(d.getCtx(), spec, d.resourcepool, d.hostsystem)
	if err != nil {
		return err
	}

	info, err := task.WaitForResult(d.getCtx(), nil)
	if err != nil {
		return err
	}

	log.Infof("Uploading Boot2docker ISO ...")
	vm := object.NewVirtualMachine(c.Client, info.Result.(types.ManagedObjectReference))
	vmPath, err := d.getVmFolder(vm)
	if err != nil {
		return err
	}

	dsurl := ds.NewURL(filepath.Join(vmPath, isoFilename))
	p := soap.DefaultUpload
	if err = c.Client.UploadFile(d.getCtx(), d.ISO, dsurl, &p); err != nil {
		return err
	}

	devices, err := vm.Device(d.getCtx())
	if err != nil {
		return err
	}

	var add []types.BaseVirtualDevice
	controller, err := devices.FindDiskController("scsi")
	if err != nil {
		return err
	}

	disk := devices.CreateDisk(controller, ds.Reference(),
		ds.Path(fmt.Sprintf("%s/%s.vmdk", vmPath, d.MachineName)))

	// Convert MB to KB
	disk.CapacityInKB = int64(d.DiskSize) * 1024
	add = append(add, disk)
	ide, err := devices.FindIDEController("")
	if err != nil {
		return err
	}

	cdrom, err := devices.CreateCdrom(ide)
	if err != nil {
		return err
	}

	add = append(add, devices.InsertIso(cdrom, ds.Path(fmt.Sprintf("%s/%s", vmPath, isoFilename))))
	if err := vm.AddDevice(d.getCtx(), add...); err != nil {
		return err
	}

	if err := d.addNetworks(vm, d.networks); err != nil {
		return err
	}

	err = d.postCreate(vm)
	if err != nil {
		return err
	}

	if err := d.provisionVm(vm); err != nil {
		return err
	}

	return nil
}

func (d *Driver) createFromVmName() error {
	c, err := d.getSoapClient()
	if err != nil {
		return err
	}

	var info *types.TaskInfo
	var loc types.VirtualMachineRelocateSpec

	if d.resourcepool != nil {
		pool := d.resourcepool.Reference()
		loc.Pool = &pool
	}

	if d.hostsystem != nil {
		host := d.hostsystem.Reference()
		loc.Host = &host
	}

	spec := types.VirtualMachineCloneSpec{
		Location: loc,
		Config: &types.VirtualMachineConfigSpec{
			NumCPUs:    int32(d.CPU),
			MemoryMB:   int64(d.Memory),
			VAppConfig: d.getVAppConfig(),
		},
	}

	ds, err := d.getDatastore(spec.Config)
	if err != nil {
		return err
	}

	spec.Config.Files = &types.VirtualMachineFileInfo{
		VmPathName: fmt.Sprintf("[%s]", ds.Name()),
	}

	dsref := ds.Reference()
	spec.Location.Datastore = &dsref

	vm2Clone, err := d.fetchVM(d.CloneFrom)
	if err != nil {
		return err
	}

	var o mo.VirtualMachine

	if err = vm2Clone.Properties(d.getCtx(), vm2Clone.Reference(), []string{"summary.config.guestId"}, &o); err != nil {
		return err
	}
	// ensure that the guestId of the new vm matches the vm it is cloned from
	spec.Config.GuestId = o.Summary.Config.GuestId

	folder, err := d.findFolder()
	if err != nil {
		return err
	}

	task, err := vm2Clone.Clone(d.getCtx(), folder, d.MachineName, spec)
	if err != nil {
		return err
	}

	info, err = task.WaitForResult(d.getCtx(), nil)
	if err != nil {
		return err
	}

	// Retrieve the new VM
	vm := object.NewVirtualMachine(c.Client, info.Result.(types.ManagedObjectReference))
	if err := d.addNetworks(vm, d.networks); err != nil {
		return err
	}

	if err := d.resizeDisk(vm); err != nil {
		return err
	}

	log.Debugf("[createFromVmName] machine [%s] has OS [%s]", d.MachineName, d.OS)
	return d.postCreate(vm)
}

func (d *Driver) createFromLibraryName() error {
	c, err := d.getSoapClient()
	if err != nil {
		return err
	}

	folder, err := d.findFolder()
	if err != nil {
		return err
	}

	libManager := library.NewManager(d.getRestLogin(c.Client))
	if err := libManager.Login(d.getCtx(), d.getUserInfo()); err != nil {
		return err
	}

	query := fmt.Sprintf("/%s/%s", d.ContentLibrary, d.CloneFrom)
	results, err := vapifinder.NewFinder(libManager).Find(d.getCtx(), query)
	if err != nil {
		return err
	}

	if len(results) < 1 {
		return fmt.Errorf("No results found in content library: %s", d.CloneFrom)
	}

	if len(results) > 1 {
		return fmt.Errorf("More than one result returned from finder query: %s", d.CloneFrom)
	}

	item, ok := results[0].GetResult().(library.Item)
	if !ok {
		return fmt.Errorf("Content Library item is not a template: %q is a %T", d.CloneFrom, item)
	}
	hostId := ""
	if d.hostsystem != nil {
		hostId = d.hostsystem.Reference().Value
	}

	ds, err := d.getDatastore(&types.VirtualMachineConfigSpec{})
	if err != nil {
		return err
	}

	m := vcenter.NewManager(libManager.Client)

	deploy := vcenter.Deploy{
		DeploymentSpec: vcenter.DeploymentSpec{
			Name:                d.MachineName,
			DefaultDatastoreID:  ds.Reference().Value,
			AcceptAllEULA:       true,
			StorageProvisioning: "thin",
		},
		Target: vcenter.Target{
			ResourcePoolID: d.resourcepool.Reference().Value,
			HostID:         hostId,
			FolderID:       folder.Reference().Value,
		},
	}
	ref, err := m.DeployLibraryItem(d.getCtx(), item.ID, deploy)
	if err != nil {
		return err
	}

	obj, err := d.finder.ObjectReference(d.getCtx(), *ref)
	if err != nil {
		return err
	}

	// At this point, the VM is deployed from content library with defaults from template
	// Reconfiguration of the VM based on driver inputs follows

	vm := obj.(*object.VirtualMachine)
	log.Debugf("[createFromLibraryName] machine [%s] has OS [%s]", d.MachineName, d.OS)

	spec := types.VirtualMachineConfigSpec{
		NumCPUs:    int32(d.CPU),
		MemoryMB:   int64(d.Memory),
		VAppConfig: d.getVAppConfig(),
	}

	task, err := vm.Reconfigure(d.getCtx(), spec)
	if err != nil {
		return err
	}

	err = task.Wait(d.getCtx())
	if err != nil {
		return err
	}

	if err := d.resizeDisk(vm); err != nil {
		return err
	}

	if err := d.addNetworks(vm, d.networks); err != nil {
		return err
	}

	return d.postCreate(vm)
}
