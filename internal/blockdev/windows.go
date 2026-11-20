//go:build windows

package blockdev

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	ioctlDiskGetDriveGeometryEx = 0x000700A0
	ioctlDiskUpdateProperties   = 0x00070140
	ioctlStorageGetDeviceNumber = 0x002D1080
	ioctlStorageQueryProperty   = 0x002D1400
	ioctlVolumeGetDiskExtents   = 0x00560000
	fsctlLockVolume             = 0x00090018
	fsctlUnlockVolume           = 0x0009001C
	fsctlDismountVolume         = 0x00090020

	busUSB = 7
	busSD  = 0xC
	busMMC = 0xD
)

var (
	kernel32                         = syscall.NewLazyDLL("kernel32.dll")
	procFindFirstVolumeW             = kernel32.NewProc("FindFirstVolumeW")
	procFindNextVolumeW              = kernel32.NewProc("FindNextVolumeW")
	procFindVolumeClose              = kernel32.NewProc("FindVolumeClose")
	procGetVolumePathNamesForVolumeW = kernel32.NewProc("GetVolumePathNamesForVolumeNameW")
)

type winDevice struct {
	f       *os.File
	h       syscall.Handle
	a       *aligned
	size    int64
	ss      int
	volumes []syscall.Handle
}

func (d *winDevice) ReadAt(p []byte, off int64) (int, error)  { return d.a.ReadAt(p, off) }
func (d *winDevice) WriteAt(p []byte, off int64) (int, error) { return d.a.WriteAt(p, off) }
func (d *winDevice) Size() int64                              { return d.size }
func (d *winDevice) SectorSize() int                          { return d.ss }
func (d *winDevice) Path() string                             { return d.f.Name() }
func (d *winDevice) IsFile() bool                             { return false }
func (d *winDevice) Sync() error                              { return d.f.Sync() }
func (d *winDevice) Close() error {
	err := d.f.Sync()
	var n uint32
	if e := syscall.DeviceIoControl(d.h, ioctlDiskUpdateProperties, nil, 0, nil, 0, &n, nil); e != nil && err == nil {
		err = fmt.Errorf("refreshing partition table: %v (unplug and reinsert the stick)", e)
	}
	for _, v := range d.volumes {
		syscall.DeviceIoControl(v, fsctlUnlockVolume, nil, 0, nil, 0, &n, nil)
		syscall.CloseHandle(v)
	}
	if cerr := d.f.Close(); err == nil {
		err = cerr
	}
	return err
}

var diskRE = regexp.MustCompile(`(?i)^(?:\\\\\.\\)?(?:physicaldrive|disk)?(\d+)$`)

// Open opens a target. Disks may be given as \\.\PhysicalDrive2,
// PhysicalDrive2, disk2 or 2; anything else is treated as an image file.
func Open(path string, o Options) (Device, error) {
	m := diskRE.FindStringSubmatch(path)
	if m == nil {
		return openFile(path, o)
	}
	num, _ := strconv.Atoi(m[1])
	dev := fmt.Sprintf(`\\.\PhysicalDrive%d`, num)
	info, err := describe(num)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", dev, err)
	}
	if info.System && o.Write {
		return nil, ErrSystemDisk
	}
	if o.Write && !info.Removable && info.Bus != "usb" && info.Bus != "sd" && !o.AllowFixed {
		return nil, fmt.Errorf("%s is a fixed %s disk; pass --allow-fixed if you are certain", dev, info.Bus)
	}
	access := uint32(syscall.GENERIC_READ)
	if o.Write {
		access |= syscall.GENERIC_WRITE
	}
	h, err := syscall.CreateFile(syscall.StringToUTF16Ptr(dev), access,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
	if err != nil {
		if errors.Is(err, syscall.ERROR_ACCESS_DENIED) {
			return nil, fmt.Errorf("%s: access denied (run from an elevated/Administrator prompt)", dev)
		}
		return nil, fmt.Errorf("%s: %w", dev, err)
	}
	d := &winDevice{h: h, size: info.Size, ss: info.SectorSize}
	d.f = os.NewFile(uintptr(h), dev)
	d.a = &aligned{raw: d.f, align: int64(info.SectorSize)}
	if o.Write {
		vols, err := lockVolumes(num)
		d.volumes = vols
		if err != nil {
			d.Close()
			return nil, err
		}
	}
	return d, nil
}

func ioctl(h syscall.Handle, code uint32, in []byte, out []byte) (uint32, error) {
	var n uint32
	var ip, op *byte
	if len(in) > 0 {
		ip = &in[0]
	}
	if len(out) > 0 {
		op = &out[0]
	}
	err := syscall.DeviceIoControl(h, code, ip, uint32(len(in)), op, uint32(len(out)), &n, nil)
	return n, err
}

func openQuery(path string) (syscall.Handle, error) {
	return syscall.CreateFile(syscall.StringToUTF16Ptr(path), 0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE, nil, syscall.OPEN_EXISTING, 0, 0)
}

func describe(num int) (Disk, error) {
	path := fmt.Sprintf(`\\.\PhysicalDrive%d`, num)
	d := Disk{Path: path}
	h, err := openQuery(path)
	if err != nil {
		return d, err
	}
	defer syscall.CloseHandle(h)
	geo := make([]byte, 256)
	if _, err := ioctl(h, ioctlDiskGetDriveGeometryEx, nil, geo); err != nil {
		return d, fmt.Errorf("drive geometry: %w", err)
	}
	d.SectorSize = int(binary.LittleEndian.Uint32(geo[20:]))
	d.Size = int64(binary.LittleEndian.Uint64(geo[24:]))
	q := make([]byte, 12) // STORAGE_PROPERTY_QUERY: StorageDeviceProperty, PropertyStandardQuery
	desc := make([]byte, 1024)
	if n, err := ioctl(h, ioctlStorageQueryProperty, q, desc); err == nil && n >= 32 {
		desc = desc[:n]
		d.Removable = desc[10] != 0
		str := func(off uint32) string {
			if off == 0 || int(off) >= len(desc) {
				return ""
			}
			end := int(off)
			for end < len(desc) && desc[end] != 0 {
				end++
			}
			return strings.TrimSpace(string(desc[off:end]))
		}
		d.Model = strings.TrimSpace(str(binary.LittleEndian.Uint32(desc[12:])) + " " + str(binary.LittleEndian.Uint32(desc[16:])))
		switch binary.LittleEndian.Uint32(desc[28:]) {
		case busUSB:
			d.Bus = "usb"
		case busSD, busMMC:
			d.Bus = "sd"
		case 0x11:
			d.Bus = "nvme"
		case 0x0B:
			d.Bus = "sata"
		default:
			d.Bus = "other"
		}
	}
	if d.SectorSize != 512 && d.SectorSize != 4096 {
		return d, fmt.Errorf("unsupported sector size %d", d.SectorSize)
	}
	sys := systemDisks()
	d.System = sys[num]
	for _, v := range volumesOnDisk(num) {
		d.Mounts = append(d.Mounts, v.paths...)
	}
	return d, nil
}

type volume struct {
	name  string // \\?\Volume{GUID}\
	paths []string
}

func enumVolumes() []string {
	buf := make([]uint16, 64)
	r, _, _ := procFindFirstVolumeW.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if syscall.Handle(r) == syscall.InvalidHandle {
		return nil
	}
	find := r
	defer procFindVolumeClose.Call(find)
	var out []string
	for {
		out = append(out, syscall.UTF16ToString(buf))
		ok, _, _ := procFindNextVolumeW.Call(find, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if ok == 0 {
			break
		}
	}
	return out
}

func volumeDisks(h syscall.Handle) []uint32 {
	out := make([]byte, 8+24*16)
	n, err := ioctl(h, ioctlVolumeGetDiskExtents, nil, out)
	if err != nil || n < 8 {
		return nil
	}
	cnt := binary.LittleEndian.Uint32(out[0:])
	var disks []uint32
	for i := uint32(0); i < cnt && 8+24*(i+1) <= n; i++ {
		disks = append(disks, binary.LittleEndian.Uint32(out[8+24*i:]))
	}
	return disks
}

func volumePaths(name string) []string {
	buf := make([]uint16, 1024)
	var ret uint32
	ok, _, _ := procGetVolumePathNamesForVolumeW.Call(
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(name))),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(unsafe.Pointer(&ret)))
	if ok == 0 {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(buf); i++ {
		if buf[i] == 0 {
			if i == start {
				break
			}
			out = append(out, syscall.UTF16ToString(buf[start:i]))
			start = i + 1
		}
	}
	return out
}

func volumeDevicePath(name string) string {
	// \\?\Volume{...}\ -> \\.\Volume{...}  (no trailing slash: opens the volume, not its root)
	return `\\.\` + strings.TrimSuffix(strings.TrimPrefix(name, `\\?\`), `\`)
}

func volumesOnDisk(num int) []volume {
	var out []volume
	for _, v := range enumVolumes() {
		h, err := openQuery(volumeDevicePath(v))
		if err != nil {
			continue
		}
		disks := volumeDisks(h)
		syscall.CloseHandle(h)
		for _, dn := range disks {
			if int(dn) == num {
				out = append(out, volume{name: v, paths: volumePaths(v)})
				break
			}
		}
	}
	return out
}

func systemDisks() map[int]bool {
	out := map[int]bool{}
	for _, env := range []string{"SystemDrive", "windir"} {
		v := os.Getenv(env)
		if len(v) < 2 || v[1] != ':' {
			continue
		}
		h, err := openQuery(`\\.\` + v[:2])
		if err != nil {
			continue
		}
		for _, d := range volumeDisks(h) {
			out[int(d)] = true
		}
		syscall.CloseHandle(h)
	}
	return out
}

// lockVolumes locks and dismounts every volume that lives on disk num so the
// raw disk can be written. Handles stay open (and locked) until Close.
func lockVolumes(num int) ([]syscall.Handle, error) {
	var held []syscall.Handle
	for _, v := range volumesOnDisk(num) {
		h, err := syscall.CreateFile(syscall.StringToUTF16Ptr(volumeDevicePath(v.name)),
			syscall.GENERIC_READ|syscall.GENERIC_WRITE, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
			nil, syscall.OPEN_EXISTING, 0, 0)
		if err != nil {
			return held, fmt.Errorf("opening volume %s: %w", strings.Join(v.paths, ","), err)
		}
		held = append(held, h)
		var n uint32
		locked := false
		for try := 0; try < 10 && !locked; try++ {
			locked = syscall.DeviceIoControl(h, fsctlLockVolume, nil, 0, nil, 0, &n, nil) == nil
		}
		if !locked {
			return held, fmt.Errorf("volume %s is in use (close Explorer windows and programs using it)", strings.Join(v.paths, ","))
		}
		if err := syscall.DeviceIoControl(h, fsctlDismountVolume, nil, 0, nil, 0, &n, nil); err != nil {
			return held, fmt.Errorf("dismounting %s: %w", strings.Join(v.paths, ","), err)
		}
	}
	return held, nil
}

// List enumerates physical drives.
func List(all bool) ([]Disk, error) {
	var out []Disk
	for i := 0; i < 64; i++ {
		d, err := describe(i)
		if err != nil {
			continue
		}
		out = append(out, d)
	}
	return out, nil
}
