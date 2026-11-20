//go:build linux

package blockdev

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

const (
	blkGetSize64 = 0x80081272
	blkSSZGet    = 0x1268
	blkRRPart    = 0x125F
)

type linuxDevice struct {
	f    *os.File
	size int64
	ss   int
}

func (d *linuxDevice) ReadAt(p []byte, off int64) (int, error)  { return d.f.ReadAt(p, off) }
func (d *linuxDevice) WriteAt(p []byte, off int64) (int, error) { return d.f.WriteAt(p, off) }
func (d *linuxDevice) Size() int64                              { return d.size }
func (d *linuxDevice) SectorSize() int                          { return d.ss }
func (d *linuxDevice) Path() string                             { return d.f.Name() }
func (d *linuxDevice) IsFile() bool                             { return false }
func (d *linuxDevice) Sync() error                              { return d.f.Sync() }
func (d *linuxDevice) Close() error {
	err := d.f.Sync()
	// Ask the kernel to re-read the new partition table. Loop devices
	// without partition scanning return EINVAL; that is harmless.
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, d.f.Fd(), blkRRPart, 0); e != 0 && e != syscall.EINVAL && err == nil {
		err = fmt.Errorf("re-reading partition table: %v (unplug and reinsert the stick)", e)
	}
	if cerr := d.f.Close(); err == nil {
		err = cerr
	}
	return err
}

func ioctlInt(fd uintptr, req uintptr, out unsafe.Pointer) error {
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(out)); e != 0 {
		return e
	}
	return nil
}

// Open opens a target path.
func Open(path string, o Options) (Device, error) {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) && o.Create {
			return openFile(path, o)
		}
		return nil, err
	}
	if st.Mode().IsRegular() {
		return openFile(path, o)
	}
	if st.Mode()&os.ModeDevice == 0 || st.Mode()&os.ModeCharDevice != 0 {
		return nil, fmt.Errorf("%s is neither a block device nor a regular file", path)
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}
	name := filepath.Base(real)
	sys := "/sys/class/block/" + name
	if _, err := os.Stat(sys + "/partition"); err == nil {
		return nil, fmt.Errorf("%s is a partition; give the whole disk (e.g. /dev/sdX)", path)
	}
	info := describe(name)
	if info.System && o.Write {
		return nil, ErrSystemDisk
	}
	if o.Write && !info.Removable && info.Bus != "usb" && info.Bus != "mmc" && !o.AllowFixed && !strings.HasPrefix(name, "loop") {
		return nil, fmt.Errorf("%s is a fixed %s disk; pass --allow-fixed if you are certain", path, info.Bus)
	}
	if o.Write && len(info.Mounts) > 0 {
		return nil, fmt.Errorf("%s has mounted filesystems (%s); unmount them first", path, strings.Join(info.Mounts, ", "))
	}
	flag := syscall.O_RDONLY
	if o.Write {
		flag = syscall.O_RDWR | syscall.O_EXCL // EXCL on a block device: fails if in use
	}
	fd, err := syscall.Open(real, flag|syscall.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, syscall.EBUSY) {
			return nil, fmt.Errorf("%s is in use (mounted, swap or held by another program)", path)
		}
		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			return nil, fmt.Errorf("%s: permission denied (run as root)", path)
		}
		return nil, err
	}
	f := os.NewFile(uintptr(fd), real)
	var size uint64
	var ss int32
	if err := ioctlInt(f.Fd(), blkGetSize64, unsafe.Pointer(&size)); err != nil {
		f.Close()
		return nil, fmt.Errorf("BLKGETSIZE64: %w", err)
	}
	if err := ioctlInt(f.Fd(), blkSSZGet, unsafe.Pointer(&ss)); err != nil {
		f.Close()
		return nil, fmt.Errorf("BLKSSZGET: %w", err)
	}
	if ss != 512 && ss != 4096 {
		f.Close()
		return nil, fmt.Errorf("unsupported logical sector size %d", ss)
	}
	return &linuxDevice{f: f, size: int64(size), ss: int(ss)}, nil
}

func readTrim(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

type mount struct{ dev, point string }

func mounts() []mount {
	var out []mount
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 5 {
			out = append(out, mount{dev: fields[2], point: fields[4]})
		}
	}
	return out
}

func swapDevs() map[string]bool {
	out := map[string]bool{}
	f, err := os.Open("/proc/swaps")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 0 && strings.HasPrefix(fields[0], "/dev/") {
			if r, err := filepath.EvalSymlinks(fields[0]); err == nil {
				out[filepath.Base(r)] = true
			}
		}
	}
	return out
}

// holders returns the block device names of a disk and its partitions,
// including device-mapper/LVM/RAID devices stacked on them.
func holders(name string) map[string]string {
	devs := map[string]string{}
	var add func(n string, depth int)
	add = func(n string, depth int) {
		if depth > 8 {
			return
		}
		devs[n] = readTrim("/sys/class/block/" + n + "/dev")
		hs, _ := os.ReadDir("/sys/class/block/" + n + "/holders")
		for _, h := range hs {
			add(h.Name(), depth+1)
		}
	}
	add(name, 0)
	entries, _ := os.ReadDir("/sys/class/block/" + name)
	for _, e := range entries {
		if _, err := os.Stat("/sys/class/block/" + name + "/" + e.Name() + "/partition"); err == nil {
			add(e.Name(), 1)
		}
	}
	return devs
}

func describe(name string) Disk {
	d := Disk{Path: "/dev/" + name}
	sys := "/sys/class/block/" + name
	sectors, _ := strconv.ParseInt(readTrim(sys+"/size"), 10, 64)
	d.Size = sectors * 512
	d.SectorSize, _ = strconv.Atoi(readTrim(sys + "/queue/logical_block_size"))
	d.Model = strings.TrimSpace(readTrim(sys+"/device/vendor") + " " + readTrim(sys+"/device/model"))
	d.Removable = readTrim(sys+"/removable") == "1"
	link, _ := filepath.EvalSymlinks(sys)
	switch {
	case strings.Contains(link, "/usb"):
		d.Bus = "usb"
	case strings.HasPrefix(name, "mmcblk"):
		d.Bus = "mmc"
	case strings.HasPrefix(name, "nvme"):
		d.Bus = "nvme"
	case strings.HasPrefix(name, "loop"):
		d.Bus = "loop"
	case strings.HasPrefix(name, "vd"):
		d.Bus = "virtio"
	default:
		d.Bus = "ata/scsi"
	}
	devs := holders(name)
	numbers := map[string]bool{}
	for _, num := range devs {
		if num != "" {
			numbers[num] = true
		}
	}
	critical := map[string]bool{"/": true, "/boot": true, "/boot/efi": true, "/efi": true, "/usr": true, "/var": true, "/home": true}
	for _, m := range mounts() {
		if numbers[m.dev] {
			d.Mounts = append(d.Mounts, m.point)
			if critical[m.point] {
				d.System = true
			}
		}
	}
	sw := swapDevs()
	for n := range devs {
		if sw[n] {
			d.System = true
			d.Mounts = append(d.Mounts, "[swap]")
		}
	}
	return d
}

// List enumerates whole disks.
func List(all bool) ([]Disk, error) {
	entries, err := os.ReadDir("/sys/block")
	if err != nil {
		return nil, err
	}
	var out []Disk
	for _, e := range entries {
		n := e.Name()
		if !all {
			skip := false
			for _, p := range []string{"loop", "ram", "zram", "dm-", "md", "sr", "nbd", "fd"} {
				if strings.HasPrefix(n, p) {
					skip = true
				}
			}
			if skip {
				continue
			}
		}
		d := describe(n)
		if d.Size == 0 {
			continue
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}
