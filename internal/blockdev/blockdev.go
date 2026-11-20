// Package blockdev opens the write target: a whole USB disk (Linux block
// device or Windows \\.\PhysicalDriveN) or a regular image file.
//
// Safety rules enforced here, before any byte is written:
//   - partitions are refused; only whole disks are accepted
//   - disks holding the running system are refused
//   - non-removable, non-USB disks are refused unless explicitly allowed
//   - on Linux the disk is opened O_EXCL, which fails if anything on it is mounted
//   - on Windows every volume on the disk is locked and dismounted first
package blockdev

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Device is an open write target.
type Device interface {
	io.ReaderAt
	io.WriterAt
	Size() int64
	SectorSize() int
	Path() string
	IsFile() bool
	Sync() error
	// Close flushes, asks the OS to re-read the partition table and releases
	// any volume locks.
	Close() error
}

// Options control Open.
type Options struct {
	Write      bool  // open for writing (otherwise read-only)
	Create     bool  // image files: create or replace
	Size       int64 // image files: size when creating
	AllowFixed bool  // permit non-removable disks
}

// Disk describes a candidate target disk.
type Disk struct {
	Path       string   `json:"path"`
	Model      string   `json:"model"`
	Size       int64    `json:"size"`
	SectorSize int      `json:"sector_size"`
	Removable  bool     `json:"removable"`
	Bus        string   `json:"bus"`
	System     bool     `json:"system"`
	Mounts     []string `json:"mounts,omitempty"`
}

// ErrSystemDisk is returned for the disk the OS runs from.
var ErrSystemDisk = errors.New("refusing to touch the disk the running system uses")

type fileDevice struct {
	f    *os.File
	size int64
}

func (d *fileDevice) ReadAt(p []byte, off int64) (int, error)  { return d.f.ReadAt(p, off) }
func (d *fileDevice) WriteAt(p []byte, off int64) (int, error) { return d.f.WriteAt(p, off) }
func (d *fileDevice) Size() int64                              { return d.size }
func (d *fileDevice) SectorSize() int                          { return 512 }
func (d *fileDevice) Path() string                             { return d.f.Name() }
func (d *fileDevice) IsFile() bool                             { return true }
func (d *fileDevice) Sync() error                              { return d.f.Sync() }
func (d *fileDevice) Close() error {
	err := d.f.Sync()
	if cerr := d.f.Close(); err == nil {
		err = cerr
	}
	return err
}

func openFile(path string, o Options) (Device, error) {
	if o.Create {
		if o.Size < 64<<20 {
			return nil, errors.New("image size must be at least 64 MiB (use --size)")
		}
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			return nil, err
		}
		size := o.Size / 512 * 512
		if err := f.Truncate(size); err != nil {
			f.Close()
			return nil, err
		}
		return &fileDevice{f: f, size: size}, nil
	}
	flag := os.O_RDONLY
	if o.Write {
		flag = os.O_RDWR
	}
	f, err := os.OpenFile(path, flag, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if st.Size()%512 != 0 {
		f.Close()
		return nil, fmt.Errorf("%s: image size is not a multiple of 512 bytes", path)
	}
	return &fileDevice{f: f, size: st.Size()}, nil
}

// aligned turns arbitrary reads and writes into whole-sector operations, as
// raw disk handles on Windows require.
type aligned struct {
	raw interface {
		io.ReaderAt
		io.WriterAt
	}
	align int64
}

func (a *aligned) span(off int64, n int) (start, end int64) {
	start = off - off%a.align
	end = off + int64(n)
	if r := end % a.align; r != 0 {
		end += a.align - r
	}
	return
}

func (a *aligned) ReadAt(p []byte, off int64) (int, error) {
	if off%a.align == 0 && int64(len(p))%a.align == 0 {
		return a.raw.ReadAt(p, off)
	}
	start, end := a.span(off, len(p))
	buf := make([]byte, end-start)
	if _, err := a.raw.ReadAt(buf, start); err != nil {
		return 0, err
	}
	return copy(p, buf[off-start:]), nil
}

func (a *aligned) WriteAt(p []byte, off int64) (int, error) {
	written := 0
	// unaligned head
	if r := off % a.align; r != 0 {
		start := off - r
		page := make([]byte, a.align)
		if _, err := a.raw.ReadAt(page, start); err != nil {
			return 0, err
		}
		n := copy(page[r:], p)
		if _, err := a.raw.WriteAt(page, start); err != nil {
			return 0, err
		}
		p, off, written = p[n:], off+int64(n), n
	}
	// aligned body, in bounded chunks
	for int64(len(p)) >= a.align {
		n := int64(len(p)) / a.align * a.align
		if n > 8<<20 {
			n = 8 << 20
		}
		if _, err := a.raw.WriteAt(p[:n], off); err != nil {
			return written, err
		}
		p, off, written = p[n:], off+n, written+int(n)
	}
	// unaligned tail
	if len(p) > 0 {
		page := make([]byte, a.align)
		if _, err := a.raw.ReadAt(page, off); err != nil {
			return written, err
		}
		copy(page, p)
		if _, err := a.raw.WriteAt(page, off); err != nil {
			return written, err
		}
		written += len(p)
	}
	return written, nil
}
