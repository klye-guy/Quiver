// Package fat reads FAT12/16/32 filesystems and builds new FAT32 filesystems.
package fat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"

	"archavist.com/quiver/internal/vfs"
)

// Reader is an opened FAT filesystem located at an offset within r.
type Reader struct {
	r        io.ReaderAt
	base     int64
	bps      int64 // bytes per sector
	spc      int64 // sectors per cluster
	fatOff   int64
	rootOff  int64 // FAT12/16 fixed root directory
	rootSize int64
	dataOff  int64
	clusters uint32
	bits     int // 12, 16 or 32
	rootClus uint32
	fat      []uint32
	total    int64

	Label    string
	VolumeID uint32
}

// Open parses the boot sector at base.
func Open(r io.ReaderAt, base int64) (*Reader, error) {
	bs := make([]byte, 512)
	if _, err := r.ReadAt(bs, base); err != nil {
		return nil, err
	}
	if bs[510] != 0x55 || bs[511] != 0xAA {
		return nil, errors.New("FAT boot sector signature missing")
	}
	fs := &Reader{r: r, base: base}
	fs.bps = int64(binary.LittleEndian.Uint16(bs[11:]))
	fs.spc = int64(bs[13])
	rsvd := int64(binary.LittleEndian.Uint16(bs[14:]))
	nfats := int64(bs[16])
	rootEnts := int64(binary.LittleEndian.Uint16(bs[17:]))
	tot := int64(binary.LittleEndian.Uint16(bs[19:]))
	fatSz := int64(binary.LittleEndian.Uint16(bs[22:]))
	if tot == 0 {
		tot = int64(binary.LittleEndian.Uint32(bs[32:]))
	}
	if fatSz == 0 {
		fatSz = int64(binary.LittleEndian.Uint32(bs[36:]))
	}
	switch fs.bps {
	case 512, 1024, 2048, 4096:
	default:
		return nil, fmt.Errorf("invalid FAT bytes per sector %d", fs.bps)
	}
	if fs.spc == 0 || fs.spc&(fs.spc-1) != 0 || nfats == 0 || rsvd == 0 || fatSz == 0 || tot == 0 {
		return nil, errors.New("invalid FAT BPB")
	}
	rootSecs := (rootEnts*32 + fs.bps - 1) / fs.bps
	dataSec := rsvd + nfats*fatSz + rootSecs
	if dataSec >= tot {
		return nil, errors.New("FAT data region beyond volume")
	}
	fs.clusters = uint32((tot - dataSec) / fs.spc)
	fs.total = tot * fs.bps
	switch {
	case fs.clusters < 4085:
		fs.bits = 12
	case fs.clusters < 65525:
		fs.bits = 16
	default:
		fs.bits = 32
	}
	fs.fatOff = base + rsvd*fs.bps
	fs.rootOff = base + (rsvd+nfats*fatSz)*fs.bps
	fs.rootSize = rootSecs * fs.bps
	fs.dataOff = base + dataSec*fs.bps
	var lab []byte
	if fs.bits == 32 {
		fs.rootClus = binary.LittleEndian.Uint32(bs[44:])
		fs.VolumeID = binary.LittleEndian.Uint32(bs[67:])
		lab = bs[71:82]
	} else {
		fs.VolumeID = binary.LittleEndian.Uint32(bs[39:])
		lab = bs[43:54]
	}
	fs.Label = strings.TrimRight(string(lab), " ")
	raw := make([]byte, fatSz*fs.bps)
	if _, err := r.ReadAt(raw, fs.fatOff); err != nil {
		return nil, fmt.Errorf("reading FAT: %w", err)
	}
	n := fs.clusters + 2
	fs.fat = make([]uint32, n)
	for i := uint32(0); i < n; i++ {
		switch fs.bits {
		case 32:
			if int(i)*4+4 > len(raw) {
				return nil, errors.New("FAT too small")
			}
			fs.fat[i] = binary.LittleEndian.Uint32(raw[i*4:]) & 0x0FFFFFFF
		case 16:
			if int(i)*2+2 > len(raw) {
				return nil, errors.New("FAT too small")
			}
			fs.fat[i] = uint32(binary.LittleEndian.Uint16(raw[i*2:]))
		case 12:
			o := i + i/2
			if int(o)+2 > len(raw) {
				return nil, errors.New("FAT too small")
			}
			v := uint32(binary.LittleEndian.Uint16(raw[o:]))
			if i&1 == 1 {
				v >>= 4
			}
			fs.fat[i] = v & 0xFFF
		}
	}
	return fs, nil
}

// Size is the total byte size of the filesystem according to its BPB.
func (fs *Reader) Size() int64 { return fs.total }

// Bits is the FAT width (12, 16 or 32).
func (fs *Reader) Bits() int { return fs.bits }

func (fs *Reader) eoc(v uint32) bool {
	switch fs.bits {
	case 12:
		return v >= 0xFF8
	case 16:
		return v >= 0xFFF8
	}
	return v >= 0x0FFFFFF8
}

func (fs *Reader) chain(start uint32, limit int64) ([]vfs.Extent, error) {
	var out []vfs.Extent
	cs := fs.bps * fs.spc
	seen := 0
	for c := start; ; {
		if c < 2 || c >= fs.clusters+2 {
			return nil, fmt.Errorf("cluster %d out of range", c)
		}
		off := fs.dataOff + int64(c-2)*cs
		if n := len(out); n > 0 && out[n-1].Off+out[n-1].Len == off {
			out[n-1].Len += cs
		} else {
			out = append(out, vfs.Extent{Off: off, Len: cs})
		}
		seen++
		if int64(seen)*cs >= limit && limit > 0 {
			break
		}
		if seen > int(fs.clusters) {
			return nil, errors.New("cluster chain loop")
		}
		next := fs.fat[c]
		if fs.eoc(next) {
			break
		}
		c = next
	}
	return out, nil
}

// Tree reads the directory hierarchy.
func (fs *Reader) Tree() (*vfs.Node, error) {
	root := vfs.NewDir("", time.Time{})
	var data []byte
	var err error
	if fs.bits == 32 {
		data, err = fs.readChain(fs.rootClus, 0)
	} else {
		data = make([]byte, fs.rootSize)
		_, err = fs.r.ReadAt(data, fs.rootOff)
	}
	if err != nil {
		return nil, err
	}
	if err := fs.fill(root, data, 0, true); err != nil {
		return nil, err
	}
	return root, nil
}

func (fs *Reader) readChain(start uint32, size int64) ([]byte, error) {
	ex, err := fs.chain(start, size)
	if err != nil {
		return nil, err
	}
	var total int64
	for _, e := range ex {
		total += e.Len
	}
	if total > 64<<20 {
		return nil, errors.New("directory too large")
	}
	r, _ := vfs.ExtentOpener(fs.r, ex)()
	return io.ReadAll(r)
}

func fatTime(d, t uint16) time.Time {
	if d == 0 {
		return time.Time{}
	}
	return time.Date(1980+int(d>>9), time.Month((d>>5)&15), int(d&31),
		int(t>>11), int((t>>5)&63), int(t&31)*2, 0, time.UTC)
}

func (fs *Reader) fill(dir *vfs.Node, data []byte, depth int, isRoot bool) error {
	if depth > 64 {
		return errors.New("directory hierarchy too deep")
	}
	var lfn []uint16
	var lfnSum byte
	lfnOK := false
	for pos := 0; pos+32 <= len(data); pos += 32 {
		e := data[pos : pos+32]
		if e[0] == 0 {
			break
		}
		if e[0] == 0xE5 {
			lfnOK = false
			continue
		}
		attr := e[11]
		if attr&0x3F == 0x0F { // long file name entry
			ord := e[0]
			chars := make([]uint16, 0, 13)
			for _, r := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
				for i := r[0]; i < r[1]; i += 2 {
					chars = append(chars, binary.LittleEndian.Uint16(e[i:]))
				}
			}
			if ord&0x40 != 0 {
				lfn = chars
				lfnSum = e[13]
				lfnOK = true
			} else if lfnOK && e[13] == lfnSum {
				lfn = append(chars, lfn...)
			} else {
				lfnOK = false
			}
			continue
		}
		if attr&0x08 != 0 { // volume label
			if isRoot && attr&0x10 == 0 {
				fs.Label = strings.TrimRight(string(e[0:11]), " ")
			}
			lfnOK = false
			continue
		}
		short := e[0:11]
		var sum byte
		for _, c := range short {
			sum = (sum>>1 | sum<<7) + c
		}
		name := ""
		if lfnOK && sum == lfnSum {
			for i, c := range lfn {
				if c == 0 {
					lfn = lfn[:i]
					break
				}
			}
			name = string(utf16.Decode(lfn))
		} else {
			base := strings.TrimRight(string(short[0:8]), " ")
			ext := strings.TrimRight(string(short[8:11]), " ")
			if base != "" && base[0] == 0x05 {
				base = "\xe5" + base[1:]
			}
			if e[12]&0x08 != 0 {
				base = strings.ToLower(base)
			}
			if e[12]&0x10 != 0 {
				ext = strings.ToLower(ext)
			}
			name = base
			if ext != "" {
				name += "." + ext
			}
		}
		lfnOK = false
		if name == "." || name == ".." {
			continue
		}
		clus := uint32(binary.LittleEndian.Uint16(e[26:])) | uint32(binary.LittleEndian.Uint16(e[20:]))<<16
		size := int64(binary.LittleEndian.Uint32(e[28:]))
		mt := fatTime(binary.LittleEndian.Uint16(e[24:]), binary.LittleEndian.Uint16(e[22:]))
		if attr&0x10 != 0 {
			sub := vfs.NewDir(name, mt)
			sub.Hidden = attr&0x02 != 0
			if clus != 0 {
				d, err := fs.readChain(clus, 0)
				if err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
				if err := fs.fill(sub, d, depth+1, false); err != nil {
					return err
				}
			}
			dir.Children = append(dir.Children, sub)
			continue
		}
		var n *vfs.Node
		if size == 0 {
			n = vfs.Bytes(name, nil, mt)
		} else {
			ex, err := fs.chain(clus, size)
			if err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
			// trim to file size
			rem := size
			for i := range ex {
				if ex[i].Len > rem {
					ex[i].Len = rem
				}
				rem -= ex[i].Len
			}
			if rem > 0 {
				return fmt.Errorf("%s: cluster chain shorter than file size", name)
			}
			n = vfs.FromExtents(name, fs.r, ex, size, mt)
		}
		n.Hidden = attr&0x02 != 0
		dir.Children = append(dir.Children, n)
	}
	return nil
}
