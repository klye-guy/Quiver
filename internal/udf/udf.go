// Package udf reads UDF 1.02–2.01 filesystems as found on optical-media
// images (Windows installation ISOs carry their real content only in UDF).
// It supports type-1 partition maps, short/long/embedded allocation
// descriptors, allocation extent chains, File Entries and Extended File
// Entries. Metadata/sparable/virtual partitions (UDF 2.50+, Blu-ray, packet
// writing) are rejected with an explicit error rather than guessed at.
package udf

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

const sector = 2048

// ErrNotUDF is returned when no UDF anchor is present.
var ErrNotUDF = errors.New("not a UDF filesystem")

// FS is an opened UDF volume.
type FS struct {
	r          io.ReaderAt
	size       int64
	blockSize  int64
	partStart  int64 // first sector of partition 0 (the only one supported)
	partLen    int64
	partNumber uint16
	fsd        longAD
	VolumeID   string
}

type longAD struct {
	length  uint32
	block   uint32
	partRef uint16
}

type tag struct {
	id       uint16
	location uint32
}

func parseTag(b []byte) (tag, error) {
	if len(b) < 16 {
		return tag{}, errors.New("short descriptor")
	}
	var sum byte
	for i := 0; i < 16; i++ {
		if i != 4 {
			sum += b[i]
		}
	}
	if sum != b[4] {
		return tag{}, errors.New("descriptor tag checksum mismatch")
	}
	return tag{id: binary.LittleEndian.Uint16(b[0:]), location: binary.LittleEndian.Uint32(b[12:])}, nil
}

func (fs *FS) readSector(lba int64) ([]byte, error) {
	if lba < 0 || (lba+1)*sector > fs.size {
		return nil, fmt.Errorf("sector %d out of range", lba)
	}
	b := make([]byte, sector)
	_, err := fs.r.ReadAt(b, lba*sector)
	return b, err
}

// Open locates the anchor and parses the volume descriptor sequence.
func Open(r io.ReaderAt, size int64) (*FS, error) {
	fs := &FS{r: r, size: size, blockSize: sector}
	if !hasNSR(r, size) {
		return nil, ErrNotUDF
	}
	avdp, err := fs.readSector(256)
	if err != nil {
		return nil, ErrNotUDF
	}
	t, err := parseTag(avdp)
	if err != nil || t.id != 2 {
		return nil, ErrNotUDF
	}
	vdsLen := int64(binary.LittleEndian.Uint32(avdp[16:]))
	vdsLoc := int64(binary.LittleEndian.Uint32(avdp[20:]))
	havePD, haveLVD := false, false
	for i := int64(0); i < vdsLen/sector && i < 64; i++ {
		d, err := fs.readSector(vdsLoc + i)
		if err != nil {
			return nil, err
		}
		t, err := parseTag(d)
		if err != nil {
			continue
		}
		switch t.id {
		case 5: // Partition Descriptor
			if !havePD {
				fs.partNumber = binary.LittleEndian.Uint16(d[22:])
				fs.partStart = int64(binary.LittleEndian.Uint32(d[188:]))
				fs.partLen = int64(binary.LittleEndian.Uint32(d[192:]))
				havePD = true
			}
		case 6: // Logical Volume Descriptor
			if haveLVD {
				continue
			}
			fs.blockSize = int64(binary.LittleEndian.Uint32(d[212:]))
			if fs.blockSize != sector {
				return nil, fmt.Errorf("unsupported UDF logical block size %d", fs.blockSize)
			}
			fs.VolumeID = dstring(d[84 : 84+128])
			fs.fsd = parseLongAD(d[248:])
			nMaps := binary.LittleEndian.Uint32(d[268:])
			if nMaps != 1 || d[440] != 1 {
				return nil, errors.New("unsupported UDF partition map (only a single type-1 map is supported)")
			}
			haveLVD = true
		case 8: // terminator
			i = 1 << 30
		}
	}
	if !havePD || !haveLVD {
		return nil, errors.New("incomplete UDF volume descriptor sequence")
	}
	return fs, nil
}

func hasNSR(r io.ReaderAt, size int64) bool {
	b := make([]byte, 8)
	for lba := int64(16); lba < 32; lba++ {
		if (lba+1)*sector > size {
			return false
		}
		if _, err := r.ReadAt(b, lba*sector); err != nil {
			return false
		}
		id := string(b[1:6])
		if id == "NSR02" || id == "NSR03" {
			return true
		}
	}
	return false
}

func parseLongAD(b []byte) longAD {
	return longAD{
		length:  binary.LittleEndian.Uint32(b[0:]) & 0x3FFFFFFF,
		block:   binary.LittleEndian.Uint32(b[4:]),
		partRef: binary.LittleEndian.Uint16(b[8:]),
	}
}

// dstring decodes a fixed-length OSTA CS0 d-string (last byte = used length).
func dstring(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	n := int(b[len(b)-1])
	if n == 0 || n > len(b)-1 {
		return ""
	}
	return cs0(b[:n])
}

// cs0 decodes OSTA compressed Unicode.
func cs0(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	switch b[0] {
	case 8:
		r := make([]rune, 0, len(b)-1)
		for _, c := range b[1:] {
			r = append(r, rune(c))
		}
		return strings.TrimRight(string(r), "\x00")
	case 16:
		u := make([]uint16, (len(b)-1)/2)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(b[1+2*i:])
		}
		return strings.TrimRight(string(utf16.Decode(u)), "\x00")
	}
	return ""
}

func (fs *FS) blockOffset(block uint32) (int64, error) {
	if int64(block) >= fs.partLen {
		return 0, fmt.Errorf("logical block %d outside partition", block)
	}
	return (fs.partStart + int64(block)) * fs.blockSize, nil
}

type entry struct {
	fileType byte
	size     int64
	extents  []vfs.Extent
	embedded []byte
	mtime    time.Time
}

func (fs *FS) readEntry(ad longAD) (*entry, error) {
	off, err := fs.blockOffset(ad.block)
	if err != nil {
		return nil, err
	}
	d, err := fs.readSector(off / sector)
	if err != nil {
		return nil, err
	}
	t, err := parseTag(d)
	if err != nil {
		return nil, err
	}
	var lEA, lAD, base int
	var tsOff int
	switch t.id {
	case 261: // File Entry
		lEA = int(binary.LittleEndian.Uint32(d[168:]))
		lAD = int(binary.LittleEndian.Uint32(d[172:]))
		base = 176
		tsOff = 84
	case 266: // Extended File Entry
		lEA = int(binary.LittleEndian.Uint32(d[208:]))
		lAD = int(binary.LittleEndian.Uint32(d[212:]))
		base = 216
		tsOff = 92
	default:
		return nil, fmt.Errorf("expected file entry, found tag %d", t.id)
	}
	if base+lEA+lAD > len(d) || lEA < 0 || lAD < 0 {
		return nil, errors.New("file entry descriptors overflow block")
	}
	e := &entry{
		fileType: d[16+11],
		size:     int64(binary.LittleEndian.Uint64(d[56:])),
		mtime:    timestamp(d[tsOff : tsOff+12]),
	}
	flags := binary.LittleEndian.Uint16(d[16+18:])
	ads := d[base+lEA : base+lEA+lAD]
	switch flags & 7 {
	case 3:
		e.embedded = append([]byte(nil), ads...)
		if int64(len(e.embedded)) < e.size {
			return nil, errors.New("embedded data shorter than file size")
		}
		e.embedded = e.embedded[:e.size]
		return e, nil
	case 0, 1:
		if err := fs.collectExtents(e, ads, flags&7 == 1, 0); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("extended allocation descriptors are not supported")
	}
	var total int64
	for _, x := range e.extents {
		total += x.Len
	}
	if total < e.size {
		return nil, fmt.Errorf("allocation (%d bytes) shorter than file size (%d)", total, e.size)
	}
	// trim to the information length
	remaining := e.size
	for i := range e.extents {
		if e.extents[i].Len > remaining {
			e.extents[i].Len = remaining
		}
		remaining -= e.extents[i].Len
	}
	for len(e.extents) > 0 && e.extents[len(e.extents)-1].Len == 0 {
		e.extents = e.extents[:len(e.extents)-1]
	}
	return e, nil
}

func (fs *FS) collectExtents(e *entry, ads []byte, long bool, depth int) error {
	if depth > 64 {
		return errors.New("allocation extent chain too long")
	}
	step := 8
	if long {
		step = 16
	}
	for len(ads) >= step {
		raw := binary.LittleEndian.Uint32(ads[0:])
		kind, length := raw>>30, int64(raw&0x3FFFFFFF)
		block := binary.LittleEndian.Uint32(ads[4:])
		if long && binary.LittleEndian.Uint16(ads[8:]) != 0 {
			return errors.New("allocation descriptor references unsupported partition")
		}
		ads = ads[step:]
		if length == 0 {
			break
		}
		switch kind {
		case 0: // recorded and allocated
			off, err := fs.blockOffset(block)
			if err != nil {
				return err
			}
			if off+length > fs.size {
				return errors.New("file extent beyond end of image")
			}
			e.extents = append(e.extents, vfs.Extent{Off: off, Len: length})
		case 1, 2: // not recorded: reads as zeros
			e.extents = append(e.extents, vfs.Extent{Off: -1, Len: length})
		case 3: // continuation in an Allocation Extent Descriptor
			off, err := fs.blockOffset(block)
			if err != nil {
				return err
			}
			d, err := fs.readSector(off / sector)
			if err != nil {
				return err
			}
			t, err := parseTag(d)
			if err != nil || t.id != 258 {
				return errors.New("bad allocation extent descriptor")
			}
			l := int(binary.LittleEndian.Uint32(d[20:]))
			if 24+l > len(d) {
				return errors.New("allocation extent descriptor overflow")
			}
			return fs.collectExtents(e, d[24:24+l], long, depth+1)
		}
	}
	return nil
}

func timestamp(b []byte) time.Time {
	tz := int16(binary.LittleEndian.Uint16(b[0:]) & 0x0FFF)
	if tz&0x0800 != 0 {
		tz |= -0x1000 // sign-extend 12-bit
	}
	loc := time.UTC
	if tz != -2047 && binary.LittleEndian.Uint16(b[0:])>>12 == 1 {
		loc = time.FixedZone("", int(tz)*60)
	}
	y := int(binary.LittleEndian.Uint16(b[2:]))
	if y == 0 || b[4] == 0 {
		return time.Time{}
	}
	return time.Date(y, time.Month(b[4]), int(b[5]), int(b[6]), int(b[7]), int(b[8]), 0, loc).UTC()
}

func (fs *FS) content(e *entry) ([]byte, error) {
	if e.embedded != nil {
		return e.embedded, nil
	}
	if e.size > 64<<20 {
		return nil, errors.New("directory too large")
	}
	r, _ := vfs.ExtentOpener(fs.r, e.extents)()
	return io.ReadAll(io.LimitReader(r, e.size))
}

// Tree reads the full directory hierarchy.
func (fs *FS) Tree() (*vfs.Node, error) {
	off, err := fs.blockOffset(fs.fsd.block)
	if err != nil {
		return nil, err
	}
	d, err := fs.readSector(off / sector)
	if err != nil {
		return nil, err
	}
	t, err := parseTag(d)
	if err != nil || t.id != 256 {
		return nil, errors.New("file set descriptor not found")
	}
	rootAD := parseLongAD(d[400:])
	rootEntry, err := fs.readEntry(rootAD)
	if err != nil {
		return nil, fmt.Errorf("root directory: %w", err)
	}
	root := vfs.NewDir("", rootEntry.mtime)
	if err := fs.fill(root, rootEntry, map[uint32]bool{rootAD.block: true}, 0); err != nil {
		return nil, err
	}
	return root, nil
}

func (fs *FS) fill(dir *vfs.Node, e *entry, visited map[uint32]bool, depth int) error {
	if depth > 64 {
		return errors.New("directory hierarchy too deep")
	}
	data, err := fs.content(e)
	if err != nil {
		return err
	}
	for pos := 0; pos+38 <= len(data); {
		t, err := parseTag(data[pos:])
		if err != nil || t.id != 257 {
			return fmt.Errorf("bad file identifier descriptor in %q", dir.Name)
		}
		chars := data[pos+18]
		lFI := int(data[pos+19])
		icb := parseLongAD(data[pos+20:])
		lIU := int(binary.LittleEndian.Uint16(data[pos+36:]))
		end := pos + 38 + lIU + lFI
		if end > len(data) {
			return errors.New("file identifier overflows directory")
		}
		name := cs0(data[pos+38+lIU : end])
		pos += (38 + lIU + lFI + 3) &^ 3
		if chars&0x08 != 0 || chars&0x04 != 0 { // parent or deleted
			continue
		}
		if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
			return fmt.Errorf("invalid file name %q", name)
		}
		child, err := fs.readEntry(icb)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		switch child.fileType {
		case 4: // directory
			if visited[icb.block] {
				return fmt.Errorf("directory loop at %q", name)
			}
			visited[icb.block] = true
			sub := vfs.NewDir(name, child.mtime)
			sub.Hidden = chars&0x01 != 0
			if err := fs.fill(sub, child, visited, depth+1); err != nil {
				return err
			}
			dir.Children = append(dir.Children, sub)
		case 5: // regular file
			var n *vfs.Node
			if child.embedded != nil {
				n = vfs.Bytes(name, child.embedded, child.mtime)
			} else {
				n = vfs.FromExtents(name, fs.r, child.extents, child.size, child.mtime)
			}
			n.Hidden = chars&0x01 != 0
			dir.Children = append(dir.Children, n)
		case 12: // symlink: record but don't follow
			dir.Children = append(dir.Children, &vfs.Node{Name: name, Link: "(udf symlink)", MTime: child.mtime})
		default:
			// sockets, FIFOs, devices: not representable on FAT; ignore
		}
	}
	return nil
}
