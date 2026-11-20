// Package gpt reads and writes GUID Partition Tables (UEFI 2.10 §5.3) with a
// protective MBR. The protective MBR carries no boot code: the stick is
// UEFI-only by design.
package gpt

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"strings"
	"unicode/utf16"
)

const (
	numEntries = 128
	entrySize  = 128
)

// GUID is stored in the on-disk (mixed-endian) byte order.
type GUID [16]byte

// ParseGUID parses the canonical text form.
func ParseGUID(s string) (GUID, error) {
	var g GUID
	h := strings.ReplaceAll(s, "-", "")
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 16 {
		return g, fmt.Errorf("invalid GUID %q", s)
	}
	// first three fields are little-endian on disk
	g[0], g[1], g[2], g[3] = b[3], b[2], b[1], b[0]
	g[4], g[5] = b[5], b[4]
	g[6], g[7] = b[7], b[6]
	copy(g[8:], b[8:])
	return g, nil
}

// MustGUID panics on malformed constants.
func MustGUID(s string) GUID {
	g, err := ParseGUID(s)
	if err != nil {
		panic(err)
	}
	return g
}

func (g GUID) String() string {
	return fmt.Sprintf("%08X-%04X-%04X-%X-%X",
		binary.LittleEndian.Uint32(g[0:]), binary.LittleEndian.Uint16(g[4:]),
		binary.LittleEndian.Uint16(g[6:]), g[8:10], g[10:16])
}

// IsZero reports whether the GUID is all zeros (unused entry).
func (g GUID) IsZero() bool { return g == GUID{} }

// RandomGUID returns a version-4 GUID.
func RandomGUID() GUID {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return FromBytes(b)
}

// FromBytes turns 16 arbitrary bytes into a version-4, variant-1 GUID.
func FromBytes(b [16]byte) GUID {
	b[6] = b[6]&0x0F | 0x40
	b[8] = b[8]&0x3F | 0x80
	var g GUID
	g[0], g[1], g[2], g[3] = b[3], b[2], b[1], b[0]
	g[4], g[5] = b[5], b[4]
	g[6], g[7] = b[7], b[6]
	copy(g[8:], b[8:])
	return g
}

// Well-known partition types.
var (
	TypeESP       = MustGUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B")
	TypeBasicData = MustGUID("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7")
	TypeLinuxData = MustGUID("0FC63DAF-8483-4772-8E79-3D69D8477DE4")
)

// Basic-data partition attributes honoured by Windows.
const (
	AttrHidden        = uint64(1) << 62
	AttrNoDriveLetter = uint64(1) << 63
)

// Partition is one table entry. Slot is the zero-based entry index
// (partition number - 1).
type Partition struct {
	Slot  int
	Type  GUID
	GUID  GUID
	First uint64 // first LBA
	Last  uint64 // last LBA, inclusive
	Attr  uint64
	Name  string
}

// Bytes returns the partition size.
func (p Partition) Bytes(sectorSize int) int64 { return int64(p.Last-p.First+1) * int64(sectorSize) }

// Table is a whole-disk GPT.
type Table struct {
	SectorSize   int
	TotalSectors uint64
	DiskGUID     GUID
	Parts        []Partition // sorted by Slot, only used entries
}

// entryLBAs is the number of sectors the entry array occupies.
func (t *Table) entryLBAs() uint64 {
	return uint64((numEntries*entrySize + t.SectorSize - 1) / t.SectorSize)
}

// FirstUsable is the first LBA available to partitions.
func (t *Table) FirstUsable() uint64 { return 2 + t.entryLBAs() }

// LastUsable is the last LBA available to partitions.
func (t *Table) LastUsable() uint64 { return t.TotalSectors - 2 - t.entryLBAs() }

// AlignLBA is the 1 MiB alignment unit in sectors.
func (t *Table) AlignLBA() uint64 { return uint64(1<<20) / uint64(t.SectorSize) }

// FreeSpan is a gap between partitions, already 1 MiB aligned.
type FreeSpan struct{ First, Last uint64 }

// Free returns aligned gaps large enough to be useful (≥ 1 MiB).
func (t *Table) Free() []FreeSpan {
	a := t.AlignLBA()
	align := func(x uint64) uint64 { return (x + a - 1) / a * a }
	var out []FreeSpan
	cur := align(t.FirstUsable())
	if cur < a {
		cur = a
	}
	sorted := append([]Partition(nil), t.Parts...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && sorted[j].First < sorted[j-1].First; j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	for _, p := range sorted {
		if p.First > cur && p.First-cur >= a {
			out = append(out, FreeSpan{cur, p.First - 1})
		}
		if n := align(p.Last + 1); n > cur {
			cur = n
		}
	}
	last := t.LastUsable()
	// keep the tail aligned too
	last = (last+1)/a*a - 1
	if last > cur && last-cur+1 >= a {
		out = append(out, FreeSpan{cur, last})
	}
	return out
}

// NextSlot returns the lowest unused entry index.
func (t *Table) NextSlot() int {
	used := map[int]bool{}
	for _, p := range t.Parts {
		used[p.Slot] = true
	}
	for i := 0; i < numEntries; i++ {
		if !used[i] {
			return i
		}
	}
	return -1
}

// Get returns the partition in a slot.
func (t *Table) Get(slot int) (Partition, bool) {
	for _, p := range t.Parts {
		if p.Slot == slot {
			return p, true
		}
	}
	return Partition{}, false
}

// Remove deletes the partition in a slot.
func (t *Table) Remove(slot int) bool {
	for i, p := range t.Parts {
		if p.Slot == slot {
			t.Parts = append(t.Parts[:i], t.Parts[i+1:]...)
			return true
		}
	}
	return false
}

// Validate checks bounds and overlaps.
func (t *Table) Validate() error {
	for i, p := range t.Parts {
		if p.Slot < 0 || p.Slot >= numEntries {
			return fmt.Errorf("slot %d out of range", p.Slot)
		}
		if p.First < t.FirstUsable() || p.Last > t.LastUsable() || p.Last < p.First {
			return fmt.Errorf("partition %d (%d-%d) outside usable range", p.Slot+1, p.First, p.Last)
		}
		for _, q := range t.Parts[i+1:] {
			if q.Slot == p.Slot {
				return fmt.Errorf("duplicate slot %d", p.Slot)
			}
			if p.First <= q.Last && q.First <= p.Last {
				return fmt.Errorf("partitions %d and %d overlap", p.Slot+1, q.Slot+1)
			}
		}
	}
	return nil
}

func (t *Table) entries() []byte {
	arr := make([]byte, numEntries*entrySize)
	for _, p := range t.Parts {
		e := arr[p.Slot*entrySize : (p.Slot+1)*entrySize]
		copy(e[0:16], p.Type[:])
		copy(e[16:32], p.GUID[:])
		binary.LittleEndian.PutUint64(e[32:], p.First)
		binary.LittleEndian.PutUint64(e[40:], p.Last)
		binary.LittleEndian.PutUint64(e[48:], p.Attr)
		u := utf16.Encode([]rune(p.Name))
		if len(u) > 36 {
			u = u[:36]
		}
		for i, c := range u {
			binary.LittleEndian.PutUint16(e[56+2*i:], c)
		}
	}
	return arr
}

func (t *Table) header(myLBA, altLBA, entriesLBA uint64, entriesCRC uint32) []byte {
	h := make([]byte, t.SectorSize)
	copy(h[0:8], "EFI PART")
	binary.LittleEndian.PutUint32(h[8:], 0x00010000)
	binary.LittleEndian.PutUint32(h[12:], 92)
	binary.LittleEndian.PutUint64(h[24:], myLBA)
	binary.LittleEndian.PutUint64(h[32:], altLBA)
	binary.LittleEndian.PutUint64(h[40:], t.FirstUsable())
	binary.LittleEndian.PutUint64(h[48:], t.LastUsable())
	copy(h[56:72], t.DiskGUID[:])
	binary.LittleEndian.PutUint64(h[72:], entriesLBA)
	binary.LittleEndian.PutUint32(h[80:], numEntries)
	binary.LittleEndian.PutUint32(h[84:], entrySize)
	binary.LittleEndian.PutUint32(h[88:], entriesCRC)
	binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h[:92]))
	return h
}

func (t *Table) protectiveMBR() []byte {
	m := make([]byte, t.SectorSize)
	e := m[446:462]
	e[1], e[2], e[3] = 0x00, 0x02, 0x00 // CHS of LBA 1
	e[4] = 0xEE
	e[5], e[6], e[7] = 0xFF, 0xFF, 0xFF
	binary.LittleEndian.PutUint32(e[8:], 1)
	size := t.TotalSectors - 1
	if size > 0xFFFFFFFF {
		size = 0xFFFFFFFF
	}
	binary.LittleEndian.PutUint32(e[12:], uint32(size))
	m[510], m[511] = 0x55, 0xAA
	return m
}

// Write writes the backup table first, then the primary table and the
// protective MBR, so a crash mid-write leaves at most one damaged copy.
func (t *Table) Write(w io.WriterAt) error {
	if err := t.Validate(); err != nil {
		return err
	}
	ss := int64(t.SectorSize)
	arr := t.entries()
	crc := crc32.ChecksumIEEE(arr)
	last := t.TotalSectors - 1
	backupEntries := last - t.entryLBAs()
	if _, err := w.WriteAt(arr, int64(backupEntries)*ss); err != nil {
		return err
	}
	if _, err := w.WriteAt(t.header(last, 1, backupEntries, crc), int64(last)*ss); err != nil {
		return err
	}
	primary := make([]byte, 0, int(ss)*2+len(arr))
	primary = append(primary, t.protectiveMBR()...)
	primary = append(primary, t.header(1, last, 2, crc)...)
	primary = append(primary, arr...)
	_, err := w.WriteAt(primary, 0)
	return err
}

// ErrNoGPT means neither the primary nor the backup header is valid.
var ErrNoGPT = errors.New("no valid GPT found")

// Read loads the table, falling back to the backup header if the primary is
// damaged.
func Read(r io.ReaderAt, sectorSize int, diskBytes int64) (*Table, error) {
	t := &Table{SectorSize: sectorSize, TotalSectors: uint64(diskBytes / int64(sectorSize))}
	if t.TotalSectors < 64 {
		return nil, ErrNoGPT
	}
	tryHeader := func(lba uint64) (*Table, error) {
		ss := int64(sectorSize)
		h := make([]byte, ss)
		if _, err := r.ReadAt(h, int64(lba)*ss); err != nil {
			return nil, err
		}
		if string(h[0:8]) != "EFI PART" {
			return nil, ErrNoGPT
		}
		hs := binary.LittleEndian.Uint32(h[12:])
		if hs < 92 || int64(hs) > ss {
			return nil, ErrNoGPT
		}
		crc := binary.LittleEndian.Uint32(h[16:])
		tmp := append([]byte(nil), h[:hs]...)
		binary.LittleEndian.PutUint32(tmp[16:], 0)
		if crc32.ChecksumIEEE(tmp) != crc {
			return nil, errors.New("GPT header CRC mismatch")
		}
		if binary.LittleEndian.Uint64(h[24:]) != lba {
			return nil, errors.New("GPT header location mismatch")
		}
		n := binary.LittleEndian.Uint32(h[80:])
		es := binary.LittleEndian.Uint32(h[84:])
		if es < 128 || n == 0 || n > 1024 || es > 1024 {
			return nil, errors.New("unsupported GPT entry geometry")
		}
		arr := make([]byte, int(n)*int(es))
		elba := binary.LittleEndian.Uint64(h[72:])
		if _, err := r.ReadAt(arr, int64(elba)*ss); err != nil {
			return nil, err
		}
		if crc32.ChecksumIEEE(arr) != binary.LittleEndian.Uint32(h[88:]) {
			return nil, errors.New("GPT entry array CRC mismatch")
		}
		out := &Table{SectorSize: sectorSize, TotalSectors: t.TotalSectors}
		copy(out.DiskGUID[:], h[56:72])
		for i := 0; i < int(n) && i < numEntries; i++ {
			e := arr[i*int(es) : (i+1)*int(es)]
			var p Partition
			copy(p.Type[:], e[0:16])
			if p.Type.IsZero() {
				continue
			}
			p.Slot = i
			copy(p.GUID[:], e[16:32])
			p.First = binary.LittleEndian.Uint64(e[32:])
			p.Last = binary.LittleEndian.Uint64(e[40:])
			p.Attr = binary.LittleEndian.Uint64(e[48:])
			u := make([]uint16, 36)
			for j := range u {
				u[j] = binary.LittleEndian.Uint16(e[56+2*j:])
			}
			if k := indexZero(u); k >= 0 {
				u = u[:k]
			}
			p.Name = string(utf16.Decode(u))
			out.Parts = append(out.Parts, p)
		}
		return out, nil
	}
	t1, err1 := tryHeader(1)
	if err1 == nil {
		return t1, nil
	}
	t2, err2 := tryHeader(t.TotalSectors - 1)
	if err2 == nil {
		return t2, nil
	}
	if err1 == ErrNoGPT && err2 == ErrNoGPT {
		return nil, ErrNoGPT
	}
	return nil, fmt.Errorf("primary GPT: %v; backup GPT: %v", err1, err2)
}

func indexZero(u []uint16) int {
	for i, c := range u {
		if c == 0 {
			return i
		}
	}
	return -1
}

// Wipe zeroes the first and last MiB of a disk, destroying old partition
// tables and filesystem signatures that some OSes would otherwise detect.
func Wipe(w io.WriterAt, diskBytes int64) error {
	z := make([]byte, 1<<20)
	if _, err := w.WriteAt(z, 0); err != nil {
		return err
	}
	if diskBytes > 2<<20 {
		if _, err := w.WriteAt(z, diskBytes-int64(len(z))); err != nil {
			return err
		}
	}
	return nil
}
