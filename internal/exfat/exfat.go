// Package exfat creates an empty exFAT filesystem, following Microsoft's
// published "exFAT file system specification". It writes only the
// structures a freshly formatted volume needs: the main and backup boot
// regions, one FAT, the allocation bitmap, the up-case table and a root
// directory holding the volume label. The rest of the cluster heap is left
// untouched (it is free space).
package exfat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode"
	"unicode/utf16"
)

// Options control formatting.
type Options struct {
	SectorSize   int    // 512 or 4096
	Label        string // up to 11 UTF-16 characters
	Serial       uint32
	PartitionLBA uint64 // recorded in the boot sector
	ClusterSize  int64  // 0 = choose like Windows does
}

// Layout is the computed geometry, exposed for tests and reporting.
type Layout struct {
	BytesPerSector   int64
	ClusterSize      int64
	VolumeSectors    uint64
	FatOffset        uint32 // sectors
	FatLength        uint32 // sectors
	HeapOffset       uint32 // sectors
	ClusterCount     uint32
	BitmapClusters   uint32
	UpcaseClusters   uint32
	RootCluster      uint32
	UpcaseTable      []byte
	UpcaseChecksum   uint32
	BitmapBytes      uint32
	firstFreeCluster uint32
}

func defaultCluster(size int64) int64 {
	switch {
	case size <= 256<<20:
		return 4 << 10
	case size <= 32<<30:
		return 32 << 10
	default:
		return 128 << 10
	}
}

func shift(v int64) (uint8, bool) {
	for s := uint8(0); s < 32; s++ {
		if int64(1)<<s == v {
			return s, true
		}
	}
	return 0, false
}

// Plan computes the geometry for a volume of size bytes.
func Plan(size int64, o Options) (*Layout, error) {
	bps := int64(o.SectorSize)
	if bps != 512 && bps != 4096 {
		return nil, fmt.Errorf("unsupported sector size %d", bps)
	}
	cs := o.ClusterSize
	if cs == 0 {
		cs = defaultCluster(size)
	}
	if cs < bps || cs > 32<<20 {
		return nil, fmt.Errorf("invalid cluster size %d", cs)
	}
	if _, ok := shift(cs); !ok {
		return nil, errors.New("cluster size must be a power of two")
	}
	l := &Layout{BytesPerSector: bps, ClusterSize: cs, VolumeSectors: uint64(size / bps)}
	if size < 8<<20 {
		return nil, errors.New("exFAT volume must be at least 8 MiB")
	}
	spc := cs / bps
	align := int64(1<<20) / bps // align FAT and heap to 1 MiB
	if align < spc {
		align = spc
	}
	l.FatOffset = uint32(align) // leaves room for both 12-sector boot regions
	if align < 24 {
		l.FatOffset = 24
	}
	vol := int64(l.VolumeSectors)
	// Iterate: the FAT length depends on the cluster count, which depends
	// on where the heap starts.
	count := (vol - int64(l.FatOffset)) / spc
	for i := 0; i < 8; i++ {
		fatLen := ((count+2)*4 + bps - 1) / bps
		heap := int64(l.FatOffset) + fatLen
		heap = (heap + align - 1) / align * align
		nc := (vol - heap) / spc
		if nc <= 0 {
			return nil, errors.New("volume too small")
		}
		l.FatLength, l.HeapOffset = uint32(fatLen), uint32(heap)
		if nc == count {
			break
		}
		count = nc
	}
	if count > 0xFFFFFFF5 {
		return nil, errors.New("volume too large for this cluster size")
	}
	l.ClusterCount = uint32(count)
	l.BitmapBytes = uint32((count + 7) / 8)
	l.BitmapClusters = uint32((int64(l.BitmapBytes) + cs - 1) / cs)
	l.UpcaseTable, l.UpcaseChecksum = upcaseTable()
	l.UpcaseClusters = uint32((int64(len(l.UpcaseTable)) + cs - 1) / cs)
	l.RootCluster = 2 + l.BitmapClusters + l.UpcaseClusters
	l.firstFreeCluster = l.RootCluster + 1
	if l.firstFreeCluster-2 > l.ClusterCount {
		return nil, errors.New("volume too small for metadata")
	}
	return l, nil
}

// upcaseTable builds a compressed up-case table: runs of identity mappings
// are encoded as 0xFFFF followed by the run length.
func upcaseTable() ([]byte, uint32) {
	var u []uint16
	for c := 0; c <= 0xFFFF; {
		up := c
		if !(c >= 0xD800 && c <= 0xDFFF) {
			if r := unicode.ToUpper(rune(c)); r <= 0xFFFF {
				up = int(r)
			}
		}
		if up != c {
			u = append(u, uint16(up))
			c++
			continue
		}
		run := 0
		for c+run <= 0xFFFF {
			x := c + run
			ux := x
			if !(x >= 0xD800 && x <= 0xDFFF) {
				if r := unicode.ToUpper(rune(x)); r <= 0xFFFF {
					ux = int(r)
				}
			}
			if ux != x {
				break
			}
			run++
		}
		if run >= 3 {
			u = append(u, 0xFFFF, uint16(run))
		} else {
			for k := 0; k < run; k++ {
				u = append(u, uint16(c+k))
			}
		}
		c += run
	}
	b := make([]byte, 2*len(u))
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[2*i:], v)
	}
	var sum uint32
	for _, x := range b {
		sum = (sum>>1 | sum<<31) + uint32(x)
	}
	return b, sum
}

func bootChecksum(sectors []byte, bps int) uint32 {
	var sum uint32
	for i := 0; i < 11*bps; i++ {
		if i == 106 || i == 107 || i == 112 {
			continue
		}
		sum = (sum>>1 | sum<<31) + uint32(sectors[i])
	}
	return sum
}

func (l *Layout) bootRegion(o Options) []byte {
	bps := int(l.BytesPerSector)
	r := make([]byte, 12*bps)
	bs := r[:bps]
	le := binary.LittleEndian
	copy(bs[0:3], []byte{0xEB, 0x76, 0x90})
	copy(bs[3:11], "EXFAT   ")
	le.PutUint64(bs[64:], o.PartitionLBA)
	le.PutUint64(bs[72:], l.VolumeSectors)
	le.PutUint32(bs[80:], l.FatOffset)
	le.PutUint32(bs[84:], l.FatLength)
	le.PutUint32(bs[88:], l.HeapOffset)
	le.PutUint32(bs[92:], l.ClusterCount)
	le.PutUint32(bs[96:], l.RootCluster)
	le.PutUint32(bs[100:], o.Serial)
	le.PutUint16(bs[104:], 0x0100)
	s1, _ := shift(l.BytesPerSector)
	s2, _ := shift(l.ClusterSize / l.BytesPerSector)
	bs[108], bs[109] = s1, s2
	bs[110] = 1    // number of FATs
	bs[111] = 0x80 // drive select
	used := l.firstFreeCluster - 2
	bs[112] = byte(uint64(used) * 100 / uint64(l.ClusterCount))
	bs[510], bs[511] = 0x55, 0xAA
	for i := 1; i <= 8; i++ { // extended boot sectors
		le.PutUint32(r[(i+1)*bps-4:], 0xAA550000)
	}
	sum := bootChecksum(r, bps)
	cs := r[11*bps : 12*bps]
	for i := 0; i < bps; i += 4 {
		le.PutUint32(cs[i:], sum)
	}
	return r
}

func (l *Layout) clusterOffset(c uint32) int64 {
	return int64(l.HeapOffset)*l.BytesPerSector + int64(c-2)*l.ClusterSize
}

// Format writes the filesystem to w at byte offset base.
func Format(w io.WriterAt, base, size int64, o Options) (*Layout, error) {
	l, err := Plan(size, o)
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	bps := l.BytesPerSector
	// Boot regions (main + backup), with everything up to the FAT zeroed.
	head := make([]byte, int64(l.FatOffset)*bps)
	br := l.bootRegion(o)
	copy(head, br)
	copy(head[12*bps:], br)
	if _, err := w.WriteAt(head, base); err != nil {
		return nil, err
	}
	// FAT: media entries plus chains for the three metadata objects.
	fat := make([]byte, int64(l.FatLength)*bps)
	le.PutUint32(fat[0:], 0xFFFFFFF8)
	le.PutUint32(fat[4:], 0xFFFFFFFF)
	chain := func(first, n uint32) {
		for i := uint32(0); i < n; i++ {
			v := first + i + 1
			if i == n-1 {
				v = 0xFFFFFFFF
			}
			le.PutUint32(fat[(first+i)*4:], v)
		}
	}
	chain(2, l.BitmapClusters)
	chain(2+l.BitmapClusters, l.UpcaseClusters)
	chain(l.RootCluster, 1)
	if _, err := w.WriteAt(fat, base+int64(l.FatOffset)*bps); err != nil {
		return nil, err
	}
	// Zero the gap between FAT and heap.
	if gap := int64(l.HeapOffset-l.FatOffset-l.FatLength) * bps; gap > 0 {
		if _, err := w.WriteAt(make([]byte, gap), base+int64(l.FatOffset+l.FatLength)*bps); err != nil {
			return nil, err
		}
	}
	// Allocation bitmap.
	bm := make([]byte, int64(l.BitmapClusters)*l.ClusterSize)
	for c := uint32(0); c < l.firstFreeCluster-2; c++ {
		bm[c/8] |= 1 << (c % 8)
	}
	if _, err := w.WriteAt(bm, base+l.clusterOffset(2)); err != nil {
		return nil, err
	}
	// Up-case table.
	up := make([]byte, int64(l.UpcaseClusters)*l.ClusterSize)
	copy(up, l.UpcaseTable)
	if _, err := w.WriteAt(up, base+l.clusterOffset(2+l.BitmapClusters)); err != nil {
		return nil, err
	}
	// Root directory: volume label, bitmap and up-case entries.
	root := make([]byte, l.ClusterSize)
	e := root[0:32]
	e[0] = 0x83
	lab := utf16.Encode([]rune(o.Label))
	if len(lab) > 11 {
		lab = lab[:11]
	}
	e[1] = byte(len(lab))
	for i, c := range lab {
		le.PutUint16(e[2+2*i:], c)
	}
	e = root[32:64]
	e[0] = 0x81
	le.PutUint32(e[20:], 2)
	le.PutUint64(e[24:], uint64(l.BitmapBytes))
	e = root[64:96]
	e[0] = 0x82
	le.PutUint32(e[4:], l.UpcaseChecksum)
	le.PutUint32(e[20:], 2+l.BitmapClusters)
	le.PutUint64(e[24:], uint64(len(l.UpcaseTable)))
	if _, err := w.WriteAt(root, base+l.clusterOffset(l.RootCluster)); err != nil {
		return nil, err
	}
	return l, nil
}

// Probe reports whether an exFAT boot sector with a valid boot-region
// checksum is present at base, and returns its serial number and size.
func Probe(r io.ReaderAt, base int64) (serial uint32, sizeBytes int64, err error) {
	b := make([]byte, 512)
	if _, err := r.ReadAt(b, base); err != nil {
		return 0, 0, err
	}
	if string(b[3:11]) != "EXFAT   " || b[510] != 0x55 || b[511] != 0xAA {
		return 0, 0, errors.New("no exFAT boot sector")
	}
	bps := 1 << b[108]
	if bps != 512 && bps != 4096 {
		return 0, 0, errors.New("bad exFAT sector size")
	}
	region := make([]byte, 12*bps)
	if _, err := r.ReadAt(region, base); err != nil {
		return 0, 0, err
	}
	if binary.LittleEndian.Uint32(region[11*bps:]) != bootChecksum(region, bps) {
		return 0, 0, errors.New("exFAT boot checksum mismatch")
	}
	return binary.LittleEndian.Uint32(b[100:]), int64(binary.LittleEndian.Uint64(b[72:])) * int64(bps), nil
}
