package fat

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"archavist.com/quiver/internal/vfs"
)

// MaxFileSize is the largest file FAT32 can store.
const MaxFileSize = 1<<32 - 1

const minFAT32Clusters = 65525 + 16 // stay clear of the FAT16/FAT32 boundary

// Options control FAT32 creation.
type Options struct {
	SectorSize    int    // logical sector size of the target device: 512 or 4096
	Label         string // volume label (sanitised to 11 FAT characters)
	VolumeID      uint32
	HiddenSectors uint64 // LBA of the partition start, recorded in the BPB
	MinBytes      int64  // filesystem is at least this large
	ExtraBytes    int64  // free space to leave beyond the content
	Align         int64  // align the data region to this many bytes (default 1 MiB)
	OEMName       string // 8 chars; default "MSWIN4.1" for widest compatibility
}

// Plan is a fully computed FAT32 layout for a file tree. Planning reads no
// file data; Write streams it.
type Plan struct {
	opt          Options
	bps, cs      int64
	rsvd, fatSz  int64
	clusters     uint32
	totalSectors int64
	root         *dirPlan
	files        []*filePlan
	used         uint32

	// Renamed lists names that had to be changed to be valid on FAT.
	Renamed []string
}

type dirPlan struct {
	node    *vfs.Node
	parent  *dirPlan
	path    string
	first   uint32
	nclus   uint32
	entries []dirEntry
}

type dirEntry struct {
	name  string
	sfn   [11]byte
	lfn   []uint16
	node  *vfs.Node
	dir   *dirPlan
	file  *filePlan
	isDir bool
}

type filePlan struct {
	node  *vfs.Node
	path  string
	first uint32
	nclus uint32
}

// TotalBytes is the size of the filesystem.
func (p *Plan) TotalBytes() int64 { return p.totalSectors * p.bps }

// ClusterSize is the chosen allocation unit.
func (p *Plan) ClusterSize() int64 { return p.cs }

// FreeBytes is the space left unallocated.
func (p *Plan) FreeBytes() int64 { return int64(p.clusters-p.used) * p.cs }

// PlanFS computes a layout for root. Children must already be in their final
// order (call vfs.Node.SortRecursive for deterministic output).
func PlanFS(root *vfs.Node, opt Options) (*Plan, error) {
	if opt.SectorSize != 512 && opt.SectorSize != 4096 {
		return nil, fmt.Errorf("unsupported sector size %d", opt.SectorSize)
	}
	if opt.Align == 0 {
		opt.Align = 1 << 20
	}
	if opt.OEMName == "" {
		opt.OEMName = "MSWIN4.1"
	}
	p := &Plan{opt: opt, bps: int64(opt.SectorSize)}
	var err error
	p.root, err = p.buildDir(root, nil, "/", 0)
	if err != nil {
		return nil, err
	}
	// Choose the cluster size giving the smallest filesystem; ties go to the
	// larger cluster (fewer FAT entries, faster reads).
	bestTotal := int64(-1)
	var best Plan
	for cs := int64(32768); cs >= p.bps; cs /= 2 {
		q := *p
		q.cs = cs
		if err := q.layout(); err != nil {
			continue
		}
		if bestTotal < 0 || q.TotalBytes() < bestTotal {
			bestTotal, best = q.TotalBytes(), q
		}
	}
	if bestTotal < 0 {
		return nil, errors.New("content does not fit any FAT32 layout")
	}
	*p = best
	if err := p.layout(); err != nil { // recompute per-entry cluster counts for the chosen size
		return nil, err
	}
	p.allocate()
	return p, nil
}

func (p *Plan) buildDir(n *vfs.Node, parent *dirPlan, dpath string, depth int) (*dirPlan, error) {
	if depth > 60 {
		return nil, fmt.Errorf("%s: directory nesting too deep for FAT", dpath)
	}
	d := &dirPlan{node: n, parent: parent, path: dpath}
	usedSFN := map[[11]byte]bool{}
	seen := map[string]string{}
	for _, c := range n.Children {
		name, changed := sanitizeLFN(c.Name)
		if changed {
			p.Renamed = append(p.Renamed, path.Join(dpath, c.Name)+" -> "+name)
		}
		key := strings.ToUpper(name)
		if prev, dup := seen[key]; dup {
			return nil, fmt.Errorf("%s: names %q and %q collide on case-insensitive FAT", dpath, prev, c.Name)
		}
		seen[key] = c.Name
		u := utf16.Encode([]rune(name))
		if len(u) > 255 {
			return nil, fmt.Errorf("%s: name too long for FAT: %q", dpath, name)
		}
		sfn, exact := makeSFN(name, usedSFN)
		usedSFN[sfn] = true
		e := dirEntry{name: name, sfn: sfn, node: c, isDir: c.Dir}
		if !exact {
			e.lfn = u
		}
		cp := path.Join(dpath, name)
		if c.Dir {
			sub, err := p.buildDir(c, d, cp, depth+1)
			if err != nil {
				return nil, err
			}
			e.dir = sub
		} else {
			if c.Link != "" {
				return nil, fmt.Errorf("%s: symbolic links must be resolved before building FAT", cp)
			}
			if c.Size > MaxFileSize {
				return nil, fmt.Errorf("%s: %d bytes exceeds the FAT32 4 GiB file limit", cp, c.Size)
			}
			e.file = &filePlan{node: c, path: cp}
		}
		d.entries = append(d.entries, e)
	}
	return d, nil
}

func (d *dirPlan) slots() int64 {
	n := int64(2) // "." and ".." (root: label + spare)
	for _, e := range d.entries {
		n++
		if e.lfn != nil {
			n += int64((len(e.lfn) + 12) / 13)
		}
	}
	return n
}

func (p *Plan) neededClusters(d *dirPlan) (int64, error) {
	slots := d.slots()
	if slots > 65536 {
		return 0, fmt.Errorf("%s: too many entries for a FAT directory", d.path)
	}
	dc := (slots*32 + p.cs - 1) / p.cs
	if dc == 0 {
		dc = 1
	}
	d.nclus = uint32(dc)
	total := dc
	for _, e := range d.entries {
		if e.dir != nil {
			n, err := p.neededClusters(e.dir)
			if err != nil {
				return 0, err
			}
			total += n
		} else if e.file.node.Size > 0 {
			e.file.nclus = uint32((e.file.node.Size + p.cs - 1) / p.cs)
			total += int64(e.file.nclus)
		} else {
			e.file.nclus = 0
		}
	}
	return total, nil
}

func (p *Plan) layout() error {
	need, err := p.neededClusters(p.root)
	if err != nil {
		return err
	}
	spc := p.cs / p.bps
	if spc > 128 {
		return errors.New("cluster too large")
	}
	c := need + (p.opt.ExtraBytes+p.cs-1)/p.cs
	if c < minFAT32Clusters {
		c = minFAT32Clusters
	}
	alignSec := p.opt.Align / p.bps
	for iter := 0; iter < 100; iter++ {
		p.fatSz = ((c+2)*4 + p.bps - 1) / p.bps
		p.rsvd = 32
		if start := p.rsvd + 2*p.fatSz; alignSec > 1 && start%alignSec != 0 {
			p.rsvd += alignSec - start%alignSec
		}
		if p.rsvd > 0xFFFF {
			return errors.New("reserved region too large")
		}
		p.totalSectors = p.rsvd + 2*p.fatSz + c*spc
		if short := p.opt.MinBytes - p.totalSectors*p.bps; short > 0 {
			c += (short + p.cs - 1) / p.cs
			continue
		}
		if c >= 0x0FFFFFF5-2 || p.totalSectors > 0xFFFFFFFF {
			return errors.New("filesystem too large for FAT32")
		}
		p.clusters = uint32(c)
		return nil
	}
	return errors.New("FAT32 layout did not converge")
}

func (p *Plan) allocate() {
	next := uint32(2)
	p.files = p.files[:0]
	var alloc func(d *dirPlan)
	alloc = func(d *dirPlan) {
		d.first = next
		next += d.nclus
		for _, e := range d.entries {
			if e.file != nil {
				if e.file.nclus > 0 {
					e.file.first = next
					next += e.file.nclus
				}
				p.files = append(p.files, e.file)
			}
		}
		for _, e := range d.entries {
			if e.dir != nil {
				alloc(e.dir)
			}
		}
	}
	alloc(p.root)
	p.used = next - 2
}

func (p *Plan) clusterOffset(c uint32) int64 {
	return (p.rsvd+2*p.fatSz)*p.bps + int64(c-2)*p.cs
}

// Hooks receive progress and per-file digests while writing.
type Hooks struct {
	// File is called after each file is written with its SHA-256.
	File func(path string, size int64, sum [32]byte)
	// Progress is called with the number of file bytes just written.
	Progress func(n int64)
}

// Write emits the filesystem to w starting at byte offset base.
func (p *Plan) Write(w io.WriterAt, base int64, hooks Hooks) error {
	if err := p.writeReserved(w, base); err != nil {
		return err
	}
	if err := p.writeFATs(w, base); err != nil {
		return err
	}
	if err := p.writeDirs(w, base, p.root); err != nil {
		return err
	}
	buf := make([]byte, 4<<20)
	for pass := 0; pass < 2; pass++ {
		for _, f := range p.files {
			if f.node.Deferred != (pass == 1) {
				continue
			}
			if err := p.writeFile(w, base, f, buf, hooks); err != nil {
				return err
			}
		}
	}
	return nil
}

type progressWriter struct {
	w  io.Writer
	h  hash.Hash
	fn func(int64)
}

func (pw *progressWriter) Write(b []byte) (int, error) {
	n, err := pw.w.Write(b)
	pw.h.Write(b[:n])
	if pw.fn != nil {
		pw.fn(int64(n))
	}
	return n, err
}

func (p *Plan) writeFile(w io.WriterAt, base int64, f *filePlan, buf []byte, hooks Hooks) error {
	h := sha256.New()
	size := f.node.Size
	if size > 0 {
		r, err := f.node.Open()
		if err != nil {
			return fmt.Errorf("%s: %w", f.path, err)
		}
		off := base + p.clusterOffset(f.first)
		pw := &progressWriter{w: io.NewOffsetWriter(w, off), h: h, fn: hooks.Progress}
		n, err := io.CopyBuffer(pw, io.LimitReader(r, size), buf)
		if c, ok := r.(io.Closer); ok {
			c.Close()
		}
		if err != nil {
			return fmt.Errorf("%s: %w", f.path, err)
		}
		if n != size {
			return fmt.Errorf("%s: source ended after %d of %d bytes", f.path, n, size)
		}
		if tail := int64(f.nclus)*p.cs - size; tail > 0 {
			if _, err := w.WriteAt(make([]byte, tail), off+size); err != nil {
				return err
			}
		}
	}
	if hooks.File != nil {
		var sum [32]byte
		copy(sum[:], h.Sum(nil))
		hooks.File(f.path, size, sum)
	}
	return nil
}

func (p *Plan) writeReserved(w io.WriterAt, base int64) error {
	bps := p.bps
	region := make([]byte, p.rsvd*bps)
	bs := region[:512]
	copy(bs[0:3], []byte{0xEB, 0x58, 0x90})
	copy(bs[3:11], fmt.Sprintf("%-8.8s", p.opt.OEMName))
	le := binary.LittleEndian
	le.PutUint16(bs[11:], uint16(bps))
	bs[13] = byte(p.cs / bps)
	le.PutUint16(bs[14:], uint16(p.rsvd))
	bs[16] = 2
	bs[21] = 0xF8
	le.PutUint16(bs[24:], 63)
	le.PutUint16(bs[26:], 255)
	hidden := p.opt.HiddenSectors
	if hidden > 0xFFFFFFFF {
		hidden = 0
	}
	le.PutUint32(bs[28:], uint32(hidden))
	le.PutUint32(bs[32:], uint32(p.totalSectors))
	le.PutUint32(bs[36:], uint32(p.fatSz))
	le.PutUint32(bs[44:], 2) // root cluster
	le.PutUint16(bs[48:], 1) // FSInfo sector
	le.PutUint16(bs[50:], 6) // backup boot sector
	bs[64] = 0x80
	bs[66] = 0x29
	le.PutUint32(bs[67:], p.opt.VolumeID)
	copy(bs[71:82], labelBytes(p.opt.Label))
	copy(bs[82:90], "FAT32   ")
	bs[510], bs[511] = 0x55, 0xAA

	fsi := region[bps : bps+512]
	le.PutUint32(fsi[0:], 0x41615252)
	le.PutUint32(fsi[484:], 0x61417272)
	le.PutUint32(fsi[488:], p.clusters-p.used)
	le.PutUint32(fsi[492:], p.used+2)
	le.PutUint32(fsi[508:], 0xAA550000)

	copy(region[6*bps:], region[:512])
	copy(region[7*bps:], fsi)
	_, err := w.WriteAt(region, base)
	return err
}

func (p *Plan) writeFATs(w io.WriterAt, base int64) error {
	fat := make([]byte, p.fatSz*p.bps)
	le := binary.LittleEndian
	le.PutUint32(fat[0:], 0x0FFFFFF8)
	le.PutUint32(fat[4:], 0x0FFFFFFF)
	chain := func(first, n uint32) {
		for i := uint32(0); i < n; i++ {
			v := first + i + 1
			if i == n-1 {
				v = 0x0FFFFFFF
			}
			le.PutUint32(fat[(first+i)*4:], v)
		}
	}
	var walk func(d *dirPlan)
	walk = func(d *dirPlan) {
		chain(d.first, d.nclus)
		for _, e := range d.entries {
			if e.dir != nil {
				walk(e.dir)
			} else if e.file.nclus > 0 {
				chain(e.file.first, e.file.nclus)
			}
		}
	}
	walk(p.root)
	off := base + p.rsvd*p.bps
	for i := int64(0); i < 2; i++ {
		if _, err := w.WriteAt(fat, off+i*int64(len(fat))); err != nil {
			return err
		}
	}
	return nil
}

func fatDateTime(t time.Time) (date, tm uint16) {
	if t.IsZero() || t.Year() < 1980 {
		return 0x21, 0 // 1980-01-01 00:00
	}
	if t.Year() > 2107 {
		t = time.Date(2107, 12, 31, 23, 59, 58, 0, time.UTC)
	}
	date = uint16(t.Year()-1980)<<9 | uint16(t.Month())<<5 | uint16(t.Day())
	tm = uint16(t.Hour())<<11 | uint16(t.Minute())<<5 | uint16(t.Second()/2)
	return
}

func putShort(e []byte, name [11]byte, attr byte, clus uint32, size uint32, mt time.Time) {
	le := binary.LittleEndian
	copy(e[0:11], name[:])
	e[11] = attr
	d, t := fatDateTime(mt)
	le.PutUint16(e[14:], t)
	le.PutUint16(e[16:], d)
	le.PutUint16(e[18:], d)
	le.PutUint16(e[20:], uint16(clus>>16))
	le.PutUint16(e[22:], t)
	le.PutUint16(e[24:], d)
	le.PutUint16(e[26:], uint16(clus))
	le.PutUint32(e[28:], size)
}

func sfnChecksum(n [11]byte) byte {
	var sum byte
	for _, c := range n {
		sum = (sum>>1 | sum<<7) + c
	}
	return sum
}

func (p *Plan) writeDirs(w io.WriterAt, base int64, d *dirPlan) error {
	buf := make([]byte, int64(d.nclus)*p.cs)
	pos := 0
	next := func() []byte {
		e := buf[pos : pos+32]
		pos += 32
		return e
	}
	mt := d.node.MTime
	if d.parent == nil {
		var lab [11]byte
		copy(lab[:], labelBytes(p.opt.Label))
		putShort(next(), lab, 0x08, 0, 0, mt)
	} else {
		dot := [11]byte{'.', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '}
		putShort(next(), dot, 0x10, d.first, 0, mt)
		dotdot := [11]byte{'.', '.', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '}
		parent := uint32(0)
		if d.parent.parent != nil {
			parent = d.parent.first
		}
		putShort(next(), dotdot, 0x10, parent, 0, d.parent.node.MTime)
	}
	for _, e := range d.entries {
		if e.lfn != nil {
			sum := sfnChecksum(e.sfn)
			units := append(append([]uint16(nil), e.lfn...), 0)
			n := (len(e.lfn) + 12) / 13
			for len(units) < n*13 {
				units = append(units, 0xFFFF)
			}
			for i := n; i >= 1; i-- {
				ent := next()
				ord := byte(i)
				if i == n {
					ord |= 0x40
				}
				ent[0] = ord
				ent[11] = 0x0F
				ent[13] = sum
				chunk := units[(i-1)*13 : i*13]
				k := 0
				for _, r := range [][2]int{{1, 11}, {14, 26}, {28, 32}} {
					for j := r[0]; j < r[1]; j += 2 {
						binary.LittleEndian.PutUint16(ent[j:], chunk[k])
						k++
					}
				}
			}
		}
		var attr byte = 0x20
		var clus, size uint32
		if e.dir != nil {
			attr = 0x10
			clus = e.dir.first
		} else {
			clus = e.file.first
			size = uint32(e.file.node.Size)
		}
		if e.node.Hidden {
			attr |= 0x02
		}
		putShort(next(), e.sfn, attr, clus, size, e.node.MTime)
	}
	if _, err := w.WriteAt(buf, base+p.clusterOffset(d.first)); err != nil {
		return err
	}
	for _, e := range d.entries {
		if e.dir != nil {
			if err := p.writeDirs(w, base, e.dir); err != nil {
				return err
			}
		}
	}
	return nil
}

const sfnSpecials = "$%'-_@~`!(){}^#&"

func validSFNChar(r rune) bool {
	return (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune(sfnSpecials, r)
}

// makeSFN returns an 8.3 alias for name, unique within used. exact is true
// when the alias equals the name, so no long-name entries are needed.
func makeSFN(name string, used map[[11]byte]bool) (sfn [11]byte, exact bool) {
	upper := strings.ToUpper(name)
	base, ext := upper, ""
	if i := strings.LastIndexByte(upper, '.'); i > 0 {
		base, ext = upper[:i], upper[i+1:]
	}
	fits := len(base) >= 1 && len(base) <= 8 && len(ext) <= 3 && !strings.HasPrefix(upper, ".")
	for _, r := range base + ext {
		if !validSFNChar(r) {
			fits = false
		}
	}
	if fits {
		for i := range sfn {
			sfn[i] = ' '
		}
		copy(sfn[0:8], base)
		copy(sfn[8:11], ext)
		if !used[sfn] {
			return sfn, name == upper
		}
	}
	// Lossy basis name with numeric tail.
	s := strings.TrimLeft(upper, ".")
	base, ext = s, ""
	if i := strings.LastIndexByte(s, '.'); i > 0 {
		base, ext = s[:i], s[i+1:]
	}
	clean := func(in string, max int) string {
		var b strings.Builder
		for _, r := range in {
			if r == ' ' || r == '.' {
				continue
			}
			if !validSFNChar(r) {
				r = '_'
			}
			b.WriteRune(r)
			if b.Len() >= max {
				break
			}
		}
		return b.String()
	}
	base, ext = clean(base, 8), clean(ext, 3)
	if base == "" {
		base = "_"
	}
	for i := 1; ; i++ {
		tail := "~" + strconv.Itoa(i)
		b := base
		if len(b) > 8-len(tail) {
			b = b[:8-len(tail)]
		}
		for j := range sfn {
			sfn[j] = ' '
		}
		copy(sfn[0:8], b+tail)
		copy(sfn[8:11], ext)
		if !used[sfn] {
			return sfn, false
		}
	}
}

// sanitizeLFN replaces characters that FAT long names cannot hold.
func sanitizeLFN(name string) (string, bool) {
	var b strings.Builder
	changed := false
	for _, r := range name {
		if r < 0x20 || strings.ContainsRune(`"*/:<>?\|`, r) {
			r = '_'
			changed = true
		}
		b.WriteRune(r)
	}
	s := b.String()
	if t := strings.TrimRight(s, ". "); t != s {
		s = t + strings.Repeat("_", len(s)-len(t))
		changed = true
	}
	return s, changed
}

func labelBytes(label string) []byte {
	out := []byte("           ")
	i := 0
	for _, r := range strings.ToUpper(label) {
		if i >= 11 {
			break
		}
		if r != ' ' && !validSFNChar(r) {
			r = '_'
		}
		out[i] = byte(r)
		i++
	}
	if strings.TrimSpace(string(out)) == "" {
		return []byte("NO NAME    ")
	}
	return out
}

// LabelString returns the label as it will be stored.
func LabelString(label string) string { return strings.TrimRight(string(labelBytes(label)), " ") }

// SanitizeName returns the name a file will have on FAT.
func SanitizeName(name string) string {
	s, _ := sanitizeLFN(name)
	return s
}

// SetHiddenSectors records the partition's starting LBA in the BPB. It does
// not change the layout.
func (p *Plan) SetHiddenSectors(lba uint64) { p.opt.HiddenSectors = lba }

// Files returns the number of files in the plan.
func (p *Plan) Files() int { return len(p.files) }
