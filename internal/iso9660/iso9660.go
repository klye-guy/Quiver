// Package iso9660 reads ISO 9660 images, including the Rock Ridge (SUSP/RRIP)
// and Joliet extensions and the El Torito boot catalog. It is a read-only,
// bounds-checked parser intended for untrusted input: every length and offset
// taken from the image is validated against the image size.
package iso9660

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf16"

	"archavist.com/quiver/internal/vfs"
)

const sectorSize = 2048

// ErrNotISO is returned when no ISO 9660 primary volume descriptor is found.
var ErrNotISO = errors.New("not an ISO 9660 image")

// Image is an opened ISO 9660 filesystem.
type Image struct {
	r    io.ReaderAt
	size int64

	VolumeID string
	// GrubUUID is the identifier GRUB's iso9660 driver reports for this
	// volume (derived from the PVD modification date), or "" if unset.
	GrubUUID  string
	primary   []byte // root directory record from the PVD
	joliet    []byte // root directory record from the Joliet SVD, if any
	catalog   uint32 // El Torito boot catalog LBA (0 = none)
	rrSkip    int
	rockRidge bool
}

// Open parses the volume descriptor set.
func Open(r io.ReaderAt, size int64) (*Image, error) {
	im := &Image{r: r, size: size}
	buf := make([]byte, sectorSize)
	found := false
	for lba := int64(16); lba < 16+64; lba++ {
		if (lba+1)*sectorSize > size {
			break
		}
		if _, err := r.ReadAt(buf, lba*sectorSize); err != nil {
			return nil, err
		}
		if string(buf[1:6]) != "CD001" {
			break
		}
		switch buf[0] {
		case 0: // boot record
			if strings.HasPrefix(string(buf[7:39]), "EL TORITO SPECIFICATION") {
				im.catalog = binary.LittleEndian.Uint32(buf[0x47:])
			}
		case 1: // primary
			if !found {
				im.VolumeID = strings.TrimRight(string(buf[40:72]), " \x00")
				if m := buf[830:846]; strings.Trim(string(m), "0\x00") != "" {
					im.GrubUUID = fmt.Sprintf("%s-%s-%s-%s-%s-%s-%s", m[0:4], m[4:6], m[6:8], m[8:10], m[10:12], m[12:14], m[14:16])
				}
				im.primary = append([]byte(nil), buf[156:156+34]...)
				found = true
			}
		case 2: // supplementary; Joliet is identified by its UCS-2 escape sequence
			esc := buf[88:91]
			if esc[0] == '%' && esc[1] == '/' && (esc[2] == '@' || esc[2] == 'C' || esc[2] == 'E') {
				im.joliet = append([]byte(nil), buf[156:156+34]...)
			}
		case 255:
			lba = 1 << 40 // terminator
		}
	}
	if !found {
		return nil, ErrNotISO
	}
	if err := im.detectRockRidge(); err != nil {
		return nil, err
	}
	return im, nil
}

// Flavor describes which name space Tree will use.
func (im *Image) Flavor() string {
	switch {
	case im.rockRidge:
		return "iso9660+rockridge"
	case im.joliet != nil:
		return "iso9660+joliet"
	default:
		return "iso9660"
	}
}

// HasJoliet reports whether a Joliet tree is present.
func (im *Image) HasJoliet() bool { return im.joliet != nil }

type record struct {
	lba    uint32
	length uint32
	flags  byte
	name   []byte
	su     []byte
	date   [7]byte
}

func parseRecord(b []byte) (record, error) {
	if len(b) < 34 {
		return record{}, errors.New("short directory record")
	}
	nl := int(b[32])
	if 33+nl > len(b) {
		return record{}, errors.New("directory record name overflows record")
	}
	rec := record{
		lba:    binary.LittleEndian.Uint32(b[2:]),
		length: binary.LittleEndian.Uint32(b[10:]),
		flags:  b[25],
		name:   b[33 : 33+nl],
	}
	copy(rec.date[:], b[18:25])
	su := 33 + nl
	if nl%2 == 0 { // padding byte after an even-length name
		su++
	}
	if su < len(b) {
		rec.su = b[su:]
	}
	return rec, nil
}

func (rec record) isDir() bool { return rec.flags&0x02 != 0 }

func (rec record) mtime() time.Time {
	d := rec.date
	if d[1] == 0 || d[2] == 0 {
		return time.Time{}
	}
	loc := time.FixedZone("", int(int8(d[6]))*15*60)
	return time.Date(1900+int(d[0]), time.Month(d[1]), int(d[2]), int(d[3]), int(d[4]), int(d[5]), 0, loc).UTC()
}

func (im *Image) readDir(lba, length uint32) ([]record, error) {
	off := int64(lba) * sectorSize
	if length > 64<<20 || off+int64(length) > im.size {
		return nil, fmt.Errorf("directory extent at LBA %d out of range", lba)
	}
	buf := make([]byte, length)
	if _, err := im.r.ReadAt(buf, off); err != nil {
		return nil, err
	}
	var recs []record
	for pos := 0; pos < len(buf); {
		l := int(buf[pos])
		if l == 0 { // records never span sectors; zero means "next sector"
			pos = (pos/sectorSize + 1) * sectorSize
			continue
		}
		if pos+l > len(buf) {
			return nil, fmt.Errorf("directory record at LBA %d overflows extent", lba)
		}
		rec, err := parseRecord(buf[pos : pos+l])
		if err != nil {
			return nil, err
		}
		recs = append(recs, rec)
		pos += l
	}
	return recs, nil
}

func (im *Image) detectRockRidge() error {
	root, err := parseRecord(im.primary)
	if err != nil {
		return err
	}
	recs, err := im.readDir(root.lba, root.length)
	if err != nil || len(recs) == 0 {
		return err
	}
	su := recs[0].su // the root "." record carries the SP entry
	if len(su) >= 7 && su[0] == 'S' && su[1] == 'P' && su[4] == 0xBE && su[5] == 0xEF {
		im.rrSkip = int(su[6])
		// Confirm RRIP is actually in use by looking for any RR entry.
		for _, rec := range recs[1:] {
			e := im.susp(rec.su)
			if e.hasRR {
				im.rockRidge = true
				break
			}
		}
		if len(recs) <= 2 { // empty root: trust the SP entry
			im.rockRidge = true
		}
	}
	return nil
}

type suspInfo struct {
	name      string
	hasName   bool
	link      string
	isLink    bool
	relocated bool   // RE: this is a relocated directory, skip
	childLink uint32 // CL: placeholder for a relocated directory
	mode      uint32
	hasRR     bool
}

func (im *Image) susp(area []byte) suspInfo {
	var info suspInfo
	var name, link strings.Builder
	var linkParts []string
	var partial strings.Builder
	absolute := false
	if im.rrSkip < len(area) {
		area = area[im.rrSkip:]
	} else {
		area = nil
	}
	for depth := 0; depth < 16 && area != nil; depth++ {
		var next []byte
		for len(area) >= 4 {
			sig := string(area[0:2])
			l := int(area[2])
			if l < 4 || l > len(area) {
				break
			}
			e := area[:l]
			switch sig {
			case "NM":
				info.hasRR = true
				if len(e) >= 5 && e[4]&0x06 == 0 {
					name.Write(e[5:])
					info.hasName = true
				}
			case "PX":
				info.hasRR = true
				if len(e) >= 8 {
					info.mode = binary.LittleEndian.Uint32(e[4:])
				}
			case "SL":
				info.hasRR = true
				info.isLink = true
				comps := e[5:]
				for len(comps) >= 2 {
					cf, cl := comps[0], int(comps[1])
					if 2+cl > len(comps) {
						break
					}
					switch {
					case cf&0x08 != 0:
						absolute = true
					case cf&0x02 != 0:
						partial.WriteString(".")
					case cf&0x04 != 0:
						partial.WriteString("..")
					default:
						partial.Write(comps[2 : 2+cl])
					}
					if cf&0x01 == 0 && cf&0x08 == 0 { // component complete
						linkParts = append(linkParts, partial.String())
						partial.Reset()
					}
					comps = comps[2+cl:]
				}
			case "RE":
				info.hasRR = true
				info.relocated = true
			case "CL":
				info.hasRR = true
				if len(e) >= 8 {
					info.childLink = binary.LittleEndian.Uint32(e[4:])
				}
			case "TF", "RR", "PN", "SF":
				info.hasRR = true
			case "CE":
				if len(e) >= 24 {
					blk := binary.LittleEndian.Uint32(e[4:])
					off := binary.LittleEndian.Uint32(e[12:])
					ln := binary.LittleEndian.Uint32(e[20:])
					abs := int64(blk)*sectorSize + int64(off)
					if ln <= sectorSize*4 && abs+int64(ln) <= im.size {
						buf := make([]byte, ln)
						if _, err := im.r.ReadAt(buf, abs); err == nil {
							next = buf
						}
					}
				}
			case "ST":
				area = nil
			}
			if area == nil {
				break
			}
			area = area[l:]
		}
		area = next
	}
	if info.hasName {
		info.name = name.String()
	}
	if info.isLink {
		if absolute {
			link.WriteString("/")
		}
		link.WriteString(strings.Join(linkParts, "/"))
		info.link = link.String()
	}
	return info
}

func decodeName(raw []byte, jolietNames bool) string {
	var s string
	if jolietNames {
		u := make([]uint16, len(raw)/2)
		for i := range u {
			u[i] = binary.BigEndian.Uint16(raw[2*i:])
		}
		s = string(utf16.Decode(u))
	} else {
		s = string(raw)
	}
	if i := strings.LastIndexByte(s, ';'); i >= 0 {
		s = s[:i]
	}
	if !jolietNames {
		s = strings.TrimSuffix(s, ".")
	}
	return s
}

// Tree reads the complete directory hierarchy. Rock Ridge names are
// preferred, then Joliet, then plain ISO 9660 names.
func (im *Image) Tree() (*vfs.Node, error) {
	rootRec := im.primary
	useJoliet := false
	if !im.rockRidge && im.joliet != nil {
		rootRec, useJoliet = im.joliet, true
	}
	root, err := parseRecord(rootRec)
	if err != nil {
		return nil, err
	}
	node := vfs.NewDir("", root.mtime())
	visited := map[uint32]bool{}
	if err := im.fill(node, root, useJoliet, visited, 0); err != nil {
		return nil, err
	}
	return node, nil
}

func (im *Image) fill(dir *vfs.Node, rec record, joliet bool, visited map[uint32]bool, depth int) error {
	if depth > 64 {
		return errors.New("directory hierarchy too deep")
	}
	if visited[rec.lba] {
		return fmt.Errorf("directory loop at LBA %d", rec.lba)
	}
	visited[rec.lba] = true
	recs, err := im.readDir(rec.lba, rec.length)
	if err != nil {
		return err
	}
	type pending struct {
		name    string
		rec     record
		extents []vfs.Extent
		size    int64
		info    suspInfo
	}
	var cur *pending
	flush := func() {
		if cur == nil {
			return
		}
		p := cur
		cur = nil
		var n *vfs.Node
		if p.info.isLink {
			n = &vfs.Node{Name: p.name, Link: p.info.link, MTime: p.rec.mtime()}
		} else {
			n = vfs.FromExtents(p.name, im.r, p.extents, p.size, p.rec.mtime())
		}
		n.Hidden = p.rec.flags&0x01 != 0
		dir.Children = append(dir.Children, n)
	}
	for _, r := range recs {
		if len(r.name) == 1 && (r.name[0] == 0 || r.name[0] == 1) {
			continue // "." and ".."
		}
		var info suspInfo
		if im.rockRidge && !joliet {
			info = im.susp(r.su)
			if info.relocated {
				continue
			}
		}
		name := decodeName(r.name, joliet)
		if info.hasName {
			name = info.name
		}
		if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
			return fmt.Errorf("invalid file name %q in directory at LBA %d", name, rec.lba)
		}
		if info.childLink != 0 {
			// Placeholder for a deep directory moved elsewhere (RRIP CL).
			flush()
			sub := vfs.NewDir(name, r.mtime())
			target, err := im.readDir(info.childLink, sectorSize)
			if err != nil || len(target) == 0 {
				return fmt.Errorf("bad relocated directory %q", name)
			}
			if err := im.fill(sub, target[0], joliet, visited, depth+1); err != nil {
				return err
			}
			dir.Children = append(dir.Children, sub)
			continue
		}
		if r.isDir() && !info.isLink {
			flush()
			sub := vfs.NewDir(name, r.mtime())
			sub.Hidden = r.flags&0x01 != 0
			if err := im.fill(sub, r, joliet, visited, depth+1); err != nil {
				return err
			}
			dir.Children = append(dir.Children, sub)
			continue
		}
		off := int64(r.lba) * sectorSize
		if r.length > 0 && off+int64(r.length) > im.size {
			return fmt.Errorf("file %q extends beyond end of image", name)
		}
		if cur != nil && cur.name == name && cur.rec.flags&0x80 != 0 {
			// continuation of a multi-extent file
			cur.extents = append(cur.extents, vfs.Extent{Off: off, Len: int64(r.length)})
			cur.size += int64(r.length)
			cur.rec.flags = r.flags
			continue
		}
		flush()
		cur = &pending{name: name, rec: r, info: info, size: int64(r.length),
			extents: []vfs.Extent{{Off: off, Len: int64(r.length)}}}
	}
	flush()
	return nil
}

// BootEntry is an El Torito boot image.
type BootEntry struct {
	Platform byte   // 0x00 x86 BIOS, 0xEF UEFI
	LBA      uint32 // 2048-byte sector of the image
	Sectors  uint16 // 512-byte virtual sectors (often unreliable for UEFI)
}

// Offset returns the byte offset of the boot image.
func (b BootEntry) Offset() int64 { return int64(b.LBA) * sectorSize }

// BootEntries parses the El Torito boot catalog.
func (im *Image) BootEntries() ([]BootEntry, error) {
	if im.catalog == 0 {
		return nil, nil
	}
	off := int64(im.catalog) * sectorSize
	buf := make([]byte, sectorSize)
	if off+sectorSize > im.size {
		return nil, errors.New("boot catalog out of range")
	}
	if _, err := im.r.ReadAt(buf, off); err != nil {
		return nil, err
	}
	if buf[0] != 1 || buf[30] != 0x55 || buf[31] != 0xAA {
		return nil, errors.New("invalid El Torito validation entry")
	}
	var out []BootEntry
	platform := buf[1]
	add := func(e []byte, plat byte) {
		if e[0] != 0x88 {
			return
		}
		out = append(out, BootEntry{
			Platform: plat,
			Sectors:  binary.LittleEndian.Uint16(e[6:]),
			LBA:      binary.LittleEndian.Uint32(e[8:]),
		})
	}
	add(buf[32:64], platform)
	for pos := 64; pos+32 <= len(buf); {
		h := buf[pos]
		if h != 0x90 && h != 0x91 {
			break
		}
		plat := buf[pos+1]
		count := int(binary.LittleEndian.Uint16(buf[pos+2:]))
		pos += 32
		for i := 0; i < count && pos+32 <= len(buf); pos += 32 {
			if buf[pos] == 0x44 { // extension entry
				continue
			}
			add(buf[pos:pos+32], plat)
			i++
		}
		if h == 0x91 {
			break
		}
	}
	return out, nil
}

// LooksLikeUDFBridgeStub reports whether the ISO 9660 tree is only the
// placeholder that UDF-bridge media (e.g. Windows ISOs) put there.
func LooksLikeUDFBridgeStub(root *vfs.Node) bool {
	files, _, _ := root.Count()
	if files > 3 {
		return false
	}
	for _, c := range root.Children {
		if strings.EqualFold(c.Name, "README.TXT") {
			b, err := vfs.ReadAll(c)
			if err == nil && bytes.Contains(bytes.ToUpper(b), []byte("UDF")) {
				return true
			}
		}
	}
	return files == 0
}
