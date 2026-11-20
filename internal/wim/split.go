// Package wim splits a Windows Imaging (WIM) file into a spanned set of .swm
// parts so that installation images larger than 4 GiB fit on FAT32. Windows
// Setup consumes install.swm/install2.swm/... natively (the same files
// `DISM /Split-Image` produces).
//
// Resources are copied byte-for-byte; nothing is decompressed or recompressed,
// so the SHA-1 hashes in the lookup table remain valid. Only non-solid WIMs
// (the .wim format on Microsoft ISOs) are supported; solid/ESD archives are
// refused with an explicit error.
package wim

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
)

const (
	headerSize = 208
	entrySize  = 50

	flagMetadata = 0x02
	flagCompress = 0x04
	flagSpanned  = 0x08
	flagSolid    = 0x10

	hdrFlagSpanned = 0x00000008
)

// DefaultMaxPart keeps every part comfortably below the FAT32 file limit.
const DefaultMaxPart = 4000 << 20

type reshdr struct {
	size   uint64 // stored size (56 bits)
	flags  byte
	offset uint64
	orig   uint64
}

func parseReshdr(b []byte) reshdr {
	v := binary.LittleEndian.Uint64(b[0:])
	return reshdr{
		size:   v & 0x00FFFFFFFFFFFFFF,
		flags:  byte(v >> 56),
		offset: binary.LittleEndian.Uint64(b[8:]),
		orig:   binary.LittleEndian.Uint64(b[16:]),
	}
}

func (r reshdr) put(b []byte) {
	binary.LittleEndian.PutUint64(b[0:], r.size&0x00FFFFFFFFFFFFFF|uint64(r.flags)<<56)
	binary.LittleEndian.PutUint64(b[8:], r.offset)
	binary.LittleEndian.PutUint64(b[16:], r.orig)
}

type entry struct {
	hdr    reshdr
	part   uint16
	refcnt uint32
	hash   [20]byte
}

// Part is one .swm file of a split set.
type Part struct {
	Name string
	Size int64
	Open func() (io.Reader, error)
}

// Split plans a spanned set for the WIM in r. Names follow DISM's convention:
// base+".swm", base+"2.swm", base+"3.swm", ...
func Split(r io.ReaderAt, size int64, base string, maxPart int64) ([]Part, error) {
	hdr := make([]byte, headerSize)
	if _, err := r.ReadAt(hdr, 0); err != nil {
		return nil, err
	}
	if string(hdr[0:8]) != "MSWIM\x00\x00\x00" || binary.LittleEndian.Uint32(hdr[8:]) != headerSize {
		return nil, errors.New("not a WIM file")
	}
	if v := binary.LittleEndian.Uint32(hdr[12:]); v != 0x10d00 && v != 0x10b00 {
		return nil, fmt.Errorf("unsupported WIM version %#x (solid/ESD archives cannot be split; export to a .wim with DISM first)", v)
	}
	if binary.LittleEndian.Uint16(hdr[40:]) != 1 || binary.LittleEndian.Uint16(hdr[42:]) != 1 {
		return nil, errors.New("WIM is already part of a split set")
	}
	lt := parseReshdr(hdr[48:])
	xmlh := parseReshdr(hdr[72:])
	boot := parseReshdr(hdr[96:])
	if lt.flags&flagCompress != 0 || xmlh.flags&flagCompress != 0 {
		return nil, errors.New("compressed lookup table or XML is not supported")
	}
	if lt.size%entrySize != 0 || int64(lt.offset+lt.size) > size || int64(xmlh.offset+xmlh.size) > size {
		return nil, errors.New("WIM header points outside the file")
	}
	table := make([]byte, lt.size)
	if _, err := r.ReadAt(table, int64(lt.offset)); err != nil {
		return nil, err
	}
	xmlRaw := make([]byte, xmlh.size)
	if _, err := r.ReadAt(xmlRaw, int64(xmlh.offset)); err != nil {
		return nil, err
	}
	var meta, data []entry
	for i := 0; i < len(table); i += entrySize {
		e := entry{
			hdr:    parseReshdr(table[i:]),
			part:   binary.LittleEndian.Uint16(table[i+24:]),
			refcnt: binary.LittleEndian.Uint32(table[i+26:]),
		}
		copy(e.hash[:], table[i+30:i+50])
		if e.hdr.flags&(flagSolid|flagSpanned) != 0 {
			return nil, errors.New("WIM contains solid or spanned resources; export it with DISM /Export-Image first")
		}
		if int64(e.hdr.offset+e.hdr.size) > size {
			return nil, errors.New("WIM resource extends beyond end of file")
		}
		if e.hdr.flags&flagMetadata != 0 {
			meta = append(meta, e)
		} else {
			data = append(data, e)
		}
	}
	sort.SliceStable(data, func(i, j int) bool { return data[i].hdr.offset < data[j].hdr.offset })

	slack := int64(len(xmlRaw))
	var groups [][]entry
	cur := append([]entry(nil), meta...)
	curSize := int64(headerSize) + slack
	for _, e := range meta {
		curSize += int64(e.hdr.size) + entrySize
	}
	if curSize > maxPart {
		return nil, errors.New("image metadata alone exceeds the part size")
	}
	for _, e := range data {
		need := int64(e.hdr.size) + entrySize
		if int64(headerSize)+slack+need > maxPart {
			return nil, fmt.Errorf("a single WIM resource (%d bytes) is larger than the part size", e.hdr.size)
		}
		if curSize+need > maxPart && len(cur) > 0 {
			groups = append(groups, cur)
			cur, curSize = nil, int64(headerSize)+slack
		}
		cur = append(cur, e)
		curSize += need
	}
	groups = append(groups, cur)

	total := len(groups)
	if total > 0xFFFF {
		return nil, errors.New("too many parts")
	}
	parts := make([]Part, 0, total)
	for i, g := range groups {
		num := i + 1
		name := base + ".swm"
		if num > 1 {
			name = base + strconv.Itoa(num) + ".swm"
		}
		p, err := buildPart(r, hdr, g, num, total, boot, xmlRaw, lt.flags, xmlh.flags)
		if err != nil {
			return nil, err
		}
		p.Name = name
		if p.Size > maxPart {
			return nil, fmt.Errorf("internal error: part %d is %d bytes", num, p.Size)
		}
		parts = append(parts, p)
	}
	return parts, nil
}

func buildPart(r io.ReaderAt, srcHdr []byte, g []entry, num, total int, boot reshdr, xmlRaw []byte, tableFlags, xmlFlags byte) (Part, error) {
	off := uint64(headerSize)
	type chunk struct{ off, n int64 }
	var chunks []chunk
	table := make([]byte, 0, len(g)*entrySize)
	var newBoot reshdr
	for _, e := range g {
		ne := e
		ne.hdr.offset = off
		ne.part = uint16(num)
		chunks = append(chunks, chunk{int64(e.hdr.offset), int64(e.hdr.size)})
		if num == 1 && e.hdr.flags&flagMetadata != 0 && e.hdr.offset == boot.offset && boot.size != 0 {
			newBoot = ne.hdr
		}
		b := make([]byte, entrySize)
		ne.hdr.put(b)
		binary.LittleEndian.PutUint16(b[24:], ne.part)
		binary.LittleEndian.PutUint32(b[26:], ne.refcnt)
		copy(b[30:], ne.hash[:])
		table = append(table, b...)
		off += e.hdr.size
	}
	tableOff := off
	xmlOff := tableOff + uint64(len(table))
	// The XML is copied unchanged into every part, exactly as wimlib's
	// wimsplit does; its TOTALBYTES values describe the image, not the part.
	xml := xmlRaw
	partSize := int64(xmlOff) + int64(len(xml))

	hdr := append([]byte(nil), srcHdr...)
	binary.LittleEndian.PutUint32(hdr[16:], binary.LittleEndian.Uint32(hdr[16:])|hdrFlagSpanned)
	binary.LittleEndian.PutUint16(hdr[40:], uint16(num))
	binary.LittleEndian.PutUint16(hdr[42:], uint16(total))
	reshdr{size: uint64(len(table)), flags: tableFlags, offset: tableOff, orig: uint64(len(table))}.put(hdr[48:])
	reshdr{size: uint64(len(xml)), flags: xmlFlags, offset: xmlOff, orig: uint64(len(xml))}.put(hdr[72:])
	if num == 1 {
		newBoot.put(hdr[96:])
	} else {
		reshdr{}.put(hdr[96:])
		binary.LittleEndian.PutUint32(hdr[120:], 0)
	}
	reshdr{}.put(hdr[124:]) // no integrity table

	return Part{
		Size: partSize,
		Open: func() (io.Reader, error) {
			rs := []io.Reader{bytes.NewReader(hdr)}
			for _, c := range chunks {
				rs = append(rs, io.NewSectionReader(r, c.off, c.n))
			}
			rs = append(rs, bytes.NewReader(table), bytes.NewReader(xml))
			return io.MultiReader(rs...), nil
		},
	}, nil
}
