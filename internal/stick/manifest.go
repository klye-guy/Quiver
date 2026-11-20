// Package stick lays out and maintains a quiver USB stick:
//
//	partition 1  "QUIVER MENU"  FAT32 ESP: vendor-signed shim + GRUB copied
//	             unmodified from one of the user's images, plus grub.cfg
//	partition N  "QV <title>"   FAT32: one image's files, booted by that
//	             image's own vendor-signed loader
//
// Every partition carries /.quiver/files.sha256 listing every file on it, and
// the menu partition carries /.quiver/manifest.json describing the whole
// stick. Together they make the stick verifiable offline and produce a single
// fingerprint an administrator can record at build time.
package stick

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"archavist.com/quiver/internal/fat"
	"archavist.com/quiver/internal/gpt"
	"archavist.com/quiver/internal/pe"
	"archavist.com/quiver/internal/vfs"
)

// Version is the tool version recorded on every stick.
var Version = "1.1.1"

const (
	formatVersion = 1
	menuPartName  = "QUIVER MENU"
	dataPartName  = "QUIVER DATA"
	imagePrefix   = "QV "
	isoPrefix     = "QV-ISO "
	metaDir       = ".quiver"
	sumsFile      = "files.sha256"
	manifestFile  = "manifest.json"
	imageMetaFile = "image.json"
	menuMinBytes  = 128 << 20
)

// SignatureSummary is the part of an Authenticode result worth recording.
type SignatureSummary struct {
	Signer      string `json:"signer"`
	TrustAnchor string `json:"trust_anchor"`
	Valid       bool   `json:"valid"`
}

func summarize(info *pe.Info) []SignatureSummary {
	if info == nil {
		return nil
	}
	var out []SignatureSummary
	for _, s := range info.Signatures {
		out = append(out, SignatureSummary{Signer: s.Signer, TrustAnchor: s.TrustAnchor, Valid: s.Valid()})
	}
	return out
}

// ImageMeta describes one image partition. A copy lives on the partition
// itself so the menu can be rebuilt if the menu partition is lost.
type ImageMeta struct {
	Format        int    `json:"format"`
	Tool          string `json:"tool"`
	Slot          int    `json:"slot"` // GPT partition number (1-based)
	PartitionGUID string `json:"partition_guid"`
	VolumeID      string `json:"volume_id"`
	Title         string `json:"title"`
	SourceName    string `json:"source_name"`
	SourceSHA256  string `json:"source_sha256"`
	SourceSize    int64  `json:"source_size"`
	SourceFormat  string `json:"source_format"`
	VolumeLabel   string `json:"volume_label"`
	Kind          string `json:"kind"`
	// Mode is "extract" (files on this FAT32 partition) or "iso" (original
	// ISO byte-for-byte on partition ISOSlot; this partition holds /EFI only).
	Mode             string             `json:"mode"`
	ISOSlot          int                `json:"iso_slot,omitempty"`
	ISOPartitionGUID string             `json:"iso_partition_guid,omitempty"`
	ISOGrubUUID      string             `json:"iso_grub_uuid,omitempty"`
	Loader           string             `json:"loader"`
	LoaderSHA256     string             `json:"loader_sha256"`
	LoaderSigs       []SignatureSummary `json:"loader_signatures"`
	Stage2           string             `json:"stage2,omitempty"`
	Stage2SHA256     string             `json:"stage2_sha256,omitempty"`
	Stage2Sigs       []SignatureSummary `json:"stage2_signatures,omitempty"`
	MenuCapable      bool               `json:"menu_capable"`
	Fixups           []string           `json:"fixups,omitempty"`
	Warnings         []string           `json:"warnings,omitempty"`
	Files            int                `json:"files"`
	Bytes            int64              `json:"bytes"`
	Added            time.Time          `json:"added"`
}

// MenuSettings are user-tunable menu options.
type MenuSettings struct {
	Timeout      int    `json:"timeout"`
	DefaultSlot  int    `json:"default_slot"`
	User         string `json:"user,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
}

// Donor records where the menu's shim and GRUB came from.
type Donor struct {
	SourceName   string             `json:"source_name"`
	SourceSHA256 string             `json:"source_sha256"`
	Files        map[string]string  `json:"files"` // name -> sha256
	ShimSigs     []SignatureSummary `json:"shim_signatures"`
	GRUBSigs     []SignatureSummary `json:"grub_signatures"`
	GRUBPrefixes []string           `json:"grub_prefixes"`
}

// DataInfo describes the optional shared-storage partition. Its contents
// belong to the user and are not covered by verification.
type DataInfo struct {
	Slot          int    `json:"slot"`
	PartitionGUID string `json:"partition_guid"`
	Filesystem    string `json:"filesystem"`
	Label         string `json:"label"`
	Serial        string `json:"serial"`
	Bytes         int64  `json:"bytes"`
}

// Manifest describes the whole stick.
type Manifest struct {
	Format     int          `json:"format"`
	Tool       string       `json:"tool"`
	DiskGUID   string       `json:"disk_guid"`
	SectorSize int          `json:"sector_size"`
	MenuVolume string       `json:"menu_volume_id"`
	Menu       MenuSettings `json:"menu"`
	Donor      Donor        `json:"donor"`
	Images     []ImageMeta  `json:"images"`
	Data       *DataInfo    `json:"data,omitempty"`
	Created    time.Time    `json:"created"`
	Updated    time.Time    `json:"updated"`
}

func (m *Manifest) sortImages() {
	sort.Slice(m.Images, func(i, j int) bool { return m.Images[i].Slot < m.Images[j].Slot })
}

func (m *Manifest) image(slot int) (int, *ImageMeta) {
	for i := range m.Images {
		if m.Images[i].Slot == slot {
			return i, &m.Images[i]
		}
	}
	return -1, nil
}

func marshal(v any) []byte {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

// ---- deterministic or random identifiers ----

type ids struct{ seed []byte }

func (g ids) bytes(label string) [16]byte {
	var out [16]byte
	if g.seed == nil {
		if _, err := rand.Read(out[:]); err != nil {
			panic(err)
		}
		return out
	}
	m := hmac.New(sha256.New, g.seed)
	m.Write([]byte(label))
	copy(out[:], m.Sum(nil))
	return out
}

func (g ids) guid(label string) gpt.GUID { return gpt.FromBytes(g.bytes(label)) }

func (g ids) volID(label string) uint32 {
	b := g.bytes("vol:" + label)
	v := binary.LittleEndian.Uint32(b[:])
	if v == 0 {
		v = 1
	}
	return v
}

// ---- checksum lists ----

// sumsCollector produces /.quiver/files.sha256 as a deferred file: its size
// is known from the paths before anything is written, and its content is
// assembled from the digests computed while the other files are written.
type sumsCollector struct {
	lines map[string][32]byte
	size  int64
	paths []string
}

func newSums(tree *vfs.Node) (*sumsCollector, error) {
	c := &sumsCollector{lines: map[string][32]byte{}}
	err := tree.Walk(func(p string, n *vfs.Node) error {
		if n.Dir || n.Deferred {
			return nil
		}
		fp := fatPath(p)
		c.paths = append(c.paths, fp)
		c.size += int64(64 + 2 + len(strings.TrimPrefix(fp, "/")) + 1)
		return nil
	})
	sort.Strings(c.paths)
	return c, err
}

// fatPath maps a tree path to the name it will have on FAT.
func fatPath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = fat.SanitizeName(s)
	}
	return strings.Join(parts, "/")
}

func (c *sumsCollector) record(p string, _ int64, sum [32]byte) { c.lines[p] = sum }

func (c *sumsCollector) render() ([]byte, error) {
	var b bytes.Buffer
	for _, p := range c.paths {
		s, ok := c.lines[p]
		if !ok {
			return nil, fmt.Errorf("internal error: no digest recorded for %s", p)
		}
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(s[:]), strings.TrimPrefix(p, "/"))
	}
	if int64(b.Len()) != c.size {
		return nil, fmt.Errorf("internal error: checksum list is %d bytes, planned %d", b.Len(), c.size)
	}
	return b.Bytes(), nil
}

func (c *sumsCollector) node(mtime time.Time) *vfs.Node {
	return &vfs.Node{
		Name:     sumsFile,
		Size:     c.size,
		MTime:    mtime,
		Deferred: true,
		Open: func() (io.Reader, error) {
			b, err := c.render()
			if err != nil {
				return nil, err
			}
			return bytes.NewReader(b), nil
		},
	}
}

// fingerprint condenses the stick's checksum lists into one value.
func fingerprint(diskGUID string, menuSums []byte, slots map[int][]byte, volIDs map[int]string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "quiver-fingerprint-v1\ndisk %s\n", diskGUID)
	ms := sha256.Sum256(menuSums)
	fmt.Fprintf(&b, "menu %x\n", ms)
	keys := make([]int, 0, len(slots))
	for k := range slots {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	for _, k := range keys {
		s := sha256.Sum256(slots[k])
		fmt.Fprintf(&b, "slot %d %s %x\n", k, volIDs[k], s)
	}
	f := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(f[:])
}
