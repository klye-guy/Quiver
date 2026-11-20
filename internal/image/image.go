// Package image loads a boot image (ISO 9660/UDF optical image, raw FAT
// image or bare EFI application), classifies it, and prepares its file tree
// for a FAT32 partition: resolving symlinks, splitting oversized WIMs,
// re-pointing label-based boot parameters at the new filesystem, and pinning
// GRUB to its own partition.
//
// Nothing here modifies or substitutes any EFI executable. Every loader that
// runs at boot is the image vendor's original, byte-identical binary.
package image

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"archavist.com/quiver/internal/fat"
	"archavist.com/quiver/internal/iso9660"
	"archavist.com/quiver/internal/pe"
	"archavist.com/quiver/internal/udf"
	"archavist.com/quiver/internal/vfs"
	"archavist.com/quiver/internal/wim"
)

// LoaderPath is the UEFI removable-media boot path for x86-64.
const LoaderPath = "/EFI/BOOT/BOOTX64.EFI"

// Source is a loaded image.
type Source struct {
	Path        string
	Name        string
	Size        int64
	SHA256      string
	Format      string
	VolumeLabel string
	Kind        string
	Tree        *vfs.Node

	Loader       *pe.Info
	LoaderSHA256 string
	// Second stage (grubx64.efi next to a shim), if present.
	Stage2       *pe.Info
	Stage2Name   string
	Stage2SHA256 string

	Warnings []string
	Fixups   []string

	isoUUID string
	f       *os.File
}

// Close releases the underlying file.
func (s *Source) Close() error {
	if s.f != nil {
		return s.f.Close()
	}
	return nil
}

func (s *Source) warn(format string, a ...any) {
	s.Warnings = append(s.Warnings, fmt.Sprintf(format, a...))
}
func (s *Source) fix(format string, a ...any) { s.Fixups = append(s.Fixups, fmt.Sprintf(format, a...)) }

// HashFile returns the SHA-256 of a file, reporting progress.
func HashFile(f *os.File, size int64, progress func(done, total int64)) (string, error) {
	h := sha256.New()
	buf := make([]byte, 4<<20)
	var done int64
	r := io.NewSectionReader(f, 0, size)
	for {
		n, err := r.Read(buf)
		h.Write(buf[:n])
		done += int64(n)
		if progress != nil {
			progress(done, size)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Load opens and analyses an image. The caller must Close it.
func Load(p string, progress func(done, total int64)) (*Source, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s: not a regular file", p)
	}
	s := &Source{Path: p, Name: filepath.Base(p), Size: st.Size(), f: f}
	if s.SHA256, err = HashFile(f, s.Size, progress); err != nil {
		f.Close()
		return nil, err
	}
	if err := s.load(); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s: %w", s.Name, err)
	}
	return s, nil
}

func (s *Source) load() error {
	head := make([]byte, 512)
	n, _ := s.f.ReadAt(head, 0)
	head = head[:n]
	mtime := time.Time{}
	if st, err := s.f.Stat(); err == nil {
		mtime = st.ModTime().UTC()
	}

	switch {
	case len(head) >= 2 && head[0] == 'M' && head[1] == 'Z':
		return s.loadEFI(mtime)
	case len(head) == 512 && head[510] == 0x55 && head[511] == 0xAA && looksLikeFATBoot(head):
		fs, err := fat.Open(s.f, 0)
		if err == nil {
			t, err := fs.Tree()
			if err != nil {
				return err
			}
			s.Tree, s.Format, s.VolumeLabel = t, fmt.Sprintf("fat%d image", fs.Bits()), fs.Label
			return s.finish()
		}
	}

	iso, isoErr := iso9660.Open(s.f, s.Size)
	u, udfErr := udf.Open(s.f, s.Size)
	if isoErr != nil && udfErr != nil {
		return errors.New("not a recognised image (ISO 9660, UDF, FAT image or EFI application)")
	}
	var isoTree *vfs.Node
	if isoErr == nil {
		t, err := iso.Tree()
		if err != nil {
			return fmt.Errorf("reading ISO 9660 tree: %w", err)
		}
		isoTree = t
		s.VolumeLabel = iso.VolumeID
		s.isoUUID = iso.GrubUUID
	}
	useUDF := udfErr == nil && (isoTree == nil || iso9660.LooksLikeUDFBridgeStub(isoTree) || iso.Flavor() == "iso9660")
	if useUDF {
		t, err := u.Tree()
		if err != nil {
			return fmt.Errorf("reading UDF tree: %w", err)
		}
		s.Tree, s.Format = t, "udf"
		if s.VolumeLabel == "" {
			s.VolumeLabel = u.VolumeID
		}
	} else {
		s.Tree, s.Format = isoTree, iso.Flavor()
	}
	if isoErr == nil && s.Tree.Lookup(LoaderPath) == nil {
		if err := s.mergeElTorito(iso); err != nil {
			s.warn("could not read El Torito UEFI boot image: %v", err)
		}
	}
	return s.finish()
}

func looksLikeFATBoot(b []byte) bool {
	bps := int(b[11]) | int(b[12])<<8
	return (bps == 512 || bps == 4096) && b[13] != 0 && b[16] != 0 && (string(b[54:59]) == "FAT12" || string(b[54:59]) == "FAT16" || string(b[82:87]) == "FAT32")
}

func (s *Source) loadEFI(mtime time.Time) error {
	data, err := io.ReadAll(io.NewSectionReader(s.f, 0, s.Size))
	if err != nil {
		return err
	}
	info, err := pe.Inspect(data)
	if err != nil {
		return err
	}
	name := map[string]string{"x64": "BOOTX64.EFI", "aa64": "BOOTAA64.EFI", "ia32": "BOOTIA32.EFI"}[info.Machine]
	if name == "" {
		return fmt.Errorf("unsupported EFI machine type %s", info.Machine)
	}
	root := vfs.NewDir("", mtime)
	dir, _ := root.MkdirAll("/EFI/BOOT", mtime)
	dir.Children = append(dir.Children, vfs.FromExtents(name, s.f, []vfs.Extent{{Off: 0, Len: s.Size}}, s.Size, mtime))
	s.Tree, s.Format, s.Kind = root, "efi application", "efi-app"
	s.VolumeLabel = strings.ToUpper(strings.TrimSuffix(s.Name, filepath.Ext(s.Name)))
	return s.finish()
}

// mergeElTorito adds files from the El Torito UEFI boot image (a FAT image
// inside the ISO) that the ISO 9660 tree lacks.
func (s *Source) mergeElTorito(iso *iso9660.Image) error {
	entries, err := iso.BootEntries()
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.Platform != 0xEF {
			continue
		}
		fs, err := fat.Open(s.f, e.Offset())
		if err != nil {
			return err
		}
		if e.Offset()+fs.Size() > s.Size {
			return errors.New("El Torito image extends past end of ISO")
		}
		t, err := fs.Tree()
		if err != nil {
			return err
		}
		added := 0
		err = t.Walk(func(p string, n *vfs.Node) error {
			if n.Dir || p == "/" {
				return nil
			}
			if s.Tree.Lookup(p) != nil {
				return nil
			}
			dir, err := s.Tree.MkdirAll(path.Dir(p), n.MTime)
			if err != nil {
				return err
			}
			dir.Children = append(dir.Children, n)
			added++
			return nil
		})
		if err != nil {
			return err
		}
		if added > 0 {
			s.fix("added %d file(s) from the El Torito UEFI boot image", added)
		}
		if s.Tree.Lookup(LoaderPath) != nil {
			return nil
		}
	}
	return nil
}

func readNode(n *vfs.Node, max int64) ([]byte, error) {
	if n.Size > max {
		return nil, fmt.Errorf("%s is too large to inspect", n.Name)
	}
	return vfs.ReadAll(n)
}

func digest(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (s *Source) finish() error {
	s.Tree.SortRecursive()
	ln := s.Tree.Lookup(LoaderPath)
	if ln == nil || ln.Dir {
		return errors.New(`no x86-64 UEFI loader (\EFI\BOOT\BOOTX64.EFI) found; BIOS-only images are not supported`)
	}
	data, err := readNode(ln, 64<<20)
	if err != nil {
		return err
	}
	if s.Loader, err = pe.Inspect(data); err != nil {
		return fmt.Errorf("UEFI loader: %w", err)
	}
	s.LoaderSHA256 = digest(data)
	if s.Loader.Machine != "x64" {
		return fmt.Errorf("UEFI loader is %s, not x64", s.Loader.Machine)
	}
	if s.Loader.IsShim {
		for _, cand := range []string{"grubx64.efi", "GRUBX64.EFI"} {
			if g := s.Tree.Lookup("/EFI/BOOT/" + cand); g != nil && !g.Dir {
				if b, err := readNode(g, 64<<20); err == nil {
					if info, err := pe.Inspect(b); err == nil {
						s.Stage2, s.Stage2Name, s.Stage2SHA256 = info, g.Name, digest(b)
					}
				}
				break
			}
		}
	} else if s.Loader.IsGRUB {
		s.Stage2 = nil
	}
	if s.Kind == "" {
		s.Kind = classify(s.Tree)
	}
	if !s.Loader.Signed() {
		s.warn("the UEFI loader is not validly signed; firmware with Secure Boot enabled will refuse to start it")
	}
	if s.Kind == "debian-installer" {
		s.warn("Debian's installer looks for an ISO 9660 medium; if it cannot find its installation media, choose to select the device manually")
	}
	return nil
}

func classify(t *vfs.Node) string {
	has := func(p string) bool { return t.Lookup(p) != nil }
	switch {
	case has("/sources/boot.wim") && (has("/sources/install.wim") || has("/sources/install.esd") || has("/sources/install.swm")):
		return "windows-setup"
	case has("/sources/boot.wim"):
		return "winpe"
	case has("/casper"):
		return "linux-casper"
	case has("/live/filesystem.squashfs"):
		return "linux-live-boot"
	case has("/install.amd") || has("/install.a64"):
		return "debian-installer"
	case has("/LiveOS") || has("/images/pxeboot"):
		return "linux-dracut"
	case has("/arch"):
		return "linux-archiso"
	case has("/boot/x86_64/loader"):
		return "linux-suse"
	}
	return "generic-efi"
}

// FSUUID formats a FAT volume ID the way Linux (udev/blkid) presents it.
func FSUUID(id uint32) string { return fmt.Sprintf("%04X-%04X", id>>16, id&0xFFFF) }

// GrubUUID formats a FAT volume ID the way GRUB's search --fs-uuid expects it.
func GrubUUID(id uint32) string { return strings.ToLower(FSUUID(id)) }

// Prepare applies FAT-compatibility fixups for a partition with the given
// FAT volume ID. It mutates s.Tree and records every change in s.Fixups.
func (s *Source) Prepare(volID uint32) error {
	t := s.Tree
	// 1. Never ship shim's fallback loader: on a removable path it would
	//    write boot entries into the host machine's NVRAM.
	if d := t.Lookup("/EFI/BOOT"); d != nil && d.Dir {
		for _, fb := range []string{"fbx64.efi", "fbia32.efi", "fbaa64.efi"} {
			if d.Remove(fb) {
				s.fix("removed shim fallback /EFI/BOOT/%s (prevents NVRAM writes on host machines)", fb)
			}
		}
	}
	// 2. FAT has no symbolic links.
	if err := s.resolveLinks(); err != nil {
		return err
	}
	// 3. Windows images: split WIMs larger than the FAT32 file limit.
	if err := s.splitWIMs(); err != nil {
		return err
	}
	// 4. Re-point label-based boot parameters at the new filesystem.
	if s.VolumeLabel != "" {
		if err := s.rewriteLabels(volID); err != nil {
			return err
		}
	}
	// 5. Pin GRUB to this partition (see docs: "GRUB prefix pinning").
	s.pinGRUB(volID)
	// 6. Anything still too large cannot be stored.
	return t.Walk(func(p string, n *vfs.Node) error {
		if !n.Dir && n.Size > fat.MaxFileSize {
			return fmt.Errorf("%s is %d bytes; FAT32 cannot store files over 4 GiB", p, n.Size)
		}
		return nil
	})
}

func (s *Source) resolveLinks() error {
	type link struct {
		dir  *vfs.Node
		node *vfs.Node
		path string
	}
	var links []link
	var walk func(dir *vfs.Node, p string)
	walk = func(dir *vfs.Node, p string) {
		for _, c := range dir.Children {
			cp := path.Join(p, c.Name)
			if c.Link != "" {
				links = append(links, link{dir, c, cp})
			} else if c.Dir {
				walk(c, cp)
			}
		}
	}
	walk(s.Tree, "/")
	for _, l := range links {
		target, tp := s.follow(l.path, 0)
		switch {
		case target != nil && !target.Dir:
			cp := *target
			cp.Name = l.node.Name
			l.dir.Put(&cp)
			s.fix("symlink %s -> %s stored as a copy of %s", l.path, l.node.Link, tp)
		default:
			l.dir.Remove(l.node.Name)
			what := "a directory"
			if target == nil {
				what = "nothing inside the image"
			}
			s.fix("symlink %s -> %s omitted (points to %s)", l.path, l.node.Link, what)
		}
	}
	return nil
}

func (s *Source) follow(p string, depth int) (*vfs.Node, string) {
	if depth > 8 {
		return nil, ""
	}
	n := s.Tree.Lookup(p)
	if n == nil || n.Link == "" {
		return n, p
	}
	tgt := n.Link
	if !strings.HasPrefix(tgt, "/") {
		tgt = path.Join(path.Dir(p), tgt)
	}
	return s.follow(path.Clean(tgt), depth+1)
}

// Split thresholds; variables only so tests can exercise splitting with
// small files.
var (
	wimSplitAbove int64 = fat.MaxFileSize
	wimPartSize   int64 = wim.DefaultMaxPart
)

func (s *Source) splitWIMs() error {
	src := s.Tree.Lookup("/sources")
	if src == nil || !src.Dir {
		return nil
	}
	for _, c := range append([]*vfs.Node(nil), src.Children...) {
		lower := strings.ToLower(c.Name)
		if c.Dir || c.Size <= wimSplitAbove {
			continue
		}
		if !strings.HasSuffix(lower, ".wim") {
			if strings.HasSuffix(lower, ".esd") {
				return fmt.Errorf("/sources/%s is larger than 4 GiB and ESD archives cannot be split; convert it to a .wim with DISM first", c.Name)
			}
			continue
		}
		if c.ReaderAt == nil {
			return fmt.Errorf("/sources/%s: no random access to split it", c.Name)
		}
		base := strings.TrimSuffix(c.Name, c.Name[len(c.Name)-4:])
		parts, err := wim.Split(c.ReaderAt(), c.Size, base, wimPartSize)
		if err != nil {
			return fmt.Errorf("/sources/%s: %w", c.Name, err)
		}
		src.Remove(c.Name)
		for _, p := range parts {
			src.Put(&vfs.Node{Name: p.Name, Size: p.Size, Open: p.Open, MTime: c.MTime})
		}
		s.fix("split /sources/%s (%d bytes) into %d .swm parts for FAT32", c.Name, c.Size, len(parts))
	}
	src.SortRecursive()
	return nil
}

func isBootConfig(p string, n *vfs.Node) bool {
	if n.Dir || n.Size == 0 || n.Size > 1<<20 {
		return false
	}
	lp := strings.ToLower(p)
	if !(strings.HasPrefix(lp, "/boot/") || strings.HasPrefix(lp, "/efi/") || strings.HasPrefix(lp, "/loader/")) {
		return false
	}
	return strings.HasSuffix(lp, ".cfg") || strings.HasSuffix(lp, ".conf")
}

func (s *Source) rewriteLabels(volID uint32) error {
	label := s.VolumeLabel
	if len(label) < 3 {
		return nil
	}
	up, low := FSUUID(volID), GrubUUID(volID)
	variants := []string{label}
	if strings.Contains(label, " ") {
		variants = append(variants, strings.ReplaceAll(label, " ", `\x20`), strings.ReplaceAll(label, " ", `\040`))
	}
	type rule struct {
		re  *regexp.Regexp
		rep string
	}
	var rules []rule
	for _, v := range variants {
		q := regexp.QuoteMeta(v)
		end := `(["'\s/:,;]|$)`
		rules = append(rules,
			rule{regexp.MustCompile(`(?m)(?:CD)?LABEL=` + q + end), "UUID=" + up + "$1"},
			rule{regexp.MustCompile(`(?m)archisolabel=` + q + end), "archisodevice=/dev/disk/by-uuid/" + up + "$1"},
			rule{regexp.MustCompile(`(?m)img_label=` + q + end), "img_dev=/dev/disk/by-uuid/" + up + "$1"},
			rule{regexp.MustCompile(`(?m)(search\b[^\n]*?)(?:-l|--label)\s+(['"]?)` + q + `(['"]?)` + end), "${1}--fs-uuid ${2}" + low + "${3}${4}"},
		)
	}
	return s.Tree.Walk(func(p string, n *vfs.Node) error {
		if !isBootConfig(p, n) {
			return nil
		}
		b, err := vfs.ReadAll(n)
		if err != nil {
			return err
		}
		out := string(b)
		for _, r := range rules {
			out = r.re.ReplaceAllString(out, r.rep)
		}
		if out == string(b) {
			return nil
		}
		dir := s.Tree.Lookup(path.Dir(p))
		dir.Put(vfs.Bytes(n.Name, []byte(out), n.MTime))
		s.fix("%s: volume label %q references now point to filesystem UUID %s", p, label, up)
		return nil
	})
}

func (s *Source) pinGRUB(volID uint32) {
	g := s.Stage2
	if g == nil && s.Loader.IsGRUB {
		g = s.Loader
	}
	if g == nil {
		return
	}
	cfgDir := ""
	switch {
	case s.Tree.Lookup("/boot/grub/grub.cfg") != nil || s.Tree.Lookup("/boot/grub/x86_64-efi/grub.cfg") != nil:
		cfgDir = "/boot/grub"
	default:
		return
	}
	stub := fmt.Sprintf(`# Written by quiver: keeps this image's GRUB on its own partition.
# Without it, GRUB searches every disk for its config and could pick up a
# different image on the same stick. See the quiver documentation.
search --no-floppy --fs-uuid --set=root %s
set prefix=($root)%s
if [ -e $prefix/x86_64-efi/grub.cfg ]; then
	source $prefix/x86_64-efi/grub.cfg
else
	source $prefix/grub.cfg
fi
`, GrubUUID(volID), cfgDir)
	for _, pfx := range g.GRUBPrefixes {
		if s.Tree.Lookup(pfx) != nil {
			continue
		}
		dir, err := s.Tree.MkdirAll(pfx, time.Time{})
		if err != nil {
			continue
		}
		dir.Put(vfs.Bytes("grub.cfg", []byte(stub), time.Time{}))
		s.fix("added %s/grub.cfg so GRUB loads %s/grub.cfg from this partition", pfx, cfgDir)
	}
	s.Tree.SortRecursive()
}
