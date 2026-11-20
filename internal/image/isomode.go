package image

import (
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"archavist.com/quiver/internal/fat"
	"archavist.com/quiver/internal/vfs"
)

// Write modes for an image.
const (
	// ModeExtract copies the image's files onto one FAT32 partition.
	ModeExtract = "extract"
	// ModeISO writes the original ISO byte-for-byte to its own partition and
	// puts only the EFI boot files on a small FAT32 boot partition. No file
	// size limit applies.
	ModeISO = "iso"
)

// ISOBackedSupport reports whether the image can be written in ISO-backed
// mode, and why not if it cannot. ISO-backed mode needs:
//   - an ISO 9660 source (the boot partition's GRUB reads it directly);
//   - a GRUB-based boot chain (GRUB can read ISO 9660; firmware, shim and
//     systemd-boot cannot);
//   - a GRUB configuration the redirect can reach;
//   - a Linux-style image whose initramfs finds its media by label/UUID or
//     by scanning block devices, as it does on a dd-written stick.
func (s *Source) ISOBackedSupport() error {
	switch {
	case !strings.HasPrefix(s.Format, "iso9660"):
		return fmt.Errorf("source is %s, not ISO 9660", s.Format)
	case s.Kind == "windows-setup" || s.Kind == "winpe":
		return errors.New("Windows media boot through bootmgr, which can only read FAT")
	case s.grub() == nil:
		return errors.New("boot chain is not GRUB (only GRUB can read ISO 9660 at boot)")
	case s.isoCfgDir() == "" && s.Tree.Lookup("/EFI/BOOT/grub.cfg") == nil:
		return errors.New("no GRUB configuration found to redirect to")
	case s.isoUUID == "":
		return errors.New("ISO has no volume modification date for GRUB to identify it by")
	}
	return nil
}

// NeedsLargeFiles reports whether extract mode would hit the FAT32 limit
// (ignoring WIMs, which are split).
func (s *Source) NeedsLargeFiles() bool {
	big := false
	_ = s.Tree.Walk(func(p string, n *vfs.Node) error {
		lp := strings.ToLower(p)
		if !n.Dir && n.Size > fat.MaxFileSize && !(strings.HasPrefix(lp, "/sources/") && strings.HasSuffix(lp, ".wim")) {
			big = true
		}
		return nil
	})
	return big
}

// ChooseMode picks the write mode. requested is "auto", "extract" or "iso".
// Auto uses ISO-backed mode for every eligible Linux image: the partition is
// then byte-identical to the vendor ISO, keeps its original labels, and has
// no file size limit.
func (s *Source) ChooseMode(requested string) (string, error) {
	support := s.ISOBackedSupport()
	switch requested {
	case ModeExtract:
		return ModeExtract, nil
	case ModeISO:
		if support != nil {
			return "", fmt.Errorf("%s cannot be written ISO-backed: %v", s.Name, support)
		}
		return ModeISO, nil
	case "", "auto":
		if support == nil {
			return ModeISO, nil
		}
		return ModeExtract, nil
	}
	return "", fmt.Errorf("unknown mode %q (auto, extract or iso)", requested)
}

func (s *Source) grub() interface{ grubPrefixes() []string } {
	switch {
	case s.Stage2 != nil && s.Stage2.IsGRUB:
		return prefixes(s.Stage2.GRUBPrefixes)
	case s.Loader != nil && s.Loader.IsGRUB:
		return prefixes(s.Loader.GRUBPrefixes)
	}
	return nil
}

type prefixes []string

func (p prefixes) grubPrefixes() []string { return p }

func (s *Source) isoCfgDir() string {
	if s.Tree.Lookup("/boot/grub/grub.cfg") != nil || s.Tree.Lookup("/boot/grub/x86_64-efi/grub.cfg") != nil {
		return "/boot/grub"
	}
	return ""
}

// ISOUUID is the identifier GRUB uses for the ISO 9660 volume.
func (s *Source) ISOUUID() string { return s.isoUUID }

// ISOReader gives access to the raw image bytes.
func (s *Source) ISOReader() io.ReaderAt { return s.f }

// PrepareISOBacked replaces the tree with the boot-partition contents for
// ISO-backed mode. isoPart is the GPT partition number that will hold the
// ISO. Only the /EFI tree is copied, unmodified (minus shim's fallback);
// GRUB configuration stubs redirect GRUB to the ISO partition.
func (s *Source) PrepareISOBacked(isoPart int) error {
	if err := s.ISOBackedSupport(); err != nil {
		return err
	}
	// Media are found on the ISO partition exactly as on a dd-written stick,
	// so the extract-mode caveat about Debian's installer does not apply.
	var keep []string
	for _, w := range s.Warnings {
		if !strings.HasPrefix(w, "Debian's installer") {
			keep = append(keep, w)
		}
	}
	s.Warnings = keep
	cfg := s.isoCfgDir() // must be read from the full tree, before it is replaced
	efi := s.Tree.Lookup("/EFI")
	root := vfs.NewDir("", s.Tree.MTime)
	cp := *efi
	root.Children = append(root.Children, &cp)
	s.Tree = root
	if d := s.Tree.Lookup("/EFI/BOOT"); d != nil && d.Dir {
		for _, fb := range []string{"fbx64.efi", "fbia32.efi", "fbaa64.efi"} {
			if d.Remove(fb) {
				s.fix("removed shim fallback /EFI/BOOT/%s (prevents NVRAM writes on host machines)", fb)
			}
		}
	}
	// FAT has no symlinks; the EFI tree rarely contains any.
	if err := s.resolveLinks(); err != nil {
		return err
	}
	s.fix("ISO-backed: the original ISO is written byte-for-byte to partition %d; this partition holds only its /EFI boot files", isoPart)
	if cfg != "" {
		stub := isoStub(isoPart, s.isoUUID, cfg)
		put := func(dir string) {
			if s.Tree.Lookup(dir+"/grub.cfg") != nil {
				return
			}
			d, err := s.Tree.MkdirAll(dir, time.Time{})
			if err != nil {
				return
			}
			d.Put(vfs.Bytes("grub.cfg", []byte(stub), time.Time{}))
			s.fix("added %s/grub.cfg redirecting GRUB to %s/grub.cfg on the ISO partition", dir, cfg)
		}
		for _, p := range s.grub().grubPrefixes() {
			put(path.Clean(p))
		}
		put("/boot/grub") // GRUB builds whose prefix is /boot/grub (CD images)
		put("/EFI/BOOT")  // fallback: GRUB looks next to itself ($cmdpath)
	}
	s.Tree.SortRecursive()
	return s.Tree.Walk(func(p string, n *vfs.Node) error {
		if !n.Dir && n.Size > fat.MaxFileSize {
			return fmt.Errorf("%s is larger than 4 GiB", p)
		}
		return nil
	})
}

// isoStub points GRUB at the ISO partition. It prefers the partition on
// the same disk as the boot partition GRUB is reading this file from ($root;
// $cmdpath is empty when GRUB is chainloaded), so two ISOs with the same
// volume UUID can never be confused, and falls back to the ISO's UUID.
func isoStub(part int, uuid, cfgDir string) string {
	return fmt.Sprintf(`# Written by quiver: this image's files are on partition %[1]d, which holds
# the original ISO byte-for-byte. Point GRUB there and load its own config.
set qv_iso=
if regexp --set=1:qv_disk '^\(?([^,)]+),' "$root"; then
	if [ -e "($qv_disk,gpt%[1]d)%[3]s" ]; then
		set qv_iso="$qv_disk,gpt%[1]d"
	fi
fi
if [ -z "$qv_iso" ]; then
	if regexp --set=1:qv_disk '^\(([^,)]+),' "$cmdpath"; then
		if [ -e "($qv_disk,gpt%[1]d)%[3]s" ]; then
			set qv_iso="$qv_disk,gpt%[1]d"
		fi
	fi
fi
if [ -z "$qv_iso" ]; then
	search --no-floppy --fs-uuid --set=qv_iso %[2]s
fi
set root=$qv_iso
set prefix=($root)%[3]s
if [ -e $prefix/x86_64-efi/grub.cfg ]; then
	source $prefix/x86_64-efi/grub.cfg
else
	source $prefix/grub.cfg
fi
`, part, uuid, cfgDir)
}
