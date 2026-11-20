package stick

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"path"
	"strings"
	"time"
	"unicode/utf8"

	"archavist.com/quiver/internal/blockdev"
	"archavist.com/quiver/internal/fat"
	"archavist.com/quiver/internal/gpt"
	"archavist.com/quiver/internal/image"
	"archavist.com/quiver/internal/menu"
	"archavist.com/quiver/internal/pe"
	"archavist.com/quiver/internal/vfs"
)

// Policy restricts which images may be written.
type Policy struct {
	// Checksums maps an image's file name to its expected SHA-256 (lower-case hex).
	Checksums map[string]string
	// RequireChecksums refuses images without an entry in Checksums.
	RequireChecksums bool
	// RequireSigned refuses images whose UEFI loader has no valid signature.
	RequireSigned bool
}

// Check enforces the policy on a loaded image.
func (p Policy) Check(s *image.Source) error {
	want, ok := p.Checksums[s.Name]
	switch {
	case ok && !strings.EqualFold(want, s.SHA256):
		return fmt.Errorf("%s: SHA-256 %s does not match the expected %s", s.Name, s.SHA256, want)
	case !ok && p.RequireChecksums:
		return fmt.Errorf("%s: no expected checksum supplied and --require-checksums is set", s.Name)
	}
	if p.RequireSigned && !s.Loader.Signed() {
		return fmt.Errorf("%s: UEFI loader is not validly signed and --require-signed is set", s.Name)
	}
	return nil
}

// Env carries callbacks and settings shared by all operations.
type Env struct {
	Seed     string // non-empty: derive all identifiers and times from it (reproducible output)
	Log      func(format string, a ...any)
	Progress func(label string, done, total int64)
	now      time.Time
}

func (e *Env) logf(format string, a ...any) {
	if e.Log != nil {
		e.Log(format, a...)
	}
}

func (e *Env) ids() ids {
	if e.Seed == "" {
		return ids{}
	}
	return ids{seed: []byte(e.Seed)}
}

func (e *Env) time() time.Time {
	if e.Seed != "" {
		return time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	if e.now.IsZero() {
		e.now = time.Now().UTC().Truncate(time.Second)
	}
	return e.now
}

// DonorFiles are the vendor-signed binaries that run the menu.
type DonorFiles struct {
	Shim       []byte
	GRUB       []byte
	GRUBName   string
	MokManager []byte
	Info       Donor
	grubInfo   *pe.Info
}

// DonorFromSource extracts shim + GRUB from an image, verifying both carry
// intact signatures.
func DonorFromSource(s *image.Source) (*DonorFiles, error) {
	if !s.Loader.IsShim || s.Stage2 == nil || !s.Stage2.IsGRUB {
		return nil, fmt.Errorf("%s does not boot through shim + GRUB", s.Name)
	}
	if !s.Loader.Signed() || !s.Stage2.Signed() {
		return nil, fmt.Errorf("%s: shim or GRUB signature is not intact", s.Name)
	}
	read := func(p string) ([]byte, error) {
		n := s.Tree.Lookup(p)
		if n == nil {
			return nil, fmt.Errorf("%s missing", p)
		}
		return vfs.ReadAll(n)
	}
	d := &DonorFiles{GRUBName: s.Stage2Name, grubInfo: s.Stage2}
	var err error
	if d.Shim, err = read(image.LoaderPath); err != nil {
		return nil, err
	}
	if d.GRUB, err = read("/EFI/BOOT/" + s.Stage2Name); err != nil {
		return nil, err
	}
	if mm := s.Tree.Lookup("/EFI/BOOT/mmx64.efi"); mm != nil {
		d.MokManager, _ = vfs.ReadAll(mm)
	}
	d.Info = Donor{
		SourceName:   s.Name,
		SourceSHA256: s.SHA256,
		Files:        map[string]string{},
		ShimSigs:     summarize(s.Loader),
		GRUBSigs:     summarize(s.Stage2),
		GRUBPrefixes: s.Stage2.GRUBPrefixes,
	}
	d.Info.Files["BOOTX64.EFI"] = sha(d.Shim)
	d.Info.Files[d.GRUBName] = sha(d.GRUB)
	if d.MokManager != nil {
		d.Info.Files["mmx64.efi"] = sha(d.MokManager)
	}
	return d, nil
}

// menuRank prefers GRUB builds whose config lookup is known (Debian/Ubuntu).
func menuRank(s *image.Source) int {
	if s.Stage2 == nil {
		return 0
	}
	for _, p := range s.Stage2.GRUBPrefixes {
		switch strings.ToLower(p) {
		case "/efi/ubuntu", "/efi/debian":
			return 2
		}
	}
	return 1
}

// pickDonor chooses the menu loader from the images being written.
func pickDonor(srcs []*image.Source) (*DonorFiles, error) {
	var best *image.Source
	for _, s := range srcs {
		if s.Loader.IsShim && s.Stage2 != nil && s.Stage2.IsGRUB && s.Loader.Signed() && s.Stage2.Signed() {
			if best == nil || menuRank(s) > menuRank(best) {
				best = s
			}
		}
	}
	if best == nil {
		return nil, errors.New("none of the images boots through a signed shim + GRUB, so there is no signed loader to run the menu;\n" +
			"pass --menu-from with any recent Ubuntu or Debian ISO (it does not have to be written to the stick)")
	}
	return DonorFromSource(best)
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// imageJob is a prepared image waiting to be written.
type imageJob struct {
	src   *image.Source
	meta  ImageMeta
	plan  *fat.Plan
	sums  *sumsCollector
	part  gpt.Partition  // FAT32 partition (boot files, or the whole image)
	iso   *gpt.Partition // ISO-backed mode: the raw ISO partition
	volID uint32
}

func (j *imageJob) sectors(ss int) (boot, iso uint64) {
	boot = roundUp(uint64(j.plan.TotalBytes()), 1<<20) / uint64(ss)
	if j.iso != nil {
		iso = roundUp(uint64(j.src.Size), 1<<20) / uint64(ss)
	}
	return
}

// span is the number of sectors the job's partitions occupy.
func (j *imageJob) span(ss int) uint64 {
	b, i := j.sectors(ss)
	return b + i
}

// place assigns LBAs from first (1 MiB aligned) and returns the next LBA.
func (j *imageJob) place(first uint64, ss int) uint64 {
	b, i := j.sectors(ss)
	j.part.First, j.part.Last = first, first+b-1
	next := first + b
	if j.iso != nil {
		j.iso.First, j.iso.Last = next, next+i-1
		next += i
	}
	return next
}

func (j *imageJob) partitions() []gpt.Partition {
	out := []gpt.Partition{j.part}
	if j.iso != nil {
		out = append(out, *j.iso)
	}
	return out
}

func titleFor(s *image.Source, titles map[string]string) string {
	if t, ok := titles[s.Name]; ok && t != "" {
		return t
	}
	return strings.TrimSuffix(s.Name, path.Ext(s.Name))
}

func gptName(prefix, title string) string {
	n := prefix + title
	for utf8.RuneCountInString(n) > 36 {
		_, size := utf8.DecodeLastRuneInString(n)
		n = n[:len(n)-size]
	}
	return n
}

func (e *Env) prepareImage(s *image.Source, mode string, slot, isoSlot int, title string, g ids, sectorSize int) (*imageJob, error) {
	volID := g.volID(fmt.Sprintf("slot-%d", slot))
	if mode == image.ModeISO {
		if err := s.PrepareISOBacked(isoSlot); err != nil {
			return nil, fmt.Errorf("%s: %w", s.Name, err)
		}
	} else if err := s.Prepare(volID); err != nil {
		return nil, fmt.Errorf("%s: %w", s.Name, err)
	}
	now := e.time()
	files, _, bytes := s.Tree.Count()
	job := &imageJob{src: s, volID: volID}
	job.part = gpt.Partition{Slot: slot - 1, Type: gpt.TypeBasicData, GUID: g.guid(fmt.Sprintf("part-%d", slot)), Name: gptName(imagePrefix, title)}
	if s.Kind != "windows-setup" && s.Kind != "winpe" {
		// Keep Windows from giving every image partition a drive letter when
		// the stick is plugged in. Windows media are exempt: Setup needs a
		// drive letter for its own partition to find install.wim/.swm.
		job.part.Attr = gpt.AttrNoDriveLetter | gpt.AttrHidden
	}
	job.meta = ImageMeta{
		Format: formatVersion, Tool: "quiver " + Version, Slot: slot,
		PartitionGUID: job.part.GUID.String(), VolumeID: image.FSUUID(volID), Title: title,
		SourceName: s.Name, SourceSHA256: s.SHA256, SourceSize: s.Size, SourceFormat: s.Format,
		VolumeLabel: s.VolumeLabel, Kind: s.Kind, Mode: mode,
		Loader: image.LoaderPath, LoaderSHA256: s.LoaderSHA256, LoaderSigs: summarize(s.Loader),
		Stage2: s.Stage2Name, Stage2SHA256: s.Stage2SHA256, Stage2Sigs: summarize(s.Stage2),
		MenuCapable: s.Loader.IsShim && s.Stage2 != nil && s.Stage2.IsGRUB && s.Loader.Signed() && s.Stage2.Signed(),
		Fixups:      s.Fixups, Warnings: s.Warnings, Files: files, Bytes: bytes, Added: now,
	}
	label := fat.LabelString(s.VolumeLabel)
	if mode == image.ModeISO {
		iso := gpt.Partition{Slot: isoSlot - 1, Type: gpt.TypeLinuxData, GUID: g.guid(fmt.Sprintf("part-%d", isoSlot)), Name: gptName(isoPrefix, title)}
		job.iso = &iso
		job.meta.ISOSlot, job.meta.ISOPartitionGUID, job.meta.ISOGrubUUID = isoSlot, iso.GUID.String(), s.ISOUUID()
		job.meta.Bytes += s.Size
		// Never reuse the ISO's label: the live system must find the ISO
		// partition, not this one, when it looks its media up by label.
		label = fmt.Sprintf("QVBOOT%d", slot)
	}
	qd, err := s.Tree.MkdirAll("/"+metaDir, now)
	if err != nil {
		return nil, err
	}
	qd.Hidden = true
	qd.Put(vfs.Bytes(imageMetaFile, marshal(job.meta), now))
	if job.sums, err = newSums(s.Tree); err != nil {
		return nil, err
	}
	qd.Put(job.sums.node(now))
	s.Tree.SortRecursive()
	if label == "NO NAME" || label == "" {
		label = fmt.Sprintf("QUIVER%d", slot)
	}
	job.plan, err = fat.PlanFS(s.Tree, fat.Options{SectorSize: sectorSize, Label: label, VolumeID: volID})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", s.Name, err)
	}
	for _, r := range job.plan.Renamed {
		s.Fixups = append(s.Fixups, "renamed for FAT: "+r)
	}
	return job, nil
}

func (e *Env) writeImage(dev blockdev.Device, job *imageJob) error {
	ss := int64(dev.SectorSize())
	job.plan.SetHiddenSectors(job.part.First)
	_, _, totalBytes := job.src.Tree.Count()
	if job.iso != nil {
		totalBytes += job.src.Size
	}
	var done int64
	label := "writing " + job.meta.Title
	progress := func(n int64) {
		done += n
		if e.Progress != nil {
			e.Progress(label, done, totalBytes)
		}
	}
	err := job.plan.Write(dev, int64(job.part.First)*ss, fat.Hooks{File: job.sums.record, Progress: progress})
	if err != nil {
		return fmt.Errorf("writing %s: %w", job.src.Name, err)
	}
	if job.iso == nil {
		return nil
	}
	// Copy the ISO byte-for-byte, re-hashing it on the way: the partition
	// must equal the file that was checked earlier.
	off := int64(job.iso.First) * ss
	h := sha256.New()
	pw := &countingWriter{w: io.NewOffsetWriter(dev, off), h: h, fn: progress}
	n, err := io.CopyBuffer(pw, io.NewSectionReader(job.src.ISOReader(), 0, job.src.Size), make([]byte, 4<<20))
	if err != nil {
		return fmt.Errorf("writing %s: %w", job.src.Name, err)
	}
	if n != job.src.Size || hex.EncodeToString(h.Sum(nil)) != job.src.SHA256 {
		return fmt.Errorf("%s changed while it was being written", job.src.Name)
	}
	if tail := job.iso.Bytes(int(ss)) - n; tail > 0 {
		if _, err := dev.WriteAt(make([]byte, tail), off+n); err != nil {
			return err
		}
	}
	return nil
}

type countingWriter struct {
	w  io.Writer
	h  hash.Hash
	fn func(int64)
}

func (c *countingWriter) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	c.h.Write(b[:n])
	c.fn(int64(n))
	return n, err
}

// menuJob builds the menu partition contents.
type menuJob struct {
	plan *fat.Plan
	sums *sumsCollector
	tree *vfs.Node
}

func readmeText() string {
	return `This USB stick was prepared with quiver ` + Version + `.

Partition 1 (this one) holds the boot menu: an unmodified shim and GRUB,
both vendor-signed and copied from one of the images on this stick, plus a
generated grub.cfg. Every other partition holds one image, booted by that
image's own vendor-signed UEFI loader. Secure Boot stays enabled throughout.

.quiver/manifest.json   describes every image and where the menu came from
.quiver/files.sha256    SHA-256 of every file on this partition
                        (each image partition has its own copy)

Check the stick with:   quiver verify --disk <device>
`
}

func (e *Env) buildMenu(m *Manifest, donor *DonorFiles, volID uint32, sectorSize int, minBytes int64) (*menuJob, error) {
	now := e.time()
	root := vfs.NewDir("", now)
	boot, _ := root.MkdirAll("/EFI/BOOT", now)
	boot.Put(vfs.Bytes("BOOTX64.EFI", donor.Shim, now))
	boot.Put(vfs.Bytes(donor.GRUBName, donor.GRUB, now))
	if donor.MokManager != nil {
		boot.Put(vfs.Bytes("mmx64.efi", donor.MokManager, now))
	}
	cfg := []byte(e.menuConfig(m))
	// The donor GRUB reads grub.cfg from its compiled-in prefix
	// (/EFI/<vendor>), then /boot/grub, then the directory it was loaded
	// from. Provide the same file at each so any GRUB build finds it.
	boot.Put(vfs.Bytes("grub.cfg", cfg, now))
	gb, _ := root.MkdirAll("/boot/grub", now)
	gb.Put(vfs.Bytes("grub.cfg", cfg, now))
	prefixes := append([]string{"/EFI/ubuntu", "/EFI/debian"}, donor.Info.GRUBPrefixes...)
	for _, p := range prefixes {
		if strings.EqualFold(p, "/EFI/BOOT") {
			continue
		}
		d, err := root.MkdirAll(p, now)
		if err != nil {
			return nil, err
		}
		d.Put(vfs.Bytes("grub.cfg", cfg, now))
	}
	qd, _ := root.MkdirAll("/"+metaDir, now)
	qd.Hidden = true
	qd.Put(vfs.Bytes(manifestFile, marshal(m), now))
	qd.Put(vfs.Bytes("README.txt", []byte(readmeText()), now))
	sums, err := newSums(root)
	if err != nil {
		return nil, err
	}
	qd.Put(sums.node(now))
	root.SortRecursive()
	plan, err := fat.PlanFS(root, fat.Options{SectorSize: sectorSize, Label: "QUIVER", VolumeID: volID, MinBytes: minBytes})
	if err != nil {
		return nil, err
	}
	return &menuJob{plan: plan, sums: sums, tree: root}, nil
}

func (e *Env) menuConfig(m *Manifest) string {
	var entries []menu.Entry
	for _, im := range m.Images {
		valid := false
		for _, s := range im.LoaderSigs {
			valid = valid || s.Valid
		}
		entries = append(entries, menu.Entry{Title: im.Title, Slot: im.Slot, FSUUID: strings.ToLower(im.VolumeID), Loader: im.Loader, Unsigned: !valid})
	}
	return menu.Config(entries, menu.Options{
		Timeout: m.Menu.Timeout, DefaultSlot: m.Menu.DefaultSlot, User: m.Menu.User,
		PasswordHash: m.Menu.PasswordHash, Version: Version,
	})
}

func (e *Env) writeMenu(dev blockdev.Device, mj *menuJob, part gpt.Partition) ([]byte, error) {
	ss := int64(dev.SectorSize())
	if mj.plan.TotalBytes() > part.Bytes(dev.SectorSize()) {
		return nil, fmt.Errorf("menu does not fit its partition (%d > %d bytes)", mj.plan.TotalBytes(), part.Bytes(dev.SectorSize()))
	}
	mj.plan.SetHiddenSectors(part.First)
	if err := mj.plan.Write(dev, int64(part.First)*ss, fat.Hooks{File: mj.sums.record}); err != nil {
		return nil, fmt.Errorf("writing menu: %w", err)
	}
	return mj.sums.render()
}

// BuildOptions are the inputs to Build.
type BuildOptions struct {
	Images   []string
	Mode     string       // auto, extract or iso
	Data     *DataRequest // optional shared-storage partition
	Titles   map[string]string
	MenuFrom string
	Menu     MenuSettings
	Policy   Policy
}

// Result summarises a completed write.
type Result struct {
	Manifest    *Manifest
	Fingerprint string
	FreeBytes   int64
}

func roundUp(x, a uint64) uint64 { return (x + a - 1) / a * a }

// menuFSBytes is the minimum filesystem size for the menu partition. It is
// kept 2 MiB below the partition size because FAT layout rounding can add up
// to one cluster plus the 1 MiB data-region alignment.
func menuFSBytes(p gpt.Partition, ss int) int64 { return p.Bytes(ss) - 2<<20 }

// Build erases dev and writes a new stick.
func (e *Env) Build(dev blockdev.Device, o BuildOptions) (*Result, error) {
	if len(o.Images) == 0 {
		return nil, errors.New("no images given")
	}
	g := e.ids()
	ss := dev.SectorSize()
	var srcs []*image.Source
	defer func() {
		for _, s := range srcs {
			s.Close()
		}
	}()
	for _, p := range o.Images {
		e.logf("reading %s", p)
		s, err := image.Load(p, func(d, t int64) {
			if e.Progress != nil {
				e.Progress("hashing "+path.Base(strings.ReplaceAll(p, `\`, "/")), d, t)
			}
		})
		if err != nil {
			return nil, err
		}
		srcs = append(srcs, s)
		if err := o.Policy.Check(s); err != nil {
			return nil, err
		}
	}
	var donor *DonorFiles
	var err error
	if o.MenuFrom != "" {
		ms, err := image.Load(o.MenuFrom, nil)
		if err != nil {
			return nil, fmt.Errorf("--menu-from: %w", err)
		}
		if err := o.Policy.Check(ms); err != nil {
			ms.Close()
			return nil, err
		}
		donor, err = DonorFromSource(ms)
		ms.Close()
		if err != nil {
			return nil, fmt.Errorf("--menu-from: %w", err)
		}
	} else if donor, err = pickDonor(srcs); err != nil {
		return nil, err
	}
	e.logf("menu loader: shim + %s from %s", donor.GRUBName, donor.Info.SourceName)

	tab := &gpt.Table{SectorSize: ss, TotalSectors: uint64(dev.Size()) / uint64(ss), DiskGUID: g.guid("disk")}
	align := tab.AlignLBA()
	if tab.TotalSectors < 4*align {
		return nil, errors.New("target is too small")
	}
	// Menu partition: size it with an empty manifest; the real menu has the
	// same minimum size, and its content is tiny compared with it.
	menuVol := g.volID("menu")
	probe, err := e.buildMenu(&Manifest{}, donor, menuVol, ss, menuMinBytes)
	if err != nil {
		return nil, err
	}
	menuPart := gpt.Partition{Slot: 0, Type: gpt.TypeESP, GUID: g.guid("part-1"), Name: menuPartName, First: align}
	menuPart.Last = menuPart.First + roundUp(uint64(probe.plan.TotalBytes())+(4<<20), uint64(1<<20))/uint64(ss) - 1

	var jobs []*imageJob
	next := menuPart.Last + 1
	slot := 2
	for _, s := range srcs {
		mode, err := s.ChooseMode(o.Mode)
		if err != nil {
			return nil, err
		}
		isoSlot := 0
		if mode == image.ModeISO {
			isoSlot = slot + 1
		}
		job, err := e.prepareImage(s, mode, slot, isoSlot, titleFor(s, o.Titles), g, ss)
		if err != nil {
			return nil, err
		}
		slot++
		if isoSlot != 0 {
			slot++
		}
		next = job.place(roundUp(next, align), ss)
		jobs = append(jobs, job)
	}
	lastUsable := (tab.LastUsable()+1)/align*align - 1
	if next-1 > lastUsable {
		need := int64(next+1+tab.FirstUsable()) * int64(ss) // + backup GPT
		return nil, fmt.Errorf("the stick needs %d MiB but %s holds %d MiB (short by %d MiB)",
			(need+(1<<20)-1)>>20, dev.Path(), dev.Size()>>20, (need-dev.Size()+(1<<20)-1)>>20)
	}
	var dataPart *gpt.Partition
	var dataLabel string
	if o.Data != nil {
		if dataLabel, err = validDataLabel(o.Data.Label); err != nil {
			return nil, err
		}
		first, last, err := placeData(gpt.FreeSpan{First: roundUp(next, align), Last: lastUsable}, o.Data.Size, ss, align)
		if err != nil {
			return nil, err
		}
		dataPart = &gpt.Partition{Slot: slot - 1, Type: gpt.TypeBasicData, GUID: g.guid(fmt.Sprintf("part-%d", slot)),
			Name: dataPartName, First: first, Last: last}
	}

	m := &Manifest{
		Format: formatVersion, Tool: "quiver " + Version, DiskGUID: tab.DiskGUID.String(), SectorSize: ss,
		MenuVolume: image.FSUUID(menuVol), Menu: o.Menu, Donor: donor.Info, Created: e.time(), Updated: e.time(),
	}
	if m.Menu.DefaultSlot == 0 {
		m.Menu.DefaultSlot = 2
	}
	for _, j := range jobs {
		m.Images = append(m.Images, j.meta)
	}
	var dataSerial uint32
	if dataPart != nil {
		m.Data, dataSerial = dataInfo(*dataPart, dataLabel, g, ss)
	}
	mj, err := e.buildMenu(m, donor, menuVol, ss, menuFSBytes(menuPart, ss))
	if err != nil {
		return nil, err
	}

	// Nothing has been written yet. From here on the device is modified;
	// the partition table goes last so an interrupted run leaves a blank disk.
	e.logf("erasing partition table on %s", dev.Path())
	if err := gpt.Wipe(dev, dev.Size()); err != nil {
		return nil, err
	}
	slotSums := map[int][]byte{}
	vols := map[int]string{}
	for _, j := range jobs {
		where := fmt.Sprintf("partition %d", j.meta.Slot)
		if j.iso != nil {
			where = fmt.Sprintf("partitions %d (boot) + %d (ISO, byte-identical)", j.meta.Slot, j.meta.ISOSlot)
		}
		e.logf("writing %s to %s, %.2f GiB", j.src.Name, where, gib(int64(j.span(ss))*int64(ss)))
		if err := e.writeImage(dev, j); err != nil {
			return nil, err
		}
		b, err := j.sums.render()
		if err != nil {
			return nil, err
		}
		slotSums[j.meta.Slot], vols[j.meta.Slot] = b, j.meta.VolumeID
		tab.Parts = append(tab.Parts, j.partitions()...)
	}
	if dataPart != nil {
		if err := e.formatData(dev, *dataPart, dataLabel, dataSerial); err != nil {
			return nil, err
		}
		tab.Parts = append(tab.Parts, *dataPart)
	}
	e.logf("writing boot menu")
	menuSums, err := e.writeMenu(dev, mj, menuPart)
	if err != nil {
		return nil, err
	}
	tab.Parts = append([]gpt.Partition{menuPart}, tab.Parts...)
	e.logf("writing partition table")
	if err := tab.Write(dev); err != nil {
		return nil, err
	}
	if err := dev.Sync(); err != nil {
		return nil, err
	}
	return &Result{Manifest: m, Fingerprint: fingerprint(m.DiskGUID, menuSums, slotSums, vols), FreeBytes: freeBytes(tab)}, nil
}

func freeBytes(t *gpt.Table) int64 {
	var n int64
	for _, f := range t.Free() {
		n += int64(f.Last-f.First+1) * int64(t.SectorSize)
	}
	return n
}

func gib(n int64) float64 { return float64(n) / (1 << 30) }
