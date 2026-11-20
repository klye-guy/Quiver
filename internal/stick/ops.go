package stick

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"archavist.com/quiver/internal/blockdev"
	"archavist.com/quiver/internal/exfat"
	"archavist.com/quiver/internal/fat"
	"archavist.com/quiver/internal/gpt"
	"archavist.com/quiver/internal/image"
	"archavist.com/quiver/internal/pe"
	"archavist.com/quiver/internal/vfs"
)

// state is an existing stick read from a device.
type state struct {
	tab      *gpt.Table
	menuPart gpt.Partition
	manifest *Manifest
	donor    *DonorFiles
	menuErr  error
}

func readJSON(tree *vfs.Node, p string, v any) error {
	n := tree.Lookup(p)
	if n == nil {
		return fmt.Errorf("%s not found", p)
	}
	b, err := vfs.ReadAll(n)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func openFS(dev blockdev.Device, p gpt.Partition) (*fat.Reader, *vfs.Node, error) {
	fs, err := fat.Open(dev, int64(p.First)*int64(dev.SectorSize()))
	if err != nil {
		return nil, nil, err
	}
	if fs.Size() > p.Bytes(dev.SectorSize()) {
		return nil, nil, errors.New("filesystem larger than its partition")
	}
	t, err := fs.Tree()
	return fs, t, err
}

// donorFromTree reads the menu loader files and checks them against the
// digests recorded in the manifest.
func donorFromTree(t *vfs.Node, info Donor, check bool) (*DonorFiles, error) {
	d := &DonorFiles{Info: info}
	for name, want := range info.Files {
		n := t.Lookup("/EFI/BOOT/" + name)
		if n == nil {
			return nil, fmt.Errorf("menu loader file %s is missing", name)
		}
		b, err := vfs.ReadAll(n)
		if err != nil {
			return nil, err
		}
		if check && sha(b) != want {
			return nil, fmt.Errorf("menu loader file %s does not match the manifest (possible tampering)", name)
		}
		switch strings.ToLower(name) {
		case "bootx64.efi":
			d.Shim = b
		case "mmx64.efi":
			d.MokManager = b
		default:
			d.GRUB, d.GRUBName = b, name
		}
	}
	if d.Shim == nil || d.GRUB == nil {
		return nil, errors.New("menu loader files incomplete")
	}
	return d, nil
}

func (e *Env) open(dev blockdev.Device) (*state, error) {
	tab, err := gpt.Read(dev, dev.SectorSize(), dev.Size())
	if err != nil {
		return nil, fmt.Errorf("%s: %w (not a quiver stick?)", dev.Path(), err)
	}
	st := &state{tab: tab}
	found := false
	for _, p := range tab.Parts {
		if p.Name == menuPartName && p.Type == gpt.TypeESP {
			st.menuPart, found = p, true
		}
	}
	if !found {
		return nil, fmt.Errorf("%s has no %q partition (not a quiver stick)", dev.Path(), menuPartName)
	}
	_, tree, err := openFS(dev, st.menuPart)
	if err != nil {
		st.menuErr = fmt.Errorf("menu partition unreadable: %w", err)
		return st, nil
	}
	var m Manifest
	if err := readJSON(tree, "/"+metaDir+"/"+manifestFile, &m); err != nil {
		st.menuErr = fmt.Errorf("manifest unreadable: %w", err)
		return st, nil
	}
	if m.Format != formatVersion {
		return nil, fmt.Errorf("stick format %d is not supported by this version", m.Format)
	}
	st.manifest = &m
	st.donor, err = donorFromTree(tree, m.Donor, true)
	if err != nil {
		st.menuErr = err
	}
	return st, nil
}

func (st *state) requireHealthy() error {
	if st.menuErr != nil {
		return fmt.Errorf("%v; run `quiver menu --repair` first", st.menuErr)
	}
	return nil
}

func (e *Env) rewriteMenu(dev blockdev.Device, st *state) (string, error) {
	st.manifest.sortImages()
	st.manifest.Updated = e.time()
	vol, err := parseVolID(st.manifest.MenuVolume)
	if err != nil {
		return "", err
	}
	mj, err := e.buildMenu(st.manifest, st.donor, vol, dev.SectorSize(), menuFSBytes(st.menuPart, dev.SectorSize()))
	if err != nil {
		return "", err
	}
	menuSums, err := e.writeMenu(dev, mj, st.menuPart)
	if err != nil {
		return "", err
	}
	if err := dev.Sync(); err != nil {
		return "", err
	}
	return e.fingerprintOf(dev, st, menuSums)
}

func parseVolID(s string) (uint32, error) {
	v, err := strconv.ParseUint(strings.ReplaceAll(s, "-", ""), 16, 32)
	if err != nil {
		return 0, fmt.Errorf("bad volume id %q", s)
	}
	return uint32(v), nil
}

func (e *Env) fingerprintOf(dev blockdev.Device, st *state, menuSums []byte) (string, error) {
	slots := map[int][]byte{}
	vols := map[int]string{}
	for _, im := range st.manifest.Images {
		p, ok := st.tab.Get(im.Slot - 1)
		if !ok {
			return "", fmt.Errorf("slot %d missing from partition table", im.Slot)
		}
		_, t, err := openFS(dev, p)
		if err != nil {
			return "", fmt.Errorf("slot %d: %w", im.Slot, err)
		}
		n := t.Lookup("/" + metaDir + "/" + sumsFile)
		if n == nil {
			return "", fmt.Errorf("slot %d has no checksum list", im.Slot)
		}
		b, err := vfs.ReadAll(n)
		if err != nil {
			return "", err
		}
		slots[im.Slot], vols[im.Slot] = b, im.VolumeID
	}
	return fingerprint(st.manifest.DiskGUID, menuSums, slots, vols), nil
}

// AddOptions are the inputs to Add.
type AddOptions struct {
	Image  string
	Mode   string // auto, extract or iso
	Title  string
	Policy Policy
}

// Add writes one more image into free space and updates the menu.
func (e *Env) Add(dev blockdev.Device, o AddOptions) (*Result, error) {
	st, err := e.open(dev)
	if err != nil {
		return nil, err
	}
	if err := st.requireHealthy(); err != nil {
		return nil, err
	}
	s, err := image.Load(o.Image, func(d, t int64) {
		if e.Progress != nil {
			e.Progress("hashing", d, t)
		}
	})
	if err != nil {
		return nil, err
	}
	defer s.Close()
	if err := o.Policy.Check(s); err != nil {
		return nil, err
	}
	idx := st.tab.NextSlot()
	if idx < 0 {
		return nil, errors.New("partition table is full")
	}
	slot := idx + 1
	title := o.Title
	if title == "" {
		title = titleFor(s, nil)
	}
	ss := dev.SectorSize()
	mode, err := s.ChooseMode(o.Mode)
	if err != nil {
		return nil, err
	}
	isoSlot := 0
	if mode == image.ModeISO {
		st.tab.Parts = append(st.tab.Parts, gpt.Partition{Slot: idx}) // reserve while picking the next slot
		isoIdx := st.tab.NextSlot()
		st.tab.Parts = st.tab.Parts[:len(st.tab.Parts)-1]
		if isoIdx < 0 {
			return nil, errors.New("partition table is full")
		}
		isoSlot = isoIdx + 1
	}
	job, err := e.prepareImage(s, mode, slot, isoSlot, title, e.ids(), ss)
	if err != nil {
		return nil, err
	}
	need := job.span(ss)
	var largest uint64
	placed := false
	for _, f := range st.tab.Free() {
		size := f.Last - f.First + 1
		if size > largest {
			largest = size
		}
		if size >= need {
			job.place(f.First, ss)
			placed = true
			break
		}
	}
	if !placed {
		return nil, fmt.Errorf("%s needs %.2f GiB; the largest free area is %.2f GiB", s.Name,
			gib(int64(need)*int64(ss)), gib(int64(largest)*int64(ss)))
	}
	e.logf("writing %s (%s mode, %.2f GiB)", s.Name, mode, gib(int64(need)*int64(ss)))
	if err := e.writeImage(dev, job); err != nil {
		return nil, err
	}
	st.tab.Parts = append(st.tab.Parts, job.partitions()...)
	if err := st.tab.Write(dev); err != nil {
		return nil, err
	}
	st.manifest.Images = append(st.manifest.Images, job.meta)
	e.logf("updating boot menu")
	fp, err := e.rewriteMenu(dev, st)
	if err != nil {
		return nil, err
	}
	return &Result{Manifest: st.manifest, Fingerprint: fp, FreeBytes: freeBytes(st.tab)}, nil
}

// Remove deletes the image in a partition slot.
func (e *Env) Remove(dev blockdev.Device, slot int) (*Result, error) {
	st, err := e.open(dev)
	if err != nil {
		return nil, err
	}
	if err := st.requireHealthy(); err != nil {
		return nil, err
	}
	if st.manifest.Data != nil && st.manifest.Data.Slot == slot {
		return nil, errors.New("that is the data partition; use `quiver data --remove`")
	}
	i, im := st.manifest.image(slot)
	p, ok := st.tab.Get(slot - 1)
	if im == nil || !ok || p.Name == menuPartName {
		return nil, fmt.Errorf("slot %d is not an image on this stick (give the image's boot slot, as shown by `quiver list`)", slot)
	}
	e.logf("removing %s (partition %d)", im.Title, slot)
	victims := []gpt.Partition{p}
	if im.ISOSlot != 0 {
		if ip, ok := st.tab.Get(im.ISOSlot - 1); ok {
			victims = append(victims, ip)
		}
	}
	for _, v := range victims {
		if err := wipeStart(dev, v); err != nil {
			return nil, err
		}
		st.tab.Remove(v.Slot)
	}
	if err := st.tab.Write(dev); err != nil {
		return nil, err
	}
	st.manifest.Images = append(st.manifest.Images[:i], st.manifest.Images[i+1:]...)
	if st.manifest.Menu.DefaultSlot == slot {
		st.manifest.Menu.DefaultSlot = 0
		if len(st.manifest.Images) > 0 {
			st.manifest.Menu.DefaultSlot = st.manifest.Images[0].Slot
		}
	}
	fp, err := e.rewriteMenu(dev, st)
	if err != nil {
		return nil, err
	}
	return &Result{Manifest: st.manifest, Fingerprint: fp, FreeBytes: freeBytes(st.tab)}, nil
}

// wipeStart destroys a partition's filesystem signature so no OS mounts the
// stale data.
func wipeStart(dev blockdev.Device, p gpt.Partition) error {
	n := p.Bytes(dev.SectorSize())
	if n > 1<<20 {
		n = 1 << 20
	}
	_, err := dev.WriteAt(make([]byte, n), int64(p.First)*int64(dev.SectorSize()))
	return err
}

// RemoveData deletes the shared-storage partition and everything on it.
func (e *Env) RemoveData(dev blockdev.Device) (*Result, error) {
	st, err := e.open(dev)
	if err != nil {
		return nil, err
	}
	if err := st.requireHealthy(); err != nil {
		return nil, err
	}
	d := st.manifest.Data
	if d == nil {
		return nil, errors.New("this stick has no data partition")
	}
	p, ok := st.tab.Get(d.Slot - 1)
	if !ok || p.Name != dataPartName {
		return nil, errors.New("data partition missing from the partition table")
	}
	e.logf("removing data partition %d", d.Slot)
	if err := wipeStart(dev, p); err != nil {
		return nil, err
	}
	st.tab.Remove(p.Slot)
	if err := st.tab.Write(dev); err != nil {
		return nil, err
	}
	st.manifest.Data = nil
	fp, err := e.rewriteMenu(dev, st)
	if err != nil {
		return nil, err
	}
	return &Result{Manifest: st.manifest, Fingerprint: fp, FreeBytes: freeBytes(st.tab)}, nil
}

// MenuOptions change menu settings. Nil fields are left unchanged.
type MenuOptions struct {
	Timeout      *int
	DefaultSlot  *int
	User         *string
	PasswordHash *string // "" clears the password
	Titles       map[int]string
	Repair       bool
	MenuFrom     string
	Policy       Policy
}

// Menu rewrites the menu partition, optionally rebuilding it from the image
// partitions when it is damaged.
func (e *Env) Menu(dev blockdev.Device, o MenuOptions) (*Result, error) {
	st, err := e.open(dev)
	if err != nil {
		return nil, err
	}
	if o.MenuFrom != "" {
		s, err := image.Load(o.MenuFrom, nil)
		if err != nil {
			return nil, fmt.Errorf("--menu-from: %w", err)
		}
		if err := o.Policy.Check(s); err != nil {
			s.Close()
			return nil, err
		}
		st.donor, err = DonorFromSource(s)
		s.Close()
		if err != nil {
			return nil, err
		}
		if st.manifest != nil {
			st.manifest.Donor = st.donor.Info
		}
	}
	if st.menuErr != nil || o.Repair {
		if !o.Repair {
			return nil, st.requireHealthy()
		}
		if err := e.repair(dev, st); err != nil {
			return nil, err
		}
	}
	m := st.manifest
	if o.Timeout != nil {
		m.Menu.Timeout = *o.Timeout
	}
	if o.DefaultSlot != nil {
		if _, im := m.image(*o.DefaultSlot); im == nil {
			return nil, fmt.Errorf("slot %d is not an image on this stick", *o.DefaultSlot)
		}
		m.Menu.DefaultSlot = *o.DefaultSlot
	}
	if o.User != nil {
		m.Menu.User = *o.User
	}
	if o.PasswordHash != nil {
		m.Menu.PasswordHash = *o.PasswordHash
		if m.Menu.PasswordHash != "" && m.Menu.User == "" {
			m.Menu.User = "admin"
		}
	}
	for slot, t := range o.Titles {
		_, im := m.image(slot)
		if im == nil {
			return nil, fmt.Errorf("slot %d is not an image on this stick", slot)
		}
		im.Title = t
	}
	fp, err := e.rewriteMenu(dev, st)
	if err != nil {
		return nil, err
	}
	return &Result{Manifest: m, Fingerprint: fp, FreeBytes: freeBytes(st.tab)}, nil
}

// repair rebuilds the manifest from the image partitions' own metadata.
func (e *Env) repair(dev blockdev.Device, st *state) error {
	old := st.manifest
	m := &Manifest{Format: formatVersion, Tool: "quiver " + Version, DiskGUID: st.tab.DiskGUID.String(),
		SectorSize: dev.SectorSize(), Menu: MenuSettings{Timeout: -1}, Created: e.time()}
	if old != nil {
		m.Menu, m.Created, m.MenuVolume = old.Menu, old.Created, old.MenuVolume
	}
	if m.MenuVolume == "" {
		m.MenuVolume = image.FSUUID(e.ids().volID("menu-repair"))
	}
	var donorSlot *gpt.Partition
	for _, p := range st.tab.Parts {
		if !strings.HasPrefix(p.Name, imagePrefix) {
			continue
		}
		_, t, err := openFS(dev, p)
		if err != nil {
			e.logf("partition %d unreadable, skipped: %v", p.Slot+1, err)
			continue
		}
		var im ImageMeta
		if err := readJSON(t, "/"+metaDir+"/"+imageMetaFile, &im); err != nil {
			e.logf("partition %d has no quiver metadata, skipped", p.Slot+1)
			continue
		}
		if im.Slot != p.Slot+1 || im.PartitionGUID != p.GUID.String() {
			return fmt.Errorf("partition %d metadata does not match the partition table", p.Slot+1)
		}
		if im.ISOSlot != 0 {
			if ip, ok := st.tab.Get(im.ISOSlot - 1); !ok || ip.GUID.String() != im.ISOPartitionGUID {
				e.logf("partition %d: its ISO partition %d is missing, skipped", p.Slot+1, im.ISOSlot)
				continue
			}
		}
		m.Images = append(m.Images, im)
		if im.MenuCapable && donorSlot == nil {
			pp := p
			donorSlot = &pp
		}
	}
	for _, p := range st.tab.Parts {
		if p.Name != dataPartName {
			continue
		}
		serial, size, err := exfat.Probe(dev, int64(p.First)*int64(dev.SectorSize()))
		if err != nil {
			e.logf("data partition %d unreadable, left out of the manifest: %v", p.Slot+1, err)
			continue
		}
		m.Data = &DataInfo{Slot: p.Slot + 1, PartitionGUID: p.GUID.String(), Filesystem: "exfat",
			Label: defaultDataLabel, Serial: image.FSUUID(serial), Bytes: size}
		if old != nil && old.Data != nil && old.Data.Slot == p.Slot+1 {
			m.Data.Label = old.Data.Label
		}
	}
	if st.donor == nil {
		if donorSlot == nil {
			return errors.New("no image can supply a signed menu loader; pass --menu-from")
		}
		_, t, err := openFS(dev, *donorSlot)
		if err != nil {
			return err
		}
		d := &DonorFiles{}
		for _, c := range t.Lookup("/EFI/BOOT").Children {
			b, err := vfs.ReadAll(c)
			if err != nil {
				return err
			}
			info, err := pe.Inspect(b)
			if err != nil {
				continue
			}
			switch {
			case strings.EqualFold(c.Name, "BOOTX64.EFI"):
				d.Shim = b
				d.Info.ShimSigs = summarize(info)
			case strings.EqualFold(c.Name, "mmx64.efi"):
				d.MokManager = b
			case info.IsGRUB:
				d.GRUB, d.GRUBName = b, c.Name
				d.Info.GRUBSigs = summarize(info)
				d.Info.GRUBPrefixes = info.GRUBPrefixes
			}
		}
		if d.Shim == nil || d.GRUB == nil {
			return errors.New("donor partition lacks shim or GRUB")
		}
		d.Info.SourceName = fmt.Sprintf("partition %d", donorSlot.Slot+1)
		d.Info.Files = map[string]string{"BOOTX64.EFI": sha(d.Shim), d.GRUBName: sha(d.GRUB)}
		if d.MokManager != nil {
			d.Info.Files["mmx64.efi"] = sha(d.MokManager)
		}
		st.donor = d
	}
	m.Donor = st.donor.Info
	st.manifest = m
	e.logf("rebuilt manifest with %d image(s)", len(m.Images))
	return nil
}

// Info is what List returns.
type Info struct {
	Manifest  *Manifest
	Table     *gpt.Table
	FreeBytes int64
	MenuError string
}

// List reads the stick's manifest.
func (e *Env) List(dev blockdev.Device) (*Info, error) {
	st, err := e.open(dev)
	if err != nil {
		return nil, err
	}
	in := &Info{Manifest: st.manifest, Table: st.tab, FreeBytes: freeBytes(st.tab)}
	if st.menuErr != nil {
		in.MenuError = st.menuErr.Error()
	}
	return in, nil
}

// PartitionReport is the verification result for one partition.
type PartitionReport struct {
	Slot     int
	Name     string
	Files    int
	Problems []string
}

// VerifyReport is the result of Verify.
type VerifyReport struct {
	Partitions  []PartitionReport
	Fingerprint string
	Problems    []string
}

// OK reports whether nothing was wrong.
func (r *VerifyReport) OK() bool {
	if len(r.Problems) > 0 {
		return false
	}
	for _, p := range r.Partitions {
		if len(p.Problems) > 0 {
			return false
		}
	}
	return true
}

// Verify re-hashes every file on the stick and checks it against the
// checksum lists, the manifest and the partition table.
func (e *Env) Verify(dev blockdev.Device) (*VerifyReport, error) {
	st, err := e.open(dev)
	if err != nil {
		return nil, err
	}
	rep := &VerifyReport{}
	if st.menuErr != nil {
		rep.Problems = append(rep.Problems, st.menuErr.Error())
	}
	if st.manifest == nil {
		return rep, nil
	}
	m := st.manifest
	if m.DiskGUID != st.tab.DiskGUID.String() {
		rep.Problems = append(rep.Problems, "disk GUID differs from the manifest")
	}
	sums := map[int][]byte{}
	vols := map[int]string{}
	var menuSums []byte
	check := func(p gpt.Partition, wantVol string) PartitionReport {
		pr := PartitionReport{Slot: p.Slot + 1, Name: p.Name}
		fs, t, err := openFS(dev, p)
		if err != nil {
			pr.Problems = append(pr.Problems, "filesystem unreadable: "+err.Error())
			return pr
		}
		if got := image.FSUUID(fs.VolumeID); got != wantVol {
			pr.Problems = append(pr.Problems, fmt.Sprintf("volume ID %s, manifest says %s", got, wantVol))
		}
		sn := t.Lookup("/" + metaDir + "/" + sumsFile)
		if sn == nil {
			pr.Problems = append(pr.Problems, "checksum list missing")
			return pr
		}
		raw, err := vfs.ReadAll(sn)
		if err != nil {
			pr.Problems = append(pr.Problems, err.Error())
			return pr
		}
		if p.Slot == st.menuPart.Slot {
			menuSums = raw
		} else {
			sums[p.Slot+1], vols[p.Slot+1] = raw, wantVol
		}
		want, err := parseSums(raw)
		if err != nil {
			pr.Problems = append(pr.Problems, err.Error())
			return pr
		}
		seen := map[string]bool{}
		buf := make([]byte, 4<<20)
		var done, total int64
		_ = t.Walk(func(path string, n *vfs.Node) error {
			if !n.Dir {
				total += n.Size
			}
			return nil
		})
		_ = t.Walk(func(path string, n *vfs.Node) error {
			if n.Dir {
				return nil
			}
			rel := strings.TrimPrefix(path, "/")
			if rel == metaDir+"/"+sumsFile {
				return nil
			}
			ws, listed := want[strings.ToUpper(rel)]
			if !listed {
				pr.Problems = append(pr.Problems, "unexpected file: "+rel)
				return nil
			}
			seen[strings.ToUpper(rel)] = true
			r, err := n.Open()
			if err != nil {
				pr.Problems = append(pr.Problems, rel+": "+err.Error())
				return nil
			}
			h := sha256.New()
			c, err := io.CopyBuffer(h, io.LimitReader(r, n.Size), buf)
			done += c
			if e.Progress != nil {
				e.Progress(fmt.Sprintf("verifying partition %d", pr.Slot), done, total)
			}
			if err != nil || c != n.Size {
				pr.Problems = append(pr.Problems, rel+": read error")
				return nil
			}
			if hex.EncodeToString(h.Sum(nil)) != ws {
				pr.Problems = append(pr.Problems, "MODIFIED: "+rel)
			}
			pr.Files++
			return nil
		})
		var missing []string
		for k := range want {
			if !seen[k] {
				missing = append(missing, k)
			}
		}
		sort.Strings(missing)
		for _, k := range missing {
			pr.Problems = append(pr.Problems, "missing: "+k)
		}
		return pr
	}
	rep.Partitions = append(rep.Partitions, check(st.menuPart, m.MenuVolume))
	// Menu loader binaries must still carry intact signatures.
	if st.donor != nil {
		for name, b := range map[string][]byte{"BOOTX64.EFI": st.donor.Shim, st.donor.GRUBName: st.donor.GRUB} {
			if info, err := pe.Inspect(b); err != nil || !info.Signed() {
				rep.Problems = append(rep.Problems, "menu loader "+name+" has no intact signature")
			}
		}
	}
	for _, im := range m.Images {
		p, ok := st.tab.Get(im.Slot - 1)
		if !ok {
			rep.Problems = append(rep.Problems, fmt.Sprintf("slot %d (%s) is in the manifest but not the partition table", im.Slot, im.Title))
			continue
		}
		if p.GUID.String() != im.PartitionGUID {
			rep.Problems = append(rep.Problems, fmt.Sprintf("slot %d partition GUID differs from the manifest", im.Slot))
		}
		rep.Partitions = append(rep.Partitions, check(p, im.VolumeID))
		if im.ISOSlot != 0 {
			rep.Partitions = append(rep.Partitions, e.checkISO(dev, st, im))
		}
	}
	known := map[int]bool{st.menuPart.Slot + 1: true}
	for _, im := range m.Images {
		known[im.Slot] = true
		if im.ISOSlot != 0 {
			known[im.ISOSlot] = true
		}
	}
	if d := m.Data; d != nil {
		known[d.Slot] = true
		pr := PartitionReport{Slot: d.Slot, Name: dataPartName + " (contents not verified)"}
		p, ok := st.tab.Get(d.Slot - 1)
		switch {
		case !ok:
			pr.Problems = append(pr.Problems, "missing from the partition table")
		case p.GUID.String() != d.PartitionGUID:
			pr.Problems = append(pr.Problems, "partition GUID differs from the manifest")
		default:
			if serial, _, err := exfat.Probe(dev, int64(p.First)*int64(dev.SectorSize())); err != nil {
				pr.Problems = append(pr.Problems, "no valid exFAT filesystem: "+err.Error())
			} else if image.FSUUID(serial) != d.Serial {
				pr.Problems = append(pr.Problems, "exFAT serial differs from the manifest (reformatted?)")
			}
		}
		rep.Partitions = append(rep.Partitions, pr)
	}
	for _, p := range st.tab.Parts {
		if !known[p.Slot+1] {
			rep.Problems = append(rep.Problems, fmt.Sprintf("partition %d (%q) is not in the manifest", p.Slot+1, p.Name))
		}
	}
	if menuSums != nil {
		rep.Fingerprint = fingerprint(m.DiskGUID, menuSums, sums, vols)
	}
	return rep, nil
}

// checkISO confirms an ISO-backed image's partition still holds the source
// ISO byte-for-byte (its SHA-256 is the vendor's published checksum).
func (e *Env) checkISO(dev blockdev.Device, st *state, im ImageMeta) PartitionReport {
	pr := PartitionReport{Slot: im.ISOSlot, Name: gptName(isoPrefix, im.Title)}
	p, ok := st.tab.Get(im.ISOSlot - 1)
	if !ok {
		pr.Problems = append(pr.Problems, "ISO partition missing from the partition table")
		return pr
	}
	if p.GUID.String() != im.ISOPartitionGUID {
		pr.Problems = append(pr.Problems, "ISO partition GUID differs from the manifest")
	}
	if p.Bytes(dev.SectorSize()) < im.SourceSize {
		pr.Problems = append(pr.Problems, "ISO partition smaller than the ISO")
		return pr
	}
	h := sha256.New()
	r := io.NewSectionReader(dev, int64(p.First)*int64(dev.SectorSize()), im.SourceSize)
	buf := make([]byte, 4<<20)
	var done int64
	for {
		n, err := r.Read(buf)
		h.Write(buf[:n])
		done += int64(n)
		if e.Progress != nil {
			e.Progress(fmt.Sprintf("verifying partition %d (ISO)", pr.Slot), done, im.SourceSize)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			pr.Problems = append(pr.Problems, "read error: "+err.Error())
			return pr
		}
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != im.SourceSHA256 {
		pr.Problems = append(pr.Problems, "MODIFIED: ISO contents no longer match "+im.SourceName)
	} else {
		pr.Files = 1
		pr.Name += " = " + im.SourceName
	}
	return pr
}

// parseSums reads a sha256sum-format list keyed by upper-cased path (FAT is
// case-insensitive).
func parseSums(b []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if len(line) < 67 || line[64:66] != "  " {
			return nil, fmt.Errorf("malformed checksum line %q", line)
		}
		out[strings.ToUpper(line[66:])] = line[:64]
	}
	return out, sc.Err()
}
