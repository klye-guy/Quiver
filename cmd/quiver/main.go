// Command quiver builds multi-image UEFI boot sticks that keep Secure Boot
// enabled. See README.md for the design and threat model.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"archavist.com/quiver/internal/blockdev"
	"archavist.com/quiver/internal/fat"
	"archavist.com/quiver/internal/image"
	"archavist.com/quiver/internal/menu"
	"archavist.com/quiver/internal/stick"
)

var version = "1.1.1"

const usage = `quiver %s — multi-image UEFI boot sticks that keep Secure Boot on

Usage:
  quiver list-disks [--all]
  quiver inspect IMAGE...                    analyse images without writing anything
  quiver build  --disk TARGET [options] IMAGE...
  quiver add    --disk TARGET [--title T] IMAGE
  quiver remove --disk TARGET SLOT
  quiver data   --disk TARGET [--size N] [--label L] | --remove
  quiver list   --disk TARGET
  quiver verify --disk TARGET [--expect FINGERPRINT]
  quiver menu   --disk TARGET [menu options]
  quiver version

TARGET is a whole disk (/dev/sdX on Linux; \\.\PhysicalDriveN, diskN or N on
Windows) or an image file path. Writing to disks needs root/Administrator.

Run "quiver COMMAND -h" for the options of each command.
`

func main() {
	stick.Version = version
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	cmds := map[string]func([]string) error{
		"list-disks": cmdListDisks,
		"inspect":    cmdInspect,
		"build":      cmdBuild,
		"add":        cmdAdd,
		"remove":     cmdRemove,
		"list":       cmdList,
		"verify":     cmdVerify,
		"menu":       cmdMenu,
		"data":       cmdData,
		"version": func([]string) error {
			fmt.Printf("quiver %s\n", version)
			return nil
		},
	}
	name := os.Args[1]
	if name == "-h" || name == "--help" || name == "help" {
		fmt.Printf(usage, version)
		return
	}
	fn, ok := cmds[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "quiver: unknown command %q\n\n", name)
		fmt.Fprintf(os.Stderr, usage, version)
		os.Exit(2)
	}
	if err := fn(os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "\nquiver: error:", err)
		os.Exit(1)
	}
}

// parse accepts flags anywhere among the positional arguments.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

// ---- progress ----

type progress struct {
	label    string
	finished string
	last     time.Time
	tty      bool
}

func newProgress() *progress {
	st, err := os.Stderr.Stat()
	return &progress{tty: err == nil && st.Mode()&os.ModeCharDevice != 0}
}

func (p *progress) update(label string, done, total int64) {
	now := time.Now()
	if label == p.label && now.Sub(p.last) < 250*time.Millisecond && done < total {
		return
	}
	if label != p.label && p.label != "" && p.tty {
		fmt.Fprintln(os.Stderr)
	}
	p.label, p.last = label, now
	pct := 100.0
	if total > 0 {
		pct = float64(done) * 100 / float64(total)
	}
	if p.tty {
		fmt.Fprintf(os.Stderr, "\r  %-44.44s %6.1f%%  %s / %s   ", label, pct, human(done), human(total))
	} else if done >= total && p.finished != label {
		p.finished = label
		fmt.Fprintf(os.Stderr, "  %s: done (%s)\n", label, human(total))
	}
}

func (p *progress) log(format string, a ...any) {
	if p.label != "" && p.tty {
		fmt.Fprintln(os.Stderr)
	}
	p.label = ""
	fmt.Fprintf(os.Stderr, "• "+format+"\n", a...)
}

func (p *progress) env(seed string) *stick.Env {
	return &stick.Env{Seed: seed, Log: p.log, Progress: p.update}
}

func human(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

var sizeRE = regexp.MustCompile(`(?i)^(\d+(?:\.\d+)?)\s*([kmgt]?)i?b?$`)

func parseSize(s string) (int64, error) {
	m := sizeRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, fmt.Errorf("invalid size %q (examples: 16G, 7800M)", s)
	}
	f, _ := strconv.ParseFloat(m[1], 64)
	mult := map[string]float64{"": 1, "k": 1 << 10, "m": 1 << 20, "g": 1 << 30, "t": 1 << 40}[strings.ToLower(m[2])]
	return int64(f * mult), nil
}

// ---- shared option groups ----

type policyFlags struct {
	checksums        multi
	requireChecksums bool
	requireSigned    bool
}

func (p *policyFlags) register(fs *flag.FlagSet) {
	fs.Var(&p.checksums, "checksums", "SHA256SUMS-style `file` of expected image hashes (repeatable)")
	fs.BoolVar(&p.requireChecksums, "require-checksums", false, "refuse images that have no entry in a --checksums file")
	fs.BoolVar(&p.requireSigned, "require-signed", false, "refuse images whose UEFI loader is not validly signed")
}

var bsdSumRE = regexp.MustCompile(`^SHA256 \((.+)\) = ([0-9a-fA-F]{64})$`)

func (p *policyFlags) policy() (stick.Policy, error) {
	pol := stick.Policy{Checksums: map[string]string{}, RequireChecksums: p.requireChecksums, RequireSigned: p.requireSigned}
	for _, f := range p.checksums {
		fh, err := os.Open(f)
		if err != nil {
			return pol, err
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			var hash, name string
			if m := bsdSumRE.FindStringSubmatch(line); m != nil {
				name, hash = m[1], m[2]
			} else if len(line) > 66 {
				hash, name = line[:64], strings.TrimLeft(line[64:], " *")
			}
			if len(hash) != 64 || strings.Trim(strings.ToLower(hash), "0123456789abcdef") != "" {
				continue
			}
			name = filepath.Base(strings.ReplaceAll(name, `\`, "/"))
			pol.Checksums[name] = strings.ToLower(hash)
		}
		fh.Close()
		if err := sc.Err(); err != nil {
			return pol, err
		}
	}
	return pol, nil
}

func readPassword(file, env string) (string, error) {
	var pw string
	switch {
	case file == "-":
		fmt.Fprint(os.Stderr, "menu password (input is visible; prefer --password-file): ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		pw = line
	case file != "":
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		pw = strings.SplitN(string(b), "\n", 2)[0]
	case env != "":
		pw = os.Getenv(env)
		if pw == "" {
			return "", fmt.Errorf("environment variable %s is empty", env)
		}
	default:
		return "", nil
	}
	return strings.TrimRight(pw, "\r\n"), nil
}

func openTarget(path string, o blockdev.Options) (blockdev.Device, error) {
	if path == "" {
		return nil, errors.New("--disk is required")
	}
	return blockdev.Open(path, o)
}

func confirm(dev blockdev.Device, yes bool, what string) error {
	if yes {
		return nil
	}
	if dev.IsFile() {
		fmt.Fprintf(os.Stderr, "\n%s image file %s (%s).\n", what, dev.Path(), human(dev.Size()))
	} else {
		fmt.Fprintf(os.Stderr, "\n%s disk %s (%s).\n", what, dev.Path(), human(dev.Size()))
		if ds, err := blockdev.List(true); err == nil {
			for _, d := range ds {
				if strings.EqualFold(d.Path, dev.Path()) {
					fmt.Fprintf(os.Stderr, "  model: %s   bus: %s   removable: %v\n", d.Model, d.Bus, d.Removable)
				}
			}
		}
	}
	fmt.Fprintf(os.Stderr, "Type the target path exactly (%s) to continue: ", dev.Path())
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	if strings.TrimSpace(line) != dev.Path() {
		return errors.New("not confirmed; nothing was written")
	}
	return nil
}

// ---- commands ----

func cmdListDisks(args []string) error {
	fs := flag.NewFlagSet("list-disks", flag.ContinueOnError)
	all := fs.Bool("all", false, "include loop, RAM and virtual devices")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	ds, err := blockdev.List(*all)
	if err != nil {
		return err
	}
	if *asJSON {
		return json.NewEncoder(os.Stdout).Encode(ds)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DISK\tSIZE\tBUS\tREMOVABLE\tMODEL\tNOTES")
	for _, d := range ds {
		notes := strings.Join(d.Mounts, " ")
		if d.System {
			notes = "SYSTEM DISK (refused) " + notes
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%s\t%s\n", d.Path, human(d.Size), d.Bus, d.Removable, d.Model, notes)
	}
	return tw.Flush()
}

func cmdInspect(args []string) error {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	mode := fs.String("mode", "auto", "write mode to plan for: auto, extract or iso")
	pf := &policyFlags{}
	pf.register(fs)
	paths, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("give at least one image")
	}
	pol, err := pf.policy()
	if err != nil {
		return err
	}
	pr := newProgress()
	type report struct {
		Image        string   `json:"image"`
		Size         int64    `json:"size"`
		SHA256       string   `json:"sha256"`
		Format       string   `json:"format"`
		Label        string   `json:"volume_label"`
		Kind         string   `json:"kind"`
		Loader       any      `json:"loader"`
		Stage2       any      `json:"stage2,omitempty"`
		MenuCapable  bool     `json:"menu_capable"`
		Mode         string   `json:"mode"`
		ModeNote     string   `json:"mode_note,omitempty"`
		Files        int      `json:"files"`
		PartitionB   int64    `json:"partition_bytes"`
		Fixups       []string `json:"fixups"`
		Warnings     []string `json:"warnings"`
		PolicyResult string   `json:"policy"`
	}
	var reps []report
	failed := false
	for _, p := range paths {
		s, err := image.Load(p, func(d, t int64) { pr.update("hashing "+filepath.Base(p), d, t) })
		if err != nil {
			pr.log("%v", err)
			failed = true
			continue
		}
		r := report{Image: s.Name, Size: s.Size, SHA256: s.SHA256, Format: s.Format, Label: s.VolumeLabel, Kind: s.Kind, Loader: s.Loader}
		if s.Stage2 != nil {
			r.Stage2 = s.Stage2
		}
		r.MenuCapable = s.Loader.IsShim && s.Stage2 != nil && s.Stage2.IsGRUB && s.Loader.Signed() && s.Stage2.Signed()
		r.PolicyResult = "ok"
		if err := pol.Check(s); err != nil {
			r.PolicyResult = err.Error()
			failed = true
		}
		r.Mode, err = s.ChooseMode(*mode)
		if err != nil {
			r.Warnings = append(r.Warnings, err.Error())
			failed = true
			r.Mode = "extract"
		}
		if why := s.ISOBackedSupport(); why != nil {
			r.ModeNote = "ISO-backed mode unavailable: " + why.Error()
		}
		var perr error
		if r.Mode == image.ModeISO {
			perr = s.PrepareISOBacked(99)
		} else {
			perr = s.Prepare(0x51D0C0DE)
		}
		if err := perr; err != nil {
			r.Warnings = append(r.Warnings, "cannot be written: "+err.Error())
			failed = true
		} else {
			s.Tree.SortRecursive()
			if plan, err := fat.PlanFS(s.Tree, fat.Options{SectorSize: 512, Label: "PROBE", VolumeID: 1}); err == nil {
				r.PartitionB = plan.TotalBytes()
				r.Files = plan.Files()
				for _, rn := range plan.Renamed {
					s.Fixups = append(s.Fixups, "renamed for FAT: "+rn)
				}
			} else {
				r.Warnings = append(r.Warnings, "cannot be written: "+err.Error())
				failed = true
			}
		}
		r.Fixups, r.Warnings = s.Fixups, append(s.Warnings, r.Warnings...)
		s.Close()
		reps = append(reps, r)
	}
	if pr.tty && pr.label != "" {
		fmt.Fprintln(os.Stderr)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(reps); err != nil {
			return err
		}
	} else {
		for _, r := range reps {
			fmt.Printf("\n%s\n", r.Image)
			fmt.Printf("  size        %s\n  sha256      %s\n  format      %s (label %q)\n  kind        %s\n", human(r.Size), r.SHA256, r.Format, r.Label, r.Kind)
			printLoader := func(name string, v any) {
				b, _ := json.Marshal(v)
				var li struct {
					Machine    string
					IsShim     bool `json:"is_shim"`
					IsGRUB     bool `json:"is_grub"`
					Signatures []struct {
						Signer      string
						Chain       []string
						DigestValid bool   `json:"digest_valid"`
						SignerValid bool   `json:"signer_valid"`
						Anchor      string `json:"trust_anchor"`
						Nested      bool
						Error       string
					}
				}
				json.Unmarshal(b, &li)
				role := "efi"
				if li.IsShim {
					role = "shim"
				} else if li.IsGRUB {
					role = "grub"
				}
				fmt.Printf("  %-11s %s, %s\n", name, li.Machine, role)
				if len(li.Signatures) == 0 {
					fmt.Printf("              UNSIGNED — refused when Secure Boot is enabled\n")
				}
				for _, s := range li.Signatures {
					state := "valid"
					if !(s.DigestValid && s.SignerValid && s.Error == "") {
						state = "INVALID " + s.Error
					}
					fmt.Printf("              signed by %q → %s [%s]\n", s.Signer, s.Anchor, state)
				}
			}
			printLoader("loader", r.Loader)
			if r.Stage2 != nil {
				printLoader("stage 2", r.Stage2)
			}
			fmt.Printf("  menu donor  %v\n", r.MenuCapable)
			fmt.Printf("  mode        %s\n", r.Mode)
			if r.ModeNote != "" {
				fmt.Printf("              (%s)\n", r.ModeNote)
			}
			if r.PartitionB > 0 {
				if r.Mode == image.ModeISO {
					fmt.Printf("  partitions  %s boot (%d files) + %s ISO, byte-identical\n", human(r.PartitionB), r.Files, human(r.Size))
				} else {
					fmt.Printf("  partition   %s for %d files\n", human(r.PartitionB), r.Files)
				}
			}
			for _, f := range r.Fixups {
				fmt.Printf("  fixup       %s\n", f)
			}
			for _, w := range r.Warnings {
				fmt.Printf("  WARNING     %s\n", w)
			}
			fmt.Printf("  policy      %s\n", r.PolicyResult)
		}
	}
	if failed {
		return errors.New("one or more images cannot be written as-is (see above)")
	}
	return nil
}

type menuFlags struct {
	timeout      int
	user         string
	passwordFile string
	passwordEnv  string
}

func (m *menuFlags) register(fs *flag.FlagSet) {
	fs.IntVar(&m.timeout, "timeout", -1, "menu timeout in `seconds`; -1 waits for a choice")
	fs.StringVar(&m.user, "user", "admin", "menu superuser `name` when a password is set")
	fs.StringVar(&m.passwordFile, "password-file", "", "protect menu entries with the password on the first line of `file` (\"-\" reads stdin)")
	fs.StringVar(&m.passwordEnv, "password-env", "", "read the menu password from environment `variable`")
}

func (m *menuFlags) hash() (string, error) {
	pw, err := readPassword(m.passwordFile, m.passwordEnv)
	if err != nil || pw == "" {
		return "", err
	}
	if !menu.ValidUser(m.user) {
		return "", errors.New("--user may contain only letters, digits, '_' and '-'")
	}
	return menu.HashPassword(pw)
}

func cmdBuild(args []string) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	disk := fs.String("disk", "", "target disk or image file (ERASED)")
	size := fs.String("size", "", "create an image file of this `size` (e.g. 16G) instead of writing a disk")
	menuFrom := fs.String("menu-from", "", "take the signed shim + GRUB for the menu from this `image`")
	seed := fs.String("seed", "", "derive all IDs and timestamps from `string` for bit-reproducible output")
	defSlot := fs.Int("default", 0, "partition `slot` booted when the timeout expires (default: first image)")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	allowFixed := fs.Bool("allow-fixed", false, "allow writing to a non-removable disk")
	mode := fs.String("mode", "auto", "how images are written: auto, extract or iso (see README)")
	data := fs.String("data", "", "add an exFAT data partition: `SIZE` (e.g. 64G) or \"rest\" for all remaining space")
	dataLabel := fs.String("data-label", "", "label for the data partition (default QUIVER-DATA)")
	var titles multi
	fs.Var(&titles, "title", "`FILE=TITLE` menu title for an image (repeatable)")
	mf := &menuFlags{}
	mf.register(fs)
	pf := &policyFlags{}
	pf.register(fs)
	paths, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return errors.New("give at least one image")
	}
	pol, err := pf.policy()
	if err != nil {
		return err
	}
	hash, err := mf.hash()
	if err != nil {
		return err
	}
	tmap := map[string]string{}
	for _, t := range titles {
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			return fmt.Errorf("--title %q: expected FILE=TITLE", t)
		}
		tmap[filepath.Base(k)] = v
	}
	o := blockdev.Options{Write: true, AllowFixed: *allowFixed}
	if *size != "" {
		n, err := parseSize(*size)
		if err != nil {
			return err
		}
		o.Create, o.Size = true, n
	}
	dev, err := openTarget(*disk, o)
	if err != nil {
		return err
	}
	if err := confirm(dev, *yes, "ALL DATA WILL BE ERASED on"); err != nil {
		dev.Close()
		return err
	}
	pr := newProgress()
	env := pr.env(*seed)
	settings := stick.MenuSettings{Timeout: mf.timeout, DefaultSlot: *defSlot}
	if hash != "" {
		settings.User, settings.PasswordHash = mf.user, hash
	}
	bo := stick.BuildOptions{Images: paths, Mode: *mode, Titles: tmap, MenuFrom: *menuFrom, Menu: settings, Policy: pol}
	if *data != "" {
		bo.Data = &stick.DataRequest{Label: *dataLabel}
		if *data != "rest" {
			if bo.Data.Size, err = parseSize(*data); err != nil {
				dev.Close()
				return err
			}
		}
	}
	res, err := env.Build(dev, bo)
	if cerr := dev.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	pr.log("done")
	printSummary(res.Manifest, res.Fingerprint, res.FreeBytes)
	return nil
}

func printSummary(m *stick.Manifest, fp string, free int64) {
	fmt.Println()
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "SLOT\tTITLE\tKIND\tMODE\tSIZE\tLOADER SIGNED BY")
	for _, im := range m.Images {
		var anchors []string
		for _, s := range im.LoaderSigs {
			if s.Valid {
				anchors = append(anchors, s.TrustAnchor)
			}
		}
		if len(anchors) == 0 {
			anchors = []string{"UNSIGNED"}
		}
		mode := im.Mode
		if mode == "" {
			mode = "extract"
		}
		if im.ISOSlot != 0 {
			mode = fmt.Sprintf("iso (ISO on %d)", im.ISOSlot)
		}
		fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%s\t%s\n", im.Slot, im.Title, im.Kind, mode, human(im.Bytes), strings.Join(anchors, "; "))
	}
	tw.Flush()
	pw := "none"
	if m.Menu.PasswordHash != "" {
		pw = "user " + m.Menu.User
	}
	fmt.Printf("\nmenu loader   shim + GRUB from %s\nmenu password %s\n", m.Donor.SourceName, pw)
	if d := m.Data; d != nil {
		fmt.Printf("data          partition %d, %s %s, label %s\n", d.Slot, human(d.Bytes), d.Filesystem, d.Label)
	}
	fmt.Printf("free space    %s\n", human(free))
	if fp != "" {
		fmt.Printf("fingerprint   %s\n", fp)
		fmt.Println("\nRecord the fingerprint; `quiver verify --expect <fingerprint>` proves the stick is unchanged.")
	}
}

func slotArg(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 2 {
		return 0, fmt.Errorf("invalid slot %q (image slots start at 2)", s)
	}
	return n, nil
}

func cmdAdd(args []string) error {
	fs := flag.NewFlagSet("add", flag.ContinueOnError)
	disk := fs.String("disk", "", "quiver stick (disk or image file)")
	title := fs.String("title", "", "menu `title` (default: file name)")
	mode := fs.String("mode", "auto", "how the image is written: auto, extract or iso")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	allowFixed := fs.Bool("allow-fixed", false, "allow writing to a non-removable disk")
	pf := &policyFlags{}
	pf.register(fs)
	paths, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(paths) != 1 {
		return errors.New("give exactly one image")
	}
	pol, err := pf.policy()
	if err != nil {
		return err
	}
	dev, err := openTarget(*disk, blockdev.Options{Write: true, AllowFixed: *allowFixed})
	if err != nil {
		return err
	}
	if err := confirm(dev, *yes, "Adding an image to"); err != nil {
		dev.Close()
		return err
	}
	pr := newProgress()
	res, err := pr.env("").Add(dev, stick.AddOptions{Image: paths[0], Mode: *mode, Title: *title, Policy: pol})
	if cerr := dev.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	printSummary(res.Manifest, res.Fingerprint, res.FreeBytes)
	return nil
}

func cmdRemove(args []string) error {
	fs := flag.NewFlagSet("remove", flag.ContinueOnError)
	disk := fs.String("disk", "", "quiver stick (disk or image file)")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	allowFixed := fs.Bool("allow-fixed", false, "allow writing to a non-removable disk")
	pos, err := parse(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("give the slot number to remove (see `quiver list`)")
	}
	slot, err := slotArg(pos[0])
	if err != nil {
		return err
	}
	dev, err := openTarget(*disk, blockdev.Options{Write: true, AllowFixed: *allowFixed})
	if err != nil {
		return err
	}
	if err := confirm(dev, *yes, fmt.Sprintf("Removing slot %d from", slot)); err != nil {
		dev.Close()
		return err
	}
	pr := newProgress()
	res, err := pr.env("").Remove(dev, slot)
	if cerr := dev.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	printSummary(res.Manifest, res.Fingerprint, res.FreeBytes)
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	disk := fs.String("disk", "", "quiver stick (disk or image file)")
	asJSON := fs.Bool("json", false, "print the full manifest as JSON")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	dev, err := openTarget(*disk, blockdev.Options{})
	if err != nil {
		return err
	}
	defer dev.Close()
	info, err := newProgress().env("").List(dev)
	if err != nil {
		return err
	}
	if info.MenuError != "" {
		fmt.Fprintln(os.Stderr, "WARNING:", info.MenuError)
	}
	if info.Manifest == nil {
		return errors.New("no readable manifest; try `quiver menu --repair`")
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(info.Manifest)
	}
	m := info.Manifest
	fmt.Printf("disk %s  created %s  updated %s\n", m.DiskGUID, m.Created.Format(time.RFC3339), m.Updated.Format(time.RFC3339))
	printSummary(m, "", info.FreeBytes)
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	disk := fs.String("disk", "", "quiver stick (disk or image file)")
	expect := fs.String("expect", "", "fail unless the stick's fingerprint equals this value")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	dev, err := openTarget(*disk, blockdev.Options{})
	if err != nil {
		return err
	}
	defer dev.Close()
	pr := newProgress()
	rep, err := pr.env("").Verify(dev)
	if err != nil {
		return err
	}
	if pr.tty && pr.label != "" {
		fmt.Fprintln(os.Stderr)
	}
	for _, p := range rep.Partitions {
		state := "OK"
		if len(p.Problems) > 0 {
			state = fmt.Sprintf("%d PROBLEM(S)", len(p.Problems))
		}
		fmt.Printf("partition %-3d %-38s %6d files  %s\n", p.Slot, p.Name, p.Files, state)
		for _, x := range p.Problems {
			fmt.Printf("    - %s\n", x)
		}
	}
	for _, x := range rep.Problems {
		fmt.Printf("stick: %s\n", x)
	}
	fmt.Printf("fingerprint %s\n", rep.Fingerprint)
	if *expect != "" {
		if !strings.EqualFold(*expect, rep.Fingerprint) {
			return errors.New("fingerprint does NOT match the expected value")
		}
		fmt.Println("fingerprint matches the expected value")
	}
	if !rep.OK() {
		return errors.New("verification failed")
	}
	fmt.Println("verification passed")
	return nil
}

func cmdMenu(args []string) error {
	fs := flag.NewFlagSet("menu", flag.ContinueOnError)
	disk := fs.String("disk", "", "quiver stick (disk or image file)")
	timeout := fs.Int("timeout", -2, "menu timeout in `seconds`; -1 waits for a choice")
	defSlot := fs.Int("default", 0, "partition `slot` to boot when the timeout expires")
	user := fs.String("user", "", "menu superuser `name`")
	pwFile := fs.String("password-file", "", "set the menu password from the first line of `file` (\"-\" reads stdin)")
	pwEnv := fs.String("password-env", "", "set the menu password from environment `variable`")
	noPw := fs.Bool("no-password", false, "remove the menu password")
	repair := fs.Bool("repair", false, "rebuild the menu partition from the image partitions")
	menuFrom := fs.String("menu-from", "", "replace the menu's shim + GRUB with those from this `image`")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	allowFixed := fs.Bool("allow-fixed", false, "allow writing to a non-removable disk")
	var titles multi
	fs.Var(&titles, "title", "`SLOT=TITLE` rename a menu entry (repeatable)")
	pf := &policyFlags{}
	pf.register(fs)
	if _, err := parse(fs, args); err != nil {
		return err
	}
	pol, err := pf.policy()
	if err != nil {
		return err
	}
	o := stick.MenuOptions{Repair: *repair, MenuFrom: *menuFrom, Titles: map[int]string{}, Policy: pol}
	if *timeout != -2 {
		o.Timeout = timeout
	}
	if *defSlot != 0 {
		o.DefaultSlot = defSlot
	}
	if *user != "" {
		if !menu.ValidUser(*user) {
			return errors.New("--user may contain only letters, digits, '_' and '-'")
		}
		o.User = user
	}
	if *noPw {
		empty := ""
		o.PasswordHash = &empty
	} else if pw, err := readPassword(*pwFile, *pwEnv); err != nil {
		return err
	} else if pw != "" {
		h, err := menu.HashPassword(pw)
		if err != nil {
			return err
		}
		o.PasswordHash = &h
	}
	for _, t := range titles {
		k, v, ok := strings.Cut(t, "=")
		if !ok {
			return fmt.Errorf("--title %q: expected SLOT=TITLE", t)
		}
		n, err := slotArg(k)
		if err != nil {
			return err
		}
		o.Titles[n] = v
	}
	dev, err := openTarget(*disk, blockdev.Options{Write: true, AllowFixed: *allowFixed})
	if err != nil {
		return err
	}
	if err := confirm(dev, *yes, "Rewriting the boot menu on"); err != nil {
		dev.Close()
		return err
	}
	pr := newProgress()
	res, err := pr.env("").Menu(dev, o)
	if cerr := dev.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	printSummary(res.Manifest, res.Fingerprint, res.FreeBytes)
	return nil
}

func cmdData(args []string) error {
	fs := flag.NewFlagSet("data", flag.ContinueOnError)
	disk := fs.String("disk", "", "quiver stick (disk or image file)")
	size := fs.String("size", "", "partition `size` (default: the largest free area)")
	label := fs.String("label", "", "exFAT `label`, up to 11 characters (default QUIVER-DATA)")
	remove := fs.Bool("remove", false, "delete the data partition AND ALL FILES ON IT")
	yes := fs.Bool("yes", false, "do not ask for confirmation")
	allowFixed := fs.Bool("allow-fixed", false, "allow writing to a non-removable disk")
	if _, err := parse(fs, args); err != nil {
		return err
	}
	req := stick.DataRequest{Label: *label}
	if *size != "" {
		n, err := parseSize(*size)
		if err != nil {
			return err
		}
		req.Size = n
	}
	dev, err := openTarget(*disk, blockdev.Options{Write: true, AllowFixed: *allowFixed})
	if err != nil {
		return err
	}
	what := "Creating an exFAT data partition on"
	if *remove {
		what = "DELETING the data partition and all its files on"
	}
	if err := confirm(dev, *yes, what); err != nil {
		dev.Close()
		return err
	}
	env := newProgress().env("")
	var res *stick.Result
	if *remove {
		res, err = env.RemoveData(dev)
	} else {
		res, err = env.Data(dev, req)
	}
	if cerr := dev.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	printSummary(res.Manifest, res.Fingerprint, res.FreeBytes)
	return nil
}
