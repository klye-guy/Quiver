package image

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"archavist.com/quiver/internal/vfs"
)

func need(t *testing.T, tools ...string) {
	for _, tool := range tools {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not installed", tool)
		}
	}
}

func run(t *testing.T, name string, args ...string) {
	t.Helper()
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
}

// fakeLoader returns a minimal PE so classification succeeds; signature
// state is irrelevant to these tests.
func fakeLoader(t *testing.T) []byte {
	shim := os.Getenv("QUIVER_TEST_SHIM")
	if shim != "" {
		b, err := os.ReadFile(shim)
		if err == nil {
			return b
		}
	}
	t.Skip("set QUIVER_TEST_SHIM to a PE file")
	return nil
}

// TestWindowsUDF builds a UDF ISO laid out like Windows media, with an
// install.wim above the (test-lowered) split threshold and a file large
// enough to need several UDF allocation descriptors.
func TestWindowsUDF(t *testing.T) {
	need(t, "genisoimage", "wimcapture", "wimverify")
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	payload := filepath.Join(dir, "payload")
	for _, d := range []string{"efi/boot", "efi/microsoft/boot", "sources", "support"} {
		os.MkdirAll(filepath.Join(src, d), 0o755)
	}
	os.MkdirAll(payload, 0o755)
	for i := 0; i < 6; i++ {
		b := make([]byte, 3<<20)
		rand.Read(b)
		os.WriteFile(filepath.Join(payload, "f"+string(rune('a'+i))), b, 0o644)
	}
	run(t, "wimcapture", payload, filepath.Join(src, "sources", "install.wim"), "Windows Test", "--compress=LZX")
	run(t, "wimcapture", payload, filepath.Join(src, "sources", "boot.wim"), "WinPE", "--compress=none")
	os.WriteFile(filepath.Join(src, "efi", "boot", "bootx64.efi"), fakeLoader(t), 0o644)
	os.WriteFile(filepath.Join(src, "efi", "microsoft", "boot", "bcd"), []byte("bcd"), 0o644)
	os.WriteFile(filepath.Join(src, "bootmgr"), []byte("bootmgr"), 0o644)
	big := filepath.Join(src, "support", "big.bin")
	f, _ := os.Create(big)
	f.Truncate(1300 << 20) // > 1 GiB: forces multiple allocation descriptors
	f.WriteAt([]byte("tail-marker"), 1300<<20-11)
	f.Close()
	iso := filepath.Join(dir, "win.iso")
	run(t, "genisoimage", "-quiet", "-udf", "-iso-level", "3", "-V", "CCCOMA_X64FRE_EN-US_DV9", "-o", iso, src)

	old1, old2 := wimSplitAbove, wimPartSize
	wimSplitAbove, wimPartSize = 4<<20, 8<<20
	defer func() { wimSplitAbove, wimPartSize = old1, old2 }()

	s, err := Load(iso, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Format != "udf" || s.Kind != "windows-setup" {
		t.Fatalf("format=%s kind=%s", s.Format, s.Kind)
	}
	// UDF content must match the source byte for byte.
	bn := s.Tree.Lookup("/support/big.bin")
	if bn == nil || bn.Size != 1300<<20 {
		t.Fatalf("big.bin missing or wrong size")
	}
	tail := make([]byte, 11)
	bn.ReaderAt().ReadAt(tail, 1300<<20-11)
	if string(tail) != "tail-marker" {
		t.Fatalf("UDF multi-extent read wrong: %q", tail)
	}
	if err := s.Prepare(0x1234ABCD); err != nil {
		t.Fatal(err)
	}
	srcDir := s.Tree.Lookup("/sources")
	var names []string
	for _, c := range srcDir.Children {
		names = append(names, c.Name)
	}
	joined := strings.Join(names, ",")
	if strings.Contains(joined, "install.wim") || !strings.Contains(joined, "install.swm") || !strings.Contains(joined, "install2.swm") {
		t.Fatalf("expected split parts, got %s", joined)
	}
	out := filepath.Join(dir, "out")
	os.MkdirAll(out, 0o755)
	for _, c := range srcDir.Children {
		b, err := vfs.ReadAll(c)
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(out, c.Name), b, 0o644)
	}
	run(t, "wimverify", filepath.Join(out, "install.swm"), "--ref="+filepath.Join(out, "install*.swm"))
}

// TestElToritoOnlyEFI: the EFI loader exists only inside the El Torito
// FAT image, not in the ISO 9660 tree.
func TestElToritoOnlyEFI(t *testing.T) {
	need(t, "xorriso", "mkfs.vfat", "mmd", "mcopy")
	dir := t.TempDir()
	loader := fakeLoader(t)
	lp := filepath.Join(dir, "BOOTX64.EFI")
	os.WriteFile(lp, loader, 0o644)
	img := filepath.Join(dir, "efiboot.img")
	run(t, "mkfs.vfat", "-C", img, "4096")
	run(t, "mmd", "-i", img, "::/EFI", "::/EFI/BOOT")
	run(t, "mcopy", "-i", img, lp, "::/EFI/BOOT/BOOTX64.EFI")
	src := filepath.Join(dir, "src")
	os.MkdirAll(filepath.Join(src, "boot"), 0o755)
	os.WriteFile(filepath.Join(src, "boot", "kernel"), []byte("kernel"), 0o644)
	b, _ := os.ReadFile(img)
	os.WriteFile(filepath.Join(src, "boot", "efiboot.img"), b, 0o644)
	iso := filepath.Join(dir, "et.iso")
	run(t, "xorriso", "-as", "mkisofs", "-quiet", "-R", "-J", "-V", "ETONLY", "-e", "boot/efiboot.img", "-no-emul-boot", "-o", iso, src)
	s, err := Load(iso, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	n := s.Tree.Lookup(LoaderPath)
	if n == nil {
		t.Fatal("loader not merged from El Torito image")
	}
	got, _ := vfs.ReadAll(n)
	if sha256.Sum256(got) != sha256.Sum256(loader) || !bytes.Equal(got[:2], []byte("MZ")) {
		t.Fatal("merged loader content differs")
	}
	if len(s.Fixups) == 0 {
		t.Fatal("merge not recorded as a fixup")
	}
}
