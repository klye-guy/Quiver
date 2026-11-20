package wim

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestSplitWithWimlib builds a WIM with wimlib, splits it with this package,
// and has wimlib verify and extract the resulting spanned set.
func TestSplitWithWimlib(t *testing.T) {
	capture, err := exec.LookPath("wimcapture")
	if err != nil {
		t.Skip("wimlib not installed")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	os.MkdirAll(filepath.Join(src, "sub"), 0o755)
	want := map[string][]byte{}
	for i, n := range []int{3 << 20, 5 << 20, 1 << 20, 7 << 20, 2 << 20, 4<<20 + 3} {
		b := make([]byte, n)
		rand.Read(b)
		name := filepath.Join(src, "f"+string(rune('a'+i))+".bin")
		os.WriteFile(name, b, 0o644)
		want[filepath.Base(name)] = b
	}
	os.WriteFile(filepath.Join(src, "sub", "small.txt"), []byte("small"), 0o644)
	wimPath := filepath.Join(dir, "install.wim")
	if out, err := exec.Command(capture, src, wimPath, "Image One", "--compress=LZX").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	if out, err := exec.Command("wimappend", src, wimPath, "Image Two").CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
	f, _ := os.Open(wimPath)
	st, _ := f.Stat()
	parts, err := Split(f, st.Size(), "install", 8<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) < 3 {
		t.Fatalf("expected several parts, got %d", len(parts))
	}
	for _, p := range parts {
		r, _ := p.Open()
		b, _ := io.ReadAll(r)
		if int64(len(b)) != p.Size || p.Size > 8<<20 {
			t.Fatalf("%s: size %d planned %d", p.Name, len(b), p.Size)
		}
		os.WriteFile(filepath.Join(dir, p.Name), b, 0o644)
	}
	first := filepath.Join(dir, "install.swm")
	ref := "--ref=" + filepath.Join(dir, "install*.swm")
	if out, err := exec.Command("wimverify", first, ref).CombinedOutput(); err != nil {
		t.Fatalf("wimverify: %v\n%s", err, out)
	}
	for _, img := range []string{"1", "2"} {
		dst := filepath.Join(dir, "out"+img)
		if out, err := exec.Command("wimapply", first, img, dst, ref).CombinedOutput(); err != nil {
			t.Fatalf("wimapply: %v\n%s", err, out)
		}
		for name, b := range want {
			got, err := os.ReadFile(filepath.Join(dst, name))
			if err != nil || !bytes.Equal(got, b) {
				t.Fatalf("image %s: %s differs after split/apply", img, name)
			}
		}
	}
}
