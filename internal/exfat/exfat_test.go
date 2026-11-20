package exfat

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestFormatFsck(t *testing.T) {
	fsck, err := exec.LookPath("fsck.exfat")
	if err != nil {
		t.Skip("exfatprogs not installed")
	}
	for _, c := range []struct {
		size int64
		ss   int
	}{{64 << 20, 512}, {700 << 20, 512}, {40 << 30, 512}, {300 << 20, 4096}} {
		p := filepath.Join(t.TempDir(), "x.img")
		f, _ := os.Create(p)
		f.Truncate(c.size)
		l, err := Format(f, 0, c.size, Options{SectorSize: c.ss, Label: "QUIVER-DATA", Serial: 0xDEADBEEF})
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		out, err := exec.Command(fsck, "-n", p).CombinedOutput()
		if err != nil || !strings.Contains(string(out), "clean") {
			t.Fatalf("size %d ss %d: fsck.exfat: %v\n%s", c.size, c.ss, err, out)
		}
		if dump, err := exec.LookPath("dump.exfat"); err == nil && c.ss == 512 {
			out, _ := exec.Command(dump, p).CombinedOutput()
			if !strings.Contains(string(out), "QUIVER-DATA") {
				t.Fatalf("label not found:\n%s", out)
			}
		}
		rf, _ := os.Open(p)
		serial, size, err := Probe(rf, 0)
		rf.Close()
		if err != nil || serial != 0xDEADBEEF || size != c.size/int64(c.ss)*int64(c.ss) {
			t.Fatalf("probe: %x %d %v", serial, size, err)
		}
		t.Logf("%d MiB: cluster %d, %d clusters", c.size>>20, l.ClusterSize, l.ClusterCount)
	}
}
