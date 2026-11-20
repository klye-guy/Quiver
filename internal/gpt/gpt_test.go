package gpt

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTripAndSgdisk(t *testing.T) {
	for _, ss := range []int{512, 4096} {
		size := int64(256 << 20)
		tab := &Table{SectorSize: ss, TotalSectors: uint64(size / int64(ss)), DiskGUID: RandomGUID()}
		a := tab.AlignLBA()
		tab.Parts = []Partition{
			{Slot: 0, Type: TypeESP, GUID: RandomGUID(), First: a, Last: 65*a - 1, Name: "QUIVER MENU"},
			{Slot: 1, Type: TypeBasicData, GUID: RandomGUID(), First: 65 * a, Last: 129*a - 1, Name: "QV Ubuntu 24.04"},
		}
		p := filepath.Join(t.TempDir(), "d.img")
		f, _ := os.Create(p)
		f.Truncate(size)
		if err := tab.Write(f); err != nil {
			t.Fatal(err)
		}
		back, err := Read(f, ss, size)
		if err != nil {
			t.Fatal(err)
		}
		if len(back.Parts) != 2 || back.Parts[1].Name != "QV Ubuntu 24.04" || back.DiskGUID != tab.DiskGUID {
			t.Fatalf("round trip mismatch: %+v", back.Parts)
		}
		free := back.Free()
		if len(free) != 1 || free[0].First != 129*a {
			t.Fatalf("free = %+v", free)
		}
		// corrupt primary header: backup must be used
		f.WriteAt(make([]byte, ss), int64(ss))
		if _, err := Read(f, ss, size); err != nil {
			t.Fatalf("backup fallback failed: %v", err)
		}
		f.Close()
		if ss == 512 {
			if sg, err := exec.LookPath("sgdisk"); err == nil {
				tab.Write(mustOpen(t, p))
				out, err := exec.Command(sg, "-v", p).CombinedOutput()
				if err != nil || !strings.Contains(string(out), "No problems found") {
					t.Fatalf("sgdisk -v: %v\n%s", err, out)
				}
			}
		}
	}
	if g := MustGUID("C12A7328-F81F-11D2-BA4B-00A0C93EC93B"); g.String() != "C12A7328-F81F-11D2-BA4B-00A0C93EC93B" {
		t.Fatalf("GUID string %s", g)
	}
}

func mustOpen(t *testing.T, p string) *os.File {
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
