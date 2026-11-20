package fat

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"archavist.com/quiver/internal/vfs"
)

func sampleTree() (*vfs.Node, map[string][]byte) {
	mt := time.Date(2024, 5, 6, 7, 8, 10, 0, time.UTC)
	root := vfs.NewDir("", mt)
	want := map[string][]byte{}
	add := func(p string, b []byte) {
		dir, _ := root.MkdirAll(filepath.Dir(p), mt)
		dir.Children = append(dir.Children, vfs.Bytes(filepath.Base(p), b, mt))
		want[p] = b
	}
	add("/EFI/BOOT/BOOTX64.EFI", bytes.Repeat([]byte("MZ"), 40000))
	add("/EFI/BOOT/grubx64.efi", bytes.Repeat([]byte{1, 2, 3}, 100000))
	add("/boot/grub/grub.cfg", []byte("menuentry x {}\n"))
	add("/.disk/info", []byte("Ubuntu 24.04"))
	add("/empty.txt", nil)
	add("/A Very Long File Name With Spaces and Ünïcödé.txt", []byte("hello"))
	add("/casper/filesystem.squashfs", bytes.Repeat([]byte{0xAB}, 3<<20+17))
	for i := 0; i < 300; i++ { // force multi-cluster directory and many ~N tails
		add(fmt.Sprintf("/pool/main/package-with-long-name-%03d.deb", i), []byte(fmt.Sprint(i)))
	}
	add("/deep/a/b/c/d/e/f/g/h/i/j/k/file", []byte("deep"))
	root.SortRecursive()
	return root, want
}

func TestBuildAndReadBack(t *testing.T) {
	for _, ss := range []int{512, 4096} {
		t.Run(fmt.Sprint(ss), func(t *testing.T) {
			root, want := sampleTree()
			plan, err := PlanFS(root, Options{SectorSize: ss, Label: "Test Vol", VolumeID: 0x1234ABCD, HiddenSectors: 2048})
			if err != nil {
				t.Fatal(err)
			}
			img := filepath.Join(t.TempDir(), "fs.img")
			f, err := os.Create(img)
			if err != nil {
				t.Fatal(err)
			}
			if err := f.Truncate(plan.TotalBytes()); err != nil {
				t.Fatal(err)
			}
			got := map[string][32]byte{}
			if err := plan.Write(f, 0, Hooks{File: func(p string, _ int64, s [32]byte) { got[p] = s }}); err != nil {
				t.Fatal(err)
			}
			f.Close()
			for p, b := range want {
				if got[p] != sha256.Sum256(b) {
					t.Errorf("hook digest mismatch for %s", p)
				}
			}
			if fsck, err := exec.LookPath("fsck.fat"); err == nil {
				out, err := exec.Command(fsck, "-n", "-V", img).CombinedOutput()
				if err != nil {
					t.Fatalf("fsck.fat failed: %v\n%s", err, out)
				}
			}
			rf, _ := os.Open(img)
			defer rf.Close()
			r, err := Open(rf, 0)
			if err != nil {
				t.Fatal(err)
			}
			if r.Bits() != 32 || r.VolumeID != 0x1234ABCD || r.Label != "TEST VOL" {
				t.Fatalf("bits=%d id=%x label=%q", r.Bits(), r.VolumeID, r.Label)
			}
			tree, err := r.Tree()
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			err = tree.Walk(func(p string, nd *vfs.Node) error {
				if nd.Dir {
					return nil
				}
				n++
				b, err := vfs.ReadAll(nd)
				if err != nil {
					return err
				}
				if !bytes.Equal(b, want[p]) {
					return fmt.Errorf("content mismatch for %s", p)
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if n != len(want) {
				t.Fatalf("read %d files, want %d", n, len(want))
			}
		})
	}
}

func TestSFN(t *testing.T) {
	used := map[[11]byte]bool{}
	cases := []struct {
		in, want string
		exact    bool
	}{
		{"BOOTX64.EFI", "BOOTX64 EFI", true},
		{"grubx64.efi", "GRUBX64 EFI", false},
		{".disk", "DISK~1     ", false},
		{"filesystem.squashfs", "FILESY~1SQU", false},
		{"filesystem.size", "FILESY~1SIZ", false},
		{"filesystem.manifest", "FILESY~1MAN", false},
		{"filesystem.manifest-remove", "FILESY~2MAN", false},
	}
	for _, c := range cases {
		s, exact := makeSFN(c.in, used)
		used[s] = true
		if string(s[:]) != c.want || exact != c.exact {
			t.Errorf("%s: got %q exact=%v, want %q exact=%v", c.in, s, exact, c.want, c.exact)
		}
	}
}
