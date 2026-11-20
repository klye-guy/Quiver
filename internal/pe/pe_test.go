package pe

import (
	"os"
	"testing"
)

// Set QUIVER_TEST_SHIM to a Microsoft-signed shim (e.g. Ubuntu's
// /usr/lib/shim/shimx64.efi.signed.latest).
func TestSignedAndTampered(t *testing.T) {
	p := os.Getenv("QUIVER_TEST_SHIM")
	if p == "" {
		t.Skip("QUIVER_TEST_SHIM not set")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	info, err := Inspect(b)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Signed() || !info.IsShim || info.Machine != "x64" {
		t.Fatalf("expected a valid signed x64 shim: %+v", info)
	}
	b[len(b)/3] ^= 0xFF // flip a byte inside the image
	info, err = Inspect(b)
	if err != nil {
		t.Fatal(err)
	}
	if info.Signed() {
		t.Fatal("tampered image still reported as validly signed")
	}
}
