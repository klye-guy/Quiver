//go:build !linux && !windows

package blockdev

import "errors"

// Open supports only image files on this platform.
func Open(path string, o Options) (Device, error) { return openFile(path, o) }

// List is unsupported on this platform.
func List(all bool) ([]Disk, error) {
	return nil, errors.New("disk listing is only supported on Linux and Windows; write to an image file instead")
}
