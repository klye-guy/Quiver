// Package vfs is the in-memory file tree that every source reader produces
// and the FAT32 builder consumes. File contents are never held in memory for
// large files: each file node carries an Open function that streams its bytes
// from the original source (ISO extents, FAT cluster chains, generated buffers).
package vfs

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"time"
)

// Node is a file, directory or symbolic link.
type Node struct {
	Name     string
	Dir      bool
	Children []*Node
	Size     int64
	Open     func() (io.Reader, error)
	Link     string // non-empty for a symbolic link; the raw target
	MTime    time.Time
	Hidden   bool

	// ReaderAt, when set, gives random access to the file content.
	ReaderAt func() io.ReaderAt

	// Deferred files are written after every other file in the same
	// filesystem. Their Size must be correct at planning time; their content
	// may be produced by Open only once the other files have been written
	// (used for checksum lists that cover everything else).
	Deferred bool
}

// NewDir returns an empty directory node.
func NewDir(name string, mtime time.Time) *Node {
	return &Node{Name: name, Dir: true, MTime: mtime}
}

// Bytes returns a file node backed by an in-memory buffer.
func Bytes(name string, b []byte, mtime time.Time) *Node {
	data := append([]byte(nil), b...)
	return &Node{
		Name:  name,
		Size:  int64(len(data)),
		MTime: mtime,
		Open:  func() (io.Reader, error) { return bytes.NewReader(data), nil },
	}
}

// Child returns the direct child with the given name, compared without case
// (FAT, the target filesystem, is case-insensitive).
func (n *Node) Child(name string) *Node {
	for _, c := range n.Children {
		if strings.EqualFold(c.Name, name) {
			return c
		}
	}
	return nil
}

// Lookup resolves a slash-separated path relative to n, case-insensitively.
func (n *Node) Lookup(p string) *Node {
	cur := n
	for _, part := range strings.Split(strings.Trim(p, "/"), "/") {
		if part == "" {
			continue
		}
		if cur == nil || !cur.Dir {
			return nil
		}
		cur = cur.Child(part)
	}
	return cur
}

// Put adds or replaces a child (matched case-insensitively).
func (n *Node) Put(c *Node) {
	for i, old := range n.Children {
		if strings.EqualFold(old.Name, c.Name) {
			n.Children[i] = c
			return
		}
	}
	n.Children = append(n.Children, c)
}

// Remove deletes a child by name. It reports whether a child was removed.
func (n *Node) Remove(name string) bool {
	for i, c := range n.Children {
		if strings.EqualFold(c.Name, name) {
			n.Children = append(n.Children[:i], n.Children[i+1:]...)
			return true
		}
	}
	return false
}

// MkdirAll returns the directory at p, creating missing components.
func (n *Node) MkdirAll(p string, mtime time.Time) (*Node, error) {
	cur := n
	for _, part := range strings.Split(strings.Trim(p, "/"), "/") {
		if part == "" {
			continue
		}
		next := cur.Child(part)
		if next == nil {
			next = NewDir(part, mtime)
			cur.Children = append(cur.Children, next)
		}
		if !next.Dir {
			return nil, fmt.Errorf("%s: not a directory", part)
		}
		cur = next
	}
	return cur, nil
}

// SortRecursive orders every directory's children by name so that output is
// deterministic regardless of source ordering.
func (n *Node) SortRecursive() {
	if !n.Dir {
		return
	}
	sort.SliceStable(n.Children, func(i, j int) bool {
		a, b := strings.ToUpper(n.Children[i].Name), strings.ToUpper(n.Children[j].Name)
		if a != b {
			return a < b
		}
		return n.Children[i].Name < n.Children[j].Name
	})
	for _, c := range n.Children {
		c.SortRecursive()
	}
}

// WalkFunc is called for each node with its slash-separated path ("/" for the root).
type WalkFunc func(p string, n *Node) error

// SkipDir may be returned by a WalkFunc to skip a directory's children.
var SkipDir = errors.New("skip directory")

// Walk visits n and all descendants in pre-order.
func (n *Node) Walk(fn WalkFunc) error {
	return walk("/", n, fn)
}

func walk(p string, n *Node, fn WalkFunc) error {
	if err := fn(p, n); err != nil {
		if err == SkipDir {
			return nil
		}
		return err
	}
	if !n.Dir {
		return nil
	}
	for _, c := range n.Children {
		if err := walk(path.Join(p, c.Name), c, fn); err != nil {
			return err
		}
	}
	return nil
}

// ReadAll returns the full content of a file node.
func ReadAll(n *Node) ([]byte, error) {
	if n == nil || n.Dir || n.Open == nil {
		return nil, errors.New("not a readable file")
	}
	r, err := n.Open()
	if err != nil {
		return nil, err
	}
	if c, ok := r.(io.Closer); ok {
		defer c.Close()
	}
	b, err := io.ReadAll(io.LimitReader(r, n.Size+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != n.Size {
		return nil, fmt.Errorf("%s: read %d bytes, expected %d", n.Name, len(b), n.Size)
	}
	return b, nil
}

// Extent is a contiguous byte range of an underlying reader.
type Extent struct {
	Off, Len int64
}

// ExtentOpener returns an Open function that streams the given extents of r in
// order. Extents with a negative Off are unrecorded and read as zeros.
func ExtentOpener(r io.ReaderAt, extents []Extent) func() (io.Reader, error) {
	ex := append([]Extent(nil), extents...)
	return func() (io.Reader, error) {
		readers := make([]io.Reader, 0, len(ex))
		for _, e := range ex {
			if e.Off < 0 {
				readers = append(readers, io.LimitReader(zeroReader{}, e.Len))
				continue
			}
			readers = append(readers, io.NewSectionReader(r, e.Off, e.Len))
		}
		return io.MultiReader(readers...), nil
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// Count returns the number of files and directories under n (inclusive).
func (n *Node) Count() (files, dirs int, bytes int64) {
	_ = n.Walk(func(_ string, c *Node) error {
		if c.Dir {
			dirs++
		} else {
			files++
			bytes += c.Size
		}
		return nil
	})
	return
}

// FromExtents builds a file node whose content is the given extents of r.
// The node also exposes random access through ReaderAt.
func FromExtents(name string, r io.ReaderAt, extents []Extent, size int64, mtime time.Time) *Node {
	ex := append([]Extent(nil), extents...)
	return &Node{
		Name:     name,
		Size:     size,
		MTime:    mtime,
		Open:     ExtentOpener(r, ex),
		ReaderAt: func() io.ReaderAt { return &extentReaderAt{r: r, ex: ex, size: size} },
	}
}

type extentReaderAt struct {
	r    io.ReaderAt
	ex   []Extent
	size int64
}

func (e *extentReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	n := 0
	pos := int64(0)
	for _, x := range e.ex {
		if len(p) == 0 {
			break
		}
		if off >= pos+x.Len {
			pos += x.Len
			continue
		}
		within := off - pos
		chunk := x.Len - within
		if chunk > int64(len(p)) {
			chunk = int64(len(p))
		}
		if x.Off < 0 {
			clear(p[:chunk])
		} else if _, err := e.r.ReadAt(p[:chunk], x.Off+within); err != nil && err != io.EOF {
			return n, err
		}
		n += int(chunk)
		p = p[chunk:]
		off += chunk
		pos += x.Len
	}
	if len(p) > 0 {
		return n, io.EOF
	}
	return n, nil
}
