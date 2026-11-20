package stick

import (
	"errors"
	"fmt"
	"strings"

	"archavist.com/quiver/internal/blockdev"
	"archavist.com/quiver/internal/exfat"
	"archavist.com/quiver/internal/gpt"
	"archavist.com/quiver/internal/image"
)

// DataRequest asks for a shared exFAT storage partition.
type DataRequest struct {
	Size  int64  // bytes; 0 = all of the chosen free area
	Label string // exFAT label, up to 11 characters (default QUIVER-DATA)
}

const defaultDataLabel = "QUIVER-DATA"

// placeData chooses where the data partition goes inside a free span. A
// sized partition sits at the end of the span so the space before it stays
// available for future images.
func placeData(span gpt.FreeSpan, size int64, ss int, align uint64) (first, last uint64, err error) {
	avail := span.Last - span.First + 1
	if size == 0 {
		if avail < 16*align {
			return 0, 0, errors.New("less than 16 MiB free for a data partition")
		}
		return span.First, span.Last, nil
	}
	n := roundUp(uint64(size)/uint64(ss), align)
	if n > avail {
		return 0, 0, fmt.Errorf("data partition of %.2f GiB does not fit in %.2f GiB of free space",
			gib(int64(n)*int64(ss)), gib(int64(avail)*int64(ss)))
	}
	return span.Last + 1 - n, span.Last, nil
}

func validDataLabel(l string) (string, error) {
	if l == "" {
		return defaultDataLabel, nil
	}
	if len([]rune(l)) > 11 {
		return "", errors.New("data partition label is limited to 11 characters")
	}
	if strings.ContainsAny(l, `"*/:<>?\|`) {
		return "", errors.New(`data partition label may not contain " * / : < > ? \ |`)
	}
	return l, nil
}

// dataInfo describes the data partition that formatData will create.
func dataInfo(p gpt.Partition, label string, g ids, ss int) (*DataInfo, uint32) {
	serial := g.volID(fmt.Sprintf("data-%d", p.Slot+1))
	return &DataInfo{Slot: p.Slot + 1, PartitionGUID: p.GUID.String(), Filesystem: "exfat",
		Label: label, Serial: image.FSUUID(serial), Bytes: p.Bytes(ss)}, serial
}

// formatData writes an empty exFAT filesystem into p.
func (e *Env) formatData(dev blockdev.Device, p gpt.Partition, label string, serial uint32) error {
	ss := dev.SectorSize()
	e.logf("formatting %.2f GiB exFAT data partition %d", gib(p.Bytes(ss)), p.Slot+1)
	if _, err := exfat.Format(dev, int64(p.First)*int64(ss), p.Bytes(ss), exfat.Options{
		SectorSize: ss, Label: label, Serial: serial, PartitionLBA: p.First,
	}); err != nil {
		return fmt.Errorf("formatting data partition: %w", err)
	}
	return nil
}

// Data creates the shared-storage partition on an existing stick, in the
// largest free area.
func (e *Env) Data(dev blockdev.Device, req DataRequest) (*Result, error) {
	st, err := e.open(dev)
	if err != nil {
		return nil, err
	}
	if err := st.requireHealthy(); err != nil {
		return nil, err
	}
	if st.manifest.Data != nil {
		return nil, fmt.Errorf("this stick already has a data partition (partition %d)", st.manifest.Data.Slot)
	}
	label, err := validDataLabel(req.Label)
	if err != nil {
		return nil, err
	}
	var best gpt.FreeSpan
	for _, f := range st.tab.Free() {
		if f.Last-f.First > best.Last-best.First {
			best = f
		}
	}
	if best.Last == 0 {
		return nil, errors.New("no free space on the stick")
	}
	first, last, err := placeData(best, req.Size, dev.SectorSize(), st.tab.AlignLBA())
	if err != nil {
		return nil, err
	}
	g := e.ids()
	idx := st.tab.NextSlot()
	if idx < 0 {
		return nil, errors.New("partition table is full")
	}
	p := gpt.Partition{Slot: idx, Type: gpt.TypeBasicData, GUID: g.guid(fmt.Sprintf("part-%d", idx+1)),
		Name: dataPartName, First: first, Last: last}
	info, serial := dataInfo(p, label, g, dev.SectorSize())
	if err := e.formatData(dev, p, label, serial); err != nil {
		return nil, err
	}
	st.tab.Parts = append(st.tab.Parts, p)
	if err := st.tab.Write(dev); err != nil {
		return nil, err
	}
	st.manifest.Data = info
	fp, err := e.rewriteMenu(dev, st)
	if err != nil {
		return nil, err
	}
	return &Result{Manifest: st.manifest, Fingerprint: fp, FreeBytes: freeBytes(st.tab)}, nil
}
