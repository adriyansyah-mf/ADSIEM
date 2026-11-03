package unpack

import (
	"encoding/binary"
	"strings"
)

// ISO 9660: the primary volume descriptor at sector 16 holds the root
// directory record; directory records point to extents of 2048-byte
// sectors. Joliet and Rock Ridge names are not read (the 8.3-style ISO
// names are enough to tell an .exe or .lnk); UDF-only images are not
// opened.

const isoSector = 2048

func (s *state) iso(prefix string, data []byte, depth int) {
	pvd := 16 * isoSector
	if len(data) < pvd+190 || data[pvd] != 1 { // type 1: primary volume descriptor
		s.note("iso: no primary volume descriptor")
		return
	}
	root := data[pvd+156 : pvd+156+34]
	seen := map[uint32]bool{}
	s.isoDir(prefix, data, root, "", depth, seen, 0)
}

// isoDir walks the directory whose record is rec.
func (s *state) isoDir(prefix string, data, rec []byte, dir string, depth int, seen map[uint32]bool, level int) {
	lba, size := binary.LittleEndian.Uint32(rec[2:]), binary.LittleEndian.Uint32(rec[10:])
	if level > 16 || seen[lba] {
		return
	}
	seen[lba] = true
	start, end := int64(lba)*isoSector, int64(lba)*isoSector+int64(size)
	if start < 0 || end > int64(len(data)) {
		return
	}
	for off := start; off < end; {
		n := int64(data[off])
		if n == 0 { // records do not cross sectors: skip to the next one
			off = (off/isoSector + 1) * isoSector
			continue
		}
		if n < 34 || off+n > end {
			return
		}
		r := data[off : off+n]
		off += n
		nameLen := int(r[32])
		if 33+nameLen > len(r) {
			continue
		}
		name := string(r[33 : 33+nameLen])
		if nameLen == 1 && (name == "\x00" || name == "\x01") { // . and ..
			continue
		}
		name = strings.TrimSuffix(name, ";1")
		name = strings.TrimSuffix(name, ".")
		path := name
		if dir != "" {
			path = dir + "/" + name
		}
		if r[25]&0x02 != 0 { // directory
			s.isoDir(prefix, data, r, path, depth, seen, level+1)
			continue
		}
		flba, fsize := int64(binary.LittleEndian.Uint32(r[2:])), int64(binary.LittleEndian.Uint32(r[10:]))
		if fsize == 0 {
			continue
		}
		if fsize > s.lim.EntrySize {
			s.note("%s: larger than %d bytes", path, s.lim.EntrySize)
			continue
		}
		fs, fe := flba*isoSector, flba*isoSector+fsize
		if fs < 0 || fe > int64(len(data)) {
			s.note("%s: outside the image", path)
			continue
		}
		if !s.add(prefix, path, "iso", data[fs:fe], depth) {
			return
		}
	}
}
