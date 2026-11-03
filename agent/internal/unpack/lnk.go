package unpack

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf16"
)

// Windows shortcuts ([MS-SHLLINK]): a malicious LNK is a command line
// (powershell -enc ..., mshta http://..., cmd /c ...) behind a document
// icon. lnkText returns its target and string data as text lines, which the
// YARA rules then read like a script.

var lnkCLSID = []byte{0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}

func isLNK(b []byte) bool {
	return len(b) >= 0x4C && binary.LittleEndian.Uint32(b) == 0x4C && bytes.Equal(b[4:20], lnkCLSID)
}

const (
	lnkHasIDList   = 1 << 0
	lnkHasLinkInfo = 1 << 1
	lnkHasName     = 1 << 2
	lnkHasRelPath  = 1 << 3
	lnkHasWorkDir  = 1 << 4
	lnkHasArgs     = 1 << 5
	lnkHasIcon     = 1 << 6
	lnkIsUnicode   = 1 << 7
)

func lnkText(b []byte) string {
	if !isLNK(b) {
		return ""
	}
	flags := binary.LittleEndian.Uint32(b[0x14:])
	off := 0x4C
	if flags&lnkHasIDList != 0 {
		if off+2 > len(b) {
			return ""
		}
		off += 2 + int(binary.LittleEndian.Uint16(b[off:]))
	}
	var lines []string
	if flags&lnkHasLinkInfo != 0 {
		if off+28 > len(b) {
			return ""
		}
		size := int(binary.LittleEndian.Uint32(b[off:]))
		if size >= 28 && off+size <= len(b) {
			info := b[off : off+size]
			infoFlags := binary.LittleEndian.Uint32(info[8:])
			if infoFlags&1 != 0 { // VolumeIDAndLocalBasePath
				if p := int(binary.LittleEndian.Uint32(info[16:])); p > 0 && p < len(info) {
					if base := cString(info[p:]); base != "" {
						lines = append(lines, "target: "+base)
					}
				}
			}
		}
		if size < 0 || off+size > len(b) {
			return strings.Join(lines, "\n")
		}
		off += size
	}
	unicode := flags&lnkIsUnicode != 0
	for _, f := range []struct {
		bit  uint32
		name string
	}{{lnkHasName, "name"}, {lnkHasRelPath, "relative_path"}, {lnkHasWorkDir, "working_dir"},
		{lnkHasArgs, "arguments"}, {lnkHasIcon, "icon"}} {
		if flags&f.bit == 0 {
			continue
		}
		if off+2 > len(b) {
			break
		}
		n := int(binary.LittleEndian.Uint16(b[off:]))
		off += 2
		var s string
		if unicode {
			if off+2*n > len(b) {
				break
			}
			u := make([]uint16, n)
			for i := range u {
				u[i] = binary.LittleEndian.Uint16(b[off+2*i:])
			}
			s = string(utf16.Decode(u))
			off += 2 * n
		} else {
			if off+n > len(b) {
				break
			}
			s = string(b[off : off+n])
			off += n
		}
		if s != "" {
			lines = append(lines, f.name+": "+s)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	return "LNK shortcut\n" + strings.Join(lines, "\n") + "\n"
}

func cString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}
