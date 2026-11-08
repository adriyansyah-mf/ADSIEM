package webblock

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
)

// Markers around the block the agent manages in the hosts file. Lines outside
// the markers are never changed.
const (
	BlockBegin = "# BEGIN ADSIEM WEBBLOCK"
	BlockEnd   = "# END ADSIEM WEBBLOCK"
)

// Sink addresses blocked domains resolve to; the page server listens there.
const (
	SinkV4 = "127.84.0.1"
	SinkV6 = "::1"
)

// domainRe is what the agent accepts from the server. Anything else (spaces,
// newlines, comments, uppercase) is dropped so the list can never inject
// extra lines into the hosts file.
var domainRe = regexp.MustCompile(`^[a-z0-9-]+(\.[a-z0-9-]+)+$`)

func validDomain(d string) bool { return len(d) <= 253 && domainRe.MatchString(d) }

// RenderBlock renders the managed block with LF line endings, or "" when no
// domain is valid. Invalid domains are skipped and logged once per call.
func RenderBlock(domains []string, ipv6 bool) string {
	seen := make(map[string]bool, len(domains))
	valid := make([]string, 0, len(domains))
	skipped := 0
	for _, d := range domains {
		if !validDomain(d) {
			skipped++
			continue
		}
		if !seen[d] {
			seen[d] = true
			valid = append(valid, d)
		}
	}
	if skipped > 0 {
		slog.Warn("webblock: skipped invalid domains", "count", skipped)
	}
	if len(valid) == 0 {
		return ""
	}
	sort.Strings(valid)
	var b strings.Builder
	b.WriteString(BlockBegin + "\n")
	for _, d := range valid {
		names := []string{d}
		if !strings.HasPrefix(d, "www.") {
			names = append(names, "www."+d)
		}
		for _, n := range names {
			b.WriteString(SinkV4 + " " + n + "\n")
			if ipv6 {
				b.WriteString(SinkV6 + " " + n + "\n")
			}
		}
	}
	b.WriteString(BlockEnd + "\n")
	return b.String()
}

func markerLine(line string) string { return strings.TrimRight(line, " \t\r\n") }

func blankLine(line string) bool { return strings.TrimRight(line, "\r\n") == "" }

// ourLine reports whether a line looks like one this package writes, used to
// clean up after a BEGIN marker that lost its END.
func ourLine(line string) bool {
	f := strings.Fields(line)
	if len(f) != 2 {
		return false
	}
	switch f[0] {
	case SinkV4:
		return true
	case SinkV6:
		return f[1] != "localhost" && !strings.HasPrefix(f[1], "ip6-")
	}
	return false
}

// ReplaceBlock removes every managed block from content and, when block is
// not empty, appends it at the end after one blank line. Foreign lines and
// the file's line endings are kept byte for byte. hadBlock reports that a
// block existed; tampered that a BEGIN had no END or there was more than one
// block.
func ReplaceBlock(content, block string) (out string, hadBlock bool, tampered bool) {
	eol := "\n"
	if strings.Contains(content, "\r\n") {
		eol = "\r\n"
	}
	var lines []string
	if content != "" {
		lines = strings.SplitAfter(content, "\n")
		if lines[len(lines)-1] == "" {
			lines = lines[:len(lines)-1]
		}
	}
	kept := make([]string, 0, len(lines))
	dropBlank := func() {
		if n := len(kept); n > 0 && blankLine(kept[n-1]) {
			kept = kept[:n-1]
		}
	}
	blocks := 0
	for i := 0; i < len(lines); {
		if markerLine(lines[i]) != BlockBegin {
			kept = append(kept, lines[i])
			i++
			continue
		}
		blocks++
		hadBlock = true
		dropBlank()
		j := i + 1
		closed := false
		for ; j < len(lines); j++ {
			m := markerLine(lines[j])
			if m == BlockEnd {
				closed = true
				j++
				break
			}
			if m == BlockBegin {
				break
			}
		}
		if closed {
			i = j
			continue
		}
		// BEGIN without END: drop the marker and the sink lines directly
		// after it, keep everything else.
		tampered = true
		i++
		for i < len(lines) && ourLine(lines[i]) {
			i++
		}
	}
	if blocks > 1 {
		tampered = true
	}
	if block != "" {
		if n := len(kept); n > 0 && !strings.HasSuffix(kept[n-1], "\n") {
			kept[n-1] += eol
		}
		if len(kept) > 0 {
			kept = append(kept, eol)
		}
		block = strings.ReplaceAll(strings.ReplaceAll(block, "\r\n", "\n"), "\n", eol)
		kept = append(kept, block)
	}
	return strings.Join(kept, ""), hadBlock, tampered
}

// Hosts manages the block in the system hosts file.
type Hosts interface {
	Apply(domains []string, ipv6 bool) (tampered bool, err error)
	Remove() error
}

// HostsFile implements Hosts on a hosts file. Flush clears the OS DNS cache
// after a real write.
type HostsFile struct {
	Path  string
	Flush func() error
}

// NewHostsFile returns the hosts file of this OS.
func NewHostsFile() *HostsFile {
	return &HostsFile{Path: defaultHostsPath(), Flush: flushDNSCache}
}

// Apply writes the block for domains (removes it when none are valid). It
// returns tampered when the block was found damaged and repaired.
func (h *HostsFile) Apply(domains []string, ipv6 bool) (bool, error) {
	return h.rewrite(RenderBlock(domains, ipv6))
}

// Remove deletes the block; a missing hosts file is not an error.
func (h *HostsFile) Remove() error {
	_, err := h.rewrite("")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (h *HostsFile) rewrite(block string) (bool, error) {
	raw, err := os.ReadFile(h.Path)
	if err != nil {
		return false, err
	}
	content := string(raw)
	out, _, tampered := ReplaceBlock(content, block)
	if out == content {
		return tampered, nil
	}
	st, err := os.Stat(h.Path)
	if err != nil {
		return tampered, err
	}
	if err := writeAtomic(h.Path, []byte(out), st.Mode().Perm()); err != nil {
		return tampered, err
	}
	if h.Flush != nil {
		if err := h.Flush(); err != nil {
			slog.Warn("webblock: dns cache flush failed", "error", err)
		}
	}
	return tampered, nil
}

// writeAtomic writes path+".adsiem.tmp" next to path, syncs it and renames it
// over path.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".adsiem.tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(mode)
	}
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = replaceFile(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
