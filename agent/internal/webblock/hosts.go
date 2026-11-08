package webblock

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
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
// Domains in bare get no www. line (feed entries: a feed lists exact hosts, so
// guessing www. only adds lines); every other domain gets one.
func RenderBlock(domains []string, ipv6 bool, bare map[string]bool) string {
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
	written := make(map[string]bool, 2*len(valid))
	for _, d := range valid {
		names := []string{d}
		if !strings.HasPrefix(d, "www.") && !bare[d] {
			names = append(names, "www."+d)
		}
		for _, n := range names {
			if written[n] {
				continue
			}
			written[n] = true
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
	return (f[0] == SinkV4 || f[0] == SinkV6) && validDomain(f[1])
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
		if markerLine(lines[i]) == BlockEnd {
			// END without BEGIN: remove it and the sink lines above it.
			tampered = true
			hadBlock = true
			for n := len(kept); n > 0 && ourLine(kept[n-1]); n = len(kept) {
				kept = kept[:n-1]
			}
			dropBlank()
			i++
			continue
		}
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
	// Apply writes the block; changed says the file was rewritten, tampered
	// that the markers were found damaged.
	Apply(domains []string, ipv6 bool, bare map[string]bool) (changed, tampered bool, err error)
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
// returns changed when the file was rewritten and tampered when the block was
// found damaged and repaired.
func (h *HostsFile) Apply(domains []string, ipv6 bool, bare map[string]bool) (bool, bool, error) {
	return h.rewrite(RenderBlock(domains, ipv6, bare))
}

// Remove deletes the block; a missing hosts file is not an error.
func (h *HostsFile) Remove() error {
	_, _, err := h.rewrite("")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// rewrite puts block in place of the managed block; changed reports that
// the file was written.
func (h *HostsFile) rewrite(block string) (changed, tampered bool, err error) {
	path, err := filepath.EvalSymlinks(h.Path)
	if err != nil {
		return false, false, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return false, false, err
	}
	content := string(raw)
	out, _, tampered := ReplaceBlock(content, block)
	if out == content {
		return false, tampered, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		return false, tampered, err
	}
	if err := writeHosts(path, []byte(out), st.Mode().Perm()); err != nil {
		return false, tampered, err
	}
	if h.Flush != nil {
		if err := h.Flush(); err != nil {
			slog.Warn("webblock: dns cache flush failed", "error", err)
		}
	}
	return true, tampered, nil
}
