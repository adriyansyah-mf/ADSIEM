package agent_test

import (
	"testing"

	"github.com/siem-platform/agent/internal/tailer"
)

func TestDecodeAcceptsCurrentAndLegacyEntries(t *testing.T) {
	cases := []struct {
		entry, logType, location, raw string
	}{
		// current: logType \x00 location \x00 line
		{"linux_auth\x00/var/log/secure\x00sshd[1]: Failed password for root", "linux_auth", "/var/log/secure", "sshd[1]: Failed password for root"},
		// buffered by an older agent before the upgrade: logType \x00 line
		{"syslog\x00kernel: hello", "syslog", "", "kernel: hello"},
		// no separator at all
		{"just a line", "unknown", "", "just a line"},
	}
	for _, c := range cases {
		lt, loc, raw := tailer.Decode(c.entry)
		if lt != c.logType || loc != c.location || raw != c.raw {
			t.Errorf("Decode(%q) = (%q, %q, %q), want (%q, %q, %q)", c.entry, lt, loc, raw, c.logType, c.location, c.raw)
		}
	}
}
