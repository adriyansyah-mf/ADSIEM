package sca

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEvalNoEmptyPasswords(t *testing.T) {
	good := writeTemp(t, "shadow", "root:$6$abc:19000:0:99999:7:::\nuser:$6$def:19000:0:99999:7:::\n")
	if s, _ := evalNoEmptyPasswords(good); s != StatusPass {
		t.Fatalf("expected pass, got %s", s)
	}
	bad := writeTemp(t, "shadow", "root:$6$abc:19000:0:99999:7:::\nguest::19000:0:99999:7:::\n")
	if s, _ := evalNoEmptyPasswords(bad); s != StatusFail {
		t.Fatalf("expected fail, got %s", s)
	}
	if s, _ := evalNoEmptyPasswords("/nonexistent/shadow"); s != StatusNotApplicable {
		t.Fatalf("expected not_applicable for missing file, got %s", s)
	}
}

func TestEvalNoEmptyPasswordsUnreadableIsError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "shadow")
	if err := os.WriteFile(path, []byte("secret"), 0000); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root — permission bits don't block root reads")
	}
	if s, _ := evalNoEmptyPasswords(path); s != StatusError {
		t.Fatalf("expected error for unreadable shadow file, got %s", s)
	}
}

func TestEvalNoDuplicateRootUID(t *testing.T) {
	good := writeTemp(t, "passwd", "root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n")
	if s, _ := evalNoDuplicateRootUID(good); s != StatusPass {
		t.Fatalf("expected pass, got %s", s)
	}
	bad := writeTemp(t, "passwd", "root:x:0:0:root:/root:/bin/bash\nbackdoor:x:0:0::/home/backdoor:/bin/bash\n")
	if s, _ := evalNoDuplicateRootUID(bad); s != StatusFail {
		t.Fatalf("expected fail, got %s", s)
	}
}

func TestEvalNoLegacyServices(t *testing.T) {
	if s, _ := evalNoLegacyServices([]PortInfo{{Port: 22, Proto: "tcp", State: "listen"}}); s != StatusPass {
		t.Fatalf("expected pass, got %s", s)
	}
	if s, _ := evalNoLegacyServices([]PortInfo{{Port: 23, Proto: "tcp", State: "listen"}}); s != StatusFail {
		t.Fatalf("expected fail for listening telnet, got %s", s)
	}
	if s, _ := evalNoLegacyServices([]PortInfo{{Port: 23, Proto: "tcp", State: "closed"}}); s != StatusPass {
		t.Fatalf("expected pass for non-listening legacy port, got %s", s)
	}
}
