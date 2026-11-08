//go:build linux

package webblock

import (
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
)

type fakeRedirect struct {
	mu       sync.Mutex
	applied  [][2]int
	removed  int
	applyErr error
}

func (f *fakeRedirect) Apply(h, s int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied = append(f.applied, [2]int{h, s})
	return f.applyErr
}

func (f *fakeRedirect) Remove() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed++
	return nil
}

func TestNftScript(t *testing.T) {
	want := "add table ip adsiem_webblock\n" +
		"flush table ip adsiem_webblock\n" +
		"table ip adsiem_webblock {\n" +
		"\tchain output {\n" +
		"\t\ttype nat hook output priority -100; policy accept;\n" +
		"\t\tip daddr 127.84.0.1 tcp dport 80 redirect to :40001\n" +
		"\t\tip daddr 127.84.0.1 tcp dport 443 redirect to :40002\n" +
		"\t}\n}\n"
	if got := nftApplyScript(40001, 40002); got != want {
		t.Fatalf("script\n%s\nwant\n%s", got, want)
	}
	if got := nftApplyScript(40001, 0); strings.Contains(got, "dport 443") {
		t.Fatalf("443 rule without a port:\n%s", got)
	}
	if got := nftRemoveScript(); got != "add table ip adsiem_webblock\ndelete table ip adsiem_webblock\n" {
		t.Fatalf("remove script %q", got)
	}
}

type cmdCall struct {
	path, stdin string
	args        []string
}

// fakeCmds records the commands; fail decides which ones fail.
func fakeCmds(t *testing.T, fail func(args []string) bool) *[]cmdCall {
	t.Helper()
	old := cmdRun
	t.Cleanup(func() { cmdRun = old })
	calls := &[]cmdCall{}
	cmdRun = func(path, stdin string, args ...string) (string, error) {
		*calls = append(*calls, cmdCall{path, stdin, args})
		if fail != nil && fail(args) {
			return "", errors.New("exit 1")
		}
		return "", nil
	}
	return calls
}

func argLists(calls []cmdCall) []string {
	var out []string
	for _, c := range calls {
		out = append(out, strings.Join(c.args, " "))
	}
	return out
}

func TestNftApplyRemoveUseStdin(t *testing.T) {
	calls := fakeCmds(t, nil)
	n := nftRedirect{path: "/usr/sbin/nft"}
	if err := n.Apply(1, 2); err != nil {
		t.Fatal(err)
	}
	if err := n.Remove(); err != nil {
		t.Fatal(err)
	}
	c := *calls
	if len(c) != 2 || c[0].path != "/usr/sbin/nft" || !reflect.DeepEqual(c[0].args, []string{"-f", "-"}) ||
		c[0].stdin != nftApplyScript(1, 2) || c[1].stdin != nftRemoveScript() {
		t.Fatalf("calls %+v", c)
	}
}

func TestIptablesApplyFresh(t *testing.T) {
	// chain and jump missing: -S and -C fail
	calls := fakeCmds(t, func(a []string) bool { return a[3] == "-S" || a[3] == "-C" })
	if err := (iptRedirect{path: "/usr/sbin/iptables"}).Apply(40001, 40002); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-w -t nat -S ADSIEM_WEBBLOCK",
		"-w -t nat -N ADSIEM_WEBBLOCK",
		"-w -t nat -F ADSIEM_WEBBLOCK",
		"-w -t nat -A ADSIEM_WEBBLOCK -p tcp --dport 80 -j REDIRECT --to-ports 40001",
		"-w -t nat -A ADSIEM_WEBBLOCK -p tcp --dport 443 -j REDIRECT --to-ports 40002",
		"-w -t nat -C OUTPUT -d 127.84.0.1/32 -p tcp -j ADSIEM_WEBBLOCK",
		"-w -t nat -I OUTPUT 1 -d 127.84.0.1/32 -p tcp -j ADSIEM_WEBBLOCK",
	}
	if got := argLists(*calls); !reflect.DeepEqual(got, want) {
		t.Fatalf("args\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, c := range *calls {
		if c.path != "/usr/sbin/iptables" {
			t.Fatalf("path %q", c.path)
		}
	}
}

func TestIptablesApplyIdempotent(t *testing.T) {
	calls := fakeCmds(t, nil) // chain and jump exist
	if err := (iptRedirect{path: "/sbin/iptables"}).Apply(5, 6); err != nil {
		t.Fatal(err)
	}
	for _, a := range argLists(*calls) {
		if strings.Contains(a, " -N ") || strings.Contains(a, " -I OUTPUT") {
			t.Fatalf("re-created what exists: %s", a)
		}
	}
}

func TestIptablesRemove(t *testing.T) {
	checks := 0
	calls := fakeCmds(t, func(a []string) bool {
		if a[3] == "-C" {
			checks++
			return checks > 1 // the jump is there once
		}
		return false
	})
	if err := (iptRedirect{path: "/sbin/iptables"}).Remove(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"-w -t nat -S ADSIEM_WEBBLOCK",
		"-w -t nat -C OUTPUT -d 127.84.0.1/32 -p tcp -j ADSIEM_WEBBLOCK",
		"-w -t nat -D OUTPUT -d 127.84.0.1/32 -p tcp -j ADSIEM_WEBBLOCK",
		"-w -t nat -C OUTPUT -d 127.84.0.1/32 -p tcp -j ADSIEM_WEBBLOCK",
		"-w -t nat -F ADSIEM_WEBBLOCK",
		"-w -t nat -X ADSIEM_WEBBLOCK",
	}
	if got := argLists(*calls); !reflect.DeepEqual(got, want) {
		t.Fatalf("args\n%s", strings.Join(got, "\n"))
	}
	// no chain: nothing to do
	calls2 := fakeCmds(t, func(a []string) bool { return a[3] == "-S" })
	if err := (iptRedirect{path: "/sbin/iptables"}).Remove(); err != nil || len(*calls2) != 1 {
		t.Fatalf("err %v calls %v", err, argLists(*calls2))
	}
}

func TestDetectRedirectPrefersNft(t *testing.T) {
	old := redirectLookPath
	t.Cleanup(func() { redirectLookPath = old })
	fakeCmds(t, nil)
	redirectLookPath = func(n string) (string, error) { return "/abs/" + n, nil }
	if r, ok := detectRedirect().(nftRedirect); !ok || r.path != "/abs/nft" {
		t.Fatalf("got %#v", detectRedirect())
	}
	redirectLookPath = func(n string) (string, error) {
		if n == "iptables" {
			return "/abs/iptables", nil
		}
		return "", errors.New("missing")
	}
	if r, ok := detectRedirect().(iptRedirect); !ok || r.path != "/abs/iptables" {
		t.Fatalf("got %#v", detectRedirect())
	}
	redirectLookPath = func(string) (string, error) { return "", errors.New("missing") }
	if r := detectRedirect(); r != nil {
		t.Fatalf("got %#v", r)
	}
}

const procSample = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1002 1 0000000000000000 100 0 0 10 0
   2: 0100547F:01BB 0100007F:9C40 01 00000000:00000000 00:00000000 00000000     0        0 1003 1 0000000000000000 20 4 30 10 -1
`

func TestListeningParser(t *testing.T) {
	any4, sink := "00000000", hexAddr(net.ParseIP(SinkV4).To4())
	if sink != "0100547F" {
		t.Fatalf("sink hex %s", sink)
	}
	for _, tc := range []struct {
		port int
		want bool
	}{
		{80, true},    // 0.0.0.0:80 LISTEN
		{8080, false}, // listening, but on 127.0.0.1 only
		{443, false},  // 127.84.0.1:443 is an ESTABLISHED socket, not LISTEN
	} {
		if got := listening(strings.NewReader(procSample), tc.port, any4, sink); got != tc.want {
			t.Errorf("port %d: got %v want %v", tc.port, got, tc.want)
		}
	}
	v6 := "  sl  local_address                         remote_address                        st\n" +
		"   0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A 0 0 0 0 0 1\n"
	if !listening(strings.NewReader(v6), 443, strings.Repeat("0", 32)) {
		t.Fatal("[::]:443 not seen")
	}
}

func TestPortInUseReadsProc(t *testing.T) {
	d := t.TempDir()
	o4, o6 := procTCP, procTCP6
	t.Cleanup(func() { procTCP, procTCP6 = o4, o6 })
	procTCP, procTCP6 = filepath.Join(d, "tcp"), filepath.Join(d, "tcp6")
	os.WriteFile(procTCP, []byte(procSample), 0o644)
	if !portInUse(80) || portInUse(443) {
		t.Fatal("tcp")
	}
	os.WriteFile(procTCP6, []byte("x\n 0: 00000000000000000000000000000000:01BB 00000000000000000000000000000000:0000 0A\n"), 0o644)
	if !portInUse(443) {
		t.Fatal("tcp6")
	}
}

// With a redirect backend the default plan binds only high ports on
// 127.0.0.1, never 80/443 and never [::1].
func TestStartWithRedirectNeverBindsPrivilegedPorts(t *testing.T) {
	r := &fakeRedirect{}
	c := &captured{}
	s := &Server{Push: c.push, Hostname: "WS-1", Redirect: r}
	ca := testCA(t)
	v6, status := s.Start(testPage, "sec", testLookup, ca)
	if status != "ok" || v6 {
		t.Fatalf("status %q v6 %v", status, v6)
	}
	b := s.Bound()
	if b.HTTP6 != "" || b.HTTPS6 != "" {
		t.Fatalf("[::1] listeners on Linux: %+v", b)
	}
	ports := map[string]int{}
	for name, a := range map[string]string{"http": b.HTTP4, "https": b.HTTPS4} {
		host, p, err := net.SplitHostPort(a)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := strconv.Atoi(p)
		if host != "127.0.0.1" || n < 1024 {
			t.Fatalf("%s bound %s", name, a)
		}
		ports[name] = n
	}
	if len(r.applied) != 1 || r.applied[0] != [2]int{ports["http"], ports["https"]} {
		t.Fatalf("redirect applied %v, ports %v", r.applied, ports)
	}
	resp, err := http.Get("http://" + b.HTTP4)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	// a page swap keeps the listeners and re-applies the same ports
	s.Start("<i>{{domain}}</i>", "c", testLookup, ca)
	if len(r.applied) != 2 || r.applied[1] != r.applied[0] || s.Bound() != b {
		t.Fatalf("applied %v bound %+v", r.applied, s.Bound())
	}
	s.Stop()
	s.Stop()
	if r.removed != 1 {
		t.Fatalf("removed %d", r.removed)
	}
}

func TestStartRedirectFailureIsPageUnavailable(t *testing.T) {
	r := &fakeRedirect{applyErr: errors.New("nft: permission denied")}
	s := &Server{Redirect: r}
	t.Cleanup(s.Stop)
	_, status := s.Start(testPage, "", testLookup, nil)
	if !strings.HasPrefix(status, "page_unavailable: ") || !strings.Contains(status, "redirect (nft: permission denied)") ||
		!strings.Contains(status, AddrHTTPS4+" (no CA)") {
		t.Fatalf("status %q", status)
	}
	if r.applied[0][1] != 0 {
		t.Fatalf("443 redirected without an HTTPS listener: %v", r.applied)
	}
}

func TestFallbackSkipsPortsInUse(t *testing.T) {
	d := t.TempDir()
	o4, o6 := procTCP, procTCP6
	t.Cleanup(func() { procTCP, procTCP6 = o4, o6 })
	procTCP, procTCP6 = filepath.Join(d, "tcp"), filepath.Join(d, "tcp6")
	both := " 0: 00000000:0050 00000000:0000 0A\n 1: 00000000:01BB 00000000:0000 0A\n"
	os.WriteFile(procTCP, []byte("hdr\n"+both), 0o644)
	s := &Server{}
	s.detectOnce.Do(func() {}) // no redirect backend
	t.Cleanup(s.Stop)
	_, status := s.Start(testPage, "", testLookup, testCA(t))
	want := "page_unavailable: " + AddrHTTP4 + " (port in use by another service), " + AddrHTTPS4 + " (port in use by another service)"
	if status != want {
		t.Fatalf("status %q", status)
	}
	if b := s.Bound(); b != (Addrs{}) {
		t.Fatalf("bound %+v", b)
	}
}
