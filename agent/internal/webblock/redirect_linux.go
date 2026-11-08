//go:build linux

package webblock

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// On Linux a listener on 127.84.0.1:80 makes every later bind of
// 0.0.0.0:80 or [::]:80 fail with EADDRINUSE (nginx, apache, docker -p 80:80
// would not start). So the page server listens on two free high ports on
// 127.0.0.1 and a NAT OUTPUT redirect sends 127.84.0.1:80/443 there; the
// agent never holds a privileged port another service may want. The redirect
// keeps the destination host of the connection out of the picture: TLS still
// sees the original SNI and HTTP the original Host header.

const (
	redirectTimeout = 10 * time.Second
	nftTable        = "adsiem_webblock"
	iptChain        = "ADSIEM_WEBBLOCK"
)

// cmdRun runs an absolute tool path with optional stdin; replaced in tests.
var cmdRun = func(path, stdin string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), redirectTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(out))
	if err != nil {
		return text, fmt.Errorf("%s %s: %w: %s", path, strings.Join(args, " "), err, text)
	}
	return text, nil
}

// redirectLookPath is replaced in tests.
var redirectLookPath = exec.LookPath

// nftRedirect implements Redirector with its own nftables table.
type nftRedirect struct{ path string }

// nftApplyScript replaces the table in one transaction: add (no-op when it
// exists), flush, then declare the chain and its two rules.
func nftApplyScript(httpPort, httpsPort int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table ip %s\n", nftTable)
	fmt.Fprintf(&b, "flush table ip %s\n", nftTable)
	fmt.Fprintf(&b, "table ip %s {\n", nftTable)
	b.WriteString("\tchain output {\n")
	b.WriteString("\t\ttype nat hook output priority -100; policy accept;\n")
	if httpPort > 0 {
		fmt.Fprintf(&b, "\t\tip daddr %s tcp dport 80 redirect to :%d\n", SinkV4, httpPort)
	}
	if httpsPort > 0 {
		fmt.Fprintf(&b, "\t\tip daddr %s tcp dport 443 redirect to :%d\n", SinkV4, httpsPort)
	}
	b.WriteString("\t}\n}\n")
	return b.String()
}

// nftRemoveScript deletes the table; adding it first makes the delete succeed
// whether or not it exists.
func nftRemoveScript() string {
	return fmt.Sprintf("add table ip %s\ndelete table ip %s\n", nftTable, nftTable)
}

func (n nftRedirect) Apply(httpPort, httpsPort int) error {
	_, err := cmdRun(n.path, nftApplyScript(httpPort, httpsPort), "-f", "-")
	return err
}

func (n nftRedirect) Remove() error {
	_, err := cmdRun(n.path, nftRemoveScript(), "-f", "-")
	return err
}

// iptRedirect implements Redirector with its own iptables nat chain.
type iptRedirect struct{ path string }

func iptArgs(args ...string) []string { return append([]string{"-w", "-t", "nat"}, args...) }

// iptJump is the OUTPUT rule that sends the sink's TCP traffic to our chain.
func iptJump(op string) []string {
	return iptArgs(op, "OUTPUT", "-d", SinkV4+"/32", "-p", "tcp", "-j", iptChain)
}

// iptRules are the REDIRECT rules of our chain (the jump already matched the
// destination address).
func iptRules(httpPort, httpsPort int) [][]string {
	var out [][]string
	if httpPort > 0 {
		out = append(out, iptArgs("-A", iptChain, "-p", "tcp", "--dport", "80", "-j", "REDIRECT", "--to-ports", strconv.Itoa(httpPort)))
	}
	if httpsPort > 0 {
		out = append(out, iptArgs("-A", iptChain, "-p", "tcp", "--dport", "443", "-j", "REDIRECT", "--to-ports", strconv.Itoa(httpsPort)))
	}
	return out
}

func (r iptRedirect) run(args []string) error {
	_, err := cmdRun(r.path, "", args...)
	return err
}

func (r iptRedirect) chainExists() bool { return r.run(iptArgs("-S", iptChain)) == nil }

func (r iptRedirect) Apply(httpPort, httpsPort int) error {
	if !r.chainExists() {
		if err := r.run(iptArgs("-N", iptChain)); err != nil {
			return err
		}
	}
	if err := r.run(iptArgs("-F", iptChain)); err != nil {
		return err
	}
	for _, a := range iptRules(httpPort, httpsPort) {
		if err := r.run(a); err != nil {
			return err
		}
	}
	if r.run(iptJump("-C")) != nil {
		if err := r.run(iptArgs("-I", "OUTPUT", "1", "-d", SinkV4+"/32", "-p", "tcp", "-j", iptChain)); err != nil {
			return err
		}
	}
	return nil
}

func (r iptRedirect) Remove() error {
	if !r.chainExists() {
		return nil
	}
	for i := 0; i < 8 && r.run(iptJump("-C")) == nil; i++ {
		if err := r.run(iptJump("-D")); err != nil {
			return err
		}
	}
	if err := r.run(iptArgs("-F", iptChain)); err != nil {
		return err
	}
	return r.run(iptArgs("-X", iptChain))
}

// detectRedirect picks nft when it is on PATH and answers (as the firewall
// engine detects it), else iptables; nil when neither works.
func detectRedirect() Redirector {
	if p, err := redirectLookPath("nft"); err == nil {
		if _, err := cmdRun(p, "", "list", "tables"); err == nil {
			return nftRedirect{path: p}
		} else {
			slog.Warn("webblock: nft present but not usable", "err", err)
		}
	}
	if p, err := redirectLookPath("iptables"); err == nil {
		if _, err := cmdRun(p, "", "-w", "-t", "nat", "-S", "OUTPUT"); err == nil {
			return iptRedirect{path: p}
		} else {
			slog.Warn("webblock: iptables present but not usable", "err", err)
		}
	}
	return nil
}

// removeRedirects deletes our table and chain by name, whichever tool made
// them (Cleanup; the ports need not be known).
func removeRedirects() error {
	var errs []error
	if p, err := redirectLookPath("nft"); err == nil {
		if err := (nftRedirect{path: p}).Remove(); err != nil {
			errs = append(errs, err)
		}
	}
	if p, err := redirectLookPath("iptables"); err == nil {
		if err := (iptRedirect{path: p}).Remove(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// tcpStateListen is the LISTEN state in /proc/net/tcp.
const tcpStateListen = "0A"

// listening reports whether a /proc/net/tcp(6)-format table has a socket in
// LISTEN state on port at one of the local addresses (hex, as the file
// writes them).
func listening(r io.Reader, port int, addrs ...string) bool {
	want := map[string]bool{}
	for _, a := range addrs {
		want[fmt.Sprintf("%s:%04X", a, port)] = true
	}
	sc := bufio.NewScanner(r)
	for i := 0; sc.Scan() && i < ownerMaxRows; i++ {
		f := strings.Fields(sc.Text())
		if len(f) > 3 && f[3] == tcpStateListen && want[strings.ToUpper(f[1])] {
			return true
		}
	}
	return false
}

// procTCP and procTCP6 are replaced in tests.
var procTCP, procTCP6 = "/proc/net/tcp", "/proc/net/tcp6"

// portInUse reports whether another service listens on port on 0.0.0.0,
// 127.84.0.1 or [::] (binding the sink then would collide with it).
func portInUse(port int) bool {
	check := func(file string, addrs ...string) bool {
		f, err := os.Open(file)
		if err != nil {
			return false
		}
		defer f.Close()
		return listening(f, port, addrs...)
	}
	v4 := []string{"00000000", hexAddr([]byte{127, 84, 0, 1})}
	return check(procTCP, v4...) || check(procTCP6, strings.Repeat("0", 32))
}

// defaultPlan: with a redirect two high ports on 127.0.0.1; without one the
// sink's ports directly, each only when no other service listens on it. No
// [::1] listeners on Linux: redirecting ::1 would capture local services.
func (s *Server) defaultPlan() ([]bindSpec, Redirector) {
	if r := s.redirector(); r != nil {
		return []bindSpec{
			{name: "http4", addr: "127.0.0.1:0", label: AddrHTTP4, redirect: 80},
			{name: "https4", addr: "127.0.0.1:0", label: AddrHTTPS4, tls: true, redirect: 443},
		}, r
	}
	specs := []bindSpec{
		{name: "http4", addr: AddrHTTP4, label: AddrHTTP4},
		{name: "https4", addr: AddrHTTPS4, label: AddrHTTPS4, tls: true},
	}
	for i, port := range []int{80, 443} {
		if portInUse(port) {
			specs[i].skip = "port in use by another service"
		}
	}
	return specs, nil
}

func (s *Server) redirector() Redirector {
	if s.Redirect != nil {
		return s.Redirect
	}
	s.detectOnce.Do(func() {
		s.detected = detectRedirect()
		if s.detected == nil {
			slog.Warn("webblock: neither nft nor iptables usable; binding the block page ports directly where free")
		}
	})
	return s.detected
}
