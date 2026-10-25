package update

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// Offer is what a heartbeat response carries when the server wants this agent
// on another version. Revision changes when an operator retries a rollout, so
// a version that failed before is attempted again.
type Offer struct {
	Version  string `json:"version"`
	Revision int    `json:"revision"`
	URL      string `json:"url"` // server path of the package, fetched with the agent token
	Signed   Signed `json:"signed"`
}

// Status is reported on every heartbeat.
type Status struct {
	Kind     string `json:"kind"` // deb | rpm | msi | "" (unsupported)
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	State    string `json:"state"` // idle | unsupported | downloading | installing | updated | failed
	Target   string `json:"target,omitempty"`
	Revision int    `json:"revision,omitempty"`
	Attempts int    `json:"attempts,omitempty"`
	Error    string `json:"error,omitempty"`
}

const (
	MaxAttempts    = 3
	installTimeout = 15 * time.Minute
	// an installer that succeeded restarts the agent; still running this
	// long after it means the new version never started
	restartGrace = 5 * time.Minute
	maxPackage   = 512 << 20
)

func retryAfter(attempts int) time.Duration { return time.Duration(attempts) * 10 * time.Minute }

// Fetch writes the package at a server path to w.
type Fetch func(ctx context.Context, path string, w io.Writer) error

// Install runs the platform installer for a verified package file, writing
// its output to logPath; it returns once the installer exits.
type Install func(ctx context.Context, kind, pkg, logPath string) error

// persisted across the restart an upgrade causes: the new process reads it to
// report the outcome
type state struct {
	State       string    `json:"state"`
	Target      string    `json:"target"`
	Revision    int       `json:"revision"`
	Attempts    int       `json:"attempts"`
	LastAttempt time.Time `json:"last_attempt"`
	FromVersion string    `json:"from_version"`
	Error       string    `json:"error"`
}

type Updater struct {
	dir     string
	version string
	keys    []ed25519.PublicKey
	kind    string
	reason  string // why updates are unsupported here
	fetch   Fetch
	install Install
	now     func() time.Time

	mu   sync.Mutex
	st   state
	busy bool
}

// New prepares updates for this agent. kind is from DetectKind; kindErr makes
// the agent report "unsupported" with that reason, as does having no key.
func New(stateDir, version string, keys []ed25519.PublicKey, kind string, kindErr error, fetch Fetch, install Install) *Updater {
	u := &Updater{dir: filepath.Join(stateDir, "update"), version: version, keys: keys, kind: kind,
		fetch: fetch, install: install, now: time.Now}
	switch {
	case kindErr != nil:
		u.reason = kindErr.Error()
	case len(keys) == 0:
		u.reason = "no trusted update key (built without one and update.trusted_keys is empty)"
	}
	u.load()
	return u
}

func (u *Updater) statePath() string { return filepath.Join(u.dir, "state.json") }
func (u *Updater) logPath() string   { return filepath.Join(u.dir, "install.log") }

func (u *Updater) load() {
	raw, err := os.ReadFile(u.statePath())
	if err != nil {
		return
	}
	if json.Unmarshal(raw, &u.st) != nil {
		u.st = state{}
		return
	}
	switch u.st.State {
	case "downloading":
		u.st.State, u.st.Error = "failed", "agent restarted during the download"
	case "installing":
		// the outcome of the installer that replaced (or failed to replace) the previous process
		if u.st.Target == u.version {
			u.st.State, u.st.Error = "updated", ""
			slog.Info("agent updated", "from", u.st.FromVersion, "to", u.version)
		} else {
			u.st.State = "failed"
			u.st.Error = fmt.Sprintf("installer ran but the agent still runs %s%s", u.version, tail(u.logPath()))
		}
	}
	u.save()
	_ = os.RemoveAll(filepath.Join(u.dir, "pkg"))
}

func (u *Updater) save() {
	raw, _ := json.Marshal(u.st)
	if err := os.MkdirAll(u.dir, 0o700); err != nil {
		slog.Warn("update state not saved", "err", err)
		return
	}
	tmp := u.statePath() + ".tmp"
	err := os.WriteFile(tmp, raw, 0o600)
	if err == nil {
		err = os.Rename(tmp, u.statePath())
	}
	if err != nil {
		slog.Warn("update state not saved", "err", err)
	}
}

// Status is what the next heartbeat reports.
func (u *Updater) Status() Status {
	u.mu.Lock()
	defer u.mu.Unlock()
	s := Status{Kind: u.kind, OS: runtime.GOOS, Arch: runtime.GOARCH}
	if u.reason != "" {
		s.Kind, s.State, s.Error = "", "unsupported", u.reason
		return s
	}
	s.State = u.st.State
	if s.State == "" {
		s.State = "idle"
	}
	s.Target, s.Revision, s.Attempts, s.Error = u.st.Target, u.st.Revision, u.st.Attempts, u.st.Error
	return s
}

// Offer handles the heartbeat's update offer (nil: none). At most one update
// runs at a time; a failed one is retried with backoff, MaxAttempts times per
// offer revision.
func (u *Updater) Offer(o *Offer) {
	if o == nil || u.reason != "" || o.Version == u.version {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.busy {
		return
	}
	if o.Version != u.st.Target || o.Revision != u.st.Revision {
		u.st = state{Target: o.Version, Revision: o.Revision}
	}
	if u.st.Attempts >= MaxAttempts || (u.st.Attempts > 0 && u.now().Sub(u.st.LastAttempt) < retryAfter(u.st.Attempts)) {
		return
	}
	u.st.Attempts++
	u.st.LastAttempt, u.st.FromVersion = u.now(), u.version
	u.st.State, u.st.Error = "downloading", ""
	u.save()
	u.busy = true
	go u.run(*o)
}

func (u *Updater) run(o Offer) {
	ctx, cancel := context.WithTimeout(context.Background(), installTimeout)
	defer cancel()
	pkg, err := u.prepare(ctx, o)
	if err != nil {
		u.finish(err)
		return
	}
	u.mu.Lock()
	u.st.State = "installing"
	u.save() // before the installer: it stops this process
	u.mu.Unlock()
	slog.Info("installing agent update", "from", u.version, "to", o.Version, "kind", u.kind)
	if err := u.install(ctx, u.kind, pkg, u.logPath()); err != nil {
		_ = os.Remove(pkg)
		u.finish(fmt.Errorf("%w%s", err, tail(u.logPath())))
		return
	}
	time.AfterFunc(restartGrace, func() {
		u.finish(errors.New("installer reported success but the agent was not restarted"))
	})
}

// prepare verifies the offer and downloads the package it signs.
func (u *Updater) prepare(ctx context.Context, o Offer) (string, error) {
	m, err := Verify(o.Signed, u.keys)
	if err != nil {
		return "", err
	}
	if m.Version != o.Version || m.OS != runtime.GOOS || m.Arch != runtime.GOARCH || m.Format != u.kind {
		return "", fmt.Errorf("signed package is %s %s/%s %s, this agent needs %s %s/%s %s",
			m.Version, m.OS, m.Arch, m.Format, o.Version, runtime.GOOS, runtime.GOARCH, u.kind)
	}
	if m.Size > maxPackage {
		return "", fmt.Errorf("package of %d bytes is over the %d byte limit", m.Size, maxPackage)
	}
	dir := filepath.Join(u.dir, "pkg")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	// the signed file name decides the extension msiexec / dpkg see; never a path
	path := filepath.Join(dir, filepath.Base(filepath.Clean("/"+m.File)))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	w := &limitWriter{w: io.MultiWriter(f, h), left: m.Size}
	err = u.fetch(ctx, o.URL, w)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil && w.left != 0 {
		err = fmt.Errorf("downloaded %d of %d bytes", m.Size-w.left, m.Size)
	}
	if err == nil && hex.EncodeToString(h.Sum(nil)) != m.SHA256 {
		err = errors.New("downloaded package does not match the signed SHA-256")
	}
	if err != nil {
		_ = os.Remove(path)
		return "", fmt.Errorf("download: %w", err)
	}
	return path, nil
}

func (u *Updater) finish(err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.busy {
		return
	}
	u.busy = false
	u.st.State, u.st.Error = "failed", truncate(err.Error(), 600)
	u.save()
	slog.Warn("agent update failed", "target", u.st.Target, "attempt", u.st.Attempts, "err", err)
}

type limitWriter struct {
	w    io.Writer
	left int64
}

func (l *limitWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > l.left {
		return 0, errors.New("package is larger than its signed size")
	}
	n, err := l.w.Write(p)
	l.left -= int64(n)
	return n, err
}

// tail is the end of the installer log, for the error the server shows.
func tail(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) == 0 {
		return ""
	}
	raw = bytes.ReplaceAll(raw, []byte{0}, nil) // msiexec logs are UTF-16LE; their text is ASCII
	if len(raw) > 400 {
		raw = raw[len(raw)-400:]
	}
	return ": " + string(raw)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
