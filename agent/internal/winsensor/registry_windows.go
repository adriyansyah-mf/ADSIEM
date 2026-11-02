//go:build windows

package winsensor

import (
	"errors"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/siem-platform/agent/internal/buffer"
	"github.com/siem-platform/agent/internal/tailer"
)

const (
	regRescanEvery = 10 * time.Minute // also catches a change a notification missed
	regUsersEvery  = 2 * time.Minute  // hives of users who signed in since
)

// watched is one spec under one root, its last snapshot and its notifier.
type watched struct {
	root     registry.Key
	rootName string // HKLM or HKU\<SID>
	base     string // path prefix under root (HKU: the SID)
	spec     regSpec
	snap     regSnapshot
	key      registry.Key // open for notifications (0 while the key does not exist)
}

func (w *watched) target(rel string) string {
	return w.rootName + `\` + rel
}

// RegistryWatcher reports changes to the persistence keys.
type RegistryWatcher struct {
	buf     *buffer.Buffer
	changed chan *watched
	stop    chan struct{}
	done    chan struct{}
	mu      sync.Mutex
	all     []*watched
	users   map[string]bool
}

// StartRegistry takes a baseline of the persistence keys (no lines for what
// is already there) and reports what changes from then on.
func StartRegistry(buf *buffer.Buffer) *RegistryWatcher {
	r := &RegistryWatcher{buf: buf, changed: make(chan *watched, 64), stop: make(chan struct{}),
		done: make(chan struct{}), users: map[string]bool{}}
	for _, s := range machineSpecs {
		r.add(&watched{root: registry.LOCAL_MACHINE, rootName: "HKLM", spec: s})
	}
	r.addUsers()
	go r.run()
	return r
}

func (r *RegistryWatcher) add(w *watched) {
	w.snap = r.snapshot(w)
	r.mu.Lock()
	r.all = append(r.all, w)
	r.mu.Unlock()
	go r.notify(w)
}

// addUsers watches the hives of users signed in since the last look.
func (r *RegistryWatcher) addUsers() {
	k, err := registry.OpenKey(registry.USERS, "", registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return
	}
	sids, _ := k.ReadSubKeyNames(-1)
	k.Close()
	for _, sid := range sids {
		if !strings.HasPrefix(sid, "S-1-5-21-") || strings.HasSuffix(sid, "_Classes") || r.users[sid] {
			continue
		}
		r.users[sid] = true
		for _, s := range userSpecs {
			r.add(&watched{root: registry.USERS, rootName: `HKU\` + sid, base: sid, spec: s})
		}
	}
}

func (r *RegistryWatcher) fullPath(w *watched, rel string) string {
	if w.base == "" {
		return rel
	}
	return w.base + `\` + rel
}

// snapshot reads a spec's values (and depth-1 subkeys) now.
func (r *RegistryWatcher) snapshot(w *watched) regSnapshot {
	snap := newSnapshot()
	if w.spec.depth == 0 {
		r.readValues(w, w.spec.path, &snap)
		return snap
	}
	k, err := registry.OpenKey(w.root, r.fullPath(w, w.spec.path), registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return snap
	}
	subs, _ := k.ReadSubKeyNames(-1)
	k.Close()
	for _, sub := range subs {
		rel := w.spec.path + `\` + sub
		if w.spec.child == "" {
			snap.keys[w.target(rel)] = true
		} else {
			rel += `\` + w.spec.child
		}
		r.readValues(w, rel, &snap)
	}
	return snap
}

func (r *RegistryWatcher) readValues(w *watched, rel string, snap *regSnapshot) {
	k, err := registry.OpenKey(w.root, r.fullPath(w, rel), registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	names, _ := k.ReadValueNames(-1)
	for _, name := range names {
		if !w.spec.wants(name) {
			continue
		}
		buf := make([]byte, 4096)
		n, typ, err := k.GetValue(name, buf)
		if errors.Is(err, registry.ErrShortBuffer) && n > 0 && n <= 1<<20 {
			buf = make([]byte, n)
			n, typ, err = k.GetValue(name, buf)
		}
		if err != nil && !errors.Is(err, registry.ErrShortBuffer) {
			continue
		}
		if n > len(buf) {
			n = len(buf)
		}
		vn := name
		if vn == "" {
			vn = "(Default)"
		}
		snap.values[w.target(rel+`\`+vn)] = regDetails(typ, buf[:n])
	}
}

// notify waits for changes under the spec's key and reports them; a key
// that does not exist yet is retried at the rescan.
func (r *RegistryWatcher) notify(w *watched) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	k, err := registry.OpenKey(w.root, r.fullPath(w, w.spec.path), registry.NOTIFY)
	if err != nil {
		return
	}
	r.mu.Lock()
	select {
	case <-r.stop:
		r.mu.Unlock()
		k.Close()
		return
	default:
	}
	w.key = k
	r.mu.Unlock()
	defer func() { // the key is closed here unless Close closed it already
		r.mu.Lock()
		if w.key == k {
			w.key = 0
			k.Close()
		}
		r.mu.Unlock()
	}()
	filter := uint32(windows.REG_NOTIFY_CHANGE_NAME | windows.REG_NOTIFY_CHANGE_LAST_SET)
	for {
		if err := windows.RegNotifyChangeKeyValue(windows.Handle(k), w.spec.depth > 0, filter, 0, false); err != nil {
			return // key closed (stop) or deleted: the rescan opens it again
		}
		select {
		case <-r.stop:
			return
		case r.changed <- w:
		}
	}
}

func (r *RegistryWatcher) run() {
	defer close(r.done)
	rescan := time.NewTicker(regRescanEvery)
	defer rescan.Stop()
	users := time.NewTicker(regUsersEvery)
	defer users.Stop()
	for {
		select {
		case <-r.stop:
			return
		case w := <-r.changed:
			time.Sleep(200 * time.Millisecond) // let a burst of writes settle
			r.check(w)
		case <-rescan.C:
			r.mu.Lock()
			all := append([]*watched(nil), r.all...)
			r.mu.Unlock()
			for _, w := range all {
				r.check(w)
				r.mu.Lock()
				idle := w.key == 0
				r.mu.Unlock()
				if idle {
					go r.notify(w) // the key may exist now
				}
			}
		case <-users.C:
			r.addUsers()
		}
	}
}

func (r *RegistryWatcher) check(w *watched) {
	cur := r.snapshot(w)
	for _, l := range regDiff(w.snap, cur) {
		r.buf.Push(tailer.Encode(LogTypeRegistry, l))
	}
	w.snap = cur
}

// Close stops watching.
func (r *RegistryWatcher) Close() {
	select {
	case <-r.stop:
		return
	default:
	}
	close(r.stop)
	r.mu.Lock()
	for _, w := range r.all {
		if w.key != 0 {
			w.key.Close() // ends the waiting RegNotifyChangeKeyValue
			w.key = 0
		}
	}
	r.mu.Unlock()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		slog.Warn("registry watcher did not stop in time")
	}
}
