//go:build linux

package prevent

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:embed bpf/prevent.bpf.o
var lsmObj []byte

// Keep in sync with prevent.bpf.c.
const (
	actDetect     = 1
	actBlock      = 2
	hasPath       = 1
	hasDir        = 2
	hasParent     = 4
	pathLen       = 256
	selfMagic     = 0x50524556
	decisionBytes = 48 + pathLen + nameLen
)

type dirKey struct {
	Ino uint64
	Dev uint32
	Pad uint32
}

type lsmEngine struct {
	coll   *ebpf.Collection
	links  []link.Link
	reader *ringbuf.Reader
	report func(Decision)

	mu     sync.Mutex
	policy *Policy
	done   sync.WaitGroup
}

// bpfLSMEnabled: the kernel must be booted with "bpf" in its LSM list.
func bpfLSMEnabled() bool {
	b, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), ",") {
		if l == "bpf" {
			return true
		}
	}
	return false
}

func startLSM(report func(Decision)) (*lsmEngine, error) {
	if !bpfLSMEnabled() {
		return nil, errors.New(`"bpf" is not in /sys/kernel/security/lsm (boot with lsm=...,bpf)`)
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(lsmObj))
	if err != nil {
		return nil, fmt.Errorf("load spec: %w", err)
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load into kernel: %w", err)
	}
	e := &lsmEngine{coll: coll, report: report}
	l, err := link.AttachLSM(link.LSMOptions{Program: coll.Programs["check_exec"]})
	if err != nil {
		e.close()
		return nil, fmt.Errorf("attach lsm/bprm_check_security: %w", err)
	}
	e.links = append(e.links, l)
	tp, err := link.Tracepoint("syscalls", "sys_enter_prctl", coll.Programs["enter_prctl"], nil)
	if err != nil {
		e.close()
		return nil, fmt.Errorf("attach prctl tracepoint: %w", err)
	}
	e.links = append(e.links, tp)
	unix.Prctl(selfMagic, 0, 0, 0, 0) // EINVAL; the tracepoint records our tgid
	var self uint32
	if err := coll.Maps["prevent_config"].Lookup(uint32(1), &self); err != nil || self == 0 {
		e.close()
		return nil, fmt.Errorf("could not identify the agent's own process: %v", err)
	}
	if e.reader, err = ringbuf.NewReader(coll.Maps["decisions"]); err != nil {
		e.close()
		return nil, err
	}
	e.done.Add(1)
	go e.read()
	slog.Info("prevent: BPF LSM engine attached", "self_tgid", self)
	return e, nil
}

func (e *lsmEngine) close() {
	for _, l := range e.links {
		l.Close()
	}
	if e.reader != nil {
		e.reader.Close()
		e.done.Wait()
	}
	e.coll.Close()
}

func clearMap(m *ebpf.Map, keySize int) {
	key := make([]byte, keySize)
	var keys [][]byte
	it := m.Iterate()
	var val []byte
	for it.Next(&key, &val) {
		keys = append(keys, append([]byte(nil), key...))
	}
	for _, k := range keys {
		m.Delete(k)
	}
}

func fixed(s string, n int) []byte {
	b := make([]byte, n)
	copy(b, s)
	if len(s) >= n {
		b[n-1] = 0 // the kernel reads at most n-1 bytes
	}
	return b
}

// kernelDev turns a stat device number into the kernel's s_dev encoding.
func kernelDev(dev uint64) uint32 {
	return unix.Major(dev)<<20 | unix.Minor(dev)
}

// apply loads p into the maps; enforcement is off while it does.
func (e *lsmEngine) apply(p *Policy) error {
	cfg := e.coll.Maps["prevent_config"]
	if err := cfg.Put(uint32(0), uint32(0)); err != nil {
		return err
	}
	e.mu.Lock()
	e.policy = p
	e.mu.Unlock()
	clearMap(e.coll.Maps["deny_path"], pathLen)
	clearMap(e.coll.Maps["deny_dir"], 16)
	clearMap(e.coll.Maps["parent_mask"], nameLen)
	clearMap(e.coll.Maps["child_mask"], nameLen)
	has := uint32(0)
	actions := e.coll.Maps["rule_action"]
	parentMask, childMask := map[string]uint64{}, map[string]uint64{}
	k := uint32(0)
	for _, c := range p.Rules {
		act := uint32(actDetect)
		if c.block {
			act = actBlock
		}
		if err := actions.Put(uint32(c.index), act); err != nil {
			return err
		}
		switch c.RuleType {
		case TypePath:
			if len(c.Value) >= pathLen {
				slog.Warn("prevent: path too long for the kernel engine", "rule", c.Name)
				continue
			}
			if err := e.coll.Maps["deny_path"].Put(fixed(c.Value, pathLen), uint32(c.index)); err != nil {
				return err
			}
			has |= hasPath
		case TypeDir:
			var st unix.Stat_t
			if err := unix.Stat(c.Value, &st); err != nil {
				continue // not there (yet); re-applied every minute
			}
			key := dirKey{Ino: st.Ino, Dev: kernelDev(st.Dev)}
			if err := e.coll.Maps["deny_dir"].Put(key, uint32(c.index)); err != nil {
				return err
			}
			has |= hasDir
		case TypeParent:
			if err := e.coll.Maps["parent_rule"].Put(k, uint32(c.index)); err != nil {
				return err
			}
			for _, n := range c.parents {
				parentMask[n] |= 1 << k
			}
			for _, n := range c.children {
				childMask[n] |= 1 << k
			}
			k++
			has |= hasParent
		}
	}
	for n, m := range parentMask {
		if err := e.coll.Maps["parent_mask"].Put(fixed(n, nameLen), m); err != nil {
			return err
		}
	}
	for n, m := range childMask {
		if err := e.coll.Maps["child_mask"].Put(fixed(n, nameLen), m); err != nil {
			return err
		}
	}
	return cfg.Put(uint32(0), has)
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func (e *lsmEngine) read() {
	defer e.done.Done()
	for {
		rec, err := e.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		b := rec.RawSample
		if len(b) < decisionBytes {
			continue
		}
		le := binary.LittleEndian
		idx := int(le.Uint32(b[24:]))
		e.mu.Lock()
		p := e.policy
		e.mu.Unlock()
		if p == nil || idx >= len(p.Rules) {
			continue
		}
		e.report(Decision{
			Rule:    p.Rules[idx],
			Blocked: le.Uint32(b[28:]) == actBlock,
			Engine:  "lsm",
			PID:     le.Uint32(b[12:]),
			PPID:    le.Uint32(b[16:]),
			UID:     le.Uint32(b[20:]),
			Comm:    cstr(b[32:48]),
			Path:    cstr(b[48 : 48+pathLen]),
			Parent:  cstr(b[48+pathLen : 48+pathLen+nameLen]),
		})
	}
}
