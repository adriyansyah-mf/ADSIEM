//go:build linux

package prevent

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/siem-platform/agent/internal/malhash"
)

// The fanotify engine runs in a helper process (the agent binary started
// again with HelperEnv set), never inside the agent itself.
//
// Go's os/exec forks with vfork: the forking thread waits, still counted
// as running, until the child's exec finishes. With fanotify in the same
// process that exec waits for our answer, and our answer can wait for a
// garbage collection that waits for the forking thread: every exec on
// the host then hangs. The helper never forks, so its collector cannot
// be held up by anyone. It reads policies on stdin and writes decisions
// on stdout; when the agent goes away stdin closes, the helper exits and
// the kernel allows whatever was pending.

// HelperEnv marks the helper process.
const HelperEnv = "SIEM_AGENT_FANOTIFY_HELPER"

// IsHelper reports whether this process was started as the helper; the
// agent's main (and test mains) call RunHelper then and do nothing else.
func IsHelper() bool { return os.Getenv(HelperEnv) == "1" }

type helperPolicy struct {
	Rules         []Rule `json:"rules"`
	KernelDecides bool   `json:"kernel_decides"`
	// the saved known-malware set (internal/malhash), loaded again when the
	// version changes; empty when execs are not checked against it
	MalwareFile    string `json:"malware_file,omitempty"`
	MalwareVersion string `json:"malware_version,omitempty"`
}

// helperDecision is a decision, or with Applied set the acknowledgement
// that a policy is in force.
type helperDecision struct {
	Applied int    `json:"applied,omitempty"`
	Index   int    `json:"index"` // -1: a known-malware hash, Label names it
	Label   string `json:"label,omitempty"`
	Blocked bool   `json:"blocked"`
	Path    string `json:"path"`
	Parent  string `json:"parent"`
	SHA256  string `json:"sha256,omitempty"`
	Comm    string `json:"comm"`
	PID     uint32 `json:"pid"`
	PPID    uint32 `json:"ppid"`
	UID     uint32 `json:"uid"`
}

type helperHello struct {
	Ready  bool   `json:"ready"`
	Mounts int    `json:"mounts"`
	Error  string `json:"error,omitempty"`
}

// RunHelper is the helper process: it returns when stdin closes.
func RunHelper() int {
	out := json.NewEncoder(os.Stdout)
	var outMu sync.Mutex
	write := func(v any) {
		outMu.Lock()
		out.Encode(v)
		outMu.Unlock()
	}
	eng, err := startFanotifyLocal(func(d Decision) {
		label := ""
		if d.Rule.RuleType == TypeKnownMalware {
			label = d.Rule.Name
		}
		write(helperDecision{
			Index: d.Rule.index, Label: label, Blocked: d.Blocked, Path: d.Path, Parent: d.Parent, SHA256: d.SHA256,
			Comm: d.Comm, PID: d.PID, PPID: d.PPID, UID: d.UID,
		})
	})
	if err != nil {
		write(helperHello{Error: err.Error()})
		return 1
	}
	write(helperHello{Ready: true, Mounts: len(eng.marked)})
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 1<<20), 64<<20)
	var malware *malhash.Set
	var malwareVersion string
	for in.Scan() {
		var msg helperPolicy
		if err := json.Unmarshal(in.Bytes(), &msg); err != nil {
			continue
		}
		p, _ := Compile(msg.Rules)
		switch {
		case msg.MalwareFile == "":
			malware, malwareVersion = nil, ""
		case msg.MalwareVersion != malwareVersion:
			set, err := malhash.Load(msg.MalwareFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "prevent helper: known-malware hashes not loaded: %v\n", err)
				malware, malwareVersion = nil, ""
			} else {
				malware, malwareVersion = set, msg.MalwareVersion
			}
		}
		if malware != nil {
			p = p.withMalware(malware, msg.MalwareFile)
		}
		eng.setPolicy(p, msg.KernelDecides)
		write(helperDecision{Applied: len(p.Rules) + 1})
	}
	eng.close()
	return 0
}

// fanClient drives the helper from the agent.
type fanClient struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	report func(Decision)

	mu      sync.Mutex
	policy  *Policy
	done    chan struct{}
	applied chan struct{}
}

func startFanotify(report func(Decision)) (*fanClient, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(self)
	cmd.Args = []string{self, "-test.run=^$"} // a test binary must not run its tests
	cmd.Env = append(os.Environ(), HelperEnv+"=1")
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start fanotify helper: %w", err)
	}
	c := &fanClient{cmd: cmd, stdin: stdin, report: report, done: make(chan struct{}), applied: make(chan struct{}, 1)}
	dec := json.NewDecoder(stdout)
	var hello helperHello
	if err := dec.Decode(&hello); err != nil || !hello.Ready {
		stdin.Close()
		cmd.Wait()
		if hello.Error != "" {
			return nil, errors.New(hello.Error)
		}
		return nil, fmt.Errorf("fanotify helper did not start: %v", err)
	}
	go c.read(dec)
	slog.Info("prevent: fanotify engine started", "helper_pid", cmd.Process.Pid, "mounts", hello.Mounts)
	return c, nil
}

func (c *fanClient) read(dec *json.Decoder) {
	defer close(c.done)
	for {
		var d helperDecision
		if err := dec.Decode(&d); err != nil {
			return
		}
		if d.Applied > 0 {
			select {
			case c.applied <- struct{}{}:
			default:
			}
			continue
		}
		c.mu.Lock()
		p := c.policy
		c.mu.Unlock()
		if p == nil || d.Index < -1 || d.Index >= len(p.Rules) {
			continue
		}
		var rule *compiled
		if d.Index == -1 {
			rule = p.malwareRule(d.Label, d.SHA256)
		} else {
			rule = p.Rules[d.Index]
		}
		c.report(Decision{
			Rule: rule, Blocked: d.Blocked, Engine: "fanotify", Path: d.Path, Parent: d.Parent,
			SHA256: d.SHA256, Comm: d.Comm, PID: d.PID, PPID: d.PPID, UID: d.UID,
		})
	}
}

// setPolicy sends the rules p was compiled from; the helper compiles the
// same list to the same indexes.
func (c *fanClient) setPolicy(p *Policy, kernelDecides bool) {
	rules := make([]Rule, 0, len(p.Rules))
	for _, r := range p.Rules {
		rr := r.Rule
		if !r.block {
			rr.Action = ActionDetect // the guard's verdict travels with the rule
		}
		rules = append(rules, rr)
	}
	msg := helperPolicy{Rules: rules, KernelDecides: kernelDecides}
	if p.checksMalware() && p.malwareFile != "" {
		msg.MalwareFile = p.malwareFile
		msg.MalwareVersion = fmt.Sprintf("%s|%s|%d|%d", p.malware.Version, p.malware.Action, p.malware.Seq, p.malware.Len())
	}
	b, _ := json.Marshal(msg)
	c.mu.Lock()
	c.policy = p
	c.mu.Unlock()
	select { // drop a stale acknowledgement
	case <-c.applied:
	default:
	}
	if _, err := c.stdin.Write(append(b, '\n')); err != nil {
		slog.Warn("prevent: fanotify helper gone", "err", err)
		return
	}
	select {
	case <-c.applied:
	case <-c.done:
		slog.Warn("prevent: fanotify helper exited")
	case <-time.After(5 * time.Second):
		slog.Warn("prevent: fanotify helper did not confirm the rules")
	}
}

func (c *fanClient) close() {
	c.stdin.Close()
	exited := make(chan struct{})
	go func() { c.cmd.Wait(); close(exited) }()
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		c.cmd.Process.Kill()
		<-exited
	}
}
