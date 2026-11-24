package task

import (
	"sync"
	"testing"
	"time"
)

// fakeHost records what the tasks did to a host's network state.
type fakeHost struct {
	mu       sync.Mutex
	isolated bool
	order    []string
	done     chan string
}

func newFakeRunner(h *fakeHost, delay map[string]time.Duration) *Runner {
	return &Runner{
		exec: func(t TaskDef) (any, error) {
			time.Sleep(delay[t.TaskType])
			h.mu.Lock()
			defer h.mu.Unlock()
			switch t.TaskType {
			case "isolate_host":
				h.isolated = true
			case "unisolate_host":
				h.isolated = false
			}
			h.order = append(h.order, t.ID)
			return nil, nil
		},
		submit: func(id string, _ TaskResult) { h.done <- id },
	}
}

func waitDone(t *testing.T, h *fakeHost, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d tasks finished", i, n)
		}
	}
}

// An isolate_host and the unisolate_host that releases it, delivered in one
// heartbeat: the slower isolate used to finish last and leave the host
// isolated.
func TestDispatchIsolateThenUnisolateLeavesHostReleased(t *testing.T) {
	h := &fakeHost{done: make(chan string, 8)}
	r := newFakeRunner(h, map[string]time.Duration{"isolate_host": 100 * time.Millisecond})

	r.Dispatch(TaskDef{ID: "iso", TaskType: "isolate_host"})
	r.Dispatch(TaskDef{ID: "uniso", TaskType: "unisolate_host"})
	waitDone(t, h, 2)

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.isolated {
		t.Fatalf("host left isolated; tasks ran in order %v", h.order)
	}
	if len(h.order) != 2 || h.order[0] != "iso" || h.order[1] != "uniso" {
		t.Fatalf("tasks ran in order %v, want [iso uniso]", h.order)
	}
}

func TestDispatchUnisolateThenIsolateLeavesHostIsolated(t *testing.T) {
	h := &fakeHost{done: make(chan string, 8)}
	r := newFakeRunner(h, map[string]time.Duration{"unisolate_host": 100 * time.Millisecond})

	r.Dispatch(TaskDef{ID: "uniso", TaskType: "unisolate_host"})
	r.Dispatch(TaskDef{ID: "iso", TaskType: "isolate_host"})
	waitDone(t, h, 2)

	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.isolated {
		t.Fatalf("host released though isolate_host came last; order %v", h.order)
	}
}

// block_ip and unblock_ip change the firewall too and keep their order.
func TestDispatchFirewallTasksKeepOrder(t *testing.T) {
	h := &fakeHost{done: make(chan string, 16)}
	r := newFakeRunner(h, map[string]time.Duration{"block_ip": 30 * time.Millisecond})

	want := []string{"b1", "u1", "b2", "flush", "u2"}
	types := []string{"block_ip", "unblock_ip", "block_ip", "firewall_flush", "unblock_ip"}
	for i, id := range want {
		r.Dispatch(TaskDef{ID: id, TaskType: types[i]})
	}
	waitDone(t, h, len(want))

	h.mu.Lock()
	defer h.mu.Unlock()
	for i := range want {
		if h.order[i] != want[i] {
			t.Fatalf("tasks ran in order %v, want %v", h.order, want)
		}
	}
}

// Other tasks still run concurrently: a slow one doesn't hold up the rest,
// nor an isolation.
func TestDispatchOtherTasksStayConcurrent(t *testing.T) {
	h := &fakeHost{done: make(chan string, 8)}
	r := newFakeRunner(h, map[string]time.Duration{"memory_scan": 300 * time.Millisecond})

	r.Dispatch(TaskDef{ID: "slow", TaskType: "memory_scan"})
	r.Dispatch(TaskDef{ID: "fast", TaskType: "process_list"})
	r.Dispatch(TaskDef{ID: "iso", TaskType: "isolate_host"})

	first := map[string]bool{}
	for i := 0; i < 2; i++ {
		select {
		case id := <-h.done:
			first[id] = true
		case <-time.After(5 * time.Second):
			t.Fatal("tasks did not finish")
		}
	}
	if first["slow"] {
		t.Fatalf("the slow task finished before the others: %v", first)
	}
	waitDone(t, h, 1)
}

// A task already in flight is not run twice.
func TestDispatchSkipsInflightDuplicate(t *testing.T) {
	h := &fakeHost{done: make(chan string, 8)}
	r := newFakeRunner(h, map[string]time.Duration{"isolate_host": 50 * time.Millisecond})

	r.Dispatch(TaskDef{ID: "iso", TaskType: "isolate_host"})
	r.Dispatch(TaskDef{ID: "iso", TaskType: "isolate_host"})
	waitDone(t, h, 1)
	select {
	case id := <-h.done:
		t.Fatalf("task %s ran twice", id)
	case <-time.After(150 * time.Millisecond):
	}
}
