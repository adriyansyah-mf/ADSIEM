package tailer

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/evidence"
	"github.com/siem-platform/agent/internal/heartbeat"
)

// queued lists unacknowledged journal events, acknowledging none.
func queued(t *testing.T, j *evidence.Journal) []evidence.Envelope {
	t.Helper()
	var out []evidence.Envelope
	seen := map[string]bool{}
	for {
		e, ok, err := j.Peek(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !ok || seen[e.EventID] {
			return out
		}
		seen[e.EventID] = true
		out = append(out, e)
		// park it so Peek moves on; quarantine keeps the payload
		if err := j.Quarantine(context.Background(), e.EventID, "inspected by test"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDurableManagerRestartsOnLogTypeChangeAndJoinsSources(t *testing.T) {
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	m := NewDurableManager(env.journal, env.publisher)
	m.Update([]heartbeat.LogSource{{Path: path, LogType: "syslog", IsEnabled: true}})
	env.baselined(t, path)
	first := m.sources[path]
	appendFile(t, path, "as syslog\n")
	waitFor(t, "syslog event", func() bool { return env.journal.Snapshot().QueuedEvents == 1 })

	m.Update([]heartbeat.LogSource{{Path: path, LogType: "linux_auth", IsEnabled: true}})
	select {
	case <-first.done:
	default:
		t.Fatal("Update returned before the replaced source stopped")
	}
	appendFile(t, path, "as auth\n")
	waitFor(t, "auth event", func() bool { return env.journal.Snapshot().QueuedEvents == 2 })

	second := m.sources[path]
	m.StopAll()
	select {
	case <-second.done:
	default:
		t.Fatal("StopAll returned before its source stopped")
	}
	appendFile(t, path, "after stop\n")
	time.Sleep(3 * durablePoll)
	events := queued(t, env.journal)
	if len(events) != 2 || events[0].LogType != "syslog" || events[1].LogType != "linux_auth" || events[1].RawMessage != "as auth" {
		t.Fatalf("events %+v", events)
	}
}

func TestManagerStopsDisabledSourcesAndWaits(t *testing.T) {
	env := newTailEnv(t)
	path := filepath.Join(t.TempDir(), "app.log")
	writeFile(t, path, "")
	m := NewDurableManager(env.journal, env.publisher)
	m.Update([]heartbeat.LogSource{{Path: path, LogType: "syslog", IsEnabled: true}})
	s := m.sources[path]
	m.Update([]heartbeat.LogSource{{Path: path, LogType: "syslog", IsEnabled: false}})
	select {
	case <-s.done:
	default:
		t.Fatal("disabled source still running after Update")
	}
	if len(m.sources) != 0 {
		t.Fatalf("sources %v", m.sources)
	}
}
