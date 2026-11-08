package winsensor

import (
	"strconv"
	"sync/atomic"
	"time"

	"github.com/siem-platform/agent/internal/etw"
)

// kind is the ETW session an event came from.
type kind int

const (
	kernelProcess kind = iota
	providerProcess
	networkEvent
	dnsEvent
	fileEvent
	imageEvent
	accessEvent
	amsiEvent
	// writeEvent: the guard-only Kernel-File session (opens and writes).
	writeEvent
)

type source struct {
	kind kind
	ev   *etw.Event
}

// Queue sizes: SIEM events, and the guard's Kernel-File writes apart.
const (
	eventQueueSize = 8192
	writeQueueSize = 8192
)

// eventQueue carries ETW events from the sessions' consumers to the run
// loop. Writes, which come at the rate of every write on the host and only
// feed the ransomware guard, have their own bounded channel and drop
// counter: a flood of them never takes a SIEM event's place, and the loop
// handles waiting SIEM events before any write.
type eventQueue struct {
	events, writes         chan source
	dropped, writesDropped atomic.Uint64
}

func newEventQueue(events, writes int) *eventQueue {
	return &eventQueue{events: make(chan source, events), writes: make(chan source, writes)}
}

// push returns the ETW handler for a session of kind k. A full queue drops
// and counts rather than stall the ETW consumer.
func (q *eventQueue) push(k kind) func(*etw.Event) {
	ch, dropped := q.events, &q.dropped
	if k == writeEvent {
		ch, dropped = q.writes, &q.writesDropped
	}
	return func(ev *etw.Event) {
		select {
		case ch <- source{k, ev}:
		default:
			dropped.Add(1)
		}
	}
}

// loopHooks are what loop calls; nil hooks are skipped.
type loopHooks struct {
	handle func(source)
	tick   func(time.Time)
	report func()
	stop   func()
}

// loop serves the queue until stop closes. A write is handled only once no
// SIEM event waits (they are drained first), so writes cost SIEM events
// neither queue space nor latency beyond one write.
func (q *eventQueue) loop(stop <-chan struct{}, tick, report <-chan time.Time, h loopHooks) {
	for {
		select {
		case <-stop:
			if h.stop != nil {
				h.stop()
			}
			return
		case src := <-q.events:
			h.handle(src)
		case w := <-q.writes:
		drain:
			for {
				select {
				case src := <-q.events:
					h.handle(src)
				default:
					break drain
				}
			}
			h.handle(w)
		case now := <-tick:
			if h.tick != nil {
				h.tick(now)
			}
		case <-report:
			if h.report != nil {
				h.report()
			}
		}
	}
}

// statusLine reports the sensor's own losses: SIEM events and guard-only
// writes dropped because the agent fell behind, since the last report and
// in total.
func statusLine(dropped, droppedTotal, writes, writesTotal uint64) string {
	return line(255, [][2]string{{"Channel", "ETW"}, {"Provider", "SIEMAgent"},
		{"Dropped", strconv.FormatUint(dropped, 10)}, {"DroppedTotal", strconv.FormatUint(droppedTotal, 10)},
		{"WritesDropped", strconv.FormatUint(writes, 10)}, {"WritesDroppedTotal", strconv.FormatUint(writesTotal, 10)}})
}
