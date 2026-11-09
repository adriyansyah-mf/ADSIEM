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

// Queue sizes: SIEM events; the guard session's opens and writes apart.
const (
	eventQueueSize = 8192
	openQueueSize  = 8192
	writeQueueSize = 8192
)

// eventQueue carries ETW events from the sessions' consumers to the run
// loop. The guard's Kernel-File session comes at the rate of every write on
// the host and only feeds the ransomware guard, so it has queues of its own
// with their own drop counters: its opens (which name the writes) and its
// writes. A flood of writes never takes a SIEM event's or an open's place,
// and the loop serves waiting SIEM events, then opens, before any write.
type eventQueue struct {
	events, opens, writes                chan source
	dropped, opensDropped, writesDropped atomic.Uint64
}

func newEventQueue(events, writes int) *eventQueue {
	return &eventQueue{events: make(chan source, events), opens: make(chan source, writes),
		writes: make(chan source, writes)}
}

// push returns the ETW handler for a session of kind k. A full queue drops
// and counts rather than stall the ETW consumer.
func (q *eventQueue) push(k kind) func(*etw.Event) {
	if k == writeEvent {
		return func(ev *etw.Event) {
			ch, dropped := q.writes, &q.writesDropped
			if ev.ID != fileWrite { // an open: names the writes that follow
				ch, dropped = q.opens, &q.opensDropped
			}
			select {
			case ch <- source{k, ev}:
			default:
				dropped.Add(1)
			}
		}
	}
	return func(ev *etw.Event) {
		select {
		case q.events <- source{k, ev}:
		default:
			q.dropped.Add(1)
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

// loop serves the queue until stop closes. Priority: SIEM events, then the
// guard's opens, then its writes: a write is handled only once no SIEM event
// or open waits, so writes cost neither queue space nor more latency than
// one write, and every open is seen before the writes that follow it.
func (q *eventQueue) loop(stop <-chan struct{}, tick, report <-chan time.Time, h loopHooks) {
	drain := func(ch chan source) {
		for {
			select {
			case src := <-ch:
				h.handle(src)
			default:
				return
			}
		}
	}
	for {
		select {
		case <-stop:
			if h.stop != nil {
				h.stop()
			}
			return
		case src := <-q.events:
			h.handle(src)
		case o := <-q.opens:
			drain(q.events)
			h.handle(o)
		case w := <-q.writes:
			drain(q.events)
			drain(q.opens)
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

// status is the sensor's own health for windows_etw_status: SIEM events
// dropped since the last report and in total; the guard session's writes
// and opens dropped (since the last report); writes through an unknown
// FileObject (since the last report); and the fast decode's self-check.
type status struct {
	dropped, droppedTotal, writes, writesTotal, opens, unresolved, fastMismatches uint64
	fastOff                                                                       bool
}

func statusLine(s status) string {
	u := func(v uint64) string { return strconv.FormatUint(v, 10) }
	return line(255, [][2]string{{"Channel", "ETW"}, {"Provider", "SIEMAgent"},
		{"Dropped", u(s.dropped)}, {"DroppedTotal", u(s.droppedTotal)},
		{"WritesDropped", u(s.writes)}, {"WritesDroppedTotal", u(s.writesTotal)},
		{"OpensDropped", u(s.opens)}, {"WritesUnresolved", u(s.unresolved)},
		{"FastMismatches", u(s.fastMismatches)}, {"FastDecodeOff", strconv.FormatBool(s.fastOff)}})
}
