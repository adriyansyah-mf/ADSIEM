package evidence

import (
	"crypto/rand"
	"math"
	"reflect"
	"runtime"
	"strconv"
	"testing"
)

func randomKey() eventKey {
	var k eventKey
	_, _ = rand.Read(k[:])
	return k
}

func TestEventIndexKeepsOccurrencesOldestFirst(t *testing.T) {
	x := newEventIndex()
	k := randomKey()
	a := eventPosition{Sequence: 1, Offset: 16, End: 90}
	b := eventPosition{Sequence: 2, Offset: 16, End: 90}
	x.add(k, a)
	x.add(k, b)
	if got := x.get(k); !reflect.DeepEqual(got, []eventPosition{a, b}) {
		t.Fatalf("positions %+v", got)
	}
	if len(x.wide[k]) != 1 {
		t.Fatalf("first occurrence not packed: %+v", x)
	}
}

func TestEventIndexFallsBackForPositionsBeyond32Bits(t *testing.T) {
	x := newEventIndex()
	k := randomKey()
	far := eventPosition{Sequence: math.MaxUint32 + 1, Offset: 16, End: 90}
	big := eventPosition{Sequence: 1, Offset: math.MaxUint32, End: math.MaxUint32 + 80}
	x.add(k, far)
	x.add(k, big)
	if got := x.get(k); !reflect.DeepEqual(got, []eventPosition{far, big}) {
		t.Fatalf("unpackable positions lost or reordered: %+v", got)
	}
	if len(x.packed) != 0 || x.Len() != 1 {
		t.Fatalf("packed=%d len=%d", len(x.packed), x.Len())
	}
}

func TestPruneIndexRepacksTheOldestSurvivor(t *testing.T) {
	j := &Journal{index: newEventIndex(), segments: []segment{{sequence: 2}}}
	k, gone := randomKey(), randomKey()
	j.index.add(k, eventPosition{Sequence: 1, Offset: 16, End: 90})
	j.index.add(k, eventPosition{Sequence: 2, Offset: 16, End: 90})
	j.index.add(gone, eventPosition{Sequence: 1, Offset: 90, End: 160})
	j.pruneIndex()
	if got := j.index.get(k); !reflect.DeepEqual(got, []eventPosition{{Sequence: 2, Offset: 16, End: 90}}) {
		t.Fatalf("survivor %+v", got)
	}
	if _, wide := j.index.wide[k]; wide || j.index.Len() != 1 {
		t.Fatalf("survivor not repacked or deleted key kept: %+v", j.index)
	}
}

// BenchmarkIndexMemory reports the heap cost of the index per retained event
// (one occurrence each, as for a normal backlog).
// Map tables grow in powers of two, so the per-event cost depends on where the
// count falls; 2.6M is a full 1 GiB journal of ~400-byte events.
func BenchmarkIndexMemory(b *testing.B) {
	for _, events := range []int{100_000, 700_000, 1_000_000, 2_600_000} {
		b.Run(strconv.Itoa(events), func(b *testing.B) { benchmarkIndexMemory(b, events) })
	}
}

func benchmarkIndexMemory(b *testing.B, events int) {
	for i := 0; i < b.N; i++ {
		runtime.GC()
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		x := newEventIndex()
		for n := 0; n < events; n++ {
			x.add(randomKey(), eventPosition{Sequence: uint64(n / 4096), Offset: int64(n % 4096 * 400), End: int64(n%4096*400 + 400)})
		}
		runtime.GC()
		runtime.ReadMemStats(&after)
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/float64(events), "B/event")
		b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/(1<<20), "MiB")
		runtime.KeepAlive(x)
	}
}
