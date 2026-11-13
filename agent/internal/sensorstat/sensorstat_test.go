package sensorstat

import (
	"testing"

	"github.com/siem-platform/agent/internal/tailer"
)

func TestSensorOf(t *testing.T) {
	for logType, want := range map[string]string{
		"windows_etw_process": ETW, "windows_etw_network": ETW, "windows_etw_status": "",
		"linux_process_exec": ProcExec, "linux_network_connect": Netwatch, "linux_network_snapshot": Netwatch,
		"linux_dns_query": Netwatch, "linux_file_event": LinSensor, "linux_process_exit": LinSensor,
		"linux_sensor_health": "", "syslog": "", "ioc_match": "",
	} {
		if got := SensorOf(logType); got != want {
			t.Errorf("SensorOf(%q) = %q, want %q", logType, got, want)
		}
	}
}

func TestSnapshotCountsRunningAndLost(t *testing.T) {
	r := New()
	r.SetRunning(ETW, true, "")
	r.SetRunning(ProcExec, false, "eBPF: operation not permitted")
	lost := uint64(7)
	r.SetLost(ETW, func() uint64 { return lost })
	for i := 0; i < 3; i++ {
		r.Observe(tailer.Encode("windows_etw_process", "EventID=1"))
	}
	r.Observe(tailer.Encode("syslog", "not a sensor"))

	snap := r.Snapshot()
	etw := snap[ETW]
	if !etw.Running || etw.Events != 3 || etw.Lost != 7 || etw.LastEventAt == "" {
		t.Fatalf("etw: %+v", etw)
	}
	if pe := snap[ProcExec]; pe.Running || pe.Error == "" {
		t.Fatalf("a sensor that failed to start is reported with its error: %+v", pe)
	}
	if _, ok := snap[Netwatch]; ok || len(snap) != 2 {
		t.Fatalf("sensors never started stay out: %v", snap)
	}
	lost = 9
	if r.Snapshot()[ETW].Lost != 9 {
		t.Fatal("lost is read at every snapshot")
	}
}
