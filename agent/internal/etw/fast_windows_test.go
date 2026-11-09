//go:build windows

package etw

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// The fast decode of Kernel-File Write reads FileObject at 8 + pointer size
// (after ByteOffset and Irp): it must give the value TDH decodes for the
// same writes. Two sessions see the same marked file's writes.
func TestFastWriteFileObjectMatchesTDH(t *testing.T) {
	full, fast := &recorder{}, &recorder{}
	fs, err := Start(Config{Name: "SIEMAgent-Test-WriteTDH", Providers: []Provider{{GUID: kernelFileProvider,
		Keywords: 0x10 | 0x80 | 0x200, EventIDs: []uint16{12, 16}}}}, full.add)
	if err != nil {
		t.Fatalf("tdh session: %v", err)
	}
	defer fs.Close()
	ws, err := Start(Config{Name: "SIEMAgent-Test-WriteFast", Providers: []Provider{{GUID: kernelFileProvider,
		Keywords: 0x10 | 0x80 | 0x200, EventIDs: []uint16{12, 16}}},
		Fast: []Fast{{ID: 16, Offset: func(ptr int) int { return 8 + ptr }}}}, fast.add)
	if err != nil {
		t.Fatalf("fast session: %v", err)
	}
	defer ws.Close()
	time.Sleep(2 * time.Second)

	p := filepath.Join(t.TempDir(), fmt.Sprintf("siemfast%d.txt", time.Now().UnixNano()))
	if err := os.WriteFile(p, make([]byte, 4096), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(p, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteAt([]byte("in place"), 0)
	f.Close()
	pid := uint32(os.Getpid())
	time.Sleep(3 * time.Second)

	want := map[uint64]bool{}
	full.mu.Lock()
	for _, e := range full.events {
		if e.ID == 16 && e.PID == pid {
			if v, ok := e.Get("FileObject"); ok {
				if n, err := strconv.ParseUint(v, 0, 64); err == nil {
					want[n] = true
				}
			}
		}
	}
	full.mu.Unlock()
	if len(want) == 0 {
		t.Fatal("no TDH-decoded writes of the test process")
	}
	fast.mu.Lock()
	defer fast.mu.Unlock()
	got := map[uint64]bool{}
	for _, e := range fast.events {
		if e.ID == 16 && e.PID == pid {
			if len(e.Props) != 0 {
				t.Fatalf("fast event decoded properties: %+v", e.Props)
			}
			got[e.Value] = true
		}
	}
	for v := range want {
		if !got[v] {
			t.Errorf("FileObject %#x (TDH) not among the fast values %v", v, got)
		}
	}
}
