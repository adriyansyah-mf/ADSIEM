//go:build windows

package etw

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// kernelProcessProvider is in session_windows_test.go.
const kernelFileProvider = "{EDD08927-9CC4-4E65-B970-C2560FB5C289}" // Microsoft-Windows-Kernel-File

// Kernel-File keywords: FILENAME, CREATE, WRITE, DELETE_PATH,
// RENAME_SETLINK_PATH, CREATE_NEW_FILE.
const kernelFileKeywords = 0x10 | 0x80 | 0x200 | 0x400 | 0x800 | 0x1000

// TestFileAndImageSources creates, writes, renames and deletes a marked file
// and loads a marked DLL, then logs every property Kernel-File and
// Kernel-Process (image load) gave for them, to decide the field mapping of
// the agent's file and image telemetry from evidence.
func TestFileAndImageSources(t *testing.T) {
	fileRec, imgRec := &recorder{}, &recorder{}
	fs, err := Start(Config{Name: "SIEMAgent-Test-File", Providers: []Provider{{GUID: kernelFileProvider,
		Keywords: kernelFileKeywords, EventIDs: []uint16{12, 14, 16, 19, 26, 27, 30}}}}, fileRec.add)
	if err != nil {
		t.Fatalf("file session: %v", err)
	}
	defer fs.Close()
	is, err := Start(Config{Name: "SIEMAgent-Test-Image", Providers: []Provider{{GUID: kernelProcessProvider,
		Keywords: 0x40, EventIDs: []uint16{5}}}}, imgRec.add)
	if err != nil {
		t.Fatalf("image session: %v", err)
	}
	defer is.Close()
	time.Sleep(2 * time.Second)

	marker := fmt.Sprintf("siemetw%d", time.Now().UnixNano())
	dir := t.TempDir()
	created := filepath.Join(dir, marker+".txt")
	renamed := filepath.Join(dir, marker+".locked")
	if err := os.WriteFile(created, []byte("plain text"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(created, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(" appended")
	f.Close()
	if err := os.Rename(created, renamed); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(renamed); err != nil {
		t.Fatal(err)
	}

	sys, _ := windows.GetSystemDirectory()
	dll := filepath.Join(dir, marker+".dll")
	if data, err := os.ReadFile(filepath.Join(sys, "version.dll")); err == nil {
		os.WriteFile(dll, data, 0o644)
	}
	h, err := windows.LoadLibrary(dll)
	if err != nil {
		t.Fatalf("load %s: %v", dll, err)
	}
	windows.FreeLibrary(h)
	pid := uint32(os.Getpid())

	hasMarker := func(e *Event) bool {
		for _, p := range e.Props {
			if strings.Contains(strings.ToLower(p.Value), marker) {
				return true
			}
		}
		return false
	}
	deadline := time.Now().Add(15 * time.Second)
	var image *Event
	for time.Now().Before(deadline) && image == nil {
		time.Sleep(500 * time.Millisecond)
		image = imgRec.find(hasMarker)
	}
	time.Sleep(time.Second) // file events trail the image load

	t.Logf("file session: %d events, %d decode errors; image session: %d events, %d decode errors (test pid %d)",
		len(fileRec.events), fs.DecodeErrors(), len(imgRec.events), is.DecodeErrors(), pid)
	fileRec.mu.Lock()
	objects := map[string]bool{} // FileObject of the marked creates, to find their writes
	byID := map[uint16]int{}
	for _, e := range fileRec.events {
		byID[e.ID]++
		if hasMarker(e) {
			dump(t, fmt.Sprintf("kernel-file id %d", e.ID), e)
			if v, ok := e.Get("FileObject"); ok {
				objects[v] = true
			}
		}
	}
	shown := map[uint16]bool{}
	for _, e := range fileRec.events {
		if v, ok := e.Get("FileObject"); ok && objects[v] && !hasMarker(e) && !shown[e.ID] {
			shown[e.ID] = true
			dump(t, fmt.Sprintf("kernel-file id %d (same FileObject, no name)", e.ID), e)
		}
	}
	t.Logf("kernel-file events by id: %v", byID)
	fileRec.mu.Unlock()

	imgRec.mu.Lock()
	drivers := 0
	for _, e := range imgRec.events {
		if v, _ := e.Get("ProcessID"); (v == "0" || v == "4") && drivers < 2 {
			drivers++
			dump(t, "kernel-process image load in pid 0/4", e)
		}
	}
	imgRec.mu.Unlock()
	if image == nil {
		t.Fatal("no image load event for the marked DLL")
	}
	dump(t, "kernel-process image load", image)
}
