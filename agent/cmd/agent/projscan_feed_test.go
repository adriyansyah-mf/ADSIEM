package main

import (
	"testing"
	"time"

	"github.com/siem-platform/agent/internal/linsensor"
	"github.com/siem-platform/agent/internal/projscan"
	"github.com/siem-platform/agent/internal/winsensor"
)

// On Windows a clone is seen as git creating .git\HEAD: the file feed hands it
// to the project scanner, also when the anti-ransomware guard is off.
func TestWindowsFileFeedOffersClonesToTheProjectScanner(t *testing.T) {
	projects := projscan.New(projscan.Options{Emit: func(string) {}})
	feed := windowsFileFeed(nil, projects)
	if feed == nil {
		t.Fatal("no feed although the project scanner is on")
	}
	feed(winsensor.FileEvent{Time: time.Now(), PID: 10, Image: `C:\Program Files\Git\mingw64\bin\git.exe`,
		Action: "create", Path: `C:\Users\ana\src\test-task\.git\HEAD`})
	feed(winsensor.FileEvent{Time: time.Now(), PID: 11, Image: `C:\Windows\explorer.exe`,
		Action: "create", Path: `C:\Users\ana\Desktop\a.txt`})
	if projects.InFlight() != 1 { // the clone is being waited on
		t.Fatalf("in flight = %d, want 1", projects.InFlight())
	}
}

func TestWindowsFileFeedStillFeedsTheGuard(t *testing.T) {
	var got []linsensor.FileEvent
	feed := windowsFileFeed(func(e linsensor.FileEvent) { got = append(got, e) }, nil)
	feed(winsensor.FileEvent{Image: `C:\x\a.exe`, Action: "write", Path: `C:\d\f`})
	if len(got) != 1 || got[0].Image != `C:\x\a.exe` || got[0].Action != "write" || got[0].Path != `C:\d\f` {
		t.Fatalf("%+v", got)
	}
	if windowsFileFeed(nil, nil) != nil {
		t.Fatal("both off: no feed")
	}
}
