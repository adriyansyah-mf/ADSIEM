package notify

import (
	"testing"
	"time"
)

func TestSetEnabledFollowsThePolicy(t *testing.T) {
	n := &Notifier{recent: map[string]time.Time{}, now: time.Now, show: func(_, _ string) error { return nil }}
	n.SetEnabled(false)
	if n.allow("a") {
		t.Fatal("policy off: no pop-ups")
	}
	n.SetEnabled(true)
	if !n.allow("a") {
		t.Fatal("back on")
	}
	var none *Notifier
	none.SetEnabled(false) // no notifier on this platform: no panic
}
