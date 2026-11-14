package hygiene

import "testing"

func TestUTCOffset(t *testing.T) {
	for in, want := range map[int]string{25200: "+07:00", 0: "+00:00", -16200: "-04:30", 20700: "+05:45"} {
		if got := utcOffset(in); got != want {
			t.Errorf("%d: %q, want %q", in, got, want)
		}
	}
}
