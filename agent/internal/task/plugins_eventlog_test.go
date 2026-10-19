package task

import "testing"

func TestEventlogXPath(t *testing.T) {
	cases := []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"event_ids": "4625", "hours": "24"},
			"*[System[(EventID=4625) and TimeCreated[timediff(@SystemTime) <= 86400000]]]"},
		{map[string]any{"event_ids": []any{"4624", "4625"}, "hours": 1},
			"*[System[(EventID=4624 or EventID=4625) and TimeCreated[timediff(@SystemTime) <= 3600000]]]"},
		{map[string]any{"event_ids": "1102, 104", "hours": 0}, "*[System[(EventID=1102 or EventID=104)]]"},
		{map[string]any{"hours": 0}, "*"},
		{map[string]any{"xpath": "*[System[Level=2]]", "event_ids": "1"}, "*[System[Level=2]]"},
	}
	for _, c := range cases {
		got, err := eventlogXPath(c.args)
		if err != nil || got != c.want {
			t.Errorf("eventlogXPath(%v) = %q, %v; want %q", c.args, got, err, c.want)
		}
	}
	// parameters are never spliced into XPath unchecked
	if _, err := eventlogXPath(map[string]any{"event_ids": "4625]] or [[1=1"}); err == nil {
		t.Error("non-numeric event id accepted")
	}
}
