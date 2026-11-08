package webblock

import "testing"

func TestRenderVectors(t *testing.T) {
	cases := []struct {
		page   string
		values map[string]string
		want   string
	}{
		{"<p>{{ domain }}</p>{{other}}", map[string]string{"domain": "<b>x</b>"}, "<p>&lt;b&gt;x&lt;/b&gt;</p>{{other}}"},
		{"{{domain}}", map[string]string{"domain": "'"}, "&#x27;"},
		{"{{domain}}", map[string]string{"domain": `"`}, "&quot;"},
		{"{{domain}}", map[string]string{"domain": "&amp;<>"}, "&amp;amp;&lt;&gt;"},
		{"{{\t reason \n}}|{{source}}", map[string]string{"reason": "r", "source": "s"}, "r|s"},
		{"{{ time }} {{hostname}} {{contact}}", map[string]string{"time": "t", "hostname": "h"}, "t h "},
		{"{{domain }}{{Domain}}{{ do main }}", map[string]string{"domain": "d"}, "d{{Domain}}{{ do main }}"},
		{"{{domain}}", nil, ""},
	}
	for _, c := range cases {
		if got := Render(c.page, c.values); got != c.want {
			t.Errorf("Render(%q) = %q, want %q", c.page, got, c.want)
		}
	}
}

func TestDocumentWrapper(t *testing.T) {
	want := `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Site blocked</title></head><body><i>a</i></body></html>`
	if got := Document("<i>{{domain}}</i>", map[string]string{"domain": "a"}); got != want {
		t.Fatalf("%s", got)
	}
}
