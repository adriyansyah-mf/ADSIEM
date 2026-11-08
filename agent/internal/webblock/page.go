package webblock

import (
	"regexp"
	"strings"
)

// space is Python's unicode \s, so the placeholder pattern matches the server's
// (server-api/app/services/web_page.py) byte for byte.
const space = `[\t\n\v\f\r \x1c-\x1f\x{85}\x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}]*`

var varPattern = regexp.MustCompile(`\{\{` + space + `(domain|reason|source|time|hostname|contact)` + space + `\}\}`)

var htmlEscaper = strings.NewReplacer(
	"&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#x27;")

// Render fills the template variables, HTML-escaped like Python
// html.escape(quote=True). Unknown placeholders are left as they are.
func Render(page string, values map[string]string) string {
	return varPattern.ReplaceAllStringFunc(page, func(m string) string {
		name := varPattern.FindStringSubmatch(m)[1]
		return htmlEscaper.Replace(values[name])
	})
}

// Document wraps the rendered page like web_page.document().
func Document(page string, values map[string]string) string {
	return `<!doctype html><html><head><meta charset="utf-8">` +
		`<meta name="viewport" content="width=device-width, initial-scale=1">` +
		`<title>Site blocked</title></head><body>` + Render(page, values) + `</body></html>`
}
