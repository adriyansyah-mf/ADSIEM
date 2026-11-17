package mlscore

import (
	"bytes"
	"math"
	"regexp"
	"strings"
)

// HTML page features (FeaturesHTML) for the HTML model (ml/html/train.py):
// phishing kits, redirectors and HTML smuggling. Static, byte level: no DOM,
// no script runs. The same code feeds training (cmd/htmlfeat writes the
// vectors) and scoring, so the two never differ.
//
// One pass over the tags does most of the work; plain substring counts on
// the lower-cased page do the rest, and the few regular expressions left run
// on script text only (a page of a few hundred KB takes about a millisecond).

// FeaturesHTML names the HTML feature set; a model records it.
const FeaturesHTML = "html1"

// htmlMaxBytes: features read at most this much of a file (pages larger than
// this are rare and still get their size feature).
const htmlMaxBytes = 4 << 20

// HTMLFeatureNames, in vector order.
var HTMLFeatureNames = []string{
	"log_size", "lines", "max_line_len", "avg_line_len", "nonascii_ratio", "byte_entropy",
	"tags", "scripts", "script_src", "script_bytes_ratio", "iframes", "iframe_hidden",
	"forms", "form_action_abs", "form_action_php", "form_action_empty", "inputs", "password_inputs",
	"hidden_inputs", "email_inputs", "links", "links_empty", "links_abs", "distinct_hosts",
	"meta_refresh", "location_assign", "window_open", "document_write", "eval", "atob",
	"unescape", "fromcharcode", "escape_density", "longest_b64", "b64_blobs", "data_uris",
	"blob_api", "download_attr", "msave_blob", "title_len", "title_brand", "body_brand",
	"login_words", "telegram_api", "ajax_post", "fetch_calls", "external_css", "favicon_abs",
	"text_ratio", "longest_string", "has_body", "has_doctype", "onload_handlers", "base_tag",
	"crypto_words", "charcode_ops", "split_reverse_join", "settimeout_redirect",
}

// DimHTML is the vector length.
var DimHTML = len(HTMLFeatureNames)

// on lower-cased script text only
var (
	reLocation   = regexp.MustCompile(`location(\.href)?\s*=[^=]|location\.(replace|assign)\s*\(`)
	reTimeoutLoc = regexp.MustCompile(`settimeout\s*\([^)]{0,300}location`)
	reAjaxPost   = regexp.MustCompile(`\$\.(ajax|post)\s*\(|type\s*:\s*["']post["']|method\s*:\s*["']post["']`)
)

var htmlBrands = []string{"paypal", "microsoft", "office 365", "office365", "outlook", "onedrive", "sharepoint",
	"apple", "icloud", "google", "gmail", "amazon", "netflix", "facebook", "instagram", "whatsapp", "linkedin",
	"dropbox", "docusign", "adobe", "wells fargo", "chase", "bank of america", "dhl", "fedex", "usps", "binance",
	"coinbase", "metamask", "webmail", "roundcube", "zimbra", "bca", "mandiri", "bank bri", "bni", "dana",
	"ovo", "gopay", "shopee", "tokopedia", "djp", "bpjs"}

var htmlLoginWords = []string{"sign in", "signin", "log in", "login", "password", "passcode", "verify your",
	"verification", "confirm your", "account", "suspended", "unusual activity", "update your", "security check",
	"kata sandi", "masuk", "verifikasi", "akun"}

// LooksHTML reports whether a file is an HTML page (or SVG/HTA with markup)
// by its first bytes, or by its name for .htm/.html/.hta/.svg/.xhtml.
func LooksHTML(b []byte, path string) bool {
	p := strings.ToLower(path)
	for _, ext := range []string{".html", ".htm", ".hta", ".xhtml", ".svg", ".shtml"} {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	head := b
	if len(head) > 1024 {
		head = head[:1024]
	}
	head = bytes.ToLower(bytes.TrimLeft(bytes.TrimPrefix(head, []byte("\xef\xbb\xbf")), " \t\r\n"))
	for _, m := range [][]byte{[]byte("<!doctype html"), []byte("<html"), []byte("<head"), []byte("<script"),
		[]byte("<body"), []byte("<meta"), []byte("<iframe"), []byte("<form"), []byte("<svg")} {
		if bytes.HasPrefix(head, m) {
			return true
		}
	}
	return false
}

func countAny(s string, words []string) float64 {
	n := 0
	for _, w := range words {
		n += strings.Count(s, w)
	}
	return float64(n)
}

// attr returns the value of name= in a lower-cased tag ("" when absent).
func attr(tag, name string) (string, bool) {
	for i := 0; ; {
		j := strings.Index(tag[i:], name)
		if j < 0 {
			return "", false
		}
		j += i
		k := j + len(name)
		if (j == 0 || !isAlnum(tag[j-1]) && tag[j-1] != '-') && k < len(tag) {
			for k < len(tag) && tag[k] == ' ' {
				k++
			}
			if k < len(tag) && tag[k] == '=' {
				k++
				for k < len(tag) && tag[k] == ' ' {
					k++
				}
				if k >= len(tag) {
					return "", true
				}
				q := tag[k]
				if q == '"' || q == '\'' {
					e := strings.IndexByte(tag[k+1:], q)
					if e < 0 {
						return tag[k+1:], true
					}
					return tag[k+1 : k+1+e], true
				}
				e := k
				for e < len(tag) && tag[e] != ' ' && tag[e] != '>' && tag[e] != '\t' && tag[e] != '\n' {
					e++
				}
				return tag[k:e], true
			}
		}
		i = j + 1
	}
}

func absURL(v string) bool {
	return strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://") || strings.HasPrefix(v, "//")
}

func isB64(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// ExtractHTML is the FeaturesHTML vector of a page.
func ExtractHTML(b []byte) []float64 {
	size := len(b)
	if len(b) > htmlMaxBytes {
		b = b[:htmlMaxBytes]
	}
	low := strings.ToLower(string(b))
	n := math.Max(float64(len(b)), 1)

	// bytes: lines, entropy, non-ASCII, base64 runs, escapes, quoted strings
	var hist [256]float64
	lines, maxLine, cur := 1, 0, 0
	nonASCII, b64run, longestB64, b64Blobs, escapes := 0, 0, 0, 0, 0
	longestStr, strStart := 0, -1
	var quote byte
	for i, c := range b {
		hist[c]++
		if c >= 0x80 {
			nonASCII++
		}
		if c == '\n' {
			lines++
			cur = 0
			quote, strStart = 0, -1
		} else {
			cur++
			if cur > maxLine {
				maxLine = cur
			}
		}
		if isB64(c) {
			b64run++
		} else {
			if b64run >= 100 {
				b64Blobs++
				if b64run > longestB64 {
					longestB64 = b64run
				}
			}
			b64run = 0
		}
		switch {
		case c == '\\' && i+1 < len(b) && (b[i+1] == 'x' || b[i+1] == 'u') && i+3 < len(b) && isHex(b[i+2]) && isHex(b[i+3]):
			escapes++
		case c == '%' && i+2 < len(b) && isHex(b[i+1]) && isHex(b[i+2]):
			escapes++
		case c == '&' && i+2 < len(b) && b[i+1] == '#':
			escapes++
		}
		if c == '"' || c == '\'' {
			switch {
			case quote == 0:
				quote, strStart = c, i
			case quote == c:
				if l := i - strStart + 1; l > longestStr {
					longestStr = l
				}
				quote, strStart = 0, -1
			}
		}
	}
	if b64run >= 100 {
		b64Blobs++
		if b64run > longestB64 {
			longestB64 = b64run
		}
	}
	ent := 0.0
	for _, h := range hist {
		if h > 0 {
			p := h / n
			ent -= p * math.Log2(p)
		}
	}

	// one pass over the tags
	var tags, scripts, scriptSrc, iframes, iframeHidden, forms, actAbs, actPHP, actEmpty float64
	var inputs, pw, hiddenIn, email, links, linksEmpty, linksAbs, metaRefresh, css, favicon, onload, base float64
	var scriptText strings.Builder
	scriptBytes, textBytes := 0, 0
	title := ""
	for i := 0; i < len(low); {
		lt := strings.IndexByte(low[i:], '<')
		if lt < 0 {
			textBytes += len(strings.TrimSpace(low[i:]))
			break
		}
		textBytes += len(strings.TrimSpace(low[i : i+lt]))
		i += lt
		if i+1 >= len(low) {
			break
		}
		c := low[i+1]
		if !(c >= 'a' && c <= 'z' || c == '!' || c == '/') {
			i++
			continue
		}
		gt := strings.IndexByte(low[i:], '>')
		if gt < 0 {
			break
		}
		tag := low[i : i+gt+1]
		end := i + gt + 1
		tags++
		name := tag[1:]
		if k := strings.IndexAny(name, " \t\r\n/>"); k > 0 {
			name = name[:k]
		}
		if strings.Contains(tag, " onload=") || strings.Contains(tag, " onerror=") ||
			strings.Contains(tag, " onmouseover=") || strings.Contains(tag, " onfocus=") {
			onload++
		}
		switch name {
		case "script":
			scripts++
			if _, ok := attr(tag, "src"); ok {
				scriptSrc++
			}
			if e := strings.Index(low[end:], "</script"); e >= 0 {
				scriptBytes += e
				if scriptText.Len() < htmlMaxBytes {
					scriptText.WriteString(low[end : end+e])
					scriptText.WriteByte('\n')
				}
				end += e
			}
		case "style":
			if e := strings.Index(low[end:], "</style"); e >= 0 {
				end += e
			}
		case "title":
			if e := strings.Index(low[end:], "</title"); e >= 0 && title == "" {
				title = strings.TrimSpace(low[end : end+e])
			}
		case "iframe":
			iframes++
			if strings.Contains(tag, "display:none") || strings.Contains(tag, "display: none") ||
				strings.Contains(tag, "visibility:hidden") || strings.Contains(tag, " hidden") {
				iframeHidden++
			} else if w, ok := attr(tag, "width"); ok && (w == "0" || w == "1") {
				iframeHidden++
			} else if h, ok := attr(tag, "height"); ok && (h == "0" || h == "1") {
				iframeHidden++
			}
		case "form":
			forms++
			a, _ := attr(tag, "action")
			switch {
			case a == "" || a == "#":
				actEmpty++
			default:
				if absURL(a) {
					actAbs++
				}
				if strings.Contains(a, ".php") {
					actPHP++
				}
			}
		case "input":
			inputs++
			switch t, _ := attr(tag, "type"); t {
			case "password":
				pw++
			case "hidden":
				hiddenIn++
			case "email":
				email++
			}
		case "a":
			if h, ok := attr(tag, "href"); ok {
				links++
				if h == "" || h == "#" || strings.HasPrefix(h, "javascript:") {
					linksEmpty++
				}
				if absURL(h) {
					linksAbs++
				}
			}
		case "meta":
			if v, _ := attr(tag, "http-equiv"); v == "refresh" {
				metaRefresh++
			}
		case "link":
			rel, _ := attr(tag, "rel")
			href, _ := attr(tag, "href")
			if strings.Contains(rel, "stylesheet") && absURL(href) {
				css++
			}
			if strings.Contains(rel, "icon") && absURL(href) {
				favicon++
			}
		case "base":
			base = 1
		}
		i = end
	}
	st := scriptText.String()

	// hosts of absolute URLs anywhere
	hosts := map[string]bool{}
	for i, seen := 0, 0; seen < 2000; seen++ {
		j := strings.Index(low[i:], "://")
		if j < 0 {
			break
		}
		j += i + 3
		k := j
		for k < len(low) && k-j < 253 && (isAlnum(low[k]) || low[k] == '.' || low[k] == '-') {
			k++
		}
		if k > j && j >= 7 && (strings.HasSuffix(low[:j], "http://") || strings.HasSuffix(low[:j], "https://")) {
			hosts[low[j:k]] = true
		}
		i = k
	}

	titleBrand, bodyBrand := 0.0, 0.0
	for _, br := range htmlBrands {
		if len(br) > 3 && strings.Contains(title, br) || len(br) <= 3 && containsWord(title, br) {
			titleBrand = 1
		}
		if len(br) > 3 && strings.Contains(low, br) || len(br) <= 3 && containsWord(low, br) {
			bodyBrand++
		}
	}

	b2f := func(v bool) float64 {
		if v {
			return 1
		}
		return 0
	}
	cnt := func(s string) float64 { return float64(strings.Count(low, s)) }
	re := func(r *regexp.Regexp) float64 { return float64(len(r.FindAllStringIndex(st, -1))) }
	return []float64{
		math.Log1p(float64(size)),
		float64(lines),
		float64(maxLine),
		n / float64(lines),
		float64(nonASCII) / n,
		ent,
		tags,
		scripts,
		scriptSrc,
		float64(scriptBytes) / n,
		iframes,
		iframeHidden,
		forms,
		actAbs,
		actPHP,
		actEmpty,
		inputs,
		pw,
		hiddenIn,
		email,
		links,
		linksEmpty,
		linksAbs,
		float64(len(hosts)),
		metaRefresh,
		re(reLocation),
		cnt("window.open("),
		cnt("document.write"),
		cnt("eval("),
		cnt("atob("),
		cnt("unescape(") + cnt("decodeuricomponent("),
		cnt("fromcharcode"),
		float64(escapes) / n * 1000,
		float64(longestB64),
		float64(b64Blobs),
		cnt(";base64,"),
		float64(strings.Count(st, "new blob(") + strings.Count(st, "createobjecturl")),
		cnt(" download=") + cnt(".download=") + cnt(".download ="),
		cnt("mssaveoropenblob") + cnt("mssaveblob"),
		float64(len(title)),
		titleBrand,
		bodyBrand,
		countAny(low, htmlLoginWords),
		cnt("api.telegram.org"),
		re(reAjaxPost),
		cnt("fetch("),
		css,
		favicon,
		float64(textBytes) / n,
		float64(longestStr),
		b2f(strings.Contains(low, "<body")),
		b2f(strings.Contains(low[:min(len(low), 512)], "<!doctype")),
		onload,
		base,
		countAny(low, []string{"seed phrase", "recovery phrase", "private key", "wallet connect", "walletconnect"}),
		cnt("charcodeat"),
		cnt(".split(\"\").reverse().join") + cnt(".split('').reverse().join"),
		re(reTimeoutLoc),
	}
}

func containsWord(s, w string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		j += i
		before := j == 0 || !isAlnum(s[j-1])
		after := j+len(w) >= len(s) || !isAlnum(s[j+len(w)])
		if before && after {
			return true
		}
		i = j + 1
	}
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
