package yara

import (
	"fmt"
	"strconv"
	"strings"
)

type tokKind int

const (
	tEOF       tokKind = iota
	tIdent             // rule names, keywords, module names
	tStrID             // $a, $, $a* (s holds the name without '$')
	tStrCount          // #a
	tStrOffset         // @a
	tStrLength         // !a
	tInt               // integer literal, KB/MB applied
	tFloat             // float literal
	tText              // "..." with escapes decoded
	tRegex             // /.../flags, lexed only on request
	tPunct             // operators and punctuation
)

type token struct {
	kind tokKind
	s    string // identifier, punct, decoded text, regex body
	i    int64
	f    float64
	wild bool   // $a* in a string set
	re   string // regex flags
	line int
}

func (t token) String() string {
	switch t.kind {
	case tEOF:
		return "end of input"
	case tStrID:
		return "$" + t.s
	case tStrCount:
		return "#" + t.s
	case tStrOffset:
		return "@" + t.s
	case tStrLength:
		return "!" + t.s
	case tInt:
		return strconv.FormatInt(t.i, 10)
	case tText:
		return strconv.Quote(t.s)
	}
	return t.s
}

// Error is a compile error with the line it was found on.
type Error struct {
	Line int
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("line %d: %s", e.Line, e.Msg) }

type lexer struct {
	src  string
	pos  int
	line int
}

type lexState struct{ pos, line int }

func (l *lexer) save() lexState     { return lexState{l.pos, l.line} }
func (l *lexer) restore(s lexState) { l.pos, l.line = s.pos, s.line }

func (l *lexer) errf(format string, args ...any) error {
	return &Error{Line: l.line, Msg: fmt.Sprintf(format, args...)}
}

// skipSpace skips whitespace and comments.
func (l *lexer) skipSpace() error {
	for l.pos < len(l.src) {
		c := l.src[l.pos]
		switch {
		case c == '\n':
			l.line++
			l.pos++
		case c == ' ' || c == '\t' || c == '\r':
			l.pos++
		case strings.HasPrefix(l.src[l.pos:], "//"):
			for l.pos < len(l.src) && l.src[l.pos] != '\n' {
				l.pos++
			}
		case strings.HasPrefix(l.src[l.pos:], "/*"):
			end := strings.Index(l.src[l.pos+2:], "*/")
			if end < 0 {
				return l.errf("unterminated comment")
			}
			l.line += strings.Count(l.src[l.pos:l.pos+2+end], "\n")
			l.pos += end + 4
		default:
			return nil
		}
	}
	return nil
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool { return isIdentStart(c) || (c >= '0' && c <= '9') }

func (l *lexer) ident() string {
	start := l.pos
	for l.pos < len(l.src) && isIdentChar(l.src[l.pos]) {
		l.pos++
	}
	return l.src[start:l.pos]
}

var puncts = []string{"..", "<<", ">>", "<=", ">=", "==", "!=", "(", ")", "[", "]", "{", "}", ",", ":", "=", ".", "+", "-", "*", "\\", "%", "&", "|", "^", "~", "<", ">", "/"}

func (l *lexer) next() (token, error) {
	if err := l.skipSpace(); err != nil {
		return token{}, err
	}
	t := token{line: l.line}
	if l.pos >= len(l.src) {
		t.kind = tEOF
		return t, nil
	}
	c := l.src[l.pos]
	switch {
	case isIdentStart(c):
		t.kind, t.s = tIdent, l.ident()
		if len(t.s) > 128 {
			return t, l.errf("identifier too long: %s", t.s)
		}
		return t, nil
	case c == '$' || c == '#' || c == '@' || (c == '!' && !strings.HasPrefix(l.src[l.pos:], "!=")):
		l.pos++
		t.s = l.ident()
		switch c {
		case '$':
			t.kind = tStrID
			if l.pos < len(l.src) && l.src[l.pos] == '*' {
				l.pos++
				t.wild = true
			}
		case '#':
			t.kind = tStrCount
		case '@':
			t.kind = tStrOffset
		case '!':
			t.kind = tStrLength
		}
		return t, nil
	case c >= '0' && c <= '9':
		return l.number()
	case c == '"':
		s, err := l.text()
		t.kind, t.s = tText, s
		return t, err
	}
	for _, p := range puncts {
		if strings.HasPrefix(l.src[l.pos:], p) {
			l.pos += len(p)
			t.kind, t.s = tPunct, p
			return t, nil
		}
	}
	return t, l.errf("unexpected character %q", c)
}

func (l *lexer) number() (token, error) {
	t := token{line: l.line}
	start := l.pos
	src := l.src
	if strings.HasPrefix(src[l.pos:], "0x") || strings.HasPrefix(src[l.pos:], "0o") {
		base := 16
		if src[l.pos+1] == 'o' {
			base = 8
		}
		l.pos += 2
		for l.pos < len(src) && isIdentChar(src[l.pos]) {
			l.pos++
		}
		v, err := strconv.ParseUint(src[start+2:l.pos], base, 64)
		if err != nil {
			return t, l.errf("invalid number %s", src[start:l.pos])
		}
		t.kind, t.i = tInt, int64(v)
		return t, nil
	}
	for l.pos < len(src) && src[l.pos] >= '0' && src[l.pos] <= '9' {
		l.pos++
	}
	// "1.5" is a float, "0..10" is a range.
	if l.pos+1 < len(src) && src[l.pos] == '.' && src[l.pos+1] >= '0' && src[l.pos+1] <= '9' {
		l.pos++
		for l.pos < len(src) && src[l.pos] >= '0' && src[l.pos] <= '9' {
			l.pos++
		}
		f, err := strconv.ParseFloat(src[start:l.pos], 64)
		if err != nil {
			return t, l.errf("invalid number %s", src[start:l.pos])
		}
		t.kind, t.f = tFloat, f
		return t, nil
	}
	v, err := strconv.ParseInt(src[start:l.pos], 10, 64)
	if err != nil {
		return t, l.errf("invalid number %s", src[start:l.pos])
	}
	switch {
	case strings.HasPrefix(src[l.pos:], "KB"):
		v *= 1024
		l.pos += 2
	case strings.HasPrefix(src[l.pos:], "MB"):
		v *= 1024 * 1024
		l.pos += 2
	}
	if l.pos < len(src) && isIdentChar(src[l.pos]) {
		return t, l.errf("invalid number %s%c", src[start:l.pos], src[l.pos])
	}
	t.kind, t.i = tInt, v
	return t, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// text lexes a double-quoted string. The result is raw bytes (\xHH may
// produce any byte), returned in a Go string.
func (l *lexer) text() (string, error) {
	l.pos++ // opening quote
	var b strings.Builder
	for {
		if l.pos >= len(l.src) || l.src[l.pos] == '\n' {
			return "", l.errf("unterminated string")
		}
		c := l.src[l.pos]
		l.pos++
		if c == '"' {
			return b.String(), nil
		}
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		if l.pos >= len(l.src) {
			return "", l.errf("unterminated string")
		}
		e := l.src[l.pos]
		l.pos++
		switch e {
		case '"', '\\':
			b.WriteByte(e)
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'x':
			if l.pos+1 >= len(l.src) {
				return "", l.errf("invalid \\x escape")
			}
			hi, ok1 := hexVal(l.src[l.pos])
			lo, ok2 := hexVal(l.src[l.pos+1])
			if !ok1 || !ok2 {
				return "", l.errf("invalid \\x escape")
			}
			b.WriteByte(hi<<4 | lo)
			l.pos += 2
		default:
			return "", l.errf("invalid escape sequence \\%c", e)
		}
	}
}

// regex lexes /body/flags. The caller has seen that the next character
// is '/'. A "\/" in the body is an escaped slash.
func (l *lexer) regex() (token, error) {
	if err := l.skipSpace(); err != nil {
		return token{}, err
	}
	t := token{kind: tRegex, line: l.line}
	if l.pos >= len(l.src) || l.src[l.pos] != '/' {
		return t, l.errf("expected regular expression")
	}
	l.pos++
	var b strings.Builder
	for {
		if l.pos >= len(l.src) || l.src[l.pos] == '\n' {
			return t, l.errf("unterminated regular expression")
		}
		c := l.src[l.pos]
		l.pos++
		if c == '/' {
			break
		}
		if c == '\\' && l.pos < len(l.src) {
			if l.src[l.pos] == '/' {
				b.WriteByte('/')
				l.pos++
				continue
			}
			b.WriteByte(c)
			c = l.src[l.pos]
			l.pos++
		}
		b.WriteByte(c)
	}
	t.s = b.String()
	if t.s == "" {
		return t, l.errf("empty regular expression")
	}
	for l.pos < len(l.src) && (l.src[l.pos] == 'i' || l.src[l.pos] == 's') {
		t.re += string(l.src[l.pos])
		l.pos++
	}
	return t, nil
}

// hexBody returns the raw text between '{' and '}' of a hex string,
// with comments removed. The caller has consumed the '{'.
func (l *lexer) hexBody() (string, error) {
	var b strings.Builder
	for {
		if l.pos >= len(l.src) {
			return "", l.errf("unterminated hex string")
		}
		switch {
		case l.src[l.pos] == '}':
			l.pos++
			return b.String(), nil
		case strings.HasPrefix(l.src[l.pos:], "//"), strings.HasPrefix(l.src[l.pos:], "/*"):
			if err := l.skipSpace(); err != nil {
				return "", err
			}
			b.WriteByte(' ')
		default:
			if l.src[l.pos] == '\n' {
				l.line++
			}
			b.WriteByte(l.src[l.pos])
			l.pos++
		}
	}
}

func (l *lexer) peekByte() byte {
	if l.skipSpace() != nil || l.pos >= len(l.src) {
		return 0
	}
	return l.src[l.pos]
}
