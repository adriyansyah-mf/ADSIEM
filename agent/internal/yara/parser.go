package yara

import (
	"fmt"
	"strings"
)

var keywords = map[string]bool{
	"all": true, "and": true, "any": true, "ascii": true, "at": true, "base64": true,
	"base64wide": true, "condition": true, "contains": true, "defined": true,
	"endswith": true, "entrypoint": true, "false": true, "filesize": true, "for": true,
	"fullword": true, "global": true, "import": true, "icontains": true, "iendswith": true,
	"iequals": true, "in": true, "include": true, "int16": true, "int16be": true,
	"int32": true, "int32be": true, "int8": true, "int8be": true, "istartswith": true,
	"matches": true, "meta": true, "nocase": true, "none": true, "not": true, "of": true,
	"or": true, "private": true, "rule": true, "startswith": true, "strings": true,
	"them": true, "true": true, "uint16": true, "uint16be": true, "uint32": true,
	"uint32be": true, "uint8": true, "uint8be": true, "wide": true, "xor": true,
}

type parser struct {
	lx       lexer
	tok      token
	tokState lexState // lexer state before tok, to re-lex it as a regex

	ns      string
	rules   []*rule
	byName  map[string]*rule
	imports map[string]*module

	cur        *rule
	referenced map[*stringDef]bool
	vars       []*loopVar // loop variables in scope, innermost last
	forOfDepth int
	maxVars    int
	noOf       bool // parsing a for-quantifier: "<n> of" is not an of-expression
}

// parseSource parses one rule source. Rules are appended to the
// namespace's rule list; firstIdx is the global index of the first one.
func parseSource(src, ns string, firstIdx int) (rules []*rule, maxVars int, err error) {
	p := &parser{
		lx:      lexer{src: src, line: 1},
		ns:      ns,
		byName:  map[string]*rule{},
		imports: map[string]*module{},
	}
	defer func() {
		if r := recover(); r != nil {
			e, ok := r.(*Error)
			if !ok {
				panic(r)
			}
			rules, err = nil, e
		}
	}()
	p.advance()
	for p.tok.kind != tEOF {
		switch {
		case p.isIdent("import"):
			p.advance()
			if p.tok.kind != tText {
				p.fail("expected module name after import")
			}
			m, ok := modules[p.tok.s]
			if !ok {
				p.fail("unknown module %q (supported: %s)", p.tok.s, strings.Join(SupportedModules(), ", "))
			}
			p.imports[m.name] = m
			p.advance()
		case p.isIdent("include"):
			p.fail("include is not supported")
		default:
			r := p.parseRule()
			r.idx = firstIdx + len(p.rules)
			p.rules = append(p.rules, r)
		}
	}
	return p.rules, p.maxVars, nil
}

func (p *parser) fail(format string, args ...any) {
	panic(&Error{Line: p.tok.line, Msg: fmt.Sprintf(format, args...)})
}

func (p *parser) advance() {
	p.tokState = p.lx.save()
	t, err := p.lx.next()
	if err != nil {
		panic(err)
	}
	p.tok = t
}

func (p *parser) isIdent(s string) bool { return p.tok.kind == tIdent && p.tok.s == s }
func (p *parser) isPunct(s string) bool { return p.tok.kind == tPunct && p.tok.s == s }

func (p *parser) expectPunct(s string) {
	if !p.isPunct(s) {
		p.fail("expected %q, found %s", s, p.tok)
	}
	p.advance()
}

func (p *parser) expectIdent(s string) {
	if !p.isIdent(s) {
		p.fail("expected %q, found %s", s, p.tok)
	}
	p.advance()
}

func (p *parser) parseRule() *rule {
	r := &rule{ns: p.ns, line: p.tok.line}
	for p.isIdent("private") || p.isIdent("global") {
		if p.tok.s == "private" {
			r.private = true
		} else {
			r.global = true
		}
		p.advance()
	}
	p.expectIdent("rule")
	if p.tok.kind != tIdent || keywords[p.tok.s] {
		p.fail("expected rule name, found %s", p.tok)
	}
	r.name = p.tok.s
	if _, dup := p.byName[r.name]; dup {
		p.fail("duplicated rule %q", r.name)
	}
	p.advance()
	if p.isPunct(":") {
		p.advance()
		for p.tok.kind == tIdent && !keywords[p.tok.s] {
			r.tags = append(r.tags, p.tok.s)
			p.advance()
		}
		if len(r.tags) == 0 {
			p.fail("expected tag after ':'")
		}
	}
	p.expectPunct("{")
	p.cur = r
	p.referenced = map[*stringDef]bool{}
	if p.isIdent("meta") {
		p.advance()
		p.expectPunct(":")
		p.parseMeta(r)
	}
	if p.isIdent("strings") {
		p.advance()
		p.expectPunct(":")
		p.parseStrings(r)
	}
	p.expectIdent("condition")
	p.expectPunct(":")
	r.cond = p.parseExpr()
	p.boolish(r.cond)
	p.expectPunct("}")
	for _, s := range r.strs {
		if s.id != "" && !p.referenced[s] {
			panic(&Error{Line: s.line, Msg: fmt.Sprintf("unreferenced string $%s in rule %s", s.id, r.name)})
		}
	}
	p.byName[r.name] = r
	p.cur = nil
	return r
}

func (p *parser) parseMeta(r *rule) {
	for p.tok.kind == tIdent && !p.isIdent("strings") && !p.isIdent("condition") {
		key := p.tok.s
		p.advance()
		p.expectPunct("=")
		neg := false
		if p.isPunct("-") {
			neg = true
			p.advance()
		}
		var v any
		switch {
		case p.tok.kind == tText && !neg:
			v = p.tok.s
		case p.tok.kind == tInt:
			if neg {
				v = -p.tok.i
			} else {
				v = p.tok.i
			}
		case p.isIdent("true") && !neg:
			v = true
		case p.isIdent("false") && !neg:
			v = false
		default:
			p.fail("invalid meta value for %q", key)
		}
		r.meta = append(r.meta, Meta{Key: key, Value: v})
		p.advance()
	}
}

func (p *parser) parseStrings(r *rule) {
	seen := map[string]bool{}
	for p.tok.kind == tStrID {
		s := &stringDef{id: p.tok.s, line: p.tok.line}
		if p.tok.wild {
			p.fail("invalid string identifier $%s*", s.id)
		}
		if s.id != "" {
			if seen[s.id] {
				p.fail("duplicated string identifier $%s", s.id)
			}
			seen[s.id] = true
		}
		p.advance()
		if !p.isPunct("=") {
			p.fail("expected '=' after $%s", s.id)
		}
		// Look at the raw input: the value may be a regex or hex string,
		// which the token lexer cannot read.
		switch p.lx.peekByte() {
		case '/':
			t, err := p.lx.regex()
			if err != nil {
				panic(err)
			}
			s.kind, s.src = strRegex, t.s
			s.nocase = strings.Contains(t.re, "i")
			s.dotall = strings.Contains(t.re, "s")
			s.regexWindow = regexScanLimit
			p.advance()
			p.parseModifiers(s)
		case '{':
			p.advance() // the '{'
			body, err := p.lx.hexBody()
			if err != nil {
				panic(err)
			}
			s.kind, s.src = strHex, body
			p.advance()
			p.parseModifiers(s)
		default:
			p.advance()
			if p.tok.kind != tText {
				p.fail("expected string value for $%s", s.id)
			}
			if p.tok.s == "" {
				p.fail("empty string $%s", s.id)
			}
			s.kind, s.src = strText, p.tok.s
			p.advance()
			p.parseModifiers(s)
		}
		if err := compileString(s); err != nil {
			panic(&Error{Line: s.line, Msg: fmt.Sprintf("string $%s: %v", s.id, err)})
		}
		r.strs = append(r.strs, s)
	}
}

func (p *parser) parseModifiers(s *stringDef) {
	seen := map[string]bool{}
	for p.tok.kind == tIdent {
		m := p.tok.s
		if m != "nocase" && m != "wide" && m != "ascii" && m != "fullword" && m != "private" &&
			m != "xor" && m != "base64" && m != "base64wide" {
			break
		}
		if seen[m] {
			p.fail("duplicated modifier %s", m)
		}
		seen[m] = true
		allowed := true
		switch s.kind {
		case strHex:
			allowed = m == "private"
		case strRegex:
			allowed = m != "xor" && m != "base64" && m != "base64wide"
		}
		if !allowed {
			p.fail("modifier %s is not valid for this string type", m)
		}
		p.advance()
		switch m {
		case "nocase":
			s.nocase = true
		case "wide":
			s.wide = true
		case "ascii":
			s.ascii = true
		case "fullword":
			s.fullword = true
		case "private":
			s.private = true
		case "xor":
			s.xor, s.xorMin, s.xorMax = true, 0, 255
			if p.isPunct("(") {
				p.advance()
				s.xorMin = p.byteArg()
				s.xorMax = s.xorMin
				if p.isPunct("-") {
					p.advance()
					s.xorMax = p.byteArg()
				}
				if s.xorMax < s.xorMin {
					p.fail("invalid xor range")
				}
				p.expectPunct(")")
			}
		case "base64", "base64wide":
			if m == "base64" {
				s.base64 = true
			} else {
				s.base64wide = true
			}
			if p.isPunct("(") {
				p.advance()
				if p.tok.kind != tText || len(p.tok.s) != 64 {
					p.fail("base64 alphabet must be 64 bytes")
				}
				if s.b64alpha != "" && s.b64alpha != p.tok.s {
					p.fail("base64 and base64wide must use the same alphabet")
				}
				s.b64alpha = p.tok.s
				p.advance()
				p.expectPunct(")")
			}
		}
	}
	if s.xor && s.nocase {
		p.fail("xor and nocase cannot be combined")
	}
	if (s.base64 || s.base64wide) && (s.nocase || s.xor || s.fullword) {
		p.fail("base64 cannot be combined with nocase, xor or fullword")
	}
}

func (p *parser) byteArg() int {
	if p.tok.kind != tInt || p.tok.i < 0 || p.tok.i > 255 {
		p.fail("xor key must be 0-255")
	}
	v := int(p.tok.i)
	p.advance()
	return v
}

// ─── expressions ─────────────────────────────────────────────────────

func (p *parser) parseExpr() expr {
	x := p.parseAnd()
	for p.isIdent("or") {
		p.advance()
		y := p.parseAnd()
		p.boolish(x)
		p.boolish(y)
		x = &binExpr{op: "or", l: x, r: y, t: tyBool}
	}
	return x
}

func (p *parser) parseAnd() expr {
	x := p.parseNot()
	for p.isIdent("and") {
		p.advance()
		y := p.parseNot()
		p.boolish(x)
		p.boolish(y)
		x = &binExpr{op: "and", l: x, r: y, t: tyBool}
	}
	return x
}

func (p *parser) parseNot() expr {
	switch {
	case p.isIdent("not"):
		p.advance()
		x := p.parseNot()
		p.boolish(x)
		return &unExpr{op: "not", x: x, t: tyBool}
	case p.isIdent("defined"):
		p.advance()
		return &definedExpr{x: p.parseNot()}
	}
	return p.parseEq()
}

var strOps = map[string]bool{
	"contains": true, "icontains": true, "startswith": true, "istartswith": true,
	"endswith": true, "iendswith": true, "iequals": true,
}

func (p *parser) parseEq() expr {
	x := p.parseRel()
	for {
		switch {
		case p.isPunct("==") || p.isPunct("!="):
			op := p.tok.s
			p.advance()
			y := p.parseRel()
			x = p.comparison(op, x, y)
		case p.tok.kind == tIdent && strOps[p.tok.s]:
			op := p.tok.s
			p.advance()
			y := p.parseRel()
			if x.typ() != tyStr || y.typ() != tyStr {
				p.fail("operator %s needs string operands", op)
			}
			x = &binExpr{op: op, l: x, r: y, t: tyBool}
		case p.isIdent("matches"):
			p.advance()
			if x.typ() != tyStr {
				p.fail("matches needs a string on the left")
			}
			if !p.isPunct("/") {
				p.fail("expected regular expression after matches")
			}
			p.lx.restore(p.tokState)
			t, err := p.lx.regex()
			if err != nil {
				panic(err)
			}
			prog, err := compileRegex(t.s, strings.Contains(t.re, "i"), strings.Contains(t.re, "s"), false)
			if err != nil {
				p.fail("invalid regular expression: %v", err)
			}
			p.advance()
			x = &matchesExpr{x: x, re: prog}
		default:
			return x
		}
	}
}

func (p *parser) parseRel() expr {
	x := p.parseBitOr()
	for p.isPunct("<") || p.isPunct("<=") || p.isPunct(">") || p.isPunct(">=") {
		op := p.tok.s
		p.advance()
		y := p.parseBitOr()
		x = p.comparison(op, x, y)
	}
	return x
}

func (p *parser) comparison(op string, x, y expr) expr {
	xt, yt := x.typ(), y.typ()
	switch {
	case isNum(xt) && isNum(yt):
	case xt == tyStr && yt == tyStr:
	default:
		p.fail("cannot compare %s and %s with %s", xt, yt, op)
	}
	return &binExpr{op: op, l: x, r: y, t: tyBool}
}

func isNum(t vtype) bool { return t == tyInt || t == tyFloat }

func (p *parser) intBinary(next func() expr, ops ...string) expr {
	x := next()
	for {
		op := ""
		for _, o := range ops {
			if p.isPunct(o) {
				op = o
			}
		}
		if op == "" {
			return x
		}
		p.advance()
		y := next()
		p.requireType(x, tyInt, op)
		p.requireType(y, tyInt, op)
		x = &binExpr{op: op, l: x, r: y, t: tyInt}
	}
}

func (p *parser) parseBitOr() expr  { return p.intBinary(p.parseBitXor, "|") }
func (p *parser) parseBitXor() expr { return p.intBinary(p.parseBitAnd, "^") }
func (p *parser) parseBitAnd() expr { return p.intBinary(p.parseShift, "&") }
func (p *parser) parseShift() expr  { return p.intBinary(p.parseAdd, "<<", ">>") }

func (p *parser) parseAdd() expr {
	x := p.parseMul()
	for p.isPunct("+") || p.isPunct("-") {
		op := p.tok.s
		p.advance()
		x = p.arith(op, x, p.parseMul())
	}
	return x
}

func (p *parser) parseMul() expr {
	x := p.parseUnary()
	for p.isPunct("*") || p.isPunct("\\") || p.isPunct("%") {
		if p.isPunct("%") && p.noOf && p.percentOf() {
			break // "for 50% of ..." quantifier
		}
		op := p.tok.s
		p.advance()
		y := p.parseUnary()
		if op == "%" {
			p.requireType(x, tyInt, op)
			p.requireType(y, tyInt, op)
			p.checkDivisor(op, y)
			x = &binExpr{op: op, l: x, r: y, t: tyInt}
			continue
		}
		x = p.arith(op, x, y)
	}
	return x
}

func (p *parser) arith(op string, x, y expr) expr {
	if !isNum(x.typ()) || !isNum(y.typ()) {
		p.fail("operator %s needs numeric operands, got %s and %s", op, x.typ(), y.typ())
	}
	p.checkDivisor(op, y)
	t := tyInt
	if x.typ() == tyFloat || y.typ() == tyFloat {
		t = tyFloat
	}
	return &binExpr{op: op, l: x, r: y, t: t}
}

// checkDivisor rejects a literal zero divisor, as libyara does.
func (p *parser) checkDivisor(op string, y expr) {
	if op != "\\" && op != "%" {
		return
	}
	switch v := y.(type) {
	case *intLit:
		if v.v == 0 {
			p.fail("division by zero")
		}
	case *floatLit:
		if v.v == 0 {
			p.fail("division by zero")
		}
	}
}

// checkRange rejects a literal range whose bounds are reversed.
func (p *parser) checkRange(lo, hi expr) {
	l, ok1 := lo.(*intLit)
	h, ok2 := hi.(*intLit)
	if ok1 && ok2 && l.v > h.v {
		p.fail("range lower bound must be less than upper bound")
	}
}

func (p *parser) parseUnary() expr {
	switch {
	case p.isPunct("-"):
		p.advance()
		x := p.parseUnary()
		if !isNum(x.typ()) {
			p.fail("unary minus needs a number")
		}
		return &unExpr{op: "-", x: x, t: x.typ()}
	case p.isPunct("~"):
		p.advance()
		x := p.parseUnary()
		p.requireType(x, tyInt, "~")
		return &unExpr{op: "~", x: x, t: tyInt}
	}
	return p.parsePrimary()
}

func (p *parser) requireType(x expr, t vtype, ctx string) {
	if x.typ() != t {
		p.fail("%s needs %s, got %s", ctx, t, x.typ())
	}
}

// boolish accepts any expression usable as a condition. YARA casts
// integers, floats and strings to boolean.
func (p *parser) boolish(x expr) {
	switch x.typ() {
	case tyBool, tyInt, tyFloat, tyStr:
		return
	}
	p.fail("expression of type %s cannot be used as a condition", x.typ())
}

var intFuncs = map[string]readInt{
	"uint8": {size: 1}, "uint16": {size: 2}, "uint32": {size: 4},
	"int8": {size: 1, signed: true}, "int16": {size: 2, signed: true}, "int32": {size: 4, signed: true},
	"uint8be": {size: 1, be: true}, "uint16be": {size: 2, be: true}, "uint32be": {size: 4, be: true},
	"int8be": {size: 1, signed: true, be: true}, "int16be": {size: 2, signed: true, be: true}, "int32be": {size: 4, signed: true, be: true},
}

func (p *parser) parsePrimary() expr {
	t := p.tok
	switch t.kind {
	case tInt:
		p.advance()
		return p.maybeOf(&intLit{v: t.i})
	case tFloat:
		p.advance()
		return &floatLit{v: t.f}
	case tText:
		p.advance()
		return &strLit{v: t.s}
	case tStrID:
		if t.wild {
			p.fail("$%s* is only valid in a string set", t.s)
		}
		s := p.findString(t.s)
		p.advance()
		m := &strMatch{s: s}
		switch {
		case p.isIdent("at"):
			p.advance()
			m.at = p.parseBitOr()
			p.requireType(m.at, tyInt, "at")
		case p.isIdent("in"):
			p.advance()
			m.in = p.parseRange()
		}
		if lit, ok := m.at.(*intLit); ok && s != nil {
			markFixed(s, lit.v)
		} else if s != nil {
			s.fixed = fixedNo
		}
		return m
	case tStrCount:
		s := p.lookupString(t.s)
		p.advance()
		c := &strCount{s: s}
		if p.isIdent("in") {
			p.advance()
			c.in = p.parseRange()
		}
		return c
	case tStrOffset, tStrLength:
		s := p.lookupString(t.s)
		p.advance()
		var idx expr
		if p.isPunct("[") {
			p.advance()
			idx = p.parseBitOr()
			p.requireType(idx, tyInt, "string index")
			p.expectPunct("]")
		}
		if t.kind == tStrOffset {
			return &strOffset{s: s, idx: idx}
		}
		return &strLength{s: s, idx: idx}
	case tPunct:
		if t.s == "(" {
			p.advance()
			saved := p.noOf
			p.noOf = false
			x := p.parseExpr()
			p.noOf = saved
			p.expectPunct(")")
			return p.maybeOf(x)
		}
		p.fail("unexpected %s", t)
	case tIdent:
		return p.parseIdentExpr()
	}
	p.fail("unexpected %s", t)
	return nil
}

func (p *parser) parseIdentExpr() expr {
	t := p.tok
	switch t.s {
	case "true", "false":
		p.advance()
		return &boolLit{v: t.s == "true"}
	case "filesize":
		p.advance()
		return &filesizeExpr{}
	case "entrypoint":
		p.advance()
		return &entrypointExpr{}
	case "all", "any", "none":
		p.advance()
		q := quant{k: map[string]quantKind{"all": qAll, "any": qAny, "none": qNone}[t.s]}
		return p.parseOf(q)
	case "for":
		return p.parseFor()
	}
	if rf, ok := intFuncs[t.s]; ok {
		p.advance()
		p.expectPunct("(")
		rf.off = p.parseBitOr()
		p.requireType(rf.off, tyInt, t.s)
		p.expectPunct(")")
		return &rf
	}
	if keywords[t.s] {
		p.fail("unexpected keyword %s", t.s)
	}
	p.advance()
	var x expr
	var s *schema
	if v := p.lookupVar(t.s); v != nil {
		x, s = &varRef{v: v}, v.s
	} else if m, ok := p.imports[t.s]; ok {
		x, s = &moduleRef{m: m}, m.schema
		return p.parseMembers(x, s, m)
	} else if r, ok := p.byName[t.s]; ok {
		return p.maybeOf(&ruleRef{r: r})
	} else if _, ok := modules[t.s]; ok {
		p.fail("module %s used without import", t.s)
	} else {
		p.fail("undefined identifier %q", t.s)
	}
	return p.maybeOf(p.parseMembers(x, s, nil))
}

// parseMembers parses .field, [index] and (args) after an identifier.
func (p *parser) parseMembers(x expr, s *schema, m *module) expr {
	for {
		switch {
		case p.isPunct("."):
			p.advance()
			if s.t != tyStruct || p.tok.kind != tIdent {
				p.fail("invalid field access")
			}
			name := p.tok.s
			f, ok := s.fields[name]
			if !ok {
				p.fail("unknown field %q", name)
			}
			p.advance()
			if f.t == tyFunc {
				if m == nil {
					p.fail("%s is not callable here", name)
				}
				x = p.parseCall(m, name, f)
				s = &schema{t: x.typ()}
				continue
			}
			x, s = &member{x: x, name: name, s: f}, f
		case p.isPunct("["):
			p.advance()
			idx := p.parseBitOr()
			p.expectPunct("]")
			switch s.t {
			case tyArray:
				p.requireType(idx, tyInt, "array index")
			case tyDict:
				p.requireType(idx, tyStr, "dictionary key")
			default:
				p.fail("%s cannot be indexed", s.t)
			}
			x, s = &indexExpr{x: x, idx: idx, s: s.elem}, s.elem
		default:
			if _, isMod := x.(*moduleRef); isMod {
				p.fail("module %s cannot be used as a value", m.name)
			}
			return x
		}
	}
}

func (p *parser) parseCall(m *module, name string, f *schema) expr {
	p.expectPunct("(")
	var args []expr
	for !p.isPunct(")") {
		if len(args) > 0 {
			p.expectPunct(",")
		}
		args = append(args, p.parseExpr())
	}
	p.advance()
	for _, o := range f.fns {
		if len(o.args) != len(args) {
			continue
		}
		ok := true
		for i, at := range o.args {
			got := args[i].typ()
			if got != at && !(at == tyFloat && got == tyInt) {
				ok = false
				break
			}
		}
		if ok {
			return &callExpr{m: m, fn: o, args: args}
		}
	}
	types := make([]string, len(args))
	for i, a := range args {
		types[i] = a.typ().String()
	}
	p.fail("no %s.%s(%s)", m.name, name, strings.Join(types, ", "))
	return nil
}

// maybeOf turns "<n> of ..." and "<n>% of ..." into an of-expression.
func (p *parser) maybeOf(x expr) expr {
	if p.noOf {
		return x
	}
	if p.isIdent("of") {
		p.requireType(x, tyInt, "of quantifier")
		return p.parseOf(quant{k: qNum, n: x})
	}
	if p.isPunct("%") {
		st, tok, ts := p.lx.save(), p.tok, p.tokState
		p.advance()
		if p.isIdent("of") {
			p.requireType(x, tyInt, "percentage")
			return p.parseOf(quant{k: qPct, n: x})
		}
		p.lx.restore(st)
		p.tok, p.tokState = tok, ts
	}
	return x
}

func (p *parser) parseOf(q quant) expr {
	p.expectIdent("of")
	o := &ofExpr{q: q}
	if p.isPunct("(") && p.peekIsRuleSet() {
		o.rules = p.parseRuleSet()
		return o
	}
	o.strs = p.parseStringSet()
	switch {
	case p.isIdent("at"):
		p.advance()
		o.at = p.parseBitOr()
		p.requireType(o.at, tyInt, "at")
	case p.isIdent("in"):
		p.advance()
		o.in = p.parseRange()
	}
	return o
}

// percentOf reports whether the current "%" is followed by "of".
func (p *parser) percentOf() bool {
	st, tok, ts := p.lx.save(), p.tok, p.tokState
	p.advance()
	ok := p.isIdent("of")
	p.lx.restore(st)
	p.tok, p.tokState = tok, ts
	return ok
}

func (p *parser) peekIsRuleSet() bool {
	st, tok, ts := p.lx.save(), p.tok, p.tokState
	p.advance()
	isRule := p.tok.kind == tIdent
	p.lx.restore(st)
	p.tok, p.tokState = tok, ts
	return isRule
}

func (p *parser) parseRuleSet() []*rule {
	p.expectPunct("(")
	var out []*rule
	for {
		if p.tok.kind != tIdent {
			p.fail("expected rule name in rule set")
		}
		name := p.tok.s
		p.advance()
		if p.isPunct("*") {
			p.advance()
			n := 0
			for _, r := range p.rules {
				if strings.HasPrefix(r.name, name) {
					out = append(out, r)
					n++
				}
			}
			if n == 0 {
				p.fail("no rule matches %s*", name)
			}
		} else {
			r, ok := p.byName[name]
			if !ok {
				p.fail("undefined rule %q", name)
			}
			out = append(out, r)
		}
		if p.isPunct(")") {
			p.advance()
			return out
		}
		p.expectPunct(",")
	}
}

func (p *parser) parseStringSet() []*stringDef {
	if p.cur == nil {
		p.fail("string set outside a rule")
	}
	if p.isIdent("them") {
		p.advance()
		if len(p.cur.strs) == 0 {
			p.fail("rule %s has no strings for 'them'", p.cur.name)
		}
		for _, s := range p.cur.strs {
			p.referenced[s] = true
		}
		return p.cur.strs
	}
	p.expectPunct("(")
	var out []*stringDef
	for {
		if p.tok.kind != tStrID {
			p.fail("expected string identifier in set, found %s", p.tok)
		}
		if p.tok.wild {
			n := 0
			for _, s := range p.cur.strs {
				if strings.HasPrefix(s.id, p.tok.s) {
					out = append(out, s)
					p.referenced[s] = true
					n++
				}
			}
			if n == 0 {
				p.fail("no string matches $%s*", p.tok.s)
			}
		} else {
			out = append(out, p.lookupString(p.tok.s))
		}
		p.advance()
		if p.isPunct(")") {
			p.advance()
			return out
		}
		p.expectPunct(",")
	}
}

// lookupString resolves a string reference that can match anywhere.
func (p *parser) lookupString(id string) *stringDef {
	s := p.findString(id)
	if s != nil {
		s.fixed = fixedNo
	}
	return s
}

// markFixed records a "$a at <literal>" use. libyara only searches a
// string at that offset when every use of it is such a test.
func markFixed(s *stringDef, off int64) {
	switch {
	case s.fixed == fixedUnset:
		s.fixed, s.fixedOff = fixedYes, off
	case s.fixed == fixedYes && s.fixedOff != off:
		s.fixed = fixedNo
	}
}

func (p *parser) findString(id string) *stringDef {
	if id == "" {
		if p.forOfDepth == 0 {
			p.fail("$ is only valid inside for..of")
		}
		return nil
	}
	if p.cur != nil {
		for _, s := range p.cur.strs {
			if s.id == id {
				p.referenced[s] = true
				return s
			}
		}
	}
	p.fail("undefined string identifier $%s", id)
	return nil
}

func (p *parser) parseRange() *rangeExpr {
	p.expectPunct("(")
	lo := p.parseBitOr()
	p.expectPunct("..")
	hi := p.parseBitOr()
	p.expectPunct(")")
	p.requireType(lo, tyInt, "range")
	p.requireType(hi, tyInt, "range")
	p.checkRange(lo, hi)
	return &rangeExpr{lo: lo, hi: hi}
}

func (p *parser) parseQuant() quant {
	switch {
	case p.isIdent("all"):
		p.advance()
		return quant{k: qAll}
	case p.isIdent("any"):
		p.advance()
		return quant{k: qAny}
	case p.isIdent("none"):
		p.advance()
		return quant{k: qNone}
	}
	p.noOf = true
	n := p.parseBitOr()
	p.noOf = false
	p.requireType(n, tyInt, "quantifier")
	if p.isPunct("%") {
		p.advance()
		return quant{k: qPct, n: n}
	}
	return quant{k: qNum, n: n}
}

func (p *parser) parseFor() expr {
	p.expectIdent("for")
	q := p.parseQuant()
	if p.isIdent("of") {
		p.advance()
		f := &forOfExpr{q: q, strs: p.parseStringSet()}
		p.expectPunct(":")
		p.expectPunct("(")
		p.forOfDepth++
		f.body = p.parseExpr()
		p.forOfDepth--
		p.boolish(f.body)
		p.expectPunct(")")
		return f
	}
	f := &forInExpr{q: q}
	var names []string
	for {
		if p.tok.kind != tIdent || keywords[p.tok.s] {
			p.fail("expected loop variable, found %s", p.tok)
		}
		names = append(names, p.tok.s)
		p.advance()
		if !p.isPunct(",") {
			break
		}
		p.advance()
	}
	p.expectIdent("in")
	var types []*schema
	if p.isPunct("(") {
		p.advance()
		first := p.parseBitOr()
		if p.isPunct("..") {
			p.advance()
			hi := p.parseBitOr()
			p.expectPunct(")")
			p.requireType(first, tyInt, "range")
			p.requireType(hi, tyInt, "range")
			p.checkRange(first, hi)
			f.rng = &rangeExpr{lo: first, hi: hi}
			types = []*schema{sInt()}
		} else {
			f.enum = []expr{first}
			for p.isPunct(",") {
				p.advance()
				f.enum = append(f.enum, p.parseBitOr())
			}
			p.expectPunct(")")
			for _, e := range f.enum {
				if e.typ() != first.typ() || (e.typ() != tyInt && e.typ() != tyStr) {
					p.fail("enumeration items must all be integers or all strings")
				}
			}
			types = []*schema{{t: first.typ()}}
		}
	} else {
		f.iter = p.parseIdentExpr()
		var s *schema
		switch it := f.iter.(type) {
		case *member:
			s = it.s
		case *indexExpr:
			s = it.s
		case *varRef:
			s = it.v.s
		}
		switch {
		case s != nil && s.t == tyArray:
			types = []*schema{s.elem}
		case s != nil && s.t == tyDict:
			types = []*schema{sStr(), s.elem}
		default:
			p.fail("for..in needs a range, enumeration, array or dictionary")
		}
	}
	if len(names) != len(types) {
		p.fail("expected %d loop variable(s), got %d", len(types), len(names))
	}
	for i, n := range names {
		if p.lookupVar(n) != nil {
			p.fail("loop variable %s already defined", n)
		}
		v := &loopVar{name: n, s: types[i], slot: len(p.vars)}
		p.vars = append(p.vars, v)
		f.vars = append(f.vars, v)
	}
	if len(p.vars) > p.maxVars {
		p.maxVars = len(p.vars)
	}
	p.expectPunct(":")
	p.expectPunct("(")
	f.body = p.parseExpr()
	p.boolish(f.body)
	p.expectPunct(")")
	p.vars = p.vars[:len(p.vars)-len(names)]
	return f
}

func (p *parser) lookupVar(name string) *loopVar {
	for i := len(p.vars) - 1; i >= 0; i-- {
		if p.vars[i].name == name {
			return p.vars[i]
		}
	}
	return nil
}
