package yara

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// truth casts a value to boolean the way YARA does. defined is false
// for undefined values.
func truth(v value) (b, defined bool) {
	switch v.k {
	case tyBool, tyInt:
		return v.i != 0, true
	case tyFloat:
		return v.f != 0, true
	case tyStr:
		return v.s != "", true
	}
	return false, false
}

func toFloat(v value) float64 {
	if v.k == tyFloat {
		return v.f
	}
	return float64(v.i)
}

func (sc *scanCtx) eval(e expr) value {
	switch e := e.(type) {
	case *boolLit:
		return vBool(e.v)
	case *intLit:
		return vInt(e.v)
	case *floatLit:
		return vFloat(e.v)
	case *strLit:
		return vStr(e.v)
	case *filesizeExpr:
		return vInt(int64(len(sc.data)))
	case *entrypointExpr:
		return sc.entrypoint()
	case *strMatch:
		return sc.evalStrMatch(sc.resolve(e.s), e.at, e.in)
	case *strCount:
		ms := sc.stringMatches(sc.resolve(e.s))
		if e.in == nil {
			return vInt(int64(len(ms)))
		}
		lo, hi, ok := sc.evalRange(e.in)
		if !ok {
			return undef
		}
		n := 0
		for _, m := range ms {
			if int64(m.off) >= lo && int64(m.off) <= hi {
				n++
			}
		}
		return vInt(int64(n))
	case *strOffset:
		m, ok := sc.nthMatch(sc.resolve(e.s), e.idx)
		if !ok {
			return undef
		}
		return vInt(int64(m.off))
	case *strLength:
		m, ok := sc.nthMatch(sc.resolve(e.s), e.idx)
		if !ok {
			return undef
		}
		return vInt(int64(m.len))
	case *readInt:
		return sc.evalReadInt(e)
	case *unExpr:
		return sc.evalUnary(e)
	case *binExpr:
		return sc.evalBinary(e)
	case *matchesExpr:
		v := sc.eval(e.x)
		if v.k == tyUndef {
			return undef
		}
		return vBool(e.re.search([]byte(v.s)))
	case *definedExpr:
		return vBool(sc.eval(e.x).k != tyUndef)
	case *ofExpr:
		return sc.evalOf(e)
	case *forOfExpr:
		n, total := 0, len(e.strs)
		for _, s := range e.strs {
			sc.curStr = append(sc.curStr, s)
			b, _ := truth(sc.eval(e.body))
			sc.curStr = sc.curStr[:len(sc.curStr)-1]
			if b {
				n++
			}
		}
		return sc.quantify(e.q, n, total)
	case *forInExpr:
		return sc.evalForIn(e)
	case *ruleRef:
		return vBool(sc.ruleResult(e.r))
	case *varRef:
		return sc.vars[e.v.slot]
	case *moduleRef:
		return sc.module(e.m).root
	case *member:
		if e.s.konst != nil {
			return *e.s.konst
		}
		x := sc.eval(e.x)
		if x.k != tyStruct {
			return undef
		}
		v, ok := x.m[e.name]
		if !ok {
			return undef
		}
		return v
	case *indexExpr:
		x := sc.eval(e.x)
		idx := sc.eval(e.idx)
		if idx.k == tyUndef {
			return undef
		}
		switch x.k {
		case tyArray:
			if idx.i < 0 || idx.i >= int64(len(x.a)) {
				return undef
			}
			return x.a[idx.i]
		case tyDict:
			if v, ok := x.m[idx.s]; ok {
				return v
			}
		}
		return undef
	case *callExpr:
		args := make([]value, len(e.args))
		for i, a := range e.args {
			args[i] = sc.eval(a)
			if args[i].k == tyUndef {
				return undef
			}
			if e.fn.args[i] == tyFloat && args[i].k == tyInt {
				args[i] = vFloat(float64(args[i].i))
			}
		}
		md := sc.module(e.m)
		return e.fn.impl(sc, md.state, args)
	}
	panic("yara: unhandled expression")
}

func (sc *scanCtx) resolve(s *stringDef) *stringDef {
	if s == nil {
		return sc.curStr[len(sc.curStr)-1]
	}
	return s
}

func (sc *scanCtx) evalRange(r *rangeExpr) (lo, hi int64, ok bool) {
	l, h := sc.eval(r.lo), sc.eval(r.hi)
	if l.k == tyUndef || h.k == tyUndef {
		return 0, 0, false
	}
	return l.i, h.i, true
}

func (sc *scanCtx) evalStrMatch(s *stringDef, at expr, in *rangeExpr) value {
	ms := sc.stringMatches(s)
	switch {
	case at != nil:
		off := sc.eval(at)
		if off.k == tyUndef {
			return undef
		}
		for _, m := range ms {
			if int64(m.off) == off.i {
				return vBool(true)
			}
		}
		return vBool(false)
	case in != nil:
		lo, hi, ok := sc.evalRange(in)
		if !ok {
			return undef
		}
		for _, m := range ms {
			if int64(m.off) >= lo && int64(m.off) <= hi {
				return vBool(true)
			}
		}
		return vBool(false)
	}
	return vBool(len(ms) > 0)
}

func (sc *scanCtx) nthMatch(s *stringDef, idx expr) (smatch, bool) {
	i := int64(1)
	if idx != nil {
		v := sc.eval(idx)
		if v.k == tyUndef {
			return smatch{}, false
		}
		i = v.i
	}
	ms := sc.stringMatches(s)
	if i < 1 || i > int64(len(ms)) {
		return smatch{}, false
	}
	return ms[i-1], true
}

func (sc *scanCtx) evalReadInt(e *readInt) value {
	off := sc.eval(e.off)
	if off.k == tyUndef || off.i < 0 || off.i+int64(e.size) > int64(len(sc.data)) {
		return undef
	}
	b := sc.data[off.i : off.i+int64(e.size)]
	var u uint64
	switch {
	case e.size == 1:
		u = uint64(b[0])
	case e.size == 2 && e.be:
		u = uint64(binary.BigEndian.Uint16(b))
	case e.size == 2:
		u = uint64(binary.LittleEndian.Uint16(b))
	case e.be:
		u = uint64(binary.BigEndian.Uint32(b))
	default:
		u = uint64(binary.LittleEndian.Uint32(b))
	}
	if !e.signed {
		return vInt(int64(u))
	}
	switch e.size {
	case 1:
		return vInt(int64(int8(u)))
	case 2:
		return vInt(int64(int16(u)))
	}
	return vInt(int64(int32(u)))
}

func (sc *scanCtx) evalUnary(e *unExpr) value {
	x := sc.eval(e.x)
	if x.k == tyUndef {
		return undef
	}
	switch e.op {
	case "not":
		b, _ := truth(x)
		return vBool(!b)
	case "-":
		if x.k == tyFloat {
			return vFloat(-x.f)
		}
		return vInt(-x.i)
	case "~":
		return vInt(^x.i)
	}
	panic("yara: bad unary " + e.op)
}

func (sc *scanCtx) evalBinary(e *binExpr) value {
	switch e.op {
	// libyara 4.5 reads an undefined operand of "and"/"or" as false;
	// the result is always defined. Only "not" propagates undefined.
	case "and":
		if lb, _ := truth(sc.eval(e.l)); !lb {
			return vBool(false)
		}
		rb, _ := truth(sc.eval(e.r))
		return vBool(rb)
	case "or":
		if lb, _ := truth(sc.eval(e.l)); lb {
			return vBool(true)
		}
		rb, _ := truth(sc.eval(e.r))
		return vBool(rb)
	}
	l, r := sc.eval(e.l), sc.eval(e.r)
	if l.k == tyUndef || r.k == tyUndef {
		return undef
	}
	if l.k == tyStr && r.k == tyStr {
		return stringOp(e.op, l.s, r.s)
	}
	if e.op == "==" || e.op == "!=" || e.op == "<" || e.op == "<=" || e.op == ">" || e.op == ">=" {
		if l.k == tyFloat || r.k == tyFloat {
			a, b := toFloat(l), toFloat(r)
			return vBool(cmp(e.op, compareF(a, b)))
		}
		return vBool(cmp(e.op, compareI(l.i, r.i)))
	}
	if e.t == tyFloat {
		a, b := toFloat(l), toFloat(r)
		switch e.op {
		case "+":
			return vFloat(a + b)
		case "-":
			return vFloat(a - b)
		case "*":
			return vFloat(a * b)
		case "\\":
			if b == 0 {
				return undef
			}
			return vFloat(a / b)
		}
	}
	a, b := l.i, r.i
	switch e.op {
	case "+":
		return vInt(a + b)
	case "-":
		return vInt(a - b)
	case "*":
		return vInt(a * b)
	case "\\":
		if b == 0 {
			return undef
		}
		return vInt(a / b)
	case "%":
		if b == 0 {
			return undef
		}
		return vInt(a % b)
	case "&":
		return vInt(a & b)
	case "|":
		return vInt(a | b)
	case "^":
		return vInt(a ^ b)
	case "<<":
		if b < 0 {
			return undef
		}
		if b >= 64 {
			return vInt(0)
		}
		return vInt(a << b)
	case ">>":
		if b < 0 {
			return undef
		}
		if b >= 64 {
			return vInt(0)
		}
		return vInt(a >> b)
	}
	panic("yara: bad binary " + e.op)
}

func compareI(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func compareF(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmp(op string, c int) bool {
	switch op {
	case "==":
		return c == 0
	case "!=":
		return c != 0
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	}
	return c >= 0
}

func stringOp(op, a, b string) value {
	la, lb := func() string { return string(lowerASCII([]byte(a))) }, func() string { return string(lowerASCII([]byte(b))) }
	switch op {
	case "contains":
		return vBool(strings.Contains(a, b))
	case "icontains":
		return vBool(strings.Contains(la(), lb()))
	case "startswith":
		return vBool(strings.HasPrefix(a, b))
	case "istartswith":
		return vBool(strings.HasPrefix(la(), lb()))
	case "endswith":
		return vBool(strings.HasSuffix(a, b))
	case "iendswith":
		return vBool(strings.HasSuffix(la(), lb()))
	case "iequals":
		return vBool(la() == lb())
	}
	return vBool(cmp(op, bytes.Compare([]byte(a), []byte(b))))
}

// quantify applies a quantifier to n hits out of total.
func (sc *scanCtx) quantify(q quant, n, total int) value {
	switch q.k {
	case qAll:
		return vBool(n == total)
	case qAny:
		return vBool(n > 0)
	case qNone:
		return vBool(n == 0)
	}
	v := sc.eval(q.n)
	if v.k == tyUndef {
		return undef
	}
	if q.k == qPct {
		return vBool(int64(n)*100 >= v.i*int64(total))
	}
	return vBool(int64(n) >= v.i)
}

func (sc *scanCtx) evalOf(e *ofExpr) value {
	n := 0
	if e.rules != nil {
		for _, r := range e.rules {
			if sc.ruleResult(r) {
				n++
			}
		}
		return sc.quantify(e.q, n, len(e.rules))
	}
	for _, s := range e.strs {
		v := sc.evalStrMatch(s, e.at, e.in)
		if v.k == tyUndef {
			return undef
		}
		if v.i != 0 {
			n++
		}
	}
	return sc.quantify(e.q, n, len(e.strs))
}

func (sc *scanCtx) evalForIn(e *forInExpr) value {
	n, total := 0, 0
	body := func() {
		total++
		if b, _ := truth(sc.eval(e.body)); b {
			n++
		}
	}
	switch {
	case e.rng != nil:
		lo, hi, ok := sc.evalRange(e.rng)
		if !ok || lo > hi {
			return undef
		}
		for i := lo; i <= hi; i++ {
			if total&1023 == 0 && sc.ctx.Err() != nil {
				return undef
			}
			sc.vars[e.vars[0].slot] = vInt(i)
			body()
		}
	case e.enum != nil:
		for _, x := range e.enum {
			sc.vars[e.vars[0].slot] = sc.eval(x)
			body()
		}
	default:
		it := sc.eval(e.iter)
		switch it.k {
		case tyArray:
			for _, x := range it.a {
				sc.vars[e.vars[0].slot] = x
				body()
			}
		case tyDict:
			keys := make([]string, 0, len(it.m))
			for k := range it.m {
				keys = append(keys, k)
			}
			for _, k := range keys {
				sc.vars[e.vars[0].slot] = vStr(k)
				sc.vars[e.vars[1].slot] = it.m[k]
				body()
			}
		default:
			return undef
		}
	}
	return sc.quantify(e.q, n, total)
}

// entrypoint is the deprecated top-level keyword: the PE or ELF entry
// point as a file offset.
func (sc *scanCtx) entrypoint() value {
	for _, name := range []string{"pe", "elf"} {
		m, ok := modules[name]
		if !ok {
			continue
		}
		root := sc.module(m).root
		if ep, ok := root.m["entry_point"]; ok && ep.k == tyInt {
			return ep
		}
	}
	return undef
}
