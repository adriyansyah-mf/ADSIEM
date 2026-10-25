package yara

// vtype is the static type of an expression, also used as the kind of
// a runtime value.
type vtype int

const (
	tyUndef vtype = iota
	tyBool
	tyInt
	tyFloat
	tyStr
	tyStruct
	tyArray
	tyDict
	tyFunc
)

func (t vtype) String() string {
	return [...]string{"undefined", "boolean", "integer", "float", "string", "structure", "array", "dictionary", "function"}[t]
}

type strKind int

const (
	strText strKind = iota
	strHex
	strRegex
)

type stringDef struct {
	id   string // name without '$'; "" for an anonymous string
	kind strKind
	src  string // text bytes, regex body, or hex body (for messages)
	line int

	nocase, wide, ascii, fullword, private bool
	dotall                                 bool // regex /s
	xor                                    bool
	xorMin, xorMax                         int
	base64, base64wide                     bool
	b64alpha                               string

	// Compiled forms. A text string expands to literal variants; a hex
	// string without wildcards also becomes a literal.
	lits []litVariant
	prog *byteProg
	// regexWindow bounds how far a regex match may extend, like libyara's
	// RE_SCAN_LIMIT; zero means unbounded (hex strings).
	regexWindow int

	// fixed is fixedYes when the string is only ever tested with
	// "at <fixedOff>"; matches elsewhere are then not recorded.
	fixed    fixedState
	fixedOff int64
}

type fixedState int8

const (
	fixedUnset fixedState = iota
	fixedYes
	fixedNo
)

// litVariant is one byte pattern a text string can appear as.
type litVariant struct {
	pat    []byte
	nocase bool // search case-insensitively (ASCII)
	xor    bool // pattern was matched under a single-byte XOR key
	wide   bool // for fullword checks
}

// Meta is a rule's meta field: string, int64 or bool.
type Meta struct {
	Key   string
	Value any
}

type rule struct {
	name    string
	ns      string
	tags    []string
	meta    []Meta
	strs    []*stringDef
	cond    expr
	private bool
	global  bool
	idx     int // position in Rules.rules
	line    int
}

type expr interface{ typ() vtype }

type quantKind int

const (
	qAll quantKind = iota
	qAny
	qNone
	qNum // at least n
	qPct // at least n percent
)

type quant struct {
	k quantKind
	n expr
}

type rangeExpr struct{ lo, hi expr }

type (
	boolLit  struct{ v bool }
	intLit   struct{ v int64 }
	floatLit struct{ v float64 }
	strLit   struct{ v string }

	filesizeExpr   struct{}
	entrypointExpr struct{}

	// s == nil refers to the string bound by the enclosing for..of.
	strMatch struct {
		s  *stringDef
		at expr
		in *rangeExpr
	}
	strCount struct {
		s  *stringDef
		in *rangeExpr
	}
	strOffset struct {
		s   *stringDef
		idx expr // nil means 1
	}
	strLength struct {
		s   *stringDef
		idx expr
	}

	readInt struct {
		size   int
		signed bool
		be     bool
		off    expr
	}

	unExpr struct {
		op string
		x  expr
		t  vtype
	}
	binExpr struct {
		op   string
		l, r expr
		t    vtype
	}
	matchesExpr struct {
		x  expr
		re *byteProg
	}
	definedExpr struct{ x expr }

	ofExpr struct {
		q     quant
		strs  []*stringDef
		rules []*rule
		at    expr
		in    *rangeExpr
	}
	forOfExpr struct {
		q    quant
		strs []*stringDef
		body expr
	}
	forInExpr struct {
		q    quant
		vars []*loopVar
		// exactly one of rng, enum, iter is set
		rng  *rangeExpr
		enum []expr
		iter expr
		body expr
	}

	ruleRef struct{ r *rule }
	varRef  struct{ v *loopVar }

	moduleRef struct{ m *module }
	member    struct {
		x    expr
		name string
		s    *schema
	}
	indexExpr struct {
		x   expr
		idx expr
		s   *schema
	}
	callExpr struct {
		m    *module
		fn   *overload
		args []expr
	}
)

type loopVar struct {
	name string
	s    *schema // type of the variable
	slot int     // index into the evaluator's variable stack
}

func (boolLit) typ() vtype        { return tyBool }
func (intLit) typ() vtype         { return tyInt }
func (floatLit) typ() vtype       { return tyFloat }
func (strLit) typ() vtype         { return tyStr }
func (filesizeExpr) typ() vtype   { return tyInt }
func (entrypointExpr) typ() vtype { return tyInt }
func (strMatch) typ() vtype       { return tyBool }
func (strCount) typ() vtype       { return tyInt }
func (strOffset) typ() vtype      { return tyInt }
func (strLength) typ() vtype      { return tyInt }
func (readInt) typ() vtype        { return tyInt }
func (u unExpr) typ() vtype       { return u.t }
func (b binExpr) typ() vtype      { return b.t }
func (matchesExpr) typ() vtype    { return tyBool }
func (definedExpr) typ() vtype    { return tyBool }
func (ofExpr) typ() vtype         { return tyBool }
func (forOfExpr) typ() vtype      { return tyBool }
func (forInExpr) typ() vtype      { return tyBool }
func (ruleRef) typ() vtype        { return tyBool }
func (v varRef) typ() vtype       { return v.v.s.t }
func (moduleRef) typ() vtype      { return tyStruct }
func (m member) typ() vtype       { return m.s.t }
func (i indexExpr) typ() vtype    { return i.s.t }
func (c callExpr) typ() vtype     { return c.fn.ret }
