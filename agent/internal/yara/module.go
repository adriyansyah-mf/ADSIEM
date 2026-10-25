package yara

import "sort"

// value is a runtime value. k == tyUndef is YARA's "undefined".
type value struct {
	k vtype
	i int64
	f float64
	s string
	m map[string]value // tyStruct, tyDict
	a []value          // tyArray
}

var undef = value{}

func vInt(i int64) value     { return value{k: tyInt, i: i} }
func vFloat(f float64) value { return value{k: tyFloat, f: f} }
func vStr(s string) value    { return value{k: tyStr, s: s} }
func vBool(b bool) value {
	if b {
		return value{k: tyBool, i: 1}
	}
	return value{k: tyBool}
}

// schema describes a module member for compile-time checking.
type schema struct {
	t      vtype
	fields map[string]*schema // tyStruct
	elem   *schema            // tyArray, tyDict
	fns    []*overload        // tyFunc
	konst  *value             // constant fields need no module data
}

type overload struct {
	args []vtype
	ret  vtype
	impl func(sc *scanCtx, state any, args []value) value
}

type module struct {
	name   string
	schema *schema
	// load parses the scanned data once per scan. root holds the data
	// fields; state is handed to the module's functions.
	load func(sc *scanCtx) (root value, state any)
}

var modules = map[string]*module{}

func registerModule(m *module) { modules[m.name] = m }

// schema constructors keep module declarations short.
func sInt() *schema                        { return &schema{t: tyInt} }
func sFloat() *schema                      { return &schema{t: tyFloat} }
func sStr() *schema                        { return &schema{t: tyStr} }
func sStruct(f map[string]*schema) *schema { return &schema{t: tyStruct, fields: f} }
func sArray(e *schema) *schema             { return &schema{t: tyArray, elem: e} }
func sDict(e *schema) *schema              { return &schema{t: tyDict, elem: e} }
func sConst(i int64) *schema {
	v := vInt(i)
	return &schema{t: tyInt, konst: &v}
}
func sFunc(o ...*overload) *schema { return &schema{t: tyFunc, fns: o} }
func fn(ret vtype, impl func(sc *scanCtx, state any, args []value) value, args ...vtype) *overload {
	return &overload{args: args, ret: ret, impl: impl}
}

// SupportedModules lists the modules a rule may import.
func SupportedModules() []string {
	names := make([]string, 0, len(modules))
	for n := range modules {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
