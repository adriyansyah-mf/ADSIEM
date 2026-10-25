package yara

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"hash/crc32"
	"math"
	"strconv"
	"time"
)

// dataRange returns data[off:off+size], truncated at the end of the
// data. Like libyara, the offset must fall inside the data.
func dataRange(sc *scanCtx, off, size int64) ([]byte, bool) {
	n := int64(len(sc.data))
	if off < 0 || size < 0 || off >= n {
		return nil, false
	}
	return sc.data[off:min(off+size, n)], true
}

// rangeOrString builds the two overloads most math and hash functions
// have: f(offset, size) over the scanned data and f(string).
func rangeOrString(ret vtype, f func(b []byte) value) []*overload {
	return []*overload{
		fn(ret, func(sc *scanCtx, _ any, a []value) value {
			b, ok := dataRange(sc, a[0].i, a[1].i)
			if !ok {
				return undef
			}
			return f(b)
		}, tyInt, tyInt),
		fn(ret, func(_ *scanCtx, _ any, a []value) value { return f([]byte(a[0].s)) }, tyStr),
	}
}

func entropy(b []byte) float64 {
	if len(b) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	e := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		x := float64(c) / float64(len(b))
		e -= x * math.Log2(x)
	}
	return e
}

func mean(b []byte) float64 {
	sum := 0.0
	for _, c := range b {
		sum += float64(c)
	}
	return sum / float64(len(b))
}

func deviation(b []byte, m float64) float64 {
	sum := 0.0
	for _, c := range b {
		sum += math.Abs(float64(c) - m)
	}
	return sum / float64(len(b))
}

// serialCorrelation follows libyara's math module (a variant of ent).
func serialCorrelation(b []byte) float64 {
	var last, t1, t2, t3 float64
	for _, c := range b {
		u := float64(c)
		t1 += last * u
		t2 += u
		t3 += u * u
		last = u
	}
	t2 *= t2
	n := float64(len(b))
	scc := n*t3 - t2
	if scc == 0 {
		return -100000
	}
	return (n*t1 - t2) / scc
}

func monteCarloPi(b []byte) (float64, bool) {
	const monten = 6
	inCirc := math.Pow(math.Pow(256, monten/2)-1, 2)
	count, in := 0, 0
	for i := 0; i+monten <= len(b); i += monten {
		var x, y float64
		for j := 0; j < monten/2; j++ {
			x = x*256 + float64(b[i+j])
			y = y*256 + float64(b[i+j+monten/2])
		}
		count++
		if x*x+y*y <= inCirc {
			in++
		}
	}
	if count == 0 {
		return 0, false
	}
	pi := 4 * float64(in) / float64(count)
	return math.Abs((pi - math.Pi) / math.Pi), true
}

func byteCounts(b []byte) [256]int {
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	return counts
}

func init() {
	registerModule(&module{
		name: "math",
		load: func(*scanCtx) (value, any) { return value{k: tyStruct, m: map[string]value{}}, nil },
		schema: sStruct(map[string]*schema{
			"MEAN_BYTES": {t: tyFloat, konst: &value{k: tyFloat, f: 127.5}},
			"entropy":    sFunc(rangeOrString(tyFloat, func(b []byte) value { return vFloat(entropy(b)) })...),
			"mean":       sFunc(rangeOrString(tyFloat, func(b []byte) value { return vFloat(mean(b)) })...),
			"serial_correlation": sFunc(rangeOrString(tyFloat, func(b []byte) value {
				return vFloat(serialCorrelation(b))
			})...),
			"monte_carlo_pi": sFunc(rangeOrString(tyFloat, func(b []byte) value {
				if v, ok := monteCarloPi(b); ok {
					return vFloat(v)
				}
				return undef
			})...),
			"deviation": sFunc(
				fn(tyFloat, func(sc *scanCtx, _ any, a []value) value {
					b, ok := dataRange(sc, a[0].i, a[1].i)
					if !ok {
						return undef
					}
					return vFloat(deviation(b, a[2].f))
				}, tyInt, tyInt, tyFloat),
				fn(tyFloat, func(_ *scanCtx, _ any, a []value) value {
					return vFloat(deviation([]byte(a[0].s), a[1].f))
				}, tyStr, tyFloat),
			),
			"in_range": sFunc(fn(tyBool, func(_ *scanCtx, _ any, a []value) value {
				return vBool(a[0].f >= a[1].f && a[0].f <= a[2].f)
			}, tyFloat, tyFloat, tyFloat)),
			"max": sFunc(fn(tyInt, func(_ *scanCtx, _ any, a []value) value {
				return vInt(int64(max(uint64(a[0].i), uint64(a[1].i))))
			}, tyInt, tyInt)),
			"min": sFunc(fn(tyInt, func(_ *scanCtx, _ any, a []value) value {
				return vInt(int64(min(uint64(a[0].i), uint64(a[1].i))))
			}, tyInt, tyInt)),
			"to_number": sFunc(fn(tyInt, func(_ *scanCtx, _ any, a []value) value {
				return vInt(a[0].i)
			}, tyBool)),
			"abs": sFunc(fn(tyInt, func(_ *scanCtx, _ any, a []value) value {
				if a[0].i < 0 {
					return vInt(-a[0].i)
				}
				return a[0]
			}, tyInt)),
			"count": sFunc(
				fn(tyInt, func(sc *scanCtx, _ any, a []value) value {
					b, ok := dataRange(sc, a[1].i, a[2].i)
					if !ok || a[0].i < 0 || a[0].i > 255 {
						return undef
					}
					return vInt(int64(byteCounts(b)[a[0].i]))
				}, tyInt, tyInt, tyInt),
				fn(tyInt, func(sc *scanCtx, _ any, a []value) value {
					if a[0].i < 0 || a[0].i > 255 || len(sc.data) == 0 {
						return undef
					}
					return vInt(int64(byteCounts(sc.data)[a[0].i]))
				}, tyInt),
			),
			"percentage": sFunc(
				fn(tyFloat, func(sc *scanCtx, _ any, a []value) value {
					b, ok := dataRange(sc, a[1].i, a[2].i)
					if !ok || a[0].i < 0 || a[0].i > 255 || len(b) == 0 {
						return undef
					}
					return vFloat(float64(byteCounts(b)[a[0].i]) / float64(len(b)))
				}, tyInt, tyInt, tyInt),
				fn(tyFloat, func(sc *scanCtx, _ any, a []value) value {
					if a[0].i < 0 || a[0].i > 255 || len(sc.data) == 0 {
						return undef
					}
					return vFloat(float64(byteCounts(sc.data)[a[0].i]) / float64(len(sc.data)))
				}, tyInt),
			),
			"mode": sFunc(
				fn(tyInt, func(sc *scanCtx, _ any, a []value) value {
					b, ok := dataRange(sc, a[0].i, a[1].i)
					if !ok {
						return undef
					}
					return vInt(int64(modeByte(b)))
				}, tyInt, tyInt),
				fn(tyInt, func(sc *scanCtx, _ any, _ []value) value {
					if len(sc.data) == 0 {
						return undef
					}
					return vInt(int64(modeByte(sc.data)))
				}),
			),
			"to_string": sFunc(
				fn(tyStr, func(_ *scanCtx, _ any, a []value) value {
					return vStr(strconv.FormatInt(a[0].i, 10))
				}, tyInt),
				fn(tyStr, func(_ *scanCtx, _ any, a []value) value {
					switch a[1].i {
					case 8, 10, 16:
						return vStr(strconv.FormatInt(a[0].i, int(a[1].i)))
					}
					return undef
				}, tyInt, tyInt),
			),
		}),
	})

	hexHash := func(sum func([]byte) []byte) []*overload {
		return rangeOrString(tyStr, func(b []byte) value { return vStr(hex.EncodeToString(sum(b))) })
	}
	registerModule(&module{
		name: "hash",
		load: func(*scanCtx) (value, any) { return value{k: tyStruct, m: map[string]value{}}, nil },
		schema: sStruct(map[string]*schema{
			"md5":    sFunc(hexHash(func(b []byte) []byte { s := md5.Sum(b); return s[:] })...),
			"sha1":   sFunc(hexHash(func(b []byte) []byte { s := sha1.Sum(b); return s[:] })...),
			"sha256": sFunc(hexHash(func(b []byte) []byte { s := sha256.Sum256(b); return s[:] })...),
			"crc32": sFunc(rangeOrString(tyInt, func(b []byte) value {
				return vInt(int64(crc32.ChecksumIEEE(b)))
			})...),
			"checksum32": sFunc(rangeOrString(tyInt, func(b []byte) value {
				var sum uint32
				for _, c := range b {
					sum += uint32(c)
				}
				return vInt(int64(sum))
			})...),
		}),
	})

	registerModule(&module{
		name: "time",
		load: func(*scanCtx) (value, any) { return value{k: tyStruct, m: map[string]value{}}, nil },
		schema: sStruct(map[string]*schema{
			"now": sFunc(fn(tyInt, func(*scanCtx, any, []value) value { return vInt(time.Now().Unix()) })),
		}),
	})
}

// modeByte is the most common byte; ties go to the lowest value.
func modeByte(b []byte) byte {
	counts := byteCounts(b)
	best := 0
	for i := 1; i < 256; i++ {
		if counts[i] > counts[best] {
			best = i
		}
	}
	return byte(best)
}
