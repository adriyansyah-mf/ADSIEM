package mlscore

import (
	"math"
	"unicode/utf8"
)

// utf8DecodeRune decodes one rune; invalid bytes give -1 and are skipped,
// as Python's decode(errors="ignore") does.
func utf8DecodeRune(b []byte) (rune, int) {
	r, size := utf8.DecodeRune(b)
	if r == utf8.RuneError && size <= 1 {
		return -1, 1
	}
	return r, size
}

// numpySum32 adds float32 values the way numpy's pairwise sum does for
// short arrays: sequentially under 8, else eight running sums combined
// pairwise, then the remainder.
func numpySum32(a []float32) float32 {
	if len(a) < 8 {
		s := float32(0)
		for _, v := range a {
			s += v
		}
		return s
	}
	var r [8]float32
	copy(r[:], a[:8])
	i := 8
	for ; i+8 <= len(a); i += 8 {
		for j := 0; j < 8; j++ {
			r[j] += a[i+j]
		}
	}
	s := ((r[0] + r[1]) + (r[2] + r[3])) + ((r[4] + r[5]) + (r[6] + r[7]))
	for ; i < len(a); i++ {
		s += a[i]
	}
	return s
}

// byteEntropyCounts: thrember's byte/entropy histogram as counts, with the
// block entropy in float32 like numpy (it picks the bin).
func byteEntropyCounts(b []byte) [256]int {
	const window, step = 2048, 1024
	var out [256]int
	block := func(blk []byte) {
		var c [16]int
		for _, x := range blk {
			c[x>>4]++
		}
		var terms []float32
		for _, n := range c {
			if n > 0 {
				p := float32(n) / float32(window)
				terms = append(terms, -p*float32(math.Log2(float64(p))))
			}
		}
		h := numpySum32(terms) * 2
		bin := int(h * 2)
		if bin == 16 {
			bin = 15
		}
		for i, n := range c {
			out[bin*16+i] += n
		}
	}
	if len(b) < window {
		block(b)
		return out
	}
	for start := 0; start+window <= len(b); start += step {
		block(b[start : start+window])
	}
	return out
}
