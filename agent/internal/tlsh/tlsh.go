// Package tlsh computes TLSH locality-sensitive hashes (the "T1" form:
// 128 buckets, 1-byte checksum, as MalwareBazaar, VirusTotal and EMBER2024
// publish them) and the distance between two of them: a small distance
// means similar content, so a variant of a known sample is found even
// though its SHA-256 differs.
//
// Port of the reference implementation by Trend Micro
// (https://github.com/trendmicro/tlsh, Apache-2.0 or BSD): same Pearson
// table, length encoding, quartiles and distance (length and ratio weight
// 12, bit-pair distances 1/2/6).
package tlsh

import (
	"encoding/hex"
	"errors"
	"sort"
	"strings"
)

const (
	codeSize   = 32  // 128 buckets x 2 bits
	effBuckets = 128 // buckets used (the mapping produces 256)
	// MinLength is the shortest input that gets a hash.
	MinLength = 50
)

// Hash is a parsed TLSH digest.
type Hash struct {
	Checksum byte
	Lvalue   byte
	Q1, Q2   byte // ratios, 4 bits each
	Code     [codeSize]byte
	// Truncated: parsed from a digest missing its last byte (URLhaus cuts
	// them to 68 hex digits); Code[0] is unknown and left out of distances.
	Truncated bool
}

// vTable is Pearson's table from the reference implementation.
var vTable = [256]byte{
	1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163,
	14, 197, 213, 181, 161, 85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200,
	110, 177, 104, 103, 141, 253, 255, 50, 77, 101, 81, 18, 45, 96, 31, 222,
	25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227, 149, 235,
	97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248,
	174, 169, 211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243,
	132, 56, 148, 75, 128, 133, 158, 100, 130, 126, 91, 13, 153, 246, 216, 219,
	119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92, 32, 136, 114, 52, 10,
	138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
	170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131,
	125, 173, 15, 238, 79, 95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123,
	118, 73, 2, 157, 46, 116, 9, 145, 134, 228, 207, 212, 202, 215, 69, 229,
	27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39, 203,
	233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76,
	140, 36, 210, 172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120,
	51, 65, 28, 144, 254, 221, 93, 189, 194, 139, 112, 43, 71, 109, 184, 209,
}

// topval: the upper bound of each length class (Lvalue).
var topval = [170]uint32{1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656, 854, 1110, 1443, 1876,
	2439, 3171, 3475, 3823, 4205, 4626, 5088, 5597, 6157, 6772, 7450, 8195, 9014, 9916, 10907, 11998, 13198, 14518,
	15970, 17567, 19323, 21256, 23382, 25720, 28292, 31121, 34233, 37656, 41422, 45564, 50121, 55133, 60646, 66711,
	73382, 80721, 88793, 97672, 107439, 118183, 130002, 143002, 157302, 173032, 190335, 209369, 230306, 253337,
	278670, 306538, 337191, 370911, 408002, 448802, 493682, 543050, 597356, 657091, 722800, 795081, 874589, 962048,
	1058252, 1164078, 1280486, 1408534, 1549388, 1704327, 1874759, 2062236, 2268459, 2495305, 2744836, 3019320,
	3321252, 3653374, 4018711, 4420582, 4862641, 5348905, 5883796, 6472176, 7119394, 7831333, 8614467, 9475909,
	10423501, 11465851, 12612437, 13873681, 15261050, 16787154, 18465870, 20312458, 22343706, 24578077, 27035886,
	29739474, 32713425, 35984770, 39583245, 43541573, 47895730, 52685306, 57953837, 63749221, 70124148, 77136564,
	84850228, 93335252, 102668779, 112935659, 124229227, 136652151, 150317384, 165349128, 181884040, 200072456,
	220079703, 242087671, 266296456, 292926096, 322218735, 354440623, 389884688, 428873168, 471760495, 518936559,
	570830240, 627913311, 690704607, 759775136, 835752671, 919327967, 1011260767, 1112386880, 1223623232,
	1345985727, 1480584256, 1628642751, 1791507135, 1970657856, 2167723648, 2384496256, 2622945920, 2885240448,
	3173764736, 3491141248, 3840255616, 4224281216}

// lCapturing: the reference's binary search over topval.
func lCapturing(n uint32) byte {
	bottom, top, idx := 0, 170, 85
	for {
		if idx == 0 {
			return 0
		}
		if idx >= len(topval) {
			return byte(len(topval) - 1)
		}
		if n <= topval[idx] && n > topval[idx-1] {
			return byte(idx)
		}
		if n < topval[idx] {
			top = idx - 1
		} else {
			bottom = idx + 1
		}
		idx = (bottom + top) / 2
	}
}

func bMap(salt, i, j, k byte) byte { return vTable[vTable[vTable[salt^i]^j]^k] }

// ErrTooSimple: the input is shorter than MinLength or too uniform to hash.
var ErrTooSimple = errors.New("tlsh: input too short or too uniform")

// Sum hashes data.
func Sum(data []byte) (Hash, error) {
	var h Hash
	if len(data) < MinLength {
		return h, ErrTooSimple
	}
	var buckets [256]uint32
	var checksum byte
	for i := 4; i < len(data); i++ {
		a, b, c, d, e := data[i], data[i-1], data[i-2], data[i-3], data[i-4]
		checksum = bMap(1, a, b, checksum)
		buckets[bMap(49, a, b, c)]++
		buckets[bMap(12, a, b, d)]++
		buckets[bMap(178, a, c, d)]++
		buckets[bMap(166, a, c, e)]++
		buckets[bMap(84, a, b, e)]++
		buckets[bMap(230, a, d, e)]++
	}
	sorted := make([]uint32, effBuckets)
	copy(sorted, buckets[:effBuckets])
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	q1, q2, q3 := sorted[effBuckets/4-1], sorted[effBuckets/2-1], sorted[effBuckets-effBuckets/4-1]
	if q3 == 0 {
		return h, ErrTooSimple
	}
	nonzero := 0
	for _, v := range buckets[:effBuckets] {
		if v > 0 {
			nonzero++
		}
	}
	if nonzero <= 4*codeSize/2 {
		return h, ErrTooSimple
	}
	for i := 0; i < codeSize; i++ {
		var c byte
		for j := 0; j < 4; j++ {
			k := buckets[4*i+j]
			switch {
			case q3 < k:
				c += 3 << (j * 2)
			case q2 < k:
				c += 2 << (j * 2)
			case q1 < k:
				c += 1 << (j * 2)
			}
		}
		h.Code[i] = c
	}
	h.Checksum = checksum
	h.Lvalue = lCapturing(uint32(len(data)))
	h.Q1 = byte(uint64(q1) * 100 / uint64(q3) % 16)
	h.Q2 = byte(uint64(q2) * 100 / uint64(q3) % 16)
	return h, nil
}

func swap(b byte) byte { return b<<4 | b>>4 }

// String is the "T1" + 70 hex digit form.
func (h Hash) String() string {
	b := make([]byte, 3+codeSize)
	b[0], b[1], b[2] = swap(h.Checksum), swap(h.Lvalue), swap(h.Q2<<4|h.Q1)
	for i := 0; i < codeSize; i++ {
		b[3+i] = h.Code[codeSize-1-i]
	}
	return "T1" + strings.ToUpper(hex.EncodeToString(b))
}

// ErrFormat: not a T1 TLSH digest.
var ErrFormat = errors.New("tlsh: not a T1 digest")

// Parse reads a digest: "T1" + 70 hex digits, the 70 digits alone, or a
// digest cut to 68 digits (Truncated).
func Parse(s string) (Hash, error) {
	var h Hash
	s = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "T1"), "t1")
	if len(s) == 2*(3+codeSize)-2 {
		s, h.Truncated = s+"00", true
	}
	if len(s) != 2*(3+codeSize) {
		return h, ErrFormat
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return h, ErrFormat
	}
	h.Checksum, h.Lvalue = swap(b[0]), swap(b[1])
	q := swap(b[2])
	h.Q1, h.Q2 = q&0x0f, q>>4
	for i := 0; i < codeSize; i++ {
		h.Code[codeSize-1-i] = b[3+i]
	}
	return h, nil
}

func modDiff(x, y, r int) int {
	var dl, dr int
	if y > x {
		dl, dr = y-x, x+r-y
	} else {
		dl, dr = x-y, y+r-x
	}
	return min(dl, dr)
}

// pairDiff[x][y]: the bit-pair distance of two code bytes (1, 2, 6 for a
// difference of 1, 2, 3 in a pair), as the reference's table.
var pairDiff = func() (t [256][256]uint8) {
	pd := func(a, b int) uint8 {
		switch d := max(a-b, b-a); d {
		case 0:
			return 0
		case 1:
			return 1
		case 2:
			return 2
		}
		return 6
	}
	for x := 0; x < 256; x++ {
		for y := 0; y < 256; y++ {
			var d uint8
			for s := 0; s < 8; s += 2 {
				d += pd(x>>s&3, y>>s&3)
			}
			t[x][y] = d
		}
	}
	return
}()

// Distance between two digests, length included (0: same; under ~50:
// usually the same family; the scale has no upper bound).
func Distance(a, b Hash) int {
	diff := 0
	switch l := modDiff(int(a.Lvalue), int(b.Lvalue), 256); l {
	case 0:
	case 1:
		diff = 1
	default:
		diff = l * 12
	}
	for _, q := range [][2]byte{{a.Q1, b.Q1}, {a.Q2, b.Q2}} {
		if d := modDiff(int(q[0]), int(q[1]), 16); d <= 1 {
			diff += d
		} else {
			diff += (d - 1) * 12
		}
	}
	if a.Checksum != b.Checksum {
		diff++
	}
	for i := range a.Code {
		if i == 0 && (a.Truncated || b.Truncated) {
			continue
		}
		diff += int(pairDiff[a.Code[i]][b.Code[i]])
	}
	return diff
}
