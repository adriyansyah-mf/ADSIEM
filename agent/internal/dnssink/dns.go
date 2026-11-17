// Package dnssink answers DNS for the web block's own domains and every
// subdomain of them, so a blocked domain cannot be reached through a name
// the hosts file does not list (cdn.evil.com, x7f3.evil.com).
//
// The agent never takes over the host's DNS. It runs a small resolver that
// answers only names under a blocked domain (Windows: 127.84.0.1:53; Linux:
// 169.254.84.1:53 on its dummy link), and asks the OS to send exactly those
// names to it: an NRPT rule on Windows (each blocked domain and its
// subdomains), routing domains (~evil.com) on the dummy link in
// systemd-resolved on Linux. Every other name resolves as before. If the
// resolver is down, only the blocked names fail to resolve.
//
// A blocked name gets A 127.84.0.1 (the web block's page) and no AAAA; any
// other type gets an empty answer; a name not under a blocked domain (which
// the OS should never send) is refused.
package dnssink

import (
	"encoding/binary"
	"errors"
	"strings"
)

// SinkV4 is the address blocked names resolve to: the web block's page server.
var SinkV4 = [4]byte{127, 84, 0, 1}

const (
	typeA    = 1
	typeAAAA = 28
	classIN  = 1

	rcodeNoError = 0
	rcodeFormErr = 1
	rcodeRefused = 5

	answerTTL = 60
	maxName   = 255
)

var errMalformed = errors.New("dnssink: malformed query")

// question is the one question of a query.
type question struct {
	name  string // lower case, no trailing dot
	qtype uint16
	raw   []byte // the question section as received (name, type, class)
}

// parseQuery reads the header and the single question of a standard query.
func parseQuery(msg []byte) (id uint16, flags uint16, q question, err error) {
	if len(msg) < 12 {
		return 0, 0, q, errMalformed
	}
	id = binary.BigEndian.Uint16(msg[0:2])
	flags = binary.BigEndian.Uint16(msg[2:4])
	if flags&0x8000 != 0 { // a response, not a query
		return id, flags, q, errMalformed
	}
	if binary.BigEndian.Uint16(msg[4:6]) != 1 {
		return id, flags, q, errMalformed
	}
	off := 12
	var labels []string
	total := 0
	for {
		if off >= len(msg) {
			return id, flags, q, errMalformed
		}
		n := int(msg[off])
		off++
		if n == 0 {
			break
		}
		if n&0xC0 != 0 { // no compression in a question we accept
			return id, flags, q, errMalformed
		}
		if off+n > len(msg) {
			return id, flags, q, errMalformed
		}
		total += n + 1
		if total > maxName {
			return id, flags, q, errMalformed
		}
		labels = append(labels, strings.ToLower(string(msg[off:off+n])))
		off += n
	}
	if off+4 > len(msg) {
		return id, flags, q, errMalformed
	}
	q.qtype = binary.BigEndian.Uint16(msg[off : off+2])
	if binary.BigEndian.Uint16(msg[off+2:off+4]) != classIN {
		return id, flags, q, errMalformed
	}
	q.raw = msg[12 : off+4]
	q.name = strings.Join(labels, ".")
	return id, flags, q, nil
}

// response builds the reply to id/flags/q with rcode and, for a sinkholed
// A query, one A record.
func response(id, qflags uint16, q question, rcode uint16, withA bool) []byte {
	flags := uint16(0x8000) | (qflags & 0x7800) | (qflags & 0x0100) | 0x0080 | 0x0400 | rcode // QR, opcode, RD, RA, AA
	an := 0
	if withA {
		an = 1
	}
	out := make([]byte, 12, 12+len(q.raw)+16)
	binary.BigEndian.PutUint16(out[0:2], id)
	binary.BigEndian.PutUint16(out[2:4], flags)
	if q.raw != nil {
		binary.BigEndian.PutUint16(out[4:6], 1)
	}
	binary.BigEndian.PutUint16(out[6:8], uint16(an))
	out = append(out, q.raw...)
	if withA {
		rr := make([]byte, 16)
		binary.BigEndian.PutUint16(rr[0:2], 0xC00C) // pointer to the question's name
		binary.BigEndian.PutUint16(rr[2:4], typeA)
		binary.BigEndian.PutUint16(rr[4:6], classIN)
		binary.BigEndian.PutUint32(rr[6:10], answerTTL)
		binary.BigEndian.PutUint16(rr[10:12], 4)
		copy(rr[12:16], SinkV4[:])
		out = append(out, rr...)
	}
	return out
}

// Answer is what the resolver did with one query.
type Answer struct {
	Name    string // the name asked
	Type    uint16
	Blocked string // the blocked domain it fell under ("" when refused)
}

// Handle answers one query against blocked (lower-case domains). It never
// panics on any input; a message it cannot read gets FORMERR when it has a
// header to answer, else nothing.
func Handle(msg []byte, blocked func(name string) string) ([]byte, Answer) {
	id, flags, q, err := parseQuery(msg)
	if err != nil {
		if len(msg) < 12 || flags&0x8000 != 0 {
			return nil, Answer{}
		}
		return response(id, flags, question{}, rcodeFormErr, false), Answer{}
	}
	if flags&0x7800 != 0 { // opcode other than QUERY
		return response(id, flags, q, rcodeRefused, false), Answer{Name: q.name, Type: q.qtype}
	}
	under := blocked(q.name)
	if under == "" {
		return response(id, flags, q, rcodeRefused, false), Answer{Name: q.name, Type: q.qtype}
	}
	return response(id, flags, q, rcodeNoError, q.qtype == typeA), Answer{Name: q.name, Type: q.qtype, Blocked: under}
}

// Matcher reports the blocked domain a name falls under: the name itself or
// one of its parents.
type Matcher map[string]bool

func (m Matcher) Under(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for name != "" {
		if m[name] {
			return name
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return ""
		}
		name = name[i+1:]
	}
	return ""
}
