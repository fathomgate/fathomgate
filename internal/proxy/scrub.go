package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// MinSecretLen is the shortest Secret value that is scrubbed. Shorter values
// would match ordinary text too often, so they pass through unchanged
// (ADR 0017, decision 3).
const MinSecretLen = 4

// Secret is a value the operator handed an upstream from netguard's own
// environment (`--upstream-env-pass NAME`). Wherever it is scrubbed, every
// occurrence of Value, exact or in one of its encodedForms, becomes
// "[redacted:NAME]".
//
// String and GoString return that marker, so a Secret formatted with %v,
// %+v or %#v never prints its value.
type Secret struct {
	Name  string
	Value string
}

// String returns "[redacted:NAME]", never the value.
func (s Secret) String() string { return "[redacted:" + s.Name + "]" }

// GoString returns the same marker as String.
func (s Secret) GoString() string { return s.String() }

// scrubber replaces known values in a byte stream with their markers. It
// works on the raw stream, before line splitting and escaping, so a value
// split across two writes, or one that contains a newline, is still found.
// It holds back at most the longest value's length minus one byte: a tail
// that could still grow into a value. Not safe for concurrent use; the
// lineWriter that owns it holds its lock.
type scrubber struct {
	secrets []scrubValue // longest first
	pending []byte
}

type scrubValue struct {
	value  []byte
	marker []byte
}

// encodedForms returns v and the forms it takes inside a quoted string in
// the logs an upstream is likely to write: Go %q and strconv.Quote, JSON
// (with and without HTML escaping, and ASCII-only as Python's json.dumps
// writes it by default), and backslashes doubled (a Python repr of a value
// without quotes). Only the text between the quotes is used, so the forms
// match wherever the value sits in a longer string. Duplicates are dropped.
func encodedForms(v string) []string {
	forms := []string{v}
	add := func(f string) {
		for _, g := range forms {
			if g == f {
				return
			}
		}
		forms = append(forms, f)
	}
	add(unquote(strconv.Quote(v)))
	add(unquote(strconv.QuoteToASCII(v)))
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	if enc.Encode(v) == nil {
		add(unquote(strings.TrimSuffix(b.String(), "\n")))
	}
	b.Reset()
	enc.SetEscapeHTML(false)
	if enc.Encode(v) == nil {
		add(unquote(strings.TrimSuffix(b.String(), "\n")))
	}
	add(jsonASCII(v))
	add(strings.ReplaceAll(v, `\`, `\\`))
	return forms
}

// unquote drops the surrounding quote characters of a quoted string.
func unquote(q string) string {
	if len(q) >= 2 {
		return q[1 : len(q)-1]
	}
	return q
}

// jsonASCII is v as JSON string contents with every non-ASCII character
// written as a \u escape (UTF-16 surrogate pairs above U+FFFF), as Python's
// json.dumps does with ensure_ascii.
func jsonASCII(v string) string {
	var b strings.Builder
	for _, r := range v {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r < 0x20 || r == 0x7f || r >= 0x80:
			if r > 0xffff {
				r1, r2 := utf16.EncodeRune(r)
				fmt.Fprintf(&b, `\u%04x\u%04x`, r1, r2)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// newScrubber returns a scrubber for the values of at least MinSecretLen
// bytes, and their encodedForms, or nil if there are none. When values
// overlap, the longest wins at any position; ties keep the order given.
func newScrubber(secrets []Secret) *scrubber {
	var vs []scrubValue
	for _, s := range secrets {
		if len(s.Value) < MinSecretLen {
			continue
		}
		for _, f := range encodedForms(s.Value) {
			vs = append(vs, scrubValue{value: []byte(f), marker: []byte(s.String())})
		}
	}
	if len(vs) == 0 {
		return nil
	}
	sort.SliceStable(vs, func(i, j int) bool { return len(vs[i].value) > len(vs[j].value) })
	return &scrubber{secrets: vs}
}

// write scrubs p, prefixed by whatever the previous call held back, and
// returns what can be released. With final set nothing is held back: the
// stream has ended, so a partial value can no longer complete. A stream that
// ends in the first MinSecretLen or more bytes of a value (an upstream that
// died mid-write) has that tail replaced by the value's marker too, so a
// truncated value is not printed either.
func (s *scrubber) write(p []byte, final bool) []byte {
	data := make([]byte, 0, len(s.pending)+len(p))
	data = append(data, s.pending...)
	data = append(data, p...)
	s.pending = nil
	out := make([]byte, 0, len(data))
	for i := 0; i < len(data); {
		rest := data[i:]
		matched, wait := false, false
		for _, v := range s.secrets {
			if len(rest) >= len(v.value) {
				if bytes.HasPrefix(rest, v.value) {
					out = append(out, v.marker...)
					i += len(v.value)
					matched = true
					break
				}
			} else if bytes.HasPrefix(v.value, rest) {
				if final {
					if len(rest) >= MinSecretLen {
						out = append(out, v.marker...)
						return out
					}
					continue
				}
				// rest may still become this value (or a longer one
				// than any that matches now): wait for more bytes.
				wait = true
				break
			}
		}
		if wait {
			s.pending = append([]byte(nil), rest...)
			break
		}
		if !matched {
			out = append(out, data[i])
			i++
		}
	}
	return out
}

// RedactSecrets returns s with every occurrence of a Secret value of at
// least MinSecretLen bytes, or of one of its encodedForms, replaced by
// "[redacted:NAME]". It also replaces each of those forms as netguard's own
// escaping of upstream text renders it (escapeControl, which doubles
// backslashes), so an error or log line that carries an upstream's words
// cannot print the value either. It is the last guard on netguard's stderr;
// relayed upstream stderr is scrubbed earlier, on the raw bytes before
// escaping.
func RedactSecrets(s string, secrets []Secret) string {
	var vs []scrubValue
	for _, sec := range secrets {
		if len(sec.Value) < MinSecretLen {
			continue
		}
		marker := []byte(sec.String())
		seen := map[string]bool{}
		for _, f := range encodedForms(sec.Value) {
			for _, g := range []string{f, escapeControl(f, 0)} {
				if !seen[g] {
					seen[g] = true
					vs = append(vs, scrubValue{value: []byte(g), marker: marker})
				}
			}
		}
	}
	if len(vs) == 0 {
		return s
	}
	sort.SliceStable(vs, func(i, j int) bool { return len(vs[i].value) > len(vs[j].value) })
	sc := &scrubber{secrets: vs}
	return string(sc.write([]byte(s), true))
}
