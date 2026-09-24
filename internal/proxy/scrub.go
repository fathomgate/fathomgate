package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// MinSecretLen is the shortest Secret value that is scrubbed. Shorter values
// would match ordinary text too often, so they pass through unchanged
// (ADR 0017, decision 3).
const MinSecretLen = 4

// Secret is a variable the operator passes to an upstream from netguard's
// own environment (`--upstream-env-pass NAME`): its name and value. Build
// one with NewSecret. Wherever it is scrubbed, every occurrence of the
// value, exact or in one of its encodedForms, becomes "[redacted:NAME]".
//
// Formatting a Secret never yields the value: String, GoString, Format
// (every fmt verb, %d and %x included), MarshalJSON and LogValue all
// return the marker. The value sits behind a pointer, so a printer that
// reflects into a struct holding a Secret in an unexported field (where fmt
// cannot call these methods) shows an address, not the value.
type Secret struct {
	name  string
	value *string
}

// NewSecret returns the Secret for variable name with the given value.
func NewSecret(name, value string) Secret { return Secret{name: name, value: &value} }

// Name is the variable name.
func (s Secret) Name() string { return s.name }

// val is the value; only the proxy reads it, to start the upstream and to
// build redactors.
func (s Secret) val() string {
	if s.value == nil {
		return ""
	}
	return *s.value
}

// String returns "[redacted:NAME]", never the value.
func (s Secret) String() string { return "[redacted:" + s.name + "]" }

// GoString returns the marker.
func (s Secret) GoString() string { return s.String() }

// Format writes the marker for every verb and flag.
func (s Secret) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, s.String()) }

// MarshalJSON encodes the marker as a JSON string.
func (s Secret) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// LogValue makes slog record the marker.
func (s Secret) LogValue() slog.Value { return slog.StringValue(s.String()) }

// scrubber replaces known values in a byte stream with their markers. It
// works on the raw stream, before line splitting and escaping, so a value
// split across two writes, or one that contains a newline, is still found.
// It holds back at most the longest form's length minus one byte: a tail
// that could still grow into a value. Not safe for concurrent use; the
// lineWriter that owns it holds its lock.
type scrubber struct {
	secrets []scrubValue // longest first; shared, never modified
	pending []byte
}

type scrubValue struct {
	value  []byte
	marker []byte
}

// Redactor replaces passed values, and the forms they take in logs, with
// their markers. Build it once with NewRedactor; it is immutable and safe
// for concurrent use. A nil *Redactor redacts nothing.
type Redactor struct {
	stream []scrubValue // encodedForms, for raw upstream bytes
	text   []scrubValue // encodedForms and each as escapeControl renders it
}

// NewRedactor returns a Redactor for the secrets whose values are at least
// MinSecretLen bytes, or nil if there are none. When forms overlap, the
// longest wins at any position; ties keep the order given.
func NewRedactor(secrets []Secret) *Redactor {
	var r Redactor
	for _, s := range secrets {
		v := s.val()
		if len(v) < MinSecretLen {
			continue
		}
		marker := []byte(s.String())
		seen := map[string]bool{}
		for _, f := range encodedForms(v) {
			r.stream = append(r.stream, scrubValue{value: []byte(f), marker: marker})
			for _, g := range []string{f, escapeControl(f, 0)} {
				if !seen[g] {
					seen[g] = true
					r.text = append(r.text, scrubValue{value: []byte(g), marker: marker})
				}
			}
		}
	}
	if len(r.stream) == 0 {
		return nil
	}
	longestFirst(r.stream)
	longestFirst(r.text)
	return &r
}

func longestFirst(vs []scrubValue) {
	sort.SliceStable(vs, func(i, j int) bool { return len(vs[i].value) > len(vs[j].value) })
}

// Redact returns s with every passed value, in any of its encodedForms or
// as netguard's escapeControl renders one, replaced by its marker. Use it
// on whole strings: error messages and log lines. A string that ends in the
// first MinSecretLen or more bytes of a form has that tail replaced too.
func (r *Redactor) Redact(s string) string {
	if r == nil {
		return s
	}
	sc := scrubber{secrets: r.text}
	return string(sc.write([]byte(s), true))
}

// newStream returns a scrubber for one raw byte stream, or nil.
func (r *Redactor) newStream() *scrubber {
	if r == nil {
		return nil
	}
	return &scrubber{secrets: r.stream}
}

// encodedForms returns v and the forms it takes in the logs an upstream is
// likely to write: inside a Go %q or strconv.QuoteToASCII string; inside a
// JSON string (with and without HTML escaping, and ASCII-only as Python's
// json.dumps writes it by default); percent-encoded (query and path
// escaping); Python byte escapes (\xNN for every byte outside printable
// ASCII, as a bytes repr writes them, and for control bytes only, as a str
// repr does); and with backslashes doubled. Only the text between quotes is
// used, so a form matches wherever the value sits in a longer string.
// Duplicates are dropped. Not covered: base64, HTML entities, a Python repr
// that escapes a quote character, and any other transform.
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
	add(url.QueryEscape(v))
	add(url.PathEscape(v))
	add(pyByteEscape(v, true))
	add(pyByteEscape(v, false))
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

// pyByteEscape is v as Python writes it inside a repr, without the quotes:
// backslash doubled, \t \n \r named, other control bytes as \xNN, and with
// nonASCII every byte from 0x7f up as \xNN too (a bytes repr). Quote
// characters are left as they are.
func pyByteEscape(v string, nonASCII bool) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\t':
			b.WriteString(`\t`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c < 0x20 || c == 0x7f || (nonASCII && c >= 0x80):
			fmt.Fprintf(&b, `\x%02x`, c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
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
