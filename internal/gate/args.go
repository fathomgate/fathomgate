// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"reflect"
	"strings"
	"unicode/utf8"

	"github.com/fathomgate/fathomgate/internal/classify"
)

// Parse error kinds, for the decision log line only (never the agent).
const (
	parseNotObject    = "not_object"
	parseInvalidJSON  = "invalid_json"
	parseInvalidUTF8  = "invalid_utf8"
	parseDuplicateKey = "duplicate_key"
	parseTrailingData = "trailing_data"
)

// parseArguments decodes a tools/call's arguments into a map, or returns
// the kind of problem. Absent arguments and JSON null are an empty object.
// Anything else must be one JSON object in valid UTF-8 with no top-level key
// given twice: two parsers that keep different copies of a duplicated key
// (first wins against last wins) would let fathomgate check one value while
// the upstream uses the other, and Go silently replaces invalid UTF-8 where
// the upstream may not.
//
// Only top-level keys are checked for duplicates. Below the top level
// fathomgate reads only the values of target, command and config
// arguments, and those must be strings or arrays of strings (an object
// there is a bad target, a failed command or, with the closed argument
// list, a malformed argument). A value in a profile's args list is
// forwarded without being read, so a duplicate inside it cannot make
// fathomgate check something other than what the upstream uses.
func parseArguments(raw json.RawMessage) (map[string]any, string) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return map[string]any{}, ""
	}
	if !utf8.Valid(trimmed) {
		return nil, parseInvalidUTF8
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	tok, err := dec.Token()
	if err != nil {
		return nil, parseInvalidJSON
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, parseNotObject
	}
	out := map[string]any{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, parseInvalidJSON
		}
		key, ok := tok.(string)
		if !ok {
			return nil, parseInvalidJSON
		}
		if _, dup := out[key]; dup {
			return nil, parseDuplicateKey
		}
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, parseInvalidJSON
		}
		out[key] = v
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, parseInvalidJSON
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, parseTrailingData
	}
	return out, ""
}

// targetProblem is why the target arguments of a call were refused. The
// value is internal; the agent sees the fixed text from reasonFor.
type targetProblem int

const (
	targetsOK targetProblem = iota
	// targetBadName: a target is not a string, or not a hostname or IP
	// literal.
	targetBadName
)

// targets extracts the target names of a call from the profile's parameter
// mapping, exactly as the upstream will receive them.
//
//   - target_params: the value must be a string holding one name. A comma
//     is not a separator here, so "a,b" is refused as a bad name.
//   - targets_params: an array of strings, or a string split on commas. No
//     part is trimmed, so "a, b" is refused (" b" is not a hostname), and
//     an empty part is refused. An empty array or string adds nothing.
//   - group_params: any value other than null, "" or [] means the call
//     selects devices by group; groups is set and no name is added.
//
// null counts as absent everywhere. Names are de-duplicated on the exact
// string, in argument order.
func targets(spec classify.ToolSpec, args map[string]any) (names []string, groups bool, problem targetProblem) {
	seen := map[string]bool{}
	add := func(s string) bool {
		if !validTargetName(s) {
			return false
		}
		if !seen[s] {
			seen[s] = true
			names = append(names, s)
		}
		return true
	}
	for _, p := range spec.TargetParams {
		v, ok := args[p]
		if !ok || v == nil {
			continue
		}
		s, ok := v.(string)
		if !ok || !add(s) {
			return nil, false, targetBadName
		}
	}
	for _, p := range spec.TargetsParams {
		switch v := args[p].(type) {
		case nil:
		case string:
			if v == "" {
				continue
			}
			for _, part := range strings.Split(v, ",") {
				if !add(part) {
					return nil, false, targetBadName
				}
			}
		case []any:
			for _, e := range v {
				s, ok := e.(string)
				if !ok || !add(s) {
					return nil, false, targetBadName
				}
			}
		default:
			return nil, false, targetBadName
		}
	}
	for _, p := range spec.GroupParams {
		switch v := args[p].(type) {
		case nil:
		case string:
			groups = groups || v != ""
		case []any:
			groups = groups || len(v) > 0
		default:
			groups = true
		}
	}
	return names, groups, targetsOK
}

// maxNameLen is the longest DNS name in text form.
const maxNameLen = 253

// validTargetName reports whether s is a hostname or an IP literal, byte for
// byte as the upstream will receive it.
//
// A hostname is 1 to 253 bytes of ASCII letters, digits, '-', '_' and '.',
// in labels of 1 to 63 bytes, none starting with '-' (an option to ssh or
// ping on the upstream's host). '_' is allowed because upstream inventories
// key devices by name (upa's TOML, eos-mcp's router list), not only by DNS
// name. If the last label is numeric (decimal digits, or 0x and hex digits)
// the whole name must be a dotted-quad IPv4 address in canonical form, so
// the inet_aton spellings 127.1, 2130706433, 0x7f.1 and 010.0.0.1 are
// refused. A name Python's json.loads reads as a non-string (null, true,
// false, NaN, Infinity, 1e5) is refused (see jsonScalar). A name containing
// ':' must be an IPv6 address without a zone.
// Everything else is refused: '@' (user@host to an SSH client), whitespace,
// control characters, brackets, '%', '/', non-ASCII bytes.
func validTargetName(s string) bool {
	if s == "" || len(s) > maxNameLen {
		return false
	}
	if strings.IndexByte(s, ':') >= 0 {
		a, err := netip.ParseAddr(s)
		return err == nil && a.Is6() && a.Zone() == ""
	}
	for i := 0; i < len(s); i++ {
		if !hostByte(s[i]) {
			return false
		}
	}
	if jsonScalar(s) {
		return false
	}
	labels := strings.Split(s, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' {
			return false
		}
	}
	if numericLabel(labels[len(labels)-1]) {
		a, err := netip.ParseAddr(s)
		return err == nil && a.Is4()
	}
	return true
}

// jsonScalar reports whether Python's json.loads reads s as something other
// than a string: null, true, false, NaN, Infinity or a JSON number such as
// 1e5. FastMCP upstreams json.loads a string sent for a parameter that is not
// typed str, so hostnames="null" reaches the tool as None (every device) while
// fathomgate would see one target named null. Such a name is refused. (Arrays
// and objects need '[', '{' or '"', which are refused already.)
func jsonScalar(s string) bool {
	switch s {
	case "null", "true", "false", "NaN", "Infinity":
		return true
	}
	// JSON number: int [frac] [exp], int = 0 | [1-9][0-9]*. A leading '-'
	// is refused before this is reached.
	i, n := 0, len(s)
	digits := func() int {
		start := i
		for i < n && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		return i - start
	}
	if digits() == 0 {
		return false
	}
	if i < n && s[i] == '.' {
		i++
		if digits() == 0 {
			return false
		}
	}
	if i < n && (s[i] == 'e' || s[i] == 'E') {
		i++
		if i < n && (s[i] == '+' || s[i] == '-') {
			i++
		}
		if digits() == 0 {
			return false
		}
	}
	return i == n
}

// numericLabel reports whether a label reads as a number to inet_aton:
// decimal digits, or 0x followed by hex digits (0x alone included).
func numericLabel(l string) bool {
	if len(l) >= 2 && l[0] == '0' && (l[1] == 'x' || l[1] == 'X') {
		for i := 2; i < len(l); i++ {
			if !hexByte(l[i]) {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(l); i++ {
		if l[i] < '0' || l[i] > '9' {
			return false
		}
	}
	return true
}

// hostByte reports whether c may appear in a hostname target.
func hostByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.'
}

func hexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// declaresTargets reports whether the profile gives the tool any target
// source.
func declaresTargets(spec classify.ToolSpec) bool {
	return len(spec.TargetParams) > 0 || len(spec.TargetsParams) > 0 || len(spec.GroupParams) > 0
}

// argumentFindings is the hook for the closed argument list (board task
// M1-35, ADR 0033, PR #161): the argument names classify reports as not
// named by the profile, and the named target, command or config arguments
// whose value is not a string that does not parse as JSON, or a list of
// such strings. Either one is default:bad_arguments; the argument is never
// stripped and never named to the agent (the decision log line carries the
// names, capped).
//
// TODO(M1-35): once PR #161 is on main, read res.UnnamedArgs and
// res.MalformedArgs directly and drop the reflection. Until then
// classify.Result has neither field and this returns nothing;
// TestClosedArgumentListHook starts running, and must pass, the moment it
// does. M1-19 must not wire the gate into the proxy before that.
func argumentFindings(res classify.Result) (unnamed, malformed []string) {
	v := reflect.ValueOf(res)
	field := func(name string) []string {
		f := v.FieldByName(name)
		if !f.IsValid() {
			return nil
		}
		s, _ := f.Interface().([]string)
		return s
	}
	return field("UnnamedArgs"), field("MalformedArgs")
}
