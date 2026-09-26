// SPDX-License-Identifier: FSL-1.1-ALv2

// Package policytest reads and runs the *.test.yaml files of `fathomgate
// policy test` (policy-schema section 7, ADR 0035).
//
// A file holds two kinds of case. A class-given case (request.class) runs
// policy.Evaluate on the request as written, as every case did before ADR
// 0035. A gate case (request.arguments or request.arguments_json) runs
// internal/gate Explain, the steps serve runs on every tools/call: parse,
// caps, normalise, classify, the closed argument list, targets, resolve,
// Evaluate. Its profile comes from the run's profile set (the embedded set,
// or --profiles), and its inventory from the test file, both loaded by
// internal/configset as serve loads them.
//
// Nothing here prints or returns an argument value. Case names, argument
// names and target names in messages are quoted when they are not printable
// ASCII, since a suite that carries injection inputs is itself the
// injection text.
package policytest

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
	"github.com/goccy/go-yaml/parser"
	"github.com/goccy/go-yaml/token"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/policy"
	"github.com/fathomgate/fathomgate/internal/termsafe"
	"github.com/fathomgate/fathomgate/internal/yamlstrict"
)

// MaxArgumentBytes is the proxy's cap on a tools/call's arguments as the
// agent sent them (internal/proxy maxArgumentBytes, ADR 0026 *Argument
// cap*). The proxy refuses a larger call before the gate runs, so a gate
// case above it could never show what serve does; it is a load error.
const MaxArgumentBytes = 64 << 10

// MaxCaseName caps a case name in bytes. A name is printed on every PASS
// and FAIL line, so a long one multiplies the output (security review of
// PR #197, L3).
const MaxCaseName = 256

// ParseErrors are the decision log line's parse_error codes a gate case may
// assert (ADR 0026, and M1-39 for the two caps).
var ParseErrors = []string{"invalid_utf8", "invalid_json", "not_object", "duplicate_key", "trailing_data", "too_many_commands", "too_many_targets"}

// File is the schema of a *.test.yaml file.
type File struct {
	// Policy is the policy path, relative to the test file's directory.
	Policy string `yaml:"policy"`
	// Inventory is the inventory the gate cases resolve targets through: a
	// path relative to the test file, or the document inline. Class-given
	// cases ignore it.
	Inventory *Inventory `yaml:"inventory,omitempty"`
	// Cases are the assertions.
	Cases []Case `yaml:"cases"`
}

// Inventory is the file-level inventory: exactly one of Path and Inline.
type Inventory struct {
	Path   string
	Inline []byte
}

// UnmarshalYAML takes a string (a path) or a mapping (the inventory
// document itself, in the inventory-schema section 3 format).
func (inv *Inventory) UnmarshalYAML(n ast.Node) error {
	switch n.(type) {
	case *ast.StringNode, *ast.LiteralNode:
		var s string
		if err := yaml.NodeToValue(n, &s); err != nil {
			return errors.New("inventory: a path must be a string")
		}
		if strings.TrimSpace(s) == "" {
			return errors.New("inventory: the path is empty")
		}
		inv.Path = s
		return nil
	case *ast.MappingNode, *ast.MappingValueNode:
		if err := plainYAML(n, false); err != nil {
			return fmt.Errorf("inventory: %w", err)
		}
		inv.Inline = []byte(n.String())
		return nil
	}
	return errors.New("inventory: give a path or the inventory document as a mapping")
}

// Case is one (request, expected decision) pair.
type Case struct {
	Name    string  `yaml:"name"`
	Request Request `yaml:"request"`
	Expect  Expect  `yaml:"expect"`
}

// Request is a case's input. A class-given case sets Class and may set
// Targets; a gate case sets Arguments or ArgumentsJSON, Server and Tool, and
// may set Annotations. Both may set Session.
type Request struct {
	Server  string         `yaml:"server,omitempty"`
	Tool    string         `yaml:"tool,omitempty"`
	Class   classify.Class `yaml:"class,omitempty"`
	Targets *[]Target      `yaml:"targets,omitempty"`
	Session policy.Session `yaml:"session,omitempty"`

	// Arguments is the arguments object, encoded with encoding/json.
	Arguments *Arguments `yaml:"arguments,omitempty"`
	// ArgumentsJSON is the arguments exactly as the agent's bytes.
	ArgumentsJSON *string `yaml:"arguments_json,omitempty"`
	// Annotations are the tool's hints as an upstream would send them.
	Annotations *Annotations `yaml:"annotations,omitempty"`
}

// Target is a class-given case's target; Known defaults to true.
type Target struct {
	Name  string   `yaml:"name"`
	Role  string   `yaml:"role,omitempty"`
	Tags  []string `yaml:"tags,omitempty"`
	Site  string   `yaml:"site,omitempty"`
	Known *bool    `yaml:"known,omitempty"`
}

// Annotations are readOnlyHint and destructiveHint; absent is nil.
type Annotations struct {
	ReadOnlyHint    *bool `yaml:"readOnlyHint,omitempty"`
	DestructiveHint *bool `yaml:"destructiveHint,omitempty"`
}

// Arguments is a gate case's arguments mapping, already encoded as the JSON
// object the gate receives.
type Arguments struct {
	JSON []byte
}

// UnmarshalYAML accepts a mapping of plain YAML: string keys, values that
// are strings, numbers, booleans, null, lists and mappings. A merge key, a
// tag, an anchor or an alias is refused, since each makes the YAML say
// something other than what the case shows; so is an unquoted value that
// would reach the gate as something other than what is written (see
// plainScalar), and a number JSON cannot hold. For bytes a mapping cannot
// express, use arguments_json.
func (a *Arguments) UnmarshalYAML(n ast.Node) error {
	switch n.(type) {
	case *ast.MappingNode, *ast.MappingValueNode:
	default:
		return errors.New("arguments must be a mapping; use {} for a call with none, or arguments_json for other bytes")
	}
	if err := plainYAML(n, true); err != nil {
		return fmt.Errorf("arguments: %w", err)
	}
	var m map[string]any
	if err := yaml.NodeToValue(n, &m); err != nil {
		return errors.New("arguments: cannot be decoded as a mapping")
	}
	if m == nil {
		m = map[string]any{}
	}
	if err := jsonValue(m); err != nil {
		return fmt.Errorf("arguments: %w", err)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return errors.New("arguments: cannot be encoded as JSON")
	}
	a.JSON = b
	return nil
}

// plainYAML refuses what makes a YAML mapping say something other than
// what it shows: a non-string key, a merge key, a tag, an anchor or an
// alias, and, with scalars set, an unquoted value plainScalar refuses.
func plainYAML(n ast.Node, scalars bool) error {
	v := &plainVisitor{scalars: scalars}
	ast.Walk(v, n)
	return v.err
}

// plainVisitor walks a mapping and keeps the first thing plainYAML refuses.
type plainVisitor struct {
	scalars bool
	keys    map[ast.Node]bool
	err     error
}

// Visit implements ast.Visitor.
func (v *plainVisitor) Visit(n ast.Node) ast.Visitor {
	if v.err != nil {
		return nil
	}
	switch t := n.(type) {
	case *ast.MappingValueNode:
		if v.keys == nil {
			v.keys = map[ast.Node]bool{}
		}
		v.keys[t.Key] = true
		if t.Key.IsMergeKey() {
			v.err = errors.New("a merge key (<<) is not allowed; write the keys out")
			return nil
		}
		if _, ok := t.Key.(*ast.StringNode); !ok {
			v.err = errors.New("every key must be a string; quote it")
			return nil
		}
	case *ast.TagNode:
		v.err = errors.New("a YAML tag is not allowed")
		return nil
	case *ast.AnchorNode, *ast.AliasNode:
		v.err = errors.New("an anchor or alias is not allowed; write the value out")
		return nil
	case *ast.StringNode, *ast.IntegerNode, *ast.FloatNode, *ast.BoolNode, *ast.NullNode, *ast.InfinityNode, *ast.NanNode:
		if v.scalars && !v.isKey(n) {
			if what, lookalike := plainScalar(n); what != "" || lookalike {
				line := 0
				if tk := n.GetToken(); tk != nil && tk.Position != nil {
					line = tk.Position.Line
				}
				if lookalike {
					v.err = fmt.Errorf("the unquoted value at line %d looks like a number, date or time; quote it", line)
				} else {
					v.err = fmt.Errorf("the unquoted value at line %d would reach the gate as %s, not as written; quote it, or give the exact bytes in arguments_json", line, what)
				}
				return nil
			}
		}
	}
	return v
}

// isKey reports whether n is a mapping key. Walk visits keys as well as
// values; the MappingValueNode case records each key (after checking it is
// a plain string), so the value rules in plainScalar are not applied to it.
func (v *plainVisitor) isKey(n ast.Node) bool {
	_, ok := v.keys[n]
	return ok
}

// Numbers, dates and times a YAML author writes unquoted but goccy/go-yaml
// keeps as strings, or reads as a number other than the one written.
var (
	decimalInt   = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	decimalFloat = regexp.MustCompile(`^-?(0|[1-9][0-9]*)\.[0-9]+$`)
	numberLike   = regexp.MustCompile(`^[-+]?([0-9][0-9_]*\.?[0-9_]*|\.[0-9][0-9_]*)([eE][-+]?[0-9]+)?$`)
	dateLike     = regexp.MustCompile(`^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}([Tt ]|$)`)
	timeLike     = regexp.MustCompile(`^[-+]?[0-9]+(:[0-9]+)+(\.[0-9]*)?$`)
)

// plainScalar reports an unquoted scalar that does not reach the gate as
// written (security reviews of PR #197, L4, and PR #199, R3; ADR 0035
// section 2). what names what it would become instead; lookalike is true for
// a plain string that goccy/go-yaml keeps as written but that reads as a
// number, a date or a time (1e3, 2026-09-25, 12:30, 65000:100, an all-digit
// MAC address), which the author most likely meant as something else.
//
// A number is accepted only when its text is plain decimal (no sign other
// than -, no leading zero, no _, no 0x, 0o or 0b, digits on both sides of a
// point, no exponent) and encoding/json writes the decoded value back as
// exactly that text, so 1.0, 2.50, -0, a value past float64's precision, or
// one JSON would write with an exponent, is refused. true, false and null
// are accepted as spelled; quoted strings and block scalars always are.
func plainScalar(n ast.Node) (what string, lookalike bool) {
	tk := n.GetToken()
	if tk == nil {
		return "", false
	}
	text := tk.Value
	switch n.(type) {
	case *ast.StringNode:
		if tk.Type == token.SingleQuoteType || tk.Type == token.DoubleQuoteType {
			return "", false
		}
		if numberLike.MatchString(text) || dateLike.MatchString(text) || timeLike.MatchString(text) {
			return "", true
		}
	case *ast.IntegerNode:
		if tk.Type != token.IntegerType || !decimalInt.MatchString(text) || !encodesAs(n, text) {
			return "a different number", false
		}
	case *ast.FloatNode:
		if !decimalFloat.MatchString(text) || !encodesAs(n, text) {
			return "a different number", false
		}
	case *ast.BoolNode:
		if text != "true" && text != "false" {
			return "a boolean", false
		}
	case *ast.NullNode:
		if tk.Type != token.ImplicitNullType && text != "null" {
			return "null", false
		}
	case *ast.InfinityNode, *ast.NanNode:
		return "a number JSON cannot carry", false
	}
	return "", false
}

// encodesAs reports whether the number n decodes to a value encoding/json
// writes as exactly text: the bytes the gate would receive.
func encodesAs(n ast.Node, text string) bool {
	var v any
	if err := yaml.NodeToValue(n, &v); err != nil {
		return false
	}
	b, err := json.Marshal(v)
	return err == nil && string(b) == text
}

// jsonValue checks that a decoded value is one JSON can carry as written.
func jsonValue(x any) error {
	switch t := x.(type) {
	case nil, string, bool, int, int64, uint64:
		return nil
	case float64:
		if math.IsInf(t, 0) || math.IsNaN(t) {
			return errors.New("a number is not finite")
		}
		return nil
	case []any:
		for _, e := range t {
			if err := jsonValue(e); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for _, e := range t {
			if err := jsonValue(e); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("a value of type %T cannot be sent as JSON", x)
}

// Expect is the expected decision. Effect is required; every other field
// is asserted only when present. The fields after Obligations are for gate
// cases only.
type Expect struct {
	Effect      policy.Effect `yaml:"effect"`
	Rule        string        `yaml:"rule,omitempty"`
	Obligations []string      `yaml:"obligations,omitempty"`

	Class         classify.Class `yaml:"class,omitempty"`
	ClassSource   string         `yaml:"class_source,omitempty"`
	Targets       *[]string      `yaml:"targets,omitempty"`
	UnknownTarget *bool          `yaml:"unknown_target,omitempty"`
	ParseError    string         `yaml:"parse_error,omitempty"`
	UnnamedArgs   *[]string      `yaml:"unnamed_args,omitempty"`
	MalformedArgs *[]string      `yaml:"malformed_args,omitempty"`
	Forwarded     *bool          `yaml:"forwarded,omitempty"`
	ToolError     *string        `yaml:"tool_error,omitempty"`
}

// gateOnly names the gate-only expect fields a case sets.
func (e Expect) gateOnly() []string {
	var out []string
	add := func(set bool, name string) {
		if set {
			out = append(out, name)
		}
	}
	add(e.Class != "", "class")
	add(e.ClassSource != "", "class_source")
	add(e.Targets != nil, "targets")
	add(e.UnknownTarget != nil, "unknown_target")
	add(e.ParseError != "", "parse_error")
	add(e.UnnamedArgs != nil, "unnamed_args")
	add(e.MalformedArgs != nil, "malformed_args")
	add(e.Forwarded != nil, "forwarded")
	add(e.ToolError != nil, "tool_error")
	return out
}

// IsGate reports whether the case runs the gate path.
func (c Case) IsGate() bool {
	return c.Request.Arguments != nil || c.Request.ArgumentsJSON != nil
}

// Parse decodes a test file and checks every rule that does not need the
// profile set: see check. Anchors and aliases are refused anywhere in the
// file before it is decoded, since a few kilobytes of aliases expand into
// hundreds of megabytes of case names and output (security review of PR
// #197, L3).
func Parse(b []byte) (*File, error) {
	if err := noAnchors(b); err != nil {
		return nil, err
	}
	var f File
	if err := yamlstrict.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("parse test file: %w", err)
	}
	if strings.TrimSpace(f.Policy) == "" {
		return nil, errors.New("test file: policy is required")
	}
	if len(f.Cases) == 0 {
		return nil, errors.New("test file: cases is empty")
	}
	for i, c := range f.Cases {
		if len(c.Name) > MaxCaseName {
			return nil, fmt.Errorf("test file: case %d: the name is %d bytes; at most %d", i+1, len(c.Name), MaxCaseName)
		}
		if err := c.check(); err != nil {
			return nil, fmt.Errorf("test file: case %d %s: %w", i+1, termsafe.Quote(c.Name), err)
		}
	}
	return &f, nil
}

// noAnchors refuses a YAML anchor (&) or alias (*) anywhere in a test file.
// A file that does not parse is left to the strict decoder, whose errors
// never quote the file.
func noAnchors(b []byte) error {
	f, perr := parser.ParseBytes(b, 0)
	if perr != nil || f == nil {
		// yamlstrict.Unmarshal reports it, without quoting the file.
		return nil //nolint:nilerr // the parse error is the strict decoder's to report
	}
	v := &anchorVisitor{}
	for _, d := range f.Docs {
		ast.Walk(v, d)
		if v.line != 0 {
			return fmt.Errorf("test file: line %d: anchors (&) and aliases (*) are not allowed; write each value out", v.line)
		}
	}
	return nil
}

// anchorVisitor keeps the line of the first anchor or alias.
type anchorVisitor struct{ line int }

// Visit implements ast.Visitor.
func (v *anchorVisitor) Visit(n ast.Node) ast.Visitor {
	if v.line != 0 {
		return nil
	}
	switch n.(type) {
	case *ast.AnchorNode, *ast.AliasNode:
		v.line = 1
		if tk := n.GetToken(); tk != nil && tk.Position != nil {
			v.line = tk.Position.Line
		}
		return nil
	}
	return v
}

// check applies ADR 0035's load rules to one case: each is a case that
// could never pass, or could pass for the wrong reason.
func (c Case) check() error {
	r, e := c.Request, c.Expect
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("has no name")
	}
	if !e.Effect.Valid() {
		return errors.New("expect.effect must be allow, hold or deny")
	}
	if !c.IsGate() {
		switch {
		case r.Class == "":
			return errors.New("give request.class, or request.arguments (or arguments_json) for a gate case")
		case !r.Class.Valid():
			return errors.New("request.class is not a class")
		case r.Annotations != nil:
			return errors.New("request.annotations is for a gate case (request.arguments); a class-given case sets the class itself")
		}
		if g := e.gateOnly(); len(g) > 0 {
			return fmt.Errorf("expect.%s: for a gate case only (request.arguments)", strings.Join(g, ", expect."))
		}
		return nil
	}

	switch {
	case r.Arguments != nil && r.ArgumentsJSON != nil:
		return errors.New("give request.arguments or request.arguments_json, not both")
	case r.Class != "":
		return errors.New("request.class with request.arguments: a gate case is classified by the gate; drop one")
	case r.Targets != nil:
		return errors.New("request.targets with request.arguments: the gate takes the targets from the arguments and resolves them through the inventory")
	case r.Server == "":
		return errors.New("a gate case needs request.server, the profile's server key")
	case r.Tool == "":
		return errors.New("a gate case needs request.tool")
	case e.Rule == "":
		return errors.New("a gate case needs expect.rule: the gate fails closed, so effect deny alone passes for any refusal")
	}
	if n := len(c.ArgumentBytes()); n > MaxArgumentBytes {
		return fmt.Errorf("the arguments are %d bytes; the proxy refuses more than %d before the gate runs, so the gate path cannot show it", n, MaxArgumentBytes)
	}
	if e.Class != "" && !e.Class.Valid() {
		return errors.New("expect.class is not a class")
	}
	if e.ClassSource != "" {
		if _, err := classify.ParseSource(e.ClassSource); err != nil {
			return errors.New("expect.class_source is not a class source")
		}
	}
	if e.ParseError != "" && !contains(ParseErrors, e.ParseError) {
		return fmt.Errorf("expect.parse_error must be one of %s", strings.Join(ParseErrors, ", "))
	}
	if (e.ParseError != "" || e.UnnamedArgs != nil || e.MalformedArgs != nil) && e.Rule != policy.RuleBadArguments {
		return fmt.Errorf("expect.parse_error, unnamed_args and malformed_args come only with rule %s", policy.RuleBadArguments)
	}
	return nil
}

// ArgumentBytes are the bytes a gate case sends as the call's arguments,
// nil for a class-given case.
func (c Case) ArgumentBytes() []byte {
	if c.Request.ArgumentsJSON != nil {
		return []byte(*c.Request.ArgumentsJSON)
	}
	if c.Request.Arguments != nil {
		return c.Request.Arguments.JSON
	}
	return nil
}

// request converts a class-given case into a policy.Request.
func (r Request) request() policy.Request {
	out := policy.Request{Server: r.Server, Tool: r.Tool, Class: r.Class, Session: r.Session}
	if r.Targets != nil {
		for _, t := range *r.Targets {
			known := true
			if t.Known != nil {
				known = *t.Known
			}
			out.Targets = append(out.Targets, policy.Target{Name: t.Name, Role: t.Role, Tags: t.Tags, Site: t.Site, Known: known})
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
