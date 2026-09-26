// SPDX-License-Identifier: FSL-1.1-ALv2

package policytest

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/configset"
	"github.com/fathomgate/fathomgate/internal/gate"
	"github.com/fathomgate/fathomgate/internal/gate/seam"
	"github.com/fathomgate/fathomgate/internal/inventory"
	"github.com/fathomgate/fathomgate/internal/policy"
)

// Runner runs test files against one profile set.
type Runner struct {
	profiles map[string]*classify.Profile
	source   string
}

// NewRunner loads the profile set every gate case of the run uses: the
// embedded set when dir is empty, the set in dir otherwise (replacing the
// embedded set, never merging), as serve --profiles loads it.
func NewRunner(dir string) (*Runner, error) {
	set, source, err := configset.Profiles(dir)
	if err != nil {
		if dir != "" {
			return nil, fmt.Errorf("--profiles: %w", err)
		}
		return nil, err
	}
	return &Runner{profiles: configset.ByServer(set), source: source}, nil
}

// Source is the profile set's name: "embedded" or the directory.
func (r *Runner) Source() string { return r.source }

// Result is the outcome of one case.
type Result struct {
	Name string
	// Gate reports whether the case ran the gate path.
	Gate bool
	Pass bool
	// Message explains a failure in one line. It quotes names that are
	// not printable ASCII and never holds an argument value.
	Message string
	// Effect and RuleID are what the case got.
	Effect policy.Effect
	RuleID string
	// Class and ClassSource are the gate's, for a gate case.
	Class, ClassSource string
	// Trace is the rule trace, for -v.
	Trace []policy.TraceEntry
}

// RunFile loads the test file at path, its policy and its inventory, checks
// every case, and runs them. The error is non-nil only when the files
// cannot be read or loaded or a case breaks a load rule; a failing case is
// reported in its Result.
func (r *Runner) RunFile(path string) ([]Result, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read test file: %w", err)
	}
	f, err := Parse(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	dir := filepath.Dir(path)
	p, err := policy.Load(resolve(dir, f.Policy))
	if err != nil {
		return nil, err
	}

	var resolver inventory.Resolver
	if f.Inventory != nil {
		chain, err := loadInventory(dir, f.Inventory)
		if err != nil {
			// Decode and chain errors already start with "inventory:".
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		resolver = chain
	}
	for i, c := range f.Cases {
		if c.IsGate() && r.profiles[c.Request.Server] == nil {
			return nil, fmt.Errorf("%s: case %d %s: server %s has no profile in the %s profile set; a gate case must name a profiled server (serve would deny every call to it that carries arguments)",
				path, i+1, quote(c.Name), quote(c.Request.Server), r.source)
		}
	}
	g, err := gate.New(gate.Config{Policy: p, Profiles: r.profiles, Inventory: resolver})
	if err != nil {
		return nil, err
	}
	return runCases(p, g, f.Cases), nil
}

func resolve(dir, p string) string {
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(dir, p)
}

// loadInventory reads a path as serve --inventory does (configfile checks,
// no CSV) or parses the inline document, and builds the same chain.
func loadInventory(dir string, inv *Inventory) (inventory.Resolver, error) {
	b := inv.Inline
	if inv.Path != "" {
		var err error
		b, err = configset.ReadInventory(resolve(dir, inv.Path))
		if err != nil {
			return nil, fmt.Errorf("inventory %s: %w", quote(inv.Path), err)
		}
	}
	_, chain, err := configset.ParseInventory(b)
	if err != nil {
		return nil, err
	}
	return chain, nil
}

// runCases runs every case. g is the gate for the gate cases; it holds the
// same policy p.
func runCases(p *policy.Policy, g *gate.Gate, cases []Case) []Result {
	out := make([]Result, 0, len(cases))
	for _, c := range cases {
		if c.IsGate() {
			out = append(out, runGate(g, c))
			continue
		}
		d := policy.Evaluate(p, c.Request.request())
		res := Result{Name: c.Name, Effect: d.Effect, RuleID: d.RuleID, Trace: d.Trace, Pass: true}
		res.Message = mismatch(c.Expect, d.Effect, d.RuleID, d.Obligations)
		res.Pass = res.Message == ""
		out = append(out, res)
	}
	return out
}

// mismatch checks effect, rule and obligations, in that order.
func mismatch(e Expect, effect policy.Effect, rule string, obligations []string) string {
	switch {
	case effect != e.Effect:
		return fmt.Sprintf("effect %s (rule %s), want %s", effect, quote(rule), e.Effect)
	case e.Rule != "" && rule != e.Rule:
		return fmt.Sprintf("rule %s, want %s", quote(rule), quote(e.Rule))
	case e.Obligations != nil && !sameSet(obligations, e.Obligations):
		return fmt.Sprintf("obligations %s, want %s", quoteAll(sorted(obligations)), quoteAll(sorted(e.Obligations)))
	}
	return ""
}

// runGate decides the case through the gate and checks every assertion in
// ADR 0035's order: effect, rule, class, class_source, obligations,
// targets, unknown_target, parse_error, unnamed_args, malformed_args,
// forwarded, tool_error. The log-line fields come from Verdict.Record by
// name, as the operator reads them.
func runGate(g *gate.Gate, c Case) Result {
	r := c.Request
	in := seam.CallInfo{
		Server:         r.Server,
		Tool:           r.Tool,
		Arguments:      json.RawMessage(c.ArgumentBytes()),
		DevicesTouched: r.Session.DevicesTouched,
		PendingHolds:   r.Session.PendingHolds,
	}
	if r.Annotations != nil {
		in.ReadOnlyHint, in.DestructiveHint = r.Annotations.ReadOnlyHint, r.Annotations.DestructiveHint
	}
	ex := g.Explain(context.Background(), in)
	v := ex.Verdict
	rec := record(v.Record)
	res := Result{
		Name: c.Name, Gate: true,
		Effect: policy.Effect(v.Effect), RuleID: v.RuleID,
		Class: v.Class, ClassSource: v.ClassSource,
		Trace: ex.Decision.Trace,
	}
	e := c.Expect
	msg := mismatch(Expect{Effect: e.Effect, Rule: e.Rule}, res.Effect, v.RuleID, nil)
	switch {
	case msg != "":
	case e.Class != "" && v.Class != string(e.Class):
		msg = fmt.Sprintf("class %s (class_source %s), want %s", v.Class, v.ClassSource, e.Class)
	case e.ClassSource != "" && v.ClassSource != e.ClassSource:
		msg = fmt.Sprintf("class_source %s, want %s", v.ClassSource, e.ClassSource)
	case e.Obligations != nil && !sameSet(rec.strings("obligations"), e.Obligations):
		msg = fmt.Sprintf("obligations %s, want %s", quoteAll(sorted(rec.strings("obligations"))), quoteAll(sorted(e.Obligations)))
	case e.Targets != nil && !slices.Equal(v.Targets, *e.Targets):
		msg = fmt.Sprintf("targets %s, want %s", quoteAll(v.Targets), quoteAll(*e.Targets))
	case e.UnknownTarget != nil && rec.bool("unknown_target") != *e.UnknownTarget:
		msg = fmt.Sprintf("unknown_target %t, want %t", rec.bool("unknown_target"), *e.UnknownTarget)
	case e.ParseError != "" && rec.string("parse_error") != e.ParseError:
		msg = fmt.Sprintf("parse_error %s, want %s", orNone(rec.string("parse_error")), e.ParseError)
	case e.UnnamedArgs != nil && !sameSet(rec.strings("unnamed_args"), *e.UnnamedArgs):
		msg = fmt.Sprintf("unnamed_args %s, want %s", quoteAll(sorted(rec.strings("unnamed_args"))), quoteAll(sorted(*e.UnnamedArgs)))
	case e.MalformedArgs != nil && !sameSet(rec.strings("malformed_args"), *e.MalformedArgs):
		msg = fmt.Sprintf("malformed_args %s, want %s", quoteAll(sorted(rec.strings("malformed_args"))), quoteAll(sorted(*e.MalformedArgs)))
	case e.Forwarded != nil && v.Forward != *e.Forwarded:
		msg = fmt.Sprintf("forwarded %t, want %t", v.Forward, *e.Forwarded)
	case e.ToolError != nil && v.Error != *e.ToolError:
		msg = fmt.Sprintf("tool_error %s, want %s", strconv.QuoteToASCII(v.Error), strconv.QuoteToASCII(*e.ToolError))
	}
	res.Message, res.Pass = msg, msg == ""
	return res
}

// logRecord is the decision log line's attributes by key.
type logRecord map[string]slog.Value

func record(attrs []slog.Attr) logRecord {
	out := make(logRecord, len(attrs))
	for _, a := range attrs {
		out[a.Key] = a.Value.Resolve()
	}
	return out
}

func (r logRecord) string(key string) string {
	v, ok := r[key]
	if !ok || v.Kind() != slog.KindString {
		return ""
	}
	return v.String()
}

func (r logRecord) bool(key string) bool {
	v, ok := r[key]
	return ok && v.Kind() == slog.KindBool && v.Bool()
}

func (r logRecord) strings(key string) []string {
	v, ok := r[key]
	if !ok || v.Kind() != slog.KindAny {
		return nil
	}
	s, _ := v.Any().([]string)
	return s
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func sameSet(a, b []string) bool {
	return slices.Equal(sorted(a), sorted(b))
}

func sorted(in []string) []string {
	out := slices.Clone(in)
	sort.Strings(out)
	return out
}
