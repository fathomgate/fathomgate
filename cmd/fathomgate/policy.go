// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/configset"
	"github.com/fathomgate/fathomgate/internal/gate"
	"github.com/fathomgate/fathomgate/internal/gate/seam"
	"github.com/fathomgate/fathomgate/internal/inventory"
	"github.com/fathomgate/fathomgate/internal/policy"
	"github.com/fathomgate/fathomgate/internal/policytest"
	"github.com/fathomgate/fathomgate/internal/termsafe"
)

func cmdPolicy(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fathomgate policy <test|eval> ...")
		return exitUsage
	}
	switch args[0] {
	case "test":
		return cmdPolicyTest(args[1:])
	case "eval":
		return cmdPolicyEval(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "fathomgate policy: unknown subcommand %q\n", args[0])
		return exitUsage
	}
}

// cmdPolicyTest runs one or more *.test.yaml files and prints PASS/FAIL per
// case. It exits 1 if any case fails and 2 if a file cannot be loaded. Gate
// cases (ADR 0035) use the embedded profiles, or the set --profiles names.
func cmdPolicyTest(args []string) int {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "print the class and the trace for failing cases")
	profilesDir := fs.String("profiles", "", "directory of profile YAML files that replaces the embedded set for gate cases, as serve --profiles does")
	files, err := parseInterspersed(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fathomgate policy test [--profiles <dir>] [-v] <file.test.yaml>...")
		return exitUsage
	}
	runner, err := policytest.NewRunner(*profilesDir)
	if err != nil {
		return fail(err)
	}
	total, failed := 0, 0
	for _, path := range files {
		results, err := runner.RunFile(path)
		if err != nil {
			return fail(err)
		}
		fmt.Printf("%s\n", termsafe.Quote(path))
		for _, r := range results {
			total++
			if r.Pass {
				fmt.Printf("  PASS  %s\n", termsafe.Quote(r.Name))
				continue
			}
			failed++
			fmt.Printf("  FAIL  %s: %s\n", termsafe.Quote(r.Name), r.Message)
			if *verbose {
				if r.Gate {
					fmt.Printf("        class %s (class_source %s)\n", r.Class, r.ClassSource)
				}
				printTrace(os.Stdout, r.Trace, "        ")
			}
		}
	}
	fmt.Printf("%d cases, %d passed, %d failed\n", total, total-failed, failed)
	if failed > 0 {
		return exitFail
	}
	return exitOK
}

// cmdPolicyEval evaluates one synthetic request and prints the decision and
// trace in the console's order: decision, class, target, rule, reason.
//
// With --class and --target it evaluates the class and targets as given.
// With --profile it decides the call through internal/gate, the steps serve
// runs (ADR 0035): the gate classifies the arguments and takes the targets
// from them, so --class and --target are usage errors there.
func cmdPolicyEval(args []string) int {
	fs := flag.NewFlagSet("policy eval", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "policy file (required)")
	invPath := fs.String("inventory", "", "inventory.yaml used to resolve target roles")
	profilePath := fs.String("profile", "", "server profile; decides the call through the gate from its arguments (--arg or --arguments-json)")
	server := fs.String("server", "", "upstream server name (with --profile, the profile's server key)")
	tool := fs.String("tool", "", "tool name")
	className := fs.String("class", "", "class (READ_OPERATIONAL, READ_CONFIG, WRITE_CONFIG, EXEC_ARBITRARY, INVENTORY_READ, LAB_LIFECYCLE, LOCAL_ADMIN); not with --profile")
	var targets, kvArgs stringList
	fs.Var(&targets, "target", "target device name (repeatable); not with --profile")
	fs.Var(&kvArgs, "arg", "tool argument key=value (repeatable); arrays as a,b,c; with --profile")
	argsJSON := fs.String("arguments-json", "", "the tool arguments as the agent's JSON bytes; with --profile, instead of --arg")
	touched := fs.Int("devices-touched", 0, "devices already touched in the session")
	pending := fs.Int("pending-holds", 0, "holds already pending in the session")
	asJSON := fs.Bool("json", false, "print the decision as JSON")
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *policyPath == "" {
		return fail(fmt.Errorf("--policy is required"))
	}
	p, err := policy.Load(*policyPath)
	if err != nil {
		return fail(err)
	}

	var resolver inventory.Resolver
	if *invPath != "" {
		// Read as serve --inventory reads it (configset: the configfile
		// checks, the size cap, no CSV), so eval decides with an inventory
		// serve would load (security review of PR #197, N4).
		b, err := configset.ReadInventory(*invPath)
		if err != nil {
			return fail(fmt.Errorf("--inventory: %w", err))
		}
		_, chain, err := configset.ParseInventory(b)
		if err != nil {
			return fail(fmt.Errorf("--inventory: %s: %w", termsafe.Quote(*invPath), err))
		}
		resolver = chain
	}
	session := policy.Session{DevicesTouched: *touched, PendingHolds: *pending}

	if *profilePath != "" {
		switch {
		case *className != "" || len(targets) > 0:
			return fail(errors.New("--class and --target: not with --profile; the gate classifies the call and takes its targets from the arguments (ADR 0035)"))
		case *argsJSON != "" && len(kvArgs) > 0:
			return fail(errors.New("--arg and --arguments-json: give one"))
		case *tool == "":
			return fail(errors.New("--tool is required with --profile"))
		}
		return evalGate(p, resolver, evalCall{
			profile: *profilePath, server: *server, tool: *tool,
			kvArgs: kvArgs, argsJSON: *argsJSON, session: session, asJSON: *asJSON,
		})
	}
	if len(kvArgs) > 0 || *argsJSON != "" {
		return fail(errors.New("--arg and --arguments-json: only with --profile, which classifies the call from them"))
	}
	if *className == "" {
		return fail(fmt.Errorf("--class is required unless --profile and --arg classify the call"))
	}
	c, err := classify.Parse(*className)
	if err != nil {
		return fail(err)
	}
	req := policy.Request{Server: *server, Tool: *tool, Class: c, Session: session}
	if resolver == nil {
		resolver = inventory.Chain{}
	}
	var badNames []string
	for _, name := range targets {
		// As internal/gate does: a name the gate refuses is
		// default:bad_arguments before resolution, and a name is known only
		// when a name authority lists it exactly as sent (inventory-schema
		// section 7); a hostname pattern only enriches a listed device
		// (ADR 0031).
		if !gate.ValidTargetName(name) {
			badNames = append(badNames, strconv.QuoteToASCII(name))
		}
		t := policy.Target{Name: name}
		if inv, ok := inventory.Known(resolver, name); ok {
			t.Role, t.Site, t.Tags, t.Known = inv.Role, inv.Site, inv.Tags, true
		}
		req.Targets = append(req.Targets, t)
	}
	var d policy.Decision
	if len(badNames) > 0 {
		d = policy.Decision{
			Effect: policy.Deny,
			RuleID: policy.RuleBadArguments,
			Reason: gate.ReasonBadTarget,
			Trace:  []policy.TraceEntry{{RuleID: policy.RuleBadArguments, Matched: true, Note: "not a hostname or IP address: " + strings.Join(badNames, ", ")}},
		}
	} else {
		d = policy.Evaluate(p, req)
	}
	if *asJSON {
		if err := printJSON(struct {
			Request  policy.Request  `json:"request"`
			Decision policy.Decision `json:"decision"`
		}{req, d}); err != nil {
			return fail(err)
		}
	} else {
		printDecision(req, d, "")
	}
	return effectExit(d.Effect)
}

// gateView is what policy eval --profile adds to the decision: the gate's
// own fields, as the decision log line and the agent see them.
type gateView struct {
	ClassSource   string   `json:"class_source"`
	Forwarded     bool     `json:"forwarded"`
	ToolError     string   `json:"tool_error,omitempty"`
	ParseError    string   `json:"parse_error,omitempty"`
	UnnamedArgs   []string `json:"unnamed_args,omitempty"`
	MalformedArgs []string `json:"malformed_args,omitempty"`
}

// evalCall is one policy eval --profile call as the flags give it.
type evalCall struct {
	profile, server, tool string
	kvArgs                []string
	argsJSON              string
	session               policy.Session
	asJSON                bool
}

// evalGate decides one call through internal/gate Explain, the function
// policy test runs gate cases with, with the one profile as the set. The
// profile is read as serve reads each profile (configset: the configfile
// checks, the size cap, the file named after its server key; security
// review of PR #197, N4).
func evalGate(p *policy.Policy, resolver inventory.Resolver, c evalCall) int {
	pf, err := configset.ProfileFileAt(c.profile)
	if err != nil {
		return fail(fmt.Errorf("--profile: %w", err))
	}
	prof := pf.Profile
	if c.server != "" && c.server != prof.Server {
		return fail(fmt.Errorf("--server %s: the profile's server key is %s", termsafe.Quote(c.server), prof.Server))
	}
	raw := []byte(c.argsJSON)
	if c.argsJSON == "" {
		raw, err = json.Marshal(parseArgs(c.kvArgs))
		if err != nil {
			return fail(err)
		}
	}
	g, err := gate.New(gate.Config{Policy: p, Profiles: map[string]*classify.Profile{prof.Server: prof}, Inventory: resolver})
	if err != nil {
		return fail(err)
	}
	ex := g.Explain(context.Background(), seam.CallInfo{
		Server: prof.Server, Tool: c.tool, Arguments: raw,
		DevicesTouched: c.session.DevicesTouched, PendingHolds: c.session.PendingHolds,
	})
	v := ex.Verdict
	req := policy.Request{Server: prof.Server, Tool: c.tool, Class: classify.Class(v.Class), Targets: ex.Targets, Session: c.session}
	view := gateView{
		ClassSource: v.ClassSource, Forwarded: v.Forward, ToolError: v.Error,
		ParseError: ex.ParseError, UnnamedArgs: ex.Unnamed, MalformedArgs: ex.Malformed,
	}
	if c.asJSON {
		if err := printJSON(struct {
			Request  policy.Request  `json:"request"`
			Decision policy.Decision `json:"decision"`
			Gate     gateView        `json:"gate"`
		}{req, ex.Decision, view}); err != nil {
			return fail(err)
		}
		return effectExit(ex.Decision.Effect)
	}
	var note string
	if ex.ClassNote != "" {
		note = fmt.Sprintf(" (profile %s; %s)", ex.ProfileClass, ex.ClassNote)
	}
	printDecision(req, ex.Decision, note, func(w io.Writer) {
		field(w, "class_source", v.ClassSource)
		if view.ParseError != "" {
			field(w, "parse_error", view.ParseError)
		}
		if len(view.UnnamedArgs) > 0 {
			field(w, "unnamed_args", strings.Join(termsafe.QuoteEach(view.UnnamedArgs), ", "))
		}
		if len(view.MalformedArgs) > 0 {
			field(w, "malformed_args", strings.Join(termsafe.QuoteEach(view.MalformedArgs), ", "))
		}
		field(w, "forwarded", strconv.FormatBool(view.Forwarded))
		if view.ToolError != "" {
			field(w, "tool error", termsafe.Quote(view.ToolError))
		}
	})
	return effectExit(ex.Decision.Effect)
}

func effectExit(e policy.Effect) int {
	switch e {
	case policy.Allow:
		return exitOK
	case policy.Hold:
		return exitHold
	default:
		return exitFail
	}
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// labelWidth fits the longest label, "malformed_args:", so every value
// starts in one column.
const labelWidth = len("malformed_args:")

// field prints one "label: value" line with the value aligned.
func field(w io.Writer, label, value string) {
	_, _ = fmt.Fprintf(w, "%-*s %s\n", labelWidth, label+":", value)
}

// printDecision prints the decision in the console's order. extra, when
// given, prints the gate's fields after the obligations and before the
// trace.
func printDecision(req policy.Request, d policy.Decision, classNote string, extra ...func(io.Writer)) {
	w := os.Stdout
	field(w, "decision", string(d.Effect))
	field(w, "class", string(req.Class)+classNote)
	if len(req.Targets) == 0 {
		field(w, "targets", "(none)")
	}
	for _, t := range req.Targets {
		field(w, "target", describeTarget(t))
	}
	field(w, "rule", termsafe.Quote(d.RuleID))
	if d.Reason != "" {
		field(w, "reason", termsafe.Quote(d.Reason))
	}
	if len(d.Obligations) > 0 {
		field(w, "obligations", strings.Join(d.Obligations, ", "))
	}
	if d.Approval != nil {
		field(w, "approval", fmt.Sprintf("ttl %s, approver must differ: %v", d.Approval.TTL, d.Approval.ApproverMustDiffer))
	}
	for _, f := range extra {
		f(w)
	}
	_, _ = fmt.Fprintln(w, "trace:")
	printTrace(w, d.Trace, "  ")
}

// printTrace prints one line per check. Rule ids and notes are quoted when
// they are not printable ASCII: a note can name a target or a test file's
// text.
func printTrace(w io.Writer, trace []policy.TraceEntry, indent string) {
	for _, e := range trace {
		mark := "-"
		if e.Matched {
			mark = "*"
		}
		_, _ = fmt.Fprintf(w, "%s%s %-32s %s\n", indent, mark, termsafe.Quote(e.RuleID), termsafe.Quote(e.Note))
	}
}

func describeTarget(t policy.Target) string {
	name := termsafe.Quote(t.Name)
	if !t.Known {
		return name + " (unknown)"
	}
	var parts []string
	if t.Role != "" {
		parts = append(parts, "role "+termsafe.Quote(t.Role))
	}
	if t.Site != "" {
		parts = append(parts, "site "+termsafe.Quote(t.Site))
	}
	if len(t.Tags) > 0 {
		parts = append(parts, "tags "+termsafe.Quote(strings.Join(t.Tags, ",")))
	}
	if len(parts) == 0 {
		return name
	}
	return name + " (" + strings.Join(parts, ", ") + ")"
}

// parseArgs turns --arg k=v flags into a tool argument map. Values containing
// commas become arrays, mirroring what an agent would send.
func parseArgs(kv []string) map[string]any {
	out := make(map[string]any, len(kv))
	for _, pair := range kv {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		if strings.Contains(v, ",") {
			var arr []any
			for _, part := range strings.Split(v, ",") {
				arr = append(arr, strings.TrimSpace(part))
			}
			out[k] = arr
			continue
		}
		out[k] = v
	}
	return out
}
