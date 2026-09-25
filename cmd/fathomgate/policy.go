// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/inventory"
	"github.com/fathomgate/fathomgate/internal/policy"
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
// case. It exits 1 if any case fails.
func cmdPolicyTest(args []string) int {
	fs := flag.NewFlagSet("policy test", flag.ContinueOnError)
	verbose := fs.Bool("v", false, "print the trace for failing cases")
	files, err := parseInterspersed(fs, args)
	if err != nil {
		return exitUsage
	}
	if len(files) == 0 {
		fmt.Fprintln(os.Stderr, "usage: fathomgate policy test <file.test.yaml>...")
		return exitUsage
	}
	total, failed := 0, 0
	for _, path := range files {
		results, err := policy.RunTestFile(path)
		if err != nil {
			return fail(err)
		}
		fmt.Printf("%s\n", path)
		for _, r := range results {
			total++
			if r.Pass {
				fmt.Printf("  PASS  %s\n", r.Name)
				continue
			}
			failed++
			fmt.Printf("  FAIL  %s: %s\n", r.Name, r.Message)
			if *verbose {
				printTrace(os.Stdout, r.Got, "        ")
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
func cmdPolicyEval(args []string) int {
	fs := flag.NewFlagSet("policy eval", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "policy file (required)")
	invPath := fs.String("inventory", "", "inventory.yaml used to resolve --target roles")
	profilePath := fs.String("profile", "", "server profile; with --arg, classifies the call instead of --class")
	server := fs.String("server", "", "upstream server name")
	tool := fs.String("tool", "", "tool name")
	className := fs.String("class", "", "class (READ_OPERATIONAL, READ_CONFIG, WRITE_CONFIG, EXEC_ARBITRARY, INVENTORY_READ, LAB_LIFECYCLE, LOCAL_ADMIN)")
	var targets, kvArgs stringList
	fs.Var(&targets, "target", "target device name (repeatable)")
	fs.Var(&kvArgs, "arg", "tool argument key=value (repeatable); arrays as a,b,c")
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

	req := policy.Request{Server: *server, Tool: *tool}
	req.Session = policy.Session{DevicesTouched: *touched, PendingHolds: *pending}

	var classNote string
	var argDeny *policy.Decision
	if *profilePath != "" {
		prof, err := classify.LoadProfile(*profilePath)
		if err != nil {
			return fail(err)
		}
		if req.Server == "" {
			req.Server = prof.Server
		}
		res := classify.Classify(prof, *tool, parseArgs(kvArgs))
		req.Class = res.Class
		targets = append(targets, res.Targets...)
		if res.Reason != "" {
			classNote = fmt.Sprintf(" (profile %s; %s)", res.ProfileClass, res.Reason)
		}
		argDeny = argumentDecision(res)
	}
	if *className != "" {
		c, err := classify.Parse(*className)
		if err != nil {
			return fail(err)
		}
		req.Class = c
	}
	if req.Class == "" {
		return fail(fmt.Errorf("--class is required unless --profile and --arg classify the call"))
	}

	var resolver inventory.Resolver = inventory.Chain{}
	if *invPath != "" {
		chain, err := inventory.LoadChain(*invPath)
		if err != nil {
			return fail(err)
		}
		resolver = chain
	}
	for _, name := range targets {
		t := policy.Target{Name: name}
		if inv, ok := resolver.Resolve(name); ok {
			t.Role, t.Site, t.Tags, t.Known = inv.Role, inv.Site, inv.Tags, true
		}
		req.Targets = append(req.Targets, t)
	}

	var d policy.Decision
	if argDeny != nil {
		// The gate refuses the call before Evaluate (ADR 0026 step 1,
		// ADR 0033); eval shows what the gate will do.
		d = *argDeny
	} else {
		d = policy.Evaluate(p, req)
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(struct {
			Request  policy.Request  `json:"request"`
			Decision policy.Decision `json:"decision"`
		}{req, d}); err != nil {
			return fail(err)
		}
	} else {
		printDecision(req, d, classNote)
	}
	switch d.Effect {
	case policy.Allow:
		return exitOK
	case policy.Hold:
		return exitHold
	default:
		return exitFail
	}
}

func printDecision(req policy.Request, d policy.Decision, classNote string) {
	fmt.Printf("decision:    %s\n", d.Effect)
	fmt.Printf("class:       %s%s\n", req.Class, classNote)
	if len(req.Targets) == 0 {
		fmt.Printf("targets:     (none)\n")
	}
	for _, t := range req.Targets {
		fmt.Printf("target:      %s\n", describeTarget(t))
	}
	fmt.Printf("rule:        %s\n", d.RuleID)
	if d.Reason != "" {
		fmt.Printf("reason:      %s\n", d.Reason)
	}
	if len(d.Obligations) > 0 {
		fmt.Printf("obligations: %s\n", strings.Join(d.Obligations, ", "))
	}
	if d.Approval != nil {
		fmt.Printf("approval:    ttl %s, approver must differ: %v\n", d.Approval.TTL, d.Approval.ApproverMustDiffer)
	}
	fmt.Println("trace:")
	printTrace(os.Stdout, d, "  ")
}

func printTrace(w *os.File, d policy.Decision, indent string) {
	for _, e := range d.Trace {
		mark := "-"
		if e.Matched {
			mark = "*"
		}
		_, _ = fmt.Fprintf(w, "%s%s %-32s %s\n", indent, mark, e.RuleID, e.Note)
	}
}

func describeTarget(t policy.Target) string {
	if !t.Known {
		return t.Name + " (unknown)"
	}
	var parts []string
	if t.Role != "" {
		parts = append(parts, "role "+t.Role)
	}
	if t.Site != "" {
		parts = append(parts, "site "+t.Site)
	}
	if len(t.Tags) > 0 {
		parts = append(parts, "tags "+strings.Join(t.Tags, ","))
	}
	if len(parts) == 0 {
		return t.Name
	}
	return t.Name + " (" + strings.Join(parts, ", ") + ")"
}

// argumentDecision returns the deny the gate gives a call whose arguments
// fail the profile's closed argument list, or nil when they pass. The reason
// is fixed text: the agent-facing reason never quotes an argument name. The
// trace note names them, for the operator running eval.
func argumentDecision(res classify.Result) *policy.Decision {
	if res.ArgumentsOK() {
		return nil
	}
	reason := "an argument is not named in the server profile for this tool"
	var notes []string
	if len(res.UnnamedArgs) > 0 {
		notes = append(notes, "not named: "+strings.Join(quoteAll(res.UnnamedArgs), ", "))
	}
	if len(res.MalformedArgs) > 0 {
		if len(res.UnnamedArgs) == 0 {
			reason = "a target, command or config argument is not a string or a list of strings"
		}
		notes = append(notes, "not a string or list of strings: "+strings.Join(quoteAll(res.MalformedArgs), ", "))
	}
	return &policy.Decision{
		Effect: policy.Deny,
		RuleID: policy.RuleBadArguments,
		Reason: reason,
		Trace:  []policy.TraceEntry{{RuleID: policy.RuleBadArguments, Matched: true, Note: strings.Join(notes, "; ")}},
	}
}

func quoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
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
