package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fathomgate/fathomgate/internal/classify"
)

// planPolicy is the example from docs/PLAN.md "Policy schema".
const planPolicy = `
version: 1
defaults:
  unknown_target: deny
  session:
    max_devices: 5
    max_pending: 2
rules:
  - id: reads-anywhere
    match: { class: [READ_OPERATIONAL, READ_CONFIG, INVENTORY_READ] }
    effect: allow
  - id: lab-writes-free
    match: { class: [WRITE_CONFIG], device_tags: [lab] }
    effect: allow
    obligations: [dry_run, diff]
  - id: prod-core-needs-approval
    match: { class: [WRITE_CONFIG], device_roles: [core, border] }
    effect: hold
    obligations: [dry_run, diff, timed_rollback]
    approval: { ttl: 15m, approver_must_differ: true }
  - id: fleet-cap
    match: { class: [WRITE_CONFIG] }
    when: { targets_count: { gt: 3 } }
    effect: deny
    reason: "fan-out above 3 devices needs a change ticket"
  - id: no-exec
    match: { class: [EXEC_ARBITRARY] }
    effect: deny
`

func mustParse(t *testing.T, src string) *Policy {
	t.Helper()
	p, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func known(name, role string, tags ...string) Target {
	return Target{Name: name, Role: role, Tags: tags, Known: true}
}

func TestEvaluatePlanPolicy(t *testing.T) {
	p := mustParse(t, planPolicy)
	core := known("core-rtr-01", "core", "prod")
	border := known("border-rtr-01", "border", "prod")
	lab := known("lab-leaf-01", "leaf", "lab")
	access := known("acc-sw-01", "access", "prod")
	unknown := Target{Name: "mystery-01"}

	cases := []struct {
		name        string
		req         Request
		wantEffect  Effect
		wantRule    string
		wantOblig   []string
		wantTTL     time.Duration
		wantTraceGE int
	}{
		{
			name:       "show on core allowed",
			req:        Request{Server: "netdev-ssh-mcp", Tool: "run_show_command", Class: classify.ReadOperational, Targets: []Target{core}},
			wantEffect: Allow, wantRule: "reads-anywhere",
		},
		{
			name:       "inventory read with no targets allowed",
			req:        Request{Server: "ntunes-netmiko-mcp-server", Tool: "list_devices", Class: classify.InventoryRead},
			wantEffect: Allow, wantRule: "reads-anywhere",
		},
		{
			name:       "lab write allowed with obligations",
			req:        Request{Class: classify.WriteConfig, Targets: []Target{lab}},
			wantEffect: Allow, wantRule: "lab-writes-free", wantOblig: []string{"dry_run", "diff"},
		},
		{
			name:       "core write held with ttl",
			req:        Request{Class: classify.WriteConfig, Targets: []Target{core}},
			wantEffect: Hold, wantRule: "prod-core-needs-approval", wantOblig: []string{"dry_run", "diff", "timed_rollback"}, wantTTL: 15 * time.Minute,
		},
		{
			name:       "border write held",
			req:        Request{Class: classify.WriteConfig, Targets: []Target{border}},
			wantEffect: Hold, wantRule: "prod-core-needs-approval",
		},
		{
			name:       "mixed lab and core write falls through to no-match deny",
			req:        Request{Class: classify.WriteConfig, Targets: []Target{lab, core}},
			wantEffect: Deny, wantRule: RuleNoMatch,
		},
		{
			name:       "access write not covered is denied",
			req:        Request{Class: classify.WriteConfig, Targets: []Target{access}},
			wantEffect: Deny, wantRule: RuleNoMatch,
		},
		{
			name:       "fan-out above 3 denied by fleet-cap",
			req:        Request{Class: classify.WriteConfig, Targets: []Target{access, known("acc-sw-02", "access"), known("acc-sw-03", "access"), known("acc-sw-04", "access")}},
			wantEffect: Deny, wantRule: "fleet-cap",
		},
		{
			name:       "fan-out of 4 lab devices still allowed by earlier rule",
			req:        Request{Class: classify.WriteConfig, Targets: []Target{lab, known("lab-leaf-02", "leaf", "lab"), known("lab-leaf-03", "leaf", "lab"), known("lab-leaf-04", "leaf", "lab")}},
			wantEffect: Allow, wantRule: "lab-writes-free",
		},
		{
			name:       "exec denied",
			req:        Request{Class: classify.ExecArbitrary, Targets: []Target{lab}},
			wantEffect: Deny, wantRule: "no-exec",
		},
		{
			name:       "unknown target denied even for reads",
			req:        Request{Class: classify.ReadOperational, Targets: []Target{unknown}},
			wantEffect: Deny, wantRule: RuleUnknownTarget,
		},
		{
			name:       "one unknown target among known denies the batch",
			req:        Request{Class: classify.ReadOperational, Targets: []Target{core, unknown}},
			wantEffect: Deny, wantRule: RuleUnknownTarget,
		},
		{
			name:       "session device cap",
			req:        Request{Class: classify.ReadOperational, Targets: []Target{core}, Session: Session{DevicesTouched: 5}},
			wantEffect: Deny, wantRule: RuleMaxDevices,
		},
		{
			name:       "session device cap exactly at limit passes",
			req:        Request{Class: classify.ReadOperational, Targets: []Target{core}, Session: Session{DevicesTouched: 4}},
			wantEffect: Allow, wantRule: "reads-anywhere",
		},
		{
			name:       "pending cap turns hold into deny",
			req:        Request{Class: classify.WriteConfig, Targets: []Target{core}, Session: Session{PendingHolds: 2}},
			wantEffect: Deny, wantRule: RuleMaxPending,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := Evaluate(p, tc.req)
			if d.Effect != tc.wantEffect || d.RuleID != tc.wantRule {
				t.Fatalf("got %s/%s (%s), want %s/%s\ntrace: %+v", d.Effect, d.RuleID, d.Reason, tc.wantEffect, tc.wantRule, d.Trace)
			}
			if tc.wantOblig != nil && !sameSet(d.Obligations, tc.wantOblig) {
				t.Errorf("obligations %v, want %v", d.Obligations, tc.wantOblig)
			}
			if tc.wantTTL != 0 {
				if d.Approval == nil || time.Duration(d.Approval.TTL) != tc.wantTTL || !d.Approval.ApproverMustDiffer {
					t.Errorf("approval = %+v, want ttl %s must-differ", d.Approval, tc.wantTTL)
				}
			}
			if len(d.Trace) == 0 {
				t.Error("trace is empty")
			}
			// The trace must end with the deciding entry.
			last := d.Trace[len(d.Trace)-1]
			if !last.Matched || last.RuleID != d.RuleID {
				t.Errorf("last trace entry %+v does not name the deciding rule %s", last, d.RuleID)
			}
		})
	}
}

func TestEvaluateTraceCoversEveryRuleUntilMatch(t *testing.T) {
	p := mustParse(t, planPolicy)
	d := Evaluate(p, Request{Class: classify.ExecArbitrary, Targets: []Target{known("x", "core")}})
	ids := make([]string, 0, len(d.Trace))
	for _, e := range d.Trace {
		ids = append(ids, e.RuleID)
	}
	want := []string{RuleMaxDevices, "reads-anywhere", "lab-writes-free", "prod-core-needs-approval", "fleet-cap", "no-exec"}
	if strings.Join(ids, ",") != strings.Join(want, ",") {
		t.Fatalf("trace ids %v, want %v", ids, want)
	}
	for _, e := range d.Trace[:len(d.Trace)-1] {
		if e.Matched || e.Note == "" {
			t.Errorf("non-deciding entry %+v should be unmatched with a note", e)
		}
	}
}

func TestUnknownTargetDefaults(t *testing.T) {
	base := `
version: 1
rules:
  - id: reads
    match: { class: [READ_OPERATIONAL] }
    effect: allow
  - id: writes
    match: { class: [WRITE_CONFIG] }
    effect: allow
`
	unknown := Target{Name: "ghost"}
	t.Run("unset denies writes and lets reads through", func(t *testing.T) {
		p := mustParse(t, base)
		if d := Evaluate(p, Request{Class: classify.WriteConfig, Targets: []Target{unknown}}); d.Effect != Deny || d.RuleID != RuleUnknownTarget {
			t.Fatalf("write: %s/%s", d.Effect, d.RuleID)
		}
		if d := Evaluate(p, Request{Class: classify.ExecArbitrary, Targets: []Target{unknown}}); d.Effect != Deny {
			t.Fatalf("exec: %s/%s", d.Effect, d.RuleID)
		}
		d := Evaluate(p, Request{Class: classify.ReadOperational, Targets: []Target{unknown}})
		if d.Effect != Allow || d.RuleID != "reads" {
			t.Fatalf("read: %s/%s", d.Effect, d.RuleID)
		}
		if d.Trace[0].RuleID != RuleUnknownTarget || d.Trace[0].Matched {
			t.Fatalf("read trace should note the unknown target: %+v", d.Trace[0])
		}
	})
	t.Run("allow lets rules decide for writes", func(t *testing.T) {
		p := mustParse(t, strings.Replace(base, "rules:", "defaults: { unknown_target: allow }\nrules:", 1))
		if d := Evaluate(p, Request{Class: classify.WriteConfig, Targets: []Target{unknown}}); d.Effect != Allow || d.RuleID != "writes" {
			t.Fatalf("write: %s/%s", d.Effect, d.RuleID)
		}
	})
	t.Run("deny denies reads", func(t *testing.T) {
		p := mustParse(t, strings.Replace(base, "rules:", "defaults: { unknown_target: deny }\nrules:", 1))
		if d := Evaluate(p, Request{Class: classify.ReadOperational, Targets: []Target{unknown}}); d.Effect != Deny || d.RuleID != RuleUnknownTarget {
			t.Fatalf("read: %s/%s", d.Effect, d.RuleID)
		}
	})
}

func TestMatchersToolsServersAndRanges(t *testing.T) {
	p := mustParse(t, `
version: 1
rules:
  - id: junos-config-only
    match: { servers: [junos-*], tools: [get_junos_config, "*_diff"] }
    effect: allow
  - id: single-target-only
    match: { class: [WRITE_CONFIG] }
    when: { targets_count: { eq: 1 } }
    effect: allow
  - id: two-to-three
    match: { class: [WRITE_CONFIG] }
    when: { targets_count: { gte: 2, lte: 3 } }
    effect: hold
  - id: everything-else
    effect: deny
`)
	tgt := known("a", "x")
	cases := []struct {
		name string
		req  Request
		rule string
	}{
		{"server glob and tool exact", Request{Server: "junos-mcp-server", Tool: "get_junos_config", Class: classify.ReadConfig}, "junos-config-only"},
		{"tool glob", Request{Server: "junos-mcp-server", Tool: "junos_config_diff", Class: classify.ReadConfig}, "junos-config-only"},
		{"prefixed tool", Request{Server: "junos-mcp-server", Tool: "junos-mcp-server.get_junos_config", Class: classify.ReadConfig}, "junos-config-only"},
		{"server mismatch", Request{Server: "eos-mcp", Tool: "get_junos_config", Class: classify.ReadConfig}, "everything-else"},
		{"eq range", Request{Class: classify.WriteConfig, Targets: []Target{tgt}}, "single-target-only"},
		{"gte lte range", Request{Class: classify.WriteConfig, Targets: []Target{tgt, tgt, tgt}}, "two-to-three"},
		{"above range", Request{Class: classify.WriteConfig, Targets: []Target{tgt, tgt, tgt, tgt}}, "everything-else"},
		{"catch-all with empty match", Request{Class: classify.LocalAdmin}, "everything-else"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if d := Evaluate(p, tc.req); d.RuleID != tc.rule {
				t.Fatalf("rule %s, want %s (trace %+v)", d.RuleID, tc.rule, d.Trace)
			}
		})
	}
}

func TestNilPolicyDenies(t *testing.T) {
	if d := Evaluate(nil, Request{Class: classify.ReadOperational}); d.Effect != Deny {
		t.Fatal("nil policy must deny")
	}
}

func TestValidateErrors(t *testing.T) {
	bad := map[string]string{
		"version":            "version: 2\nrules: [{id: a, effect: allow}]",
		"no rules":           "version: 1\nrules: []",
		"dup id":             "version: 1\nrules: [{id: a, effect: allow}, {id: a, effect: deny}]",
		"missing id":         "version: 1\nrules: [{effect: allow}]",
		"reserved id":        "version: 1\nrules: [{id: 'default:x', effect: allow}]",
		"bad effect":         "version: 1\nrules: [{id: a, effect: maybe}]",
		"bad class":          "version: 1\nrules: [{id: a, match: {class: [NOPE]}, effect: allow}]",
		"unknown key":        "version: 1\nrules: [{id: a, effect: allow, matches: {}}]",
		"unknown obligation": "version: 1\nrules: [{id: a, effect: allow, obligations: [dry-run]}]",
		"approval on allow":  "version: 1\nrules: [{id: a, effect: allow, approval: {ttl: 1m}}]",
		"bad ttl":            "version: 1\nrules: [{id: a, effect: hold, approval: {ttl: soon}}]",
		"empty range":        "version: 1\nrules: [{id: a, effect: allow, when: {targets_count: {}}}]",
		"impossible range":   "version: 1\nrules: [{id: a, effect: allow, when: {targets_count: {gt: 3, lt: 2}}}]",
		"unknown hold":       "version: 1\ndefaults: {unknown_target: hold}\nrules: [{id: a, effect: allow}]",
		"negative cap":       "version: 1\ndefaults: {session: {max_devices: -1}}\nrules: [{id: a, effect: allow}]",
		"bad glob":           "version: 1\nrules: [{id: a, match: {tools: ['[']}, effect: allow}]",
	}
	for name, src := range bad {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(src)); err == nil {
				t.Fatalf("expected error for %s", name)
			}
		})
	}
}

func TestRunTestFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte(planPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	testYAML := `
policy: p.yaml
cases:
  - name: core write held
    request:
      class: WRITE_CONFIG
      targets: [{name: core-rtr-01, role: core}]
    expect: {effect: hold, rule: prod-core-needs-approval, obligations: [dry_run, diff, timed_rollback]}
  - name: unknown denied
    request:
      class: READ_OPERATIONAL
      targets: [{name: ghost, known: false}]
    expect: {effect: deny, rule: default:unknown_target}
  - name: deliberately wrong
    request:
      class: EXEC_ARBITRARY
    expect: {effect: allow}
  - name: wrong rule
    request:
      class: READ_CONFIG
    expect: {effect: allow, rule: lab-writes-free}
`
	tp := filepath.Join(dir, "p.test.yaml")
	if err := os.WriteFile(tp, []byte(testYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	results, err := RunTestFile(tp)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 4 {
		t.Fatalf("got %d results", len(results))
	}
	if !results[0].Pass || !results[1].Pass {
		t.Errorf("expected first two cases to pass: %+v %+v", results[0], results[1])
	}
	if results[2].Pass || !strings.Contains(results[2].Message, "effect deny") {
		t.Errorf("case 3 should fail on effect: %+v", results[2])
	}
	if results[3].Pass || !strings.Contains(results[3].Message, "rule reads-anywhere") {
		t.Errorf("case 4 should fail on rule: %+v", results[3])
	}

	if _, err := RunTestFile(filepath.Join(dir, "missing.test.yaml")); err == nil {
		t.Error("missing file should error")
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.test.yaml"), []byte("policy: p.yaml\ncases: [{name: x, request: {class: READ_CONFIG}, expect: {effect: maybe}}]"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := RunTestFile(filepath.Join(dir, "bad.test.yaml")); err == nil {
		t.Error("bad expected effect should error")
	}
}

// TestRepoExamplePolicies runs every shipped *.test.yaml so the examples in
// policies/examples cannot drift from the engine.
func TestRepoExamplePolicies(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "policies", "examples", "*.test.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Skip("no example test files found")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			results, err := RunTestFile(f)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range results {
				if !r.Pass {
					t.Errorf("%s: %s", r.Name, r.Message)
				}
			}
		})
	}
}

func TestExamplePoliciesLoad(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "policies", "examples", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, ".test.yaml") {
			continue
		}
		if _, err := Load(f); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}
