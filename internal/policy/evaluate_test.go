// SPDX-License-Identifier: FSL-1.1-ALv2

package policy

import (
	"path/filepath"
	"slices"
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
	// One allow rule per class, so a request that reaches the rules is
	// allowed by the rule named after its class.
	base := `
version: 1
rules:
  - id: read-op
    match: { class: [READ_OPERATIONAL] }
    effect: allow
  - id: read-config
    match: { class: [READ_CONFIG] }
    effect: allow
  - id: write-config
    match: { class: [WRITE_CONFIG] }
    effect: allow
  - id: exec
    match: { class: [EXEC_ARBITRARY] }
    effect: allow
  - id: inventory
    match: { class: [INVENTORY_READ] }
    effect: allow
  - id: lab
    match: { class: [LAB_LIFECYCLE] }
    effect: allow
  - id: local
    match: { class: [LOCAL_ADMIN] }
    effect: allow
`
	ruleFor := map[classify.Class]string{
		classify.ReadOperational: "read-op",
		classify.ReadConfig:      "read-config",
		classify.WriteConfig:     "write-config",
		classify.ExecArbitrary:   "exec",
		classify.InventoryRead:   "inventory",
		classify.LabLifecycle:    "lab",
		classify.LocalAdmin:      "local",
	}
	withDefault := func(v string) string {
		return strings.Replace(base, "rules:", "defaults: { unknown_target: "+v+" }\nrules:", 1)
	}
	ghost := Target{Name: "core-x.attacker.example"}
	mixed := []Target{known("core-rtr-01", "core"), ghost}

	// ADR 0032: an unset unknown_target denies every class, exactly as an
	// explicit deny does; only an explicit allow lets the rules decide.
	for _, tc := range []struct {
		name  string
		src   string
		allow bool
	}{
		{"unset", base, false},
		{"deny", withDefault("deny"), false},
		{"allow", withDefault("allow"), true},
	} {
		p := mustParse(t, tc.src)
		for _, c := range classify.All() {
			for _, targets := range [][]Target{{ghost}, mixed} {
				d := Evaluate(p, Request{Class: c, Targets: targets})
				if tc.allow {
					if d.Effect != Allow || d.RuleID != ruleFor[c] {
						t.Errorf("%s %s %d targets: got %s/%s, want allow/%s", tc.name, c, len(targets), d.Effect, d.RuleID, ruleFor[c])
					}
					if d.Trace[0].RuleID != RuleUnknownTarget || d.Trace[0].Matched {
						t.Errorf("%s %s: trace should note the unknown target, unmatched: %+v", tc.name, c, d.Trace[0])
					}
					continue
				}
				if d.Effect != Deny || d.RuleID != RuleUnknownTarget {
					t.Errorf("%s %s %d targets: got %s/%s, want deny/%s", tc.name, c, len(targets), d.Effect, d.RuleID, RuleUnknownTarget)
				}
				if len(d.Trace) != 1 || !d.Trace[0].Matched {
					t.Errorf("%s %s: rules must not run after the unknown-target deny: %+v", tc.name, c, d.Trace)
				}
			}
		}
	}

	t.Run("unset is filled in as deny at load", func(t *testing.T) {
		if got := mustParse(t, base).Defaults.UnknownTarget; got != Deny {
			t.Fatalf("Parse left unknown_target %q, want deny", got)
		}
		if got := mustParse(t, withDefault("allow")).Defaults.UnknownTarget; got != Allow {
			t.Fatalf("Parse changed an explicit allow to %q", got)
		}
	})

	// Every YAML spelling of "no value" is unset, and unset is deny.
	t.Run("YAML null forms load as deny", func(t *testing.T) {
		for name, defaults := range map[string]string{
			"empty value":   "defaults:\n  unknown_target:\n",
			"null":          "defaults:\n  unknown_target: null\n",
			"tilde":         "defaults:\n  unknown_target: ~\n",
			"defaults null": "defaults: null\n",
			"defaults {}":   "defaults: {}\n",
			"session only":  "defaults:\n  session: { max_devices: 5 }\n",
		} {
			p := mustParse(t, strings.Replace(base, "rules:", defaults+"rules:", 1))
			if p.Defaults.UnknownTarget != Deny {
				t.Errorf("%s: loaded unknown_target %q, want deny", name, p.Defaults.UnknownTarget)
			}
			if d := Evaluate(p, Request{Class: classify.ReadOperational, Targets: []Target{ghost}}); d.Effect != Deny || d.RuleID != RuleUnknownTarget {
				t.Errorf("%s: got %s/%s, want deny/%s", name, d.Effect, d.RuleID, RuleUnknownTarget)
			}
		}
	})

	// Values that are not allow or deny are load errors, never a silent
	// default in either direction.
	t.Run("loader refuses other values", func(t *testing.T) {
		for name, defaults := range map[string]string{
			"yes":           "defaults:\n  unknown_target: yes\n",
			"true":          "defaults:\n  unknown_target: true\n",
			"false":         "defaults:\n  unknown_target: false\n",
			"empty string":  "defaults:\n  unknown_target: \"\"\n",
			"hold":          "defaults:\n  unknown_target: hold\n",
			"list":          "defaults:\n  unknown_target: [allow]\n",
			"duplicate key": "defaults:\n  unknown_target: deny\n  unknown_target: allow\n",
		} {
			if _, err := Parse([]byte(strings.Replace(base, "rules:", defaults+"rules:", 1))); err == nil {
				t.Errorf("%s: Parse accepted it", name)
			}
		}
		// Effects are case-insensitive everywhere (ParseEffect), so ALLOW
		// is the explicit allow, not an unrecognised value.
		p := mustParse(t, strings.Replace(base, "rules:", "defaults:\n  unknown_target: ALLOW\nrules:", 1))
		if p.Defaults.UnknownTarget != Allow {
			t.Errorf("ALLOW loaded as %q, want allow", p.Defaults.UnknownTarget)
		}
	})

	t.Run("a policy built without Parse fails closed", func(t *testing.T) {
		p := mustParse(t, base)
		for _, v := range []Effect{"", Hold, "bogus"} {
			p.Defaults.UnknownTarget = v
			if d := Evaluate(p, Request{Class: classify.ReadOperational, Targets: []Target{ghost}}); d.Effect != Deny || d.RuleID != RuleUnknownTarget {
				t.Errorf("unknown_target %q: got %s/%s, want deny", v, d.Effect, d.RuleID)
			}
		}
	})

	// unknown_target applies only to named targets. A request with no
	// targets (INVENTORY_READ listing the upstream's devices, LOCAL_ADMIN)
	// has nothing unknown, so the rules decide and the trace has no
	// default:unknown_target entry. A zero-target call to a tool that
	// takes a target is refused before Evaluate by the normaliser (M1-18).
	t.Run("targetless requests go to the rules", func(t *testing.T) {
		p := mustParse(t, base)
		for _, c := range classify.All() {
			d := Evaluate(p, Request{Class: c})
			if d.Effect != Allow || d.RuleID != ruleFor[c] {
				t.Errorf("%s with no targets: got %s/%s, want allow/%s", c, d.Effect, d.RuleID, ruleFor[c])
			}
			for _, e := range d.Trace {
				if e.RuleID == RuleUnknownTarget {
					t.Errorf("%s with no targets: unexpected trace entry %+v", c, e)
				}
			}
		}
	})

	t.Run("known targets are unaffected", func(t *testing.T) {
		d := Evaluate(mustParse(t, base), Request{Class: classify.ReadConfig, Targets: []Target{known("core-rtr-01", "core")}})
		if d.Effect != Allow || d.RuleID != "read-config" {
			t.Fatalf("got %s/%s", d.Effect, d.RuleID)
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

// sameSet reports whether a and b hold the same strings, in any order.
func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// The *.test.yaml runner and TestRepoExamplePolicies live in
// internal/policytest (ADR 0035), which can call internal/gate.

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
