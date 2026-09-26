// SPDX-License-Identifier: FSL-1.1-ALv2

package gate

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/fathomgate/fathomgate/internal/gate/seam"
)

// sameVerdict reports how Explain's verdict differs from Decide's for c, or
// "" when they are the same: every field, the trace compared as a handler
// would log it, and Explain's decision agreeing with the verdict.
func sameVerdict(g *Gate, c seam.CallInfo) string {
	ex := g.Explain(context.Background(), c)
	v := g.Decide(context.Background(), c)
	// Trace is a LogValuer over the decision's trace; compare what a
	// handler would log.
	if !reflect.DeepEqual(ex.Verdict.Trace.Value.Resolve().Any(), v.Trace.Value.Resolve().Any()) {
		return "traces differ"
	}
	ex.Verdict.Trace = v.Trace
	switch {
	case !reflect.DeepEqual(ex.Verdict, v):
		return "Explain's verdict differs from Decide's"
	case string(ex.Decision.Effect) != v.Effect:
		return "Explain's decision effect " + string(ex.Decision.Effect) + ", verdict " + v.Effect
	case ex.Decision.RuleID != v.RuleID:
		return "Explain's decision rule " + ex.Decision.RuleID + ", verdict " + v.RuleID
	case len(ex.Targets) != len(v.Targets):
		return "Explain resolved a different number of targets"
	}
	return ""
}

// TestExplainMatchesDecide: Explain's Verdict is exactly Decide's for the
// same call, through every kind of outcome, so fathomgate policy test and
// policy eval (which call Explain) cannot disagree with serve (which calls
// Decide) (ADR 0035; one of the two guards the maintainer accepted the
// Explain export with). Each call is checked to reach the outcome it is
// named for, so no row is vacuous.
func TestExplainMatchesDecide(t *testing.T) {
	g := newGate(t, examplePolicy(t, "prod-approval"), true)
	raw := func(s string) seam.CallInfo {
		c := call(eos, "get_version", nil)
		c.Arguments = json.RawMessage(s)
		return c
	}
	with := func(c seam.CallInfo, f func(*seam.CallInfo)) seam.CallInfo {
		f(&c)
		return c
	}
	commands := make([]any, 65)
	for i := range commands {
		commands[i] = "show version"
	}
	hold := call("junos-mcp-server", "load_and_commit_config", map[string]any{"router_name": "core-rtr-01", "config_text": "set system host-name x"})
	read := call(eos, "get_version", map[string]any{"hostname": "core-rtr-01"})
	cases := []struct {
		name, rule, parseError string
		c                      seam.CallInfo
	}{
		{"allow", "reads-anywhere", "", call(netdev, "run_show_command", map[string]any{"host": "core-rtr-01", "command": "show version"})},
		{"downgrade", "reads-anywhere", "", call(upa, "send_command_and_get_output", map[string]any{"name": "lab-leaf-01", "command": "show ip bgp summary"})},
		{"deny exec", "no-exec", "", call(eos, "run_command", map[string]any{"hostname": "core-rtr-01", "command": "reload"})},
		{"hold", "prod-core-needs-approval", "", hold},
		{"cannot run", "lab-writes-free", "", call(eos, "push_config", map[string]any{"hostname": "lab-leaf-01", "config_lines": []any{"hostname x"}})},
		{"unknown", "default:unknown_target", "", call(eos, "get_version", map[string]any{"hostname": "core-x.attacker.example"})},
		{"unnamed", "default:bad_arguments", "", call(eos, "get_version", map[string]any{"hostname": "core-rtr-01", "config_path": "/etc/passwd"})},
		{"malformed", "default:bad_arguments", "", call(eos, "get_version", map[string]any{"hostname": 7})},
		{"bad target", "default:bad_arguments", "", call(eos, "get_version", map[string]any{"hostname": "lab-x@core-rtr-01"})},
		{"duplicate key", "default:bad_arguments", "duplicate_key", raw(`{"hostname": "core-rtr-01", "hostname": "x"}`)},
		{"not an object", "default:bad_arguments", "not_object", raw(`[1]`)},
		{"unlisted tool", "default:bad_arguments", "", call(eos, "no_such_tool", map[string]any{"hostname": "core-rtr-01"})},
		{"annotation raise", "no-exec", "", with(read, func(c *seam.CallInfo) { f := false; c.ReadOnlyHint = &f })},
		{"too many commands", "default:bad_arguments", "too_many_commands", call(eos, "run_commands", map[string]any{"hostname": "core-rtr-01", "commands": commands})},
		{"too many targets", "default:bad_arguments", "too_many_targets", call(eos, "get_device_facts_batch", map[string]any{"hostnames": strings.Repeat("core-rtr-01,", 256) + "core-rtr-01"})},
		{"group selector", "default:bad_arguments", "", call(eos, "daily_brief", map[string]any{"tags": []any{"lab"}})},
		{"zero targets", "default:bad_arguments", "", call(eos, "daily_brief", map[string]any{})},
		{"session device cap", "default:session.max_devices", "", with(read, func(c *seam.CallInfo) { c.DevicesTouched = 5 })},
		{"pending holds", "default:session.max_pending", "", with(hold, func(c *seam.CallInfo) { c.PendingHolds = 2 })},
		{"counted target", "reads-anywhere", "", with(read, func(c *seam.CallInfo) {
			c.DevicesTouched = 5
			c.Counted = func(name string) bool { return name == "core-rtr-01" }
		})},
	}
	for _, tc := range cases {
		if msg := sameVerdict(g, tc.c); msg != "" {
			t.Errorf("%s: %s", tc.name, msg)
		}
		ex := g.Explain(context.Background(), tc.c)
		if ex.Verdict.RuleID != tc.rule {
			t.Errorf("%s: rule %s, want %s (the row does not reach its outcome)", tc.name, ex.Verdict.RuleID, tc.rule)
		}
		if ex.ParseError != tc.parseError {
			t.Errorf("%s: parse error %q, want %q", tc.name, ex.ParseError, tc.parseError)
		}
	}

	ex := g.Explain(context.Background(), call(eos, "get_version", map[string]any{"hostname": "core-rtr-01", "config_path": "/etc/passwd"}))
	if !reflect.DeepEqual(ex.Unnamed, []string{"config_path"}) || ex.ParseError != "" {
		t.Errorf("unnamed: %+v", ex)
	}
	ex = g.Explain(context.Background(), cases[1].c)
	if ex.ProfileClass != "EXEC_ARBITRARY" || ex.ClassNote == "" || !ex.Targets[0].Known {
		t.Errorf("downgrade: %+v", ex)
	}
}

// FuzzExplainMatchesDecide: for any argument bytes sent to any of a spread
// of tools (a command tool, a downgrade tool, a batch tool, a config push, a
// Junos load), Explain's verdict is Decide's.
func FuzzExplainMatchesDecide(f *testing.F) {
	for _, seed := range []string{
		`{"host": "core-rtr-01", "command": "show version"}`,
		`{"name": "lab-leaf-01", "command": "show clock\nreload"}`,
		`{"hostnames": "core-rtr-01,lab-leaf-01"}`,
		`{"hostname": "lab-leaf-01", "config_lines": ["end", "reload now"]}`,
		`{"router_name": "core-rtr-01", "config_text": "set system host-name x"}`,
		`{"hostname": "core-rtr-01", "hostname": "x"}`,
		`[1]`, ``, `null`, `{"tags": ["lab"]}`, "\xff",
	} {
		for tool := range uint8(5) {
			f.Add(tool, []byte(seed), uint8(0))
		}
	}
	tools := []struct{ server, tool string }{
		{netdev, "run_show_command"},
		{upa, "send_command_and_get_output"},
		{eos, "get_device_facts_batch"},
		{eos, "push_config"},
		{"junos-mcp-server", "load_and_commit_config"},
	}
	g := newGate(f, examplePolicy(f, "prod-approval"), true)
	f.Fuzz(func(t *testing.T, tool uint8, args []byte, touched uint8) {
		pick := tools[int(tool)%len(tools)]
		c := call(pick.server, pick.tool, nil)
		c.Arguments = json.RawMessage(args)
		c.DevicesTouched = int(touched % 8)
		if msg := sameVerdict(g, c); msg != "" {
			t.Fatalf("%s.%s %q: %s", pick.server, pick.tool, args, msg)
		}
	})
}
