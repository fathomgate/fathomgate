// SPDX-License-Identifier: FSL-1.1-ALv2

package gate

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/fathomgate/fathomgate/internal/gate/seam"
	"github.com/fathomgate/fathomgate/internal/policy"
)

// TestExplainMatchesDecide: Explain's Verdict is exactly Decide's for the
// same call, through every kind of outcome, so fathomgate policy test and
// policy eval (which call Explain) cannot disagree with serve (which calls
// Decide) (ADR 0035). The detail it adds agrees with the verdict.
func TestExplainMatchesDecide(t *testing.T) {
	g := newGate(t, examplePolicy(t, "prod-approval"), true)
	raw := func(s string) seam.CallInfo {
		c := call(eos, "get_version", nil)
		c.Arguments = json.RawMessage(s)
		return c
	}
	calls := map[string]seam.CallInfo{
		"allow":         call(netdev, "run_show_command", map[string]any{"host": "core-rtr-01", "command": "show version"}),
		"downgrade":     call(upa, "send_command_and_get_output", map[string]any{"name": "lab-leaf-01", "command": "show ip bgp summary"}),
		"deny exec":     call(eos, "run_command", map[string]any{"hostname": "core-rtr-01", "command": "reload"}),
		"hold":          call("junos-mcp-server", "load_and_commit_config", map[string]any{"router_name": "core-rtr-01", "config_text": "set system host-name x"}),
		"cannot run":    call(eos, "push_config", map[string]any{"hostname": "lab-leaf-01", "config_lines": []any{"hostname x"}}),
		"unknown":       call(eos, "get_version", map[string]any{"hostname": "core-x.attacker.example"}),
		"unnamed":       call(eos, "get_version", map[string]any{"hostname": "core-rtr-01", "config_path": "/etc/passwd"}),
		"malformed":     call(eos, "get_version", map[string]any{"hostname": 7}),
		"bad target":    call(eos, "get_version", map[string]any{"hostname": "lab-x@core-rtr-01"}),
		"duplicate key": raw(`{"hostname": "core-rtr-01", "hostname": "x"}`),
		"not an object": raw(`[1]`),
		"unlisted tool": call(eos, "no_such_tool", map[string]any{"hostname": "core-rtr-01"}),
		"annotation raise": func() seam.CallInfo {
			c := call(eos, "get_version", map[string]any{"hostname": "core-rtr-01"})
			f := false
			c.ReadOnlyHint = &f
			return c
		}(),
	}
	for name, c := range calls {
		ex := g.Explain(context.Background(), c)
		v := g.Decide(context.Background(), c)
		// Trace is a LogValuer over the decision's trace; compare what a
		// handler would log.
		if !reflect.DeepEqual(ex.Verdict.Trace.Value.Resolve().Any(), v.Trace.Value.Resolve().Any()) {
			t.Errorf("%s: traces differ", name)
		}
		ex.Verdict.Trace = v.Trace
		if !reflect.DeepEqual(ex.Verdict, v) {
			t.Errorf("%s: Explain verdict %+v, Decide %+v", name, ex.Verdict, v)
		}
		if string(ex.Decision.Effect) != v.Effect && v.Effect != string(policy.Deny) {
			t.Errorf("%s: decision %s, verdict %s", name, ex.Decision.Effect, v.Effect)
		}
		if ex.Decision.RuleID != v.RuleID {
			t.Errorf("%s: decision rule %s, verdict %s", name, ex.Decision.RuleID, v.RuleID)
		}
		if len(ex.Targets) != len(v.Targets) {
			t.Errorf("%s: %d resolved targets, verdict %d", name, len(ex.Targets), len(v.Targets))
		}
	}
	ex := g.Explain(context.Background(), calls["unnamed"])
	if !reflect.DeepEqual(ex.Unnamed, []string{"config_path"}) || ex.ParseError != "" {
		t.Errorf("unnamed: %+v", ex)
	}
	ex = g.Explain(context.Background(), calls["duplicate key"])
	if ex.ParseError != "duplicate_key" {
		t.Errorf("duplicate key: parse error %q", ex.ParseError)
	}
	ex = g.Explain(context.Background(), calls["downgrade"])
	if ex.ProfileClass != "EXEC_ARBITRARY" || ex.ClassNote == "" || !ex.Targets[0].Known {
		t.Errorf("downgrade: %+v", ex)
	}
}
