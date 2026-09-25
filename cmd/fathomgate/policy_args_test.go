// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"strings"
	"testing"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/policy"
)

// TestArgumentDecision: policy eval shows the gate's deny for arguments the
// profile does not name (ADR 0033), with a fixed reason that quotes no
// argument name, and the names only in the operator's trace.
func TestArgumentDecision(t *testing.T) {
	if d := argumentDecision(classify.Result{}); d != nil {
		t.Fatalf("clean arguments: %+v", d)
	}
	d := argumentDecision(classify.Result{UnnamedArgs: []string{"config_path"}})
	if d == nil || d.Effect != policy.Deny || d.RuleID != "default:bad_arguments" {
		t.Fatalf("unnamed: %+v", d)
	}
	if strings.Contains(d.Reason, "config_path") {
		t.Errorf("reason quotes the argument: %q", d.Reason)
	}
	if len(d.Trace) != 1 || !d.Trace[0].Matched || !strings.Contains(d.Trace[0].Note, `"config_path"`) {
		t.Errorf("trace: %+v", d.Trace)
	}
	d = argumentDecision(classify.Result{MalformedArgs: []string{"hostname"}})
	if d == nil || !strings.Contains(d.Reason, "does not parse as JSON") {
		t.Fatalf("malformed: %+v", d)
	}
}

// TestEvalCapabilityTable: policy eval --profile classifies a meta-tool call
// from its capability table (M1-17, test-matrix row 18), in the order
// decision, class, target, rule, reason, and shows the gate's
// default:bad_arguments for the refused parameters argument and for a
// capability id that is not one string.
func TestEvalCapabilityTable(t *testing.T) {
	base := []string{"policy", "eval", "--policy", "../../policies/examples/read-only.yaml",
		"--profile", "../../profiles/cisco-meraki-mcp-official.yaml", "--tool", "execute_api"}
	for _, tc := range []struct {
		args       []string
		code       int
		decision   string
		class      string
		rule       string
		classNotes string
	}{
		{[]string{"--arg", "capability_id=getOrganizations"}, exitOK, "allow", "INVENTORY_READ", "reads-anywhere", "capability listed in capability table dashboard"},
		{[]string{"--arg", "capability_id=getNetworkWirelessSsids"}, exitOK, "allow", "READ_CONFIG", "reads-anywhere", "capability listed in capability table dashboard"},
		{[]string{"--arg", "capability_id=rebootDevice"}, exitFail, "deny", "EXEC_ARBITRARY", "no-exec", "capability not in capability table dashboard"},
		{[]string{"--arg", "capability_id=GetOrganizations"}, exitFail, "deny", "EXEC_ARBITRARY", "no-exec", "capability not in capability table dashboard"},
		{[]string{}, exitFail, "deny", "EXEC_ARBITRARY", "no-exec", "no capability id"},
		{[]string{"--arg", "capability_id=getOrganizationDevices", "--arg", "parameters=organizationId"}, exitFail, "deny", "INVENTORY_READ", "default:bad_arguments", ""},
		{[]string{"--arg", "capability_id=getOrganizations,getOrganizations"}, exitFail, "deny", "EXEC_ARBITRARY", "default:bad_arguments", "capability id is not a string"},
	} {
		out, code := captureStdout(t, func() int { return run(append(append([]string{}, base...), tc.args...)) })
		if code != tc.code {
			t.Errorf("%q: exit %d, want %d\n%s", tc.args, code, tc.code, out)
		}
		lines := strings.Split(out, "\n")
		if len(lines) < 4 || lines[0] != "decision:    "+tc.decision ||
			!strings.HasPrefix(lines[1], "class:       "+tc.class+" (profile EXEC_ARBITRARY; ") ||
			!strings.Contains(lines[1], tc.classNotes) ||
			lines[2] != "targets:     (none)" || lines[3] != "rule:        "+tc.rule {
			t.Errorf("%q:\n%s", tc.args, out)
		}
	}
}
