// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"strings"
	"testing"
)

// TestEvalCapabilityTable: policy eval --profile decides a meta-tool call
// through the gate from its capability table (M1-17, test-matrix row 18), in
// the order decision, class, target, rule, and shows the gate's
// default:bad_arguments for the refused parameters argument and for a
// capability id that is not one string.
func TestEvalCapabilityTable(t *testing.T) {
	base := []string{"policy", "eval", "--policy", repoPath("policies", "examples", "read-only.yaml"),
		"--profile", configCopy(t, repoPath("profiles", "cisco-meraki-mcp-official.yaml")), "--tool", "execute_api"}
	for _, tc := range []struct {
		args      []string
		code      int
		decision  string
		class     string
		rule      string
		classNote string
	}{
		{[]string{"--arg", "capability_id=getOrganizations"}, exitOK, "allow", "INVENTORY_READ", "reads-anywhere", "capability listed in capability table dashboard"},
		{[]string{"--arg", "capability_id=getNetworkWirelessSsids"}, exitOK, "allow", "READ_CONFIG", "reads-anywhere", "capability listed in capability table dashboard"},
		{[]string{"--arg", "capability_id=rebootDevice"}, exitFail, "deny", "EXEC_ARBITRARY", "no-exec", "capability not in capability table dashboard"},
		{[]string{"--arg", "capability_id=GetOrganizations"}, exitFail, "deny", "EXEC_ARBITRARY", "no-exec", "capability not in capability table dashboard"},
		{[]string{"--arguments-json", "{}"}, exitFail, "deny", "EXEC_ARBITRARY", "no-exec", "no capability id"},
		{[]string{"--arg", "capability_id=getOrganizationDevices", "--arg", "parameters=organizationId"}, exitFail, "deny", "INVENTORY_READ", "default:bad_arguments", ""},
		{[]string{"--arg", "capability_id=getOrganizations,getOrganizations"}, exitFail, "deny", "EXEC_ARBITRARY", "default:bad_arguments", "capability id is not a string"},
	} {
		out, code := captureStdout(t, func() int { return run(append(append([]string{}, base...), tc.args...)) })
		if code != tc.code {
			t.Errorf("%q: exit %d, want %d\n%s", tc.args, code, tc.code, out)
		}
		lines := strings.Split(out, "\n")
		if len(lines) < 4 || lines[0] != "decision:       "+tc.decision ||
			!strings.HasPrefix(lines[1], "class:          "+tc.class) ||
			!strings.Contains(lines[1], tc.classNote) ||
			lines[2] != "targets:        (none)" || lines[3] != "rule:           "+tc.rule {
			t.Errorf("%q:\n%s", tc.args, out)
		}
		if !strings.Contains(out, "class_source:   capability_table") {
			t.Errorf("%q: no class_source line:\n%s", tc.args, out)
		}
	}
}
