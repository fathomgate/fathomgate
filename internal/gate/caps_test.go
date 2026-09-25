// SPDX-License-Identifier: FSL-1.1-ALv2

package gate

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/fathomgate/fathomgate/internal/gate/gatetest"
	"github.com/fathomgate/fathomgate/internal/gate/seam"
	"github.com/fathomgate/fathomgate/internal/policy"
)

// capMark is in every command and name the cap tests send, so a refusal
// that quoted any of them would show it.
const capMark = "fakecapmark"

func capCommands(n int) []any {
	out := make([]any, n)
	for i := range out {
		out[i] = fmt.Sprintf("show interfaces Ethernet1/%d %s", i+1, capMark)
	}
	return out
}

func manyNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = fmt.Sprintf("%s-%03d", capMark, i)
	}
	return out
}

func anyOf(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

// TestPerCallCaps (M1-39): a call with exactly 64 commands or 256 targets
// is decided as before; one more is default:bad_arguments with fixed text
// that names the cap and no command, name or argument, and parse_error
// too_many_commands or too_many_targets in the log line.
func TestPerCallCaps(t *testing.T) {
	t.Parallel()
	g := newGate(t, examplePolicy(t, "prod-approval"), false)
	tooManyCommands := "fathomgate denied %s: rule default:bad_arguments (class EXEC_ARBITRARY): a call may carry at most 64 commands; split it into smaller calls"
	tooManyTargets := "fathomgate denied %s: rule default:bad_arguments (class %s): a call may name at most 256 targets; split it into smaller calls"
	nested := capCommands(maxCommandsPerCall + 1)
	for _, tc := range []struct {
		name      string
		in        seam.CallInfo
		w         want
		parseCode string // "" when the caps pass
	}{
		{"64 commands", call(eos, "run_commands", map[string]any{"hostname": "lab-sw-01", "commands": capCommands(64)}),
			want{effect: "allow", rule: "reads-anywhere", class: "READ_OPERATIONAL", source: "downgrade", forward: true}, ""},
		{"65 commands", call(eos, "run_commands", map[string]any{"hostname": "lab-sw-01", "commands": capCommands(65)}),
			want{effect: "deny", rule: policy.RuleBadArguments, class: "EXEC_ARBITRARY", text: fmt.Sprintf(tooManyCommands, "eos-mcp.run_commands")}, parseTooManyCommands},
		// Nested arrays are flattened by the classifier, so they count by
		// their strings (and are then refused as malformed).
		{"65 commands in a nested array", call(eos, "run_commands", map[string]any{"hostname": "lab-sw-01", "commands": []any{nested[:1], nested[1:]}}),
			want{effect: "deny", rule: policy.RuleBadArguments, class: "EXEC_ARBITRARY", text: fmt.Sprintf(tooManyCommands, "eos-mcp.run_commands")}, parseTooManyCommands},
		{"64 commands in a nested array", call(eos, "run_commands", map[string]any{"hostname": "lab-sw-01", "commands": []any{nested[:1], nested[1:64]}}),
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL", text: "fathomgate denied eos-mcp.run_commands: rule default:bad_arguments (class READ_OPERATIONAL): " + reasonMalformed}, ""},
		{"64 commands to every known device", call(eos, "run_commands_batch", map[string]any{"hostnames": []any{"lab-sw-01", "lab-spine-01"}, "commands": capCommands(64)}),
			want{effect: "allow", rule: "reads-anywhere", class: "READ_OPERATIONAL", forward: true}, ""},
		{"65 commands to two devices", call(eos, "run_commands_batch", map[string]any{"hostnames": []any{"lab-sw-01", "lab-spine-01"}, "commands": capCommands(65)}),
			want{effect: "deny", rule: policy.RuleBadArguments, class: "EXEC_ARBITRARY", text: fmt.Sprintf(tooManyCommands, "eos-mcp.run_commands_batch")}, parseTooManyCommands},
		// 256 names pass the cap and reach Evaluate, which denies them as
		// unknown; 257 never get there.
		{"256 targets", call(eos, "daily_brief", map[string]any{"hostnames": anyOf(manyNames(256))}),
			want{effect: "deny", rule: policy.RuleUnknownTarget, class: "READ_OPERATIONAL"}, ""},
		{"257 targets", call(eos, "daily_brief", map[string]any{"hostnames": anyOf(manyNames(257))}),
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL", text: fmt.Sprintf(tooManyTargets, "eos-mcp.daily_brief", "READ_OPERATIONAL")}, parseTooManyTargets},
		{"256 targets, one string", call(eos, "daily_brief", map[string]any{"hostnames": strings.Join(manyNames(256), ",")}),
			want{effect: "deny", rule: policy.RuleUnknownTarget, class: "READ_OPERATIONAL"}, ""},
		{"257 targets, one string", call(eos, "daily_brief", map[string]any{"hostnames": strings.Join(manyNames(257), ",")}),
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL", text: fmt.Sprintf(tooManyTargets, "eos-mcp.daily_brief", "READ_OPERATIONAL")}, parseTooManyTargets},
		// Repeats count: the cap is on names as sent.
		{"257 repeats of one name", call(eos, "daily_brief", map[string]any{"hostnames": anyOf(slicesRepeat("lab-sw-01", 257))}),
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL", text: fmt.Sprintf(tooManyTargets, "eos-mcp.daily_brief", "READ_OPERATIONAL")}, parseTooManyTargets},
		// Group selectors count with the names.
		{"256 names and one tag", call(eos, "daily_brief", map[string]any{"hostnames": anyOf(manyNames(256)), "tags": []any{"lab"}}),
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL", text: fmt.Sprintf(tooManyTargets, "eos-mcp.daily_brief", "READ_OPERATIONAL")}, parseTooManyTargets},
		{"255 names and one tag", call(eos, "daily_brief", map[string]any{"hostnames": anyOf(manyNames(255)), "tags": []any{"lab"}}),
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL", text: "fathomgate denied eos-mcp.daily_brief: rule default:bad_arguments (class READ_OPERATIONAL): " + reasonGroup}, ""},
	} {
		v := g.Decide(context.Background(), tc.in)
		check(t, tc.name, v, tc.w)
		line := logLine(v)
		if strings.Contains(v.Error, capMark) || (v.RuleID == policy.RuleBadArguments && strings.Contains(line, capMark)) {
			t.Errorf("%s: a refusal quotes a command or name:\n%s\n%s", tc.name, v.Error, line)
		}
		gotCode := strings.Contains(line, `"parse_error":"`+tc.parseCode+`"`)
		if tc.parseCode != "" && !gotCode || tc.parseCode == "" && strings.Contains(line, `"parse_error":"too_many`) {
			t.Errorf("%s: parse_error, want %q: %s", tc.name, tc.parseCode, line)
		}
	}
}

func slicesRepeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

// TestPerCallCapConstants: the refusal text, the worst-case corpus of the
// overhead tests (M1-23) and the constants say the same numbers.
func TestPerCallCapConstants(t *testing.T) {
	if !strings.Contains(reasonTooManyCommands, " "+strconv.Itoa(maxCommandsPerCall)+" ") ||
		!strings.Contains(reasonTooManyTargets, " "+strconv.Itoa(maxTargetsPerCall)+" ") {
		t.Errorf("the reasons do not name the caps %d and %d", maxCommandsPerCall, maxTargetsPerCall)
	}
	if gatetest.CommandCap != maxCommandsPerCall || gatetest.TargetCap != maxTargetsPerCall {
		t.Errorf("gatetest caps %d and %d, gate caps %d and %d", gatetest.CommandCap, gatetest.TargetCap, maxCommandsPerCall, maxTargetsPerCall)
	}
}

// TestCountedTargets (M1-39): a target the counter key has already counted
// comes off devices_touched, so one Decide counts each device once; the
// count never goes below 0, and nil Counted takes nothing off.
func TestCountedTargets(t *testing.T) {
	t.Parallel()
	g := newGate(t, examplePolicy(t, "prod-approval"), false) // max_devices 5
	counted := func(names ...string) func(string) bool {
		return func(s string) bool {
			for _, n := range names {
				if s == n {
					return true
				}
			}
			return false
		}
	}
	read := func(touched int, c func(string) bool, hosts ...string) seam.CallInfo {
		in := call(eos, "daily_brief", map[string]any{"hostnames": anyOf(hosts)})
		in.DevicesTouched, in.Counted = touched, c
		return in
	}
	allow := want{effect: "allow", rule: "reads-anywhere", class: "READ_OPERATIONAL", forward: true}
	capped := want{effect: "deny", rule: policy.RuleMaxDevices, class: "READ_OPERATIONAL"}
	for _, tc := range []struct {
		name string
		in   seam.CallInfo
		w    want
	}{
		{"five touched, a sixth", read(5, nil, "core-rtr-01"), capped},
		{"five touched, one of them again", read(5, counted("core-rtr-01"), "core-rtr-01"), allow},
		{"four touched, one again and one new", read(4, counted("core-rtr-01"), "core-rtr-01", "lab-sw-01"), allow},
		{"five touched, one again and one new", read(5, counted("core-rtr-01"), "core-rtr-01", "lab-sw-01"), capped},
		{"counted but not in the call", read(5, counted("lab-sw-01"), "core-rtr-01"), capped},
		{"never below zero", read(0, counted("core-rtr-01", "lab-sw-01"), "core-rtr-01", "lab-sw-01"), allow},
	} {
		check(t, tc.name, g.Decide(context.Background(), tc.in), tc.w)
	}
}
