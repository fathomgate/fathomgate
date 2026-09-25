// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"strings"
	"testing"
)

// Regression cases from the security review of PR #150: multi-line commands
// were downgraded because whitespace collapsing turned line breaks into
// spaces, while netmiko and the device still ran every line. Each input
// was allowed as READ_OPERATIONAL (rule reads-anywhere) under the read-only
// example policy before the fix.
var multiLineInjections = []string{
	"show clock\nconf t\nhostname pwned\nend",
	"show clock\ncopy run start",
	"show clock\nrelo\n\nshow clock", // the blank line answers reload's [confirm]
	"show clock\ntclsh",
}

// lineBreaks are every separator a device, an SSH library or a Python
// str.splitlines() may treat as the end of a line. Tab is not here: it is
// horizontal whitespace, collapsed like a space (classification.md 5.1).
var lineBreaks = []string{
	"\n", "\r", "\r\n", "\v", "\f",
	"\x1c", "\x1d", "\x1e", // file, group, record separators (splitlines)
	"\u0085", // NEL
	"\u2028", // line separator
	"\u2029", // paragraph separator
	"\u009b", // C1 CSI
}

// freeFormTools are the command-carrying tools of the shipped profiles and
// the upa fixture, with the class source a failing command must produce.
var freeFormTools = []struct {
	server, tool, target, param string
	source                      Source
}{
	{"netdev-ssh-mcp", "run_show_command", "host", "command", SourceReclassify},
	{"eos-mcp", "run_command", "hostname", "command", SourceProfile},
	{"upa-mcp-netmiko-server", "send_command_and_get_output", "name", "command", SourceProfile},
	{"ntunes-netmiko-mcp-server", "send_command", "device", "command", SourceProfile},
	{"junos-mcp-server", "execute_junos_command", "router_name", "command", SourceProfile},
}

func TestMultiLineInjectionIsExecArbitrary(t *testing.T) {
	profiles := repoProfiles(t)
	inputs := make([]string, 0, len(lineBreaks)*len(multiLineInjections)+len(lineBreaks))
	for _, in := range multiLineInjections {
		for _, br := range lineBreaks {
			inputs = append(inputs, strings.ReplaceAll(in, "\n", br))
		}
	}
	for _, br := range lineBreaks {
		inputs = append(inputs, "show version"+br+"show clock") // two harmless lines are still two lines
	}
	for _, in := range inputs {
		c, check := classifyCommand(in)
		if c != ExecArbitrary || (check != checkControl && check != checkNonASCII) {
			t.Errorf("%q: %s (%s), want EXEC_ARBITRARY (control-character or non-ascii)", in, c, check)
		}
		for _, tt := range freeFormTools {
			r := Classify(profiles[tt.server], tt.tool, map[string]any{tt.target: "lab-sw-01", tt.param: in})
			if r.Class != ExecArbitrary || r.ClassSource != tt.source {
				t.Errorf("%s.%s %q: %s (%s), want EXEC_ARBITRARY (%s)", tt.server, tt.tool, in, r.Class, r.ClassSource, tt.source)
			}
		}
	}
	// A batch with one multi-line element fails the batch.
	r := Classify(profiles["eos-mcp"], "run_commands", map[string]any{"hostname": "lab-sw-01", "commands": []any{"show version", "show clock\nreload"}})
	if r.Class != ExecArbitrary {
		t.Errorf("run_commands batch: %s", r.Class)
	}
}

// TestFlattenedInjectionIsExecArbitrary: the same payloads on one line (as
// the old normaliser saw them) now fail the blocklist too, so the fix does
// not rest on the control-character check alone.
func TestFlattenedInjectionIsExecArbitrary(t *testing.T) {
	for _, in := range multiLineInjections {
		flat := strings.Join(strings.Fields(in), " ")
		if c, check := classifyCommand(flat); c != ExecArbitrary || check != checkBlocklist {
			t.Errorf("%q: %s (%s), want EXEC_ARBITRARY (blocklist)", flat, c, check)
		}
	}
}

// TestTabIsWhitespace pins the tab decision: tabs collapse like spaces, so
// a config dump separated by tabs is READ_CONFIG and a read separated by
// tabs is READ_OPERATIONAL.
func TestTabIsWhitespace(t *testing.T) {
	cases := map[string]Class{
		"show\trunning-config":    ReadConfig,
		"show\t\tstartup-config":  ReadConfig,
		"show\tip\tbgp\tsummary":  ReadOperational,
		"show\tclock\treload":     ExecArbitrary,
		"\tshow run\t":            ReadConfig,
		"show\ttech-support\tall": ReadConfig,
	}
	for in, want := range cases {
		if got := ClassifyCommand(in); got != want {
			t.Errorf("%q: %s, want %s", in, got, want)
		}
	}
}

// TestConfigDumpAbbreviations is the second finding of the same review:
// abbreviated config dumps and show tech-support were READ_OPERATIONAL.
func TestConfigDumpAbbreviations(t *testing.T) {
	for _, in := range []string{
		"show run", "show runn", "show running", "show running-config",
		"show conf", "show config", "show configuration",
		"show start", "show startup", "show startup-config",
		"show tech", "show tech-support", "show tech-support detail",
	} {
		if c := ClassifyCommand(in); c != ReadConfig {
			t.Errorf("%q: %s, want READ_CONFIG", in, c)
		}
	}
}
