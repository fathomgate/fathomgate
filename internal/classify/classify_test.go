// SPDX-License-Identifier: Apache-2.0

package classify

import (
	"path/filepath"
	"strings"
	"testing"
)

// Tier 1 cases for docs/specs/classification.md sections 5, 6, 8 and 9 and
// test-matrix rows 3 and 5. Where the code is stricter than the spec's
// vendor-specific design, the case pins the code and says so; the spec
// records the same difference.

// fixtureProfiles are servers from docs/research/02-network-mcp-servers.md
// that have no shipped profile yet. They model only the tool the worked
// example needs and are not a substitute for profiles/<server>.yaml.
const (
	upaFixture = `
server: upa-mcp-netmiko-server
tools:
  send_command_and_get_output:
    class: EXEC_ARBITRARY
    args: []
    target_params: [name]
    command_params: [command]
`
	mcfortigateFixture = `
server: mcfortigate
tools:
  search_config:
    class: READ_CONFIG
    args: []
    target_params: [target]
`
	clabFixture = `
server: clab-mcp-server
tools:
  destroyLab:
    class: LAB_LIFECYCLE
    args: []
`
)

func repoProfiles(t *testing.T) map[string]*Profile {
	t.Helper()
	profiles, err := LoadProfileDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	for _, src := range []string{upaFixture, mcfortigateFixture, clabFixture} {
		p, err := ParseProfile([]byte(src))
		if err != nil {
			t.Fatal(err)
		}
		profiles[p.Server] = p
	}
	return profiles
}

// TestWorkedExamples runs every row of classification.md section 9 that
// this package can express. The two Meraki execute_api rows need capability
// tables (M1-17) and are not here.
func TestWorkedExamples(t *testing.T) {
	profiles := repoProfiles(t)
	cases := []struct {
		name   string
		server string
		tool   string
		args   map[string]any
		want   Class
		source Source
	}{
		{"netdev run_show_command show ip bgp summary", "netdev-ssh-mcp", "run_show_command",
			map[string]any{"host": "lab-sw-01", "command": "show ip bgp summary"}, ReadOperational, SourceProfile},
		{"netdev run_show_command show running-config", "netdev-ssh-mcp", "run_show_command",
			map[string]any{"host": "lab-sw-01", "command": "show running-config"}, ReadConfig, SourceReclassify},
		{"upa send_command_and_get_output reload", "upa-mcp-netmiko-server", "send_command_and_get_output",
			map[string]any{"name": "lab-rtr-01", "command": "reload"}, ExecArbitrary, SourceProfile},
		{"upa send_command_and_get_output show ip route", "upa-mcp-netmiko-server", "send_command_and_get_output",
			map[string]any{"name": "lab-rtr-01", "command": "show ip route"}, ReadOperational, SourceDowngrade},
		{"eos run_command configure", "eos-mcp", "run_command",
			map[string]any{"hostname": "lab-leaf-01", "command": "configure"}, ExecArbitrary, SourceProfile},
		// Spec: READ_OPERATIONAL through an allowed filter pipe. Code: every
		// pipe fails (section 5.4), so the call stays EXEC_ARBITRARY.
		{"eos run_command show version | json", "eos-mcp", "run_command",
			map[string]any{"hostname": "lab-leaf-01", "command": "show version | json"}, ExecArbitrary, SourceProfile},
		{"eos run_commands show version then reload now", "eos-mcp", "run_commands",
			map[string]any{"hostname": "lab-leaf-01", "commands": []any{"show version", "reload now"}}, ExecArbitrary, SourceProfile},
		// Spec: READ_CONFIG. Code: the pipe fails first.
		{"ntunes send_command show running-config | section bgp", "ntunes-netmiko-mcp-server", "send_command",
			map[string]any{"device": "acc-sw-01", "command": "show running-config | section bgp"}, ExecArbitrary, SourceProfile},
		{"ntunes send_command redirect to bootflash", "ntunes-netmiko-mcp-server", "send_command",
			map[string]any{"device": "acc-sw-01", "command": "show version > bootflash:v.txt"}, ExecArbitrary, SourceProfile},
		// Spec: READ_OPERATIONAL. Code: the pipe fails.
		{"junos execute_junos_command show bgp summary | no-more", "junos-mcp-server", "execute_junos_command",
			map[string]any{"router_name": "core-rtr-01", "command": "show bgp summary | no-more"}, ExecArbitrary, SourceProfile},
		// Spec: READ_CONFIG. Code: the pipe fails.
		{"junos execute_junos_command show configuration | display set", "junos-mcp-server", "execute_junos_command",
			map[string]any{"router_name": "core-rtr-01", "command": "show configuration | display set"}, ExecArbitrary, SourceProfile},
		{"junos execute_junos_command request system reboot", "junos-mcp-server", "execute_junos_command",
			map[string]any{"router_name": "core-rtr-01", "command": "request system reboot"}, ExecArbitrary, SourceProfile},
		{"junos execute_junos_pfe_command never downgraded", "junos-mcp-server", "execute_junos_pfe_command",
			map[string]any{"router_name": "core-rtr-01", "command": "show jnh 0 exceptions"}, ExecArbitrary, SourceProfile},
		// EXEC_ARBITRARY since M1-35: the upstream renders the agent's
		// Jinja2 unsandboxed whatever apply_config says (PR #161 H2), so
		// the M3 dry-run reclassification must not apply to this tool.
		{"junos render_and_apply_j2_template apply_config false", "junos-mcp-server", "render_and_apply_j2_template",
			map[string]any{"router_name": "core-rtr-01", "template_content": "x", "apply_config": false}, ExecArbitrary, SourceProfile},
		{"junos load_and_commit_config", "junos-mcp-server", "load_and_commit_config",
			map[string]any{"router_name": "core-rtr-01", "config_text": "set system host-name x"}, WriteConfig, SourceProfile},
		// Spec: READ_CONFIG (dry_run defaults to true, section 7, M3).
		{"eos push_config without dry_run", "eos-mcp", "push_config",
			map[string]any{"hostname": "lab-leaf-01", "config_lines": []any{"hostname x"}}, WriteConfig, SourceProfile},
		{"eos push_config dry_run false", "eos-mcp", "push_config",
			map[string]any{"hostname": "lab-leaf-01", "config_lines": []any{"hostname x"}, "dry_run": false}, WriteConfig, SourceProfile},
		{"mcfortigate search_config", "mcfortigate", "search_config",
			map[string]any{"target": "fw-01", "term": "admin"}, ReadConfig, SourceProfile},
		{"netdev run_show_command get system status", "netdev-ssh-mcp", "run_show_command",
			map[string]any{"host": "fw-01", "command": "get system status"}, ReadOperational, SourceProfile},
		// Spec: EXEC_ARBITRARY because show is not on the FortiOS allow-list.
		// Code: the vendor is not known at classify time, so the command
		// passes and the config-read pattern "show system interface" makes
		// it READ_CONFIG. Not a write either way; redaction is mandatory.
		{"ntunes send_command fortios show system interface", "ntunes-netmiko-mcp-server", "send_command",
			map[string]any{"device": "fw-01", "command": "show system interface"}, ReadConfig, SourceReclassify},
		{"ntunes send_command panos show system info", "ntunes-netmiko-mcp-server", "send_command",
			map[string]any{"device": "pa-01", "command": "show system info"}, ReadOperational, SourceDowngrade},
		{"ntunes send_command panos show config running", "ntunes-netmiko-mcp-server", "send_command",
			map[string]any{"device": "pa-01", "command": "show config running"}, ReadConfig, SourceReclassify},
		{"clab destroyLab", "clab-mcp-server", "destroyLab",
			map[string]any{"labName": "lab1"}, LabLifecycle, SourceProfile},
		// Spec: the section 3 fallback classifier downgrades this to
		// READ_OPERATIONAL. Code: a tool with no profile row is
		// EXEC_ARBITRARY and never downgraded.
		{"unknown tool frobnicate", "netdev-ssh-mcp", "frobnicate",
			map[string]any{"command": "show clock"}, ExecArbitrary, SourceFallback},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, ok := profiles[tc.server]
			if !ok {
				t.Fatalf("no profile %s", tc.server)
			}
			res := Classify(p, tc.tool, tc.args)
			if res.Class != tc.want || res.ClassSource != tc.source {
				t.Fatalf("got %s (%s), want %s (%s); reason %q", res.Class, res.ClassSource, tc.want, tc.source, res.Reason)
			}
		})
	}
}

// TestExitCriterion3 is M1 exit criterion 3 and test-matrix rows 3 and 5:
// show ip bgp summary through every free-form command tool is
// READ_OPERATIONAL, reload stays EXEC_ARBITRARY, and a configuration dump
// is READ_CONFIG whatever whitespace separates its words.
func TestExitCriterion3(t *testing.T) {
	profiles := repoProfiles(t)
	tools := []struct {
		server, tool, target, param string
		source                      Source // for show ip bgp summary
	}{
		{"netdev-ssh-mcp", "run_show_command", "host", "command", SourceProfile},
		{"eos-mcp", "run_command", "hostname", "command", SourceDowngrade},
		{"upa-mcp-netmiko-server", "send_command_and_get_output", "name", "command", SourceDowngrade},
		{"ntunes-netmiko-mcp-server", "send_command", "device", "command", SourceDowngrade},
		{"junos-mcp-server", "execute_junos_command", "router_name", "command", SourceDowngrade},
	}
	configDumps := []string{
		"show running-config",
		"show  running-config",
		"show\trunning-config",
		"show \t running-config",
		"\tshow\t\trunning-config\t",
		"SHOW   Running-Config",
		"show run",
		"show startup-config",
		"show configuration",
	}
	for _, tt := range tools {
		p := profiles[tt.server]
		call := func(cmd string) Result {
			return Classify(p, tt.tool, map[string]any{tt.target: "lab-sw-01", tt.param: cmd})
		}
		t.Run(tt.server+"/show ip bgp summary", func(t *testing.T) {
			if r := call("show ip bgp summary"); r.Class != ReadOperational || r.ClassSource != tt.source {
				t.Fatalf("got %s (%s), want READ_OPERATIONAL (%s)", r.Class, r.ClassSource, tt.source)
			}
		})
		t.Run(tt.server+"/reload", func(t *testing.T) {
			r := call("reload")
			if r.Class != ExecArbitrary {
				t.Fatalf("got %s", r.Class)
			}
			if r.Reason != "command 1 failed the read allow-list (blocklist)" {
				t.Fatalf("reason %q should name the command by index and the check", r.Reason)
			}
		})
		for _, cmd := range configDumps {
			t.Run(tt.server+"/"+cmd, func(t *testing.T) {
				if r := call(cmd); r.Class != ReadConfig || r.ClassSource != SourceReclassify {
					t.Fatalf("%q: got %s (%s), want READ_CONFIG (reclassify)", cmd, r.Class, r.ClassSource)
				}
			})
		}
	}
}

func TestClassSource(t *testing.T) {
	p := mustProfile(t)
	cases := []struct {
		name   string
		tool   string
		args   map[string]any
		want   Class
		source Source
		reason string // substring; empty means Reason must be empty
	}{
		{"profile, no commands", "get_config", map[string]any{"host": "a"}, ReadConfig, SourceProfile, ""},
		{"profile, read command kept", "run_show_command", map[string]any{"host": "a", "command": "show version"}, ReadOperational, SourceProfile, ""},
		{"downgrade", "send_command_parallel", map[string]any{"devices": "a", "command": "show version"}, ReadOperational, SourceDowngrade, "passed"},
		{"exec to config read", "send_command_parallel", map[string]any{"devices": "a", "command": "show run"}, ReadConfig, SourceReclassify, "reads configuration"},
		{"read to config read", "run_show_command", map[string]any{"host": "a", "command": "show run"}, ReadConfig, SourceReclassify, "reads configuration"},
		{"read escalated to exec", "run_show_command", map[string]any{"host": "a", "command": "show version\nreload"}, ExecArbitrary, SourceReclassify, checkControl},
		{"exec kept, no command", "send_command_parallel", map[string]any{"devices": "a"}, ExecArbitrary, SourceProfile, "no command"},
		{"exec kept, second command named", "run_commands_batch", map[string]any{"hostnames": "a", "commands": []any{"show version", "write erase"}}, ExecArbitrary, SourceProfile, "command 2 failed the read allow-list (blocklist)"},
		{"exec kept, empty element", "run_commands_batch", map[string]any{"hostnames": "a", "commands": []any{"show version", "\n"}}, ExecArbitrary, SourceProfile, "command 2 failed the read allow-list (control-character)"},
		{"exec kept, whitespace-only element", "run_commands_batch", map[string]any{"hostnames": "a", "commands": []any{"show version", " \t "}}, ExecArbitrary, SourceProfile, "command 2 failed the read allow-list (empty)"},
		{"trailing newline kept", "run_show_command", map[string]any{"host": "a", "command": "show version\n"}, ExecArbitrary, SourceReclassify, "(control-character)"},
		{"spaces trimmed", "run_show_command", map[string]any{"host": "a", "command": " show version "}, ReadOperational, SourceProfile, ""},
		{"write kept", "send_config", map[string]any{"device": "a", "config_commands": "hostname x"}, WriteConfig, SourceProfile, ""},
		{"fallback, unknown tool", "mystery", map[string]any{"command": "show version"}, ExecArbitrary, SourceFallback, "not in profile"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Classify(p, tc.tool, tc.args)
			if r.Class != tc.want || r.ClassSource != tc.source {
				t.Fatalf("got %s (%s), want %s (%s)", r.Class, r.ClassSource, tc.want, tc.source)
			}
			if (tc.reason == "" && r.Reason != "") || !strings.Contains(r.Reason, tc.reason) {
				t.Fatalf("reason %q, want it to contain %q", r.Reason, tc.reason)
			}
		})
	}
	if r := Classify(nil, "x", nil); r.Class != ExecArbitrary || r.ClassSource != SourceFallback {
		t.Fatalf("nil profile: %s (%s)", r.Class, r.ClassSource)
	}
}

// TestReasonNeverQuotesInput: Reason may reach the agent (M1-18 deny text)
// and the audit line, so it carries no agent-supplied text: neither the
// command nor the tool name.
func TestReasonNeverQuotesInput(t *testing.T) {
	p := mustProfile(t)
	const marker = "zz-marker-zz"
	for _, r := range []Result{
		Classify(p, "run_show_command", map[string]any{"host": "a", "command": "reload " + marker}),
		Classify(p, "send_command_parallel", map[string]any{"devices": "a", "command": "show version\n" + marker}),
		Classify(p, "run_commands_batch", map[string]any{"hostnames": "a", "commands": []any{"show version", marker}}),
		Classify(p, marker, map[string]any{"command": "show version"}),
	} {
		if strings.Contains(r.Reason, marker) || strings.Contains(r.Reason, "reload") {
			t.Errorf("reason quotes input: %q", r.Reason)
		}
		if r.Reason == "" {
			t.Errorf("reason empty for %s", r.Class)
		}
	}
	if got := failReason(1, checkBlocklist); got != "command 2 failed the read allow-list (blocklist)" {
		t.Errorf("failReason = %q", got)
	}
}

// TestSourceRoundTrip pins the six class_source spellings of
// audit-event-schema.md and rejects anything else.
func TestSourceRoundTrip(t *testing.T) {
	want := map[Source]string{
		SourceProfile:         "profile",
		SourceCapabilityTable: "capability_table",
		SourceFallback:        "fallback",
		SourceAnnotationRaise: "annotation_raise",
		SourceDowngrade:       "downgrade",
		SourceReclassify:      "reclassify",
	}
	if len(Sources()) != len(want) {
		t.Fatalf("Sources() has %d, want %d", len(Sources()), len(want))
	}
	for _, s := range Sources() {
		if s.String() != want[s] {
			t.Errorf("%v.String() = %q, want %q", s, s.String(), want[s])
		}
		got, err := ParseSource(want[s])
		if err != nil || got != s {
			t.Errorf("ParseSource(%q) = %q, %v", want[s], got, err)
		}
	}
	for _, bad := range []string{"", "Profile", "PROFILE", "dry-run", "capability-table", "annotation"} {
		if _, err := ParseSource(bad); err == nil {
			t.Errorf("ParseSource(%q) accepted", bad)
		}
	}
}

// TestNeverDowngrade covers section 8: the token in a tool's profile notes
// keeps an EXEC_ARBITRARY tool EXEC_ARBITRARY; without it the same command
// downgrades.
func TestNeverDowngrade(t *testing.T) {
	p, err := ParseProfile([]byte(`
server: fake
tools:
  pfe:
    class: EXEC_ARBITRARY
    args: []
    command_params: [command]
    notes: never-downgrade. PFE shell.
  cli:
    class: EXEC_ARBITRARY
    args: []
    command_params: [command]
    notes: Plain CLI; never downgraded in practice (no token).
  shell:
    class: EXEC_ARBITRARY
    args: []
    command_params: [command]
    notes: Never-Downgrade. shell
  upper:
    class: EXEC_ARBITRARY
    args: []
    command_params: [command]
    notes: Lab-node exec, NEVER-DOWNGRADE.
`))
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"command": "show jnh 0 exceptions"}
	if r := Classify(p, "pfe", args); r.Class != ExecArbitrary || r.ClassSource != SourceProfile {
		t.Fatalf("pfe: %s (%s)", r.Class, r.ClassSource)
	}
	for _, tool := range []string{"shell", "upper"} {
		if r := Classify(p, tool, args); r.Class != ExecArbitrary || r.ClassSource != SourceProfile {
			t.Fatalf("%s: capitalised token must still hold: %s (%s)", tool, r.Class, r.ClassSource)
		}
	}
	if r := Classify(p, "cli", args); r.Class != ReadOperational || r.ClassSource != SourceDowngrade {
		t.Fatalf("cli: %s (%s)", r.Class, r.ClassSource)
	}
}

// TestAllowPrefix has one positive and one negative case per allow-list
// entry (section 5.2 as implemented: one vendor-agnostic list).
func TestAllowPrefix(t *testing.T) {
	cases := []struct {
		entry, pos, neg string
	}{
		{"show", "show ip bgp summary", "shows ip bgp summary"},
		{"get", "get system status", "getall system status"},
		{"display", "display version", "displays version"},
		{"monitor traffic", "monitor traffic interface ge-0/0/0 count 10", "monitor session 1"},
		{"ping", "ping 10.0.0.1 count 3", "pingall 10.0.0.1"},
		{"traceroute", "traceroute 10.0.0.1", "traceroute6 2001:db8::1"},
		{"tracepath", "tracepath 10.0.0.1", "tracepath6 2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.entry, func(t *testing.T) {
			if c, check := classifyCommand(tc.pos); c != ReadOperational {
				t.Errorf("positive %q: %s (%s)", tc.pos, c, check)
			}
			if c, check := classifyCommand(tc.neg); c != ExecArbitrary || check != checkAllowPrefix {
				t.Errorf("negative %q: %s (%s), want EXEC_ARBITRARY (allow-prefix)", tc.neg, c, check)
			}
		})
	}
	for _, cmd := range []string{"terminal length 0", "sh run", "more flash:x", "dir", "monitor interface ge-0/0/0", "monitor capture cap start", "info from state"} {
		if c, check := classifyCommand(cmd); c != ExecArbitrary || check != checkAllowPrefix {
			t.Errorf("%q: %s (%s), want EXEC_ARBITRARY (allow-prefix)", cmd, c, check)
		}
	}
}

// TestBlocklist has one positive and one negative case per blocklist entry
// (section 5.3 as implemented). The positive puts the verb as a word after
// an allowed prefix; the negative joins it into a hyphenated keyword, which
// the whitespace boundary must not match.
func TestBlocklist(t *testing.T) {
	cases := []struct {
		entry, pos, neg string
	}{
		{"configure", "show configure", "show interfaces configure-state"},
		{"config t", "show config t", "show interfaces config-t"},
		{"config terminal", "show config terminal", "show interfaces config-terminal"},
		{"edit", "show edit", "show interfaces edit-state"},
		{"set", "show set", "show interfaces set-state"},
		{"delete", "show interfaces delete", "show interfaces delete-state"},
		{"rollback", "show system rollback", "show interfaces rollback-state"},
		{"commit", "show system commit", "show interfaces commit-state"},
		{"write", "show interfaces write", "show interfaces write-state"},
		{"write mem", "show interfaces write mem", "show interfaces write-mem"},
		{"write memory", "show interfaces write memory", "show interfaces write-memory"},
		{"write erase", "show interfaces write erase", "show interfaces write-erase"},
		{"write-file", "monitor traffic interface ge-0/0/0 write-file /var/tmp/x", "monitor traffic interface ge-0/0/0 write-files count 10"},
		{"read-file", "monitor traffic interface ge-0/0/0 read-file /var/tmp/x count 10", "monitor traffic interface ge-0/0/0 read-files count 10"},
		{"copy running", "show copy running", "show interfaces copy-running"},
		{"reload", "show reload", "show interfaces reload-state"},
		{"reboot", "show reboot", "show interfaces reboot-state"},
		{"shutdown", "show interfaces shutdown", "show interfaces no-shutdown"},
		{"clear", "show clear", "show interfaces clear-state"},
		{"reset", "show reset", "show system reset-reason"},
		{"format", "show format", "show interfaces format-state"},
		{"erase", "show erase", "show interfaces erase-state"},
		{"debug", "show debug", "show interfaces debug-state"},
		{"request system", "show request system", "show interfaces request-system"},
		{"zeroize", "show zeroize", "show interfaces zeroize-state"},
		{"admin save", "show admin save", "show admin-save"},
		{"admin reboot", "show admin reboot", "show admin-reboot"},
		// Abbreviations the device CLI accepts.
		{"conf t", "show conf t", "show conf"},
		{"confi term", "show confi term", "show configuration"},
		{"wr", "show interfaces wr", "show interfaces wr-state"},
		{"wri", "show interfaces wri", "show interfaces wri-state"},
		{"rel", "show interfaces rel", "show release"},
		{"relo", "show interfaces relo", "show interfaces relo-state"},
		{"copy", "show copy run start", "show interfaces copy-state"},
		{"undebug", "show undebug all", "show interfaces undebug-state"},
		{"tclsh", "show tclsh", "show interfaces tclsh-state"},
		{"bash", "show bash", "show interfaces bash-state"},
		{"python", "show python", "show interfaces python-state"},
		{"guestshell", "show guestshell", "show interfaces guestshell-state"},
		{"start shell", "show start shell", "show start"},
	}
	for _, tc := range cases {
		t.Run(tc.entry, func(t *testing.T) {
			if c, check := classifyCommand(tc.pos); c != ExecArbitrary || check != checkBlocklist {
				t.Errorf("positive %q: %s (%s), want EXEC_ARBITRARY (blocklist)", tc.pos, c, check)
			}
			if c, check := classifyCommand(tc.neg); c == ExecArbitrary {
				t.Errorf("negative %q: %s (%s), want a read", tc.neg, c, check)
			}
		})
	}
}

// TestBlocklistStart has one positive and one negative case per verb of
// the start-anchored blocklist (classification.md section 5.3,
// bl-config-mode and the vendor rows). The negative is the same verb after
// an allowed prefix where the anywhere-list does not catch it.
func TestBlocklistStart(t *testing.T) {
	verbs := []string{
		"configure", "config", "conf", "edit", "set", "delete", "no", "commit", "rollback", "load",
		"save", "write", "wr", "copy", "erase", "format", "reload", "rel", "relo", "request",
		"restart", "shutdown", "clear", "reset", "debug", "undebug", "monitor start", "install",
		"boot", "zeroize", "reboot", "halt", "power", "activate", "deactivate", "license", "crypto",
		"archive", "exec", "start", "bash", "python", "guestshell", "tclsh", "run", "enable",
		"feature", "dockerd", "scp", "tftp", "ssh", "ftp", "telnet", "execute", "diagnose", "file",
		"test",
	}
	for _, v := range verbs {
		t.Run(v, func(t *testing.T) {
			pos := v + " x"
			if c, check := classifyCommand(pos); c != ExecArbitrary || check != checkBlocklist {
				t.Errorf("positive %q: %s (%s), want EXEC_ARBITRARY (blocklist)", pos, c, check)
			}
			if !blocklistStart.MatchString(pos) {
				t.Errorf("positive %q: not matched by blocklistStart", pos)
			}
			neg := v + "-x"
			if blocklistStart.MatchString(neg) {
				t.Errorf("negative %q: matched by blocklistStart", neg)
			}
		})
	}
	// Show arguments that share a start verb are reads.
	for _, cmd := range []string{"show boot", "show install summary", "show license", "show crypto session", "show archive log config"} {
		if c, _ := classifyCommand(cmd); c == ExecArbitrary {
			t.Errorf("%q: EXEC_ARBITRARY, want a read", cmd)
		}
	}
}

// TestSystemKeywordOverMatch pins the intended over-match of the two-way
// prefix test after "system": "ha" is a prefix of "hardware", so a
// hardware listing is READ_CONFIG. This is the stricter read class and is
// accepted rather than steered around.
func TestSystemKeywordOverMatch(t *testing.T) {
	for _, in := range []string{"get system hardware", "show system a", "show system i"} {
		if c := ClassifyCommand(in); c != ReadConfig {
			t.Errorf("%q: %s, want READ_CONFIG (documented over-match)", in, c)
		}
	}
}

// TestConfigRead has one positive and one negative case per config-read
// keyword (section 6 as implemented). Negatives put the same word where it
// is not the thing shown, or show something that is not configuration.
func TestConfigRead(t *testing.T) {
	cases := []struct {
		entry, pos, neg string
	}{
		{"run", "show run", "show interfaces run"},
		{"ru", "show ru", "show interfaces ru"},
		{"running-config", "show running-config interface Gi1", "show interfaces running-config"},
		{"star", "show start", "show ip route static"},
		{"startup-config", "show startup-config", "show interfaces startup-config"},
		{"conf", "show conf", "show bgp neighbor conf"},
		{"configuration", "show configuration interfaces", "show interfaces configuration"},
		{"config (panos)", "show config running", "show interfaces config"},
		{"config-sessions (keyword is a prefix)", "show config-sessions", "show interfaces config-sessions"},
		{"arch", "show archive config differences", "show ip arp"},
		{"tec", "show tec", "show interfaces tech"},
		{"tech-support", "show tech-support", "show interfaces tech-support"},
		{"full-conf", "show full-configuration", "show interfaces full"},
		{"current", "display current", "display version"},
		{"current-configuration", "display current-configuration", "display interface brief"},
		{"saved", "display saved-configuration", "display clock"},
		{"derived", "show derived", "show interfaces derived"},
		{"session-config", "show session-config", "show interfaces session-config"},
		{"checkpoint", "show checkpoint summary", "show interfaces checkpoint"},
		{"candidate", "show candidate", "show interfaces candidate"},
		{"bare show", "show", "show version"},
		{"bare get", "get", "get system status"},
		{"bare display", "display", "display version"},
		{"system configuration", "show system configuration", "show system info"},
		{"sys rol", "show sys rol 1", "show sys uptime"},
		{"system rollb (full word rollback is on the blocklist)", "show system rollb 1", "show system users"},
		{"system admin", "get system admin", "get system status"},
		{"system interface", "show system interface", "show system information"},
		{"system ha", "get system ha status", "get system performance status"},
	}
	for _, tc := range cases {
		t.Run(tc.entry, func(t *testing.T) {
			if c, check := classifyCommand(tc.pos); c != ReadConfig {
				t.Errorf("positive %q: %s (%s), want READ_CONFIG", tc.pos, c, check)
			}
			if c, check := classifyCommand(tc.neg); c != ReadOperational {
				t.Errorf("negative %q: %s (%s), want READ_OPERATIONAL", tc.neg, c, check)
			}
		})
	}
}

// TestDowngradeNeverAccepts lists chaining, injection and smuggling forms
// that must keep a command EXEC_ARBITRARY. Invariant 3: nothing may lower a
// class unsafely. Each case names the check that must catch it.
func TestDowngradeNeverAccepts(t *testing.T) {
	cases := []struct {
		cmd, check string
	}{
		// Chaining and substitution.
		{"show version; reload", checkShellMeta},
		{"show version;reload", checkShellMeta},
		{"show version && reload", checkShellMeta},
		{"show version & reload", checkShellMeta},
		{"show version || reload", checkShellMeta},
		{"show `reload`", checkShellMeta},
		{"show $(reload)", checkShellMeta},
		// Pipes, including filters the spec would allow.
		{"show version | reload", checkShellMeta},
		{"show run | include password", checkShellMeta},
		{"show version | json", checkShellMeta},
		{"show bgp summary | no-more", checkShellMeta},
		{"show configuration | save /var/tmp/c", checkShellMeta},
		{"show version | tee flash:v.txt", checkShellMeta},
		// Redirects.
		{"show version > flash:v.txt", checkShellMeta},
		{"show version >> flash:v.txt", checkShellMeta},
		{"show version < /etc/passwd", checkShellMeta},
		// A second line: the device runs it even though whitespace
		// collapsing would have hidden it.
		{"show version\nreload", checkControl},
		{"show version\ncopy tftp://10.0.0.9/x flash:", checkControl},
		{"show version\nterminal monitor", checkControl},
		{"show version\r\nreload", checkControl},
		{"show version\rreload", checkControl},
		{"show version\vreload", checkControl},
		{"show version\freload", checkControl},
		{"show version\x00reload", checkControl},
		{"show version\x1a", checkControl}, // Ctrl-Z
		{"show version\x03", checkControl}, // Ctrl-C
		{"show version\x1b[A", checkControl},
		{"show version\x7f", checkControl},
		// Look-alike and invisible characters.
		{"show\u00a0version", checkNonASCII},
		{"show version\u2028reload", checkNonASCII},
		{"show ver\u200bsion", checkNonASCII},
		{"\uff53\uff48\uff4f\uff57 version", checkNonASCII},
		{"show version \xff", checkNonASCII},
		// Leading-dash arguments.
		{"ping -f 10.0.0.1", checkLeadingDash},
		{"ping 10.0.0.1 -c 100000", checkLeadingDash},
		{"traceroute --help", checkLeadingDash},
		{"tracepath -b 10.0.0.1", checkLeadingDash},
		{"show -x", checkLeadingDash},
		// Not reads at all.
		{"", checkEmpty},
		{"   ", checkEmpty},
		{"\t", checkEmpty},
		{"reload", checkBlocklist},
		{"RELOAD", checkBlocklist},
		{"write erase", checkBlocklist},
		{"conf t", checkBlocklist},
	}
	for _, tc := range cases {
		t.Run(tc.cmd, func(t *testing.T) {
			c, check := classifyCommand(tc.cmd)
			if c != ExecArbitrary || check != tc.check {
				t.Fatalf("%q: %s (%s), want EXEC_ARBITRARY (%s)", tc.cmd, c, check, tc.check)
			}
		})
	}
}

// TestWhitespaceVariants is from the security review of PR #108 (T0.53):
// extra spaces and tabs must not dodge config-read detection, and the
// original command reaches Commands unchanged apart from trimming.
func TestWhitespaceVariants(t *testing.T) {
	for _, cmd := range []string{
		"show running-config",
		"show  running-config",
		"show\trunning-config",
		"show\t\trunning-config",
		"  show   running-config  ",
		"show \t startup-config",
		"show\tconfiguration\t|\tdisplay set", // pipe still fails
	} {
		want := ReadConfig
		if strings.Contains(cmd, "|") {
			want = ExecArbitrary
		}
		if got := ClassifyCommand(cmd); got != want {
			t.Errorf("%q: %s, want %s", cmd, got, want)
		}
	}
	p := mustProfile(t)
	r := Classify(p, "send_command_parallel", map[string]any{"devices": "a", "command": " show\t running-config "})
	if len(r.Commands) != 1 || r.Commands[0] != "show\t running-config" {
		t.Fatalf("commands %q: interior whitespace must be forwarded as sent", r.Commands)
	}
}
