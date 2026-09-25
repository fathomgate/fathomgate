// SPDX-License-Identifier: FSL-1.1-ALv2

package classify

import (
	"encoding/json"
	"path/filepath"
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
		// Second round of the same review: still READ_OPERATIONAL before
		// the keyword test was inverted. show sys rol 1 is Junos show
		// system rollback 1, the previous configuration with its $9$
		// secrets.
		"show sys rol 1", "show tec", "show ru", "show derived",
		// Third round: NX-OS prints saved configs from bootflash and
		// config diffs with password hashes.
		"show file bootflash:backup.cfg",
		"show diff rollback-patch checkpoint cp1 running-config",
		// A bare show prints the whole configuration on FortiOS.
		"show", "get", "display",
	} {
		if c := ClassifyCommand(in); c != ReadConfig {
			t.Errorf("%q: %s, want READ_CONFIG", in, c)
		}
	}
}

// TestShellQuotedOptionInjection: quoting, escapes, braces and $ let a shell
// on the server host rebuild a leading-dash option the leading-dash check
// never saw. Each is refused as shell-meta.
func TestShellQuotedOptionInjection(t *testing.T) {
	for _, in := range []string{
		`ping 1.1.1.1 "-f"`,
		`ping 1.1.1.1 '-f'`,
		`ping 1.1.1.1 \-f`,
		`ping {-f,1.1.1.1}`,
		`ping 1.1.1.1 $'\x2df'`,
		`ping $HOME`,
		`ping${IFS}-f${IFS}1.1.1.1`,
		`ping 1.1.1.1 [-]f`,
		`ping 1.1.1.1 *`,
		`ping 1.1.1.1 -?`,
		`ping ~root`,
		`show ip bgp regexp _65000$x`,
		`show ip bgp regexp $(reload)`,
		`show ip bgp regexp ${IFS}`,
		`show ip bgp regexp $'x'`,
	} {
		if c, check := classifyCommand(in); c != ExecArbitrary || check != checkShellMeta {
			t.Errorf("%q: %s (%s), want EXEC_ARBITRARY (shell-meta)", in, c, check)
		}
	}
	// A $ at the end of a word is a regex anchor no shell expands.
	for _, in := range []string{`show ip bgp regexp _65000$`, `show ip bgp regexp ^65000_$ `, `show ip as-path-access-list _65000$ detail`} {
		if c, check := classifyCommand(in); c != ReadOperational {
			t.Errorf("%q: %s (%s), want READ_OPERATIONAL", in, c, check)
		}
	}
}

// TestCommandLengthCap: a command over 1024 bytes is never downgraded.
func TestCommandLengthCap(t *testing.T) {
	ok := "show " + strings.Repeat("x", maxCommandLen-len("show "))
	if c, check := classifyCommand(ok); c != ReadOperational {
		t.Errorf("1024 bytes: %s (%s), want READ_OPERATIONAL", c, check)
	}
	if c, check := classifyCommand(ok + "x"); c != ExecArbitrary || check != checkTooLong {
		t.Errorf("1025 bytes: %s (%s), want EXEC_ARBITRARY (too-long)", c, check)
	}
}

// TestMonitorTrafficNeedsCount: Junos monitor traffic without count runs
// until interrupted (classification.md 5.6).
func TestMonitorTrafficNeedsCount(t *testing.T) {
	for _, in := range []string{
		"monitor traffic interface ge-0/0/0",
		"monitor traffic interface count",
		"monitor traffic interface ge-0/0/0 count",
		"monitor traffic interface ge-0/0/0 count 0",
		"monitor traffic interface ge-0/0/0 count 1001",
		"monitor traffic interface ge-0/0/0 count 999999999",
		"monitor traffic interface ge-0/0/0 count 0010x",
		"monitor traffic interface ge-0/0/0 count +5",
		"monitor traffic interface ge-0/0/0 count 5 count 999999",
		"monitor traffic interface ge-0/0/0 count 999999 count 5",
		"monitor traffic interface count count 5",
	} {
		if c, check := classifyCommand(in); c != ExecArbitrary || check != checkNoCount {
			t.Errorf("%q: %s (%s), want EXEC_ARBITRARY (monitor-no-count)", in, c, check)
		}
	}
	for _, in := range []string{
		"monitor traffic interface ge-0/0/0 count 1",
		"monitor traffic interface ge-0/0/0 count 10",
		"monitor traffic interface ge-0/0/0 count 1000",
		"monitor traffic interface ge-0/0/0 count 5 count 10",
	} {
		if c := ClassifyCommand(in); c != ReadOperational {
			t.Errorf("%q: %s, want READ_OPERATIONAL", in, c)
		}
	}
	// Junos monitor interface takes no count and runs until interrupted,
	// so it is not on the allow-list at all.
	if c, check := classifyCommand("monitor interface ge-0/0/0"); c != ExecArbitrary || check != checkAllowPrefix {
		t.Errorf("monitor interface: %s (%s), want EXEC_ARBITRARY (allow-prefix)", c, check)
	}
}

// Security review of PR #161 (M1-35). Python FastMCP (mcp >= 1.x,
// func_metadata.pre_parse_json) json.loads any string sent for a parameter
// whose annotation is not plain str, so eos-mcp's hostnames/tags/commands
// (list[str] | None) receive a list, or None, from a JSON string. fathomgate
// reads the same value as one opaque target or command string.
func TestSecurityJSONStringInListParam(t *testing.T) {
	profiles, err := LoadProfileDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	eos := profiles["eos-mcp"]
	cases := []struct {
		tool string
		raw  string
	}{
		// upstream runs "show running-config" on core-rtr-01; fathomgate sees target `["core-rtr-01"]`.
		{"run_command_batch", `{"command":"show running-config","hostnames":"[\"core-rtr-01\"]"}`},
		// JSON escape: the literal never matches an inventory name or pattern.
		{"run_command_batch", `{"command":"show version","hostnames":"[\"\\u0063ore-rtr-01\"]"}`},
		// upstream: hostnames=None, tags=None -> every configured device (server.py:476-478).
		{"daily_brief", `{"hostnames":"null"}`},
		// group through tags.
		{"get_device_facts_batch", `{"tags":" [\"prod\"]"}`},
		// config payload read as one line.
		{"push_config", `{"hostname":"lab-leaf-01","config_lines":"[\"hostname x\"]"}`},
	}
	for _, c := range cases {
		var args map[string]any
		if err := json.Unmarshal([]byte(c.raw), &args); err != nil {
			t.Fatal(err)
		}
		res := Classify(eos, c.tool, args)
		if res.ArgumentsOK() {
			t.Errorf("%s %s: ArgumentsOK, class %s, targets %q, commands %q; want MalformedArgs (upstream pre-parses the JSON string)",
				c.tool, c.raw, res.Class, res.Targets, res.Commands)
		}
	}
}

// Name tricks that must be reported as unnamed (these pass today; recorded
// so a later change to Named cannot loosen them).
func TestSecurityArgumentNameTricks(t *testing.T) {
	profiles, err := LoadProfileDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	eos := profiles["eos-mcp"]
	for _, k := range []string{
		"Config_Path", "CONFIG_PATH", "config_path ", " config_path", "config\u200bpath",
		"conf\u0456g_path",  // Cyrillic i
		"\u017Fession_name", // long s, folds to "s" under Unicode simple folding
		"_meta", "hostname\u0000", "Hostname",
	} {
		unnamed, _ := CheckArguments(eos, "get_version", map[string]any{"hostname": "lab-leaf-01", k: ""})
		if len(unnamed) != 1 || unnamed[0] != k {
			t.Errorf("%q: unnamed %q", k, unnamed)
		}
	}
	// unknown tool, and a prefixed name of a tool the profile does not list
	for _, tool := range []string{"reload_devices", "eos-mcp.reload_devices", "junos-mcp-server.get_version"} {
		unnamed, _ := CheckArguments(eos, tool, map[string]any{"file_name": "/etc/passwd"})
		if len(unnamed) != 1 {
			t.Errorf("%s: unnamed %q", tool, unnamed)
		}
	}
	// non-string command values
	for _, v := range []any{float64(1), true, map[string]any{"cmd": "reload"}, []any{"show version", []any{"reload"}}, []any{nil}} {
		_, malformed := CheckArguments(eos, "run_command", map[string]any{"hostname": "lab-leaf-01", "command": v})
		if len(malformed) != 1 {
			t.Errorf("command %#v: malformed %q", v, malformed)
		}
	}
}

// TestJSONStringCheckBoundaries: what upstreamMayParseJSON refuses and
// what it must leave alone (PR #161 H1). Config payloads keep Junos
// "[edit ...]" text and JSON objects; targets and commands never start
// with [ or {.
func TestJSONStringCheckBoundaries(t *testing.T) {
	profiles, err := LoadProfileDir(filepath.Join("..", "..", "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	junos, eos, ntunes := profiles["junos-mcp-server"], profiles["eos-mcp"], profiles["ntunes-netmiko-mcp-server"]
	cases := []struct {
		name      string
		p         *Profile
		tool      string
		args      map[string]any
		malformed bool
	}{
		{"junos edit text", junos, "load_and_commit_config", map[string]any{"router_name": "r1", "config_text": "[edit system]\nhost-name x;"}, false},
		{"junos json object payload", junos, "load_and_commit_config", map[string]any{"router_name": "r1", "config_text": `{"configuration": {"system": {"host-name": "x"}}}`}, false},
		{"junos set text", junos, "load_and_commit_config", map[string]any{"router_name": "r1", "config_text": "set system host-name x"}, false},
		{"config payload true", junos, "load_and_commit_config", map[string]any{"router_name": "r1", "config_text": " true "}, true},
		{"config payload json array", ntunes, "send_config", map[string]any{"device": "d", "config_commands": `["hostname x", "end"]`}, true},
		{"config payload invalid bracket text", eos, "push_config", map[string]any{"hostname": "h", "config_lines": "[not json"}, false},
		{"target starting with brace", eos, "get_version", map[string]any{"hostname": `{"a":1}`}, true},
		{"target bracket not valid json", eos, "run_command_batch", map[string]any{"command": "show version", "hostnames": `["a", NaN]`}, true},
		{"target false", eos, "get_device_facts_batch", map[string]any{"hostnames": "false"}, true},
		{"plain hostname", eos, "get_version", map[string]any{"hostname": "lab-leaf-01"}, false},
		{"hostname starting with n", eos, "get_version", map[string]any{"hostname": "nyc-leaf-01"}, false},
		{"hostname true-ish but not json", eos, "get_version", map[string]any{"hostname": "trueleaf"}, false},
		{"hostnames list of strings", eos, "run_command_batch", map[string]any{"command": "show version", "hostnames": []any{"[a]"}}, false},
		{"command starting with bracket", eos, "run_command", map[string]any{"hostname": "h", "command": `["show version","reload"]`}, true},
		{"command null string", eos, "run_command", map[string]any{"hostname": "h", "command": "null"}, true},
		{"normal command", eos, "run_command", map[string]any{"hostname": "h", "command": "show interfaces status"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, malformed := CheckArguments(c.p, c.tool, c.args)
			if got := len(malformed) > 0; got != c.malformed {
				t.Fatalf("malformed %q, want malformed=%v", malformed, c.malformed)
			}
		})
	}
}
