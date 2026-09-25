// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/fathomgate/fathomgate/internal/classify"
	"github.com/fathomgate/fathomgate/internal/inventory"
	"github.com/fathomgate/fathomgate/internal/policy"
)

// The three M1 validates_against servers, by their profile server names.
const (
	netdev = "netdev-ssh-mcp"
	upa    = "upa"
	eos    = "eos-mcp"
)

// attackerPatterns are the hostname patterns of the ADR 0031 tests: with
// them active, every attacker name below matched a pattern before ADR 0031.
var attackerPatterns = []inventory.Pattern{
	{Match: "^core-|^border-", Role: "core"},
	{Match: "^lab-", Tags: []string{"lab"}},
	{Match: "^fw-", Role: "firewall"},
}

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

func repoProfiles(t testing.TB) map[string]*classify.Profile {
	t.Helper()
	ps, err := classify.LoadProfileDir(repoPath("profiles"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{netdev, upa, eos} {
		if ps[s] == nil {
			t.Fatalf("no repo profile for %s", s)
		}
	}
	return ps
}

// repoInventory is inventory.example.yaml, with the attacker patterns added
// when patterns is true.
func repoInventory(t testing.TB, patterns bool) inventory.Resolver {
	t.Helper()
	f, err := inventory.LoadFile(repoPath("inventory.example.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if patterns {
		f.Roles = append(f.Roles, attackerPatterns...)
	}
	c, err := f.Chain()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func examplePolicy(t testing.TB, name string) *policy.Policy {
	t.Helper()
	p, err := policy.Load(repoPath("policies", "examples", name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func newGate(t testing.TB, pol *policy.Policy, patterns bool) *Gate {
	t.Helper()
	g, err := New(Config{Policy: pol, Profiles: repoProfiles(t), Inventory: repoInventory(t, patterns)})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func call(server, tool string, args map[string]any) CallInfo {
	raw, err := json.Marshal(args)
	if err != nil {
		panic(err)
	}
	return CallInfo{
		Server: server, Tool: tool, Arguments: raw,
		AgentProtocol: "2025-11-25", AgentEra: "stateful",
		UpstreamProtocol: "2025-06-18", UpstreamEra: "stateful",
		Transport: "stdio", Principal: "local", Session: "a1b2c3d4",
	}
}

type want struct {
	effect, rule, class, source string
	forward                     bool
	text                        string // exact Error; "" when forwarded
}

func check(t *testing.T, name string, v Verdict, w want) {
	t.Helper()
	if v.Effect != w.effect || v.RuleID != w.rule || v.Class != w.class || v.Forward != w.forward {
		t.Errorf("%s: got %s %s %s forward=%v, want %s %s %s forward=%v (%s)",
			name, v.Effect, v.RuleID, v.Class, v.Forward, w.effect, w.rule, w.class, w.forward, v.Error)
	}
	if w.source != "" && v.ClassSource != w.source {
		t.Errorf("%s: class_source %s, want %s", name, v.ClassSource, w.source)
	}
	if w.text != "" && v.Error != w.text {
		t.Errorf("%s: text\n got %q\nwant %q", name, v.Error, w.text)
	}
	if v.Forward != (v.Error == "") {
		t.Errorf("%s: forward=%v with error %q", name, v.Forward, v.Error)
	}
	if strings.ContainsAny(v.Error, "\r\n") {
		t.Errorf("%s: error text spans lines: %q", name, v.Error)
	}
}

// freeForm is the command-carrying tool of each M1 server: tool, target
// parameter, a known lab device, command parameter, and the class source a
// passing read gets (netdev-ssh-mcp's tool is READ_OPERATIONAL in its
// profile, so a read confirms the profile; the other two are
// EXEC_ARBITRARY and are downgraded).
var freeForm = []struct {
	server, tool, target, cmd, readSource string
}{
	{netdev, "run_show_command", "host", "command", "profile"},
	{upa, "send_command_and_get_output", "name", "command", "downgrade"},
	{eos, "run_command", "hostname", "command", "downgrade"},
}

// TestMatrixRows is test-matrix rows 3, 4 and 6 from arguments to decision
// through each validated profile, under read-only and prod-approval.
func TestMatrixRows(t *testing.T) {
	for _, pol := range []string{"read-only", "prod-approval"} {
		g := newGate(t, examplePolicy(t, pol), false)
		noExec := map[string]string{
			"read-only":     "free-form commands that are not reads are not permitted",
			"prod-approval": reasonNoReason,
		}[pol]
		for _, ff := range freeForm {
			name := pol + " " + ff.server + "." + ff.tool
			// Row 3: show ip bgp summary is READ_OPERATIONAL, allowed.
			v := g.Decide(context.Background(), call(ff.server, ff.tool, map[string]any{ff.target: "core-rtr-01", ff.cmd: "show ip bgp summary"}))
			check(t, name+" row 3", v, want{effect: "allow", rule: "reads-anywhere", class: "READ_OPERATIONAL", source: ff.readSource, forward: true})
			if !reflect.DeepEqual(v.Targets, []string{"core-rtr-01"}) {
				t.Errorf("%s row 3: targets %q", name, v.Targets)
			}
			// Row 4: reload is EXEC_ARBITRARY, denied by no-exec.
			v = g.Decide(context.Background(), call(ff.server, ff.tool, map[string]any{ff.target: "lab-sw-01", ff.cmd: "reload"}))
			check(t, name+" row 4", v, want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY",
				text: "fathomgate denied " + ff.server + "." + ff.tool + ": rule no-exec (class EXEC_ARBITRARY): " + noExec})
			// Row 6: a name absent from inventory is denied before the rules.
			v = g.Decide(context.Background(), call(ff.server, ff.tool, map[string]any{ff.target: "ghost-99", ff.cmd: "show version"}))
			check(t, name+" row 6", v, want{effect: "deny", rule: "default:unknown_target", class: "READ_OPERATIONAL",
				text: "fathomgate denied " + ff.server + "." + ff.tool + ": rule default:unknown_target (class READ_OPERATIONAL): target not in inventory"})
		}
	}
}

// TestInjectionInputs carries the PR #152 inputs from arguments to decision
// on every free-form tool of the M1 servers, under read-only.
func TestInjectionInputs(t *testing.T) {
	g := newGate(t, examplePolicy(t, "read-only"), false)
	execCases := []string{
		// Multi-line and control characters.
		"show clock\nconf t\nhostname pwned\nend",
		"show clock\ncopy run start",
		"show clock\nrelo\n\nshow clock",
		"show clock\ntclsh",
		"show clock\rreload",
		"show clock\r\nreload",
		"show version\u2028reload",
		"show version\u0085reload",
		"show version\x00",
		"show version\x1b[2J",
		"show version\n",
		"show\u00a0version",
		// Quoting, escapes and shell metacharacters.
		`ping 1.1.1.1 "-f"`,
		`ping 1.1.1.1 '-f'`,
		`ping 1.1.1.1 \-f`,
		`ping ${IFS}-f`,
		"show version | redirect flash:x",
		"show version; reload",
		"show `reload`",
		// Blocklist and allow-prefix.
		"reload",
		"conf t",
		"sh run",
		"",
	}
	for _, ff := range freeForm {
		for _, cmd := range execCases {
			v := g.Decide(context.Background(), call(ff.server, ff.tool, map[string]any{ff.target: "lab-sw-01", ff.cmd: cmd}))
			check(t, ff.server+" "+strings.ToValidUTF8(cmd, "?"), v, want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY"})
			if cmd != "" && strings.Contains(v.Error, cmd) {
				t.Errorf("%s %q: the command is echoed: %q", ff.server, cmd, v.Error)
			}
		}
		// Short-form config dumps are READ_CONFIG: allowed by
		// reads-anywhere under read-only, with the redact obligation (M2).
		for _, cmd := range []string{"show run", "show ru", "show running-config", "show conf", "show start", "show tech", "show sys rol 1", "show"} {
			v := g.Decide(context.Background(), call(ff.server, ff.tool, map[string]any{ff.target: "lab-sw-01", ff.cmd: cmd}))
			check(t, ff.server+" "+cmd, v, want{effect: "allow", rule: "reads-anywhere", class: "READ_CONFIG", source: "reclassify", forward: true})
		}
	}
	// A batch with one bad element fails as a whole.
	v := g.Decide(context.Background(), call(eos, "run_commands", map[string]any{"hostname": "lab-sw-01", "commands": []any{"show version", "show clock\nreload"}}))
	check(t, "run_commands batch", v, want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY"})
}

// TestAttackerHostNames: the names of the PR #154 review and ADR 0031, with
// the patterns that used to make them known active. Each is refused as a bad
// argument (not a hostname) or as an unknown target; none reaches a rule.
func TestAttackerHostNames(t *testing.T) {
	cases := map[string]string{
		"core-x.attacker.example":      "default:unknown_target",
		"core-rtr-01.attacker.example": "default:unknown_target",
		"fw-evil.example":              "default:unknown_target",
		"lab-ghost-99":                 "default:unknown_target",
		"lab-leaf-01.evil":             "default:unknown_target",
		"LAB-core-rtr-01":              "default:unknown_target",
		"CORE-rtr-01":                  "default:unknown_target",
		"Core-Rtr-01":                  "default:unknown_target",
		"CORE-RTR-01":                  "default:unknown_target",
		"LAB-SW-01":                    "default:unknown_target",
		"ghost-99":                     "default:unknown_target",
		"lab-x@core-rtr-01":            policy.RuleBadArguments,
		"admin@core-rtr-01":            policy.RuleBadArguments,
		" core-rtr-01":                 policy.RuleBadArguments,
		"core-rtr-01 ":                 policy.RuleBadArguments,
		"core-rtr-01\n":                "default:bad_arguments",
		"core-rtr-01\x00":              policy.RuleBadArguments,
		"core-rtr-01\u200b":            policy.RuleBadArguments,
		"сore-rtr-01":                  policy.RuleBadArguments, // Cyrillic es
		"-oProxyCommand=sh":            policy.RuleBadArguments,
		"core-rtr-01,lab-sw-01":        policy.RuleBadArguments,
		"core-rtr-01:22":               policy.RuleBadArguments,
		"[::1]":                        policy.RuleBadArguments,
		"fe80::1%eth0":                 policy.RuleBadArguments,
		"127.1":                        policy.RuleBadArguments,
		"2130706433":                   policy.RuleBadArguments,
		"0x7f.0.0.1":                   policy.RuleBadArguments,
		"010.0.0.1":                    policy.RuleBadArguments,
		"@core":                        policy.RuleBadArguments,
		"core-rtr-01/32":               policy.RuleBadArguments,
		"":                             policy.RuleBadArguments,
		"10.0.0.1":                     "default:unknown_target",
		"2001:db8::1":                  "default:unknown_target",
	}
	type tool struct{ pol, server, tool, target, class string }
	tools := []tool{
		{"read-only", netdev, "get_config", "host", "READ_CONFIG"},
		{"lab-open", eos, "get_config", "hostname", "READ_CONFIG"},
		{"lab-open", eos, "push_config", "hostname", "WRITE_CONFIG"},
		{"lab-open", upa, "set_config_commands_and_commit_or_save", "name", "WRITE_CONFIG"},
	}
	for _, tl := range tools {
		g := newGate(t, examplePolicy(t, tl.pol), true)
		for name, rule := range cases {
			args := map[string]any{tl.target: name}
			switch tl.tool {
			case "push_config":
				args["config_lines"] = []any{"hostname x"}
			case "set_config_commands_and_commit_or_save":
				args["commands"] = []any{"hostname x"}
			}
			v := g.Decide(context.Background(), call(tl.server, tl.tool, args))
			label := tl.pol + " " + tl.server + "." + tl.tool + " " + strings.ToValidUTF8(name, "?")
			check(t, label, v, want{effect: "deny", rule: rule, class: tl.class})
			if name != "" && strings.Contains(v.Error, strings.TrimSpace(name)) {
				t.Errorf("%s: the target is echoed: %q", label, v.Error)
			}
		}
		// The listed names are known, exactly as listed.
		v := g.Decide(context.Background(), call(tl.server, tl.tool, map[string]any{tl.target: "lab-sw-01", "config_lines": []any{"hostname x"}, "commands": []any{"hostname x"}}))
		if v.RuleID == "default:unknown_target" || v.RuleID == policy.RuleBadArguments {
			t.Errorf("%s %s.%s lab-sw-01: %s %s", tl.pol, tl.server, tl.tool, v.RuleID, v.Error)
		}
	}
}

// TestZeroTargets: a tool that declares a target source and is not
// INVENTORY_READ or LOCAL_ADMIN must name a target. eos-mcp's batch tools
// run on the upstream's whole fleet when hostnames is empty, and expand tags
// themselves.
func TestZeroTargets(t *testing.T) {
	g := newGate(t, examplePolicy(t, "lab-open"), false)
	noTarget := func(server, tool, class string) string {
		return "fathomgate denied " + server + "." + tool + ": rule default:bad_arguments (class " + class + "): " + reasonNoTarget
	}
	group := func(server, tool, class string) string {
		return "fathomgate denied " + server + "." + tool + ": rule default:bad_arguments (class " + class + "): " + reasonGroup
	}
	cases := []struct {
		name, server, tool string
		args               map[string]any
		w                  want
	}{
		{"daily_brief no args", eos, "daily_brief", map[string]any{},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL", text: noTarget(eos, "daily_brief", "READ_OPERATIONAL")}},
		{"daily_brief null hostnames", eos, "daily_brief", map[string]any{"hostnames": nil},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		{"daily_brief empty hostnames", eos, "daily_brief", map[string]any{"hostnames": []any{}},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		{"daily_brief empty string", eos, "daily_brief", map[string]any{"hostnames": ""},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		{"daily_brief tags only", eos, "daily_brief", map[string]any{"tags": []any{"core"}},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL", text: group(eos, "daily_brief", "READ_OPERATIONAL")}},
		{"daily_brief tags string", eos, "daily_brief", map[string]any{"tags": "core"},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL", text: group(eos, "daily_brief", "READ_OPERATIONAL")}},
		{"daily_brief hosts and tags", eos, "daily_brief", map[string]any{"hostnames": []any{"lab-sw-01"}, "tags": []any{"core"}},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL", text: group(eos, "daily_brief", "READ_OPERATIONAL")}},
		{"daily_brief empty tags", eos, "daily_brief", map[string]any{"hostnames": []any{"lab-sw-01"}, "tags": []any{}},
			want{effect: "allow", rule: "reads-anywhere", class: "READ_OPERATIONAL", forward: true}},
		{"daily_brief two hosts", eos, "daily_brief", map[string]any{"hostnames": []any{"lab-sw-01", "lab-sw-02"}},
			want{effect: "allow", rule: "reads-anywhere", class: "READ_OPERATIONAL", forward: true}},
		{"daily_brief csv", eos, "daily_brief", map[string]any{"hostnames": "lab-sw-01,lab-sw-02"},
			want{effect: "allow", rule: "reads-anywhere", class: "READ_OPERATIONAL", forward: true}},
		{"daily_brief csv with space", eos, "daily_brief", map[string]any{"hostnames": "lab-sw-01, lab-sw-02"},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL", text: "fathomgate denied eos-mcp.daily_brief: rule default:bad_arguments (class READ_OPERATIONAL): " + reasonBadTarget}},
		{"daily_brief csv trailing comma", eos, "daily_brief", map[string]any{"hostnames": "lab-sw-01,"},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		{"run_command_batch no hosts", eos, "run_command_batch", map[string]any{"command": "show version"},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		{"run_commands_batch tags", eos, "run_commands_batch", map[string]any{"tags": []any{"lab"}, "commands": []any{"show version"}},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		{"get_device_facts_batch no hosts", eos, "get_device_facts_batch", map[string]any{},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		{"netdev no host", netdev, "run_show_command", map[string]any{"command": "show version"},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL", text: noTarget(netdev, "run_show_command", "READ_OPERATIONAL")}},
		{"upa no name", upa, "send_command_and_get_output", map[string]any{"command": "reload"},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "EXEC_ARBITRARY"}},
		{"push_config no host", eos, "push_config", map[string]any{"config_lines": []any{"hostname x"}},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "WRITE_CONFIG"}},
		{"host not a string", netdev, "get_config", map[string]any{"host": 7},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_CONFIG", text: "fathomgate denied netdev-ssh-mcp.get_config: rule default:bad_arguments (class READ_CONFIG): " + reasonBadTarget}},
		{"host an array", netdev, "get_config", map[string]any{"host": []any{"lab-sw-01"}},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_CONFIG"}},
		{"hostnames an object", eos, "daily_brief", map[string]any{"hostnames": map[string]any{"a": "lab-sw-01"}},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		{"hostnames holds a number", eos, "daily_brief", map[string]any{"hostnames": []any{"lab-sw-01", 7}},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		// FastMCP json.loads a string sent for a list parameter: "null" is
		// None (the whole fleet) and a JSON array string is a list, while
		// fathomgate would see one target (security review of PR #161).
		{"hostnames the string null", eos, "daily_brief", map[string]any{"hostnames": "null"},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL", text: "fathomgate denied eos-mcp.daily_brief: rule default:bad_arguments (class READ_OPERATIONAL): " + reasonBadTarget}},
		{"hostnames a JSON array string", eos, "daily_brief", map[string]any{"hostnames": `["core-rtr-01"]`},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		{"hostnames a JSON empty array string", eos, "daily_brief", map[string]any{"hostnames": "[]"},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		{"hostnames holds null as text", eos, "daily_brief", map[string]any{"hostnames": []any{"null"}},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		{"hostnames a JSON number string", eos, "run_command_batch", map[string]any{"hostnames": "1e5", "command": "show version"},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		{"hostname the string null", eos, "get_version", map[string]any{"hostname": "null"},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL"}},
		{"host the string true", netdev, "get_config", map[string]any{"host": "true"},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_CONFIG"}},
		// Exempt classes: INVENTORY_READ may select by tag, LOCAL_ADMIN and
		// INVENTORY_READ tools with no target source need none.
		{"get_router_list tags", eos, "get_router_list", map[string]any{"tags": []any{"lab"}},
			want{effect: "allow", rule: "reads-anywhere", class: "INVENTORY_READ", forward: true}},
		{"get_router_list no args", eos, "get_router_list", map[string]any{},
			want{effect: "allow", rule: "reads-anywhere", class: "INVENTORY_READ", forward: true}},
		{"upa device list", upa, "get_network_device_list", map[string]any{},
			want{effect: "allow", rule: "reads-anywhere", class: "INVENTORY_READ", forward: true}},
		{"health_check", eos, "health_check", map[string]any{},
			want{effect: "deny", rule: "not-lab", class: "LOCAL_ADMIN"}},
		{"trust_host_key no host", netdev, "trust_host_key", map[string]any{},
			want{effect: "deny", rule: "not-lab", class: "LOCAL_ADMIN"}},
		{"trust_host_key bad host", netdev, "trust_host_key", map[string]any{"host": "lab-x@core-rtr-01"},
			want{effect: "deny", rule: policy.RuleBadArguments, class: "LOCAL_ADMIN"}},
	}
	for _, tc := range cases {
		v := g.Decide(context.Background(), call(tc.server, tc.tool, tc.args))
		check(t, tc.name, v, tc.w)
		if v.RuleID == policy.RuleBadArguments && len(v.Targets) != 0 {
			t.Errorf("%s: a refused call reports targets %q to count", tc.name, v.Targets)
		}
	}
}

// TestObligationsFailClosed: an allow carrying dry_run, diff or
// timed_rollback is not forwarded in M1 (ADR 0026 decision 1); the other
// obligations are carried and the call is forwarded.
func TestObligationsFailClosed(t *testing.T) {
	cases := []struct {
		obligations string
		forward     bool
		text        string
	}{
		{"[dry_run, diff]", false, "fathomgate cannot run eos-mcp.push_config: rule lab-writes (class WRITE_CONFIG): obligation dry_run cannot be met until change-safety drivers exist"},
		{"[diff]", false, "fathomgate cannot run eos-mcp.push_config: rule lab-writes (class WRITE_CONFIG): obligation diff cannot be met until change-safety drivers exist"},
		{"[notify, timed_rollback]", false, "fathomgate cannot run eos-mcp.push_config: rule lab-writes (class WRITE_CONFIG): obligation timed_rollback cannot be met until change-safety drivers exist"},
		{"[redact, notify, require_ticket, canary_first]", true, ""},
		{"[]", true, ""},
	}
	for _, tc := range cases {
		pol, err := policy.Parse([]byte("version: 1\ndefaults: {unknown_target: deny}\nrules:\n" +
			"  - id: lab-writes\n    match: {class: [WRITE_CONFIG], device_tags: [lab]}\n    effect: allow\n    obligations: " + tc.obligations + "\n"))
		if err != nil {
			t.Fatal(err)
		}
		g := newGate(t, pol, false)
		v := g.Decide(context.Background(), call(eos, "push_config", map[string]any{"hostname": "lab-sw-01", "config_lines": []any{"hostname x"}}))
		check(t, tc.obligations, v, want{effect: "allow", rule: "lab-writes", class: "WRITE_CONFIG", forward: tc.forward, text: tc.text})
	}
}

// TestHoldIsNotForwarded: prod-approval's hold rule gives the maintainer's
// fixed text, and the recorded effect stays hold.
func TestHoldIsNotForwarded(t *testing.T) {
	g := newGate(t, examplePolicy(t, "prod-approval"), false)
	for _, tc := range []struct{ server, tool, target, payload string }{
		{eos, "push_config", "hostname", "config_lines"},
		{upa, "set_config_commands_and_commit_or_save", "name", "commands"},
	} {
		v := g.Decide(context.Background(), call(tc.server, tc.tool, map[string]any{tc.target: "core-rtr-01", tc.payload: []any{"hostname x"}}))
		check(t, tc.tool, v, want{effect: "hold", rule: "prod-core-needs-approval", class: "WRITE_CONFIG",
			text: "fathomgate held " + tc.server + "." + tc.tool + ": rule prod-core-needs-approval (class WRITE_CONFIG): needs approval, and approvals aren't available yet, so this call was not run."})
	}
	// The pending cap turns the hold into a deny with fixed text.
	in := call(eos, "push_config", map[string]any{"hostname": "core-rtr-01", "config_lines": []any{"hostname x"}})
	in.PendingHolds = 2
	v := g.Decide(context.Background(), in)
	check(t, "max_pending", v, want{effect: "deny", rule: "default:session.max_pending", class: "WRITE_CONFIG",
		text: "fathomgate denied eos-mcp.push_config: rule default:session.max_pending (class WRITE_CONFIG): " + reasonMaxPending})
	// The device cap counts the counters the proxy passes in.
	in = call(eos, "get_version", map[string]any{"hostname": "core-rtr-01"})
	in.DevicesTouched = 5
	v = g.Decide(context.Background(), in)
	check(t, "max_devices", v, want{effect: "deny", rule: "default:session.max_devices", class: "READ_OPERATIONAL",
		text: "fathomgate denied eos-mcp.get_version: rule default:session.max_devices (class READ_OPERATIONAL): " + reasonMaxDevices})
}

// TestDenyTextShape: every refusal has the one first-line shape, and one
// parser reads the verb and the rule id from each.
func TestDenyTextShape(t *testing.T) {
	golden := map[string]struct{ verb, rule string }{
		"fathomgate denied netdev-ssh-mcp.run_show_command: rule no-exec (class EXEC_ARBITRARY): command did not pass the read allow-list":                                                {"denied", "no-exec"},
		"fathomgate cannot run eos-mcp.push_config: rule lab-writes (class WRITE_CONFIG): obligation dry_run cannot be met until change-safety drivers exist":                             {"cannot run", "lab-writes"},
		"fathomgate held junos.load_and_commit_config: rule prod-core-needs-approval (class WRITE_CONFIG): needs approval, and approvals aren't available yet, so this call was not run.": {"held", "prod-core-needs-approval"},
		"fathomgate denied eos-mcp.daily_brief: rule default:bad_arguments (class READ_OPERATIONAL): this tool needs at least one target named explicitly":                                {"denied", "default:bad_arguments"},
		"fathomgate denied eos-mcp.get_version: rule default:unknown_target (class READ_OPERATIONAL): target not in inventory":                                                            {"denied", "default:unknown_target"},
		"fathomgate denied netdev-ssh-mcp.get_config: rule not-lab (class READ_CONFIG): only devices tagged lab may be changed through this proxy; target not in inventory":               {"denied", "not-lab"},
	}
	for text, w := range golden {
		verb, rule, ok := parseErrorText(text)
		if !ok || verb != w.verb || rule != w.rule {
			t.Errorf("%q: parsed %q %q %v", text, verb, rule, ok)
		}
	}
	// The same text from errorText, for the fixed rows.
	dec := policy.Decision{Effect: policy.Deny, RuleID: "no-exec", Reason: "command did not pass the read allow-list"}
	if got := errorText(netdev, "run_show_command", dec, "EXEC_ARBITRARY", "", false); got != "fathomgate denied netdev-ssh-mcp.run_show_command: rule no-exec (class EXEC_ARBITRARY): command did not pass the read allow-list" {
		t.Errorf("ADR 0026 example: %q", got)
	}
	dec = policy.Decision{Effect: policy.Hold, RuleID: "prod-core-needs-approval"}
	if got := errorText("junos", "load_and_commit_config", dec, "WRITE_CONFIG", "", false); got != "fathomgate held junos.load_and_commit_config: rule prod-core-needs-approval (class WRITE_CONFIG): needs approval, and approvals aren't available yet, so this call was not run." {
		t.Errorf("ADR 0026 hold example: %q", got)
	}
	// Under unknown_target: allow, a rule denies and the text adds the
	// unknown target without naming it.
	dec = policy.Decision{Effect: policy.Deny, RuleID: "not-lab", Reason: "only devices tagged lab may be changed through this proxy"}
	if got := errorText(netdev, "get_config", dec, "READ_CONFIG", "", true); !strings.HasSuffix(got, "; target not in inventory") {
		t.Errorf("unknown suffix: %q", got)
	}
	// Operator text with a line break stays on one line; an empty reason
	// gets fathomgate's text.
	dec = policy.Decision{Effect: policy.Deny, RuleID: "multi\nline", Reason: "first\nsecond\u2028third"}
	if got := errorText(netdev, "get_config", dec, "READ_CONFIG", "", false); got != "fathomgate denied netdev-ssh-mcp.get_config: rule multi line (class READ_CONFIG): first second third" {
		t.Errorf("one line: %q", got)
	}
	dec = policy.Decision{Effect: policy.Deny, RuleID: "quiet"}
	if got := errorText(netdev, "get_config", dec, "READ_CONFIG", "", false); !strings.HasSuffix(got, ": "+reasonNoReason) {
		t.Errorf("empty reason: %q", got)
	}
	// Evaluate's reasons for the defaults name targets and counts; the
	// gate's text does not.
	dec = policy.Decision{Effect: policy.Deny, RuleID: policy.RuleUnknownTarget, Reason: "unknown targets: evil.example; a device absent from inventory is not a device the agent may touch"}
	if got := errorText(netdev, "get_config", dec, "READ_CONFIG", "", true); strings.Contains(got, "evil") {
		t.Errorf("unknown target named: %q", got)
	}
	// A name the proxy should have refused is not echoed.
	if got := errorText("srv\n", "to ol\x1b", dec, "READ_CONFIG", "", true); strings.ContainsAny(got, "\n\x1b ") && !strings.HasPrefix(got, "fathomgate denied srv_.to_ol_:") {
		t.Errorf("bad name: %q", got)
	}
}

// parseErrorText is the one parser ADR 0026 promises: the verb and the rule
// id from the first line of any refusal.
func parseErrorText(s string) (verb, rule string, ok bool) {
	rest, ok := strings.CutPrefix(s, "fathomgate ")
	if !ok {
		return "", "", false
	}
	for _, v := range []string{"denied ", "cannot run ", "held "} {
		if r, found := strings.CutPrefix(rest, v); found {
			verb, rest = strings.TrimSpace(v), r
			break
		}
	}
	if verb == "" {
		return "", "", false
	}
	_, rest, ok = strings.Cut(rest, ": rule ")
	if !ok {
		return "", "", false
	}
	rule, _, ok = strings.Cut(rest, " (class ")
	return verb, rule, ok
}

// TestParse: step 1 refuses anything but one JSON object, before any other
// stage sees it.
func TestParse(t *testing.T) {
	g := newGate(t, examplePolicy(t, "read-only"), false)
	for name, raw := range map[string]string{
		"not json":      `{"host":`,
		"array":         `["lab-sw-01"]`,
		"string":        `"lab-sw-01"`,
		"number":        `7`,
		"duplicate key": `{"host":"lab-sw-01","host":"core-x.attacker.example"}`,
		"escaped dup":   `{"host":"lab-sw-01","host":"core-x.attacker.example"}`,
		"invalid utf-8": "{\"host\":\"lab-sw-01\xff\"}",
		"trailing data": `{"host":"lab-sw-01"} {"host":"x"}`,
	} {
		in := call(netdev, "get_config", nil)
		in.Arguments = json.RawMessage(raw)
		v := g.Decide(context.Background(), in)
		check(t, name, v, want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_CONFIG",
			text: "fathomgate denied netdev-ssh-mcp.get_config: rule default:bad_arguments (class READ_CONFIG): " + reasonNotObject})
	}
	// Absent and null arguments are an empty object: the tool then has no
	// target and is refused for that.
	for _, raw := range []string{"", "null", " {} "} {
		in := call(netdev, "get_config", nil)
		in.Arguments = json.RawMessage(raw)
		v := g.Decide(context.Background(), in)
		check(t, "empty "+raw, v, want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_CONFIG",
			text: "fathomgate denied netdev-ssh-mcp.get_config: rule default:bad_arguments (class READ_CONFIG): " + reasonNoTarget})
	}
}

// TestAnnotationsOnlyRaise: readOnlyHint false or destructiveHint true
// raise a read tool; nothing lowers a class (invariant 3).
func TestAnnotationsOnlyRaise(t *testing.T) {
	g := newGate(t, examplePolicy(t, "read-only"), false)
	yes, no := true, false
	cases := []struct {
		name               string
		server, tool       string
		args               map[string]any
		readOnly, destruct *bool
		w                  want
	}{
		{"readOnlyHint false on a typed read", eos, "get_version", map[string]any{"hostname": "lab-sw-01"}, &no, nil,
			want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY", source: "annotation_raise"}},
		{"destructiveHint true on a config read", netdev, "get_config", map[string]any{"host": "lab-sw-01"}, nil, &yes,
			want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY", source: "annotation_raise"}},
		{"readOnlyHint false on an inventory read", eos, "get_router_list", map[string]any{}, &no, nil,
			want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY", source: "annotation_raise"}},
		{"raised tool with a passing command is downgraded", netdev, "run_show_command", map[string]any{"host": "lab-sw-01", "command": "show ip bgp summary"}, &no, nil,
			want{effect: "allow", rule: "reads-anywhere", class: "READ_OPERATIONAL", source: "downgrade", forward: true}},
		{"raised tool with a failing command", netdev, "run_show_command", map[string]any{"host": "lab-sw-01", "command": "reload"}, &no, nil,
			want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY", source: "annotation_raise"}},
		{"readOnlyHint true does not lower", eos, "run_command", map[string]any{"hostname": "lab-sw-01", "command": "reload"}, &yes, &no,
			want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY", source: "profile"}},
		{"readOnlyHint true on a write", eos, "push_config", map[string]any{"hostname": "lab-sw-01", "config_lines": []any{"hostname x"}}, &yes, &no,
			want{effect: "deny", rule: "no-writes", class: "WRITE_CONFIG", source: "profile"}},
		{"readOnlyHint true on a read", eos, "get_version", map[string]any{"hostname": "lab-sw-01"}, &yes, nil,
			want{effect: "allow", rule: "reads-anywhere", class: "READ_OPERATIONAL", source: "profile", forward: true}},
	}
	for _, tc := range cases {
		in := call(tc.server, tc.tool, tc.args)
		in.ReadOnlyHint, in.DestructiveHint = tc.readOnly, tc.destruct
		check(t, tc.name, g.Decide(context.Background(), in), tc.w)
	}
}

// TestNoProfile: a server with no profile gets the fallback classifier:
// every tool is EXEC_ARBITRARY, and no argument is inspected.
func TestNoProfile(t *testing.T) {
	g := newGate(t, examplePolicy(t, "read-only"), false)
	v := g.Decide(context.Background(), call("mystery", "get_thing", map[string]any{"host": "lab-x@core-rtr-01"}))
	check(t, "no profile", v, want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY", source: "fallback"})
	v = g.Decide(context.Background(), call(eos, "not_a_tool", map[string]any{}))
	check(t, "tool not in profile", v, want{effect: "deny", rule: "no-exec", class: "EXEC_ARBITRARY", source: "fallback"})
	// A nil policy denies.
	g2, err := New(Config{Profiles: repoProfiles(t)})
	if err != nil {
		t.Fatal(err)
	}
	v = g2.Decide(context.Background(), call(eos, "get_version", map[string]any{"hostname": "lab-sw-01"}))
	check(t, "nil policy", v, want{effect: "deny", rule: "default:no-match", class: "READ_OPERATIONAL",
		text: "fathomgate denied eos-mcp.get_version: rule default:no-match (class READ_OPERATIONAL): no policy loaded; target not in inventory"})
}

// TestClosedArgumentListHook: with the closed argument list (M1-35, PR
// #161), an argument the profile does not name is default:bad_arguments,
// never stripped and never named. It skips until classify.Result has
// ArgumentsOK, and must pass from the moment it does.
func TestClosedArgumentListHook(t *testing.T) {
	if _, ok := reflect.TypeOf(classify.Result{}).MethodByName("ArgumentsOK"); !ok {
		t.Skip("classify.Result has no ArgumentsOK yet (M1-35, PR #161)")
	}
	g := newGate(t, examplePolicy(t, "read-only"), false)
	for _, args := range []map[string]any{
		{"hostname": "lab-sw-01", "config_path": "/proc/self/environ"},
		{"hostname": "lab-sw-01", "config_path": ""},
		{"hostname": "lab-sw-01", "config_path": nil},
		{"hostname": "lab-sw-01", "Hostname": "core-rtr-01"},
	} {
		v := g.Decide(context.Background(), call(eos, "get_version", args))
		check(t, "unnamed", v, want{effect: "deny", rule: policy.RuleBadArguments, class: "READ_OPERATIONAL",
			text: "fathomgate denied eos-mcp.get_version: rule default:bad_arguments (class READ_OPERATIONAL): " + reasonUnnamed})
	}
	// MalformedArgs: a command or payload that is not a string or a list of
	// strings is refused the same way, before the classifier formats it.
	for _, tc := range []struct {
		tool, class string
		args        map[string]any
	}{
		{"run_command", "EXEC_ARBITRARY", map[string]any{"hostname": "lab-sw-01", "command": 7}},
		{"run_commands", "EXEC_ARBITRARY", map[string]any{"hostname": "lab-sw-01", "commands": []any{"show version", map[string]any{"cmd": "reload"}}}},
		{"push_config", "WRITE_CONFIG", map[string]any{"hostname": "lab-sw-01", "config_lines": []any{1}}},
	} {
		v := g.Decide(context.Background(), call(eos, tc.tool, tc.args))
		check(t, "malformed "+tc.tool, v, want{effect: "deny", rule: policy.RuleBadArguments, class: tc.class,
			text: "fathomgate denied eos-mcp." + tc.tool + ": rule default:bad_arguments (class " + tc.class + "): " + reasonUnnamed})
	}
}

// TestUnnamedArgumentsHookInert: until classify.Result has ArgumentsOK the
// hook refuses nothing, so today's behaviour is unchanged.
func TestUnnamedArgumentsHookInert(t *testing.T) {
	if _, ok := reflect.TypeOf(classify.Result{}).MethodByName("ArgumentsOK"); ok {
		t.Skip("classify.Result has ArgumentsOK; TestClosedArgumentListHook covers it")
	}
	if unnamedArguments(classify.Result{}) {
		t.Error("hook refused a call with no signal")
	}
}

// TestRecord: the decision line carries the ADR 0026 fields, protocol and
// era separately, and no argument value, command, payload or rejected name.
func TestRecord(t *testing.T) {
	g := newGate(t, examplePolicy(t, "prod-approval"), false)
	secret := "FAKE-secret-value"
	for _, in := range []CallInfo{
		call(eos, "run_command", map[string]any{"hostname": "core-rtr-01", "command": "show ip bgp summary " + secret}),
		call(eos, "push_config", map[string]any{"hostname": "core-rtr-01", "config_lines": []any{"username admin secret " + secret}}),
		call(eos, "get_version", map[string]any{"hostname": "evil-" + secret + "@core-rtr-01"}),
		call(eos, "get_version", map[string]any{"hostname": "ghost-" + secret}),
	} {
		v := g.Decide(context.Background(), in)
		var buf bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		logger.LogAttrs(context.Background(), slog.LevelInfo, "decision", v.Record...)
		line := buf.String()
		for _, key := range []string{"server", "tool", "class", "class_source", "targets", "roles", "unknown_target", "effect",
			"rule_id", "obligations", "forwarded", "agent_protocol", "agent_era", "upstream_protocol", "upstream_era", "transport", "principal", "session"} {
			if !strings.Contains(line, `"`+key+`":`) {
				t.Errorf("record lacks %s: %s", key, line)
			}
		}
		if strings.Contains(line, "show ip bgp") || strings.Contains(line, "username") || strings.Contains(line, "@core") {
			t.Errorf("record carries argument text: %s", line)
		}
		// A validated but unknown name is recorded (it is the target);
		// a refused one is not.
		if v.RuleID == policy.RuleBadArguments && strings.Contains(line, secret) {
			t.Errorf("record carries a refused name: %s", line)
		}
		if !strings.Contains(line, `"agent_era":"stateful"`) || !strings.Contains(line, `"agent_protocol":"2025-11-25"`) {
			t.Errorf("record protocol and era: %s", line)
		}
		if v.Trace.Key != "trace" {
			t.Errorf("trace attr %q", v.Trace.Key)
		}
	}
}

// TestConcurrentDecide: a Gate is shared by every session (run with -race).
func TestConcurrentDecide(t *testing.T) {
	g := newGate(t, examplePolicy(t, "prod-approval"), false)
	corpus := benchCorpus()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, in := range corpus {
				_ = g.Decide(context.Background(), in)
			}
		}()
	}
	wg.Wait()
}

func TestNewRejectsMisfiledProfile(t *testing.T) {
	ps := repoProfiles(t)
	if _, err := New(Config{Profiles: map[string]*classify.Profile{"other": ps[eos]}}); err == nil {
		t.Error("profile under another server name accepted")
	}
	if _, err := New(Config{Profiles: map[string]*classify.Profile{eos: nil}}); err == nil {
		t.Error("nil profile accepted")
	}
}
