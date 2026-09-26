// SPDX-License-Identifier: FSL-1.1-ALv2

package policytest

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fathomgate/fathomgate/internal/configset"
	"github.com/fathomgate/fathomgate/internal/termsafe"
)

// repoPolicy is an absolute path to a shipped example policy, written with
// forward slashes so it can sit unquoted in a test file on every OS.
func repoPolicy(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "policies", "examples", name+".yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(p)
}

// writeTest writes a test file into dir and returns its path.
func writeTest(t *testing.T, dir, body string) string {
	t.Helper()
	p := filepath.Join(dir, "case.test.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func embedded(t *testing.T) *Runner {
	t.Helper()
	r, err := NewRunner("")
	if err != nil {
		t.Fatal(err)
	}
	if r.Source() != "embedded" {
		t.Fatalf("source %q", r.Source())
	}
	return r
}

// inlineInventory lists lab-sw-01 (lab) and core-rtr-01 (core), with a lab
// pattern that must never make an unlisted name known.
const inlineInventory = `inventory:
  devices:
    - {name: lab-sw-01, role: access, tags: [lab]}
    - {name: core-rtr-01, role: core}
  roles:
    - match: "^lab-"
      tags: [lab]
`

// TestClassGivenCases is the class-given runner as it was before ADR 0035:
// effect, rule and obligations, first mismatch reported.
func TestClassGivenCases(t *testing.T) {
	body := "policy: " + repoPolicy(t, "prod-approval") + `
cases:
  - name: core write held
    request:
      class: WRITE_CONFIG
      targets: [{name: core-rtr-01, role: core}]
    expect: {effect: hold, rule: prod-core-needs-approval, obligations: [dry_run, diff, timed_rollback]}
  - name: unknown denied
    request:
      class: READ_OPERATIONAL
      targets: [{name: ghost, known: false}]
    expect: {effect: deny, rule: default:unknown_target}
  - name: deliberately wrong effect
    request:
      class: EXEC_ARBITRARY
    expect: {effect: allow}
  - name: wrong rule
    request:
      class: READ_CONFIG
    expect: {effect: allow, rule: lab-writes-free}
  - name: wrong obligations
    request:
      class: WRITE_CONFIG
      targets: [{name: core-rtr-01, role: core}]
    expect: {effect: hold, obligations: [dry_run]}
`
	results, err := embedded(t).RunFile(writeTest(t, t.TempDir(), body))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"", "", "effect deny (rule no-exec), want allow", "rule reads-anywhere, want lab-writes-free", `obligations ["diff" "dry_run" "timed_rollback"], want ["dry_run"]`}
	if len(results) != len(want) {
		t.Fatalf("%d results", len(results))
	}
	for i, r := range results {
		if r.Gate {
			t.Errorf("%s: ran as a gate case", r.Name)
		}
		if r.Message != want[i] || r.Pass != (want[i] == "") {
			t.Errorf("%s: pass %v message %q, want %q", r.Name, r.Pass, r.Message, want[i])
		}
	}
}

// TestGateAssertions: every gate expect field is checked, in ADR 0035's
// order, and a wrong value fails the case naming the field. The first case
// sets every field correctly.
func TestGateAssertions(t *testing.T) {
	call := `
    request:
      server: upa
      tool: send_command_and_get_output
      arguments: {name: lab-sw-01, command: reload}
`
	cases := []struct {
		expect string
		want   string
	}{
		{`{effect: deny, rule: no-exec, class: EXEC_ARBITRARY, class_source: profile, obligations: [], targets: [lab-sw-01], unknown_target: false, forwarded: false, tool_error: "fathomgate denied upa.send_command_and_get_output: rule no-exec (class EXEC_ARBITRARY): EXEC_ARBITRARY is denied: the call runs commands outside the read allow-list or outside configuration mode"}`, ""},
		{`{effect: allow, rule: no-exec}`, "effect deny (rule no-exec), want allow"},
		{`{effect: deny, rule: no-writes}`, "rule no-exec, want no-writes"},
		{`{effect: deny, rule: no-exec, class: READ_OPERATIONAL}`, "class EXEC_ARBITRARY (class_source profile), want READ_OPERATIONAL"},
		{`{effect: deny, rule: no-exec, class_source: downgrade}`, "class_source profile, want downgrade"},
		{`{effect: deny, rule: no-exec, obligations: [redact]}`, `obligations [], want ["redact"]`},
		{`{effect: deny, rule: no-exec, targets: [core-rtr-01]}`, `targets ["lab-sw-01"], want ["core-rtr-01"]`},
		{`{effect: deny, rule: no-exec, unknown_target: true}`, "unknown_target false, want true"},
		{`{effect: deny, rule: no-exec, forwarded: true}`, "forwarded false, want true"},
		{`{effect: deny, rule: no-exec, tool_error: ""}`, `tool_error "fathomgate denied`},
	}
	var b strings.Builder
	b.WriteString("policy: " + repoPolicy(t, "read-only") + "\n" + inlineInventory + "cases:\n")
	for i, c := range cases {
		b.WriteString("  - name: case " + string(rune('a'+i)) + call + "    expect: " + c.expect + "\n")
	}
	results, err := embedded(t).RunFile(writeTest(t, t.TempDir(), b.String()))
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range results {
		if !r.Gate {
			t.Errorf("%s: not a gate case", r.Name)
		}
		if cases[i].want == "" {
			if !r.Pass {
				t.Errorf("%s: %s", r.Name, r.Message)
			}
			continue
		}
		if r.Pass || !strings.HasPrefix(r.Message, cases[i].want) {
			t.Errorf("%s: pass %v message %q, want prefix %q", r.Name, r.Pass, r.Message, cases[i].want)
		}
	}
}

// TestGateRefusalAssertions: parse_error, unnamed_args and malformed_args
// come from the decision log line, and fail when they differ.
func TestGateRefusalAssertions(t *testing.T) {
	body := "policy: " + repoPolicy(t, "read-only") + "\n" + inlineInventory + `cases:
  - name: duplicate key
    request:
      server: eos-mcp
      tool: get_version
      arguments_json: '{"hostname": "lab-sw-01", "hostname": "x"}'
    expect: {effect: deny, rule: default:bad_arguments, parse_error: duplicate_key}
  - name: wrong parse error
    request:
      server: eos-mcp
      tool: get_version
      arguments_json: '{"hostname": "lab-sw-01", "hostname": "x"}'
    expect: {effect: deny, rule: default:bad_arguments, parse_error: not_object}
  - name: unnamed
    request:
      server: eos-mcp
      tool: get_version
      arguments: {hostname: lab-sw-01, config_path: /etc/passwd}
    expect: {effect: deny, rule: default:bad_arguments, unnamed_args: [config_path], malformed_args: []}
  - name: wrong unnamed
    request:
      server: eos-mcp
      tool: get_version
      arguments: {hostname: lab-sw-01, config_path: /etc/passwd}
    expect: {effect: deny, rule: default:bad_arguments, unnamed_args: [username]}
  - name: malformed
    request:
      server: eos-mcp
      tool: get_version
      arguments: {hostname: 7}
    expect: {effect: deny, rule: default:bad_arguments, malformed_args: [hostname]}
  - name: no parse error where one is expected
    request:
      server: eos-mcp
      tool: get_version
      arguments: {hostname: 7}
    expect: {effect: deny, rule: default:bad_arguments, parse_error: invalid_json}
`
	results, err := embedded(t).RunFile(writeTest(t, t.TempDir(), body))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"duplicate key":                        "",
		"wrong parse error":                    "parse_error duplicate_key, want not_object",
		"unnamed":                              "",
		"wrong unnamed":                        `unnamed_args ["config_path"], want ["username"]`,
		"malformed":                            "",
		"no parse error where one is expected": "parse_error (none: the decision record has no parse_error field), want invalid_json",
	}
	for _, r := range results {
		if r.Message != want[r.Name] || r.Pass != (want[r.Name] == "") {
			t.Errorf("%s: pass %v message %q, want %q", r.Name, r.Pass, r.Message, want[r.Name])
		}
	}
}

// TestLoadErrors: every case ADR 0035 makes a load error, so a suite
// cannot pass on inputs the gate never sees or for the wrong reason.
func TestLoadErrors(t *testing.T) {
	head := "policy: " + repoPolicy(t, "read-only") + "\n"
	gateCase := func(request, expect string) string {
		return head + "cases:\n  - name: x\n    request: " + request + "\n    expect: " + expect + "\n"
	}
	ok := `{server: eos-mcp, tool: get_version, arguments: {hostname: lab-sw-01}}`
	big := strings.Repeat("a", MaxArgumentBytes)
	cases := []struct {
		name, body, want string
	}{
		{"class and arguments", gateCase(`{server: eos-mcp, tool: get_version, class: READ_OPERATIONAL, arguments: {hostname: x}}`, `{effect: deny, rule: x}`), "request.class with request.arguments"},
		{"targets on a gate case", gateCase(`{server: eos-mcp, tool: get_version, targets: [{name: x}], arguments: {hostname: x}}`, `{effect: deny, rule: x}`), "request.targets with request.arguments"},
		{"empty targets on a gate case", gateCase(`{server: eos-mcp, tool: get_version, targets: [], arguments: {hostname: x}}`, `{effect: deny, rule: x}`), "request.targets with request.arguments"},
		{"neither class nor arguments", gateCase(`{server: eos-mcp, tool: get_version}`, `{effect: deny}`), "give request.class"},
		{"both argument forms", gateCase(`{server: eos-mcp, tool: get_version, arguments: {}, arguments_json: "{}"}`, `{effect: deny, rule: x}`), "not both"},
		{"no server", gateCase(`{tool: get_version, arguments: {}}`, `{effect: deny, rule: x}`), "request.server"},
		{"no tool", gateCase(`{server: eos-mcp, arguments: {}}`, `{effect: deny, rule: x}`), "request.tool"},
		{"no rule", gateCase(ok, `{effect: deny}`), "needs expect.rule"},
		{"server with no profile", gateCase(`{server: no-such-server, tool: t, arguments: {}}`, `{effect: deny, rule: default:bad_arguments}`), "has no profile in the embedded profile set"},
		{"over 64 KiB", gateCase(`{server: eos-mcp, tool: get_version, arguments: {hostname: `+big+`}}`, `{effect: deny, rule: x}`), "the proxy refuses more than 65536"},
		{"over 64 KiB as JSON", gateCase(`{server: eos-mcp, tool: get_version, arguments_json: "`+big+`a"}`, `{effect: deny, rule: x}`), "the proxy refuses more than 65536"},
		{"parse_error with another rule", gateCase(ok, `{effect: deny, rule: no-exec, parse_error: duplicate_key}`), "come only with rule default:bad_arguments"},
		{"unnamed_args with another rule", gateCase(ok, `{effect: deny, rule: no-exec, unnamed_args: [x]}`), "come only with rule default:bad_arguments"},
		{"unknown parse_error code", gateCase(ok, `{effect: deny, rule: default:bad_arguments, parse_error: nonsense}`), "expect.parse_error must be one of"},
		{"unknown class_source", gateCase(ok, `{effect: deny, rule: x, class_source: magic}`), "not a class source"},
		{"gate field on a class-given case", gateCase(`{class: READ_CONFIG}`, `{effect: allow, tool_error: ""}`), "expect.tool_error: for a gate case only"},
		{"annotations on a class-given case", gateCase(`{class: READ_CONFIG, annotations: {readOnlyHint: true}}`, `{effect: allow}`), "request.annotations is for a gate case"},
		{"merge key in arguments", gateCase(`{server: eos-mcp, tool: get_version, arguments: {<<: {hostname: lab-sw-01}}}`, `{effect: allow, rule: x}`), "arguments: a merge key (<<) is not allowed"},
		{"anchor and merge", head + "base: &b {hostname: lab-sw-01}\ncases:\n  - name: x\n    request: {server: eos-mcp, tool: get_version, arguments: {<<: *b}}\n    expect: {effect: allow, rule: x}\n", "line 2: anchors (&) and aliases (*) are not allowed"},
		{"alias in arguments", head + "cases:\n  - name: x\n    request:\n      server: eos-mcp\n      tool: get_version\n      arguments: {hostname: &h lab-sw-01, other: *h}\n    expect: {effect: allow, rule: x}\n", "line 7: anchors (&) and aliases (*) are not allowed"},
		{"anchor on a case name", head + "cases:\n  - name: &n x\n    request: " + ok + "\n    expect: {effect: allow, rule: x}\n  - name: *n\n    request: " + ok + "\n    expect: {effect: allow, rule: x}\n", "anchors (&) and aliases (*) are not allowed"},
		{"tag in arguments", gateCase(`{server: eos-mcp, tool: get_version, arguments: {hostname: !!str lab-sw-01}}`, `{effect: allow, rule: x}`), "arguments: a YAML tag is not allowed"},
		{"number key in arguments", gateCase(`{server: eos-mcp, tool: get_version, arguments: {1: lab-sw-01}}`, `{effect: allow, rule: x}`), "arguments: every key must be a string; quote it"},
		{"null arguments", gateCase(`{server: eos-mcp, tool: get_version, arguments: null}`, `{effect: allow, rule: x}`), "give request.class"},
		{"scalar arguments", gateCase(`{server: eos-mcp, tool: get_version, arguments: lab-sw-01}`, `{effect: allow, rule: x}`), "arguments must be a mapping; use {} for a call with none, or arguments_json for other bytes"},
		{"CSV inventory", head + "inventory: devices.csv\ncases:\n  - name: x\n    request: " + ok + "\n    expect: {effect: allow, rule: x}\n", "takes an inventory.yaml"},
		{"missing inventory", head + "inventory: nope.yaml\ncases:\n  - name: x\n    request: " + ok + "\n    expect: {effect: allow, rule: x}\n", "inventory"},
		{"bad inline inventory", head + "inventory: {devices: [{name: a, colour: red}]}\ncases:\n  - name: x\n    request: " + ok + "\n    expect: {effect: allow, rule: x}\n", "inventory"},
		{"inventory is a list", head + "inventory: [a]\ncases:\n  - name: x\n    request: " + ok + "\n    expect: {effect: allow, rule: x}\n", "inventory: give a path or the inventory document as a mapping"},
		{"unknown key", head + "cases:\n  - name: x\n    request: {server: eos-mcp, tool: get_version, arguments: {}, class_hint: x}\n    expect: {effect: allow, rule: x}\n", `unknown field "class_hint"`},
		{"long case name", head + "cases:\n  - name: " + strings.Repeat("n", MaxCaseName+1) + "\n    request: " + ok + "\n    expect: {effect: allow, rule: x}\n", "the name is 257 bytes; at most 256"},
		{"no cases", head + "cases: []\n", "cases is empty"},
		{"no name", gateCase(ok, `{effect: allow, rule: x}`) + "  - request: " + ok + "\n    expect: {effect: allow, rule: x}\n", "has no name"},
	}
	r := embedded(t)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := r.RunFile(writeTest(t, t.TempDir(), c.body))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %v, want it to contain %q", err, c.want)
			}
			if strings.Contains(err.Error(), big) {
				t.Error("the error quotes the arguments")
			}
		})
	}
}

// TestArgumentsEncoding: a YAML mapping reaches the gate as the JSON object
// it shows, escapes included; arguments_json reaches it byte for byte.
func TestArgumentsEncoding(t *testing.T) {
	body := `policy: p.yaml
cases:
  - name: a
    request:
      server: s
      tool: t
      arguments: {command: "show clock\nconf t", n: 3, f: 1.5, b: true, z: null, l: [a, "\x41\t"], m: {k: v}}
    expect: {effect: deny, rule: x}
  - name: b
    request:
      server: s
      tool: t
      arguments_json: '{"a": 1, "a": 2}'
    expect: {effect: deny, rule: x}
  - name: c
    request:
      server: s
      tool: t
      arguments: {}
    expect: {effect: deny, rule: x}
`
	f, err := Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`{"b":true,"command":"show clock\nconf t","f":1.5,"l":["a","A\t"],"m":{"k":"v"},"n":3,"z":null}`,
		`{"a": 1, "a": 2}`,
		`{}`,
	}
	for i, c := range f.Cases {
		if got := string(c.ArgumentBytes()); got != want[i] {
			t.Errorf("case %s: %s, want %s", c.Name, got, want[i])
		}
	}
}

// TestNoArgumentValueInOutput: no message or load error carries an argument
// value, and names that are not printable ASCII are quoted.
func TestNoArgumentValueInOutput(t *testing.T) {
	const canary = "FAKE-canary-7f3a"
	body := "policy: " + repoPolicy(t, "read-only") + "\n" + inlineInventory + `cases:
  - name: "evil\u001b[31m name"
    request:
      server: eos-mcp
      tool: get_version
      arguments: {hostname: lab-sw-01, "config_path\u001b]0;x": "` + canary + `"}
    expect: {effect: deny, rule: default:bad_arguments, unnamed_args: ["other\u001b[2J"]}
  - name: command value
    request:
      server: upa
      tool: send_command_and_get_output
      arguments: {name: lab-sw-01, command: "show clock ` + canary + `"}
    expect: {effect: deny, rule: no-exec}
`
	results, err := embedded(t).RunFile(writeTest(t, t.TempDir(), body))
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range results {
		if r.Pass {
			t.Errorf("%q passed", r.Name)
		}
		if strings.Contains(r.Message, canary) || strings.ContainsRune(r.Message, 0x1b) {
			t.Errorf("message %q", r.Message)
		}
		for _, e := range r.Trace {
			if strings.Contains(e.Note, canary) {
				t.Errorf("trace note %q", e.Note)
			}
		}
	}
	if got := termsafe.Quote(results[0].Name); got != "\"evil\\x1b[31m name\"" {
		t.Errorf("quoted name %s", got)
	}

	// The policy and inventory paths come from the test file too, and reach
	// the error that policy test prints (security review of PR #197, L1).
	r := embedded(t)
	dir := t.TempDir()
	for name, body := range map[string]string{
		"inventory path": "policy: " + repoPolicy(t, "read-only") + "\ninventory: \"nothere\\x1b[31m.yaml\"\ncases:\n  - name: x\n    request: {server: eos-mcp, tool: get_version, arguments: {hostname: lab-sw-01}}\n    expect: {effect: allow, rule: reads-anywhere}\n",
		"policy path":    "policy: \"p\\x1b[2J\\u202e.yaml\"\ncases:\n  - name: x\n    request: {class: READ_CONFIG}\n    expect: {effect: allow}\n",
	} {
		_, err := r.RunFile(writeTest(t, dir, body))
		if err == nil {
			t.Fatalf("%s: loaded", name)
		}
		msg := err.Error()
		for _, raw := range []rune{0x1b, 0x202e} {
			if strings.ContainsRune(msg, raw) {
				t.Errorf("%s: error carries %U raw: %q", name, raw, msg)
			}
		}
		if !strings.Contains(msg, "\\x1b[") {
			t.Errorf("%s: error does not show the path quoted: %q", name, msg)
		}
	}
}

// TestInventoryPath: a path inventory is read as serve --inventory reads
// it, with the configfile checks, relative to the test file; the gate case
// then resolves through it.
func TestInventoryPath(t *testing.T) {
	dir := configDir(t)
	inv := filepath.Join(dir, "inv.yaml")
	if err := os.WriteFile(inv, []byte("devices:\n  - {name: lab-sw-01, tags: [lab]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := "policy: " + repoPolicy(t, "read-only") + `
inventory: inv.yaml
cases:
  - name: listed
    request: {server: eos-mcp, tool: get_version, arguments: {hostname: lab-sw-01}}
    expect: {effect: allow, rule: reads-anywhere, unknown_target: false}
`
	path := writeTest(t, dir, body)
	r := embedded(t)
	results, err := r.RunFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !results[0].Pass {
		t.Fatal(results[0].Message)
	}
	// Relative to the test file's own directory, not the working directory.
	sub := filepath.Join(dir, "suites")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	nested := filepath.Join(sub, "nested.test.yaml")
	if err := os.WriteFile(nested, []byte(strings.Replace(body, "inventory: inv.yaml", "inventory: ../inv.yaml", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if results, err := r.RunFile(nested); err != nil || !results[0].Pass {
		t.Fatalf("relative path from a sub-directory: %v %+v", err, results)
	}

	letOthersWrite(t, inv)
	if _, err := r.RunFile(path); err == nil || !strings.Contains(err.Error(), "the inventory file") {
		t.Fatalf("an inventory others can change: %v", err)
	}
}

// TestProfilesDir: --profiles replaces the embedded set (a server only the
// embedded set has is then a load error), passes the configfile checks,
// and refuses what serve refuses.
func TestProfilesDir(t *testing.T) {
	dir := configDir(t)
	src, err := os.ReadFile(filepath.Join("..", "..", "profiles", "upa.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "upa.yaml"), src, 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := NewRunner(dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Source() != dir {
		t.Errorf("source %q", r.Source())
	}
	tests := configDir(t)
	body := func(server, tool, args string) string {
		return "policy: " + repoPolicy(t, "read-only") + "\n" + inlineInventory + "cases:\n  - name: x\n    request: {server: " + server + ", tool: " + tool + ", arguments: " + args + "}\n    expect: {effect: allow, rule: reads-anywhere}\n"
	}
	if res, err := r.RunFile(writeTest(t, tests, body("upa", "send_command_and_get_output", "{name: lab-sw-01, command: show version}"))); err != nil || !res[0].Pass {
		t.Fatalf("upa from --profiles: %v %+v", err, res)
	}
	if _, err := r.RunFile(writeTest(t, tests, body("eos-mcp", "get_version", "{hostname: lab-sw-01}"))); err == nil || !strings.Contains(err.Error(), "has no profile in the "+dir+" profile set") {
		t.Fatalf("eos-mcp with only upa in --profiles: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "other.yaml"), src, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRunner(dir); err == nil || !strings.Contains(err.Error(), "named after its server key") {
		t.Fatalf("misnamed profile: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "other.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewRunner(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("missing directory accepted")
	}
	letOthersWrite(t, filepath.Join(dir, "upa.yaml"))
	if _, err := NewRunner(dir); err == nil || !strings.Contains(err.Error(), "--profiles") {
		t.Fatalf("a profile others can change: %v", err)
	}
}

// TestPlainScalars: an unquoted value in arguments must reach the gate as
// written; one that YAML reads as another number, keeps as a string while it
// looks like a number or a date, or reads as a boolean or null from another
// spelling, is a load error pointing at arguments_json (security review of
// PR #197, L4; ADR 0035 section 2). Quoted, every one is accepted as a
// string.
func TestPlainScalars(t *testing.T) {
	refused := []string{
		"0x1F", "0o17", "017", "0b11", "+5", "1_000", "99999999999999999999",
		"1e3", "1E3", "1.5e3", "3.", ".5", "1e400",
		"2026-09-25", "2026-09-25T10:00:00Z", "12:30:00",
		"True", "TRUE", "False", "~", "Null", "NULL", ".inf", "-.inf", ".nan",
	}
	accepted := map[string]string{
		"0": "0", "7": "7", "-1": "-1", "1.5": "1.5", "0.25": "0.25",
		"true": "true", "false": "false", "null": "null",
		"192.0.2.99": `"192.0.2.99"`, "lab-sw-01": `"lab-sw-01"`, "show ip bgp summary": `"show ip bgp summary"`,
		"2001:db8::1": `"2001:db8::1"`, "yes": `"yes"`, "v1.2.3": `"v1.2.3"`,
	}
	parse := func(value string) (*File, error) {
		return Parse([]byte("policy: p.yaml\ncases:\n  - name: x\n    request: {server: s, tool: t, arguments: {v: " + value + "}}\n    expect: {effect: deny, rule: x}\n"))
	}
	for _, v := range refused {
		if _, err := parse(v); err == nil || !strings.Contains(err.Error(), "quote it, or give the exact bytes in arguments_json") {
			t.Errorf("unquoted %s: %v", v, err)
		}
		f, err := parse("\"" + v + "\"")
		if err != nil {
			t.Errorf("quoted %s: %v", v, err)
			continue
		}
		if got, want := string(f.Cases[0].ArgumentBytes()), `{"v":"`+v+`"}`; got != want {
			t.Errorf("quoted %s: %s, want %s", v, got, want)
		}
	}
	for v, want := range accepted {
		f, err := parse(v)
		if err != nil {
			t.Errorf("unquoted %s: %v", v, err)
			continue
		}
		if got := string(f.Cases[0].ArgumentBytes()); got != `{"v":`+want+`}` {
			t.Errorf("unquoted %s: %s, want {\"v\":%s}", v, got, want)
		}
	}
	// Keys are checked as keys, not as values: an unquoted key that looks
	// like a date is still a string key.
	if _, err := Parse([]byte("policy: p.yaml\ncases:\n  - name: x\n    request: {server: s, tool: t, arguments: {v1.2: a}}\n    expect: {effect: deny, rule: x}\n")); err != nil {
		t.Errorf("a key that looks like a number: %v", err)
	}
	// The message names the line, not the value.
	_, err := parse("0x1F")
	if err == nil || strings.Contains(err.Error(), "0x1F") || !strings.Contains(err.Error(), "line 4") {
		t.Errorf("message %v", err)
	}
}

// TestTestFileCaps: a test file over the size cap is refused before it is
// parsed, and anchors and aliases never expand (security review of PR #197,
// L3: 3000 aliases of a 200 KB anchored name took 40 s and printed 600 MB).
func TestTestFileCaps(t *testing.T) {
	r := embedded(t)
	dir := t.TempDir()
	big := filepath.Join(dir, "big.test.yaml")
	if err := os.WriteFile(big, []byte("policy: p.yaml\n# "+strings.Repeat("x", configset.MaxFile)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RunFile(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversized test file: %v", err)
	}

	var b strings.Builder
	b.WriteString("policy: " + repoPolicy(t, "read-only") + "\ncases:\n  - name: &n " + strings.Repeat("n", 200<<10) + "\n    request: {class: READ_CONFIG}\n    expect: {effect: allow}\n")
	for range 3000 {
		b.WriteString("  - name: *n\n    request: {class: READ_CONFIG}\n    expect: {effect: allow}\n")
	}
	path := writeTest(t, dir, b.String())
	start := time.Now()
	_, err := r.RunFile(path)
	if err == nil || !strings.Contains(err.Error(), "anchors (&) and aliases (*) are not allowed") {
		t.Fatalf("aliased names: %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("refusing the aliased file took %s", d)
	}
	if len(err.Error()) > 1024 {
		t.Errorf("the error is %d bytes", len(err.Error()))
	}
}

// TestRecordFieldAbsent: an assertion on a field the decision record does
// not carry fails with a message that says so, rather than comparing with a
// zero value (security review of PR #197, N3).
func TestRecordFieldAbsent(t *testing.T) {
	rec := record([]slog.Attr{
		slog.String("parse_error", "duplicate_key"),
		slog.Any("unnamed_args", []string{"config_path"}),
		slog.Any("obligations", "not a list"),
	})
	checks := []struct {
		key  string
		kind slog.Kind
		want bool
	}{
		{"parse_error", slog.KindString, true},
		{"unnamed_args", slog.KindAny, true},
		{"obligations", slog.KindAny, false},
		{"unknown_target", slog.KindBool, false},
		{"malformed_args", slog.KindAny, false},
	}
	for _, c := range checks {
		if got := rec.has(c.key, c.kind); got != c.want {
			t.Errorf("has(%s) = %v, want %v", c.key, got, c.want)
		}
	}
	if got := absent("unknown_target"); got != "unknown_target (none: the decision record has no unknown_target field)" {
		t.Errorf("absent: %q", got)
	}
}
