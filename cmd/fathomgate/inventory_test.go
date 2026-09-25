// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fathomgate/fathomgate/internal/configfile"
	"github.com/fathomgate/fathomgate/internal/policy"
)

const patternInventory = "testdata/inventory-patterns.yaml"

// captureStdout runs fn with os.Stdout redirected and returns what it wrote.
// Not for parallel tests.
func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	code := fn()
	os.Stdout = old
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return string(out), code
}

// evalDecision is the part of policy eval --json these tests read.
type evalDecision struct {
	Effect policy.Effect `json:"effect"`
	RuleID string        `json:"rule_id"`
}

// evalJSON runs fathomgate policy eval --json and returns its decision.
func evalJSON(t *testing.T, args ...string) (evalDecision, int) {
	t.Helper()
	out, code := captureStdout(t, func() int {
		return run(append(append([]string{"policy", "eval"}, args...), "--json"))
	})
	var got struct {
		Decision evalDecision `json:"decision"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("eval %q: %v\n%s", args, err, out)
	}
	return got.Decision, code
}

// TestEvalPatternsEnrichOnly: ADR 0031 tests 7 and 8. A name only a pattern
// matches is unknown; a listed device gets the pattern's tag or role, and the
// write rules honour it. A --target the gate would refuse is
// default:bad_arguments, as at the gate (security review of PR #184, L4),
// including the reviewer's probe names.
func TestEvalPatternsEnrichOnly(t *testing.T) {
	pol := func(name string) string { return repoPath("policies", "examples", name+".yaml") }
	write := func(target string) []string {
		return []string{"--policy", pol("lab-open"), "--server", "eos-mcp", "--tool", "push_config", "--class", "WRITE_CONFIG", "--target", target}
	}
	cases := []struct {
		name       string
		args       []string
		effect     policy.Effect
		rule, code string
	}{
		{"7: pattern-only lab name", write("lab-ghost-99"), policy.Deny, "default:unknown_target", "fail"},
		{"7: listed untagged lab-sw-09 tagged by ^lab-", write("lab-sw-09"), policy.Allow, "lab-writes-free", "ok"},
		{"7: case variant of a listed name", write("LAB-sw-09"), policy.Deny, "default:unknown_target", "fail"},
		{"8: pattern-only core name, read", []string{"--policy", pol("read-only"), "--class", "READ_CONFIG", "--target", "core-x.attacker.example"}, policy.Deny, "default:unknown_target", "fail"},
		{"8: listed core-rtr-09, read", []string{"--policy", pol("read-only"), "--class", "READ_CONFIG", "--target", "core-rtr-09"}, policy.Allow, "reads-anywhere", "ok"},
		{"listed core-rtr-09 given core by ^core-, write", []string{"--policy", pol("prod-approval"), "--server", "eos-mcp", "--tool", "push_config", "--class", "WRITE_CONFIG", "--target", "core-rtr-09"}, policy.Hold, "prod-core-needs-approval", "hold"},
		{"probe: Kelvin sign", write("\u212avm-01"), policy.Deny, policy.RuleBadArguments, "fail"},
		{"probe: Cyrillic dze", write("lab-\u0455w-09"), policy.Deny, policy.RuleBadArguments, "fail"},
		{"probe: zero-width space", write("lab-sw-09\u200b"), policy.Deny, policy.RuleBadArguments, "fail"},
		{"probe: trailing dot", write("lab-sw-09."), policy.Deny, policy.RuleBadArguments, "fail"},
		{"probe: leading space", write(" lab-sw-09"), policy.Deny, policy.RuleBadArguments, "fail"},
		{"probe: user@host", write("lab-x@core-rtr-01"), policy.Deny, policy.RuleBadArguments, "fail"},
		{"one bad name among good ones", append(write("lab-sw-09"), "--target", "lab-sw-09."), policy.Deny, policy.RuleBadArguments, "fail"},
	}
	codes := map[string]int{"ok": exitOK, "fail": exitFail, "hold": exitHold}
	for _, tc := range cases {
		d, code := evalJSON(t, append([]string{"--inventory", patternInventory}, tc.args...)...)
		if d.Effect != tc.effect || d.RuleID != tc.rule || code != codes[tc.code] {
			t.Errorf("%s: %s %s exit %d, want %s %s exit %d", tc.name, d.Effect, d.RuleID, code, tc.effect, tc.rule, codes[tc.code])
		}
	}
}

// TestInventoryResolve: ADR 0031 test 4, the CLI half. resolve prints which
// provider supplied each field, never a pattern as the name's source, and
// names the patterns an unknown name matches without making it known. It
// reads the file as serve does (L4) and prints stored and typed values
// without control or non-ASCII characters (N2).
func TestInventoryResolve(t *testing.T) {
	dir := configDir(t)
	inv := copyRepoFile(t, dir, "cmd", "fathomgate", "testdata", "inventory-patterns.yaml")
	var out, errb bytes.Buffer
	code := inventoryResolve([]string{"--inventory", inv, "lab-sw-09", "core-rtr-09"}, &out, &errb)
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	want := "lab-sw-09: known (listed by static)\n" +
		"  name    lab-sw-09                static\n" +
		"  role    access                   static\n" +
		"  site    -\n" +
		"  status  -\n" +
		"  tags    lab                      pattern\n" +
		"core-rtr-09: known (listed by static)\n" +
		"  name    core-rtr-09              static\n" +
		"  role    core                     pattern\n" +
		"  site    dfw1                     static\n" +
		"  status  -\n" +
		"  tags    prod                     static\n"
	if out.String() != want {
		t.Fatalf("resolve output\n got:\n%s\nwant:\n%s", out.String(), want)
	}

	out.Reset()
	code = inventoryResolve([]string{"--inventory", inv, "core-x.attacker.example", "LAB-SW-09", "ghost-99", "lab-\u0455w-09", "x\x1b[2J"}, &out, &errb)
	if code != exitFail {
		t.Fatalf("unknown names exit %d, want %d", code, exitFail)
	}
	want = "core-x.attacker.example: unknown (no name authority lists it)\n" +
		"  matches roles[1] \"^core-|^border-\", which never makes a name known (ADR 0031)\n" +
		"LAB-SW-09: unknown (listed as lab-sw-09; a name is known only spelled exactly as listed (inventory-schema section 7))\n" +
		"ghost-99: unknown (no name authority lists it)\n" +
		"\"lab-\\u0455w-09\": unknown (no name authority lists it)\n" +
		"  matches roles[0] \"^lab-\", which never makes a name known (ADR 0031)\n" +
		"\"x\\x1b[2J\": unknown (no name authority lists it)\n"
	if out.String() != want {
		t.Fatalf("resolve unknown output\n got:\n%s\nwant:\n%s", out.String(), want)
	}
	if strings.Contains(out.String(), "known (listed by pattern") {
		t.Fatal("a pattern listed a name")
	}

	// A stored value with an escape sequence or a bidi override is printed
	// quoted, never raw.
	evil := writeFile(t, dir, "evil.yaml", "devices:\n  - {name: sw-1, role: \"core\\e[2J\", site: \"a\\u202eb\", tags: [\"lab\\u0007\"]}\n")
	out.Reset()
	if code := inventoryResolve([]string{"--inventory", evil, "sw-1"}, &out, &errb); code != exitOK {
		t.Fatalf("evil: exit %d %s", code, errb.String())
	}
	for _, raw := range []string{"\x1b", "\u202e", "\x07"} {
		if strings.Contains(out.String(), raw) {
			t.Errorf("resolve printed %q raw:\n%s", raw, out.String())
		}
	}
	if !strings.Contains(out.String(), `"core\x1b[2J"`) || !strings.Contains(out.String(), `"a\u202eb"`) {
		t.Errorf("resolve output does not quote stored values:\n%s", out.String())
	}

	out.Reset()
	if code := inventoryResolve([]string{"--inventory", inv, "--json", "core-rtr-09", "lab-ghost-99"}, &out, &errb); code != exitFail {
		t.Fatalf("json exit %d", code)
	}
	var res []resolveResult
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || !res[0].Known || res[0].Target.Sources.Role != "pattern" || res[0].Target.Source != "static" ||
		res[1].Known || res[1].Target != nil || len(res[1].Patterns) != 1 {
		t.Fatalf("json: %s", out.String())
	}

	csv := writeFile(t, dir, "devices.csv", "name\nsw-1\n")
	loose := writeFile(t, dir, "loose.yaml", "devices: [{name: sw-1}]\n")
	letOthersWrite(t, loose)
	for _, args := range [][]string{
		{}, {"--inventory", inv}, {"--nope", "x"},
		{"--inventory", filepath.Join(dir, "missing.yaml"), "x"},
		{"--inventory", csv, "sw-1"},
		{"--inventory", loose, "sw-1"},
	} {
		errb.Reset()
		if code := inventoryResolve(args, &out, &errb); code != exitUsage {
			t.Errorf("%q: exit %d, want %d", args, code, exitUsage)
		}
	}
	errb.Reset()
	_ = inventoryResolve([]string{"--inventory", csv, "sw-1"}, &out, &errb)
	if !strings.Contains(errb.String(), "convert a CSV first") {
		t.Errorf("csv: %q", errb.String())
	}
	if got := run([]string{"inventory", "nope"}); got != exitUsage {
		t.Errorf("unknown subcommand exit %d", got)
	}
}

// TestInventoryLint: ADR 0031 test 5, the CLI half, and the review of PR
// #184 (L3, L4). A pattern that matches no listed device fails lint with the
// load warning's text; a listed name the gate refuses fails lint; every role,
// site or tag a pattern adds to a listed device is a warning; the file is
// read as serve reads it.
func TestInventoryLint(t *testing.T) {
	dir := configDir(t)
	write := func(name, body string) string { return writeFile(t, dir, name, body) }
	clean := copyRepoFile(t, dir, "cmd", "fathomgate", "testdata", "inventory-patterns.yaml")
	example := copyRepoFile(t, dir, "inventory.example.yaml")
	stale := write("stale.yaml", "devices:\n  - {name: core-rtr-01, role: core}\nroles:\n  - {match: \"^core-\", tags: [prod]}\n  - {match: \"^lab-\", tags: [lab]}\n")
	dup := write("dup.yaml", "devices:\n  - {name: a}\n  - {name: A}\n")
	badRe := write("bad-re.yaml", "devices:\n  - {name: a}\nroles:\n  - {match: \"(\", role: x}\n")
	unknownKey := write("unknown-key.yaml", "devices:\n  - {name: a, source: pattern}\n")
	statusPattern := write("status-pattern.yaml", "devices:\n  - {name: a, status: pattern}\n")
	unreachable := write("unreachable.yaml", "devices:\n  - {name: ok-1}\n  - {name: \"lab-sw-09.\"}\n  - {name: \" lab-sw-09\"}\n  - {name: \"\\u212avm-01\"}\n  - {name: \"lab-\\u0455w-09\"}\n  - {name: \"lab-sw-09\\u200b\"}\n  - {name: \"x\\e[2J\"}\n")
	csv := write("devices.csv", "name\nsw-1\n")
	loose := write("loose.yaml", "devices: [{name: sw-1}]\n")
	letOthersWrite(t, loose)

	cases := []struct {
		name, path string
		code       int
		stdout     string
		stderr     string
	}{
		{"clean", clean, exitOK, clean + ": ok (2 devices, 2 patterns)\n", ""},
		{"example", example, exitOK, "ok (12 devices, 0 patterns)", ""},
		{"stale pattern", stale, exitFail, "", "fathomgate: inventory lint: " + stale + `: inventory: roles[1] "^lab-" matches no listed device and makes nothing known (ADR 0031); list the device under devices` + "\n"},
		{"duplicate", dup, exitFail, "", "duplicate device"},
		{"bad regex", badRe, exitFail, "", "roles[0]"},
		{"source key", unknownKey, exitFail, "", "inventory: parse"},
		{"status pattern", statusPattern, exitFail, "", "status pattern is not a device status"},
		{"unreachable", unreachable, exitFail, "", `devices[1] "lab-sw-09." is not a name the gate accepts`},
		{"csv", csv, exitUsage, "", "convert a CSV first"},
		// The wording differs by platform (Windows names the ACE, Unix the
		// mode); the exit code and the path are common, and the error is
		// configfile.ErrUnsafe (checked below).
		{"others can write", loose, exitUsage, "", "the inventory file " + loose},
		{"missing", filepath.Join(dir, "missing.yaml"), exitUsage, "", "inventory lint"},
	}
	for _, tc := range cases {
		var out, errb bytes.Buffer
		code := inventoryLint([]string{tc.path}, &out, &errb)
		if code != tc.code || !strings.Contains(out.String(), tc.stdout) || !strings.Contains(errb.String(), tc.stderr) {
			t.Errorf("%s: exit %d stdout %q stderr %q; want exit %d, stdout with %q, stderr with %q",
				tc.name, code, out.String(), errb.String(), tc.code, tc.stdout, tc.stderr)
		}
		// The error line is whole and comes after the warnings.
		if tc.name == "stale pattern" && !strings.HasSuffix(errb.String(), "\n"+tc.stderr) {
			t.Errorf("stale pattern stderr %q, want it to end with the line %q", errb.String(), tc.stderr)
		}
		if tc.name == "unreachable" {
			if n := strings.Count(errb.String(), "is not a name the gate accepts"); n != 6 {
				t.Errorf("unreachable: %d names flagged, want 6:\n%s", n, errb.String())
			}
			if strings.ContainsAny(errb.String(), "\x1b\u200b\u212a\u0455") {
				t.Errorf("unreachable: raw name echoed:\n%q", errb.String())
			}
		}
	}

	// lint and resolve refuse a file others can change for the same reason
	// serve does, on every platform.
	if _, err := readInventory(loose); !errors.Is(err, configfile.ErrUnsafe) {
		t.Errorf("readInventory(others can write): %v, want configfile.ErrUnsafe", err)
	}
	if _, err := readInventory(clean); err != nil {
		t.Errorf("readInventory(clean): %v", err)
	}

	// L3: what each pattern adds to each listed device is a warning, with
	// the device's own role where the pattern adds a tag to it.
	var out, errb bytes.Buffer
	if code := inventoryLint([]string{clean}, &out, &errb); code != exitOK {
		t.Fatalf("clean: exit %d", code)
	}
	wantWarn := "fathomgate: inventory lint: " + clean + `: warning: inventory: devices[0] "lab-sw-09": roles[0] "^lab-" adds tag lab; the device's own record says role access` + "\n" +
		"fathomgate: inventory lint: " + clean + `: warning: inventory: devices[1] "core-rtr-09": roles[1] "^core-|^border-" sets role core` + "\n"
	if errb.String() != wantWarn {
		t.Errorf("clean warnings\n got %q\nwant %q", errb.String(), wantWarn)
	}

	for _, args := range [][]string{{}, {"a", "b"}} {
		if code := inventoryLint(args, &out, &errb); code != exitUsage {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}
