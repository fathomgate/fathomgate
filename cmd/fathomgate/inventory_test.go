// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
// write rules honour it.
func TestEvalPatternsEnrichOnly(t *testing.T) {
	pol := func(name string) string { return repoPath("policies", "examples", name+".yaml") }
	cases := []struct {
		name       string
		args       []string
		effect     policy.Effect
		rule, code string
	}{
		{"7: pattern-only lab name", []string{"--policy", pol("lab-open"), "--server", "eos-mcp", "--tool", "push_config", "--class", "WRITE_CONFIG", "--target", "lab-ghost-99"}, policy.Deny, "default:unknown_target", "fail"},
		{"7: listed untagged lab-sw-09 tagged by ^lab-", []string{"--policy", pol("lab-open"), "--server", "eos-mcp", "--tool", "push_config", "--class", "WRITE_CONFIG", "--target", "lab-sw-09"}, policy.Allow, "lab-writes-free", "ok"},
		{"7: case variant of a listed name", []string{"--policy", pol("lab-open"), "--server", "eos-mcp", "--tool", "push_config", "--class", "WRITE_CONFIG", "--target", "LAB-sw-09"}, policy.Deny, "default:unknown_target", "fail"},
		{"8: pattern-only core name, read", []string{"--policy", pol("read-only"), "--class", "READ_CONFIG", "--target", "core-x.attacker.example"}, policy.Deny, "default:unknown_target", "fail"},
		{"8: listed core-rtr-09, read", []string{"--policy", pol("read-only"), "--class", "READ_CONFIG", "--target", "core-rtr-09"}, policy.Allow, "reads-anywhere", "ok"},
		{"listed core-rtr-09 given core by ^core-, write", []string{"--policy", pol("prod-approval"), "--server", "eos-mcp", "--tool", "push_config", "--class", "WRITE_CONFIG", "--target", "core-rtr-09"}, policy.Hold, "prod-core-needs-approval", "hold"},
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
// names the patterns an unknown name matches without making it known.
func TestInventoryResolve(t *testing.T) {
	var out, errb bytes.Buffer
	code := inventoryResolve([]string{"--inventory", patternInventory, "lab-sw-09", "core-rtr-09"}, &out, &errb)
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
	code = inventoryResolve([]string{"--inventory", patternInventory, "core-x.attacker.example", "LAB-SW-09", "ghost-99"}, &out, &errb)
	if code != exitFail {
		t.Fatalf("unknown names exit %d, want %d", code, exitFail)
	}
	want = "core-x.attacker.example: unknown (no name authority lists it)\n" +
		"  matches roles[1] \"^core-|^border-\", which never makes a name known (ADR 0031)\n" +
		"LAB-SW-09: unknown (listed as lab-sw-09; a name is known only spelled exactly as listed (inventory-schema section 7))\n" +
		"ghost-99: unknown (no name authority lists it)\n"
	if out.String() != want {
		t.Fatalf("resolve unknown output\n got:\n%s\nwant:\n%s", out.String(), want)
	}
	if strings.Contains(out.String(), "known (listed by pattern") {
		t.Fatal("a pattern listed a name")
	}

	out.Reset()
	if code := inventoryResolve([]string{"--inventory", patternInventory, "--json", "core-rtr-09", "lab-ghost-99"}, &out, &errb); code != exitFail {
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

	for _, args := range [][]string{{}, {"--inventory", patternInventory}, {"--nope", "x"}} {
		if code := inventoryResolve(args, &out, &errb); code != exitUsage {
			t.Errorf("%q: exit %d, want %d", args, code, exitUsage)
		}
	}
	if code := inventoryResolve([]string{"--inventory", filepath.Join(t.TempDir(), "missing.yaml"), "x"}, &out, &errb); code != exitUsage {
		t.Errorf("missing inventory: exit %d", code)
	}
	if got := run([]string{"inventory", "nope"}); got != exitUsage {
		t.Errorf("unknown subcommand exit %d", got)
	}
}

// TestInventoryLint: ADR 0031 test 5, the CLI half. A pattern that matches
// no listed device fails lint with the load warning's text; a clean file and
// the shipped example pass.
func TestInventoryLint(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	stale := write("stale.yaml", "devices:\n  - {name: core-rtr-01, role: core}\nroles:\n  - {match: \"^core-\", tags: [prod]}\n  - {match: \"^lab-\", tags: [lab]}\n")
	dup := write("dup.yaml", "devices:\n  - {name: a}\n  - {name: A}\n")
	badRe := write("bad-re.yaml", "devices:\n  - {name: a}\nroles:\n  - {match: \"(\", role: x}\n")
	unknownKey := write("unknown-key.yaml", "devices:\n  - {name: a, source: pattern}\n")

	cases := []struct {
		name, path string
		code       int
		stdout     string
		stderr     string
	}{
		{"clean", patternInventory, exitOK, patternInventory + ": ok (2 devices, 2 patterns)\n", ""},
		{"example", repoPath("inventory.example.yaml"), exitOK, "ok (12 devices, 0 patterns)", ""},
		{"stale pattern", stale, exitFail, "", "fathomgate: inventory lint: " + stale + `: inventory: roles[1] "^lab-" matches no listed device and makes nothing known (ADR 0031); list the device under devices` + "\n"},
		{"duplicate", dup, exitFail, "", "duplicate device"},
		{"bad regex", badRe, exitFail, "", "roles[0]"},
		{"source key", unknownKey, exitFail, "", "inventory: parse"},
		{"missing", filepath.Join(dir, "missing.yaml"), exitUsage, "", "inventory lint"},
	}
	for _, tc := range cases {
		var out, errb bytes.Buffer
		code := inventoryLint([]string{tc.path}, &out, &errb)
		if code != tc.code || !strings.Contains(out.String(), tc.stdout) || !strings.Contains(errb.String(), tc.stderr) {
			t.Errorf("%s: exit %d stdout %q stderr %q; want exit %d, stdout with %q, stderr with %q",
				tc.name, code, out.String(), errb.String(), tc.code, tc.stdout, tc.stderr)
		}
		if tc.name == "stale pattern" && errb.String() != tc.stderr {
			t.Errorf("stale pattern stderr %q, want exactly %q", errb.String(), tc.stderr)
		}
	}
	var out, errb bytes.Buffer
	for _, args := range [][]string{{}, {"a", "b"}} {
		if code := inventoryLint(args, &out, &errb); code != exitUsage {
			t.Errorf("%q: exit %d", args, code)
		}
	}
}
