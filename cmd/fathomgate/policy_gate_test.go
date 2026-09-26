// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/fathomgate/fathomgate/internal/policy"
	"github.com/fathomgate/fathomgate/internal/policytest"
)

// TestPolicyEvalProfileUsage: under --profile the gate classifies the call
// and takes its targets from the arguments, so --class and --target are
// usage errors (ADR 0035 section 6), as are both argument forms at once, a
// --server that is not the profile's key, and argument flags without
// --profile.
func TestPolicyEvalProfileUsage(t *testing.T) {
	pol := repoPath("policies", "examples", "read-only.yaml")
	// A copy that passes the configfile checks, so each case fails on the
	// usage rule it names and not on the profile's permissions.
	prof := configCopy(t, repoPath("profiles", "eos-mcp.yaml"))
	base := []string{"policy", "eval", "--policy", pol}
	cases := map[string][]string{
		"--class with --profile":           {"--profile", prof, "--tool", "get_version", "--arg", "hostname=lab-sw-01", "--class", "READ_OPERATIONAL"},
		"--target with --profile":          {"--profile", prof, "--tool", "get_version", "--target", "lab-sw-01"},
		"--arg and --arguments-json":       {"--profile", prof, "--tool", "get_version", "--arg", "hostname=lab-sw-01", "--arguments-json", `{"hostname":"lab-sw-01"}`},
		"--server other than the profile":  {"--profile", prof, "--server", "upa", "--tool", "get_version", "--arg", "hostname=lab-sw-01"},
		"no --tool":                        {"--profile", prof, "--arg", "hostname=lab-sw-01"},
		"--arguments-json without profile": {"--class", "READ_OPERATIONAL", "--arguments-json", "{}"},
		"--arg without profile":            {"--class", "READ_OPERATIONAL", "--arg", "hostname=lab-sw-01"},
	}
	for name, args := range cases {
		if got := run(append(append([]string{}, base...), args...)); got != exitUsage {
			t.Errorf("%s: exit %d, want %d", name, got, exitUsage)
		}
	}
}

// TestPolicyEvalGateJSON: eval --profile --arguments-json shows what the
// gate decided, including the refusals before Evaluate.
func TestPolicyEvalGateJSON(t *testing.T) {
	pol := repoPath("policies", "examples", "read-only.yaml")
	prof := configCopy(t, repoPath("profiles", "netdev-ssh-mcp.yaml"))
	out, code := captureStdout(t, func() int {
		return run([]string{"policy", "eval", "--policy", pol, "--profile", prof, "--tool", "run_show_command", "--json",
			"--arguments-json", `{"host": "lab-sw-01", "command": "show version", "host": "x"}`})
	})
	var got struct {
		Decision evalDecision `json:"decision"`
		Gate     gateView     `json:"gate"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if code != exitFail || got.Decision.RuleID != policy.RuleBadArguments || got.Gate.ParseError != "duplicate_key" || got.Gate.Forwarded ||
		!strings.HasPrefix(got.Gate.ToolError, "fathomgate denied netdev-ssh-mcp.run_show_command: rule default:bad_arguments") {
		t.Fatalf("exit %d, %+v", code, got)
	}
}

// TestPolicyEvalMatchesGateCases: for every shipped gate case, policy eval
// --profile with the case's arguments gives the decision, rule and class
// the runner gives (ADR 0035: eval and test decide through one function).
// Cases that set annotations are skipped: eval has no annotation flags.
func TestPolicyEvalMatchesGateCases(t *testing.T) {
	files, err := filepath.Glob(repoPath("policies", "examples", "*.gate.test.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatal("no gate test files")
	}
	runner, err := policytest.NewRunner("")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	profiles := map[string]string{}
	for _, server := range []string{"eos-mcp", "junos-mcp-server", "netdev-ssh-mcp", "ntunes-netmiko-mcp-server", "upa"} {
		profiles[server] = configCopy(t, repoPath("profiles", server+".yaml"))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		tf, err := policytest.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		results, err := runner.RunFile(f)
		if err != nil {
			t.Fatal(err)
		}
		// configDir: eval reads --inventory with the configfile checks, which
		// a plain t.TempDir fails on Windows when it inherits a write ACE.
		inv := filepath.Join(configDir(t), "inventory.yaml")
		if err := os.WriteFile(inv, tf.Inventory.Inline, 0o600); err != nil {
			t.Fatal(err)
		}
		for i, c := range tf.Cases {
			if c.Request.Annotations != nil {
				continue
			}
			args := []string{"policy", "eval", "--json",
				"--policy", filepath.Join(filepath.Dir(f), tf.Policy),
				"--inventory", inv,
				"--profile", profiles[c.Request.Server],
				"--tool", c.Request.Tool,
				"--arguments-json", string(c.ArgumentBytes()),
				"--devices-touched", strconv.Itoa(c.Request.Session.DevicesTouched),
				"--pending-holds", strconv.Itoa(c.Request.Session.PendingHolds),
			}
			out, _ := captureStdout(t, func() int { return run(args) })
			var got struct {
				Request  policy.Request `json:"request"`
				Decision evalDecision   `json:"decision"`
				Gate     gateView       `json:"gate"`
			}
			if err := json.Unmarshal([]byte(out), &got); err != nil {
				t.Fatalf("%s: %v\n%s", c.Name, err, out)
			}
			r := results[i]
			if got.Decision.Effect != r.Effect || got.Decision.RuleID != r.RuleID || string(got.Request.Class) != r.Class || got.Gate.ClassSource != r.ClassSource {
				t.Errorf("%s: eval %s %s %s %s, test %s %s %s %s", c.Name,
					got.Decision.Effect, got.Decision.RuleID, got.Request.Class, got.Gate.ClassSource,
					r.Effect, r.RuleID, r.Class, r.ClassSource)
			}
			checked++
		}
	}
	if checked < 100 {
		t.Errorf("only %d gate cases compared", checked)
	}
}

// TestPolicyTestOutput: policy test prints no argument value, quotes case
// names that are not printable ASCII, and --profiles replaces the embedded
// set for gate cases.
func TestPolicyTestOutput(t *testing.T) {
	const canary = "FAKE-canary-51c9"
	dir := configDir(t)
	body := "policy: " + filepath.ToSlash(mustAbs(t, repoPath("policies", "examples", "read-only.yaml"))) + `
inventory: {devices: [{name: lab-sw-01, tags: [lab]}]}
cases:
  - name: "bell\u0007 and escape\u001b[2J"
    request:
      server: upa
      tool: send_command_and_get_output
      arguments: {name: lab-sw-01, command: "show ` + canary + `"}
    expect: {effect: allow, rule: no-exec}
  - name: plain
    request:
      server: upa
      tool: send_command_and_get_output
      arguments: {name: lab-sw-01, command: show version}
    expect: {effect: allow, rule: reads-anywhere}
`
	path := filepath.Join(dir, "out.test.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := captureStdout(t, func() int { return run([]string{"policy", "test", "-v", path}) })
	if code != exitFail {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if strings.Contains(out, canary) || strings.ContainsAny(out, "\x07\x1b") {
		t.Fatalf("output carries an argument value or a raw control character:\n%s", out)
	}
	if !strings.Contains(out, `FAIL  "bell\a and escape\x1b[2J"`) || !strings.Contains(out, "PASS  plain") {
		t.Fatalf("output:\n%s", out)
	}

	profiles := filepath.Join(dir, "profiles")
	if err := os.Mkdir(profiles, 0o700); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(repoPath("profiles", "eos-mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(profiles, "eos-mcp.yaml"), src, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"policy", "test", "--profiles", profiles, path}); got != exitUsage {
		t.Fatalf("upa case with only eos-mcp in --profiles: exit %d, want %d", got, exitUsage)
	}
	if got := run([]string{"policy", "test", "--profiles", filepath.Join(dir, "missing"), path}); got != exitUsage {
		t.Fatalf("missing --profiles: exit %d, want %d", got, exitUsage)
	}
}

// configCopy copies src into a new configDir, keeping its file name, and
// returns the copy's path: a file there passes the configfile checks that
// policy eval, like serve, applies to --profile and --inventory.
func configCopy(t *testing.T, src string) string {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(configDir(t), filepath.Base(src))
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return dst
}

// captureStderr runs fn with os.Stderr redirected and returns what it wrote.
// Not for parallel tests.
func captureStderr(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stderr
	os.Stderr = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	code := fn()
	os.Stderr = old
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return string(out), code
}

// TestFailEscapesControls: the error policy test prints for a test file
// whose inventory or policy path carries control and bidi characters shows
// them escaped (security review of PR #197, L1). fail() escapes the whole
// message; the paths are also quoted where they enter it.
func TestFailEscapesControls(t *testing.T) {
	dir := t.TempDir()
	pol := filepath.ToSlash(mustAbs(t, repoPath("policies", "examples", "read-only.yaml")))
	bodies := map[string]string{
		"inventory": "policy: " + pol + "\ninventory: \"nothere\\x1b[31m\\u202e.yaml\"\ncases:\n  - name: x\n    request: {server: upa, tool: send_command_and_get_output, arguments: {name: a, command: show version}}\n    expect: {effect: deny, rule: x}\n",
		"policy":    "policy: \"p\\x1b]0;title\\x07\\u2066.yaml\"\ncases:\n  - name: x\n    request: {class: READ_CONFIG}\n    expect: {effect: allow}\n",
	}
	for name, body := range bodies {
		path := filepath.Join(dir, name+".test.yaml")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		out, code := captureStderr(t, func() int { return run([]string{"policy", "test", path}) })
		if code != exitUsage {
			t.Errorf("%s: exit %d", name, code)
		}
		if strings.ContainsAny(out, "\x1b\x07\u202e\u2066") {
			t.Errorf("%s: stderr carries a raw control or bidi character: %q", name, out)
		}
		if !strings.Contains(out, "\\x1b") {
			t.Errorf("%s: stderr does not show the escape: %q", name, out)
		}
	}
}

// TestPolicyEvalReadsLikeServe: policy eval reads --profile and --inventory
// as serve does (security review of PR #197, N4): a profile file not named
// after its server key, one others can change, and a CSV inventory are
// usage errors.
func TestPolicyEvalReadsLikeServe(t *testing.T) {
	pol := repoPath("policies", "examples", "read-only.yaml")
	src, err := os.ReadFile(repoPath("profiles", "eos-mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := configDir(t)
	misnamed := filepath.Join(dir, "other.yaml")
	if err := os.WriteFile(misnamed, src, 0o600); err != nil {
		t.Fatal(err)
	}
	good := configCopy(t, repoPath("profiles", "eos-mcp.yaml"))
	args := func(profile string, extra ...string) []string {
		return append([]string{"policy", "eval", "--policy", pol, "--profile", profile, "--tool", "get_version", "--arg", "hostname=lab-sw-01"}, extra...)
	}
	if got := run(args(good)); got != exitFail {
		t.Fatalf("good profile, no inventory: exit %d, want %d (unknown target)", got, exitFail)
	}
	if got := run(args(misnamed)); got != exitUsage {
		t.Errorf("misnamed profile: exit %d, want %d", got, exitUsage)
	}
	csv := filepath.Join(dir, "devices.csv")
	if err := os.WriteFile(csv, []byte("name\nlab-sw-01\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run(args(good, "--inventory", csv)); got != exitUsage {
		t.Errorf("CSV inventory: exit %d, want %d", got, exitUsage)
	}
	letOthersWrite(t, good)
	if got := run(args(good)); got != exitUsage {
		t.Errorf("a profile others can change: exit %d, want %d", got, exitUsage)
	}
}

// TestFailSink: fail escapes C0, C1 and bidi controls anywhere in the
// message, whatever produced it, and keeps line breaks for multi-line hints.
func TestFailSink(t *testing.T) {
	out, code := captureStderr(t, func() int {
		return fail(errors.New("raw \x1b[2J \u009b \u202e end\n  hint"))
	})
	if code != exitUsage {
		t.Fatalf("exit %d", code)
	}
	if want := "fathomgate: raw \\x1b[2J \\u009b \\u202e end\n  hint\n"; out != want {
		t.Fatalf("stderr %q, want %q", out, want)
	}
}
