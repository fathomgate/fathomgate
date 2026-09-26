// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"encoding/json"
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
	prof := repoPath("profiles", "eos-mcp.yaml")
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
	prof := repoPath("profiles", "netdev-ssh-mcp.yaml")
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
		inv := filepath.Join(t.TempDir(), "inventory.yaml")
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
				"--profile", repoPath("profiles", c.Request.Server+".yaml"),
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
