// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fathomgate/fathomgate/internal/configset"
	"github.com/fathomgate/fathomgate/internal/gate/seam"
	"github.com/fathomgate/fathomgate/internal/policy"
	"github.com/fathomgate/fathomgate/profiles"
)

// TestParseServePipelineFlags: every combination of --policy, --no-policy,
// --inventory and --profiles (ADR 0027), and a repeated file flag (L1 in
// the security review of PR #171). The pipeline flags are checked after
// every other usage error, and name flags only.
func TestParseServePipelineFlags(t *testing.T) {
	t.Parallel()
	base := []string{"--server", "netdev-ssh-mcp", "--upstream", "/opt/bin/netdev-ssh-mcp"}
	with := func(extra ...string) []string { return append(slices.Clone(base), extra...) }
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr string
		want    pipelineFlags
	}{
		{"neither", base, "--policy <file> or --no-policy is required", pipelineFlags{}},
		{"no-policy", with("--no-policy"), "", pipelineFlags{noPolicy: true}},
		{"no-policy=true", with("--no-policy=true"), "", pipelineFlags{noPolicy: true}},
		{"no-policy=false is neither", with("--no-policy=false"), "--policy <file> or --no-policy is required", pipelineFlags{}},
		{"policy", with("--policy", "p.yaml"), "", pipelineFlags{policy: "p.yaml"}},
		{"policy=", with("--policy=p.yaml"), "", pipelineFlags{policy: "p.yaml"}},
		{"policy inventory profiles", with("--policy", "p.yaml", "--inventory", "i.yaml", "--profiles", "d"), "", pipelineFlags{policy: "p.yaml", inventory: "i.yaml", profiles: "d"}},
		{"both", with("--policy", "p.yaml", "--no-policy"), "--policy and --no-policy cannot be used together", pipelineFlags{}},
		{"no-policy with inventory", with("--no-policy", "--inventory", "i.yaml"), "--inventory: only with --policy <file>; --no-policy forwards every call unchecked, so leave them out or use --policy <file> instead of --no-policy", pipelineFlags{}},
		{"no-policy with both", with("--no-policy", "--inventory", "i.yaml", "--profiles", "d"), "--inventory and --profiles: only with --policy <file>; --no-policy", pipelineFlags{}},
		{"inventory alone", with("--inventory", "i.yaml"), "--inventory: only with --policy <file>", pipelineFlags{}},
		{"profiles alone", with("--profiles", "d"), "--profiles: only with --policy <file>", pipelineFlags{}},
		{"policy twice", with("--policy", "a.yaml", "--policy", "b.yaml"), "--policy is given more than once; give it once", pipelineFlags{}},
		{"policy twice with =", with("--policy=a.yaml", "-policy=b.yaml"), "--policy is given more than once", pipelineFlags{}},
		{"inventory twice", with("--policy", "p.yaml", "--inventory", "a.yaml", "--inventory", "b.yaml"), "--inventory is given more than once", pipelineFlags{}},
		{"profiles twice", with("--policy", "p.yaml", "--profiles", "a", "--profiles", "b"), "--profiles is given more than once", pipelineFlags{}},
		{"audit with policy", with("--policy", "p.yaml", "--audit", "a.jsonl"), "--audit arrives in M4", pipelineFlags{}},
		{"audit with no-policy", with("--no-policy", "--audit=a.jsonl"), "--audit arrives in M4", pipelineFlags{}},
		{"policy after --", with("--no-policy", "--", "--policy", "p.yaml"), "--policy among the upstream arguments", pipelineFlags{}},
		{"other errors first", with("--upstream-env", "NOEQUALS"), "--upstream-env argument 1 is not KEY=VALUE", pipelineFlags{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg, err := parseServe(tc.args, io.Discard, noEnv, "linux")
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				if strings.Contains(err.Error(), "a.yaml") || strings.Contains(err.Error(), "b.yaml") {
					t.Fatalf("err quotes a value: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.pipeline != tc.want {
				t.Fatalf("pipeline = %+v, want %+v", cfg.pipeline, tc.want)
			}
		})
	}
}

// writeFile writes content to dir/name and returns the path.
func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// copyRepoFile copies a repository file into dir, so it passes the
// configfile checks whatever the checkout's permissions are.
func copyRepoFile(t *testing.T, dir string, parts ...string) string {
	t.Helper()
	b, err := os.ReadFile(repoPath(parts...))
	if err != nil {
		t.Fatal(err)
	}
	return writeFile(t, dir, parts[len(parts)-1], string(b))
}

// TestServePipelineExitCodes runs serve as the binary would, with an
// upstream that does not exist. A file that does not load, or that others
// can change, is exit 2 before the upstream is started (stderr never
// mentions it); a set that loads gets as far as starting the upstream,
// which fails with exit 1.
func TestServePipelineExitCodes(t *testing.T) {
	t.Parallel()
	dir := configDir(t)
	pol := copyRepoFile(t, dir, "policies", "examples", "prod-approval.yaml")
	inv := copyRepoFile(t, dir, "inventory.example.yaml")
	netdev, err := os.ReadFile(repoPath("profiles", "netdev-ssh-mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	profDir := filepath.Join(dir, "profiles")
	writeFile(t, profDir, "netdev-ssh-mcp.yaml", string(netdev))
	writeFile(t, profDir, "LICENSE", "not a profile\n")
	emptyDir := filepath.Join(dir, "empty")
	if err := os.MkdirAll(emptyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	badProf := filepath.Dir(writeFile(t, dir, "badprof/x.yaml", "server: x\ntools:\n  t: {class: NOT_A_CLASS, args: []}\n"))
	misnamed := filepath.Dir(writeFile(t, dir, "misnamed/netdev.yaml", string(netdev)))
	ymlDir := filepath.Dir(writeFile(t, dir, "yml/netdev-ssh-mcp.yml", string(netdev)))
	subDir := filepath.Join(dir, "sub")
	writeFile(t, subDir, "netdev-ssh-mcp.yaml", string(netdev))
	writeFile(t, subDir, "more/eos-mcp.yaml", "server: eos-mcp\n")
	badPol := writeFile(t, dir, "bad-policy.yaml", "version: 1\nrules:\n  - id: r\n    effect: allow\n    matchh: {}\n")
	twoDocs := writeFile(t, dir, "two-docs.yaml", "version: 1\nrules:\n  - {id: r, effect: deny}\n---\nversion: 1\nrules:\n  - {id: s, effect: allow}\n")
	holdDefault := writeFile(t, dir, "hold-default.yaml", "version: 1\ndefaults: {unknown_target: hold}\nrules:\n  - {id: r, effect: deny}\n")
	leaky := writeFile(t, dir, "leaky.yaml", "devices:\n  - name: a\n    role: core\n    password: FAKE-canary-inventory-pw\n")
	dupInv := writeFile(t, dir, "dup-inventory.yaml", "devices:\n  - {name: a, role: core}\n  - {name: A, role: core}\n")
	badPattern := writeFile(t, dir, "bad-pattern.yaml", "devices: [{name: a, role: core}]\nroles:\n  - {match: '(', role: x}\n")
	csvInv := writeFile(t, dir, "devices.CSV", "name,role\na,core\n")
	writablePol := writeFile(t, dir, "writable-policy.yaml", "version: 1\nrules:\n  - {id: r, effect: deny}\n")
	letOthersWrite(t, writablePol)
	writableInv := writeFile(t, dir, "writable-inventory.yaml", "devices: [{name: a, role: core}]\n")
	letOthersWrite(t, writableInv)
	writableProfDir := filepath.Join(dir, "writable-profiles")
	writeFile(t, writableProfDir, "netdev-ssh-mcp.yaml", string(netdev))
	letOthersWrite(t, writableProfDir)
	writableProfFile := filepath.Join(dir, "writable-profile-file")
	letOthersWrite(t, writeFile(t, writableProfFile, "netdev-ssh-mcp.yaml", string(netdev)))

	upstream := filepath.Join(dir, "fathomgate-no-such-upstream")
	base := []string{"--server", "netdev-ssh-mcp", "--upstream", upstream}
	with := func(extra ...string) []string { return append(slices.Clone(base), extra...) }
	for _, tc := range []struct {
		name string
		args []string
		code int
		want string
	}{
		{"neither", base, exitUsage, "--policy <file> or --no-policy is required"},
		{"both", with("--policy", pol, "--no-policy"), exitUsage, "cannot be used together"},
		{"audit", with("--policy", pol, "--audit", "a.jsonl"), exitUsage, "--audit arrives in M4"},
		{"policy twice", with("--policy", pol, "--policy", pol), exitUsage, "--policy is given more than once"},
		{"no-policy", with("--no-policy"), exitFail, noPolicyWarning},
		{"policy", with("--policy", pol), exitFail, "obligation=dry_run"},
		{"policy inventory", with("--policy", pol, "--inventory", inv), exitFail, "fathomgate: proxy: upstream netdev-ssh-mcp"},
		{"policy inventory profiles", with("--policy", pol, "--inventory", inv, "--profiles", profDir), exitFail, "fathomgate: proxy: upstream netdev-ssh-mcp"},
		{"policy missing", with("--policy", filepath.Join(dir, "missing.yaml")), exitUsage, "--policy: cannot open the policy file"},
		{"policy is a directory", with("--policy", dir), exitUsage, "is a directory"},
		{"policy unknown key", with("--policy", badPol), exitUsage, `unknown field "matchh"`},
		{"policy two documents", with("--policy", twoDocs), exitUsage, "2 YAML documents"},
		{"policy hold default", with("--policy", holdDefault), exitUsage, "hold is not allowed"},
		{"policy writable by others", with("--policy", writablePol), exitUsage, "--policy: the policy file"},
		{"inventory missing", with("--policy", pol, "--inventory", filepath.Join(dir, "missing.yaml")), exitUsage, "--inventory: cannot open the inventory file"},
		{"inventory unknown key", with("--policy", pol, "--inventory", leaky), exitUsage, "--inventory: " + leaky},
		{"inventory duplicate", with("--policy", pol, "--inventory", dupInv), exitUsage, "duplicate device"},
		{"inventory bad pattern", with("--policy", pol, "--inventory", badPattern), exitUsage, "roles[0]"},
		{"inventory csv", with("--policy", pol, "--inventory", csvInv), exitUsage, "fathomgate inventory import"},
		{"inventory writable by others", with("--policy", pol, "--inventory", writableInv), exitUsage, "--inventory: the inventory file"},
		{"profiles missing", with("--policy", pol, "--profiles", filepath.Join(dir, "missing")), exitUsage, "--profiles: cannot open the profiles directory"},
		{"profiles not a directory", with("--policy", pol, "--profiles", pol), exitUsage, "is not a directory"},
		{"profiles empty", with("--policy", pol, "--profiles", emptyDir), exitUsage, "holds no *.yaml profile"},
		{"profiles invalid", with("--policy", pol, "--profiles", badProf), exitUsage, `unknown class "NOT_A_CLASS"`},
		{"profiles misnamed", with("--policy", pol, "--profiles", misnamed), exitUsage, `netdev.yaml defines server "netdev-ssh-mcp"; a profile file is named after its server key, netdev-ssh-mcp.yaml`},
		{"profiles yml", with("--policy", pol, "--profiles", ymlDir), exitUsage, "profiles are named <server>.yaml; rename it"},
		{"profiles subdirectory", with("--policy", pol, "--profiles", subDir), exitUsage, "is a directory; profiles are read from the top level only"},
		{"profiles directory writable by others", with("--policy", pol, "--profiles", writableProfDir), exitUsage, "--profiles: the profiles directory"},
		{"profile file writable by others", with("--policy", pol, "--profiles", writableProfFile), exitUsage, "--profiles: the profile"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stderr lockedBuffer
			code := serveContext(context.Background(), tc.args, &stderr, noEnv)
			out := stderr.String()
			if code != tc.code {
				t.Fatalf("exit %d, want %d; stderr:\n%s", code, tc.code, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("stderr lacks %q:\n%s", tc.want, out)
			}
			if tc.code == exitUsage && strings.Contains(out, "fathomgate-no-such-upstream") {
				t.Fatalf("the upstream was started after a usage error:\n%s", out)
			}
			if strings.Contains(out, "FAKE-canary") {
				t.Fatalf("stderr quotes a file's content:\n%s", out)
			}
		})
	}
}

// TestEmbeddedProfilesAreTheRepo: the binary embeds exactly profiles/*.yaml
// of the source tree, byte for byte, and profiles/ holds no other profile
// file the embed pattern would miss (a .yml, or a profile in a
// subdirectory).
func TestEmbeddedProfilesAreTheRepo(t *testing.T) {
	t.Parallel()
	embedded, err := fs.Glob(profiles.FS(), "*")
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(repoPath("profiles"))
	if err != nil {
		t.Fatal(err)
	}
	var repo []string
	for _, e := range entries {
		name := e.Name()
		switch {
		case e.IsDir():
			t.Errorf("profiles/%s is a directory; the embedded set is the top level only", name)
		case strings.HasSuffix(name, ".yaml"):
			repo = append(repo, name)
		case strings.HasSuffix(name, ".yml"):
			t.Errorf("profiles/%s is not embedded: profiles are *.yaml", name)
		}
	}
	slices.Sort(embedded)
	slices.Sort(repo)
	if !slices.Equal(embedded, repo) || len(repo) == 0 {
		t.Fatalf("embedded %q, repo profiles/ %q", embedded, repo)
	}
	for _, name := range repo {
		want, err := os.ReadFile(repoPath("profiles", name))
		if err != nil {
			t.Fatal(err)
		}
		got, err := fs.ReadFile(profiles.FS(), name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("embedded %s differs from profiles/%s", name, name)
		}
	}
	set, err := configset.EmbeddedProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(set) != len(repo) {
		t.Fatalf("%d embedded profiles parsed, want %d", len(set), len(repo))
	}
	lines, err := embeddedProfileLines()
	if err != nil {
		t.Fatal(err)
	}
	for i, p := range set {
		if p.Name != p.Profile.Server+".yaml" {
			t.Errorf("%s holds server %q", p.Name, p.Profile.Server)
		}
		if !strings.Contains(lines[i], p.Profile.Server) || !strings.HasSuffix(lines[i], p.Name) || !strings.Contains(lines[i], "sha256:") {
			t.Errorf("version line %q for %s", lines[i], p.Name)
		}
	}
}

// TestProfilesReplaceNotMerge: --profiles replaces the embedded set (ADR
// 0027), so a server that is only in the embedded set has no profile, and
// is treated as an empty one: every argument is unnamed.
func TestProfilesReplaceNotMerge(t *testing.T) {
	t.Parallel()
	dir := configDir(t)
	copyRepoFile(t, dir, "profiles", "netdev-ssh-mcp.yaml")
	pf := pipelineFlags{policy: copyRepoFile(t, configDir(t), "policies", "examples", "read-only.yaml"), profiles: dir}
	pl, err := loadPipeline(pf, "netdev-ssh-mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got := attr(pl.attrs, "profile"); got != "netdev-ssh-mcp.yaml" {
		t.Errorf("profile = %v, want netdev-ssh-mcp.yaml", got)
	}
	if got := attr(pl.attrs, "profiles"); got != dir {
		t.Errorf("profiles = %v, want %s", got, dir)
	}
	if hasWarn(pl, noProfileWarning) {
		t.Errorf("unexpected missing-profile warning: %+v", pl.warns)
	}
	pl, err = loadPipeline(pf, "eos-mcp")
	if err != nil {
		t.Fatal(err)
	}
	w := findWarn(pl, noProfileWarning)
	if w == nil || attr(w.attrs, "servers_with_a_profile") != "netdev-ssh-mcp" {
		t.Errorf("eos-mcp is in the embedded set only, and --profiles replaces it: %+v", pl.warns)
	}
	if got := attr(pl.attrs, "profile"); got != noProfileValue {
		t.Errorf("profile = %v", got)
	}
	if named, closed := pl.gate.Arguments("eos-mcp", "run_command"); !closed || len(named) != 0 {
		t.Errorf("eos-mcp has no profile under --profiles, so every argument is unnamed: %v %v", named, closed)
	}
	if _, closed := pl.gate.Arguments("netdev-ssh-mcp", "run_show_command"); !closed {
		t.Error("netdev-ssh-mcp's profile from --profiles is not in the gate")
	}
}

// TestNoProfileServerDeniesArguments: the orchestrator decision of
// 2026-09-25 (ADR 0027 note). Under --policy, a --server with no profile
// (here `junos`, where the key is junos-mcp-server) is an empty profile:
// a call with any argument is default:bad_arguments, and the warning
// lists the keys that do exist.
func TestNoProfileServerDeniesArguments(t *testing.T) {
	t.Parallel()
	dir := configDir(t)
	pol := writeFile(t, dir, "open.yaml", "version: 1\ndefaults: {unknown_target: allow}\nrules:\n  - {id: everything, effect: allow}\n")
	pl, err := loadPipeline(pipelineFlags{policy: pol}, "junos")
	if err != nil {
		t.Fatal(err)
	}
	w := findWarn(pl, noProfileWarning)
	if w == nil || !strings.Contains(fmt.Sprint(attr(w.attrs, "servers_with_a_profile")), "junos-mcp-server") {
		t.Fatalf("warning %+v", pl.warns)
	}
	v := pl.gate.Decide(context.Background(), seam.CallInfo{Server: "junos", Tool: "load_and_commit_config", Arguments: json.RawMessage(`{"router_name":"core-rtr-01","config_text":"set system host-name x"}`)})
	if v.Forward || v.Effect != "deny" || v.RuleID != policy.RuleBadArguments || v.Class != "EXEC_ARBITRARY" || v.ClassSource != "fallback" {
		t.Fatalf("call with arguments: %+v", v)
	}
	// With no arguments the call reaches the rules as EXEC_ARBITRARY with
	// zero targets, and this policy's catch-all allow forwards it: the
	// empty profile refuses arguments, not tools. A policy with no-exec
	// denies it (internal/gate TestFallbackBrief02Gate).
	v = pl.gate.Decide(context.Background(), seam.CallInfo{Server: "junos", Tool: "get_router_list", Arguments: json.RawMessage(`{}`)})
	if !v.Forward || v.Effect != "allow" || v.RuleID != "everything" || v.Class != "EXEC_ARBITRARY" || v.ClassSource != "fallback" || len(v.Targets) != 0 {
		t.Fatalf("call without arguments: %+v", v)
	}
}

// TestObligationsPartitioned: every obligation the policy language knows is
// either carried on a forwarded call or cannot be met in M1, never both
// and never neither, so the start-up warnings cover each one (Go review
// of PR #171, item 2).
func TestObligationsPartitioned(t *testing.T) {
	t.Parallel()
	for _, o := range policy.KnownObligations {
		_, carried := carriedUntil[o]
		if carried == slices.Contains(cannotMeet, o) {
			t.Errorf("obligation %s: carried %v, cannot be met %v", o, carried, !carried)
		}
	}
	for o := range carriedUntil {
		if !slices.Contains(policy.KnownObligations, o) {
			t.Errorf("carried obligation %s is not in policy.KnownObligations", o)
		}
	}
	for _, o := range cannotMeet {
		if !slices.Contains(policy.KnownObligations, o) {
			t.Errorf("cannot-be-met obligation %s is not in policy.KnownObligations", o)
		}
	}
}

func attr(attrs []any, key string) any {
	for i := 0; i+1 < len(attrs); i += 2 {
		if attrs[i] == key {
			return attrs[i+1]
		}
	}
	return nil
}

func findWarn(pl *pipeline, msg string) *warnLine {
	for i := range pl.warns {
		if pl.warns[i].msg == msg {
			return &pl.warns[i]
		}
	}
	return nil
}

func hasWarn(pl *pipeline, msg string) bool { return findWarn(pl, msg) != nil }

// TestLoadPipelineStartup: the start-up line's attributes and every
// start-up warning (ADR 0027, ADR 0031 decision 5, ADR 0032 point 7).
func TestLoadPipelineStartup(t *testing.T) {
	t.Parallel()
	t.Run("prod-approval", func(t *testing.T) {
		t.Parallel()
		dir := configDir(t)
		pol := copyRepoFile(t, dir, "policies", "examples", "prod-approval.yaml")
		inv := copyRepoFile(t, dir, "inventory.example.yaml")
		pl, err := loadPipeline(pipelineFlags{policy: pol, inventory: inv}, "netdev-ssh-mcp")
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]any{"policy": pol, "rules": 5, "inventory": inv, "profiles": "embedded", "profile": "netdev-ssh-mcp.yaml"}
		for k, v := range want {
			if got := attr(pl.attrs, k); got != v {
				t.Errorf("%s = %v, want %v", k, got, v)
			}
		}
		if n, ok := attr(pl.attrs, "devices").(int); !ok || n == 0 {
			t.Errorf("devices = %v", attr(pl.attrs, "devices"))
		}
		msgs := make([]string, 0, len(pl.warns))
		for _, w := range pl.warns {
			msgs = append(msgs, fmt.Sprint(w.msg, " ", w.attrs))
		}
		wantWarns := []string{
			cannotMeetWarning + " [obligation dry_run rules lab-writes-free]",
			cannotMeetWarning + " [obligation diff rules lab-writes-free]",
			holdWarning + " [rules prod-core-needs-approval]",
		}
		if !slices.Equal(msgs, wantWarns) {
			t.Errorf("warnings\n%q\nwant\n%q", msgs, wantWarns)
		}
	})
	t.Run("every warning", func(t *testing.T) {
		t.Parallel()
		dir := configDir(t)
		pol := writeFile(t, dir, "p.yaml", `version: 1
defaults: {unknown_target: allow}
rules:
  - {id: reads, match: {class: [READ_OPERATIONAL]}, effect: allow, obligations: [notify, redact]}
  - {id: tickets, match: {class: [WRITE_CONFIG]}, effect: allow, obligations: [require_ticket, canary_first, timed_rollback]}
  - {id: held, match: {class: [LAB_LIFECYCLE]}, effect: hold, obligations: [diff]}
  - {id: denied, effect: deny, obligations: [notify]}
`)
		inv := writeFile(t, dir, "i.yaml", "devices: [{name: core-1, role: core}]\nroles:\n  - {match: '^core-', tags: [prod]}\n  - {match: '^fw-', role: firewall}\n")
		pl, err := loadPipeline(pipelineFlags{policy: pol, inventory: inv}, "no-such-server")
		if err != nil {
			t.Fatal(err)
		}
		msgs := make([]string, 0, len(pl.warns))
		for _, w := range pl.warns {
			msgs = append(msgs, fmt.Sprint(w.msg, " ", w.attrs))
		}
		set, err := configset.EmbeddedProfiles()
		if err != nil {
			t.Fatal(err)
		}
		keys := make([]string, 0, len(set))
		for _, p := range set {
			keys = append(keys, p.Profile.Server)
		}
		wantWarns := []string{
			`inventory: roles[1] "^fw-" matches no listed device and makes nothing known (ADR 0031); list the device under devices [inventory ` + inv + `]`,
			noProfileWarning + " [server no-such-server profiles embedded servers_with_a_profile " + strings.Join(keys, ",") + "]",
			unknownTargetAllowWarning + " [policy " + pol + "]",
			cannotMeetWarning + " [obligation timed_rollback rules tickets]",
			carriedWarning + " [obligation redact rules reads enforced_from M2]",
			carriedWarning + " [obligation canary_first rules tickets enforced_from M4]",
			carriedWarning + " [obligation require_ticket rules tickets enforced_from M4]",
			carriedWarning + " [obligation notify rules reads enforced_from M4]",
			holdWarning + " [rules held]",
		}
		if !slices.Equal(msgs, wantWarns) {
			t.Errorf("warnings\n%s\nwant\n%s", strings.Join(msgs, "\n"), strings.Join(wantWarns, "\n"))
		}
		if got := attr(pl.attrs, "profile"); got != noProfileValue {
			t.Errorf("profile = %v", got)
		}
		if !strings.HasPrefix(unknownTargetAllowWarning, unknownTargetAllowLint) {
			t.Error("the unknown_target warning must start with policy-lint's text")
		}
	})
	t.Run("no inventory", func(t *testing.T) {
		t.Parallel()
		pol := writeFile(t, configDir(t), "p.yaml", "version: 1\nrules:\n  - {id: r, effect: deny}\n")
		pl, err := loadPipeline(pipelineFlags{policy: pol}, "netdev-ssh-mcp")
		if err != nil {
			t.Fatal(err)
		}
		if len(pl.warns) != 1 || pl.warns[0].msg != noInventoryWarning {
			t.Errorf("warnings %+v", pl.warns)
		}
		if got := attr(pl.attrs, "inventory"); got != noInventoryValue {
			t.Errorf("inventory = %v", got)
		}
	})
	t.Run("no inventory, unknown_target allow", func(t *testing.T) {
		t.Parallel()
		pol := writeFile(t, configDir(t), "p.yaml", "version: 1\ndefaults: {unknown_target: allow}\nrules:\n  - {id: r, effect: deny}\n")
		pl, err := loadPipeline(pipelineFlags{policy: pol}, "netdev-ssh-mcp")
		if err != nil {
			t.Fatal(err)
		}
		if hasWarn(pl, noInventoryWarning) || !hasWarn(pl, unknownTargetAllowWarning) {
			t.Errorf("warnings %+v", pl.warns)
		}
	})
	t.Run("no-policy", func(t *testing.T) {
		t.Parallel()
		pl, err := loadPipeline(pipelineFlags{noPolicy: true}, "netdev-ssh-mcp")
		if err != nil {
			t.Fatal(err)
		}
		if pl.gate != nil || attr(pl.attrs, "policy") != noPolicyValue || len(pl.warns) != 1 || pl.warns[0].msg != noPolicyWarning {
			t.Fatalf("pipeline %+v", pl)
		}
	})
}

// netdevCalls counts the calls runNetdevUpstream answered, in its process.
var netdevCalls atomic.Int64

// runNetdevUpstream serves a go-sdk stdio upstream with one tool shaped
// like netdev-ssh-mcp's run_show_command. Its answer carries a call count,
// so the agent can tell which calls reached it.
func runNetdevUpstream() {
	s := mcp.NewServer(&mcp.Implementation{Name: "fake-netdev", Version: "0"}, nil)
	schema := map[string]any{"type": "object", "properties": map[string]any{
		"host":     map[string]any{"type": "string"},
		"command":  map[string]any{"type": "string"},
		"username": map[string]any{"type": "string"},
	}, "required": []any{"host", "command"}}
	s.AddTool(&mcp.Tool{Name: "run_show_command", InputSchema: schema}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		n := netdevCalls.Add(1)
		var args map[string]any
		_ = json.Unmarshal(req.Params.Arguments, &args)
		b, _ := json.Marshal(args)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("call %d %s", n, b)}}}, nil
	})
	_ = s.Run(context.Background(), &mcp.StdioTransport{})
}

// serveTestArgsEnv carries the serve arguments to runFathomgateChild.
const serveTestArgsEnv = "SERVE_TEST_ARGS"

// runFathomgateChild runs `fathomgate serve` in this test binary, with the
// arguments in SERVE_TEST_ARGS (a JSON list), for the stdio end-to-end
// test: stdin and stdout are the agent's.
func runFathomgateChild() {
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv(serveTestArgsEnv)), &args); err != nil {
		fmt.Fprintln(os.Stderr, "SERVE_TEST_ARGS:", err)
		os.Exit(2)
	}
	os.Exit(run(append([]string{"serve"}, args...)))
}

// textOf is the first text block of a result, or "" (checked indexing).
func textOf(res *mcp.CallToolResult) string {
	if res == nil || len(res.Content) == 0 {
		return ""
	}
	if tc, ok := res.Content[0].(*mcp.TextContent); ok {
		return tc.Text
	}
	return ""
}

// e2eCases are the calls TestServePolicyEndToEnd makes, in order, against
// prod-approval.yaml and inventory.example.yaml.
var e2eCases = []struct {
	args    map[string]any
	text    string
	isError bool
}{
	{map[string]any{"host": "core-rtr-01", "command": "show version"}, `call 1 {"command":"show version","host":"core-rtr-01"}`, false},
	{map[string]any{"host": "core-rtr-01", "command": "reload"}, "fathomgate denied netdev-ssh-mcp.run_show_command: rule no-exec (class EXEC_ARBITRARY): EXEC_ARBITRARY is denied: the call runs commands outside the read allow-list or outside configuration mode", true},
	{map[string]any{"host": "core-x.attacker.example", "command": "show version"}, "fathomgate denied netdev-ssh-mcp.run_show_command: rule default:unknown_target (class READ_OPERATIONAL): target not in inventory", true},
	{map[string]any{"host": "core-rtr-01", "command": "show version", "username": "FAKE-admin"}, "fathomgate denied netdev-ssh-mcp.run_show_command: rule default:bad_arguments", true},
	{map[string]any{"host": "core-rtr-02", "command": "show ip bgp summary"}, `call 2 {"command":"show ip bgp summary","host":"core-rtr-02"}`, false},
}

// runE2ECases makes the e2eCases calls on cs and checks the tool list.
func runE2ECases(ctx context.Context, t *testing.T, cs *mcp.ClientSession) {
	t.Helper()
	for tool, err := range cs.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		if tool.Name != "netdev-ssh-mcp.run_show_command" {
			t.Fatalf("tool %q", tool.Name)
		}
		b, _ := json.Marshal(tool.InputSchema)
		if strings.Contains(string(b), "username") {
			t.Errorf("advertised schema keeps an argument the profile refuses: %s", b)
		}
	}
	for _, tc := range e2eCases {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: tc.args})
		if err != nil {
			t.Fatalf("tools/call %v: %v", tc.args, err)
		}
		text := textOf(res)
		if res.IsError != tc.isError || !strings.HasPrefix(text, tc.text) {
			t.Errorf("%v: isError %v %q, want %v %q", tc.args, res.IsError, text, tc.isError, tc.text)
		}
		if strings.Contains(text, "attacker") {
			t.Errorf("the tool error quotes the target: %q", text)
		}
	}
}

// checkE2ELog checks the start-up line and the decision lines.
func checkE2ELog(t *testing.T, log, pol, inv string) {
	t.Helper()
	for _, kv := range [][2]string{{"policy", pol}, {"rules", "5"}, {"inventory", inv}, {"profiles", "embedded"}, {"profile", "netdev-ssh-mcp.yaml"}} {
		if !strings.Contains(log, kv[0]+"="+kv[1]) && !strings.Contains(log, fmt.Sprintf("%s=%q", kv[0], kv[1])) {
			t.Errorf("start-up line lacks %s=%s:\n%s", kv[0], kv[1], log)
		}
	}
	if n := strings.Count(log, "msg=decision"); n != len(e2eCases) {
		t.Errorf("%d decision lines, want %d:\n%s", n, len(e2eCases), log)
	}
	for _, want := range []string{"rule_id=reads-anywhere", "rule_id=no-exec", "rule_id=default:unknown_target", "rule_id=default:bad_arguments"} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %s:\n%s", want, log)
		}
	}
	checkNoCanary(t, "stderr", log)
}

// TestServePolicyEndToEnd: `fathomgate serve --policy prod-approval.yaml
// --inventory inventory.example.yaml` in front of a real upstream process,
// with the embedded profiles: over the loopback listener for an agent in
// each era, and over stdio with fathomgate itself a child process (M2 in
// the security review of PR #171). A show command on a listed device is
// allowed and forwarded; a reload is denied by no-exec, an unknown host by
// default:unknown_target, and an argument the profile does not name by
// default:bad_arguments, each with the ADR 0026 tool error text and
// nothing sent upstream (the upstream's call count shows it). The start-up
// line names what loaded.
func TestServePolicyEndToEnd(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := configDir(t)
	pol := copyRepoFile(t, dir, "policies", "examples", "prod-approval.yaml")
	inv := copyRepoFile(t, dir, "inventory.example.yaml")
	serveArgs := []string{
		"--server", "netdev-ssh-mcp", "--upstream", exe,
		"--policy", pol, "--inventory", inv,
		"--upstream-env", serveTestUpstreamEnv + "=netdev",
		"--upstream-env", "GORACE=atexit_sleep_ms=0",
	}
	for _, era := range []string{"2025-11-25", "2026-07-28"} {
		t.Run("http "+era, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var stderr lockedBuffer
			done := make(chan int, 1)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				done <- serveContext(ctx, append(slices.Clone(serveArgs), "--listen", "127.0.0.1:0", "--", "-test.run=^$"),
					&stderr, envMap(map[string]string{listenTokenEnv: testListenToken}))
			}()
			// Whatever happens below, serve is stopped and waited for.
			t.Cleanup(func() {
				cancel()
				select {
				case <-finished:
				case <-time.After(2 * shutdownGrace):
					t.Error("serve did not return")
				}
			})
			url := waitListening(t, &stderr, done)
			cs, tr := agentOver(t, url, testListenToken, era)
			defer tr.CloseIdleConnections()
			runE2ECases(ctx, t, cs)
			_ = cs.Close()
			cancel()
			if code := exitWithin(t, done, 2*shutdownGrace); code != exitOK {
				t.Fatalf("exit %d:\n%s", code, stderr.String())
			}
			checkE2ELog(t, stderr.String(), pol, inv)
		})
	}
	t.Run("stdio", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		args, err := json.Marshal(append(slices.Clone(serveArgs), "--", "-test.run=^$"))
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, exe)
		cmd.Env = append(os.Environ(), serveTestUpstreamEnv+"=fathomgate", serveTestArgsEnv+"="+string(args), "GORACE=atexit_sleep_ms=0")
		var stderr lockedBuffer
		cmd.Stderr = &stderr
		client := mcp.NewClient(&mcp.Implementation{Name: "e2e-stdio", Version: "0"}, nil)
		cs, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
		if err != nil {
			t.Fatalf("connect: %v\n%s", err, stderr.String())
		}
		runE2ECases(ctx, t, cs)
		// Closing the session closes fathomgate's stdin: it stops its
		// upstream and exits 0.
		if err := cs.Close(); err != nil {
			t.Logf("close: %v", err)
		}
		if code := cmd.ProcessState.ExitCode(); code != exitOK {
			t.Errorf("fathomgate exit %d:\n%s", code, stderr.String())
		}
		log := stderr.String()
		if !strings.Contains(log, `msg="serving on stdio"`) {
			t.Errorf("no stdio start-up line:\n%s", log)
		}
		checkE2ELog(t, log, pol, inv)
	})
}
