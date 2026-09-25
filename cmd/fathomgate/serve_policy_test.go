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
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fathomgate/fathomgate/profiles"
)

// TestParseServePipelineFlags: every combination of --policy, --no-policy,
// --inventory and --profiles (ADR 0027). The pipeline flags are checked
// after every other usage error, and name flags only.
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
		{"policy inventory profiles", with("--policy", "p.yaml", "--inventory", "i.yaml", "--profiles", "d"), "", pipelineFlags{policy: "p.yaml", inventory: "i.yaml", profiles: "d"}},
		{"both", with("--policy", "p.yaml", "--no-policy"), "--policy and --no-policy cannot be used together", pipelineFlags{}},
		{"no-policy with inventory", with("--no-policy", "--inventory", "i.yaml"), "--inventory only configure a policy; --no-policy forwards", pipelineFlags{}},
		{"no-policy with both", with("--no-policy", "--inventory", "i.yaml", "--profiles", "d"), "--inventory and --profiles only configure a policy", pipelineFlags{}},
		{"inventory alone", with("--inventory", "i.yaml"), "--inventory only work with --policy <file>", pipelineFlags{}},
		{"profiles alone", with("--profiles", "d"), "--profiles only work with --policy <file>", pipelineFlags{}},
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
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestServePipelineExitCodes runs serve as the binary would, with an
// upstream that does not exist. A file that does not load is exit 2 before
// the upstream is started (stderr never mentions it); a set that loads gets
// as far as starting the upstream, which fails with exit 1.
func TestServePipelineExitCodes(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	pol := repoPath("policies", "examples", "prod-approval.yaml")
	inv := repoPath("inventory.example.yaml")
	profDir := filepath.Join(dir, "profiles")
	if err := os.MkdirAll(profDir, 0o755); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(repoPath("profiles", "netdev-ssh-mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, profDir, "netdev-ssh-mcp.yaml", string(b))
	emptyDir := filepath.Join(dir, "empty")
	if err := os.MkdirAll(emptyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	badProf := filepath.Dir(writeFile(t, dir, "badprof/x.yaml", "server: x\ntools:\n  t: {class: NOT_A_CLASS, args: []}\n"))
	dupProf := filepath.Join(dir, "dupprof")
	writeFile(t, dupProf, "a.yaml", string(b))
	writeFile(t, dupProf, "b.yaml", string(b))
	badPol := writeFile(t, dir, "bad-policy.yaml", "version: 1\nrules:\n  - id: r\n    effect: allow\n    matchh: {}\n")
	holdDefault := writeFile(t, dir, "hold-default.yaml", "version: 1\ndefaults: {unknown_target: hold}\nrules:\n  - {id: r, effect: deny}\n")
	badInv := writeFile(t, dir, "bad-inventory.yaml", "devicez: []\n")
	dupInv := writeFile(t, dir, "dup-inventory.yaml", "devices:\n  - {name: a, role: core}\n  - {name: A, role: core}\n")
	badPattern := writeFile(t, dir, "bad-pattern.yaml", "devices: [{name: a, role: core}]\nroles:\n  - {match: '(', role: x}\n")
	csvInv := writeFile(t, dir, "devices.CSV", "name,role\na,core\n")

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
		{"no-policy", with("--no-policy"), exitFail, "--no-policy: every call is forwarded to the upstream unchecked"},
		{"policy", with("--policy", pol), exitFail, "obligation=dry_run"},
		{"policy inventory", with("--policy", pol, "--inventory", inv), exitFail, "fathomgate: proxy: upstream netdev-ssh-mcp"},
		{"policy inventory profiles", with("--policy", pol, "--inventory", inv, "--profiles", profDir), exitFail, "fathomgate: proxy: upstream netdev-ssh-mcp"},
		{"policy missing", with("--policy", filepath.Join(dir, "missing.yaml")), exitUsage, "--policy: policy: read:"},
		{"policy is a directory", with("--policy", dir), exitUsage, "--policy: policy: read:"},
		{"policy unknown key", with("--policy", badPol), exitUsage, "--policy: " + badPol},
		{"policy hold default", with("--policy", holdDefault), exitUsage, "hold is not allowed"},
		{"inventory missing", with("--policy", pol, "--inventory", filepath.Join(dir, "missing.yaml")), exitUsage, "--inventory: inventory: read:"},
		{"inventory unknown key", with("--policy", pol, "--inventory", badInv), exitUsage, "--inventory: " + badInv},
		{"inventory duplicate", with("--policy", pol, "--inventory", dupInv), exitUsage, "duplicate device"},
		{"inventory bad pattern", with("--policy", pol, "--inventory", badPattern), exitUsage, "roles[0]"},
		{"inventory csv", with("--policy", pol, "--inventory", csvInv), exitUsage, "fathomgate inventory import"},
		{"profiles missing", with("--policy", pol, "--profiles", filepath.Join(dir, "missing")), exitUsage, "--profiles: "},
		{"profiles not a directory", with("--policy", pol, "--profiles", pol), exitUsage, "is not a directory"},
		{"profiles empty", with("--policy", pol, "--profiles", emptyDir), exitUsage, "holds no *.yaml profile"},
		{"profiles invalid", with("--policy", pol, "--profiles", badProf), exitUsage, `unknown class "NOT_A_CLASS"`},
		{"profiles duplicate", with("--policy", pol, "--profiles", dupProf), exitUsage, `a.yaml and b.yaml both define server "netdev-ssh-mcp"`},
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
		})
	}
}

// TestEmbeddedProfilesAreTheRepo: the binary embeds exactly profiles/*.yaml
// of the source tree, byte for byte, and profiles/ holds no other profile
// file the embed pattern would miss (a .yml, or a profile in a
// subdirectory).
func TestEmbeddedProfilesAreTheRepo(t *testing.T) {
	t.Parallel()
	embedded, err := fs.Glob(profiles.FS, "*")
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
		got, err := fs.ReadFile(profiles.FS, name)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("embedded %s differs from profiles/%s", name, name)
		}
	}
	set, err := embeddedProfiles()
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
		if !strings.Contains(lines[i], p.profile.Server) || !strings.HasSuffix(lines[i], p.name) || !strings.Contains(lines[i], "sha256:") {
			t.Errorf("version line %q for %s", lines[i], p.name)
		}
	}
}

// TestProfilesReplaceNotMerge: --profiles replaces the embedded set (ADR
// 0027), so a server that is only in the embedded set has no profile.
func TestProfilesReplaceNotMerge(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	b, err := os.ReadFile(repoPath("profiles", "netdev-ssh-mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, dir, "mine.yaml", string(b))
	pf := pipelineFlags{policy: repoPath("policies", "examples", "read-only.yaml"), profiles: dir}
	pl, err := loadPipeline(pf, "netdev-ssh-mcp")
	if err != nil {
		t.Fatal(err)
	}
	if got := attr(pl.attrs, "profile"); got != "mine.yaml" {
		t.Errorf("profile = %v, want mine.yaml", got)
	}
	if got := attr(pl.attrs, "profiles"); got != dir {
		t.Errorf("profiles = %v, want %s", got, dir)
	}
	if hasWarn(pl, "no profile for this server") {
		t.Errorf("unexpected missing-profile warning: %+v", pl.warns)
	}
	pl, err = loadPipeline(pf, "eos-mcp")
	if err != nil {
		t.Fatal(err)
	}
	if !hasWarn(pl, "no profile for this server: its calls take the fallback classifier, and their arguments are not checked") {
		t.Errorf("eos-mcp is in the embedded set only, and --profiles replaces it: %+v", pl.warns)
	}
	if got := attr(pl.attrs, "profile"); got != "none (fallback classifier)" {
		t.Errorf("profile = %v", got)
	}
	if pl.gate == nil {
		t.Fatal("no gate")
	}
	if _, closed := pl.gate.Arguments("eos-mcp", "run_command"); closed {
		t.Error("eos-mcp has no profile under --profiles, so its arguments are not closed")
	}
	if _, closed := pl.gate.Arguments("netdev-ssh-mcp", "run_show_command"); !closed {
		t.Error("netdev-ssh-mcp's profile from --profiles is not in the gate")
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

func hasWarn(pl *pipeline, msg string) bool {
	return slices.ContainsFunc(pl.warns, func(w warnLine) bool { return w.msg == msg })
}

// TestLoadPipelineStartup: the start-up line's attributes and every
// start-up warning (ADR 0027, ADR 0031 decision 5, ADR 0032 point 7).
func TestLoadPipelineStartup(t *testing.T) {
	t.Parallel()
	t.Run("prod-approval", func(t *testing.T) {
		t.Parallel()
		pol := repoPath("policies", "examples", "prod-approval.yaml")
		inv := repoPath("inventory.example.yaml")
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
			"obligation cannot be met yet: a call these rules allow is not run, and the agent is told why [obligation dry_run rules lab-writes-free]",
			"obligation cannot be met yet: a call these rules allow is not run, and the agent is told why [obligation diff rules lab-writes-free]",
			"hold is not run yet: approvals arrive in M3, and until then the agent is told the call needs approval [rules prod-core-needs-approval]",
		}
		if !slices.Equal(msgs, wantWarns) {
			t.Errorf("warnings\n%q\nwant\n%q", msgs, wantWarns)
		}
	})
	t.Run("every warning", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
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
		wantWarns := []string{
			`inventory: roles[1] "^fw-": matches no listed device [inventory ` + inv + `]`,
			"no profile for this server: its calls take the fallback classifier, and their arguments are not checked [server no-such-server profiles embedded]",
			unknownTargetAllowWarning + " [policy " + pol + "]",
			"obligation cannot be met yet: a call these rules allow is not run, and the agent is told why [obligation timed_rollback rules tickets]",
			"obligation not enforced yet: a call these rules allow is forwarded without it [obligation redact rules reads enforced_from M2]",
			"obligation not enforced yet: a call these rules allow is forwarded without it [obligation canary_first rules tickets enforced_from M4]",
			"obligation not enforced yet: a call these rules allow is forwarded without it [obligation require_ticket rules tickets enforced_from M4]",
			"obligation not enforced yet: a call these rules allow is forwarded without it [obligation notify rules reads enforced_from M4]",
			"hold is not run yet: approvals arrive in M3, and until then the agent is told the call needs approval [rules held]",
		}
		if !slices.Equal(msgs, wantWarns) {
			t.Errorf("warnings\n%s\nwant\n%s", strings.Join(msgs, "\n"), strings.Join(wantWarns, "\n"))
		}
		if got := attr(pl.attrs, "profile"); got != "none (fallback classifier)" {
			t.Errorf("profile = %v", got)
		}
	})
	t.Run("unset unknown_target is not warned", func(t *testing.T) {
		t.Parallel()
		pol := writeFile(t, t.TempDir(), "p.yaml", "version: 1\nrules:\n  - {id: r, effect: deny}\n")
		pl, err := loadPipeline(pipelineFlags{policy: pol}, "netdev-ssh-mcp")
		if err != nil {
			t.Fatal(err)
		}
		if len(pl.warns) != 0 {
			t.Errorf("warnings %+v", pl.warns)
		}
		if got := attr(pl.attrs, "inventory"); got != "none (every target is unknown)" {
			t.Errorf("inventory = %v", got)
		}
	})
	t.Run("no-policy", func(t *testing.T) {
		t.Parallel()
		pl, err := loadPipeline(pipelineFlags{noPolicy: true}, "netdev-ssh-mcp")
		if err != nil {
			t.Fatal(err)
		}
		if pl.gate != nil || attr(pl.attrs, "policy") != noPolicyValue || len(pl.warns) != 1 {
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

// TestServePolicyEndToEnd: `fathomgate serve --policy prod-approval.yaml
// --inventory inventory.example.yaml` in front of a real upstream process,
// with the embedded profiles, over the loopback listener, for an agent in
// each era. A show command on a listed device is allowed and forwarded; a
// reload is denied by no-exec, an unknown host by default:unknown_target,
// and an argument the profile does not name by default:bad_arguments, each
// with the ADR 0026 tool error text and nothing sent upstream (the
// upstream's call count shows it). The start-up line names what loaded.
func TestServePolicyEndToEnd(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pol := repoPath("policies", "examples", "prod-approval.yaml")
	inv := repoPath("inventory.example.yaml")
	for _, era := range []string{"2025-11-25", "2026-07-28"} {
		t.Run(era, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var stderr lockedBuffer
			done := make(chan int, 1)
			go func() {
				done <- serveContext(ctx, []string{
					"--server", "netdev-ssh-mcp", "--upstream", exe,
					"--policy", pol, "--inventory", inv,
					"--upstream-env", serveTestUpstreamEnv + "=netdev",
					"--upstream-env", "GORACE=atexit_sleep_ms=0",
					"--listen", "127.0.0.1:0",
					"--", "-test.run=^$",
				}, &stderr, envMap(map[string]string{listenTokenEnv: testListenToken}))
			}()
			url := waitListening(t, &stderr, done)
			log := stderr.String()
			for _, want := range []string{
				"policy=" + pol, "rules=5", "inventory=" + inv, "profiles=embedded", "profile=netdev-ssh-mcp.yaml",
			} {
				if !strings.Contains(log, want) && !strings.Contains(log, fmt.Sprintf("%s=%q", strings.SplitN(want, "=", 2)[0], strings.SplitN(want, "=", 2)[1])) {
					t.Errorf("listening line lacks %s:\n%s", want, log)
				}
			}

			cs, tr := agentOver(t, url, testListenToken, era)
			defer tr.CloseIdleConnections()
			defer func() { _ = cs.Close() }()
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
			call := func(args map[string]any) (string, bool) {
				t.Helper()
				res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: args})
				if err != nil {
					t.Fatalf("tools/call %v: %v", args, err)
				}
				return res.Content[0].(*mcp.TextContent).Text, res.IsError
			}
			for _, tc := range []struct {
				args    map[string]any
				text    string
				isError bool
			}{
				{map[string]any{"host": "core-rtr-01", "command": "show version"}, `call 1 {"command":"show version","host":"core-rtr-01"}`, false},
				{map[string]any{"host": "core-rtr-01", "command": "reload"}, "fathomgate denied netdev-ssh-mcp.run_show_command: rule no-exec (class EXEC_ARBITRARY): command did not pass the read allow-list", true},
				{map[string]any{"host": "core-x.attacker.example", "command": "show version"}, "fathomgate denied netdev-ssh-mcp.run_show_command: rule default:unknown_target (class READ_OPERATIONAL)", true},
				{map[string]any{"host": "core-rtr-01", "command": "show version", "username": "FAKE-admin"}, "fathomgate denied netdev-ssh-mcp.run_show_command: rule default:bad_arguments", true},
				{map[string]any{"host": "core-rtr-02", "command": "show ip bgp summary"}, `call 2 {"command":"show ip bgp summary","host":"core-rtr-02"}`, false},
			} {
				text, isError := call(tc.args)
				if isError != tc.isError || !strings.HasPrefix(text, tc.text) {
					t.Errorf("%v: isError %v %q, want %v %q", tc.args, isError, text, tc.isError, tc.text)
				}
				if strings.Contains(text, "attacker") {
					t.Errorf("the tool error quotes the target: %q", text)
				}
			}
			cancel()
			if code := exitWithin(t, done, 2*shutdownGrace); code != exitOK {
				t.Fatalf("exit %d:\n%s", code, stderr.String())
			}
			log = stderr.String()
			if n := strings.Count(log, "msg=decision"); n != 5 {
				t.Errorf("%d decision lines, want 5:\n%s", n, log)
			}
			for _, want := range []string{"rule_id=reads-anywhere", "rule_id=no-exec", "rule_id=default:unknown_target", "rule_id=default:bad_arguments"} {
				if !strings.Contains(log, want) {
					t.Errorf("log lacks %s:\n%s", want, log)
				}
			}
			checkNoCanary(t, "stderr", log)
		})
	}
}
