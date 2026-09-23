package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/joshscott13/netguard/internal/audit"
)

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

func TestRunDispatch(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"no args", nil, exitUsage},
		{"version", []string{"version"}, exitOK},
		{"help", []string{"help"}, exitOK},
		{"unknown", []string{"bogus"}, exitUsage},
		{"serve without flags", []string{"serve"}, exitUsage},
		{"serve without upstream", []string{"serve", "--server", "netdev-ssh-mcp"}, exitUsage},
		{"serve refuses policy in M0", []string{"serve", "--server", "netdev-ssh-mcp", "--upstream", "x", "--policy", "p.yaml"}, exitUsage},
		{"serve refuses audit in M0", []string{"serve", "--audit", "a.jsonl"}, exitUsage},
		{"serve bad upstream env", []string{"serve", "--server", "netdev-ssh-mcp", "--upstream", "x", "--upstream-env", "NOEQUALS"}, exitUsage},
		{"serve upstream missing", []string{"serve", "--server", "netdev-ssh-mcp", "--upstream", "netguard-no-such-upstream-binary"}, exitFail},
		{"serve bad server name", []string{"serve", "--server", "net.dev", "--upstream", "netguard-no-such-upstream-binary"}, exitFail},
		{"policy no sub", []string{"policy"}, exitUsage},
		{"policy bad sub", []string{"policy", "frobnicate"}, exitUsage},
		{"audit no sub", []string{"audit"}, exitUsage},
		{"inventory no sub", []string{"inventory"}, exitUsage},
		{"policy test no files", []string{"policy", "test"}, exitUsage},
		{"policy eval missing policy", []string{"policy", "eval", "--class", "READ_CONFIG"}, exitUsage},
		{"redact missing key", []string{"redact"}, exitUsage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := run(tc.args); got != tc.want {
				t.Fatalf("run(%v) = %d, want %d", tc.args, got, tc.want)
			}
		})
	}
}

func TestPolicyTestExamples(t *testing.T) {
	files, err := filepath.Glob(repoPath("policies", "examples", "*.test.yaml"))
	if err != nil || len(files) == 0 {
		t.Skip("no example test files")
	}
	if got := run(append([]string{"policy", "test", "-v"}, files...)); got != exitOK {
		t.Fatalf("policy test exit %d", got)
	}

	// A failing case must exit 1.
	dir := t.TempDir()
	bad := "policy: " + filepath.ToSlash(mustAbs(t, repoPath("policies", "examples", "read-only.yaml"))) + "\n" +
		"cases:\n  - name: wrong\n    request: {class: WRITE_CONFIG, targets: [{name: x}]}\n    expect: {effect: allow}\n"
	bp := filepath.Join(dir, "bad.test.yaml")
	if err := os.WriteFile(bp, []byte(bad), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"policy", "test", bp}); got != exitFail {
		t.Fatalf("failing case exit %d, want %d", got, exitFail)
	}
	if got := run([]string{"policy", "test", filepath.Join(dir, "missing.test.yaml")}); got != exitUsage {
		t.Fatalf("missing file exit %d, want %d", got, exitUsage)
	}
}

func TestPolicyEvalExitCodes(t *testing.T) {
	pol := repoPath("policies", "examples", "prod-approval.yaml")
	inv := repoPath("inventory.example.yaml")
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"allow", []string{"--class", "READ_OPERATIONAL", "--target", "core-rtr-01"}, exitOK},
		{"hold", []string{"--class", "WRITE_CONFIG", "--target", "core-rtr-01"}, exitHold},
		{"deny exec", []string{"--class", "EXEC_ARBITRARY", "--target", "core-rtr-01", "--json"}, exitFail},
		{"deny unknown", []string{"--class", "READ_OPERATIONAL", "--target", "ghost"}, exitFail},
		{"bad class", []string{"--class", "NOPE"}, exitUsage},
		{"profile classifies show", []string{"--profile", repoPath("profiles", "eos-mcp.yaml"), "--tool", "run_command", "--arg", "hostname=lab-leaf-01", "--arg", "command=show version"}, exitOK},
		{"profile classifies reload", []string{"--profile", repoPath("profiles", "eos-mcp.yaml"), "--tool", "run_command", "--arg", "hostname=lab-leaf-01", "--arg", "command=reload"}, exitFail},
		{"profile unknown tool", []string{"--profile", repoPath("profiles", "eos-mcp.yaml"), "--tool", "nope", "--arg", "hostname=lab-leaf-01"}, exitFail},
		{"no class no profile", []string{"--tool", "x"}, exitUsage},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"policy", "eval", "--policy", pol, "--inventory", inv}, tc.args...)
			if got := run(args); got != tc.want {
				t.Fatalf("exit %d, want %d", got, tc.want)
			}
		})
	}
}

func TestAuditVerifyAndKeygen(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "audit.key")
	if got := run([]string{"audit", "keygen", "--out", key}); got != exitOK {
		t.Fatalf("keygen exit %d", got)
	}
	if got := run([]string{"audit", "keygen", "--out", key}); got != exitUsage {
		t.Fatalf("keygen overwrite exit %d, want refusal", got)
	}
	priv, err := audit.LoadKey(key)
	if err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "audit.jsonl")
	w, err := audit.NewWriter(log, audit.Options{CheckpointEvery: 2, Key: priv})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 4; i++ {
		if err := w.Append(&audit.Event{Principal: "t", Decision: "allow"}); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	if got := run([]string{"audit", "verify", log, "--key", key + ".pub", "--json"}); got != exitOK {
		t.Fatalf("verify exit %d", got)
	}
	if got := run([]string{"audit", "verify", "--key", key + ".pub", log}); got != exitOK {
		t.Fatalf("verify (flag first) exit %d", got)
	}
	raw, _ := os.ReadFile(log)
	tampered := filepath.Join(dir, "tampered.jsonl")
	if err := os.WriteFile(tampered, []byte(string(raw[:len(raw)/2])+"x"+string(raw[len(raw)/2:])), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := run([]string{"audit", "verify", tampered}); got != exitFail {
		t.Fatalf("tampered verify exit %d, want %d", got, exitFail)
	}
	if got := run([]string{"audit", "verify"}); got != exitUsage {
		t.Fatalf("verify without file exit %d", got)
	}
}

func TestRedactAndInventoryImport(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "k")
	if err := os.WriteFile(keyFile, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fixture := repoPath("tests", "fixtures", "configs", "eos.txt")
	if got := run([]string{"redact", "--key-file", keyFile, "-q", fixture}); got != exitOK {
		t.Fatalf("redact exit %d", got)
	}
	if got := run([]string{"redact", "--key-file", filepath.Join(dir, "missing"), fixture}); got != exitUsage {
		t.Fatalf("redact missing key exit %d", got)
	}

	csvPath := filepath.Join(dir, "d.csv")
	if err := os.WriteFile(csvPath, []byte("name,role,site,tags,status\na,core,dfw1,prod,active\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "inv.yaml")
	if got := run([]string{"inventory", "import", "--csv", csvPath, "--out", out}); got != exitOK {
		t.Fatalf("import exit %d", got)
	}
	if got := run([]string{"policy", "eval", "--policy", repoPath("policies", "examples", "read-only.yaml"), "--inventory", out, "--class", "READ_CONFIG", "--target", "a"}); got != exitOK {
		t.Fatalf("eval with imported inventory exit %d", got)
	}
	if got := run([]string{"inventory", "import"}); got != exitUsage {
		t.Fatalf("import without csv exit %d", got)
	}
}

func mustAbs(t *testing.T, p string) string {
	t.Helper()
	a, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return a
}
