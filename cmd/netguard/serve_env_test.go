package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// serveCanary is a --upstream-env-pass value that must never appear in
// anything netguard writes. The quote and backslash exercise the escaped
// and quoted forms.
const serveCanary = `FAKE-canary-"pw\x9`

func noEnv(string) (string, bool) { return "", false }

func envMap(m map[string]string) lookupEnvFunc {
	return func(name string) (string, bool) {
		v, ok := m[name]
		return v, ok
	}
}

func TestParseServeEnvPass(t *testing.T) {
	t.Parallel()
	base := []string{"--server", "netdev-ssh-mcp", "--upstream", "/opt/bin/netdev-ssh-mcp"}
	with := func(extra ...string) []string { return append(slices.Clone(base), extra...) }
	env := map[string]string{
		"DEVICE_PASSWORD": serveCanary,
		"SSH_AUTH_SOCK":   "/tmp/FAKE-agent.sock",
		"EMPTY":           "",
		"PATH":            "/usr/bin",
		"netguard_lower":  "FAKE-lower",
	}
	cases := []struct {
		name      string
		goos      string
		args      []string
		wantErr   string // substring; empty means success
		wantEnv   []string
		wantNames []string
	}{
		{name: "pass one", args: with("--upstream-env-pass", "DEVICE_PASSWORD"),
			wantEnv: []string{"DEVICE_PASSWORD=" + serveCanary}, wantNames: []string{"DEVICE_PASSWORD"}},
		{name: "pass before upstream-env", args: with("--upstream-env", "DEVICE_USERNAME=netops", "--upstream-env-pass", "SSH_AUTH_SOCK", "--upstream-env-pass", "DEVICE_PASSWORD"),
			wantEnv:   []string{"SSH_AUTH_SOCK=/tmp/FAKE-agent.sock", "DEVICE_PASSWORD=" + serveCanary, "DEVICE_USERNAME=netops"},
			wantNames: []string{"SSH_AUTH_SOCK", "DEVICE_PASSWORD"}},
		{name: "repeat is deduplicated", args: with("--upstream-env-pass", "DEVICE_PASSWORD", "--upstream-env-pass", "DEVICE_PASSWORD"),
			wantEnv: []string{"DEVICE_PASSWORD=" + serveCanary}, wantNames: []string{"DEVICE_PASSWORD"}},
		{name: "allow-listed name is allowed", args: with("--upstream-env-pass", "PATH"), wantEnv: []string{"PATH=/usr/bin"}, wantNames: []string{"PATH"}},
		{name: "unset", args: with("--upstream-env-pass", "NOT_THERE"), wantErr: "--upstream-env-pass NOT_THERE: not set in netguard's environment"},
		{name: "empty counts as unset", args: with("--upstream-env-pass", "EMPTY"), wantErr: "--upstream-env-pass EMPTY: set but empty"},
		{name: "NAME=VALUE", args: with("--upstream-env-pass", "DEVICE_PASSWORD="+serveCanary), wantErr: "--upstream-env-pass argument 1 is not a variable name"},
		{name: "invalid name", args: with("--upstream-env-pass", "OK", "--upstream-env-pass", "bad-name"), wantErr: "--upstream-env-pass argument 2: name must match"},
		{name: "empty name", args: with("--upstream-env-pass", ""), wantErr: "--upstream-env-pass argument 1: name must match"},
		{name: "NETGUARD_ on pass", args: with("--upstream-env-pass", "NETGUARD_REDACT_KEY"), wantErr: "--upstream-env-pass NETGUARD_REDACT_KEY: NETGUARD_* variables"},
		{name: "NETGUARD_ on env", args: with("--upstream-env", "NETGUARD_X="+serveCanary), wantErr: "--upstream-env NETGUARD_X: NETGUARD_* variables"},
		{name: "bare NETGUARD is not the prefix", args: with("--upstream-env", "NETGUARD=1"), wantEnv: []string{"NETGUARD=1"}},
		{name: "lower-case netguard_ passes on unix", args: with("--upstream-env-pass", "netguard_lower"),
			wantEnv: []string{"netguard_lower=FAKE-lower"}, wantNames: []string{"netguard_lower"}},
		{name: "lower-case netguard_ pass refused on windows", goos: "windows", args: with("--upstream-env-pass", "netguard_lower"), wantErr: "NETGUARD_* variables"},
		{name: "mixed-case Netguard_ env refused on windows", goos: "windows", args: with("--upstream-env", "Netguard_X=1"), wantErr: "NETGUARD_* variables"},
		{name: "conflict", args: with("--upstream-env", "DEVICE_PASSWORD=x", "--upstream-env-pass", "DEVICE_PASSWORD"),
			wantErr: "DEVICE_PASSWORD is given with both --upstream-env and --upstream-env-pass"},
		{name: "different case is no conflict on unix", args: with("--upstream-env", "device_password=x", "--upstream-env-pass", "DEVICE_PASSWORD"),
			wantEnv: []string{"DEVICE_PASSWORD=" + serveCanary, "device_password=x"}, wantNames: []string{"DEVICE_PASSWORD"}},
		{name: "different case conflicts on windows", goos: "windows", args: with("--upstream-env", "device_password=x", "--upstream-env-pass", "DEVICE_PASSWORD"), wantErr: "given with both"},
		{name: "windows dedup is case-insensitive", goos: "windows", args: with("--upstream-env-pass", "DEVICE_PASSWORD", "--upstream-env-pass", "Device_Password"),
			wantEnv: []string{"DEVICE_PASSWORD=" + serveCanary}, wantNames: []string{"DEVICE_PASSWORD"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			goos := tc.goos
			if goos == "" {
				goos = "linux"
			}
			lookup := envMap(env)
			if goos == "windows" { // os.LookupEnv is case-insensitive there
				lookup = func(name string) (string, bool) {
					for k, v := range env {
						if strings.EqualFold(k, name) {
							return v, true
						}
					}
					return "", false
				}
			}
			cfg, err := parseServe(tc.args, io.Discard, lookup, goos)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tc.wantErr)
				}
				if strings.Contains(err.Error(), "FAKE") {
					t.Fatalf("error carries a value: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(cfg.upstreamEnv, tc.wantEnv) {
				t.Errorf("upstream env %q, want %q", cfg.upstreamEnv, tc.wantEnv)
			}
			if !slices.Equal(cfg.passNames, tc.wantNames) {
				t.Errorf("pass names %q, want %q", cfg.passNames, tc.wantNames)
			}
			if len(cfg.secrets) != len(tc.wantNames) {
				t.Errorf("%d secrets, want %d", len(cfg.secrets), len(tc.wantNames))
			}
		})
	}
}

// Every usage error path, run through serve as the binary would: exit 2, and
// the canary value (given on the command line or in the environment) is in
// nothing written to stderr.
func TestServeErrorsNeverCarryValues(t *testing.T) {
	t.Parallel()
	base := []string{"--server", "netdev-ssh-mcp", "--upstream", "/opt/bin/netdev-ssh-mcp"}
	with := func(extra ...string) []string { return append(slices.Clone(base), extra...) }
	env := map[string]string{"DEVICE_PASSWORD": serveCanary, "NETGUARD_REDACT_KEY": serveCanary, "EMPTY": ""}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"env key malformed", with("--upstream-env", "DEVICE-PASSWORD="+serveCanary), `--upstream-env "DEVICE-PASSWORD": key must match`},
		{"env bare value", with("--upstream-env", serveCanary), "--upstream-env argument 1 is not KEY=VALUE"},
		{"env bare value second", with("--upstream-env", "A=1", "--upstream-env", serveCanary), "--upstream-env argument 2 is not KEY=VALUE"},
		{"env NETGUARD_", with("--upstream-env", "NETGUARD_X="+serveCanary), "--upstream-env NETGUARD_X:"},
		{"pass NAME=VALUE", with("--upstream-env-pass", "DEVICE_PASSWORD="+serveCanary), "--upstream-env-pass argument 1 is not a variable name"},
		{"pass bare value", with("--upstream-env-pass", serveCanary), "--upstream-env-pass argument 1: name must match"},
		{"pass NETGUARD_", with("--upstream-env-pass", "NETGUARD_REDACT_KEY"), "--upstream-env-pass NETGUARD_REDACT_KEY:"},
		{"pass unset", with("--upstream-env-pass", "NOT_THERE"), "--upstream-env-pass NOT_THERE: not set"},
		{"pass empty", with("--upstream-env-pass", "EMPTY"), "--upstream-env-pass EMPTY: set but empty"},
		{"conflict", with("--upstream-env", "DEVICE_PASSWORD="+serveCanary, "--upstream-env-pass", "DEVICE_PASSWORD"), "DEVICE_PASSWORD is given with both"},
		{"reserved flag with pass", with("--upstream-env-pass", "DEVICE_PASSWORD", "--policy", "p.yaml"), "--policy not enforced in M0"},
		{"bad server with pass", []string{"--server", "net.dev", "--upstream", "x", "--upstream-env-pass", "DEVICE_PASSWORD", "--upstream-env", "A=" + serveCanary}, "--server"},
		{"missing upstream with pass", []string{"--server", "s", "--upstream-env-pass", "DEVICE_PASSWORD"}, "required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stderr bytes.Buffer
			if code := serve(tc.args, &stderr, envMap(env)); code != exitUsage {
				t.Fatalf("exit %d, want %d; stderr %q", code, exitUsage, stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.want) {
				t.Fatalf("stderr %q, want it to contain %q", stderr.String(), tc.want)
			}
			if strings.Contains(stderr.String(), "FAKE-canary") {
				t.Fatalf("stderr carries the value: %q", stderr.String())
			}
		})
	}
}

// serveTestUpstreamEnv makes the test binary act as a leaky upstream: it
// prints the passed values to stderr and answers every JSON-RPC request with
// an error whose message carries the password, so startup fails with the
// upstream's words in netguard's error.
const serveTestUpstreamEnv = "SERVE_TEST_UPSTREAM"

func TestMain(m *testing.M) {
	if os.Getenv(serveTestUpstreamEnv) == "leaky" {
		runLeakyUpstream()
		return
	}
	os.Exit(m.Run())
}

func runLeakyUpstream() {
	pw := os.Getenv("DEVICE_PASSWORD")
	fmt.Fprintf(os.Stderr, "password is %s; pin is %s; user is %s\n", pw, os.Getenv("DEVICE_PIN"), os.Getenv("DEVICE_USERNAME"))
	fmt.Fprintf(os.Stderr, "quoted %q\n", pw)
	// One value split across two writes.
	if len(pw) > 5 {
		fmt.Fprint(os.Stderr, "again: "+pw[:5])
		time.Sleep(20 * time.Millisecond)
		fmt.Fprintln(os.Stderr, pw[5:])
	}
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal(sc.Bytes(), &req) != nil || len(req.ID) == 0 {
			continue
		}
		resp, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": req.ID,
			"error": map[string]any{"code": -32603, "message": "login failed with password " + pw},
		})
		_, _ = os.Stdout.Write(append(resp, '\n'))
	}
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// End to end through a real child process: the passed value reaches the
// upstream exactly (its stderr shows the marker, which only an exact match
// produces), a value under 4 bytes is passed but not scrubbed, and the value
// is in none of netguard's stderr: not in the relayed lines, not when split
// across writes, not in the startup error that quotes the upstream's
// JSON-RPC message.
func TestServeKeepsPassedValuesOffStderr(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := envMap(map[string]string{"DEVICE_PASSWORD": serveCanary, "DEVICE_PIN": "FK1"})
	var stderr lockedBuffer
	code := serve([]string{
		"--server", "netdev-ssh-mcp", "--upstream", exe,
		"--upstream-env", serveTestUpstreamEnv + "=leaky",
		"--upstream-env", "GORACE=atexit_sleep_ms=0",
		"--upstream-env", "DEVICE_USERNAME=netops",
		"--upstream-env-pass", "DEVICE_PASSWORD",
		"--upstream-env-pass", "DEVICE_PIN",
		"--", "-test.run=^$",
	}, &stderr, env)
	out := stderr.String()
	if code != exitFail {
		t.Fatalf("exit %d, want %d; stderr:\n%s", code, exitFail, out)
	}
	if strings.Contains(out, "FAKE-canary") {
		t.Fatalf("stderr carries the value:\n%s", out)
	}
	for _, want := range []string{
		"upstream netdev-ssh-mcp: password is [redacted:DEVICE_PASSWORD]; pin is FK1; user is netops\n",
		"upstream netdev-ssh-mcp: quoted \"[redacted:DEVICE_PASSWORD]\"\n",
		"upstream netdev-ssh-mcp: again: [redacted:DEVICE_PASSWORD]\n",
		"login failed with password [redacted:DEVICE_PASSWORD]",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stderr lacks %q:\n%s", want, out)
		}
	}
}
