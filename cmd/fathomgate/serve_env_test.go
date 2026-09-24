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

	"github.com/fathomgate/fathomgate/internal/proxy"
)

// serveCanary is a --upstream-env-pass value that must never appear in
// anything fathomgate writes. The quote and backslash exercise the escaped
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
		"DEVICE_PASSWORD":  serveCanary,
		"SSH_AUTH_SOCK":    "/tmp/FAKE-agent.sock",
		"EMPTY":            "",
		"PATH":             "/usr/bin",
		"fathomgate_lower": "FAKE-lower",
		"NETGUARD_OLD":     "FAKE-old",
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
		{name: "unset", args: with("--upstream-env-pass", "NOT_THERE"), wantErr: "--upstream-env-pass NOT_THERE: not set in fathomgate's environment"},
		{name: "empty counts as unset", args: with("--upstream-env-pass", "EMPTY"), wantErr: "--upstream-env-pass EMPTY: set but empty"},
		{name: "NAME=VALUE", args: with("--upstream-env-pass", "DEVICE_PASSWORD="+serveCanary), wantErr: "--upstream-env-pass argument 1 is not a variable name"},
		{name: "invalid name", args: with("--upstream-env-pass", "OK", "--upstream-env-pass", "bad-name"), wantErr: "--upstream-env-pass argument 2: name must match"},
		{name: "empty name", args: with("--upstream-env-pass", ""), wantErr: "--upstream-env-pass argument 1: name must match"},
		{name: "FATHOMGATE_ on pass", args: with("--upstream-env-pass", "FATHOMGATE_REDACT_KEY"), wantErr: "--upstream-env-pass FATHOMGATE_REDACT_KEY: FATHOMGATE_* variables"},
		{name: "FATHOMGATE_ on env", args: with("--upstream-env", "FATHOMGATE_X="+serveCanary), wantErr: "--upstream-env FATHOMGATE_X: FATHOMGATE_* variables"},
		{name: "bare FATHOMGATE is not the prefix", args: with("--upstream-env", "FATHOMGATE=1"), wantEnv: []string{"FATHOMGATE=1"}},
		// The placeholder prefix is neither reserved nor read (ADR 0019).
		{name: "NETGUARD_ is an ordinary name", args: with("--upstream-env-pass", "NETGUARD_OLD"),
			wantEnv: []string{"NETGUARD_OLD=FAKE-old"}, wantNames: []string{"NETGUARD_OLD"}},
		{name: "lower-case fathomgate_ passes on unix", args: with("--upstream-env-pass", "fathomgate_lower"),
			wantEnv: []string{"fathomgate_lower=FAKE-lower"}, wantNames: []string{"fathomgate_lower"}},
		{name: "lower-case fathomgate_ pass refused on windows", goos: "windows", args: with("--upstream-env-pass", "fathomgate_lower"), wantErr: "FATHOMGATE_* variables"},
		{name: "mixed-case Fathomgate_ env refused on windows", goos: "windows", args: with("--upstream-env", "Fathomgate_X=1"), wantErr: "FATHOMGATE_* variables"},
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
			// What the child gets after the allow-list: the passed
			// variables, then --upstream-env, as proxy.Command builds it.
			child := proxy.Command{Path: "x", Env: cfg.upstreamEnv, Secrets: cfg.secrets}.Transport().Command.Env
			n := len(cfg.secrets) + len(cfg.upstreamEnv)
			if n > len(child) || !slices.Equal(child[len(child)-n:], tc.wantEnv) {
				t.Errorf("child env tail %q, want %q", child[max(0, len(child)-n):], tc.wantEnv)
			}
			if !slices.Equal(cfg.passNames, tc.wantNames) {
				t.Errorf("pass names %q, want %q", cfg.passNames, tc.wantNames)
			}
			if len(cfg.secrets) != len(tc.wantNames) {
				t.Errorf("%d secrets, want %d", len(cfg.secrets), len(tc.wantNames))
			}
			for _, e := range cfg.upstreamEnv {
				if strings.Contains(e, "FAKE-canary") {
					t.Errorf("a passed value is in upstreamEnv: %q", cfg.upstreamEnv)
				}
			}
			if strings.Contains(fmt.Sprintf("%v %+v %#v", cfg, cfg, cfg), "FAKE-canary") {
				t.Error("formatting serveConfig printed a passed value")
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
	env := map[string]string{"DEVICE_PASSWORD": serveCanary, "FATHOMGATE_REDACT_KEY": serveCanary, "EMPTY": ""}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"env key malformed", with("--upstream-env", "DEVICE-PASSWORD="+serveCanary), "--upstream-env argument 1: key must match"},
		// E2: a key that is itself the start of a value.
		{"env key is part of the value", with("--upstream-env", "A=1", "--upstream-env", "FAKE-canary@x="+serveCanary), "--upstream-env argument 2: key must match"},
		// E1: a password typed as its own argument after a name.
		{"env value as separate argument", with("--upstream-env", "DEVICE_PASSWORD", serveCanary), "unexpected argument 7; arguments for the upstream go after --"},
		{"pass value as separate argument", with("--upstream-env-pass", "DEVICE_PASSWORD", serveCanary), "unexpected argument 7; arguments for the upstream go after --"},
		{"dash-prefixed value as separate argument", with("--upstream-env", "DEVICE_PASSWORD", "-"+serveCanary), "unknown flag at argument 7"},
		{"double-dash-prefixed value", with("--" + serveCanary + "=x"), "unknown flag at argument 5"},
		{"bad flag syntax", with("---" + serveCanary), "bad flag syntax at argument 5"},
		{"flag without value", with("--upstream-env"), "flag at argument 5 needs a value"},
		{"env bare value", with("--upstream-env", serveCanary), "--upstream-env argument 1 is not KEY=VALUE"},
		{"env bare value second", with("--upstream-env", "A=1", "--upstream-env", serveCanary), "--upstream-env argument 2 is not KEY=VALUE"},
		{"env FATHOMGATE_", with("--upstream-env", "FATHOMGATE_X="+serveCanary), "--upstream-env FATHOMGATE_X:"},
		{"pass NAME=VALUE", with("--upstream-env-pass", "DEVICE_PASSWORD="+serveCanary), "--upstream-env-pass argument 1 is not a variable name"},
		{"pass bare value", with("--upstream-env-pass", serveCanary), "--upstream-env-pass argument 1: name must match"},
		{"pass FATHOMGATE_", with("--upstream-env-pass", "FATHOMGATE_REDACT_KEY"), "--upstream-env-pass FATHOMGATE_REDACT_KEY:"},
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
// upstream's words in fathomgate's error.
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
// is in none of fathomgate's stderr: not in the relayed lines, not when split
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
