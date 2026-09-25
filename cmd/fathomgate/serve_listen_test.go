// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fathomgate/fathomgate/internal/proxy"
)

// Tests of `fathomgate serve --listen` (T0.31, ADR 0016): flags and
// refusals, token sources, loopback-only binding, the lifecycle (shutdown
// grace, upstream exit) and the listener end to end.

// Listen tokens used in the tests. Each is a canary: no error or log line
// may carry it.
const (
	testListenToken  = "FAKE-listen-token-0123456789abcdef01234567"
	testListenToken2 = "FAKE-listen-token-two-0123456789abcdef0123"
)

// listenCanaries are the substrings no output may carry.
var listenCanaries = []string{"FAKE-listen-token", "FAKE-canary"}

func checkNoCanary(t *testing.T, what, s string) {
	t.Helper()
	for _, c := range listenCanaries {
		if strings.Contains(s, c) {
			t.Fatalf("%s carries a token or value (%s): %q", what, c, s)
		}
	}
}

// tokenFile writes an owner-only token file and returns its path.
func tokenFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	writeOwnerOnly(t, path, []byte(content))
	return path
}

func TestParseListenAddr(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in, want string // want "" means refused
	}{
		{"localhost:0", "127.0.0.1:0"},
		{"localhost:8931", "127.0.0.1:8931"},
		{"127.0.0.1:8931", "127.0.0.1:8931"},
		{"127.10.20.30:1", "127.10.20.30:1"},
		{"[::1]:8931", "[::1]:8931"},
		{"[::1]:0", "[::1]:0"},
		{"127.0.0.1:65535", "127.0.0.1:65535"},
		{":8931", ""},
		{"0.0.0.0:8931", ""},
		{"[::]:8931", ""},
		{"192.168.1.10:8931", ""},
		{"10.0.0.1:8931", ""},
		{"example.com:8931", ""},
		{"LOCALHOST:8931", ""},
		{"localhost.:8931", ""},
		{"localhost", ""},
		{"127.0.0.1", ""},
		{"127.0.0.1:", ""},
		{"127.0.0.1:65536", ""},
		{"127.0.0.1:-1", ""},
		{"127.0.0.1:http", ""},
		{"127.1:8931", ""},
		{"[::ffff:127.0.0.1]:8931", ""},
		{"[fe80::1%lo0]:8931", ""},
		{"[::1%lo0]:8931", ""},
		{"::1:8931", ""},
		{"", ""},
	} {
		got, err := parseListenAddr(tc.in)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%q: accepted as %q", tc.in, got)
			} else if tc.in != "" && strings.Contains(err.Error(), tc.in) && !strings.Contains(errListenAddr.Error(), tc.in) {
				t.Errorf("%q: the error quotes the value: %v", tc.in, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q: %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestLoadListenTokens(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	ok := tokenFile(t, dir, "ok", testListenToken+"\n")
	crlf := tokenFile(t, dir, "crlf", testListenToken2+"\r\n")
	bare := tokenFile(t, dir, "bare", testListenToken2)
	short := tokenFile(t, dir, "short", "FAKE-listen-token-short\n")
	spaced := tokenFile(t, dir, "spaced", "FAKE-listen-token 0123456789abcdef0123456\n")
	twoLines := tokenFile(t, dir, "two-lines", testListenToken+"\n\n")
	big := tokenFile(t, dir, "big", "FAKE-listen-token-"+strings.Repeat("x", maxTokenFileBytes))
	empty := tokenFile(t, dir, "empty", "")
	shared := tokenFile(t, dir, "shared", testListenToken+"\n")
	makeShared(t, shared)

	env := func(v string) lookupEnvFunc {
		return func(k string) (string, bool) { return v, k == listenTokenEnv }
	}
	for _, tc := range []struct {
		name    string
		files   []string
		lookup  lookupEnvFunc
		want    string // error substring; "" accepts
		names   []string
		wantTok map[string]string
	}{
		{name: "one file", files: []string{"alice=" + ok}, lookup: noEnv, names: []string{"alice"}, wantTok: map[string]string{"alice": testListenToken}},
		{name: "crlf stripped once", files: []string{"bob=" + crlf}, lookup: noEnv, names: []string{"bob"}, wantTok: map[string]string{"bob": testListenToken2}},
		{name: "no newline", files: []string{"bob=" + bare}, lookup: noEnv, names: []string{"bob"}},
		{name: "two files, sorted", files: []string{"zed=" + ok, "ci:runner-1=" + crlf}, lookup: noEnv, names: []string{"ci:runner-1", "zed"}},
		{name: "path with =", files: []string{"alice=" + ok}, lookup: noEnv, names: []string{"alice"}},
		{name: "env token", lookup: env(testListenToken), names: []string{"env"}, wantTok: map[string]string{"env": testListenToken}},
		{name: "none", lookup: noEnv, want: "--listen needs a bearer token"},
		{name: "env and file", files: []string{"alice=" + ok}, lookup: env(testListenToken2), want: "FATHOMGATE_LISTEN_TOKEN and --listen-token-file are both set"},
		{name: "env empty", lookup: env(""), want: "FATHOMGATE_LISTEN_TOKEN is set but empty"},
		{name: "env short", lookup: env("FAKE-listen-token-short"), want: "FATHOMGATE_LISTEN_TOKEN: the token is 23 bytes; at least 32"},
		{name: "env newline", lookup: env(testListenToken + "\n"), want: "FATHOMGATE_LISTEN_TOKEN: the token contains white space"},
		{name: "no name", files: []string{ok}, lookup: noEnv, want: "--listen-token-file argument 1 is not NAME=PATH"},
		{name: "token as the argument", files: []string{testListenToken}, lookup: noEnv, want: "--listen-token-file argument 1 is not NAME=PATH"},
		{name: "empty name", files: []string{"=" + ok}, lookup: noEnv, want: "argument 1 is not NAME=PATH"},
		{name: "empty path", files: []string{"alice="}, lookup: noEnv, want: "argument 1 is not NAME=PATH"},
		{name: "bad name", files: []string{"alice=" + ok, "bob smith=" + crlf}, lookup: noEnv, want: "--listen-token-file argument 2: the name must be 1 to 64 characters of [A-Za-z0-9_.:-]"},
		{name: "long name", files: []string{strings.Repeat("a", 65) + "=" + ok}, lookup: noEnv, want: "argument 1: the name must be"},
		{name: "duplicate name", files: []string{"alice=" + ok, "alice=" + crlf}, lookup: noEnv, want: "--listen-token-file alice is given twice"},
		{name: "same token twice", files: []string{"alice=" + ok, "bob=" + tokenFile(t, dir, "copy", testListenToken)}, lookup: noEnv, want: "--listen-token-file alice and bob have the same token"},
		{name: "short", files: []string{"alice=" + short}, lookup: noEnv, want: "--listen-token-file alice: the token is 23 bytes; at least 32 are required"},
		{name: "space", files: []string{"alice=" + spaced}, lookup: noEnv, want: "--listen-token-file alice: the token contains white space"},
		{name: "two newlines", files: []string{"alice=" + twoLines}, lookup: noEnv, want: "the token contains white space"},
		{name: "empty file", files: []string{"alice=" + empty}, lookup: noEnv, want: "the token is 0 bytes"},
		{name: "too big", files: []string{"alice=" + big}, lookup: noEnv, want: "larger than 4096 bytes"},
		{name: "missing", files: []string{"alice=" + filepath.Join(dir, "FAKE-listen-token-as-path")}, lookup: noEnv, want: "--listen-token-file alice: cannot open the token file"},
		{name: "shared", files: []string{"alice=" + shared}, lookup: noEnv, want: "--listen-token-file alice: the token file"},
	} {
		got, err := loadListenTokens(tc.files, tc.lookup)
		if tc.want != "" {
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("%s: error %v, want %q", tc.name, err, tc.want)
			} else {
				checkNoCanary(t, tc.name, err.Error())
				if strings.Contains(err.Error(), dir) {
					t.Errorf("%s: the error quotes a path: %v", tc.name, err)
				}
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !slices.Equal(got.names, tc.names) || len(got.byName) != len(tc.names) {
			t.Errorf("%s: principals %v, want %v", tc.name, got.names, tc.names)
		}
		for name, tok := range tc.wantTok {
			if string(got.byName[name]) != tok {
				t.Errorf("%s: token of %s is %d bytes, not the expected one", tc.name, name, len(got.byName[name]))
			}
		}
	}
}

// TestListenTokenRulesMatchHandler: what serve accepts, proxy.HTTPHandler
// accepts too, so a token that passes the pre-flight never fails after the
// upstream has started.
func TestListenTokenRulesMatchHandler(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, tok string }{
		{"alice", testListenToken},
		{strings.Repeat("n", 64), testListenToken},
		{"a_b.c:d-e", strings.Repeat("!", 32)},
		{"x", "~" + strings.Repeat("0", 31)},
	} {
		if !validPrincipalName(tc.name) || checkListenToken([]byte(tc.tok)) != nil {
			t.Fatalf("%s: refused by serve", tc.name)
		}
		p, _ := memProxy(t)
		if _, err := p.HTTPHandler(proxy.HTTPOptions{Tokens: map[string][]byte{tc.name: []byte(tc.tok)}}); err != nil {
			t.Errorf("%s: serve accepts what HTTPHandler refuses: %v", tc.name, err)
		}
		_ = p.Close()
	}
}

// TestServeListenRefusals: every refused --listen form exits 2 before
// anything is bound or spawned, with a message naming the flag, and never a
// token, a path or the refused value.
func TestServeListenRefusals(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	good := tokenFile(t, dir, "good", testListenToken+"\n")
	base := []string{"--server", "netdev-ssh-mcp", "--upstream", filepath.Join(dir, "FAKE-canary-no-such-upstream")}
	with := func(extra ...string) []string { return append(slices.Clone(base), extra...) }
	withToken := func(extra ...string) []string {
		return with(append([]string{"--listen-token-file", "alice=" + good}, extra...)...)
	}
	for _, tc := range []struct {
		name string
		args []string
		env  map[string]string
		want string
	}{
		{"no token", with("--listen", "127.0.0.1:0"), nil, "--listen needs a bearer token"},
		{"all interfaces", withToken("--listen", "0.0.0.0:8931"), nil, "--listen takes localhost:<port>"},
		{"bare port", withToken("--listen", ":8931"), nil, "loopback only in M0"},
		{"IPv6 any", withToken("--listen", "[::]:8931"), nil, "loopback only in M0"},
		{"LAN", withToken("--listen", "192.168.1.10:8931"), nil, "loopback only in M0"},
		{"host name", withToken("--listen", "example.com:8931"), nil, "loopback only in M0"},
		{"token as the address", withToken("--listen", testListenToken), nil, "--listen takes"},
		{"bad port", withToken("--listen", "127.0.0.1:99999"), nil, "--listen: the port must be a number from 0 to 65535"},
		{"listen-remote", withToken("--listen", "127.0.0.1:0", "--listen-remote"), nil, "--listen-remote reserved for M1"},
		{"listen-remote=true", withToken("--listen", "0.0.0.0:0", "--listen-remote=true"), nil, "--listen-remote reserved for M1"},
		{"listen-remote=value", withToken("--listen-remote=" + testListenToken), nil, "flag at argument 7 takes no value"},
		{"listen-host", withToken("--listen", "127.0.0.1:0", "--listen-host", "fathomgate.internal"), nil, "--listen-host reserved for M1: the listener is loopback-only"},
		{"both M1 flags", with("--listen-host", "a", "--listen-remote"), nil, "--listen-host, --listen-remote reserved for M1"},
		{"M1 flags without --listen", with("--listen-remote"), nil, "--listen-remote reserved for M1"},
		{"reserved policy flag with --listen", withToken("--listen", "127.0.0.1:0", "--policy", "p.yaml"), nil, "--policy not enforced in M0"},
		{"token on argv", with("--listen", "127.0.0.1:0", "--listen-token", testListenToken), nil, "unknown flag at argument 7"},
		{"token on argv with =", with("--listen", "127.0.0.1:0", "--listen-token="+testListenToken), nil, "unknown flag at argument 7"},
		{"token file without --listen", withToken(), nil, "--listen-token-file is only used with --listen"},
		{"token file as a positional", with("--listen", "127.0.0.1:0", "--listen-token-file", "alice="+good, testListenToken), nil, "unexpected argument 9"},
		{"env and file", withToken("--listen", "127.0.0.1:0"), map[string]string{listenTokenEnv: testListenToken2}, "both set"},
		{"group-readable file", with("--listen", "127.0.0.1:0", "--listen-token-file", "alice="+func() string {
			p := tokenFile(t, dir, "loose", testListenToken2+"\n")
			makeShared(t, p)
			return p
		}()), nil, "--listen-token-file alice: the token file"},
		{"MCPGODEBUG", withToken("--listen", "127.0.0.1:0"), map[string]string{"MCPGODEBUG": "allowsessionsinstateless=1"}, "--listen: MCPGODEBUG is set"},
		{"MCPGODEBUG empty", withToken("--listen", "127.0.0.1:0"), map[string]string{"MCPGODEBUG": ""}, "MCPGODEBUG is set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var stderr lockedBuffer
			code := serveContext(context.Background(), tc.args, &stderr, envMap(tc.env))
			out := stderr.String()
			if code != exitUsage {
				t.Fatalf("exit %d, want %d; stderr %q", code, exitUsage, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("stderr %q, want it to contain %q", out, tc.want)
			}
			checkNoCanary(t, "stderr", out)
			if strings.Contains(out, dir) {
				t.Fatalf("stderr quotes a path: %q", out)
			}
		})
	}
}

// TestServeListenBindFails: an address in use exits 1 before the upstream
// is started (the upstream here does not exist, and its error would say
// so).
func TestServeListenBindFails(t *testing.T) {
	t.Parallel()
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	var stderr lockedBuffer
	code := serveContext(context.Background(), []string{
		"--server", "netdev-ssh-mcp", "--upstream", filepath.Join(t.TempDir(), "no-such-upstream"),
		"--listen", busy.Addr().String(),
	}, &stderr, envMap(map[string]string{listenTokenEnv: testListenToken}))
	out := stderr.String()
	if code != exitFail || !strings.Contains(out, "fathomgate: serve: --listen: ") || strings.Contains(out, "no-such-upstream") {
		t.Fatalf("exit %d; stderr %q", code, out)
	}
}

// memUpstream is the upstream's end of memProxy. exit cuts the pipe
// between the proxy and the upstream, as an upstream process exiting does,
// and waiting receives a value each time the "wait" tool starts.
type memUpstream struct {
	session *mcp.ServerSession
	pipe    net.Conn // the upstream's end
	waiting chan struct{}
	release chan struct{} // closed to end every "wait" call
	once    sync.Once
}

// exit is the upstream exiting: its connection closes and its blocked
// handlers return.
func (m *memUpstream) exit() {
	m.once.Do(func() {
		_ = m.pipe.Close()
		close(m.release)
	})
}

// memProxy is a proxy over an in-process upstream "fake", connected by a
// pipe, with a tool "echo" and a tool "wait", which returns when its
// context ends or the upstream exits.
func memProxy(t *testing.T) (*proxy.Proxy, *memUpstream) {
	t.Helper()
	ctx := context.Background()
	m := &memUpstream{waiting: make(chan struct{}, 1), release: make(chan struct{})}
	t.Cleanup(m.exit)
	up := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "0"}, nil)
	obj := map[string]any{"type": "object"}
	up.AddTool(&mcp.Tool{Name: "echo", InputSchema: obj}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo " + string(req.Params.Arguments)}}}, nil
	})
	up.AddTool(&mcp.Tool{Name: "wait", InputSchema: obj}, func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		select {
		case m.waiting <- struct{}{}:
		default:
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-m.release:
			return nil, errors.New("upstream exited")
		}
	})
	proxyEnd, upEnd := net.Pipe()
	m.pipe = upEnd
	ss, err := up.Connect(ctx, &mcp.IOTransport{Reader: upEnd, Writer: upEnd}, nil)
	if err != nil {
		t.Fatal(err)
	}
	m.session = ss
	p, err := proxy.New(ctx, []proxy.Upstream{{Server: "fake", NewTransport: func() mcp.Transport {
		return &mcp.IOTransport{Reader: proxyEnd, Writer: proxyEnd}
	}}}, proxy.Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	return p, m
}

// bearerRT adds the listen token to every request.
type bearerRT struct {
	token string
	base  http.RoundTripper
}

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// agentOver connects a go-sdk client over Streamable HTTP to url with
// token, in the stateful 2025-11-25 era (initialise, session id) or the
// stateless 2026-07-28 era (server/discover).
func agentOver(t *testing.T, url, token, era string) (*mcp.ClientSession, *http.Transport) {
	t.Helper()
	tr := &http.Transport{}
	ct := &mcp.StreamableClientTransport{Endpoint: url, HTTPClient: &http.Client{Transport: bearerRT{token, tr}}, MaxRetries: -1}
	var opts *mcp.ClientSessionOptions
	if era == "2025-11-25" {
		opts = &mcp.ClientSessionOptions{ProtocolVersion: era}
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(context.Background(), ct, opts)
	if err != nil {
		tr.CloseIdleConnections()
		t.Fatalf("connect (%s): %v", era, err)
	}
	return cs, tr
}

var listeningURL = regexp.MustCompile(`msg=listening url=(http://\S+)`)

// waitListening waits for the `listening url=...` line and returns the URL.
func waitListening(t *testing.T, log *lockedBuffer, done <-chan int) string {
	t.Helper()
	deadline := time.After(20 * time.Second)
	for {
		if m := listeningURL.FindStringSubmatch(log.String()); m != nil {
			return m[1]
		}
		select {
		case code := <-done:
			t.Fatalf("serve ended with %d before listening:\n%s", code, log.String())
		case <-deadline:
			t.Fatalf("no listening line:\n%s", log.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

// startListener runs runListener on a free loopback port for p with the
// token of principal alice, and returns the URL and the exit code channel.
func startListener(ctx context.Context, t *testing.T, p *proxy.Proxy, grace time.Duration) (string, <-chan int, *lockedBuffer) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	log := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(log, nil))
	run := listenRun{
		tokens: listenTokens{byName: map[string][]byte{"alice": []byte(testListenToken)}, names: []string{"alice"}},
		server: "fake", grace: grace,
	}
	done := make(chan int, 1)
	go func() { done <- runListener(ctx, p, ln, run, logger, log) }()
	return waitListening(t, log, done), done, log
}

func exitWithin(t *testing.T, done <-chan int, d time.Duration) int {
	t.Helper()
	select {
	case code := <-done:
		return code
	case <-time.After(d):
		t.Fatalf("the listener did not stop within %v", d)
		return -1
	}
}

// TestListenerEndToEnd: a real loopback listener serving an in-memory
// upstream. A go-sdk agent in each era, with a bearer token, lists the
// prefixed tools and calls one; a request without the token gets 401 and
// one with an Origin gets 403. The end of the context (SIGINT, SIGTERM)
// then stops it with exit 0, promptly although the stateful agent holds a
// GET stream open, and closes the upstream.
func TestListenerEndToEnd(t *testing.T) {
	p, upstream := memProxy(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	url, done, log := startListener(ctx, t, p, shutdownGrace)
	if !strings.HasPrefix(url, "http://127.0.0.1:") || !strings.HasSuffix(url, "/mcp") || strings.HasSuffix(url, ":0/mcp") {
		t.Fatalf("listening url %q", url)
	}
	for _, want := range []string{"server=fake", "principals=alice", "policy=\"none (M0 pass-through"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("listening line lacks %q:\n%s", want, log.String())
		}
	}

	trs := make([]*http.Transport, 0, 3)
	defer func() {
		for _, tr := range trs {
			tr.CloseIdleConnections()
		}
	}()
	for _, era := range []string{"2025-11-25", "2026-07-28"} {
		cs, tr := agentOver(t, url, testListenToken, era)
		trs = append(trs, tr)
		defer func() { _ = cs.Close() }()
		var names []string
		for tool, err := range cs.Tools(ctx, nil) {
			if err != nil {
				t.Fatalf("%s: tools/list: %v", era, err)
			}
			names = append(names, tool.Name)
		}
		slices.Sort(names)
		if !slices.Equal(names, []string{"fake.echo", "fake.wait"}) {
			t.Fatalf("%s: tools %v", era, names)
		}
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "fake.echo", Arguments: map[string]any{"era": era}})
		if err != nil || res.IsError {
			t.Fatalf("%s: tools/call: %v %+v", era, err, res)
		}
		if got := res.Content[0].(*mcp.TextContent).Text; got != fmt.Sprintf(`echo {"era":%q}`, era) {
			t.Fatalf("%s: result %q", era, got)
		}
	}

	raw := &http.Transport{}
	trs = append(trs, raw)
	for _, tc := range []struct {
		name   string
		header map[string]string
		want   int
	}{
		{"no token", nil, http.StatusUnauthorized},
		{"wrong token", map[string]string{"Authorization": "Bearer " + testListenToken2}, http.StatusUnauthorized},
		{"origin", map[string]string{"Authorization": "Bearer " + testListenToken, "Origin": "http://evil.example"}, http.StatusForbidden},
	} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		for k, v := range tc.header {
			req.Header.Set(k, v)
		}
		resp, err := raw.RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("%s: status %d, want %d", tc.name, resp.StatusCode, tc.want)
		}
	}

	cancel()
	if code := exitWithin(t, done, shutdownGrace); code != exitOK {
		t.Fatalf("exit %d, want 0:\n%s", code, log.String())
	}
	// The upstream was closed on the way out.
	ended := make(chan struct{})
	go func() { _ = upstream.session.Wait(); close(ended) }()
	select {
	case <-ended:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream session is still open after the listener stopped")
	}
	checkNoCanary(t, "log", log.String())
}

// TestListenerUpstreamExit: when the upstream exits while serving, the
// listener stops and runListener exits 1, naming the upstream; a call in
// flight gets the upstream's failure as its answer, not a hang.
func TestListenerUpstreamExit(t *testing.T) {
	p, upstream := memProxy(t)
	url, done, log := startListener(context.Background(), t, p, shutdownGrace)
	cs, tr := agentOver(t, url, testListenToken, "2026-07-28")
	defer tr.CloseIdleConnections()
	defer func() { _ = cs.Close() }()

	called := make(chan *mcp.CallToolResult, 1)
	callErr := make(chan error, 1)
	go func() {
		res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "fake.wait", Arguments: map[string]any{}})
		called <- res
		callErr <- err
	}()
	select {
	case <-upstream.waiting:
	case <-time.After(10 * time.Second):
		t.Fatal("the call never reached the upstream")
	}
	upstream.exit()
	if code := exitWithin(t, done, 2*shutdownGrace); code != exitFail {
		t.Fatalf("exit %d, want 1:\n%s", code, log.String())
	}
	if !strings.Contains(log.String(), "fathomgate: serve: upstream fake exited; the listener has stopped") {
		t.Fatalf("no exit message:\n%s", log.String())
	}
	select {
	case res := <-called:
		err := <-callErr
		if err == nil && (res == nil || !res.IsError) {
			t.Fatalf("the call in flight succeeded after the upstream exited: %+v", res)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the call in flight never ended")
	}
}

// TestShutdownGrace (J4): on shutdown a request in flight gets up to the
// grace to finish before the proxy is closed; one that does not finish in
// time is cancelled by the close at the end of the grace.
func TestShutdownGrace(t *testing.T) {
	t.Parallel()
	run := func(t *testing.T, grace time.Duration, finish bool) (closedAfter time.Duration, body string) {
		t.Helper()
		closer := &signalCloser{closed: make(chan struct{})}
		entered := make(chan struct{})
		release := make(chan struct{})
		h := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			close(entered)
			select {
			case <-release:
				_, _ = io.WriteString(w, "finished")
			case <-closer.closed:
				_, _ = io.WriteString(w, "cancelled")
			}
		})
		logs := &lockedBuffer{}
		srv := newHTTPServer(h, closer, grace, slog.New(slog.NewTextHandler(logs, nil)))
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		served := make(chan error, 1)
		go func() { served <- srv.Serve(ln) }()
		tr := &http.Transport{}
		defer tr.CloseIdleConnections()
		got := make(chan string, 1)
		go func() {
			resp, err := (&http.Client{Transport: tr}).Post("http://"+ln.Addr().String()+"/mcp", "application/json", strings.NewReader("{}"))
			if err != nil {
				got <- "error: " + err.Error()
				return
			}
			b, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			got <- string(b)
		}()
		<-entered
		start := time.Now()
		shut := make(chan error, 1)
		go func() { shut <- srv.Shutdown(context.Background()) }()
		if finish {
			select {
			case <-closer.closed:
				t.Fatal("the proxy was closed while a request was in flight within the grace")
			case <-time.After(100 * time.Millisecond):
			}
			close(release)
		}
		body = <-got
		<-closer.closed
		closedAfter = time.Since(start)
		if err := <-shut; err != nil {
			t.Fatalf("Shutdown: %v", err)
		}
		<-srv.hookDone
		if err := <-served; !errors.Is(err, http.ErrServerClosed) {
			t.Fatalf("Serve: %v", err)
		}
		if !finish && !strings.Contains(logs.String(), "shutdown grace ended with requests in flight") {
			t.Errorf("no warning for the cancelled request:\n%s", logs.String())
		}
		return closedAfter, body
	}

	t.Run("finishes within the grace", func(t *testing.T) {
		t.Parallel()
		_, body := run(t, shutdownGrace, true)
		if body != "finished" {
			t.Fatalf("response %q", body)
		}
	})
	t.Run("cancelled at the end of the grace", func(t *testing.T) {
		t.Parallel()
		const grace = 200 * time.Millisecond
		after, body := run(t, grace, false)
		if body != "cancelled" || after < grace {
			t.Fatalf("response %q, proxy closed after %v (grace %v)", body, after, grace)
		}
	})
}

// signalCloser is an io.Closer whose Close closes a channel, once.
type signalCloser struct {
	closed chan struct{}
	n      atomic.Int32
}

func (c *signalCloser) Close() error {
	if c.n.Add(1) == 1 {
		close(c.closed)
	}
	return nil
}

// TestServeListenProcess: `fathomgate serve --listen` end to end with a real
// upstream process (this test binary as a go-sdk stdio server) and a token
// file. A 2025-era agent calls a tool through it; the end of the context
// then stops it with exit 0. A second run ends with the upstream exiting in
// the middle of serving, and exits 1.
func TestServeListenProcess(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tokPath := tokenFile(t, t.TempDir(), "alice.token", testListenToken+"\n")
	args := []string{
		"--server", "fake", "--upstream", exe,
		"--upstream-env", serveTestUpstreamEnv + "=mcp",
		"--upstream-env", "GORACE=atexit_sleep_ms=0",
		"--listen", "localhost:0",
		"--listen-token-file", "alice=" + tokPath,
		"--", "-test.run=^$",
	}
	start := func(ctx context.Context) (string, <-chan int, *lockedBuffer) {
		var stderr lockedBuffer
		done := make(chan int, 1)
		go func() { done <- serveContext(ctx, args, &stderr, noEnv) }()
		return waitListening(t, &stderr, done), done, &stderr
	}

	t.Run("signal", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		url, done, stderr := start(ctx)
		if !strings.HasPrefix(url, "http://127.0.0.1:") {
			t.Fatalf("localhost bound as %q, want 127.0.0.1", url)
		}
		cs, tr := agentOver(t, url, testListenToken, "2025-11-25")
		defer tr.CloseIdleConnections()
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "fake.echo", Arguments: map[string]any{"n": 1}})
		if err != nil || res.IsError || res.Content[0].(*mcp.TextContent).Text != `echo {"n":1}` {
			t.Fatalf("tools/call: %v %+v", err, res)
		}
		cancel()
		if code := exitWithin(t, done, 2*shutdownGrace); code != exitOK {
			t.Fatalf("exit %d, want 0:\n%s", code, stderr.String())
		}
		_ = cs.Close()
		checkNoCanary(t, "stderr", stderr.String())
	})

	t.Run("upstream exits", func(t *testing.T) {
		url, done, stderr := start(context.Background())
		cs, tr := agentOver(t, url, testListenToken, "2026-07-28")
		defer tr.CloseIdleConnections()
		defer func() { _ = cs.Close() }()
		// The upstream exits without answering.
		_, _ = cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "fake.exit", Arguments: map[string]any{}})
		if code := exitWithin(t, done, 2*shutdownGrace); code != exitFail {
			t.Fatalf("exit %d, want 1:\n%s", code, stderr.String())
		}
		if !strings.Contains(stderr.String(), "upstream fake exited; the listener has stopped") {
			t.Fatalf("no exit message:\n%s", stderr.String())
		}
		checkNoCanary(t, "stderr", stderr.String())
	})
}

// runMCPUpstream serves a go-sdk stdio upstream with the tools "echo"
// (returns its arguments) and "exit" (ends the process without answering).
func runMCPUpstream() {
	s := mcp.NewServer(&mcp.Implementation{Name: "fake", Version: "0"}, nil)
	obj := map[string]any{"type": "object"}
	s.AddTool(&mcp.Tool{Name: "echo", InputSchema: obj}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args map[string]any
		_ = json.Unmarshal(req.Params.Arguments, &args)
		b, _ := json.Marshal(args)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "echo " + string(b)}}}, nil
	})
	s.AddTool(&mcp.Tool{Name: "exit", InputSchema: obj}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		os.Exit(3)
		return nil, nil
	})
	_ = s.Run(context.Background(), &mcp.StdioTransport{})
}
