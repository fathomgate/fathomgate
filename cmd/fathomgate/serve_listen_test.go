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
	"net/netip"
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
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			a, err := parseListenAddr(tc.in)
			got := netip.AddrPortFrom(a.host, a.port).String()
			if tc.want == "" {
				if err == nil {
					t.Errorf("accepted as %q", got)
				} else if tc.in != "" && strings.Contains(err.Error(), tc.in) && !strings.Contains(errListenAddr.Error(), tc.in) {
					t.Errorf("the error quotes the value: %v", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Errorf("%q, %v; want %q", got, err, tc.want)
			}
		})
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
	// A directory and file name with "=" in them: only the first "=" of
	// NAME=PATH splits.
	eqDir := filepath.Join(dir, "a=b")
	if err := os.Mkdir(eqDir, 0o700); err != nil {
		t.Fatal(err)
	}
	withEq := tokenFile(t, eqDir, "tok=en", testListenToken+"\n")

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
		{name: "path with =", files: []string{"alice=" + withEq}, lookup: noEnv, names: []string{"alice"}, wantTok: map[string]string{"alice": testListenToken}},
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
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := loadListenTokens(tc.files, tc.lookup)
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Errorf("error %v, want %q", err, tc.want)
				} else {
					checkNoCanary(t, tc.name, err.Error())
					if strings.Contains(err.Error(), dir) {
						t.Errorf("the error quotes a path: %v", err)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got.names, tc.names) || len(got.byName) != len(tc.names) {
				t.Errorf("principals %v, want %v", got.names, tc.names)
			}
			for name, tok := range tc.wantTok {
				if string(got.byName[name]) != tok {
					t.Errorf("token of %s is %d bytes, not the expected one", name, len(got.byName[name]))
				}
			}
		})
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

// listeningURLs returns the URL of every `listening` line in log, in order.
func listeningURLs(log string) []string {
	ms := listeningURL.FindAllStringSubmatch(log, -1)
	urls := make([]string, 0, len(ms))
	for _, m := range ms {
		urls = append(urls, m[1])
	}
	return urls
}

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

// startListener runs runListener for p with the token of principal alice
// on a free port of 127.0.0.1 and, where the host has it, the same port of
// [::1] (bindLoopback), and returns the first URL and the exit code
// channel.
func startListener(ctx context.Context, t *testing.T, p *proxy.Proxy, grace time.Duration) (string, <-chan int, *lockedBuffer) {
	t.Helper()
	log := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(log, nil))
	lns, err := bindLoopback(listenAddr{host: netip.MustParseAddr("127.0.0.1")}, net.Listen, logger)
	if err != nil {
		t.Fatal(err)
	}
	run := listenRun{
		tokens: listenTokens{byName: map[string][]byte{"alice": []byte(testListenToken)}, names: []string{"alice"}},
		server: "fake", grace: grace,
	}
	done := make(chan int, 1)
	go func() { done <- runListener(ctx, p, lns, run, logger, log) }()
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

// hasIPv6Loopback reports whether this host can bind [::1].
func hasIPv6Loopback() bool {
	l, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

// waitURLs waits until log has n `listening` lines and returns their URLs.
func waitURLs(t *testing.T, log *lockedBuffer, n int) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		urls := listeningURLs(log.String())
		if len(urls) >= n {
			return urls
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d listening lines, want %d:\n%s", len(urls), n, log.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestListenerEndToEnd: a real loopback listener serving an in-memory
// upstream on 127.0.0.1 and [::1] (where the host has IPv6), one
// `listening` line each. A go-sdk agent in each era, on each address, with
// a bearer token, lists the prefixed tools and calls one; a request
// without the token gets 401 and one with an Origin gets 403, and both
// close the connection. The end of the context (SIGINT, SIGTERM) then
// stops it with exit 0, promptly although the stateful agent holds a GET
// stream open, and closes the upstream.
func TestListenerEndToEnd(t *testing.T) {
	p, upstream := memProxy(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, done, log := startListener(ctx, t, p, shutdownGrace)
	families := 1
	if hasIPv6Loopback() {
		families = 2
	}
	urls := waitURLs(t, log, families)
	if urls[0] != first || !strings.HasPrefix(first, "http://127.0.0.1:") || !strings.HasSuffix(first, "/mcp") || strings.HasSuffix(first, ":0/mcp") {
		t.Fatalf("listening urls %q", urls)
	}
	if families == 2 && urls[1] != strings.Replace(first, "127.0.0.1", "[::1]", 1) {
		t.Fatalf("second listening url %q, want [::1] on the port of %q", urls[1], first)
	}
	if n := strings.Count(log.String(), "principals=alice"); n != families {
		t.Errorf("%d listening lines name the principal, want %d:\n%s", n, families, log.String())
	}
	for _, want := range []string{"server=fake", "principals=alice", "policy=\"none (M0 pass-through"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("listening line lacks %q:\n%s", want, log.String())
		}
	}

	trs := make([]*http.Transport, 0, 5)
	defer func() {
		for _, tr := range trs {
			tr.CloseIdleConnections()
		}
	}()
	for i, era := range []string{"2025-11-25", "2026-07-28"} {
		cs, tr := agentOver(t, urls[i%len(urls)], testListenToken, era)
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

	// Every refusal closes its connection (Connection: close from the
	// handler; the Go review of PR #109, item 5), so a client without a
	// token holds no connection slot past its answer.
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
		for _, url := range urls {
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
				t.Errorf("%s on %s: status %d, want %d", tc.name, url, resp.StatusCode, tc.want)
			}
			if !resp.Close {
				t.Errorf("%s on %s: the answer keeps the connection open", tc.name, url)
			}
		}
	}

	// H1 in the security review of PR #109: while fathomgate listens, no
	// one can bind either loopback family on its port.
	if families == 2 {
		port := strings.TrimSuffix(strings.TrimPrefix(first, "http://127.0.0.1:"), proxy.HTTPPath)
		for _, addr := range []string{"127.0.0.1:" + port, "[::1]:" + port} {
			if l, err := net.Listen("tcp", addr); err == nil {
				_ = l.Close()
				t.Errorf("%s could be bound while fathomgate listens on it", addr)
			}
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

// TestShutdownWithListenStream (item 1 of the Go review of PR #109): a
// 2026-era agent's subscriptions/listen stream is a POST that never ends
// on its own. Like a 2025-era GET stream it does not hold the shutdown
// grace: with it open and nothing else in flight, the proxy is closed at
// once, the stream ends, and no "cancelling them" warning is logged.
func TestShutdownWithListenStream(t *testing.T) {
	p, _ := memProxy(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	url, done, log := startListener(ctx, t, p, shutdownGrace)

	body := `{"jsonrpc":"2.0","id":1,"method":"subscriptions/listen","params":{"notifications":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"raw","version":"0"},"io.modelcontextprotocol/clientCapabilities":{}}}}`
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testListenToken)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "subscriptions/listen")
	tr := &http.Transport{}
	defer tr.CloseIdleConnections()
	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		t.Fatalf("subscriptions/listen: status %d, %q: %s", resp.StatusCode, resp.Header.Get("Content-Type"), b)
	}
	// The acknowledgement is the stream's first event; once it has arrived
	// the stream is open and held by go-sdk.
	first := make([]byte, 1)
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatalf("no acknowledgement on the listen stream: %v", err)
	}
	streamEnded := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, resp.Body); close(streamEnded) }()

	start := time.Now()
	cancel()
	if code := exitWithin(t, done, shutdownGrace); code != exitOK {
		t.Fatalf("exit %d, want 0:\n%s", code, log.String())
	}
	if d := time.Since(start); d >= shutdownGrace/2 {
		t.Fatalf("shutdown took %v with a listen stream open; the stream held the grace", d)
	}
	if strings.Contains(log.String(), "shutdown grace ended with requests in flight") {
		t.Fatalf("the listen stream was counted as a request in flight:\n%s", log.String())
	}
	select {
	case <-streamEnded:
	case <-time.After(5 * time.Second):
		t.Fatal("the listen stream is still open after shutdown")
	}
}

// TestLongLived: which requests the shutdown grace does not wait for.
func TestLongLived(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, method, mcpMethod string
		want                    bool
	}{
		{"2025 GET stream", http.MethodGet, "", true},
		{"2026 subscriptions/listen", http.MethodPost, "subscriptions/listen", true},
		{"tools/call", http.MethodPost, "tools/call", false},
		{"2025 POST", http.MethodPost, "", false},
		{"DELETE", http.MethodDelete, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest(tc.method, "http://127.0.0.1/mcp", nil)
			if tc.mcpMethod != "" {
				r.Header.Set("Mcp-Method", tc.mcpMethod)
			}
			if got := longLived(r); got != tc.want {
				t.Fatalf("longLived %v, want %v", got, tc.want)
			}
		})
	}
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
			t.Fatalf("localhost bound as %q, want 127.0.0.1 first", url)
		}
		// localhost is bound on both loopback families (H1), each named on
		// its own listening line.
		urls := []string{url}
		if hasIPv6Loopback() {
			urls = waitURLs(t, stderr, 2)
			if want := strings.Replace(url, "127.0.0.1", "[::1]", 1); urls[1] != want {
				t.Fatalf("listening urls %q, want %q second", urls, want)
			}
		}
		for i, u := range urls {
			cs, tr := agentOver(t, u, testListenToken, "2025-11-25")
			defer tr.CloseIdleConnections()
			res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "fake.echo", Arguments: map[string]any{"n": i}})
			if err != nil || res.IsError || res.Content[0].(*mcp.TextContent).Text != fmt.Sprintf(`echo {"n":%d}`, i) {
				t.Fatalf("tools/call on %s: %v %+v", u, err, res)
			}
			defer func() { _ = cs.Close() }()
		}
		cancel()
		if code := exitWithin(t, done, 2*shutdownGrace); code != exitOK {
			t.Fatalf("exit %d, want 0:\n%s", code, stderr.String())
		}
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
