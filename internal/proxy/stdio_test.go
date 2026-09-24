package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fakeUpstreamEnv makes the test binary act as a stdio upstream, so the
// Command path (a real child process over stdin/stdout) is exercised
// without any external server. "1" is a go-sdk server (stateless era,
// 2026-07-28); "legacy" is the same server pinned to the stateful era
// (2025-11-25), as a FastMCP 1.x upstream is; "badversion" is a raw JSON-RPC
// peer that answers the initialise request with a protocol version go-sdk
// rejects, and then never exits on its own. "nodiscover" stops reading at
// server/discover (ADR 0018); "die" exits 3 at once and "dielist" exits 4
// on tools/list (T0.25).
const fakeUpstreamEnv = "NETGUARD_TEST_FAKE_UPSTREAM"

// childRaceEnv stops a -race child from sleeping a second at exit to let
// the race detector report; every spawned fake exits several times per
// run, and the upstream only inherits what Command.Env passes.
const childRaceEnv = "GORACE=atexit_sleep_ms=0"

func TestMain(m *testing.M) {
	switch os.Getenv(fakeUpstreamEnv) {
	case "1":
		runFakeStdioUpstream(false)
		return
	case "legacy":
		runFakeStdioUpstream(true)
		return
	case "badversion":
		runBadVersionUpstream()
		return
	case "nodiscover":
		runNoDiscoverUpstream()
		return
	case "die":
		fmt.Fprintln(os.Stderr, "fake upstream: FAKE startup failure")
		os.Exit(3)
	case "dielist":
		runDieOnListUpstream()
		return
	}
	code := m.Run()
	if code == 0 {
		if leaks := waitForLeaks(5 * time.Second); len(leaks) > 0 {
			fmt.Fprintf(os.Stderr, "goroutine leak check: %d goroutine(s) from go-sdk or internal/proxy still running after all tests:\n\n%s\n",
				len(leaks), strings.Join(leaks, "\n\n"))
			code = 1
		} else {
			fmt.Fprintln(os.Stderr, "goroutine leak check: ok")
		}
	}
	os.Exit(code)
}

// runFakeStdioUpstream serves the fake upstream on stdio. Its "exit" tool
// ends the process without answering, like a crashing upstream; its "env"
// tool reports one environment variable. The era tools (addEraTools) ask for
// input. With legacy set it answers server/discover with method-not-found.
func runFakeStdioUpstream(legacy bool) {
	rec := &recorder{}
	s := fakeUpstream(rec, nil)
	addEraTools(s, rec)
	s.AddTool(&mcp.Tool{Name: "exit", InputSchema: objectSchema}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fmt.Fprint(os.Stderr, "last words without a newline")
		os.Exit(3)
		return nil, nil
	})
	s.AddTool(&mcp.Tool{Name: "env", InputSchema: objectSchema}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Name string `json:"name"`
		}
		_ = json.Unmarshal(req.Params.Arguments, &args)
		v, ok := os.LookupEnv(args.Name)
		if !ok {
			v = "<unset>"
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: v}}}, nil
	})
	s.AddTool(&mcp.Tool{Name: "stderr", InputSchema: objectSchema}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		fmt.Fprint(os.Stderr, "line one\n\x1b[31mred\x1b[0m\r\n")
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok"}}}, nil
	})
	var t mcp.Transport = &mcp.StdioTransport{}
	if legacy {
		t = legacyServer{t}
	}
	if err := s.Run(context.Background(), t); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// runBadVersionUpstream answers server/discover with method-not-found (so
// go-sdk falls back to the initialise request) and answers it with an unsupported
// protocol version. It ignores stdin EOF and sleeps, so only a kill ends it.
func runBadVersionUpstream() {
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		if json.Unmarshal(sc.Bytes(), &msg) != nil || len(msg.ID) == 0 {
			continue
		}
		var reply string
		if msg.Method == "initialize" { //nolint:misspell // MCP wire method name, not prose
			reply = fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"1999-01-01","capabilities":{},"serverInfo":{"name":"bad","version":"0"}}}`, msg.ID)
		} else {
			reply = fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"method not found"}}`, msg.ID)
		}
		fmt.Println(reply)
	}
	time.Sleep(time.Hour)
}

// runNoDiscoverUpstream behaves like a Python MCP SDK 1.9.3-or-older
// upstream (ADR 0018): server/discover kills its receive loop, so it answers
// nothing more and ignores stdin EOF, and only a kill ends it. A session that
// starts with the initialise request is served normally.
func runNoDiscoverUpstream() {
	s := fakeUpstream(&recorder{}, nil)
	if err := s.Run(context.Background(), noDiscover{&mcp.StdioTransport{}}); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

type noDiscover struct{ mcp.Transport }

func (t noDiscover) Connect(ctx context.Context) (mcp.Connection, error) {
	c, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return noDiscoverConn{c}, nil
}

type noDiscoverConn struct{ mcp.Connection }

func (c noDiscoverConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	m, err := c.Connection.Read(ctx)
	if r, ok := m.(*jsonrpc.Request); ok && err == nil && r.Method == "server/discover" {
		fmt.Fprintln(os.Stderr, "fake upstream: unknown method server/discover; not reading any more")
		select {} // the process lives on without reading
	}
	return m, err
}

// runDieOnListUpstream completes the handshake and exits with status 4 on
// tools/list, without answering it.
func runDieOnListUpstream() {
	s := fakeUpstream(&recorder{}, nil)
	s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/list" {
				fmt.Fprint(os.Stderr, "fake upstream: FAKE startup failure")
				os.Exit(4)
			}
			return next(ctx, method, req)
		}
	})
	if err := s.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func discardLogger() *slog.Logger { return slog.New(slog.DiscardHandler) }

func testExecutable(t *testing.T) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Skipf("no test executable: %v", err)
	}
	return exe
}

// syncBuffer is a goroutine-safe strings.Builder for captured stderr.
// Every Write signals notify (capacity 1, never blocks), so a test can wait
// for new output instead of polling.
type syncBuffer struct {
	mu     sync.Mutex
	b      strings.Builder
	notify chan struct{}
}

func newSyncBuffer() *syncBuffer { return &syncBuffer{notify: make(chan struct{}, 1)} }

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	n, err := s.b.Write(p)
	s.mu.Unlock()
	select {
	case s.notify <- struct{}{}:
	default:
	}
	return n, err
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// waitFor blocks until the buffer contains want, or fails after 5 seconds.
func (s *syncBuffer) waitFor(t *testing.T, want string) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for !strings.Contains(s.String(), want) {
		select {
		case <-s.notify:
		case <-timer.C:
			t.Fatalf("stderr never contained %q:\n%q", want, s.String())
		}
	}
}

func TestStdioUpstreamRoundTripAndExit(t *testing.T) {
	ctx := context.Background()
	// Neither of these may reach the upstream: only the allow-list and
	// --upstream-env do.
	t.Setenv("NETGUARD_TEST_SECRET", "FAKE-proxy-secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "FAKE-aws")
	stderr := newSyncBuffer()
	cmd := Command{
		Path:         testExecutable(t),
		Args:         []string{"-test.run=^$"},
		Env:          []string{fakeUpstreamEnv + "=1", "NETGUARD_TEST_UPSTREAM_VAR=FAKE-from-operator", childRaceEnv},
		Stderr:       stderr,
		StderrPrefix: "upstream netdev-ssh-mcp: ",
	}
	startCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	p, err := New(startCtx, []Upstream{{Server: testServer, NewTransport: func() mcp.Transport { return cmd.Transport() }}}, Options{})
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })

	agSrvT, agCliT := mcp.NewInMemoryTransports()
	runDone := make(chan error, 1)
	go func() { runDone <- p.Run(ctx, agSrvT) }()
	agent, err := mcp.NewClient(&mcp.Implementation{Name: "agent"}, nil).Connect(ctx, agCliT, nil)
	if err != nil {
		t.Fatal(err)
	}

	res, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01", "command": "show version"}})
	if err != nil || res.IsError || !strings.Contains(text(res), "show version") {
		t.Fatalf("round trip over stdio: %v %q", err, text(res))
	}

	envCases := []struct{ name, want string }{
		{"NETGUARD_TEST_UPSTREAM_VAR", "FAKE-from-operator"}, // --upstream-env
		{"NETGUARD_TEST_SECRET", "<unset>"},                  // proxy env withheld
		{"AWS_SECRET_ACCESS_KEY", "<unset>"},
		{"PATH", ""}, // allow-listed: any value but <unset>
	}
	for _, ec := range envCases {
		res, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.env", Arguments: map[string]any{"name": ec.name}})
		if err != nil {
			t.Fatal(err)
		}
		got := text(res)
		if ec.want == "" {
			if got == "<unset>" {
				t.Errorf("upstream env %s is unset, want it inherited", ec.name)
			}
		} else if got != ec.want {
			t.Errorf("upstream env %s = %q, want %q", ec.name, got, ec.want)
		}
	}

	if _, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.stderr"}); err != nil {
		t.Fatal(err)
	}
	stderr.waitFor(t, "upstream netdev-ssh-mcp: line one\nupstream netdev-ssh-mcp: \\u001b[31mred\\u001b[0m\n")

	// The upstream process dies mid-call.
	res, err = agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.exit"})
	if err != nil {
		t.Fatalf("want a tool error when the upstream dies mid-call, got %v", err)
	}
	if !res.IsError || !strings.Contains(text(res), "upstream netdev-ssh-mcp is not running") {
		t.Fatalf("mid-call exit: %q", text(res))
	}
	select {
	case <-p.upstreams[testServer].done:
	case <-time.After(10 * time.Second):
		t.Fatal("proxy did not notice the upstream process exit")
	}
	res, err = agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.get_config"})
	if err != nil || !res.IsError {
		t.Fatalf("call after exit: %v %q", err, text(res))
	}

	_ = agent.Close()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close after upstream exit: %v", err)
	}
	// The partial last line is flushed by Close, prefixed like the rest.
	if got := stderr.String(); !strings.HasSuffix(got, "upstream netdev-ssh-mcp: last words without a newline\n") {
		t.Fatalf("partial final stderr line not flushed on Close:\n%q", got)
	}
}

// G4: when go-sdk's Connect fails after the process started, the process is
// killed rather than left running.
func TestConnectFailureKillsUpstream(t *testing.T) {
	ct := Command{
		Path: testExecutable(t),
		Args: []string{"-test.run=^$"},
		Env:  []string{fakeUpstreamEnv + "=badversion", childRaceEnv},
	}.Transport()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: reuse(ct)}}, Options{})
	if err == nil {
		_ = p.Close()
		t.Fatal("New succeeded against an unsupported protocol version")
	}
	if !strings.Contains(err.Error(), "connect") {
		t.Fatalf("error %q", err)
	}
	if ct.Command.Process == nil {
		t.Fatal("upstream was never started")
	}
	if ct.Command.ProcessState == nil {
		t.Fatal("upstream process was not reaped; it is still running")
	}
}

func TestBaseEnv(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin", "HOME=/home/n", "USER=n", "LANG=C.UTF-8", "LC_ALL=C", "LC_TIME=C", "TMPDIR=/tmp",
		"NETGUARD_TEST_SECRET=FAKE", "AWS_SECRET_ACCESS_KEY=FAKE", "SSH_AUTH_SOCK=/tmp/agent", "LCX=1",
		"LC_FAKE_SECRET=FAKE", "LC_=x", "lc_all=C",
		"Path=C:\\Windows", "SystemRoot=C:\\Windows", "SYSTEMDRIVE=C:", "TEMP=t", "TMP=t", "USERPROFILE=u",
		"APPDATA=a", "LOCALAPPDATA=l", "PATHEXT=.EXE", "ComSpec=cmd.exe", "=C:=C:\\x", "NOVALUE",
		"\u017fystemRoot=FAKE-long-s", "SystemRoo\u212a=FAKE-kelvin",
	}
	cases := []struct {
		goos string
		want []string
	}{
		{"linux", []string{"PATH=/usr/bin", "HOME=/home/n", "USER=n", "LANG=C.UTF-8", "LC_ALL=C", "LC_TIME=C", "TMPDIR=/tmp"}},
		{"darwin", []string{"PATH=/usr/bin", "HOME=/home/n", "USER=n", "LANG=C.UTF-8", "LC_ALL=C", "LC_TIME=C", "TMPDIR=/tmp"}},
		{"windows", []string{"PATH=/usr/bin", "Path=C:\\Windows", "SystemRoot=C:\\Windows", "SYSTEMDRIVE=C:", "TEMP=t", "TMP=t", "USERPROFILE=u", "APPDATA=a", "LOCALAPPDATA=l", "PATHEXT=.EXE", "ComSpec=cmd.exe"}},
	}
	for _, tc := range cases {
		got := baseEnv(environ, tc.goos)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%s:\n got %q\nwant %q", tc.goos, got, tc.want)
		}
	}
}

func TestLineWriter(t *testing.T) {
	var out strings.Builder
	w := &lineWriter{w: &out, prefix: "upstream s: "}
	for _, chunk := range []string{"par", "tial\nwhole\r\n", "\x1b[2Jclear\n", "tab\there\n", "no newline yet"} {
		if n, err := w.Write([]byte(chunk)); n != len(chunk) || err != nil {
			t.Fatalf("Write(%q) = %d, %v", chunk, n, err)
		}
	}
	want := "upstream s: partial\nupstream s: whole\nupstream s: \\u001b[2Jclear\nupstream s: tab\\u0009here\n"
	if out.String() != want {
		t.Fatalf("got %q\nwant %q", out.String(), want)
	}
	// Flush writes the held partial line.
	w.Flush()
	if !strings.HasSuffix(out.String(), "upstream s: no newline yet\n") {
		t.Fatalf("Flush: %q", out.String())
	}
	w.Flush() // nothing held: no empty line
	if strings.HasSuffix(out.String(), "upstream s: \n") {
		t.Fatal("Flush of an empty buffer wrote a line")
	}

	// An over-long unterminated line is flushed on its own.
	out.Reset()
	w = &lineWriter{w: &out, prefix: "p: "}
	_, _ = w.Write([]byte(strings.Repeat("x", maxStderrLine)))
	if !strings.HasPrefix(out.String(), "p: xxx") || !strings.HasSuffix(out.String(), "x\n") {
		t.Fatalf("long line not flushed: %d bytes", out.Len())
	}

	// The 4096-byte cut never splits a multi-byte character: with a 3-byte
	// character straddling the limit, it moves to the next line whole.
	out.Reset()
	w = &lineWriter{w: &out, prefix: ""}
	_, _ = w.Write([]byte(strings.Repeat("x", maxStderrLine-1) + "€" + "tail\n"))
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) != 2 || lines[0] != strings.Repeat("x", maxStderrLine-1) || lines[1] != "€tail" {
		t.Fatalf("cut split a character: %d lines, second %q", len(lines), lines[len(lines)-1])
	}
	if !utf8.ValidString(out.String()) {
		t.Fatal("cut produced invalid UTF-8")
	}
	// A line of exactly maxStderrLine bytes and its newline is one line, not
	// a line plus an empty one.
	out.Reset()
	w = &lineWriter{w: &out, prefix: ""}
	_, _ = w.Write([]byte(strings.Repeat("y", maxStderrLine) + "\nnext\n"))
	if want := strings.Repeat("y", maxStderrLine) + "\nnext\n"; out.String() != want {
		t.Fatalf("exact-limit line: got %d bytes, %q...", out.Len(), out.String()[out.Len()-10:])
	}
}

func TestRuneCut(t *testing.T) {
	euro := "€" // 3 bytes
	cases := []struct {
		name string
		in   string
		want int
	}{
		{"ascii", "abc", 3},
		{"complete multibyte at end", "ab" + euro, 5},
		{"one byte of three", "ab" + euro[:1], 2},
		{"two bytes of three", "ab" + euro[:2], 2},
		{"stray continuation bytes kept", "ab\x82\x82", 4},
		{"empty", "", 0},
	}
	for _, tc := range cases {
		if got := runeCut([]byte(tc.in)); got != tc.want {
			t.Errorf("%s: runeCut = %d, want %d", tc.name, got, tc.want)
		}
	}
}

// TestStdioUpstreamEras is the era matrix over a real child process: the
// upstream is spawned over stdio pinned to each era, and an agent of each era
// negotiates, calls, gets the upstream's progress, and answers the
// upstream's prompt through netguard.
func TestStdioUpstreamEras(t *testing.T) {
	for _, e := range eras {
		t.Run("agent "+e.agent+" upstream "+e.upstream, func(t *testing.T) {
			mode := "1"
			if e.upstream == v2025 {
				mode = "legacy"
			}
			ct := Command{
				Path: testExecutable(t),
				Args: []string{"-test.run=^$"},
				Env:  []string{fakeUpstreamEnv + "=" + mode, childRaceEnv},
			}.Transport()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: reuse(ct)}}, Options{})
			cancel()
			if err != nil {
				t.Fatal(err)
			}
			if got := p.upstreams[testServer].version; got != e.upstream {
				_ = p.Close()
				t.Fatalf("stdio upstream negotiated %s, want %s", got, e.upstream)
			}
			prompts := &promptLog{}
			progress := newProgressLog()
			agent, _ := connectAgent(t, p, eraSetup{agent: e.agent, progress: progress}, prompts)
			if got := agent.InitializeResult().ProtocolVersion; got != e.agent {
				t.Fatalf("agent negotiated %s, want %s", got, e.agent)
			}

			bg := context.Background()
			res, err := agent.CallTool(bg, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01", "command": "show version"}})
			if err != nil || res.IsError || !strings.Contains(text(res), "show version") {
				t.Fatalf("round trip: %v %q", err, text(res))
			}

			// Progress crosses the real child under netguard's token (T0.17).
			checkProgress(t, agent, progress)

			res, err = agent.CallTool(bg, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask"})
			if err != nil {
				t.Fatal(err)
			}
			if e.agent == v2026 && e.upstream == v2025 {
				if !res.IsError || !strings.Contains(text(res), "ADR 0014") || len(prompts.all()) != 0 {
					t.Fatalf("want the ADR 0014 refusal, got %v %q", res.IsError, text(res))
				}
				return
			}
			if res.IsError || !strings.Contains(text(res), "pw=accept:"+agentPassword) {
				t.Fatalf("ask: %v %q", res.IsError, text(res))
			}
			if got := prompts.all(); len(got) != 1 || got[0].Message != labelledPrompt {
				t.Fatalf("prompts %+v", got)
			}
		})
	}
}
