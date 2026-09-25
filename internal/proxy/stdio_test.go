// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
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
// server/discover (ADR 0018) and "silent" answers nothing at all; "die"
// exits 3 at once, "dielist" exits 4 on tools/list, "listerror" answers
// tools/list with an error, and "garbage" prints a line that is not
// JSON-RPC (T0.25). "launcher" stands in front of another mode as `uvx` or
// `npx` stands in front of a server (ADR 0021, runLauncher).
const fakeUpstreamEnv = "FATHOMGATE_TEST_FAKE_UPSTREAM"

// Launcher fixture (ADR 0021). launchChildEnv is the mode of the launcher's
// child, the upstream's grandchild; launcherEOFEnv is "exit" for a launcher
// that exits when its stdin reaches EOF, anything else for one that ignores
// it. fakeLingerEnv makes a fake ignore SIGTERM and, where it would exit
// once its stdin closes, sleep instead, as the T0.34 server does once its
// receive loop has died: only a kill ends it. launcherExitArg in a line the
// launcher relays makes it exit at once without relaying the line.
const (
	launchChildEnv  = "FATHOMGATE_TEST_LAUNCH_CHILD"
	launcherEOFEnv  = "FATHOMGATE_TEST_LAUNCHER_EOF"
	fakeLingerEnv   = "FATHOMGATE_TEST_LINGER"
	launcherExitArg = "FAKE-launcher-exit"
	launcherPIDLine = "fake launcher: child pid "
)

// childRaceEnv stops a -race child from sleeping a second at exit to let
// the race detector report; every spawned fake exits several times per
// run, and the upstream only inherits what Command.Env passes.
const childRaceEnv = "GORACE=atexit_sleep_ms=0"

func TestMain(m *testing.M) {
	if os.Getenv(fakeUpstreamEnv) == "launcher" {
		// First, before anything else runs: the child must be started at
		// the launcher's first instruction (ADR 0021, the Windows race).
		runLauncher()
		return
	}
	if os.Getenv(fakeLingerEnv) == "1" {
		signal.Ignore(syscall.SIGTERM)
	}
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
	case "silent":
		// Reads everything, answers nothing, and ignores stdin EOF: only a
		// kill ends it.
		_, _ = io.Copy(io.Discard, os.Stdin)
		time.Sleep(time.Hour)
		return
	case "nodiscover":
		runNoDiscoverUpstream()
		return
	case "listerror":
		runListErrorUpstream()
		return
	case "garbage":
		// One line that is not JSON-RPC, then a clean exit once stdin
		// closes.
		fmt.Println("this is not JSON-RPC")
		_, _ = io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
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
	exitOrLinger()
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
	// Stdin EOF: whoever holds the other end has begun closing it.
	fmt.Fprintln(os.Stderr, "fake upstream: stdin closed")
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
	exitOrLinger()
}

// exitOrLinger ends a fake whose stdin has closed: exit 0, or with
// fakeLingerEnv set, sleep until killed.
func exitOrLinger() {
	if os.Getenv(fakeLingerEnv) == "1" {
		time.Sleep(time.Hour)
	}
	os.Exit(0)
}

// runLauncher is the launcher fixture (ADR 0021). It re-executes the test
// binary as its child in the launchChildEnv mode, with fakeLingerEnv set,
// reports the child's PID on stderr, and relays its own stdin to the
// child's, line by line, and the child's stdout to its own. The child
// inherits the launcher's stderr, as a real launcher's child does, so it
// holds the upstream's stderr pipe; it does not hold the upstream's stdout,
// so the launcher's exit ends the session (the exit watcher case). The
// launcher ignores SIGTERM, and stdin EOF unless launcherEOFEnv is "exit";
// it exits 5 on a line containing launcherExitArg.
func runLauncher() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "fake launcher:", err)
		os.Exit(1)
	}
	child := exec.Command(exe, "-test.run=^$")
	child.Env = append(os.Environ(), fakeUpstreamEnv+"="+os.Getenv(launchChildEnv), fakeLingerEnv+"=1")
	child.Stderr = os.Stderr
	in, err := child.StdinPipe()
	if err != nil {
		os.Exit(1)
	}
	out, err := child.StdoutPipe()
	if err != nil {
		os.Exit(1)
	}
	if err := child.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "fake launcher:", err)
		os.Exit(1)
	}
	signal.Ignore(syscall.SIGTERM)
	fmt.Fprintf(os.Stderr, "%s%d\n", launcherPIDLine, child.Process.Pid)
	go func() { _, _ = io.Copy(os.Stdout, out) }()
	r := bufio.NewReader(os.Stdin)
	for {
		line, err := r.ReadBytes('\n')
		if bytes.Contains(line, []byte(launcherExitArg)) {
			os.Exit(5)
		}
		if len(line) > 0 {
			_, _ = in.Write(line)
		}
		if err != nil {
			break
		}
	}
	if os.Getenv(launcherEOFEnv) == "exit" {
		os.Exit(0)
	}
	time.Sleep(time.Hour)
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
		// The process lives on without reading. A sleep, not select{}:
		// with every goroutine blocked the runtime could abort with "all
		// goroutines are asleep", and the fake would exit on its own.
		time.Sleep(time.Hour)
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

// runListErrorUpstream completes the handshake, answers tools/list with a
// JSON-RPC error, and exits 0 when its stdin closes: an exit fathomgate
// caused, which must not be reported as the upstream's exit status.
func runListErrorUpstream() {
	s := fakeUpstream(&recorder{}, nil)
	s.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/list" {
				return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "FAKE tools/list failure"}
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
	t.Setenv("FATHOMGATE_TEST_SECRET", "FAKE-proxy-secret")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "FAKE-aws")
	stderr := newSyncBuffer()
	cmd := Command{
		Path:         testExecutable(t),
		Args:         []string{"-test.run=^$"},
		Env:          []string{fakeUpstreamEnv + "=1", "FATHOMGATE_TEST_UPSTREAM_VAR=FAKE-from-operator", childRaceEnv},
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
		{"FATHOMGATE_TEST_UPSTREAM_VAR", "FAKE-from-operator"}, // --upstream-env
		{"FATHOMGATE_TEST_SECRET", "<unset>"},                  // proxy env withheld
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
// killed rather than left running. The upstream answers (with a version
// go-sdk rejects) and ignores stdin EOF, so go-sdk is still inside its own
// close when the probe bound runs out. That is an answer, not an unanswered
// probe: no restart, no warn line, and the error is the real one (S1 in the
// review of PR #77). fathomgate caused the process's end, so no exit status.
func TestConnectFailureKillsUpstream(t *testing.T) {
	logs := newSyncBuffer()
	stderr := newSyncBuffer()
	b := &commandBuilds{cmd: Command{
		Path:   testExecutable(t),
		Args:   []string{"-test.run=^$"},
		Env:    []string{fakeUpstreamEnv + "=badversion", childRaceEnv},
		Stderr: stderr,
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// The bound expires once go-sdk has begun its own close (the fake sees
	// stdin EOF) and while that close still waits its 5 s grace: the case
	// that was misread as an unanswered probe.
	e := newProbeExpiry()
	type result struct {
		p   *Proxy
		err error
	}
	done := make(chan result, 1)
	go func() {
		p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: b.build}},
			Options{Logger: slog.New(slog.NewTextHandler(logs, nil)), discoverExpired: e.ch})
		done <- result{p, err}
	}()
	stderr.waitFor(t, "fake upstream: stdin closed\n")
	e.fire()
	out := <-done
	p, err := out.p, out.err
	if err == nil {
		_ = p.Close()
		t.Fatal("New succeeded against an unsupported protocol version")
	}
	msg := err.Error()
	if !strings.Contains(msg, "proxy: upstream netdev-ssh-mcp: connect: ") || !strings.Contains(msg, "unsupported protocol version") {
		t.Errorf("error %q is not the upstream's rejected answer", msg)
	}
	if strings.Contains(msg, "upstream process ended") {
		t.Errorf("error %q reports an exit status fathomgate or go-sdk caused", msg)
	}
	if strings.Contains(logs.String(), restartWarning) {
		t.Errorf("restart warning for an upstream that answered:\n%s", logs.String())
	}
	built := b.get()
	if len(built) != 1 {
		t.Fatalf("processes started: %d, want 1", len(built))
	}
	if built[0].Command.Process == nil {
		t.Fatal("upstream was never started")
	}
	if built[0].Command.ProcessState == nil {
		t.Fatal("upstream process was not reaped; it is still running")
	}
}

func TestBaseEnv(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin", "HOME=/home/n", "USER=n", "LANG=C.UTF-8", "LC_ALL=C", "LC_TIME=C", "TMPDIR=/tmp",
		"FATHOMGATE_TEST_SECRET=FAKE", "AWS_SECRET_ACCESS_KEY=FAKE", "SSH_AUTH_SOCK=/tmp/agent", "LCX=1",
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
// upstream's prompt through fathomgate.
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

			// Progress crosses the real child under fathomgate's token (T0.17).
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
