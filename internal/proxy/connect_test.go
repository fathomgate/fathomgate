package proxy

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tests for ADR 0018 (T0.39: bound the server/discover probe, restart,
// initialise handshake only) and T0.25 (the upstream's exit status at startup).

// reuse is a NewTransport for a transport that cannot be rebuilt (an
// in-memory one): it returns t every time. Fine wherever the upstream
// answers the probe, so no restart happens.
func reuse(t mcp.Transport) func() mcp.Transport {
	return func() mcp.Transport { return t }
}

// upstreamAttempt serves the far end of one in-memory transport pair and
// returns the methods that end has received so far.
type upstreamAttempt func(t *testing.T, st mcp.Transport) (methods func() []string)

// rebuildable is a NewTransport that builds a new in-memory pair on every
// call and serves attempt i with serve[i]: the rebuildable test transport
// the restart needs. builds reports how many pairs were built, and
// methods(i) what attempt i's upstream received.
type rebuildable struct {
	t     *testing.T
	serve []upstreamAttempt

	mu      sync.Mutex
	methods []func() []string
}

func newRebuildable(t *testing.T, serve ...upstreamAttempt) *rebuildable {
	return &rebuildable{t: t, serve: serve}
}

func (r *rebuildable) build() mcp.Transport {
	r.mu.Lock()
	defer r.mu.Unlock()
	i := len(r.methods)
	if i >= len(r.serve) {
		r.t.Errorf("NewTransport called %d times, want at most %d", i+1, len(r.serve))
		return nil
	}
	st, ct := mcp.NewInMemoryTransports()
	r.methods = append(r.methods, r.serve[i](r.t, st))
	return ct
}

func (r *rebuildable) builds() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.methods)
}

func (r *rebuildable) received(i int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.methods[i]()
}

// methodLog records the method of every request or notification read.
type methodLog struct {
	mu  sync.Mutex
	all []string
}

func (l *methodLog) add(m jsonrpc.Message) {
	if r, ok := m.(*jsonrpc.Request); ok {
		l.mu.Lock()
		l.all = append(l.all, r.Method)
		l.mu.Unlock()
	}
}

func (l *methodLog) get() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.all)
}

// silentAttempt reads everything and answers nothing: a Python MCP SDK
// 1.9.3-or-older upstream after server/discover has killed its receive
// loop.
func silentAttempt(t *testing.T, st mcp.Transport) func() []string {
	conn, err := st.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	log := &methodLog{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			m, err := conn.Read(context.Background())
			if err != nil {
				return
			}
			log.add(m)
		}
	}()
	t.Cleanup(func() { _ = conn.Close(); <-done })
	return log.get
}

// hangUpAttempt closes the connection at once: an upstream that dies
// before it answers anything.
func hangUpAttempt(t *testing.T, st mcp.Transport) func() []string {
	conn, err := st.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	return func() []string { return nil }
}

// serverAttempt is the fake go-sdk upstream pinned to an era (pinServer),
// with every method it reads recorded.
func serverAttempt(version string) upstreamAttempt {
	return func(t *testing.T, st mcp.Transport) func() []string {
		log := &methodLog{}
		ss, err := fakeUpstream(&recorder{}, nil).Connect(context.Background(), pinServer(version, methodTap{st, log}), nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ss.Close() })
		return log.get
	}
}

// methodTap records the methods the wrapped server transport reads, before
// anything (pinServer included) acts on them.
type methodTap struct {
	mcp.Transport
	log *methodLog
}

func (t methodTap) Connect(ctx context.Context) (mcp.Connection, error) {
	c, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return methodTapConn{c, t.log}, nil
}

type methodTapConn struct {
	mcp.Connection
	log *methodLog
}

func (c methodTapConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	m, err := c.Connection.Read(ctx)
	if err == nil {
		c.log.add(m)
	}
	return m, err
}

// restartWarning is the start of ADR 0018's warn line.
const restartWarning = "did not answer server/discover within"

// TestDiscoverProbe: the first connect is bounded; only running out of the
// bound restarts the upstream, once, with the initialise handshake only.
func TestDiscoverProbe(t *testing.T) {
	const bound = 200 * time.Millisecond
	cases := []struct {
		name    string
		serve   []upstreamAttempt
		bound   time.Duration // 0: the real 5 s
		startup time.Duration // the caller's startup budget
		builds  int
		version string // negotiated, on success
		wantErr []string
	}{
		{
			name:  "probe answered: no restart, stateless",
			serve: []upstreamAttempt{serverAttempt(v2026)}, startup: 30 * time.Second,
			builds: 1, version: v2026,
		},
		{
			name:  "probe refused: go-sdk's own fallback, no restart",
			serve: []upstreamAttempt{serverAttempt(v2025)}, startup: 30 * time.Second,
			builds: 1, version: v2025,
		},
		{
			name:  "probe unanswered: restart, initialise handshake only",
			serve: []upstreamAttempt{silentAttempt, serverAttempt(v2026)}, bound: bound, startup: 30 * time.Second,
			builds: 2, version: v2025,
		},
		{
			name:  "second attempt hangs up: its error, no third attempt",
			serve: []upstreamAttempt{silentAttempt, hangUpAttempt}, bound: bound, startup: 30 * time.Second,
			builds: 2,
			wantErr: []string{
				"proxy: upstream netdev-ssh-mcp: connect with " + initOnly + " (restarted after server/discover got no answer within 200ms): ",
			},
		},
		{
			name:  "second attempt silent: the startup budget ends it",
			serve: []upstreamAttempt{silentAttempt, silentAttempt}, bound: bound, startup: time.Second,
			builds: 2,
			wantErr: []string{
				"proxy: upstream netdev-ssh-mcp: connect with " + initOnly + " (restarted after server/discover got no answer within 200ms): ",
				"context deadline exceeded",
			},
		},
		{
			name:  "startup budget ends inside the bound: no restart",
			serve: []upstreamAttempt{silentAttempt}, startup: bound,
			builds:  1,
			wantErr: []string{"proxy: upstream netdev-ssh-mcp: connect: context deadline exceeded"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := newSyncBuffer()
			r := newRebuildable(t, tc.serve...)
			ctx, cancel := context.WithTimeout(context.Background(), tc.startup)
			defer cancel()
			p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: r.build}},
				Options{Logger: slog.New(slog.NewTextHandler(logs, nil)), discoverWait: tc.bound})
			if err == nil {
				t.Cleanup(func() { _ = p.Close() })
			}
			if got := r.builds(); got != tc.builds {
				t.Errorf("transports built: %d, want %d", got, tc.builds)
			}
			if n := strings.Count(logs.String(), restartWarning); n != tc.builds-1 {
				t.Errorf("restart warnings: %d, want %d:\n%s", n, tc.builds-1, logs.String())
			}
			if tc.builds == 2 {
				const want = `level=WARN msg="upstream netdev-ssh-mcp did not answer server/discover within 200ms; restarting it and connecting with ` + initOnly + ` (protocol 2025-11-25)" server=netdev-ssh-mcp`
				if !strings.Contains(logs.String(), want) {
					t.Errorf("warn line missing; want %s in:\n%s", want, logs.String())
				}
				if first := r.received(0); len(first) == 0 || first[0] != "server/discover" {
					t.Errorf("first attempt received %q, want server/discover first", first)
				}
				if second := r.received(1); slices.Contains(second, "server/discover") {
					t.Errorf("second attempt received server/discover: %q", second)
				}
			}
			if tc.wantErr != nil {
				if err == nil {
					t.Fatal("New succeeded, want an error")
				}
				for _, w := range tc.wantErr {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("error %q does not contain %q", err, w)
					}
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			up := p.upstreams[testServer]
			if up.version != tc.version {
				t.Errorf("negotiated %s, want %s", up.version, tc.version)
			}
			if tc.builds == 2 {
				if second := r.received(1); len(second) == 0 || second[0] != "initialize" { //nolint:misspell // MCP wire method name
					t.Errorf("second attempt received %q, want the initialise request first", second)
				}
			}
			if p.toolCount(up) == 0 {
				t.Error("no tools listed after connect")
			}
			if !strings.Contains(logs.String(), "upstream ready") {
				t.Errorf("no upstream ready line:\n%s", logs.String())
			}
		})
	}
}

// commandBuilds is a NewTransport over a Command that keeps every
// transport it built.
type commandBuilds struct {
	cmd Command
	mu  sync.Mutex
	all []*mcp.CommandTransport
}

func (c *commandBuilds) build() mcp.Transport {
	ct := c.cmd.Transport()
	c.mu.Lock()
	c.all = append(c.all, ct)
	c.mu.Unlock()
	return ct
}

func (c *commandBuilds) get() []*mcp.CommandTransport {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.all)
}

// TestDiscoverProbeRestartsStdioUpstream is the restart over a real child
// process: the first process stops reading at server/discover and ignores
// stdin EOF, so only a kill ends it; it is killed and reaped, its stderr
// relayed, and a second process is connected with the initialise handshake
// only.
func TestDiscoverProbeRestartsStdioUpstream(t *testing.T) {
	stderr := newSyncBuffer()
	logs := newSyncBuffer()
	b := &commandBuilds{cmd: Command{
		Path:         testExecutable(t),
		Args:         []string{"-test.run=^$"},
		Env:          []string{fakeUpstreamEnv + "=nodiscover", childRaceEnv},
		Stderr:       stderr,
		StderrPrefix: "upstream netdev-ssh-mcp: ",
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: b.build}},
		Options{Logger: slog.New(slog.NewTextHandler(logs, nil)), discoverWait: time.Second})
	if err != nil {
		t.Fatalf("%v\nlog:\n%s\nstderr:\n%s", err, logs.String(), stderr.String())
	}
	t.Cleanup(func() { _ = p.Close() })

	built := b.get()
	if len(built) != 2 {
		t.Fatalf("processes started: %d, want 2", len(built))
	}
	if built[0].Command.ProcessState == nil {
		t.Fatal("the first process was not reaped before the restart")
	}
	if got := p.upstreams[testServer].version; got != v2025 {
		t.Fatalf("negotiated %s, want %s", got, v2025)
	}
	if n := strings.Count(logs.String(), restartWarning); n != 1 {
		t.Fatalf("restart warnings: %d\n%s", n, logs.String())
	}
	stderr.waitFor(t, "upstream netdev-ssh-mcp: fake upstream: unknown method server/discover; not reading any more\n")

	agent, _ := connectAgent(t, p, eraSetup{agent: v2026}, &promptLog{})
	res, err := agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01", "command": "show version"}})
	if err != nil || res.IsError || !strings.Contains(text(res), "show version") {
		t.Fatalf("round trip after the restart: %v %q", err, text(res))
	}
}

// TestStartupExitStatus (T0.25): an upstream that dies during startup is
// reported with its exit status, not only as a closed connection, and its
// last stderr line still reaches the operator.
func TestStartupExitStatus(t *testing.T) {
	cases := []struct {
		mode, phase, status string
	}{
		{"die", "connect", "exit status 3"},
		{"dielist", "tools/list", "exit status 4"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			stderr := newSyncBuffer()
			cmd := Command{
				Path:         testExecutable(t),
				Args:         []string{"-test.run=^$"},
				Env:          []string{fakeUpstreamEnv + "=" + tc.mode, childRaceEnv},
				Stderr:       stderr,
				StderrPrefix: "upstream netdev-ssh-mcp: ",
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: func() mcp.Transport { return cmd.Transport() }}}, Options{})
			if err == nil {
				_ = p.Close()
				t.Fatal("New succeeded against an upstream that dies at startup")
			}
			msg := err.Error()
			if !strings.Contains(msg, "proxy: upstream netdev-ssh-mcp: "+tc.phase+": ") {
				t.Errorf("error %q does not name the phase %s", msg, tc.phase)
			}
			if !strings.HasSuffix(msg, "; upstream process ended: "+tc.status) {
				t.Errorf("error %q does not end with the exit status %q", msg, tc.status)
			}
			if got := stderr.String(); !strings.Contains(got, "upstream netdev-ssh-mcp: fake upstream: FAKE startup failure") {
				t.Errorf("the upstream's last stderr line was not relayed:\n%q", got)
			}
		})
	}
}

// TestExitStatus: only a process that was waited for has a status.
func TestExitStatus(t *testing.T) {
	if got := exitStatus(nil); got != "exit status 0" {
		t.Errorf("nil: %q", got)
	}
	if got := exitStatus(fmt.Errorf("closing stdin: %v", os.ErrClosed)); got != "" {
		t.Errorf("not an exit error: %q", got)
	}
	if got := withExit(context.Canceled, ""); got != context.Canceled {
		t.Errorf("withExit without a status changed the error: %v", got)
	}
}
