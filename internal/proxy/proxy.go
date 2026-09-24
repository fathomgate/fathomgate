package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Name is the implementation name NetGuard reports as serverInfo toward the
// agent and as clientInfo toward each upstream.
const Name = "netguard"

// maxUpstreamTools caps how many tools one upstream may list. The upstream is
// untrusted; a server that pages forever must not hang or exhaust the proxy.
const maxUpstreamTools = 1024

// exitGrace is how long a failed call waits for the upstream's exit to be
// observed before choosing its error, so a mid-call crash reads as "not
// running" rather than as a generic failure.
const exitGrace = 2 * time.Second

// discoverProbeTimeout bounds the first connect to an upstream, which is
// go-sdk's server/discover probe and, when the probe gets an error, its
// initialise fallback (ADR 0018). An upstream that has not connected within
// it is restarted and connected again with the initialise handshake only.
// It is not configurable in M0: no flag, no profile field.
const discoverProbeTimeout = 5 * time.Second

// restartProtocolVersion is the protocol version requested on the second
// connect attempt. go-sdk sends server/discover only when the requested
// version is 2026-07-28 or newer, so this goes straight to initialise and
// negotiates down from there (to 2024-11-05 if that is all the upstream
// knows).
const restartProtocolVersion = "2025-11-25"

// initOnly names the second attempt in its warn line and error, spelled as
// ADR 0018's warn line and the MCP method spell it.
const initOnly = "initialize only" //nolint:misspell // MCP method name, not prose

// Upstream is one MCP server the proxy connects to as a client.
type Upstream struct {
	// Server is the tool prefix toward the agent. It is the `server` key of
	// the upstream's profile in profiles/, never derived from the binary name.
	Server string
	// NewTransport returns a new transport to the upstream each time it is
	// called; for a stdio upstream that is a new process. [New] calls it
	// once, and a second time only when the upstream did not connect within
	// 5 seconds of starting the first connect, spawn included, and is
	// restarted (ADR 0018).
	// `netguard serve` passes a function returning [Command.Transport]. A
	// function that returns the same transport each time (an in-memory
	// transport in tests) works only as long as that restart never happens:
	// the restart connects the used transport again, which fails (a
	// CommandTransport's exec.Cmd cannot be started twice).
	NewTransport func() mcp.Transport
}

// Options configures a [Proxy]. The zero value is usable.
type Options struct {
	// Version is reported in serverInfo and clientInfo.
	Version string
	// Logger receives proxy and go-sdk diagnostics. Nil discards them. For a
	// stdio proxy it must not write to stdout, which carries the protocol.
	Logger *slog.Logger

	// discoverExpired, when set, replaces the discoverProbeTimeout timer:
	// the first connect's bound runs out when it is closed. It is for tests
	// only, so they can expire the bound at a known point instead of racing
	// a short timer against a child's start: it is unexported, so no caller
	// outside the package can set it, and M0 has no flag or profile field
	// for the bound (ADR 0018). It is shared by every upstream in the call
	// to New: once closed, each later first connect starts expired. Log and
	// error text still say 5s.
	discoverExpired <-chan struct{}
}

// Proxy is an MCP server toward the agent and an MCP client toward each
// upstream. It is built by [New], served by [Proxy.Run] and released by
// [Proxy.Close].
type Proxy struct {
	server *mcp.Server
	logger *slog.Logger
	states *sealer          // requestState envelopes for stateless agents
	now    func() time.Time // clock for the progress rate limit
	// progressWait bounds how long a call's end waits for its queued
	// progress to reach the agent (progressFinalWait; tests shorten it).
	progressWait time.Duration
	upstreams    map[string]*upstream // by server name
	routes       map[string]route     // by prefixed tool name
	// limits caps and tracks tool calls per agent session and principal.
	// It is set by HTTPHandler and nil on stdio, where one agent owns the
	// process (calls.go).
	limits    atomic.Pointer[callLimits]
	closeOnce sync.Once
	closeErr  error
}

// route maps one agent-facing tool name to its upstream and unprefixed name.
type route struct {
	up   *upstream
	tool string
}

// upstream is one connected upstream session. done is closed, and err set,
// when the session ends for any reason; the watcher goroutine started in
// connectUpstream is its only writer and is owned by the Proxy (Close waits
// for it).
type upstream struct {
	name    string
	tt      *trackedTransport // the connected attempt's, to flush a Command's stderr on Close
	red     *Redactor         // a Command's Secrets, scrubbed from relayed errors
	session *mcp.ClientSession
	// version is the protocol version negotiated with the upstream, and so
	// its era (eraOf): go-sdk tries server/discover first and falls back to
	// the initialise handshake, or connect restarts the upstream and
	// connects with the initialise handshake only (ADR 0018).
	version string
	done    chan struct{}
	err     error
	closing atomic.Bool

	mu       sync.Mutex
	calls    map[*inflight]struct{}    // calls in flight, for elicitation/create
	progress map[string]*progressRelay // by netguard's progress token (progress.go)
	// orphans are the agent sessions that have ended a call on this
	// upstream, which may still be working on it, each until its expiry.
	// They are keyed by netguard's own key for the agent session
	// (agentSessionKey), never by the session itself, which would keep a
	// closed session alive for the whole TTL. orphanOverflow stands for
	// every session past maxOrphans and for every session that can never
	// own another call (input.go).
	orphans        map[string]orphan
	orphanOverflow time.Time
}

// exited reports whether the upstream session has ended.
func (u *upstream) exited() bool {
	select {
	case <-u.done:
		return true
	default:
		return false
	}
}

// New connects to every upstream, lists its tools once and registers each as
// "<server>.<tool>" on the agent-facing server. ctx bounds the connect and
// list phase only; it does not bound the lifetime of the upstream sessions.
//
// It fails if no upstream is given, a server name is not a valid prefix, two
// upstreams share a server name, an upstream lists the same tool twice, or
// an upstream cannot be connected or listed. Upstream tools whose name or
// input schema cannot be re-exposed are skipped and logged.
func New(ctx context.Context, upstreams []Upstream, opts Options) (_ *Proxy, err error) {
	if len(upstreams) == 0 {
		return nil, errors.New("proxy: no upstream configured")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	states, err := newSealer()
	if err != nil {
		return nil, err
	}
	impl := &mcp.Implementation{Name: Name, Version: opts.Version}
	p := &Proxy{
		logger:       logger,
		states:       states,
		now:          time.Now,
		progressWait: progressFinalWait,
		upstreams:    make(map[string]*upstream, len(upstreams)),
		routes:       make(map[string]route),
		server: mcp.NewServer(impl, &mcp.ServerOptions{
			Logger: slog.New(minLevel{logger.Handler(), slog.LevelWarn}),
			// Tools only. The tool list is fixed at startup, so no
			// listChanged; no logging capability.
			Capabilities: &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}},
		}),
	}
	defer func() {
		if err != nil {
			_ = p.Close()
		}
	}()

	for _, u := range upstreams {
		if err := ValidateServerName(u.Server); err != nil {
			return nil, fmt.Errorf("proxy: %w", err)
		}
		if _, dup := p.upstreams[u.Server]; dup {
			return nil, fmt.Errorf("proxy: server %q is configured twice; tool prefixes must be unique", u.Server)
		}
		if u.NewTransport == nil {
			return nil, fmt.Errorf("proxy: server %q has no transport", u.Server)
		}
		up, err := p.connectUpstream(ctx, impl, u, opts.discoverExpired)
		if err != nil {
			return nil, err
		}
		tools, err := listTools(ctx, up)
		if err != nil {
			// An upstream that died after the handshake: say how it ended
			// (T0.25). The deferred Close then finds it stopped.
			up.closing.Store(true)
			return nil, withExit(err, up.tt.kill(graceFor(ctx)))
		}
		if err := p.addUpstreamTools(up, tools); err != nil {
			return nil, err
		}
		p.logger.Info("upstream ready", "server", up.name, "tools", p.toolCount(up), "protocol", up.version, "era", eraOf(up.version))
	}
	p.server.AddReceivingMiddleware(refuseUndeclared, p.checkToolName)
	return p, nil
}

// connectUpstream starts one upstream session and its exit watcher. go-sdk
// negotiates the era: server/discover first (stateless, 2026-07-28), then the
// initialise handshake (stateful, 2025-11-25 and older) if the upstream
// answers the probe with an error. An upstream that has not connected within
// discoverProbeTimeout is restarted and connected with the initialise
// handshake only (ADR 0018; connect). expired, when not nil, replaces the
// timer (Options.discoverExpired).
func (p *Proxy) connectUpstream(ctx context.Context, impl *mcp.Implementation, u Upstream, expired <-chan struct{}) (*upstream, error) {
	first := u.NewTransport()
	if first == nil {
		return nil, fmt.Errorf("proxy: server %q has no transport", u.Server)
	}
	// The Redactor is built from the Command's Secrets, which a restarted
	// upstream shares, so the first transport's serves both attempts. It is
	// set before Connect because the handlers below read it.
	up := &upstream{name: u.Server, red: redactorOf(first), done: make(chan struct{})}
	client := mcp.NewClient(impl, &mcp.ClientOptions{
		Logger: slog.New(minLevel{p.logger.Handler(), slog.LevelWarn}),
		// Form elicitation only (the handler makes go-sdk advertise it): no
		// roots, no sampling. Upstream prompts reach the agent only
		// relabelled with their origin (input.go).
		Capabilities:       &mcp.ClientCapabilities{},
		ElicitationHandler: p.upstreamElicitation(up),
		// Do not let go-sdk answer MRTR input requests on our behalf;
		// forward relabels them and puts them to the agent itself.
		MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
		// Progress for netguard's own tokens only, rebuilt for the agent
		// (progress.go).
		ProgressNotificationHandler: p.upstreamProgress(up),
	})
	if expired == nil {
		ch := make(chan struct{})
		t := time.AfterFunc(discoverProbeTimeout, func() { close(ch) })
		defer t.Stop()
		expired = ch
	}
	cs, tt, err := p.connect(ctx, client, u, &trackedTransport{Transport: first}, expired)
	if err != nil {
		return nil, err
	}
	up.session = cs
	up.tt = tt
	if ir := cs.InitializeResult(); ir != nil {
		up.version = ir.ProtocolVersion
	}
	p.upstreams[u.Server] = up
	go func() {
		defer close(up.done)
		up.err = cs.Wait()
		if !up.closing.Load() {
			p.logger.Error("upstream exited; its tools now return errors", "server", up.name, "error", up.err)
		}
	}()
	return up, nil
}

// connect makes at most two connect attempts (ADR 0018) and returns the
// session and the transport it runs on.
//
// The first is go-sdk's own negotiation, bounded by expired (closed after
// discoverProbeTimeout). Only an unanswered probe leads to the second
// attempt: the bound ran out while ctx was still live, and go-sdk had not
// begun closing the connection before it did (it closes when it has an
// answer it rejects, such as an unsupported protocol version, and that
// close can outlast the bound). Then the first
// upstream process is killed and reaped, one warn line is logged, and a new
// transport (a new process) is connected with the initialise handshake only.
// The restart is not optional: an upstream that did not answer the probe
// may answer nothing more on that connection. Any other first-attempt
// error, and any second-attempt error, is returned; there is no third
// attempt. ctx bounds both attempts: when it is done, the process of the
// attempt in progress is killed at once.
//
// A failed attempt's process is stopped, and if it had hung up and ended on
// its own, its exit status is added to the error (T0.25).
func (p *Proxy) connect(ctx context.Context, client *mcp.Client, u Upstream, first *trackedTransport, expired <-chan struct{}) (*mcp.ClientSession, *trackedTransport, error) {
	const bound = discoverProbeTimeout // for the log and error text
	cs, timedOut, err := connectAttempt(ctx, client, first, nil, expired)
	if err == nil {
		return cs, first, nil
	}
	if !timedOut {
		exit := first.kill(graceFor(ctx))
		return nil, nil, withExit(fmt.Errorf("proxy: upstream %s: connect: %w", u.Server, escapedError{err}), exit)
	}
	first.kill(0)
	p.logger.Warn(fmt.Sprintf("upstream %s did not answer server/discover within %s; restarting it and connecting with %s (protocol %s)",
		u.Server, bound, initOnly, restartProtocolVersion), "server", u.Server)
	if err := ctx.Err(); err != nil {
		// Startup ended (Ctrl-C, SIGTERM, the budget) while the first
		// process was being stopped: never spawn a second upstream, with
		// its credentials, for a start that has already failed (L2 in the
		// re-review of PR #79).
		return nil, nil, fmt.Errorf("proxy: upstream %s: connect: server/discover got no answer within %s, and startup ended before the restart: %w",
			u.Server, bound, err)
	}
	t := u.NewTransport()
	if t == nil {
		return nil, nil, fmt.Errorf("proxy: server %q: NewTransport returned no transport for the restart", u.Server)
	}
	second := &trackedTransport{Transport: t}
	cs, _, err = connectAttempt(ctx, client, second, &mcp.ClientSessionOptions{ProtocolVersion: restartProtocolVersion}, nil)
	if err != nil {
		exit := second.kill(graceFor(ctx))
		return nil, nil, withExit(fmt.Errorf("proxy: upstream %s: connect with %s (restarted after server/discover got no answer within %s): %w",
			u.Server, initOnly, bound, escapedError{err}), exit)
	}
	return cs, second, nil
}

// connectAttempt is one Client.Connect on tt, bounded by ctx always and,
// when expired is not nil, by expired being closed. timedOut reports that
// the attempt failed because expired was closed while ctx was still live
// and before go-sdk had begun closing the connection: the one case connect
// retries.
//
// When the attempt's context ends, the upstream process is killed at once,
// while go-sdk is still inside Connect. go-sdk closes the session itself on
// its way out, and that close would otherwise give an upstream that has
// stopped reading the full shutdown grace (5 seconds, then SIGTERM) first,
// past the bound and past ctx.
func connectAttempt(ctx context.Context, client *mcp.Client, tt *trackedTransport, opts *mcp.ClientSessionOptions, expired <-chan struct{}) (cs *mcp.ClientSession, timedOut bool, err error) {
	actx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	// Written by the watcher, read after it is joined.
	var didExpire, closedFirst bool
	connected := make(chan struct{})
	watcher := make(chan struct{})
	go func() {
		defer close(watcher)
		select {
		case <-expired: // a nil channel never fires
			// Whether go-sdk had begun closing is read before actx is
			// cancelled, so no close the expiry causes can be counted. A
			// flag under tt.mu, not two timestamps: on Windows time.Now can
			// return the same value for both.
			didExpire, closedFirst = true, tt.closeWasRequested()
			cancel(errProbeExpired)
		case <-connected:
		}
	}()
	stopKill := context.AfterFunc(actx, tt.killProcess)
	cs, err = client.Connect(actx, tt, opts)
	killed := !stopKill()
	close(connected)
	<-watcher
	if killed && err == nil {
		// Connect finished as the context ended, and the process is being
		// killed under it: the session is lost.
		_ = cs.Close()
		cs, err = nil, context.Cause(actx)
	}
	if err != nil && ctx.Err() == nil && didExpire {
		timedOut = !closedFirst
	}
	return cs, timedOut, err
}

// errProbeExpired is the cause of a first connect cancelled by its bound.
var errProbeExpired = errors.New("server/discover got no answer within the bound")

// graceFor is how long a failed startup waits for the upstream process to
// end on its own before killing it: exitGrace, cut to what is left of ctx,
// and nothing once ctx is done.
func graceFor(ctx context.Context) time.Duration {
	if ctx.Err() != nil {
		return 0
	}
	g := exitGrace
	if d, ok := ctx.Deadline(); ok {
		g = min(g, time.Until(d))
	}
	return max(g, 0)
}

// withExit adds an upstream process's exit status, when there is one, to a
// startup error. The status is exec's text, not the upstream's.
func withExit(err error, exit string) error {
	if exit == "" {
		return err
	}
	return fmt.Errorf("%w; upstream process ended: %s", err, exit)
}

// trackedTransport records the Connection its Transport returns, and for a
// CommandTransport the process it started, so a failed Connect can close
// and kill them. go-sdk may or may not have closed that connection already.
//
// For the transports whose connection is go-sdk's plain newline-delimited
// connection (tracksConn) it also wraps the connection, to learn who ended
// it: whether a close was requested, when it finished and whether a kill
// came first, and whether the upstream hung up (its stdout reached end of
// stream, or a write to its stdin failed) before netguard or go-sdk asked
// for a close or a kill. Other transports (Streamable HTTP) are not
// wrapped, because go-sdk finds optional methods on their connections by
// type assertion, which a wrapper would hide; for them no close is ever
// seen, so an expired bound always counts as unanswered and no exit status
// is reported.
type trackedTransport struct {
	mcp.Transport

	// Orders are kept as flags set under mu, not compared timestamps: on
	// Windows time.Now can return the same value for two events.
	mu             sync.Mutex
	conn           mcp.Connection
	proc           *os.Process
	killed         bool      // killProcess has run: a process recorded later is killed at once
	closeRequested bool      // a close of the connection has been requested
	closeDone      time.Time // when that close first returned: the process has been reaped
	reapedUnkilled bool      // that close returned before any kill
	hungUp         bool      // a read or write failed before any close or kill was requested
	hungUpAt       time.Time
}

// tracksConn reports whether t's connections are go-sdk's plain
// newline-delimited connection (*mcp.ioConn), so that wrapping them hides
// nothing from go-sdk.
//
// go-sdk v1.8.0 makes these type assertions on a client session's
// connection (grep -n 'mcpConn.(' mcp/*.go):
//
//   - client.go:331 and :400, clientConnection (the unexported
//     sessionUpdated(clientSessionState)): only the Streamable HTTP client
//     connection has it. ioConn's sessionUpdated takes ServerSessionState,
//     which is the server side's serverConnection, so the assertion fails
//     on ioConn with or without the wrapper.
//   - client.go:554, hasSessionID (SessionID() string): part of the
//     exported Connection interface, so the embedded Connection promotes it
//     through the wrapper.
//   - transport.go:221, cancellationPropagator (the unexported
//     propagateCancellation() bool): ioConn does not have it, so the
//     assertion fails with or without the wrapper.
//
// An unexported method is never promoted through the embedded interface,
// which is why every other transport stays unwrapped. On a go-sdk bump,
// re-run the grep and re-check each assertion against ioConn
// (CONTRIBUTING.md, "Bumping go-sdk").
func tracksConn(t mcp.Transport) bool {
	switch t.(type) {
	case *mcp.CommandTransport, *mcp.InMemoryTransport, *mcp.IOTransport, *mcp.StdioTransport:
		return true
	}
	return false
}

// Connect implements [mcp.Transport].
func (t *trackedTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	c, err := t.Transport.Connect(ctx)
	if err != nil {
		return c, err
	}
	var proc *os.Process
	if ct, ok := t.Transport.(*mcp.CommandTransport); ok && ct.Command != nil {
		proc = ct.Command.Process // set by Start inside Connect, on this goroutine
	}
	if tracksConn(t.Transport) {
		c = trackedConn{Connection: c, t: t}
	}
	t.mu.Lock()
	t.conn, t.proc = c, proc
	kill := t.killed
	t.mu.Unlock()
	if kill && proc != nil {
		_ = proc.Kill()
	}
	return c, nil
}

// closeWasRequested reports whether a close of the connection has been
// requested.
func (t *trackedTransport) closeWasRequested() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closeRequested
}

// failed records a read or write error. It is a hang-up by the upstream
// only if nobody had asked for a close or a kill yet.
func (t *trackedTransport) failed() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.hungUp && !t.closeRequested && !t.killed {
		t.hungUp, t.hungUpAt = true, time.Now()
	}
}

// endedOnItsOwn reports whether the process hung up, then was reaped within
// exitGrace of that, before anything was killed. Only then is its exit
// status its own: after a requested close it may be the upstream's reply to
// a closed stdin, and after a kill (netguard's, or go-sdk's after its
// shutdown grace, which also comes more than exitGrace later) it is the
// kill's.
func (t *trackedTransport) endedOnItsOwn() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.hungUp && t.reapedUnkilled && t.closeDone.Sub(t.hungUpAt) <= exitGrace
}

// killProcess kills the process behind a CommandTransport, now or, if it
// has not been started yet, as soon as Connect records it. Other transports
// own no process. It is safe from any goroutine: it never calls Wait or
// reads ProcessState, and Process.Kill is safe while another goroutine is
// in Wait.
func (t *trackedTransport) killProcess() {
	t.mu.Lock()
	t.killed = true
	proc := t.proc
	t.mu.Unlock()
	if proc != nil {
		_ = proc.Kill()
	}
}

// trackedConn is a Connection that reports to its trackedTransport who
// ended it (see trackedTransport).
type trackedConn struct {
	mcp.Connection
	t *trackedTransport
}

// Read implements [mcp.Connection].
//
// Only end of stream counts as a hang-up. Any other read error (a line
// that is not JSON-RPC, say) comes from an upstream that is still there:
// go-sdk then closes the connection, and the upstream's exit on the closed
// stdin is not its own (N2 in the re-review of PR #79).
func (c trackedConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	m, err := c.Connection.Read(ctx)
	if err != nil && ctx.Err() == nil && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)) {
		c.t.failed()
	}
	return m, err
}

// Write implements [mcp.Connection]. A write to a newline-delimited
// connection fails, with ctx live, only when the pipe to the upstream's
// stdin is gone, so any such failure is a hang-up: go-sdk may write to an
// upstream that has already exited before it reads the end of its stdout.
func (c trackedConn) Write(ctx context.Context, m jsonrpc.Message) error {
	err := c.Connection.Write(ctx, m)
	if err != nil && ctx.Err() == nil {
		c.t.failed()
	}
	return err
}

// Close implements [mcp.Connection]. go-sdk's own closes, inside Connect
// and on a failed read or write, come through here too.
func (c trackedConn) Close() error {
	c.t.mu.Lock()
	c.t.closeRequested = true
	c.t.mu.Unlock()
	err := c.Connection.Close()
	c.t.mu.Lock()
	if c.t.closeDone.IsZero() {
		c.t.closeDone, c.t.reapedUnkilled = time.Now(), !c.t.killed
	}
	c.t.mu.Unlock()
	return err
}

// kill ends a failed attempt: it closes the recorded connection, which for
// a CommandTransport closes the upstream's stdin and reaps the process, and
// then flushes the process's partial last stderr line. With a grace above
// zero the process gets that long to end on its own before it is killed;
// with none it is killed first, so the close reaps at once rather than
// after go-sdk's 5-second shutdown grace. Only the direct child is killed;
// see the Command godoc on grandchildren.
//
// It returns the exit status ("exit status 3") of a process that hung up
// and ended on its own (endedOnItsOwn), and "" otherwise. The status comes
// from the error go-sdk's connection Close returns, which is Wait's: kill
// never calls Wait or reads ProcessState itself. That Close runs once
// (sync.Once), and a second caller blocks until the first has finished and
// gets the same error, so kill returns only after the process has been
// reaped, whether go-sdk closed first or not.
func (t *trackedTransport) kill(grace time.Duration) (exit string) {
	t.mu.Lock()
	c, proc := t.conn, t.proc
	t.mu.Unlock()
	defer flushStderr(t.Transport)
	if c == nil {
		return ""
	}
	var waitErr error
	if proc == nil || grace <= 0 {
		t.killProcess()
		waitErr = c.Close()
	} else {
		closed := make(chan error, 1)
		go func() { closed <- c.Close() }()
		timer := time.NewTimer(grace)
		defer timer.Stop()
		select {
		case waitErr = <-closed:
		case <-timer.C:
			t.killProcess()
			waitErr = <-closed
		}
	}
	if proc == nil || !t.endedOnItsOwn() {
		return ""
	}
	return exitStatus(waitErr)
}

// exitStatus describes how a process ended from the error its Wait
// returned: "exit status 0" for nil, exec's own text for an *exec.ExitError,
// and "" for anything else (the process may not have been waited for).
func exitStatus(err error) string {
	if err == nil {
		return "exit status 0"
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.String()
	}
	return ""
}

// redactorOf returns the Redactor for a Command's Secrets, or nil for any
// other transport or a Command without secrets.
func redactorOf(t mcp.Transport) *Redactor {
	ct, ok := t.(*mcp.CommandTransport)
	if !ok || ct.Command == nil {
		return nil
	}
	if lw, ok := ct.Command.Stderr.(*lineWriter); ok {
		return lw.red
	}
	return nil
}

// flushStderr writes out a partial final stderr line held by a Command's
// line writer. Call it only after the process has been reaped, when no more
// stderr can arrive.
func flushStderr(t mcp.Transport) {
	ct, ok := t.(*mcp.CommandTransport)
	if !ok || ct.Command == nil {
		return
	}
	if lw, ok := ct.Command.Stderr.(*lineWriter); ok {
		lw.Flush()
	}
}

// toolCount is the number of tools exposed for up.
func (p *Proxy) toolCount(up *upstream) int {
	n := 0
	for _, r := range p.routes {
		if r.up == up {
			n++
		}
	}
	return n
}

// listTools reads the upstream's full tool list, following pagination.
func listTools(ctx context.Context, up *upstream) ([]*mcp.Tool, error) {
	tools := make([]*mcp.Tool, 0, 16)
	for t, err := range up.session.Tools(ctx, nil) {
		if err != nil {
			return nil, fmt.Errorf("proxy: upstream %s: tools/list: %w", up.name, escapedError{err})
		}
		if len(tools) == maxUpstreamTools {
			return nil, fmt.Errorf("proxy: upstream %s: tools/list: more than %d tools", up.name, maxUpstreamTools)
		}
		tools = append(tools, t)
	}
	return tools, nil
}

// addUpstreamTools registers each upstream tool under its prefixed name.
// Tool descriptions, schemas and annotations are untrusted and are passed
// through unchanged: annotations are never used to decide anything here, and
// descriptions are pinned by internal/redact from M2. _meta and icons are
// dropped because the proxy does not forward resources or UI.
func (p *Proxy) addUpstreamTools(up *upstream, tools []*mcp.Tool) error {
	seen := make(map[string]bool, len(tools))
	for _, t := range tools {
		if t == nil {
			continue
		}
		if seen[t.Name] {
			return fmt.Errorf("proxy: upstream %s lists tool %q twice", up.name, t.Name)
		}
		seen[t.Name] = true
		if err := validUpstreamToolName(up.name, t.Name); err != nil {
			p.logger.Warn("skipping upstream tool", "server", up.name, "error", err)
			continue
		}
		if err := checkInputSchema(t.InputSchema); err != nil {
			p.logger.Warn("skipping upstream tool", "server", up.name, "tool", t.Name, "error", err)
			continue
		}
		name := prefixName(up.name, t.Name)
		if _, dup := p.routes[name]; dup {
			return fmt.Errorf("proxy: tool name %q collides across upstreams", name)
		}
		exposed := &mcp.Tool{
			Name:         name,
			Title:        t.Title,
			Description:  t.Description,
			InputSchema:  t.InputSchema,
			OutputSchema: t.OutputSchema,
			Annotations:  t.Annotations,
		}
		r := route{up: up, tool: t.Name}
		if err := safeAddTool(p.server, exposed, p.handler(r)); err != nil {
			p.logger.Warn("skipping upstream tool", "server", up.name, "tool", t.Name, "error", err)
			continue
		}
		p.routes[name] = r
	}
	return nil
}

// checkInputSchema rejects schemas that go-sdk's Server.AddTool would panic
// on: the input schema must be a JSON object with "type": "object".
func checkInputSchema(s any) error {
	m, ok := s.(map[string]any)
	if !ok {
		return fmt.Errorf("input schema is %T, not a JSON object", s)
	}
	if m["type"] != "object" {
		return fmt.Errorf(`input schema type is %v, not "object"`, m["type"])
	}
	return nil
}

// safeAddTool calls Server.AddTool and turns its panics on malformed tools
// into errors, so one bad upstream tool cannot crash the proxy.
func safeAddTool(s *mcp.Server, t *mcp.Tool, h mcp.ToolHandler) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("rejected by go-sdk: %v", r)
		}
	}()
	s.AddTool(t, h)
	return nil
}

// minLevel drops records below a floor. go-sdk logs every request at Info;
// only its warnings and errors reach the operator's stderr.
type minLevel struct {
	slog.Handler
	floor slog.Level
}

// Enabled reports whether l is at or above the floor and the wrapped
// handler is enabled for it.
func (h minLevel) Enabled(ctx context.Context, l slog.Level) bool {
	return l >= h.floor && h.Handler.Enabled(ctx, l)
}

// WithAttrs returns a minLevel wrapping the handler with attrs added.
func (h minLevel) WithAttrs(attrs []slog.Attr) slog.Handler {
	return minLevel{h.Handler.WithAttrs(attrs), h.floor}
}

// WithGroup returns a minLevel wrapping the handler with the group opened.
func (h minLevel) WithGroup(name string) slog.Handler {
	return minLevel{h.Handler.WithGroup(name), h.floor}
}

// Run serves one agent session on t until the agent disconnects or ctx is
// cancelled. For `netguard serve`, t is [mcp.StdioTransport].
func (p *Proxy) Run(ctx context.Context, t mcp.Transport) error {
	return p.server.Run(ctx, t)
}

// Close ends every upstream session (for a stdio upstream: close its stdin,
// wait, then terminate the process) and waits for the exit watchers. It is
// idempotent.
//
// When an HTTP handler has been built, Close first cancels every tool call
// in flight, refuses new ones, and closes every agent session. go-sdk's
// session Close waits for the requests in flight rather than cancelling
// them, so the calls are cancelled first.
func (p *Proxy) Close() error {
	p.closeOnce.Do(func() {
		if l := p.limits.Load(); l != nil {
			l.close()
			for ss := range p.server.Sessions() {
				_ = ss.Close()
			}
			// The session watchers (settleSession) return once their
			// sessions have closed.
			l.wait()
		}
		names := make([]string, 0, len(p.upstreams))
		for n := range p.upstreams {
			names = append(names, n)
		}
		slices.Sort(names)
		var errs []error
		for _, n := range names {
			up := p.upstreams[n]
			alreadyExited := up.exited()
			up.closing.Store(true)
			if err := up.session.Close(); err != nil && !alreadyExited {
				errs = append(errs, fmt.Errorf("upstream %s: close: %w", n, err))
			}
			<-up.done
			// session.Close has waited for a Command's process, and exec
			// has finished copying its stderr, so the last line is final.
			flushStderr(up.tt.Transport)
		}
		p.closeErr = errors.Join(errs...)
	})
	return p.closeErr
}

// call is one agent tools/call after the prefix has been resolved. It is
// what M1's pipeline and audit read: the agent's era is in agent.version,
// the upstream's in up.version.
type call struct {
	up        *upstream
	tool      string          // unprefixed upstream tool name
	arguments json.RawMessage // as received from the agent, not yet parsed
	agent     agentPeer
	// progressToken is the agent's own progressToken, or nil. It is never
	// sent upstream; netguard issues its own (progress.go).
	progressToken any

	// principal names the bearer token the request arrived with over the
	// HTTP listener (HTTPOptions.Tokens); it is "" on stdio. It is
	// attribution only, for the M4 audit line and (T0.30) the sealed
	// requestState: never an approver identity (invariant 6).
	principal string
	// sessionKey is netguard's own key for the agent session behind the
	// call, used to attribute a stateful upstream's prompt (input.go). The
	// tool handler sets it from Proxy.agentSessionKey.
	sessionKey string

	// An MRTR retry from a stateless agent: its answers and the
	// requestState netguard issued. Both are empty on a first call.
	inputResponses mcp.InputResponseMap
	requestState   string
}

// handler is the go-sdk tool handler for one route. The agent's _meta is
// read for era detection (go-sdk does that) and for its progressToken, and
// never forwarded.
func (p *Proxy) handler(r route) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		c, ignored := newCall(r, req)
		c.sessionKey = p.agentSessionKey(c)
		if ignored > 0 {
			p.logger.Debug("ignoring inputResponses sent without a requestState", "server", r.up.name, "tool", r.tool, "responses", ignored)
		}
		// Over HTTP, a call over its session's or principal's cap is refused
		// here, before anything reaches the upstream (T3 in the review of
		// PR #63). The call's context is also cancelled when its session is
		// deleted or the proxy closes (calls.go).
		if l := p.limits.Load(); l != nil {
			actx, release, refused := l.admit(ctx, c.principal, req.Session, prefixName(r.up.name, r.tool))
			if refused != nil {
				p.logger.Warn("call refused: too many in flight", "server", r.up.name, "tool", r.tool, "principal", c.principal)
				return refused, nil
			}
			defer release()
			ctx = actx
		}
		return p.dispatch(ctx, c)
	}
}

// newCall is what dispatch sees of one agent tools/call. inputResponses
// that arrive without a requestState answer prompts netguard never relayed
// (T0.18): they are cleared here, before dispatch, so no later stage (M1's
// pipeline and audit included) can read or act on them as answers
// (invariant 6: nothing the agent supplies stands in for a human). The call
// then goes up as a first call and an upstream that needs input asks again.
// It returns how many answers it cleared.
func newCall(r route, req *mcp.CallToolRequest) (call, int) {
	c := call{up: r.up, tool: r.tool, agent: agentOf(req), progressToken: agentProgressToken(req), principal: principalOf(req)}
	ignored := 0
	if req.Params != nil {
		c.arguments = req.Params.Arguments
		c.requestState = req.Params.RequestState
		if c.requestState != "" {
			c.inputResponses = req.Params.InputResponses
		} else {
			ignored = len(req.Params.InputResponses)
		}
	}
	return c, ignored
}

// dispatch is the seam where the M1 pipeline plugs in. From M1 it runs
// normalize, classify, inventory and policy.Evaluate on c, sequences the
// obligations, and only then forwards; on the way back the result passes
// through redact and audit. In M0 there is no policy: every call is
// forwarded as is.
func (p *Proxy) dispatch(ctx context.Context, c call) (*mcp.CallToolResult, error) {
	return p.forward(ctx, c)
}

// forward sends c to its upstream under the agent's request context, so an
// agent cancellation cancels the upstream call.
//
// Nothing of the agent's request crosses except the tool name and
// arguments, and on an MRTR retry the allow-listed answers (resume). The
// upstream sees netguard's own identity, era and capabilities: go-sdk adds
// them to _meta toward a stateless upstream. If the agent asked for
// progress, the upstream gets a progressToken netguard issued, never the
// agent's (progress.go).
//
// Outcomes, in order: an upstream request for input is relabelled and put
// to the agent (input_required for a stateless agent, elicitation/create
// for a stateful one) or refused with a tool error; the upstream result is
// returned without its _meta; an upstream JSON-RPC error is relayed through
// relayUpstreamError; an upstream that has exited, before or during the
// call, yields a tool error (isError) naming it.
func (p *Proxy) forward(ctx context.Context, c call) (*mcp.CallToolResult, error) {
	up := c.up
	params := &mcp.CallToolParams{Name: c.tool}
	if len(c.arguments) > 0 && string(c.arguments) != "null" {
		params.Arguments = c.arguments
	}
	round, prompts := 0, 0
	// Only a retry with netguard's requestState carries answers; newCall
	// has already cleared any sent without one (T0.18).
	if c.requestState != "" {
		rs, err := p.resume(c)
		if err != nil {
			return nil, err
		}
		params.InputResponses, params.RequestState = rs.responses, rs.upState
		round, prompts = rs.round, rs.prompts
	}
	if up.exited() {
		return upstreamDown(up), nil
	}
	p.logger.Debug("forwarding", "server", up.name, "tool", c.tool,
		"agent_protocol", c.agent.version, "upstream_protocol", up.version, "round", round)

	f := up.begin(ctx, c, prompts)
	pr := newProgressRelay(ctx, up.name, c.agent, c.progressToken, p.now, p.progressWait)
	if pr != nil {
		up.watchProgress(pr)
		params.SetProgressToken(pr.upToken)
	}
	// One deferred function, so the order is explicit: the call leaves the
	// upstream's in-flight set first (and becomes an orphan of its agent
	// session in the same step, so no prompt can find the upstream with
	// neither), and only then waits (up to progressWait) for its progress to
	// reach the agent. The other way round (T1 in the review of PR #63), a
	// stalled agent kept a stale entry there for that long, and a stateful
	// upstream's prompt for another agent's call was refused as
	// unattributable in the meantime.
	//
	// Every call that ends becomes an orphan, whether it was cancelled or
	// the upstream answered it: the upstream may have left a job running, or
	// go-sdk may dispatch a prompt the upstream sent just before its result
	// after that result, and either way the prompt must not reach another
	// agent session's human (J1 in the re-review of PR #72).
	defer func() {
		now := p.now()
		p.logReaped(up, up.end(f, now, now.Add(p.orphanTTL())))
		up.unwatchProgress(pr) // no-op when pr is nil
	}()
	for ; ; round++ {
		res, err := up.session.CallTool(ctx, params)
		own, note := up.refusalsFor(f)
		if err != nil {
			if own != nil && ctx.Err() == nil {
				// The upstream failed after netguard refused this call's own
				// prompt: the refusal is the reason, so say that instead.
				// An unattributed note never replaces an upstream error.
				return toolError(own.Error()), nil
			}
			return p.callFailed(ctx, c, err)
		}
		switch {
		case res == nil:
			return toolError(fmt.Sprintf("upstream %s returned no result for %s", up.name, c.tool)), nil
		case !res.NeedsInput():
			return withRefusals(passResult(res), own, note), nil
		case len(res.InputRequests) == 0:
			return toolError(fmt.Sprintf("upstream %s is busy (input_required with no requests); retry %s later", up.name, c.tool)), nil
		}

		reqs, r := relabelInputRequests(up.name, c.tool, res.InputRequests)
		switch {
		case r != nil:
		case !c.agent.canElicit:
			r = newRefusal(up.name, c.tool, "elicitation", errNoFormElicitation)
		case round >= maxInputRounds:
			r = newRefusal(up.name, c.tool, "input_required", fmt.Errorf("more than %d rounds of input in one call", maxInputRounds))
		case up.promptsSoFar(f)+len(reqs) > maxPromptsPerCall:
			// Checked before anything is asked, so no human answers half a
			// round that cannot be completed.
			r = newRefusal(up.name, c.tool, "input_required", errTooManyPrompts)
		case len(res.RequestState) > maxRequestState:
			r = newRefusal(up.name, c.tool, "input_required", errors.New("the upstream's requestState is too large"))
		}
		if r != nil {
			_ = p.refuse(up, f, r)
			return toolError(r.Error()), nil
		}

		if c.agent.stateless() {
			ids := make([]string, 0, len(reqs))
			for id := range reqs {
				ids = append(ids, id)
			}
			slices.Sort(ids)
			// Measure the sealed state, not the upstream's: escaping and
			// encoding can push a state under maxRequestState past what
			// open accepts.
			state, err := p.states.seal(sealedState{
				Server: up.name, Tool: c.tool, Args: argsDigest(c.arguments),
				IDs: ids, Up: res.RequestState, Round: round + 1,
				Prompts: up.promptsSoFar(f) + len(reqs),
			})
			if err != nil {
				r = newRefusal(up.name, c.tool, "input_required", err)
				_ = p.refuse(up, f, r)
				return toolError(r.Error()), nil
			}
			return &mcp.CallToolResult{InputRequests: reqs, RequestState: state}, nil
		}
		answers, stop, err := p.askAgent(ctx, c, f, reqs)
		if err != nil || stop != nil {
			return stop, err
		}
		params.InputResponses = answers
		params.RequestState = res.RequestState
	}
}

// orphanTTL is how long a call that has ended keeps blocking cross-session
// prompt attribution: the HTTP listener's OrphanTTL, or its default on
// stdio (where one agent session owns the process, so it never blocks). It
// is deliberately much shorter than the listener's idle SessionTimeout: an
// orphan refuses prompts to other agent sessions, so it must expire soon
// after the upstream could still be working on the call (J3 in the
// re-review of PR #72).
func (p *Proxy) orphanTTL() time.Duration {
	if l := p.limits.Load(); l != nil && l.orphanTTL > 0 {
		return l.orphanTTL
	}
	return defaultOrphanTTL
}

// callFailed maps a failed upstream call to what the agent sees.
func (p *Proxy) callFailed(ctx context.Context, c call, err error) (*mcp.CallToolResult, error) {
	up := c.up
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var ref *refusal
	if errors.As(err, &ref) {
		// go-sdk's URL-elicitation retry called netguard's own handler.
		return toolError(ref.Error()), nil
	}
	var werr *jsonrpc.Error
	if errors.As(err, &werr) {
		return nil, relayUpstreamError(up.name, werr, up.red)
	}
	if errors.Is(err, mcp.ErrConnectionClosed) || errors.Is(err, io.EOF) || awaitExit(ctx, up, exitGrace) {
		return upstreamDown(up), nil
	}
	msg := up.red.Redact(err.Error())
	p.logger.Warn("upstream call failed", "server", up.name, "tool", c.tool, "error", msg)
	return toolError(fmt.Sprintf("upstream %s: calling %s failed: %s", up.name, c.tool, escapeControl(msg, maxRelayedMessage))), nil
}

// passResult is the agent-facing copy of an upstream's final result:
// content, structured content and isError. The upstream's result _meta
// (which could claim io.modelcontextprotocol/serverInfo, for one) and any
// requestState or inputRequests on a complete result are dropped. Toward a
// stateless agent go-sdk then adds netguard's own serverInfo.
func passResult(res *mcp.CallToolResult) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content:           res.Content,
		StructuredContent: res.StructuredContent,
		IsError:           res.IsError,
	}
}

// awaitExit reports whether up has exited, waiting up to d (or until ctx is
// done) for its exit watcher when it has not yet.
func awaitExit(ctx context.Context, up *upstream, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-up.done:
		return true
	case <-ctx.Done():
		return up.exited()
	case <-t.C:
		return false
	}
}

// upstreamDown is the tool error for a call to an upstream that has exited.
func upstreamDown(up *upstream) *mcp.CallToolResult {
	return toolError(fmt.Sprintf("upstream %s is not running; restart netguard serve", up.name))
}

// toolError is a tool result with isError set and text as its only content:
// how netguard reports a failure the agent can act on, as opposed to a
// JSON-RPC protocol error.
func toolError(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}

// Reasons in the data of an unknown-tool error.
const (
	reasonUnprefixed    = "unprefixed"
	reasonUnknownServer = "unknown_server"
	reasonUnknownTool   = "unknown_tool"
)

// unknownToolData is the structured data of an unknown-tool JSON-RPC error.
type unknownToolData struct {
	Tool    string   `json:"tool"`
	Reason  string   `json:"reason"`
	Servers []string `json:"servers"`
}

// undeclaredCapability returns the capability a method belongs to when the
// proxy does not declare it (it declares tools only), or "". go-sdk would
// otherwise answer these with empty lists or an empty result, which tells
// the agent something the proxy never offered. subscriptions/listen is not
// here: it is core in 2026-07-28, and go-sdk acknowledges only the
// notifications the declared capabilities allow (none, since tools has no
// listChanged).
func undeclaredCapability(method string) string {
	switch method {
	case "prompts/list", "prompts/get":
		return "prompts"
	case "resources/list", "resources/read", "resources/templates/list", "resources/subscribe", "resources/unsubscribe":
		return "resources"
	case "logging/setLevel":
		return "logging"
	case "completion/complete":
		return "completions"
	default:
		return ""
	}
}

// refuseUndeclared is receiving middleware: a request for a method of a
// capability the proxy does not declare gets JSON-RPC method-not-found
// (-32601) in either era.
func refuseUndeclared(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if capability := undeclaredCapability(method); capability != "" {
			return nil, &jsonrpc.Error{
				Code:    jsonrpc.CodeMethodNotFound,
				Message: fmt.Sprintf("method %q is not supported: netguard does not declare the %s capability", method, capability),
			}
		}
		return next(ctx, method, req)
	}
}

// checkToolName is receiving middleware: a tools/call whose name is not a
// known "<server>.<tool>" gets a JSON-RPC invalid-params error (-32602, as
// the MCP spec requires for unknown tools) that says why, before any handler
// or upstream sees it.
func (p *Proxy) checkToolName(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if r, ok := req.(*mcp.CallToolRequest); ok && r.Params != nil {
			if _, known := p.routes[r.Params.Name]; !known {
				return nil, p.unknownTool(r.Params.Name)
			}
		}
		return next(ctx, method, req)
	}
}

func (p *Proxy) unknownTool(name string) error {
	servers := make([]string, 0, len(p.upstreams))
	for n := range p.upstreams {
		servers = append(servers, n)
	}
	slices.Sort(servers)
	shown := clip(name)
	d := unknownToolData{Tool: shown, Servers: servers}
	var msg string
	server, tool, ok := splitName(name)
	switch {
	case !ok:
		d.Reason = reasonUnprefixed
		msg = fmt.Sprintf("unknown tool %q: tool names are <server>.<tool>; servers: %s", shown, strings.Join(servers, ", "))
	case p.upstreams[server] == nil:
		d.Reason = reasonUnknownServer
		msg = fmt.Sprintf("unknown tool %q: no upstream server %q; servers: %s", shown, clip(server), strings.Join(servers, ", "))
	default:
		d.Reason = reasonUnknownTool
		msg = fmt.Sprintf("unknown tool %q: server %s has no tool %q", shown, server, clip(tool))
	}
	data, err := json.Marshal(d)
	if err != nil {
		data = nil
	}
	return &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: msg, Data: data}
}

// clip bounds agent-supplied names echoed back in errors.
func clip(s string) string {
	const limit = 200
	if len(s) <= limit {
		return s
	}
	return s[:limit] + "..."
}
