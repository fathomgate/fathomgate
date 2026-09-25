// SPDX-License-Identifier: Apache-2.0

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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Name is the implementation name Fathomgate reports as serverInfo toward the
// agent and as clientInfo toward each upstream.
const Name = "fathomgate"

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
	// `fathomgate serve` passes a function returning [Command.Transport]. A
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
	// Gate decides every tools/call before it is forwarded (ADR 0026). nil
	// keeps the M0 pass-through: every call is forwarded as the agent sent
	// it, and nothing is checked, counted or logged as a decision.
	Gate Gate

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
	now    func() time.Time // clock for the progress rate limit, orphan expiry and refusal log limit
	// progressWait bounds how long a call's end waits for its queued
	// progress to reach the agent (progressFinalWait; tests shorten it).
	progressWait time.Duration
	upstreams    map[string]*upstream // by server name
	routes       map[string]route     // by prefixed tool name
	// gate is Options.Gate; nil forwards every call (M0). counters are the
	// session counters it is given (gate.go).
	gate     Gate
	counters counters
	// limits caps and tracks tool calls per agent session and principal.
	// It is set by HTTPHandler and nil on stdio, where one agent owns the
	// process (calls.go).
	limits atomic.Pointer[callLimits]
	// locals are the agent sessions Run is serving, each with the
	// attribution key it gave it (agentSessionKey); runs numbers them.
	// connecting holds one ready channel per Run between its registration
	// and the recording of its session, closed once recorded, so no request
	// on a session is keyed before its entry exists (localKey). All three
	// are guarded by localMu, which is never held across Connect.
	localMu    sync.Mutex
	locals     map[*mcp.ServerSession]string
	connecting map[chan struct{}]struct{}
	runs       int
	// refusalLog rate-limits the Warn lines of refused upstream input
	// requests (warnRefusal) and refused requestStates (warnState), both in
	// input.go.
	refusalLog refusalLimiter
	// requestKeys numbers the keys requestKey makes up for calls whose
	// agent session fathomgate cannot name (input.go).
	requestKeys atomic.Uint64
	// testHookConnected runs in Run after Connect returns and before the
	// session is recorded; testHookKeyWaiting runs when localKey is about
	// to wait for a connecting Run. Nil outside tests.
	testHookConnected  func()
	testHookKeyWaiting func()
	// testHookBeforeAdmit runs in the tool handler over the listener after
	// go-sdk has delivered the call and before callLimits.admit (T0.57: the
	// window in which a session can be evicted or expire under a call).
	// Nil outside tests.
	testHookBeforeAdmit func()
	closeOnce           sync.Once
	closeErr            error
	// exited is closed, once (exitedOnce), when the first upstream session
	// ends on its own rather than through Close (UpstreamExited).
	exited     chan struct{}
	exitedOnce sync.Once
}

// route maps one agent-facing tool name to its upstream and unprefixed name.
type route struct {
	up   *upstream
	tool string
	// readOnly and destructive are the tool's readOnlyHint and
	// destructiveHint as the upstream sent them, nil when it did not
	// (untrusted; the gate may only raise a class on them, ADR 0010).
	readOnly, destructive *bool
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
	// version is the protocol version negotiated with the upstream: go-sdk
	// tries server/discover first and falls back to the initialise
	// handshake, or connect restarts the upstream and connects with the
	// initialise handshake only (ADR 0018). It is the version the upstream
	// answered, which after an initialise handshake can be 2026-07-28.
	version string
	// era is the upstream session's era label (upstreamEra): from version
	// and from the handshake request go-sdk had answered on the session,
	// never from which connect attempt fathomgate made. A session opened
	// with the initialise handshake is labelled stateful even at 2026-07-28
	// (T0.47, N6). It is a label for logs and the audit, not a capability:
	// no control may read it as what the upstream can or cannot send.
	era     string
	done    chan struct{}
	err     error
	closing atomic.Bool

	mu       sync.Mutex
	calls    map[*inflight]struct{}    // calls in flight, for elicitation/create
	progress map[string]*progressRelay // by fathomgate's progress token (progress.go)
	// orphans are the agent sessions that have ended a call on this
	// upstream, which may still be working on it, each until its expiry.
	// They are keyed by fathomgate's own key for the agent session
	// (agentSessionKey), never by the session itself, which would keep a
	// closed session alive for the whole TTL. orphansOf counts them by
	// principal; overflow holds, by principal, one record for that
	// principal's ended calls past maxOrphansPerPrincipal (input.go,
	// T0.44). Together they hold at most 257 × (principals + 1) records
	// per upstream (maxOrphansPerPrincipal keyed plus one overflow record
	// for each configured principal and the local agent). Go maps do not
	// shrink, so their memory stays at the high-water mark after pruning.
	orphans   map[string]orphan
	orphansOf map[string]int
	overflow  map[string]orphan
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
		gate:         opts.Gate,
		upstreams:    make(map[string]*upstream, len(upstreams)),
		routes:       make(map[string]route),
		exited:       make(chan struct{}),
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
		hints, captured := up.tt.readOnlyHints()
		if p.gate != nil && !captured {
			p.logger.Warn("readOnlyHint cannot be read from this upstream's transport; the annotation raise uses destructiveHint only", "server", up.name)
		}
		if err := p.addUpstreamTools(up, tools, hints); err != nil {
			return nil, err
		}
		p.logger.Info("upstream ready", "server", up.name, "tools", p.toolCount(up), "protocol", up.version, "era", up.era)
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
		// Progress for fathomgate's own tokens only, rebuilt for the agent
		// (progress.go).
		ProgressNotificationHandler: p.upstreamProgress(up),
	})
	// Which handshake request go-sdk had answered on each attempt's
	// session, for the era label (upstreamEra).
	hs := &handshakes{}
	client.AddSendingMiddleware(hs.middleware)
	if expired == nil {
		ch := make(chan struct{})
		t := time.AfterFunc(discoverProbeTimeout, func() { close(ch) })
		defer t.Stop()
		expired = ch
	}
	cs, tt, err := p.connect(ctx, client, u, &trackedTransport{Transport: first, logger: p.logger.With("server", u.Server)}, expired)
	if err != nil {
		return nil, err
	}
	up.session = cs
	up.tt = tt
	if ir := cs.InitializeResult(); ir != nil {
		up.version = ir.ProtocolVersion
	}
	up.era = upstreamEra(up.version, hs.take(cs))
	p.upstreams[u.Server] = up
	go func() {
		defer close(up.done)
		up.err = cs.Wait()
		if !up.closing.Load() {
			p.logger.Error("upstream exited; its tools now return errors", "server", up.name, "error", up.err)
			p.exitedOnce.Do(func() { close(p.exited) })
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
	second := &trackedTransport{Transport: t, logger: first.logger}
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
// stream, or a write to its stdin failed) before fathomgate or go-sdk asked
// for a close or a kill. Other transports (Streamable HTTP) are not
// wrapped, because go-sdk finds optional methods on their connections by
// type assertion, which a wrapper would hide; for them no close is ever
// seen, so an expired bound always counts as unanswered and no exit status
// is reported.
type trackedTransport struct {
	mcp.Transport
	logger *slog.Logger // with the server name; for the process tree's warning (ADR 0021)

	// Orders are kept as flags set under mu, not compared timestamps: on
	// Windows time.Now can return the same value for two events.
	mu             sync.Mutex
	conn           mcp.Connection
	proc           *os.Process
	tree           *procTree // proc's process group or Job Object (ADR 0021)
	killed         bool      // killProcess has run: a process recorded later is killed at once
	closeRequested bool      // a close of the connection has been requested
	closeDone      time.Time // when that close first returned: the process has been reaped
	reapedUnkilled bool      // that close returned before any kill
	hungUp         bool      // a read or write failed before any close or kill was requested
	hungUpAt       time.Time

	// hints reads readOnlyHint from tools/list answers (hints.go).
	hints hintCapture
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
// (docs/maintainers.md, "Bumping go-sdk").
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
	var tree *procTree
	if ct, ok := t.Transport.(*mcp.CommandTransport); ok && ct.Command != nil {
		proc = ct.Command.Process // set by Start inside Connect, on this goroutine
		// go-sdk has started the process and written nothing to it yet. On
		// Windows it is still suspended: it runs only once it is in its job.
		tree, err = attachTree(ct.Command, t.logger)
		if err != nil {
			// Fail closed: an upstream never runs outside its tree.
			if proc != nil {
				_ = proc.Kill()
			}
			_ = c.Close() // reaps it
			return nil, fmt.Errorf("proxy: upstream process tree (ADR 0021): %w", err)
		}
	}
	if tracksConn(t.Transport) {
		c = trackedConn{Connection: c, t: t}
		t.hints.mu.Lock()
		t.hints.wired = true
		t.hints.mu.Unlock()
	}
	t.mu.Lock()
	t.conn, t.proc, t.tree = c, proc, tree
	kill := t.killed
	t.mu.Unlock()
	if kill && proc != nil {
		tree.kill()
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
// a closed stdin, and after a kill (fathomgate's, or go-sdk's after its
// shutdown grace, which also comes more than exitGrace later) it is the
// kill's.
func (t *trackedTransport) endedOnItsOwn() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.hungUp && t.reapedUnkilled && t.closeDone.Sub(t.hungUpAt) <= exitGrace
}

// killProcess kills the process behind a CommandTransport and its whole
// tree (SIGKILL to its process group, or TerminateJobObject; ADR 0021), now
// or, if it has not been started yet, as soon as Connect records it. The
// process itself is killed too, in case it left its group. Other transports
// own no process. It is safe from any goroutine: it never calls Wait or
// reads ProcessState, and Process.Kill is safe while another goroutine is
// in Wait.
func (t *trackedTransport) killProcess() {
	t.mu.Lock()
	t.killed = true
	proc, tree := t.proc, t.tree
	t.mu.Unlock()
	tree.kill()
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
	if err == nil {
		c.t.hints.received(m)
	}
	return m, err
}

// Write implements [mcp.Connection]. A write to a newline-delimited
// connection fails, with ctx live, only when the pipe to the upstream's
// stdin is gone, so any such failure is a hang-up: go-sdk may write to an
// upstream that has already exited before it reads the end of its stdout.
func (c trackedConn) Write(ctx context.Context, m jsonrpc.Message) error {
	// Noted before the write, so the answer cannot arrive first.
	c.t.hints.sent(m)
	err := c.Connection.Write(ctx, m)
	if err != nil && ctx.Err() == nil {
		c.t.failed()
	}
	return err
}

// Close implements [mcp.Connection]. go-sdk's own closes, inside Connect
// and on a failed read or write, come through here too: so do Proxy.Close
// and the upstream exiting mid-session, which go-sdk answers by closing.
//
// For a CommandTransport the inner Close is go-sdk's shutdown (stdin, 5 s,
// SIGTERM, 5 s, kill), and returns once the process has been reaped. While
// it runs, the process's tree gets go-sdk's signals too (mirrorShutdown);
// once it has returned, the tree is swept once (ADR 0021).
func (c trackedConn) Close() error {
	c.t.mu.Lock()
	c.t.closeRequested = true
	tree := c.t.tree
	c.t.mu.Unlock()
	stop := tree.mirrorShutdown()
	err := c.Connection.Close()
	stop()
	c.t.mu.Lock()
	if c.t.closeDone.IsZero() {
		c.t.closeDone, c.t.reapedUnkilled = time.Now(), !c.t.killed
	}
	c.t.mu.Unlock()
	tree.sweep(exitGrace)
	return err
}

// kill ends a failed attempt: it closes the recorded connection, which for
// a CommandTransport closes the upstream's stdin and reaps the process, and
// then flushes the process's partial last stderr line. With a grace above
// zero the process gets that long to end on its own before it is killed;
// with none it is killed first, so the close reaps at once rather than
// after go-sdk's 5-second shutdown grace. A kill ends the process's whole
// tree, and the close sweeps what is left of it once the process has been
// reaped (killProcess, trackedConn.Close; ADR 0021), so a launcher's child
// neither outlives the attempt nor holds its stderr open past it.
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
// through unchanged, with one exception: with a Gate, a tool whose argument
// list is closed is advertised with only the properties its profile names
// (narrowSchema, ADR 0033 section 4). Annotations are never used to decide
// anything here; the gate may raise a class on them (ADR 0010). readOnly
// holds each tool's readOnlyHint as sent, nil when absent (hints.go).
// Descriptions are pinned by internal/redact from M2. _meta and icons are
// dropped because the proxy does not forward resources or UI.
func (p *Proxy) addUpstreamTools(up *upstream, tools []*mcp.Tool, readOnly map[string]*bool) error {
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
		schema := t.InputSchema
		if p.gate != nil {
			if named, closed := p.gate.Arguments(up.name, t.Name); closed {
				var dropped []string
				if schema, dropped = narrowSchema(schema, named); len(dropped) > 0 {
					p.logger.Info("advertising only the arguments the profile names", "server", up.name, "tool", t.Name, "dropped", dropped)
				}
			}
		}
		exposed := &mcp.Tool{
			Name:         name,
			Title:        t.Title,
			Description:  t.Description,
			InputSchema:  schema,
			OutputSchema: t.OutputSchema,
			Annotations:  t.Annotations,
		}
		r := route{up: up, tool: t.Name, readOnly: readOnly[t.Name]}
		if t.Annotations != nil {
			r.destructive = t.Annotations.DestructiveHint
		}
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
// cancelled. For `fathomgate serve`, t is [mcp.StdioTransport], and Run is
// called once (ADR 0012). A second Run on the same proxy is allowed (tests
// run two agents that way) and its session gets a key of its own.
//
// Run records the session it serves as a local agent with an attribution
// key of its own (localKeyPrefix and the Run's number, so "l1" for the
// first), so its calls are recognised as that one session's whether or not
// an HTTP handler has also been built, and two Runs never share a key (S1
// in the security review of T0.40).
//
// No request on the session is keyed before it is recorded. go-sdk may
// dispatch a request before Connect returns, so Run registers itself as
// connecting before it calls Connect; a local request (no session id, no
// principal) whose session is not recorded yet waits (agentSessionKey,
// localKey) until every Run that was connecting has recorded its session,
// or until the request's context ends, in which case it gets a key of its
// own (requestKey) and fails closed: its ended call is foreign to every
// later call, the local agent's included. No lock is held across Connect,
// so t's Connect may block; only local requests wait for it. A call over
// the HTTP listener never waits: it is keyed by its session id, or gets a
// key of its own.
func (p *Proxy) Run(ctx context.Context, t mcp.Transport) error {
	ready := make(chan struct{})
	p.localMu.Lock()
	if p.connecting == nil {
		p.connecting = make(map[chan struct{}]struct{})
	}
	p.connecting[ready] = struct{}{}
	p.localMu.Unlock()
	// release takes Run out of connecting and wakes the waiters. It runs
	// right after the session is recorded, and in a defer, so a panic in
	// Connect (recovered further up) cannot leave the entry behind.
	var once sync.Once
	release := func() {
		once.Do(func() {
			p.localMu.Lock()
			delete(p.connecting, ready)
			p.localMu.Unlock()
			close(ready)
		})
	}
	defer release()

	ss, err := p.server.Connect(ctx, t, nil)
	if err == nil {
		if p.testHookConnected != nil {
			p.testHookConnected()
		}
		p.localMu.Lock()
		p.runs++
		if p.locals == nil {
			p.locals = make(map[*mcp.ServerSession]string)
		}
		p.locals[ss] = localKeyPrefix + strconv.Itoa(p.runs)
		p.localMu.Unlock()
	}
	release()
	if err != nil {
		return fmt.Errorf("proxy: connect agent session: %w", err)
	}
	defer func() {
		p.localMu.Lock()
		key := p.locals[ss]
		delete(p.locals, ss)
		p.localMu.Unlock()
		p.counters.forgetSession(key)
	}()

	// As mcp.Server.Run: wait for the session to end, or close it when ctx
	// is cancelled.
	closed := make(chan error, 1)
	go func() { closed <- ss.Wait() }()
	select {
	case <-ctx.Done():
		_ = ss.Close()
		<-closed
		return ctx.Err()
	case err := <-closed:
		return err
	}
}

// UpstreamExited returns a channel that is closed when the first upstream
// session ends on its own: the process exited or hung up, or the session
// failed. With several upstreams it closes on the first of them to end and
// stays closed; which one it was is in the proxy's log. An upstream ended
// by [Proxy.Close], or one that failed during [New], does not close it.
// After it is closed, that upstream's tools answer with the tool
// error "upstream <server> is not running". `fathomgate serve --listen`
// waits on it to stop the listener and exit 1, so a supervisor restarts the
// proxy instead of it answering for a dead upstream (ADR 0016).
func (p *Proxy) UpstreamExited() <-chan struct{} { return p.exited }

// localKey is the attribution key Run gave ss, or "" when ss is not a
// session Run is serving. While a Run is connecting, a session it has not
// recorded yet may be that Run's, so localKey waits for it, and returns ""
// if ctx ends first.
func (p *Proxy) localKey(ctx context.Context, ss *mcp.ServerSession) string {
	for {
		p.localMu.Lock()
		if key, ok := p.locals[ss]; ok {
			p.localMu.Unlock()
			return key
		}
		var wait chan struct{}
		for c := range p.connecting {
			wait = c
			break
		}
		p.localMu.Unlock()
		if wait == nil {
			return ""
		}
		if p.testHookKeyWaiting != nil {
			p.testHookKeyWaiting()
		}
		select {
		case <-wait:
		case <-ctx.Done():
			return ""
		}
	}
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
// the upstream's version and era in up.version and up.era (not
// eraOf(up.version), which mislabels an upstream that answered the
// initialise handshake with 2026-07-28), and the agent side it arrived on in
// transport and principal (ADR 0016).
type call struct {
	up        *upstream
	tool      string          // unprefixed upstream tool name
	arguments json.RawMessage // as received from the agent, not yet parsed
	agent     agentPeer
	// progressToken is the agent's own progressToken, or nil. It is never
	// sent upstream; fathomgate issues its own (progress.go).
	progressToken any

	// transport is the agent transport the call arrived on:
	// transportStdio or transportHTTP (transportOf).
	transport agentTransport
	// principal names the bearer token the request arrived with over the
	// HTTP listener (HTTPOptions.Tokens); it is "" on stdio. It is
	// attribution only, for the M4 audit line, and binds the sealed
	// requestState together with transport (stateBinding, T0.30). It is
	// never an approver identity (invariant 6), and nothing in M1 may read
	// it as one.
	principal string
	// sessionKey is fathomgate's own key for the agent session behind the
	// call, used to attribute a stateful upstream's prompt (input.go). The
	// tool handler sets it from Proxy.agentSessionKey.
	sessionKey string

	// An MRTR retry from a stateless agent: its answers and the
	// requestState fathomgate issued. Both are empty on a first call.
	inputResponses mcp.InputResponseMap
	requestState   string

	// gated is set when the Gate let the call through; upArguments are then
	// the arguments the upstream receives, re-encoded from the object the
	// gate checked (reencode), never the agent's bytes. arguments stays as
	// the agent sent it: the sealed requestState binds that (argsDigest).
	gated       bool
	upArguments json.RawMessage
}

// binding is the agent side a requestState issued for c is bound to, and
// the one a retry must present (T0.30).
func (c call) binding() stateBinding {
	return stateBinding{transport: c.transport, principal: c.principal}
}

// handler is the go-sdk tool handler for one route. The agent's _meta is
// read for era detection (go-sdk does that) and for its progressToken, and
// never forwarded.
func (p *Proxy) handler(r route) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		c, ignored := newCall(ctx, r, req)
		if c.transport == transportHTTP && c.principal == "" {
			// Every request the listener serves is authenticated, and go-sdk
			// copies its principal into the request. A call over HTTP with
			// none means that copy is missing (a go-sdk change), and binding
			// it would give it a principal no listener request has: refuse
			// it before anything is keyed or forwarded (transportOf).
			p.logger.Error("call refused: it arrived over the HTTP listener with no principal", "server", r.up.name, "tool", r.tool)
			return toolError(fmt.Sprintf("fathomgate refused %s: the request arrived over the HTTP listener without an authenticated principal", prefixName(r.up.name, r.tool))), nil
		}
		c.sessionKey = p.agentSessionKey(ctx, c)
		if ignored > 0 {
			p.logger.Debug("ignoring inputResponses sent without a requestState", "server", r.up.name, "tool", r.tool, "responses", ignored)
		}
		// Over HTTP, a call over its session's or principal's cap is refused
		// here, before anything reaches the upstream (T3 in the review of
		// PR #63). The call's context is also cancelled when its session is
		// deleted or the proxy closes (calls.go).
		if l := p.limits.Load(); l != nil {
			if p.testHookBeforeAdmit != nil {
				p.testHookBeforeAdmit()
			}
			actx, release, refused, why := l.admit(ctx, c.principal, req.Session, prefixName(r.up.name, r.tool))
			if refused != nil {
				if errors.Is(why, errSessionRetired) {
					p.logger.Info("call refused: its agent session is being closed", "server", r.up.name, "tool", r.tool, "principal", c.principal)
				} else {
					p.logger.Warn("call refused: too many in flight", "server", r.up.name, "tool", r.tool, "principal", c.principal)
				}
				return refused, nil
			}
			defer release()
			ctx = actx
		}
		return p.dispatch(ctx, c)
	}
}

// newCall is what dispatch sees of one agent tools/call. inputResponses
// that arrive without a requestState answer prompts fathomgate never relayed
// (T0.18): they are cleared here, before dispatch, so no later stage (M1's
// pipeline and audit included) can read or act on them as answers
// (invariant 6: nothing the agent supplies stands in for a human). The call
// then goes up as a first call and an upstream that needs input asks again.
// It returns how many answers it cleared. ctx is the tool handler's, for
// the listener's mark (transportOf).
func newCall(ctx context.Context, r route, req *mcp.CallToolRequest) (call, int) {
	c := call{up: r.up, tool: r.tool, agent: agentOf(req), progressToken: agentProgressToken(req), transport: transportOf(ctx, req), principal: principalOf(req)}
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

// dispatch is the seam of the M1 pipeline (ADR 0026). With a Gate, every
// call, first calls and MRTR retries alike, is decided before anything
// reaches the upstream, and is forwarded only when the Verdict says so
// (gate.go); M2 adds redaction on the way back, M4 the audit event. With no
// Gate every call is forwarded as is (M0, serve --no-policy).
func (p *Proxy) dispatch(ctx context.Context, c call) (*mcp.CallToolResult, error) {
	if p.gate != nil {
		return p.gated(ctx, c)
	}
	return p.forward(ctx, c)
}

// forward sends c to its upstream under the agent's request context, so an
// agent cancellation cancels the upstream call.
//
// Nothing of the agent's request crosses except the tool name and
// arguments, and on an MRTR retry the allow-listed answers (resume). The
// upstream sees fathomgate's own identity, era and capabilities: go-sdk adds
// them to _meta toward a stateless upstream. If the agent asked for
// progress, the upstream gets a progressToken fathomgate issued, never the
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
	args := c.arguments
	if c.gated {
		args = c.upArguments
	}
	if len(args) > 0 && string(args) != "null" {
		params.Arguments = args
	}
	round, prompts := 0, 0
	// Only a retry with fathomgate's requestState carries answers; newCall
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
	pr := newProgressRelay(ctx, c, p.now, p.progressWait)
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
		p.endCall(up, f, p.now())
		up.unwatchProgress(pr) // no-op when pr is nil
	}()
	for ; ; round++ {
		res, err := up.session.CallTool(ctx, params)
		own, note := up.refusalsFor(f)
		if err != nil {
			if own != nil && ctx.Err() == nil {
				// The upstream failed after fathomgate refused this call's own
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
		case p.argumentsClosed(up.name, c.tool):
			r = newRefusal(up.name, c.tool, "input_required", errPromptsUnchecked)
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
			}, c.binding())
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
		// go-sdk's URL-elicitation retry called fathomgate's own handler.
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
// stateless agent go-sdk then adds fathomgate's own serverInfo.
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
	return toolError(fmt.Sprintf("upstream %s is not running; restart fathomgate serve", up.name))
}

// toolError is a tool result with isError set and text as its only content:
// how fathomgate reports a failure the agent can act on, as opposed to a
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
				Message: fmt.Sprintf("method %q is not supported: fathomgate does not declare the %s capability", method, capability),
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
