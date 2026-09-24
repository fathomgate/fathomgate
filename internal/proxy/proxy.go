package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

// Upstream is one MCP server the proxy connects to as a client.
type Upstream struct {
	// Server is the tool prefix toward the agent. It is the `server` key of
	// the upstream's profile in profiles/, never derived from the binary name.
	Server string
	// Transport reaches the upstream. `netguard serve` uses
	// [Command.Transport] (stdio); tests use [mcp.NewInMemoryTransports].
	Transport mcp.Transport
}

// Options configures a [Proxy]. The zero value is usable.
type Options struct {
	// Version is reported in serverInfo and clientInfo.
	Version string
	// Logger receives proxy and go-sdk diagnostics. Nil discards them. For a
	// stdio proxy it must not write to stdout, which carries the protocol.
	Logger *slog.Logger
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
	name      string
	transport mcp.Transport // to flush a Command's stderr on Close
	red       *Redactor     // a Command's Secrets, scrubbed from relayed errors
	session   *mcp.ClientSession
	// version is the protocol version negotiated with the upstream, and so
	// its era (eraOf): go-sdk tries server/discover first and falls back to
	// the initialise handshake.
	version string
	done    chan struct{}
	err     error
	closing atomic.Bool

	mu       sync.Mutex
	calls    map[*inflight]struct{}    // calls in flight, for elicitation/create
	progress map[string]*progressRelay // by netguard's progress token (progress.go)
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
		if u.Transport == nil {
			return nil, fmt.Errorf("proxy: server %q has no transport", u.Server)
		}
		up, err := p.connectUpstream(ctx, impl, u)
		if err != nil {
			return nil, err
		}
		tools, err := listTools(ctx, up)
		if err != nil {
			return nil, err
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
// initialise handshake (stateful, 2025-11-25 and older) if the upstream does
// not know server/discover.
func (p *Proxy) connectUpstream(ctx context.Context, impl *mcp.Implementation, u Upstream) (*upstream, error) {
	up := &upstream{name: u.Server, transport: u.Transport, red: redactorOf(u.Transport), done: make(chan struct{})}
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
	tt := &trackedTransport{Transport: u.Transport}
	cs, err := client.Connect(ctx, tt, nil)
	if err != nil {
		// go-sdk does not close the session on every Connect failure (an
		// unsupported protocol version, for one), so a spawned upstream
		// could outlive the error. Kill it and close the connection.
		tt.kill()
		return nil, fmt.Errorf("proxy: upstream %s: connect: %w", u.Server, escapedError{err})
	}
	up.session = cs
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

// trackedTransport records the Connection its Transport returns, so a
// failed Connect can close it. go-sdk may or may not have closed that
// connection already.
type trackedTransport struct {
	mcp.Transport

	mu   sync.Mutex
	conn mcp.Connection
}

// Connect implements [mcp.Transport].
func (t *trackedTransport) Connect(ctx context.Context) (mcp.Connection, error) {
	c, err := t.Transport.Connect(ctx)
	if err == nil {
		t.mu.Lock()
		t.conn = c
		t.mu.Unlock()
	}
	return c, err
}

// kill stops the process behind a CommandTransport, if one was started, and
// closes the recorded connection. Other transports own no process.
//
// It never calls cmd.Wait or reads cmd.ProcessState itself. go-sdk's
// connection Close owns the Wait. It runs once (sync.Once), and a second
// caller blocks until the first has finished, so this Close returns only
// after the process has been reaped, whether go-sdk closed first or not.
// Process.Kill is safe while another goroutine is in Wait, and killing
// first means Close reaps at once rather than after its 5s grace period.
// Only the direct child is killed; see the Command godoc on grandchildren.
func (t *trackedTransport) kill() {
	if ct, ok := t.Transport.(*mcp.CommandTransport); ok && ct.Command != nil && ct.Command.Process != nil {
		_ = ct.Command.Process.Kill()
	}
	t.mu.Lock()
	c := t.conn
	t.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
	flushStderr(t.Transport)
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
			flushStderr(up.transport)
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
	// upstream's in-flight set first, and only then waits (up to
	// progressWait) for its progress to reach the agent. The other way round
	// (T1 in the review of PR #63), a stalled agent kept a stale entry there
	// for that long, and a stateful upstream's prompt for another agent's
	// call was refused as unattributable in the meantime.
	defer func() {
		up.end(f)
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
