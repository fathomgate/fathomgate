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
	server    *mcp.Server
	logger    *slog.Logger
	upstreams map[string]*upstream // by server name
	routes    map[string]route     // by prefixed tool name
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
	session   *mcp.ClientSession
	done      chan struct{}
	err       error
	closing   atomic.Bool
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
	impl := &mcp.Implementation{Name: Name, Version: opts.Version}
	p := &Proxy{
		logger:    logger,
		upstreams: make(map[string]*upstream, len(upstreams)),
		routes:    make(map[string]route),
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
		p.logger.Info("upstream ready", "server", up.name, "tools", p.toolCount(up))
	}
	p.server.AddReceivingMiddleware(p.checkToolName)
	return p, nil
}

// connectUpstream starts one upstream session and its exit watcher.
func (p *Proxy) connectUpstream(ctx context.Context, impl *mcp.Implementation, u Upstream) (*upstream, error) {
	client := mcp.NewClient(impl, &mcp.ClientOptions{
		Logger: slog.New(minLevel{p.logger.Handler(), slog.LevelWarn}),
		// Advertise nothing: no roots, no sampling, no elicitation. An
		// upstream prompt must never reach the agent unlabelled (M3 adds
		// origin-labelled elicitation); until then netguard refuses it.
		Capabilities: &mcp.ClientCapabilities{},
		// Do not let go-sdk answer MRTR input requests on our behalf;
		// forward sees them and refuses them itself.
		MultiRoundTrip: &mcp.MultiRoundTripOptions{Disabled: true},
	})
	tt := &trackedTransport{Transport: u.Transport}
	cs, err := client.Connect(ctx, tt, nil)
	if err != nil {
		// go-sdk does not close the session on every Connect failure (an
		// unsupported protocol version, for one), so a spawned upstream
		// could outlive the error. Kill it and close the connection.
		tt.kill()
		return nil, fmt.Errorf("proxy: upstream %s: connect: %w", u.Server, err)
	}
	up := &upstream{name: u.Server, transport: u.Transport, session: cs, done: make(chan struct{})}
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
			return nil, fmt.Errorf("proxy: upstream %s: tools/list: %w", up.name, err)
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
func (p *Proxy) Close() error {
	p.closeOnce.Do(func() {
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

// call is one agent tools/call after the prefix has been resolved.
type call struct {
	up        *upstream
	tool      string          // unprefixed upstream tool name
	arguments json.RawMessage // as received from the agent, not yet parsed
}

// handler is the go-sdk tool handler for one route.
func (p *Proxy) handler(r route) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		c := call{up: r.up, tool: r.tool}
		if req.Params != nil {
			c.arguments = req.Params.Arguments
		}
		return p.dispatch(ctx, c)
	}
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
// Outcomes, in order: the upstream result is returned unchanged; an upstream
// request for input (MRTR elicitation, sampling or roots) is refused by
// netguard with a tool error; an upstream JSON-RPC error is relayed through
// relayUpstreamError; an upstream that has exited, before or during the call,
// yields a tool error (isError) naming it.
func (p *Proxy) forward(ctx context.Context, c call) (*mcp.CallToolResult, error) {
	up := c.up
	if up.exited() {
		return upstreamDown(up), nil
	}
	params := &mcp.CallToolParams{Name: c.tool}
	if len(c.arguments) > 0 && string(c.arguments) != "null" {
		params.Arguments = c.arguments
	}
	res, err := up.session.CallTool(ctx, params)
	if err == nil {
		switch {
		case res == nil:
			return toolError(fmt.Sprintf("upstream %s returned no result for %s", up.name, c.tool)), nil
		case res.NeedsInput():
			p.logger.Warn("netguard refused an upstream input request", "server", up.name, "tool", c.tool, "requests", len(res.InputRequests))
			return toolError(fmt.Sprintf("netguard refused an input request (elicitation, sampling or roots) from upstream %s during %s: upstream prompts are not forwarded in M0", up.name, c.tool)), nil
		}
		return res, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	var werr *jsonrpc.Error
	if errors.As(err, &werr) {
		return nil, relayUpstreamError(up.name, werr)
	}
	if errors.Is(err, mcp.ErrConnectionClosed) || errors.Is(err, io.EOF) || awaitExit(ctx, up, exitGrace) {
		return upstreamDown(up), nil
	}
	p.logger.Warn("upstream call failed", "server", up.name, "tool", c.tool, "error", err)
	return toolError(fmt.Sprintf("upstream %s: calling %s failed: %s", up.name, c.tool, escapeControl(err.Error(), maxRelayedMessage))), nil
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
