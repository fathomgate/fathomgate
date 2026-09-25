// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The two MCP eras, as protocol versions.
const (
	v2025 = "2025-11-25" // stateful: initialise handshake, server-initiated elicitation
	v2026 = "2026-07-28" // stateless: _meta self-description, MRTR
)

// eras is every agent-era x upstream-era combination.
var eras = []struct{ agent, upstream string }{
	{v2025, v2025},
	{v2025, v2026},
	{v2026, v2025},
	{v2026, v2026},
}

// Era pinning. go-sdk v1.7 speaks both eras and always prefers 2026-07-28
// (server/discover before initialise), so a fake is pinned to 2025-11-25 by
// making server/discover fail the way it does against a 2025-era SDK.

// legacyServer makes a go-sdk server behave like a 2025-era SDK (FastMCP 1.x,
// python-sdk 1.x): server/discover gets method-not-found, so the client falls
// back to the initialise handshake at 2025-11-25.
type legacyServer struct{ mcp.Transport }

func (t legacyServer) Connect(ctx context.Context) (mcp.Connection, error) {
	c, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return legacyServerConn{c}, nil
}

type legacyServerConn struct{ mcp.Connection }

func (c legacyServerConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	for {
		m, err := c.Connection.Read(ctx)
		if err != nil {
			return nil, err
		}
		if r, ok := m.(*jsonrpc.Request); ok && r.IsCall() && r.Method == "server/discover" {
			resp := &jsonrpc.Response{ID: r.ID, Error: &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "Method not found"}}
			if err := c.Write(ctx, resp); err != nil {
				return nil, err
			}
			continue
		}
		return m, nil
	}
}

// legacyAgent makes a go-sdk client behave like a 2025-era agent: its
// server/discover probe goes out as a plain ping, whose empty result names
// no stateless version, so the client falls back to the initialise request at
// 2025-11-25. The proxy never sees server/discover or any _meta triple.
type legacyAgent struct{ mcp.Transport }

func (t legacyAgent) Connect(ctx context.Context) (mcp.Connection, error) {
	c, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return legacyAgentConn{c}, nil
}

type legacyAgentConn struct{ mcp.Connection }

func (c legacyAgentConn) Write(ctx context.Context, m jsonrpc.Message) error {
	if r, ok := m.(*jsonrpc.Request); ok && r.IsCall() && r.Method == "server/discover" {
		m = &jsonrpc.Request{ID: r.ID, Method: "ping"}
	}
	return c.Connection.Write(ctx, m)
}

func pinServer(version string, t mcp.Transport) mcp.Transport {
	if version == v2025 {
		return legacyServer{t}
	}
	return t
}

func pinAgent(version string, t mcp.Transport) mcp.Transport {
	if version == v2025 {
		return legacyAgent{t}
	}
	return t
}

// wireTap records the raw result of every response the agent reads.
type wireTap struct {
	mcp.Transport
	mu      sync.Mutex
	results []string
}

func (t *wireTap) Connect(ctx context.Context) (mcp.Connection, error) {
	c, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return tapConn{c, t}, nil
}

func (t *wireTap) all() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return slices.Clone(t.results)
}

func (t *wireTap) last() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.results) == 0 {
		return ""
	}
	return t.results[len(t.results)-1]
}

type tapConn struct {
	mcp.Connection
	t *wireTap
}

func (c tapConn) Read(ctx context.Context) (jsonrpc.Message, error) {
	m, err := c.Connection.Read(ctx)
	if r, ok := m.(*jsonrpc.Response); ok && err == nil {
		c.t.mu.Lock()
		c.t.results = append(c.t.results, string(r.Result))
		c.t.mu.Unlock()
	}
	return m, err
}

// The upstream prompt used throughout. The ESC sequence and the bidi
// override must reach the agent escaped.
const (
	upstreamPrompt  = "Enter the enable password for core-rtr-01\x1b[2J"
	labelledPrompt  = `[from netdev-ssh-mcp] Enter the enable password for core-rtr-01\u001b[2J`
	upstreamPropDoc = "enable\u202epassword"
	labelledPropDoc = `enable\u202epassword`
	agentPassword   = "FAKE-enable-pw"
)

func promptFor(id string) *mcp.ElicitParams {
	return &mcp.ElicitParams{
		Message: upstreamPrompt,
		RequestedSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"password": map[string]any{"type": "string", "description": upstreamPropDoc, "title": id},
			},
		},
	}
}

func textResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// addEraTools adds the tools that ask for input and that return result
// _meta. "ask" asks once, "ask_twice" twice. Each asks in MRTR form (an
// input_required result with its own requestState); on a stateful session
// go-sdk's server turns that into a server-initiated elicitation/create and
// re-invokes the handler once, as a 2025-era server's elicit call does.
func addEraTools(s *mcp.Server, rec *recorder) {
	// A retry carries only the latest round's answers, so earlier answers
	// travel in the upstream's own requestState: "up-state-<asking>|<id>=<answer>,...".
	ask := func(ids ...string) mcp.ToolHandler {
		return func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			rec.add(req)
			answers := map[string]string{}
			var order []string
			if _, prior, ok := strings.Cut(req.Params.RequestState, "|"); ok {
				for _, kv := range strings.Split(prior, ",") {
					k, v, _ := strings.Cut(kv, "=")
					answers[k] = v
					order = append(order, k)
				}
			}
			for id, r := range req.Params.InputResponses {
				er, _ := r.(*mcp.ElicitResult)
				if er == nil {
					return textResult("bad response type for " + id), nil
				}
				answers[id] = fmt.Sprintf("%s:%v", er.Action, er.Content["password"])
				order = append(order, id)
			}
			var done []string
			for _, id := range order {
				done = append(done, id+"="+answers[id])
			}
			for _, id := range ids {
				if _, ok := answers[id]; !ok {
					state := "up-state-" + id
					if len(done) > 0 {
						state += "|" + strings.Join(done, ",")
					}
					return &mcp.CallToolResult{InputRequests: mcp.InputRequestMap{id: promptFor(id)}, RequestState: state}, nil
				}
			}
			var b strings.Builder
			fmt.Fprintf(&b, "answered state=%s", req.Params.RequestState)
			for _, id := range ids {
				fmt.Fprintf(&b, " %s=%s", id, answers[id])
			}
			return textResult(b.String()), nil
		}
	}
	asking := func(ir mcp.InputRequestMap) mcp.ToolHandler {
		return func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			rec.add(req)
			return &mcp.CallToolResult{InputRequests: ir, RequestState: "up-state"}, nil
		}
	}
	s.AddTool(&mcp.Tool{Name: "ask", InputSchema: objectSchema}, ask("pw"))
	s.AddTool(&mcp.Tool{Name: "ask_twice", InputSchema: objectSchema}, ask("pw", "otp"))
	s.AddTool(&mcp.Tool{Name: "ask_sampling", InputSchema: objectSchema}, asking(mcp.InputRequestMap{
		"s": &mcp.CreateMessageParams{MaxTokens: 10, Messages: []*mcp.SamplingMessage{{Role: "user", Content: &mcp.TextContent{Text: upstreamPrompt}}}}, //nolint:staticcheck // SA1019: the upstream under test asks for deprecated sampling
	}))
	s.AddTool(&mcp.Tool{Name: "ask_roots", InputSchema: objectSchema}, asking(mcp.InputRequestMap{"r": &mcp.ListRootsParams{}})) //nolint:staticcheck // SA1019: the upstream under test asks for deprecated roots
	s.AddTool(&mcp.Tool{Name: "ask_url", InputSchema: objectSchema}, asking(mcp.InputRequestMap{
		"u": &mcp.ElicitParams{Mode: "url", URL: "https://login.example.invalid/", ElicitationID: "e1", Message: upstreamPrompt},
	}))
	s.AddTool(&mcp.Tool{Name: "ask_nested", InputSchema: objectSchema}, asking(mcp.InputRequestMap{
		"n": &mcp.ElicitParams{Message: upstreamPrompt, RequestedSchema: map[string]any{
			"type": "object", "properties": map[string]any{"creds": map[string]any{"type": "object"}},
		}},
	}))
	s.AddTool(&mcp.Tool{Name: "ask_busy", InputSchema: objectSchema}, asking(mcp.InputRequestMap{}))
	s.AddTool(&mcp.Tool{Name: "ask_forever", InputSchema: objectSchema}, asking(mcp.InputRequestMap{"pw": promptFor("pw")}))
	addProgressTools(s, rec)
	s.AddTool(&mcp.Tool{Name: "with_meta", InputSchema: objectSchema}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		rec.add(req)
		res := textResult("meta")
		res.Meta = mcp.Meta{
			mcp.MetaKeyServerInfo:  map[string]any{"name": "fathomgate-impostor", "version": "0"},
			"com.example/upstream": "FAKE-upstream-meta",
		}
		res.RequestState = "stray-state"
		return res, nil
	})
}

// promptLog is the agent's record of the prompts it was shown.
type promptLog struct {
	mu  sync.Mutex
	got []*mcp.ElicitParams
}

func (l *promptLog) all() []*mcp.ElicitParams {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.got)
}

// eraSetup configures an eraHarness.
type eraSetup struct {
	agent, upstream string // protocol versions to pin each side to
	noElicit        bool   // the agent declares no elicitation
	manualMRTR      bool   // the agent handles input_required itself
	hooks           *blockHooks
	extra           func(*mcp.Server) // adds test-specific upstream tools
	gate            <-chan struct{}   // if set, the agent answers a prompt only once it closes (or after 5s)
	progress        *progressLog      // if set, the agent records the progress notifications it gets
	reads           *readGate         // if set, the agent reads only while it is open (progress_stall_test.go)
}

type eraHarness struct {
	proxy   *Proxy
	agent   *mcp.ClientSession
	rec     *recorder
	prompts *promptLog
	tap     *wireTap
}

func newEraHarness(t *testing.T, s eraSetup) *eraHarness {
	t.Helper()
	ctx := context.Background()
	rec := &recorder{}
	srv := fakeUpstream(rec, s.hooks)
	addEraTools(srv, rec)
	if s.extra != nil {
		s.extra(srv)
	}
	upSrvT, upCliT := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(ctx, pinServer(s.upstream, upSrvT), nil); err != nil {
		t.Fatal(err)
	}
	p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: reuse(upCliT)}}, Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	h := &eraHarness{proxy: p, rec: rec, prompts: &promptLog{}}
	h.agent, h.tap = connectAgent(t, p, s, h.prompts)
	return h
}

// connectAgent runs p for one agent pinned to s.agent and connects it. The
// agent answers every prompt with accept and agentPassword, plus a _meta of
// its own that must not reach the upstream.
func connectAgent(t *testing.T, p *Proxy, s eraSetup, prompts *promptLog) (*mcp.ClientSession, *wireTap) {
	t.Helper()
	ctx := context.Background()
	agSrvT, agCliT := mcp.NewInMemoryTransports()
	runDone := make(chan error, 1)
	go func() { runDone <- p.Run(ctx, agSrvT) }()
	opts := &mcp.ClientOptions{}
	if !s.noElicit {
		opts.ElicitationHandler = func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			prompts.mu.Lock()
			prompts.got = append(prompts.got, req.Params)
			prompts.mu.Unlock()
			if s.gate != nil {
				timer := time.NewTimer(5 * time.Second)
				defer timer.Stop()
				select {
				case <-s.gate:
				case <-timer.C:
				}
			}
			return &mcp.ElicitResult{
				Meta:    mcp.Meta{"com.example/agent": "FAKE-agent-meta"},
				Action:  "accept",
				Content: map[string]any{"password": agentPassword},
			}, nil
		}
	}
	if s.manualMRTR {
		opts.MultiRoundTrip = &mcp.MultiRoundTripOptions{Disabled: true}
	}
	if s.progress != nil {
		opts.ProgressNotificationHandler = s.progress.record
	}
	agentT := pinAgent(s.agent, agCliT)
	if s.reads != nil {
		agentT = gatedTransport{agentT, s.reads}
	}
	tap := &wireTap{Transport: agentT}
	agent, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, opts).Connect(ctx, tap, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = agent.Close()
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
			t.Error("proxy Run did not return after the agent disconnected")
		}
		if err := p.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return agent, tap
}

// propertyDoc digs the password property's description out of a schema.
func propertyDoc(schema any) string {
	b, _ := json.Marshal(schema)
	var s struct {
		Properties map[string]struct {
			Description string `json:"description"`
		} `json:"properties"`
	}
	_ = json.Unmarshal(b, &s)
	return s.Properties["password"].Description
}

// TestEraMatrix is matrix row 2 against in-process fakes: every
// agent-era x upstream-era pair negotiates, lists, calls, keeps each side's
// _meta on its own side, and handles an upstream prompt.
func TestEraMatrix(t *testing.T) {
	for _, e := range eras {
		t.Run("agent "+e.agent+" upstream "+e.upstream, func(t *testing.T) {
			h := newEraHarness(t, eraSetup{agent: e.agent, upstream: e.upstream})
			ctx := context.Background()

			// Each side negotiated its own era.
			if got := h.agent.InitializeResult().ProtocolVersion; got != e.agent {
				t.Fatalf("agent negotiated %s, want %s", got, e.agent)
			}
			up := h.proxy.upstreams[testServer]
			if up.version != e.upstream {
				t.Fatalf("upstream negotiated %s, want %s", up.version, e.upstream)
			}
			if got := h.agent.InitializeResult().ServerInfo; got == nil || got.Name != Name {
				t.Fatalf("agent sees server %+v, want %s", got, Name)
			}

			// tools/list passes through with the prefix in both eras.
			lt, err := h.agent.ListTools(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.ContainsFunc(lt.Tools, func(tl *mcp.Tool) bool { return tl.Name == "netdev-ssh-mcp.run_show_command" }) {
				t.Fatalf("tools/list lacks the prefixed tool")
			}

			// tools/call: the agent's _meta stays with the agent; the
			// upstream sees fathomgate's own identity and era.
			res, err := h.agent.CallTool(ctx, &mcp.CallToolParams{
				Meta:      mcp.Meta{"com.example/trace": "FAKE-agent-trace", "progressToken": "p1"},
				Name:      "netdev-ssh-mcp.run_show_command",
				Arguments: map[string]any{"host": "lab-sw-01", "command": "show version"},
			})
			if err != nil || res.IsError {
				t.Fatalf("call: %v %q", err, text(res))
			}
			calls := h.rec.all()
			got := calls[len(calls)-1]
			if got.Name != "run_show_command" || got.Version != e.upstream || got.ClientName != Name {
				t.Fatalf("upstream saw %+v, want run_show_command at %s from %s", got, e.upstream, Name)
			}
			for _, k := range got.MetaKeys {
				if !strings.HasPrefix(k, "io.modelcontextprotocol/") && k != "progressToken" {
					t.Errorf("agent _meta key %q reached the upstream", k)
				}
			}
			// The agent asked for progress, so the upstream got a token:
			// fathomgate's own, never the agent's.
			if tok, ok := got.ProgressToken.(string); !ok || tok == "" || tok == "p1" {
				t.Errorf("upstream progressToken %#v, want fathomgate's own", got.ProgressToken)
			}
			if e.upstream == v2026 && !slices.Contains(got.MetaKeys, mcp.MetaKeyProtocolVersion) {
				t.Errorf("stateless upstream got no self-describing _meta: %v", got.MetaKeys)
			}

			// Result _meta from the upstream stays with the upstream.
			res, err = h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.with_meta"})
			if err != nil {
				t.Fatal(err)
			}
			if _, leaked := res.Meta["com.example/upstream"]; leaked || res.RequestState != "" {
				t.Errorf("upstream result _meta or requestState reached the agent: %v %q", res.Meta, res.RequestState)
			}
			if e.agent == v2026 {
				b, _ := json.Marshal(res.Meta[mcp.MetaKeyServerInfo])
				if !strings.Contains(string(b), `"name":"fathomgate"`) {
					t.Errorf("stateless agent sees serverInfo %s, want fathomgate's", b)
				}
			}

			// An upstream prompt.
			res, err = h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: map[string]any{"host": "core-rtr-01"}})
			if err != nil {
				t.Fatalf("ask: %v", err)
			}
			prompts := h.prompts.all()
			if e.agent == v2026 && e.upstream == v2025 {
				// ADR 0014 decision point: refused, and the agent is told.
				if !res.IsError || !strings.Contains(text(res), "fathomgate refused an input request (elicitation) from upstream netdev-ssh-mcp during ask") ||
					!strings.Contains(text(res), "ADR 0014") {
					t.Fatalf("want a labelled refusal, got %v %q", res.IsError, text(res))
				}
				if len(prompts) != 0 || strings.Contains(text(res), "enable password") {
					t.Fatalf("upstream prompt reached the agent: %d prompts, %q", len(prompts), text(res))
				}
				return
			}
			if res.IsError || !strings.Contains(text(res), "answered state=up-state-pw pw=accept:"+agentPassword) {
				t.Fatalf("ask result %v %q", res.IsError, text(res))
			}
			if len(prompts) != 1 {
				t.Fatalf("agent saw %d prompts, want 1", len(prompts))
			}
			if prompts[0].Message != labelledPrompt {
				t.Errorf("prompt %q, want %q", prompts[0].Message, labelledPrompt)
			}
			if d := propertyDoc(prompts[0].RequestedSchema); d != labelledPropDoc {
				t.Errorf("schema description %q, want %q", d, labelledPropDoc)
			}
			last := h.rec.all()
			answer := last[len(last)-1]
			if strings.Contains(answer.Responses, "com.example/agent") {
				t.Errorf("agent's elicitation _meta reached the upstream: %s", answer.Responses)
			}
		})
	}
}

// TestMRTRWire drives a stateless agent's MRTR retry by hand: the wire shape
// of input_required, the sealed requestState, and every retry fathomgate
// refuses before the upstream sees it.
func TestMRTRWire(t *testing.T) {
	h := newEraHarness(t, eraSetup{agent: v2026, upstream: v2026, manualMRTR: true})
	ctx := context.Background()
	args := map[string]any{"host": "core-rtr-01"}

	first, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	if !first.NeedsInput() {
		t.Fatalf("want input_required, got %q", text(first))
	}
	wire := h.tap.last()
	for _, want := range []string{`"resultType":"input_required"`, `"requestState":"` + statePrefix, `"method":"elicitation/create"`} {
		if !strings.Contains(wire, want) {
			t.Errorf("wire result lacks %s: %s", want, wire)
		}
	}
	ep, _ := first.InputRequests["pw"].(*mcp.ElicitParams)
	if ep == nil || ep.Message != labelledPrompt || propertyDoc(ep.RequestedSchema) != labelledPropDoc {
		t.Fatalf("input request not relabelled: %+v", ep)
	}
	state := first.RequestState
	if !strings.HasPrefix(state, statePrefix) || strings.Contains(wire, `"requestState":"up-state-pw"`) {
		t.Fatalf("requestState is not fathomgate's envelope: %q", state)
	}
	accept := mcp.InputResponseMap{"pw": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"password": agentPassword}, Meta: mcp.Meta{"com.example/agent": "x"}}}
	tampered := []byte(state)
	tampered[len(statePrefix)+3] ^= 1

	before := len(h.rec.all())
	bad := []struct {
		name       string
		tool       string
		args       map[string]any
		state      string
		responses  mcp.InputResponseMap
		wantReason string
	}{
		{"tampered state", "ask", args, string(tampered), accept, reasonInvalidRequestState},
		{"upstream's raw state", "ask", args, "up-state-pw", accept, reasonInvalidRequestState},
		{"changed arguments", "ask", map[string]any{"host": "lab-sw-01"}, state, accept, reasonInvalidRequestState},
		{"state for another tool", "ask_twice", args, state, accept, reasonInvalidRequestState},
		{"action outside the allow-list", "ask", args, state, mcp.InputResponseMap{"pw": &mcp.ElicitResult{Action: "approve"}}, reasonInvalidInputResponse},
		{"sampling answer", "ask", args, state, mcp.InputResponseMap{"pw": &mcp.CreateMessageResult{Role: "assistant", Model: "m", Content: &mcp.TextContent{Text: "x"}}}, reasonInvalidInputResponse}, //nolint:staticcheck // SA1019: a deprecated sampling answer must be refused
	}
	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp." + tc.tool, Arguments: tc.args, RequestState: tc.state, InputResponses: tc.responses})
			var werr *jsonrpc.Error
			if !errors.As(err, &werr) || werr.Code != jsonrpc.CodeInvalidParams {
				t.Fatalf("want -32602, got %v", err)
			}
			var d retryErrorData
			if err := json.Unmarshal(werr.Data, &d); err != nil || d.Reason != tc.wantReason {
				t.Fatalf("data %s (%v), want reason %s", werr.Data, err, tc.wantReason)
			}
		})
	}
	if n := len(h.rec.all()); n != before {
		t.Fatalf("upstream saw %d refused retries", n-before)
	}

	// The honest retry crosses once, with the upstream's own state and the
	// allow-listed answer only.
	res, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: args, RequestState: state, InputResponses: accept})
	if err != nil || res.IsError || res.NeedsInput() {
		t.Fatalf("retry: %v %q", err, text(res))
	}
	if !strings.Contains(text(res), "answered state=up-state-pw pw=accept:"+agentPassword) {
		t.Fatalf("retry result %q", text(res))
	}
	calls := h.rec.all()[before:]
	if len(calls) != 1 || calls[0].RequestState != "up-state-pw" || strings.Contains(calls[0].Responses, "com.example") {
		t.Fatalf("upstream saw %+v", calls)
	}
}

// TestInputRequestsRefused covers every upstream input request fathomgate does
// not pass on. The upstream's prompt text never reaches the agent.
func TestInputRequestsRefused(t *testing.T) {
	cases := []struct {
		name     string
		agent    string
		noElicit bool
		tool     string
		want     string
	}{
		{"sampling", v2026, false, "ask_sampling", "fathomgate refused an input request (sampling) from upstream netdev-ssh-mcp during ask_sampling"},
		{"roots", v2026, false, "ask_roots", "(roots)"},
		{"URL elicitation", v2026, false, "ask_url", "(URL elicitation)"},
		{"nested schema", v2025, false, "ask_nested", "a property type is not"},
		{"client without elicitation, stateless", v2026, true, "ask", "does not support form elicitation"},
		{"client without elicitation, stateful", v2025, true, "ask", "does not support form elicitation"},
		{"load shedding", v2026, false, "ask_busy", "upstream netdev-ssh-mcp is busy"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newEraHarness(t, eraSetup{agent: tc.agent, upstream: v2026, noElicit: tc.noElicit})
			res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp." + tc.tool})
			if err != nil {
				t.Fatalf("want a tool error, got %v", err)
			}
			if !res.IsError || !strings.Contains(text(res), tc.want) {
				t.Fatalf("result %v %q, want %q", res.IsError, text(res), tc.want)
			}
			if strings.Contains(text(res), "enable password") || strings.Contains(text(res), "login.example") || len(h.prompts.all()) != 0 {
				t.Fatalf("upstream prompt reached the agent: %q", text(res))
			}
		})
	}
}

// TestStatefulAgentMultiRound: a stateful agent cannot take input_required,
// so fathomgate asks it with elicitation/create round after round.
func TestStatefulAgentMultiRound(t *testing.T) {
	h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2026})
	res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask_twice"})
	if err != nil || res.IsError {
		t.Fatalf("%v %q", err, text(res))
	}
	// The upstream's own requestState came back intact across both rounds.
	if want := "answered state=up-state-otp|pw=accept:" + agentPassword + " pw=accept:" + agentPassword + " otp=accept:" + agentPassword; text(res) != want {
		t.Fatalf("result %q, want %q", text(res), want)
	}
	prompts := h.prompts.all()
	if len(prompts) != 2 || prompts[0].Message != labelledPrompt || prompts[1].Message != labelledPrompt {
		t.Fatalf("prompts %+v", prompts)
	}
}

// TestInputRoundLimit: an upstream that never stops asking gets ten rounds,
// then a refusal.
func TestInputRoundLimit(t *testing.T) {
	h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2026})
	res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask_forever"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(text(res), "more than 10 rounds of input") {
		t.Fatalf("result %v %q", res.IsError, text(res))
	}
	if n := len(h.prompts.all()); n != maxInputRounds {
		t.Fatalf("agent saw %d prompts, want %d", n, maxInputRounds)
	}
}

// TestStatelessAgentMultiRound: each round is a fresh input_required with a
// fresh envelope; go-sdk's agent-side MRTR loop drives it.
func TestStatelessAgentMultiRound(t *testing.T) {
	h := newEraHarness(t, eraSetup{agent: v2026, upstream: v2026})
	res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask_twice"})
	if err != nil || res.IsError {
		t.Fatalf("%v %q", err, text(res))
	}
	// The upstream's own requestState came back intact across both rounds.
	if want := "answered state=up-state-otp|pw=accept:" + agentPassword + " pw=accept:" + agentPassword + " otp=accept:" + agentPassword; text(res) != want {
		t.Fatalf("result %q, want %q", text(res), want)
	}
	if n := len(h.prompts.all()); n != 2 {
		t.Fatalf("agent saw %d prompts, want 2", n)
	}
}

// TestUpstreamElicitationNeedsOneCall: a stateful upstream's
// elicitation/create names no call, so with two calls in flight fathomgate
// cannot say whose prompt it is and refuses it. That refusal is only ever
// added to what the upstream returns: an upstream error stays the
// upstream's error, and a result the upstream still completes keeps its
// content, with the refusal appended.
func TestUpstreamElicitationNeedsOneCall(t *testing.T) {
	hooks := &blockHooks{blocked: make(chan struct{}, 1), cancelled: make(chan struct{}, 1)}
	h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2025, hooks: hooks, extra: func(s *mcp.Server) {
		s.AddTool(&mcp.Tool{Name: "ask_direct", InputSchema: objectSchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if _, err := req.Session.Elicit(ctx, promptFor("pw")); err == nil {
				return textResult("upstream got an answer"), nil
			}
			return textResult("upstream carried on without an answer"), nil
		})
	}})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errc := make(chan error, 1)
	go func() {
		_, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.block"})
		errc <- err
	}()
	select {
	case <-hooks.blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("block never reached the upstream")
	}
	bg := context.Background()

	// The upstream fails the call: the agent gets the upstream's own error.
	_, err := h.agent.CallTool(bg, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask"})
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) || !strings.HasPrefix(werr.Message, "upstream netdev-ssh-mcp: ") ||
		!strings.Contains(werr.Message, "cannot be attributed to one call (2 in flight)") {
		t.Fatalf("want the upstream's relayed error, got %v", err)
	}

	// The upstream carries on: its result stands and the refusal is appended.
	res, err := h.agent.CallTool(bg, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask_direct"})
	if err != nil || res.IsError {
		t.Fatalf("want the upstream's result, got %v %q", err, text(res))
	}
	if got := text(res); !strings.HasPrefix(got, "upstream carried on without an answer") ||
		!strings.Contains(got, "fathomgate refused an input request (elicitation) from upstream netdev-ssh-mcp: it cannot be attributed to one call (2 in flight)") {
		t.Fatalf("result %q", got)
	}
	if len(h.prompts.all()) != 0 {
		t.Fatal("an unattributed prompt reached the agent")
	}
	cancel()
	select {
	case <-errc:
	case <-time.After(5 * time.Second):
		t.Fatal("block call did not return after cancel")
	}
	select {
	case <-hooks.cancelled:
	case <-time.After(5 * time.Second):
		t.Fatal("cancellation never reached the upstream")
	}
}

// TestPromptFlood: go-sdk runs an upstream's incoming requests concurrently,
// so a hostile stateful upstream can fire many elicitation/create at once.
// fathomgate lets one prompt per call be open and at most maxInputRounds per
// call, and refuses the rest.
func TestPromptFlood(t *testing.T) {
	const burst = 4
	release := make(chan struct{})
	h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2025, gate: release, extra: func(s *mcp.Server) {
		// ask_burst fires burst prompts at once. The agent holds the first
		// open until the other burst-1 have been refused.
		s.AddTool(&mcp.Tool{Name: "ask_burst", InputSchema: objectSchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var (
				mu          sync.Mutex
				wg          sync.WaitGroup
				ok, refused int
			)
			for i := range burst {
				wg.Add(1)
				go func() {
					defer wg.Done()
					_, err := req.Session.Elicit(ctx, promptFor(fmt.Sprint("p", i)))
					mu.Lock()
					defer mu.Unlock()
					if err == nil {
						ok++
						return
					}
					refused++
					if refused == burst-1 {
						close(release)
					}
				}()
			}
			wg.Wait()
			return textResult(fmt.Sprintf("ok=%d refused=%d", ok, refused)), nil
		})
		// ask_serial asks one more time than a call may.
		s.AddTool(&mcp.Tool{Name: "ask_serial", InputSchema: objectSchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			ok, refused := 0, 0
			for range maxInputRounds + 1 {
				if _, err := req.Session.Elicit(ctx, promptFor("pw")); err == nil {
					ok++
				} else {
					refused++
				}
			}
			return textResult(fmt.Sprintf("ok=%d refused=%d", ok, refused)), nil
		})
	}})
	bg := context.Background()

	res, err := h.agent.CallTool(bg, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask_burst"})
	if err != nil {
		t.Fatal(err)
	}
	if got := text(res); !strings.HasPrefix(got, fmt.Sprintf("ok=1 refused=%d", burst-1)) ||
		!strings.Contains(got, "another prompt from this upstream is still open for this call") {
		t.Fatalf("burst: %q", got)
	}
	if n := len(h.prompts.all()); n != 1 {
		t.Fatalf("agent saw %d prompts from a burst, want 1", n)
	}

	res, err = h.agent.CallTool(bg, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask_serial"})
	if err != nil {
		t.Fatal(err)
	}
	if got := text(res); !strings.HasPrefix(got, fmt.Sprintf("ok=%d refused=1", maxInputRounds)) ||
		!strings.Contains(got, "more than 10 prompts in one call") {
		t.Fatalf("serial: %q", got)
	}
	if n := len(h.prompts.all()); n != 1+maxInputRounds {
		t.Fatalf("agent saw %d prompts, want %d", n, 1+maxInputRounds)
	}
}

// TestAgentCancelDuringPrompt: cancelling the call while the agent is being
// asked cancels the prompt and the upstream call.
func TestAgentCancelDuringPrompt(t *testing.T) {
	for _, upEra := range []string{v2025, v2026} {
		t.Run("upstream "+upEra, func(t *testing.T) {
			ctx := context.Background()
			rec := &recorder{}
			srv := fakeUpstream(rec, nil)
			addEraTools(srv, rec)
			upSrvT, upCliT := mcp.NewInMemoryTransports()
			if _, err := srv.Connect(ctx, pinServer(upEra, upSrvT), nil); err != nil {
				t.Fatal(err)
			}
			p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: reuse(upCliT)}}, Options{})
			if err != nil {
				t.Fatal(err)
			}
			agSrvT, agCliT := mcp.NewInMemoryTransports()
			runDone := make(chan error, 1)
			go func() { runDone <- p.Run(ctx, agSrvT) }()
			asked := make(chan struct{}, 1)
			agent, err := mcp.NewClient(&mcp.Implementation{Name: "agent"}, &mcp.ClientOptions{
				ElicitationHandler: func(hctx context.Context, _ *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
					asked <- struct{}{}
					<-hctx.Done() // the human never answers
					return nil, hctx.Err()
				},
			}).Connect(ctx, legacyAgent{agCliT}, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				_ = agent.Close()
				<-runDone
				_ = p.Close()
			}()
			callCtx, cancel := context.WithCancel(ctx)
			errc := make(chan error, 1)
			go func() {
				_, err := agent.CallTool(callCtx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask"})
				errc <- err
			}()
			select {
			case <-asked:
			case <-time.After(5 * time.Second):
				t.Fatal("agent was never asked")
			}
			cancel()
			select {
			case err := <-errc:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("call error %v, want context.Canceled", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("call did not return after cancel")
			}
			// The proxy is still usable.
			res, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.get_config"})
			if err != nil || res.IsError {
				t.Fatalf("follow-up: %v %q", err, text(res))
			}
		})
	}
}
