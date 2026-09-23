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

const testServer = "netdev-ssh-mcp"

// recorder is the fake upstream's record of every tools/call it received.
type recorder struct {
	mu    sync.Mutex
	calls []recordedCall
}

type recordedCall struct {
	Name string
	Args map[string]any
}

func (r *recorder) add(name string, raw json.RawMessage) {
	var args map[string]any
	_ = json.Unmarshal(raw, &args)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, recordedCall{Name: name, Args: args})
}

func (r *recorder) all() []recordedCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

var objectSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"host":    map[string]any{"type": "string"},
		"command": map[string]any{"type": "string"},
	},
}

// fakeUpstream builds an in-process go-sdk server shaped like netdev-ssh-mcp,
// plus tools that exercise the error paths. Every call is recorded.
func fakeUpstream(rec *recorder, blocked chan<- struct{}) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "fake-netdev", Version: "0"}, nil)
	echo := func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		rec.add(req.Params.Name, req.Params.Arguments)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "ok " + req.Params.Name + " " + string(req.Params.Arguments)}}}, nil
	}
	readOnly := &mcp.ToolAnnotations{ReadOnlyHint: true}
	s.AddTool(&mcp.Tool{Name: "run_show_command", Description: "Run a show command", InputSchema: objectSchema, Annotations: readOnly}, echo)
	s.AddTool(&mcp.Tool{Name: "get_config", Description: "Get the running config", InputSchema: objectSchema}, echo)
	s.AddTool(&mcp.Tool{Name: "failing_tool", InputSchema: objectSchema}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		rec.add(req.Params.Name, req.Params.Arguments)
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "device unreachable"}}}, nil
	})
	s.AddTool(&mcp.Tool{Name: "protocol_error", InputSchema: objectSchema}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		rec.add(req.Params.Name, req.Params.Arguments)
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "host is required"}
	})
	s.AddTool(&mcp.Tool{Name: "block", InputSchema: objectSchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		rec.add(req.Params.Name, req.Params.Arguments)
		if blocked != nil {
			blocked <- struct{}{}
		}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	// Untrusted names the proxy must refuse to re-expose. go-sdk only logs
	// invalid names on the server side, so the fake can still list them.
	s.AddTool(&mcp.Tool{Name: "bad name", InputSchema: objectSchema}, echo)
	s.AddTool(&mcp.Tool{Name: "ansi\x1b[31m", InputSchema: objectSchema}, echo)
	return s
}

// harness is a proxy wired to a fake upstream and an agent-side client, all
// over in-memory transports.
type harness struct {
	proxy    *Proxy
	agent    *mcp.ClientSession
	upstream *mcp.ServerSession
	rec      *recorder
	runDone  chan error
}

func newHarness(t *testing.T, blocked chan<- struct{}) *harness {
	t.Helper()
	ctx := context.Background()
	rec := &recorder{}
	upSrvT, upCliT := mcp.NewInMemoryTransports()
	upSS, err := fakeUpstream(rec, blocked).Connect(ctx, upSrvT, nil)
	if err != nil {
		t.Fatal(err)
	}
	p, err := New(ctx, []Upstream{{Server: testServer, Transport: upCliT}}, Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	agSrvT, agCliT := mcp.NewInMemoryTransports()
	runDone := make(chan error, 1)
	go func() { runDone <- p.Run(ctx, agSrvT) }()
	agent, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(ctx, agCliT, nil)
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{proxy: p, agent: agent, upstream: upSS, rec: rec, runDone: runDone}
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
		for _, up := range p.upstreams {
			if !up.exited() {
				t.Errorf("upstream %s watcher still running after Close", up.name)
			}
		}
	})
	return h
}

func TestToolsListPrefixed(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()

	var got []*mcp.Tool
	for tool, err := range h.agent.Tools(ctx, nil) {
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, tool)
	}
	names := make([]string, 0, len(got))
	byName := map[string]*mcp.Tool{}
	for _, tool := range got {
		names = append(names, tool.Name)
		byName[tool.Name] = tool
	}
	slices.Sort(names)
	want := []string{
		"netdev-ssh-mcp.block",
		"netdev-ssh-mcp.failing_tool",
		"netdev-ssh-mcp.get_config",
		"netdev-ssh-mcp.protocol_error",
		"netdev-ssh-mcp.run_show_command",
	}
	if !slices.Equal(names, want) {
		t.Fatalf("tools/list names\n got %v\nwant %v", names, want)
	}
	if !slices.Equal(h.proxy.Tools(), want) {
		t.Fatalf("Proxy.Tools() = %v, want %v", h.proxy.Tools(), want)
	}

	show := byName["netdev-ssh-mcp.run_show_command"]
	if show.Description != "Run a show command" {
		t.Errorf("description changed: %q", show.Description)
	}
	// Annotations pass through untouched; the proxy neither trusts nor drops them.
	if show.Annotations == nil || !show.Annotations.ReadOnlyHint {
		t.Errorf("annotations not passed through: %+v", show.Annotations)
	}
	schema, _ := json.Marshal(show.InputSchema)
	if !strings.Contains(string(schema), `"command"`) {
		t.Errorf("input schema not passed through: %s", schema)
	}
}

func TestCallRoundTrip(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	cases := []struct {
		name      string
		tool      string
		args      map[string]any
		wantUp    string // unprefixed name the upstream must see
		wantError bool
		wantText  string
	}{
		{
			name:     "show command",
			tool:     "netdev-ssh-mcp.run_show_command",
			args:     map[string]any{"host": "lab-sw-01", "command": "show version"},
			wantUp:   "run_show_command",
			wantText: "ok run_show_command",
		},
		{
			name:     "no arguments",
			tool:     "netdev-ssh-mcp.get_config",
			wantUp:   "get_config",
			wantText: "ok get_config {}",
		},
		{
			name:      "upstream tool error passes through",
			tool:      "netdev-ssh-mcp.failing_tool",
			args:      map[string]any{"host": "lab-sw-01"},
			wantUp:    "failing_tool",
			wantError: true,
			wantText:  "device unreachable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := len(h.rec.all())
			res, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: tc.tool, Arguments: tc.args})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError != tc.wantError {
				t.Fatalf("IsError = %v, want %v (%s)", res.IsError, tc.wantError, text(res))
			}
			if !strings.Contains(text(res), tc.wantText) {
				t.Fatalf("result %q does not contain %q", text(res), tc.wantText)
			}
			calls := h.rec.all()[before:]
			if len(calls) != 1 {
				t.Fatalf("upstream saw %d calls, want exactly 1", len(calls))
			}
			if calls[0].Name != tc.wantUp {
				t.Fatalf("upstream saw name %q, want %q", calls[0].Name, tc.wantUp)
			}
			for k, v := range tc.args {
				if calls[0].Args[k] != v {
					t.Fatalf("upstream arg %s = %v, want %v", k, calls[0].Args[k], v)
				}
			}
		})
	}
}

func TestUnknownTool(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	cases := []struct {
		name       string
		tool       string
		wantReason string
	}{
		{"unprefixed", "run_show_command", reasonUnprefixed},
		{"empty prefix", ".run_show_command", reasonUnprefixed},
		{"empty tool", "netdev-ssh-mcp.", reasonUnprefixed},
		{"unknown server", "junos-mcp-server.run_show_command", reasonUnknownServer},
		{"unknown tool", "netdev-ssh-mcp.write_erase", reasonUnknownTool},
		{"refused upstream name", "netdev-ssh-mcp.bad name", reasonUnknownTool},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: tc.tool, Arguments: map[string]any{}})
			var werr *jsonrpc.Error
			if !errors.As(err, &werr) {
				t.Fatalf("want a JSON-RPC error, got %v", err)
			}
			if werr.Code != jsonrpc.CodeInvalidParams {
				t.Errorf("code %d, want %d", werr.Code, jsonrpc.CodeInvalidParams)
			}
			var d unknownToolData
			if err := json.Unmarshal(werr.Data, &d); err != nil {
				t.Fatalf("error data %q: %v", werr.Data, err)
			}
			if d.Reason != tc.wantReason || d.Tool != tc.tool || !slices.Equal(d.Servers, []string{testServer}) {
				t.Errorf("data = %+v, want reason %q tool %q", d, tc.wantReason, tc.tool)
			}
			if !strings.Contains(werr.Message, "unknown tool") {
				t.Errorf("message %q", werr.Message)
			}
		})
	}
	if n := len(h.rec.all()); n != 0 {
		t.Fatalf("upstream saw %d calls for unknown tools, want 0", n)
	}
}

func TestUpstreamProtocolErrorIsLabelled(t *testing.T) {
	h := newHarness(t, nil)
	_, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.protocol_error"})
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) {
		t.Fatalf("want a JSON-RPC error, got %v", err)
	}
	if werr.Code != jsonrpc.CodeInvalidParams {
		t.Errorf("code %d, want %d", werr.Code, jsonrpc.CodeInvalidParams)
	}
	if want := "upstream netdev-ssh-mcp: host is required"; werr.Message != want {
		t.Errorf("message %q, want %q", werr.Message, want)
	}
}

func TestAgentCancelCancelsUpstream(t *testing.T) {
	blocked := make(chan struct{}, 1)
	h := newHarness(t, blocked)
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		_, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.block"})
		errc <- err
	}()
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the call")
	}
	cancel()
	select {
	case err := <-errc:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("agent call error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent call did not return after cancel")
	}
	// The upstream handler returns only when its context is cancelled; a
	// following call proves the upstream is free again.
	res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.get_config"})
	if err != nil || res.IsError {
		t.Fatalf("follow-up call: %v %s", err, text(res))
	}
}

func TestUpstreamExit(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	if err := h.upstream.Close(); err != nil {
		t.Fatal(err)
	}
	up := h.proxy.upstreams[testServer]
	select {
	case <-up.done:
	case <-time.After(5 * time.Second):
		t.Fatal("proxy did not notice the upstream exit")
	}
	res, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01"}})
	if err != nil {
		t.Fatalf("want a tool error, got protocol error %v", err)
	}
	if !res.IsError || !strings.Contains(text(res), "upstream netdev-ssh-mcp is not running") {
		t.Fatalf("result %+v %q", res.IsError, text(res))
	}
	// The agent session itself stays up.
	if _, err := h.agent.ListTools(ctx, nil); err != nil {
		t.Fatalf("tools/list after upstream exit: %v", err)
	}
}

func TestNewErrors(t *testing.T) {
	ctx := context.Background()
	serve := func(t *testing.T) mcp.Transport {
		t.Helper()
		st, ct := mcp.NewInMemoryTransports()
		ss, err := fakeUpstream(&recorder{}, nil).Connect(ctx, st, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ss.Close() })
		return ct
	}
	cases := []struct {
		name    string
		ups     func(t *testing.T) []Upstream
		wantErr string
	}{
		{"none", func(*testing.T) []Upstream { return nil }, "no upstream"},
		{"empty server", func(t *testing.T) []Upstream { return []Upstream{{Server: "", Transport: serve(t)}} }, "empty"},
		{"dotted server", func(t *testing.T) []Upstream { return []Upstream{{Server: "net.dev", Transport: serve(t)}} }, "only ASCII"},
		{"nil transport", func(*testing.T) []Upstream { return []Upstream{{Server: "netdev"}} }, "no transport"},
		{"duplicate server", func(t *testing.T) []Upstream {
			return []Upstream{{Server: "netdev", Transport: serve(t)}, {Server: "netdev", Transport: serve(t)}}
		}, "configured twice"},
		{"connect failure", func(*testing.T) []Upstream {
			return []Upstream{{Server: "netdev", Transport: Command{Path: "netguard-no-such-upstream-binary"}.Transport()}}
		}, "connect"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(ctx, tc.ups(t), Options{})
			if err == nil {
				_ = p.Close()
				t.Fatal("New succeeded, want error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err, tc.wantErr)
			}
		})
	}
}

func TestAddUpstreamTools(t *testing.T) {
	obj := map[string]any{"type": "object"}
	cases := []struct {
		name      string
		tools     []*mcp.Tool
		wantErr   string
		wantNames []string
	}{
		{"duplicate upstream tool", []*mcp.Tool{{Name: "a", InputSchema: obj}, {Name: "a", InputSchema: obj}}, "twice", nil},
		{"skips non-object schema", []*mcp.Tool{{Name: "a", InputSchema: map[string]any{"type": "string"}}, {Name: "b", InputSchema: obj}}, "", []string{"s.b"}},
		{"skips missing schema", []*mcp.Tool{{Name: "a"}, {Name: "b", InputSchema: obj}}, "", []string{"s.b"}},
		{"skips invalid name", []*mcp.Tool{{Name: "a/b", InputSchema: obj}, {Name: "b", InputSchema: obj}}, "", []string{"s.b"}},
		{"skips over-long name", []*mcp.Tool{{Name: strings.Repeat("x", 127), InputSchema: obj}}, "", []string{}},
		{"keeps dotted upstream name", []*mcp.Tool{{Name: "a.b", InputSchema: obj}}, "", []string{"s.a.b"}},
		{"skips nil", []*mcp.Tool{nil, {Name: "b", InputSchema: obj}}, "", []string{"s.b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Proxy{
				server:    mcp.NewServer(&mcp.Implementation{Name: Name}, nil),
				logger:    discardLogger(),
				upstreams: map[string]*upstream{},
				routes:    map[string]route{},
			}
			err := p.addUpstreamTools(&upstream{name: "s"}, tc.tools)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := p.Tools(); !slices.Equal(got, tc.wantNames) {
				t.Fatalf("tools %v, want %v", got, tc.wantNames)
			}
		})
	}
}

func TestSplitName(t *testing.T) {
	cases := []struct {
		in           string
		server, tool string
		ok           bool
	}{
		{"netdev-ssh-mcp.run_show_command", "netdev-ssh-mcp", "run_show_command", true},
		{"s.a.b", "s", "a.b", true},
		{"run_show_command", "", "", false},
		{".x", "", "", false},
		{"x.", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range cases {
		s, tool, ok := splitName(tc.in)
		if s != tc.server || tool != tc.tool || ok != tc.ok {
			t.Errorf("splitName(%q) = %q, %q, %v; want %q, %q, %v", tc.in, s, tool, ok, tc.server, tc.tool, tc.ok)
		}
	}
	for _, name := range []string{"netdev-ssh-mcp", "junos_mcp", "eos"} {
		if err := validServerName(name); err != nil {
			t.Errorf("validServerName(%q) = %v", name, err)
		}
	}
	for _, name := range []string{"", "a.b", "a b", "a/b", "é"} {
		if err := validServerName(name); err == nil {
			t.Errorf("validServerName(%q) accepted", name)
		}
	}
}

func text(res *mcp.CallToolResult) string {
	if res == nil {
		return "<nil>"
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		} else {
			fmt.Fprintf(&b, "<%T>", c)
		}
	}
	return b.String()
}
