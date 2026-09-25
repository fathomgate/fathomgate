// SPDX-License-Identifier: FSL-1.1-ALv2

package proxy

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fathomgate/fathomgate/internal/gate/seam"
)

// TestReadOnlyHintsExactKeys (security review of PR #167, L1): keys are
// matched byte for byte, as go-sdk's decoder matches them, so a key in
// another case cannot make the two parsers read different tools or hints.
func TestReadOnlyHintsExactKeys(t *testing.T) {
	got := readOnlyHintsOf([]byte(`{"tools":[
		{"name":"a","annotations":{"readOnlyHint":false,"READONLYHINT":true}},
		{"name":"b","NAME":"other","annotations":{"readOnlyHint":true}},
		{"name":"c","annotations":{"readOnlyHint":null}},
		{"name":"d"},
		{"NAME":"e","annotations":{"readOnlyHint":false}},
		{"name":"f","annotations":{"ReadOnlyHint":false}},
		{"name":"g","annotations":{"readOnlyHint":"false"}},
		{"name":"h","annotations":{"readOnlyHint":true,"readOnlyHint":false}}
	],"TOOLS":[{"name":"x","annotations":{"readOnlyHint":false}}]}`))
	want := map[string]string{"a": "false", "b": "true", "h": "false"}
	if len(got) != len(want) {
		t.Errorf("hints for %d tools, want %d: %v", len(got), len(want), got)
	}
	for name, w := range want {
		v := got[name]
		if v == nil || map[bool]string{true: "true", false: "false"}[*v] != w {
			t.Errorf("%s: %v, want %s", name, v, w)
		}
	}
	for _, bad := range []string{``, `[]`, `{"tools":{}}`, `{"tools":[1]}`} {
		if got := readOnlyHintsOf([]byte(bad)); len(got) != 0 {
			t.Errorf("%q: %v", bad, got)
		}
	}
}

// caseSplit rewrites the upstream's tools/list answer so a case-folding
// decoder would read another hint than go-sdk does.
type caseSplit struct{ mcp.Transport }

func (t caseSplit) Connect(ctx context.Context) (mcp.Connection, error) {
	c, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return caseSplitConn{c}, nil
}

type caseSplitConn struct{ mcp.Connection }

func (c caseSplitConn) Write(ctx context.Context, m jsonrpc.Message) error {
	if r, ok := m.(*jsonrpc.Response); ok && strings.Contains(string(r.Result), `"tools":`) {
		r.Result = []byte(strings.ReplaceAll(string(r.Result), `"readOnlyHint":false,"title":"split"`, `"readOnlyHint":false,"READONLYHINT":true,"title":"split"`))
	}
	return c.Connection.Write(ctx, m)
}

// TestGateAnnotationCaseSplit: on the wire, "readOnlyHint":false beside
// "READONLYHINT":true reaches the gate as false, the value go-sdk reads.
func TestGateAnnotationCaseSplit(t *testing.T) {
	g := &fakeGate{decide: allowAll}
	h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2026, policy: g,
		extra: func(s *mcp.Server) {
			s.AddTool(&mcp.Tool{Name: "split", InputSchema: objectSchema, Annotations: &mcp.ToolAnnotations{Title: "split"}},
				func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) { return textResult("ok"), nil })
		},
		upstreamWrap: func(t mcp.Transport) mcp.Transport { return caseSplit{t} }})
	if _, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.split"}); err != nil {
		t.Fatal(err)
	}
	if in := g.all()[0]; in.ReadOnlyHint == nil || *in.ReadOnlyHint {
		t.Errorf("readOnlyHint %v, want false", in.ReadOnlyHint)
	}
}

// TestGateRetryVerifiedFirst (security review of PR #167, L2): a retry
// whose requestState does not verify is refused before the gate runs:
// no decision line, nothing counted, nothing forwarded.
func TestGateRetryVerifiedFirst(t *testing.T) {
	logger, buf := bufferLogger(slog.LevelInfo)
	g := &fakeGate{decide: allowAll}
	h := newEraHarness(t, eraSetup{agent: v2026, upstream: v2026, manualMRTR: true, policy: g, logger: logger})
	ctx := context.Background()
	args := map[string]any{"host": "core-rtr-01"}
	first, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: args})
	if err != nil || first.RequestState == "" {
		t.Fatalf("first round: %v %+v", err, first)
	}
	_, err = h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: args,
		RequestState: "FAKE-forged", InputResponses: mcp.InputResponseMap{"pw": &mcp.ElicitResult{Action: "accept"}}})
	var werr *jsonrpc.Error
	if !errors.As(err, &werr) || werr.Code != jsonrpc.CodeInvalidParams {
		t.Fatalf("forged retry: %v", err)
	}
	if len(g.all()) != 1 || len(buf.lines("msg=decision")) != 1 || len(h.rec.all()) != 1 {
		t.Errorf("gate calls %d, decision lines %d, upstream calls %d; want 1, 1, 1",
			len(g.all()), len(buf.lines("msg=decision")), len(h.rec.all()))
	}
	// A retry with the state fathomgate issued is decided and forwarded.
	res, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: args,
		RequestState: first.RequestState, InputResponses: mcp.InputResponseMap{"pw": &mcp.ElicitResult{Action: "accept", Content: map[string]any{"password": agentPassword}}}})
	// (The gate runs twice for it: core-rtr-01 is already touched.)
	if err != nil || res.IsError || len(buf.lines("msg=decision")) != 2 || len(h.rec.all()) != 2 {
		t.Errorf("valid retry: %v %q, decision lines %d, upstream calls %d", err, text(res), len(buf.lines("msg=decision")), len(h.rec.all()))
	}
}

// TestGateUpstreamExitedFirst (L2): a call to an upstream that has exited
// gets its tool error before the gate runs, so it is never logged as
// forwarded or counted.
func TestGateUpstreamExitedFirst(t *testing.T) {
	g := &fakeGate{decide: allowAll}
	h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2025, policy: g})
	up := h.proxy.upstreams[testServer]
	up.closing.Store(true)
	_ = up.session.Close()
	<-up.done
	res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "x"}})
	if err != nil || !res.IsError || !strings.Contains(text(res), "is not running") || len(g.all()) != 0 {
		t.Errorf("%v %q, gate calls %d", err, text(res), len(g.all()))
	}
	h.proxy.counters.mu.Lock()
	defer h.proxy.counters.mu.Unlock()
	if len(h.proxy.counters.keys) != 0 {
		t.Errorf("counted: %v", h.proxy.counters.keys)
	}
}

// fakeRuntimeError implements runtime.Error outside the runtime.
type fakeRuntimeError struct{}

func (fakeRuntimeError) Error() string    { return "FAKE-secret from an argument" }
func (fakeRuntimeError) RuntimeError()    {}
func (fakeRuntimeError) String() string   { return "FAKE-secret" }
func (fakeRuntimeError) GoString() string { return "FAKE-secret" }

// TestGatePanicKinds (Go review of PR #167, item 5): only the runtime's own
// errors are logged by their text; anything else, even a runtime.Error
// from elsewhere, by its type.
func TestGatePanicKinds(t *testing.T) {
	for _, tc := range []struct {
		name  string
		panic func()
		want  string
	}{
		{"runtime", func() { var s []int; _ = s[len(s)+1] }, "runtime error: index out of range"},
		{"impostor", func() { panic(fakeRuntimeError{}) }, "panic=proxy.fakeRuntimeError"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			logger, buf := bufferLogger(slog.LevelInfo)
			p := &Proxy{logger: logger, gate: &fakeGate{decide: func(seam.CallInfo) seam.Verdict { tc.panic(); return seam.Verdict{} }}}
			if _, ok := p.safeDecide(context.Background(), seam.CallInfo{Server: "s", Tool: "t"}); ok {
				t.Fatal("a panic must not be ok")
			}
			l := buf.lines("the gate panicked")
			if len(l) != 1 || !strings.Contains(l[0], tc.want) || strings.Contains(l[0], "FAKE-secret") {
				t.Errorf("%q, want %q", l, tc.want)
			}
		})
	}
}

// TestRefusalClassSource: the proxy's own refusals say the classifier never
// ran (class_source proxy).
func TestRefusalClassSource(t *testing.T) {
	v := (&Proxy{}).refusalVerdict(seam.CallInfo{Server: "s", Tool: "t"}, ruleBadArguments, reasonTooLarge, parseTooLarge)
	if v.ClassSource != "proxy" {
		t.Errorf("class_source %q", v.ClassSource)
	}
	for _, a := range v.Record {
		if a.Key == "class_source" && a.Value.String() != "proxy" {
			t.Errorf("record class_source %q", a.Value.String())
		}
	}
}

// TestArgumentsPanicClosesTool: a panic in Gate.Arguments at New leaves the
// tool closed with no named arguments.
func TestArgumentsPanicClosesTool(t *testing.T) {
	p := &Proxy{logger: discardLogger(), gate: panicArgs{}}
	if named, closed := p.toolArguments("s", "t"); !closed || named != nil {
		t.Errorf("%q %v", named, closed)
	}
}

type panicArgs struct{}

func (panicArgs) Decide(context.Context, seam.CallInfo) seam.Verdict { return seam.Verdict{} }
func (panicArgs) Arguments(string, string) ([]string, bool)          { panic("FAKE") }
