// SPDX-License-Identifier: FSL-1.1-ALv2

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fathomgate/fathomgate/internal/gate/seam"
)

// fakeGate is a Gate whose verdicts the test chooses. It records every
// CallInfo it is given.
type fakeGate struct {
	decide func(seam.CallInfo) seam.Verdict
	named  map[string][]string // closed tools and their named arguments

	mu    sync.Mutex
	calls []seam.CallInfo
}

func (g *fakeGate) Decide(_ context.Context, in seam.CallInfo) seam.Verdict {
	g.mu.Lock()
	g.calls = append(g.calls, in)
	g.mu.Unlock()
	return g.decide(in)
}

func (g *fakeGate) Arguments(_, tool string) ([]string, bool) {
	n, ok := g.named[tool]
	return n, ok
}

func (g *fakeGate) all() []seam.CallInfo {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.calls)
}

// hostOf is the "host" argument of a call, the fake gate's one target.
func hostOf(in seam.CallInfo) []string {
	var a struct {
		Host string `json:"host"`
	}
	_ = json.Unmarshal(in.Arguments, &a)
	if a.Host == "" {
		return nil
	}
	return []string{a.Host}
}

// allowAll forwards every call, with the host as its target.
func allowAll(in seam.CallInfo) seam.Verdict {
	return seam.Verdict{Forward: true, Effect: "allow", RuleID: "reads-anywhere", Class: "READ_OPERATIONAL", ClassSource: "profile", Targets: hostOf(in),
		Record: []slog.Attr{slog.String("server", in.Server), slog.String("tool", in.Tool), slog.String("decision", "allow")}}
}

// lockedBuffer is a log sink safe for the proxy's goroutines.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) lines(substr string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, line := range strings.Split(l.b.String(), "\n") {
		if strings.Contains(line, substr) {
			out = append(out, line)
		}
	}
	return out
}

func bufferLogger(level slog.Level) (*slog.Logger, *lockedBuffer) {
	buf := &lockedBuffer{}
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: level})), buf
}

// TestGateVerdictsOnTheWire: each effect reaches the agent in its wire form,
// in every era pair. Only a Verdict with Forward reaches the upstream; every
// other one is a tool error (isError, one text block) with the gate's text
// exactly, and the upstream sees nothing.
func TestGateVerdictsOnTheWire(t *testing.T) {
	const (
		denied = "fathomgate denied netdev-ssh-mcp.run_show_command: rule no-exec (class EXEC_ARBITRARY): command did not pass the read allow-list"
		held   = "fathomgate held netdev-ssh-mcp.run_show_command: rule prod-core-needs-approval (class WRITE_CONFIG): needs approval, and approvals aren't available yet, so this call was not run."
		cannot = "fathomgate cannot run netdev-ssh-mcp.run_show_command: rule lab-writes-free (class WRITE_CONFIG): obligation dry_run cannot be met until change-safety drivers exist"
	)
	cases := []struct {
		name    string
		verdict seam.Verdict
		want    string // "" for a forwarded call
	}{
		{"allow", seam.Verdict{Forward: true, Effect: "allow", RuleID: "reads-anywhere", Class: "READ_OPERATIONAL"}, ""},
		{"deny", seam.Verdict{Effect: "deny", RuleID: "no-exec", Class: "EXEC_ARBITRARY", Error: denied}, denied},
		{"hold", seam.Verdict{Effect: "hold", RuleID: "prod-core-needs-approval", Class: "WRITE_CONFIG", Error: held}, held},
		{"cannot run", seam.Verdict{Effect: "allow", RuleID: "lab-writes-free", Class: "WRITE_CONFIG", Error: cannot}, cannot},
		{"refused without text", seam.Verdict{Effect: "deny", RuleID: "r1", Class: "READ_OPERATIONAL"},
			"fathomgate denied netdev-ssh-mcp.run_show_command: rule r1 (class READ_OPERATIONAL): the policy does not allow this call"},
	}
	for _, e := range eras {
		for _, tc := range cases {
			t.Run(e.agent+"/"+e.upstream+"/"+tc.name, func(t *testing.T) {
				g := &fakeGate{decide: func(seam.CallInfo) seam.Verdict { return tc.verdict }}
				h := newEraHarness(t, eraSetup{agent: e.agent, upstream: e.upstream, policy: g})
				res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{
					Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "core-rtr-01", "command": "show version"},
				})
				if err != nil {
					t.Fatalf("a refusal is a tool result, never a JSON-RPC error: %v", err)
				}
				if len(g.all()) != 1 {
					t.Fatalf("gate called %d times, want 1", len(g.all()))
				}
				calls := h.rec.all()
				if tc.want == "" {
					if res.IsError || len(calls) != 1 {
						t.Fatalf("allow: isError=%v %q, upstream calls %d", res.IsError, text(res), len(calls))
					}
					return
				}
				if !res.IsError || len(res.Content) != 1 || text(res) != tc.want {
					t.Errorf("got isError=%v %d blocks %q\nwant %q", res.IsError, len(res.Content), text(res), tc.want)
				}
				if res.StructuredContent != nil || len(res.InputRequests) != 0 || res.RequestState != "" {
					t.Errorf("a refusal carries only its text: %+v", res)
				}
				if len(calls) != 0 {
					t.Errorf("a refused call reached the upstream: %+v", calls)
				}
			})
		}
	}
}

// TestGateCallInfo: the gate is told the call as the proxy saw it: server,
// unprefixed tool, the agent's arguments, both protocol versions and era
// labels, the transport, and the principal ("(local)" on stdio).
func TestGateCallInfo(t *testing.T) {
	g := &fakeGate{decide: allowAll}
	h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2026, policy: g})
	raw := json.RawMessage(`{"host":"lab-sw-01","command":"show version"}`)
	if _, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: raw}); err != nil {
		t.Fatal(err)
	}
	in := g.all()[0]
	want := seam.CallInfo{
		Server: testServer, Tool: "run_show_command", Arguments: raw,
		ReadOnlyHint: in.ReadOnlyHint, DestructiveHint: in.DestructiveHint,
		AgentProtocol: v2025, AgentEra: eraStateful, UpstreamProtocol: v2026, UpstreamEra: eraStateless,
		Transport: "stdio", Principal: localPrincipal,
	}
	if in.Server != want.Server || in.Tool != want.Tool || string(in.Arguments) != string(raw) ||
		in.AgentProtocol != want.AgentProtocol || in.AgentEra != want.AgentEra ||
		in.UpstreamProtocol != want.UpstreamProtocol || in.UpstreamEra != want.UpstreamEra ||
		in.Transport != want.Transport || in.Principal != want.Principal || in.SessionID != "" || in.PendingHolds != 0 {
		t.Errorf("CallInfo\n got %+v\nwant %+v", in, want)
	}
}

// TestGateForwardsCheckedArguments: with a gate, the upstream receives the
// object the gate checked, re-encoded (keys sorted, one copy of a nested
// duplicate key, numbers as written), never the agent's bytes. With no
// gate the agent's bytes cross as they are (M0).
func TestGateForwardsCheckedArguments(t *testing.T) {
	raw := json.RawMessage(`{"host":"lab-sw-01","command":"show version","n":1.50,"big":12345678901234567890,"x":{"a":1,"a":2}}`)
	for _, tc := range []struct {
		name string
		gate Gate
		want string
	}{
		{"no gate", nil, `{"host":"lab-sw-01","command":"show version","n":1.50,"big":12345678901234567890,"x":{"a":1,"a":2}}`},
		{"gate", &fakeGate{decide: allowAll}, `{"big":12345678901234567890,"command":"show version","host":"lab-sw-01","n":1.50,"x":{"a":2}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2025, policy: tc.gate})
			res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: raw})
			if err != nil || res.IsError {
				t.Fatalf("%v %q", err, text(res))
			}
			if got := strings.TrimPrefix(text(res), "ok run_show_command "); got != tc.want {
				t.Errorf("upstream received\n %s\nwant\n %s", got, tc.want)
			}
		})
	}
	// Absent arguments stay absent.
	h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2025, policy: &fakeGate{decide: allowAll}})
	res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.get_config"})
	if err != nil || text(res) != "ok get_config {}" {
		t.Errorf("no arguments: %v %q", err, text(res))
	}
}

// TestGatePanicDenies: a panic in Decide (or in the resolver it calls) is a
// deny with a fixed text, logged at Error; nothing reaches the upstream and
// the proxy keeps serving.
func TestGatePanicDenies(t *testing.T) {
	logger, buf := bufferLogger(slog.LevelInfo)
	panicking := true
	g := &fakeGate{decide: func(in seam.CallInfo) seam.Verdict {
		if panicking {
			panic("resolver exploded on FAKE-secret")
		}
		return allowAll(in)
	}}
	h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2025, policy: g, logger: logger})
	ctx := context.Background()
	res, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "core-rtr-01"}})
	if err != nil {
		t.Fatal(err)
	}
	const want = "fathomgate denied netdev-ssh-mcp.run_show_command: rule default:internal_error (class EXEC_ARBITRARY): fathomgate could not decide this call, so it was not run"
	if !res.IsError || text(res) != want {
		t.Errorf("got %v %q\nwant %q", res.IsError, text(res), want)
	}
	if n := len(h.rec.all()); n != 0 {
		t.Errorf("upstream saw %d calls", n)
	}
	if l := buf.lines("the gate panicked"); len(l) != 1 || !strings.Contains(l[0], "level=ERROR") || !strings.Contains(l[0], "panic=string") {
		t.Errorf("panic line %q", l)
	}
	if l := buf.lines("FAKE-secret"); len(l) != 0 {
		t.Errorf("the panic value was logged: %q", l)
	}
	if l := buf.lines("msg=decision"); len(l) != 1 || !strings.Contains(l[0], "rule_id=default:internal_error") || !strings.Contains(l[0], "forwarded=false") {
		t.Errorf("decision line %q", l)
	}
	panicking = false
	if res, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "core-rtr-01"}}); err != nil || res.IsError {
		t.Errorf("after a panic the proxy must keep serving: %v %q", err, text(res))
	}
}

// TestGateArgumentCap: arguments over 64 KiB are denied before Decide, with
// default:bad_arguments; at the cap they reach the gate.
func TestGateArgumentCap(t *testing.T) {
	logger, buf := bufferLogger(slog.LevelInfo)
	g := &fakeGate{decide: allowAll}
	h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2025, policy: g, logger: logger})
	ctx := context.Background()
	sized := func(n int) json.RawMessage {
		const head, tail = `{"host":"lab-sw-01","command":"`, `"}`
		return json.RawMessage(head + strings.Repeat("a", n-len(head)-len(tail)) + tail)
	}
	res, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: sized(maxArgumentBytes + 1)})
	if err != nil {
		t.Fatal(err)
	}
	const want = "fathomgate denied netdev-ssh-mcp.run_show_command: rule default:bad_arguments (class EXEC_ARBITRARY): the arguments are larger than 64 KiB"
	if !res.IsError || text(res) != want {
		t.Errorf("got %v %q\nwant %q", res.IsError, text(res), want)
	}
	if len(g.all()) != 0 || len(h.rec.all()) != 0 {
		t.Errorf("over the cap: gate calls %d, upstream calls %d", len(g.all()), len(h.rec.all()))
	}
	if l := buf.lines("msg=decision"); len(l) != 1 || !strings.Contains(l[0], "parse_error=too_large") || strings.Contains(l[0], "aaaa") {
		t.Errorf("decision line %q", l)
	}
	res, err = h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: sized(maxArgumentBytes)})
	if err != nil || res.IsError || len(g.all()) != 1 {
		t.Errorf("at the cap: %v %q, gate calls %d", err, text(res), len(g.all()))
	}
}

// stripHint removes readOnlyHint from the tools/list answer of the tool
// whose annotations title is "absent-ro", as an upstream that omits it
// sends it. go-sdk v1.8 always writes readOnlyHint, so its fake cannot.
type stripHint struct{ mcp.Transport }

func (t stripHint) Connect(ctx context.Context) (mcp.Connection, error) {
	c, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return stripHintConn{c}, nil
}

type stripHintConn struct{ mcp.Connection }

func (c stripHintConn) Write(ctx context.Context, m jsonrpc.Message) error {
	if r, ok := m.(*jsonrpc.Response); ok && bytes.Contains(r.Result, []byte(`"tools":`)) {
		r.Result = bytes.ReplaceAll(r.Result, []byte(`"readOnlyHint":false,"title":"absent-ro"`), []byte(`"title":"absent-ro"`))
	}
	return c.Connection.Write(ctx, m)
}

// TestGateAnnotations: the gate gets readOnlyHint as the upstream sent it,
// nil when absent (never go-sdk's false), and destructiveHint as go-sdk
// keeps it, in both upstream eras.
func TestGateAnnotations(t *testing.T) {
	yes, no := true, false
	tools := func(s *mcp.Server) {
		echo := func(_ context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return textResult("ok"), nil
		}
		s.AddTool(&mcp.Tool{Name: "ann_none", InputSchema: objectSchema}, echo)
		s.AddTool(&mcp.Tool{Name: "ann_ro_true", InputSchema: objectSchema, Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}}, echo)
		s.AddTool(&mcp.Tool{Name: "ann_ro_false", InputSchema: objectSchema, Annotations: &mcp.ToolAnnotations{Title: "explicit"}}, echo)
		s.AddTool(&mcp.Tool{Name: "ann_ro_absent", InputSchema: objectSchema, Annotations: &mcp.ToolAnnotations{Title: "absent-ro"}}, echo)
		s.AddTool(&mcp.Tool{Name: "ann_destructive", InputSchema: objectSchema, Annotations: &mcp.ToolAnnotations{Title: "d", DestructiveHint: &yes}}, echo)
		s.AddTool(&mcp.Tool{Name: "ann_not_destructive", InputSchema: objectSchema, Annotations: &mcp.ToolAnnotations{Title: "nd", DestructiveHint: &no}}, echo)
	}
	want := map[string]struct{ ro, d *bool }{
		"ann_none":            {nil, nil},
		"ann_ro_true":         {&yes, nil},
		"ann_ro_false":        {&no, nil},
		"ann_ro_absent":       {nil, nil},
		"ann_destructive":     {&no, &yes},
		"ann_not_destructive": {&no, &no},
	}
	show := func(b *bool) string {
		if b == nil {
			return "nil"
		}
		if *b {
			return "true"
		}
		return "false"
	}
	for _, up := range []string{v2025, v2026} {
		t.Run(up, func(t *testing.T) {
			g := &fakeGate{decide: allowAll}
			h := newEraHarness(t, eraSetup{agent: v2025, upstream: up, policy: g, extra: tools,
				upstreamWrap: func(t mcp.Transport) mcp.Transport { return stripHint{t} }})
			for name := range want {
				if _, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp." + name}); err != nil {
					t.Fatal(err)
				}
			}
			for _, in := range g.all() {
				w := want[in.Tool]
				if show(in.ReadOnlyHint) != show(w.ro) || show(in.DestructiveHint) != show(w.d) {
					t.Errorf("%s: readOnlyHint %s destructiveHint %s, want %s %s", in.Tool,
						show(in.ReadOnlyHint), show(in.DestructiveHint), show(w.ro), show(w.d))
				}
			}
		})
	}
}

// capGate forwards a call only while its key's distinct devices stay
// within max, as policy.Evaluate's max_devices does.
func capGate(max int) *fakeGate {
	return &fakeGate{decide: func(in seam.CallInfo) seam.Verdict { return capVerdict(in, max) }}
}

func capVerdict(in seam.CallInfo, max int) seam.Verdict {
	v := allowAll(in)
	if in.DevicesTouched+len(v.Targets) > max {
		v.Forward, v.Effect, v.RuleID = false, "deny", "default:session.max_devices"
		v.Error = "fathomgate denied " + in.Server + "." + in.Tool + ": rule default:session.max_devices (class READ_OPERATIONAL): this session would touch more devices than its cap allows"
	}
	return v
}

func showOn(t *testing.T, cs *mcp.ClientSession, host string) *mcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": host}})
	if err != nil {
		t.Fatalf("%s: %v", host, err)
	}
	return res
}

// TestGateCountersPerPrincipal: over HTTP devices_touched is counted per
// principal in both eras (ADR 0026 decision 4 as amended 2026-09-25): new
// clients and new sessions of one principal share the count, another
// principal has its own, a device already touched is counted once, and only
// forwarded calls count.
func TestGateCountersPerPrincipal(t *testing.T) {
	g := &fakeGate{decide: func(in seam.CallInfo) seam.Verdict {
		v := allowAll(in)
		if hostOf(in)[0] == "refused-01" {
			v.Forward, v.Effect, v.Error = false, "deny", "fathomgate denied x"
		}
		return v
	}}
	h := newHTTPHarness(t, httpSetup{policy: g})
	type step struct {
		who  *mcp.ClientSession
		host string
		want int // DevicesTouched of the last Decide
	}
	alice1 := h.connect(t, v2026, tokAlice, nil)
	alice2 := h.connect(t, v2026, tokAlice, nil)
	bob := h.connect(t, v2026, tokBob, nil)
	aliceS := h.connect(t, v2025, tokAlice, nil)
	aliceS2 := h.connect(t, v2025, tokAlice, nil)
	for i, s := range []step{
		{alice1, "a-01", 0},
		{alice2, "b-01", 1}, // same principal, another stateless client
		{bob, "a-01", 0},
		{alice1, "a-01", 1}, // touched already: counted once, so 2 - 1
		{alice2, "c-01", 2},
		{bob, "refused-01", 1},
		{bob, "d-01", 1},     // the refused call did not count
		{aliceS, "e-01", 3},  // a stateful session of alice shares her count
		{aliceS2, "e-01", 3}, // and so does another: e-01 is counted once
	} {
		showOn(t, s.who, s.host)
		calls := g.all()
		if got := calls[len(calls)-1].DevicesTouched; got != s.want {
			t.Errorf("step %d (%s): devices_touched %d, want %d", i, s.host, got, s.want)
		}
	}
	h.proxy.counters.mu.Lock()
	keys := slices.Sorted(maps.Keys(h.proxy.counters.keys))
	h.proxy.counters.mu.Unlock()
	if !slices.Equal(keys, []string{"principal:alice", "principal:bob"}) {
		t.Errorf("counter keys %q", keys)
	}
}

// TestGateCountersSurviveSessionChurn (security review of PR #167, M1): a
// 2025-era agent that opens a session, touches a device and closes it,
// again and again, cannot reset max_devices; nor can a principal that
// mixes eras.
func TestGateCountersSurviveSessionChurn(t *testing.T) {
	h := newHTTPHarness(t, httpSetup{policy: capGate(1)})
	for i := range 4 {
		cs := h.connect(t, v2025, tokAlice, nil)
		res := showOn(t, cs, "dev-0"+strconv.Itoa(i))
		if res.IsError != (i > 0) {
			t.Errorf("session %d: isError=%v %q", i, res.IsError, text(res))
		}
		if err := cs.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(h.rec.all()); n != 1 {
		t.Errorf("upstream saw %d calls, want only the first", n)
	}

	// One principal, both eras, one count.
	stateful := h.connect(t, v2025, tokBob, nil)
	stateless := h.connect(t, v2026, tokBob, nil)
	if res := showOn(t, stateful, "dev-a"); res.IsError {
		t.Fatalf("first device: %q", text(res))
	}
	if res := showOn(t, stateless, "dev-b"); !res.IsError || !strings.Contains(text(res), "default:session.max_devices") {
		t.Errorf("second device through the other era: %v %q", res.IsError, text(res))
	}
	if res := showOn(t, stateless, "dev-a"); res.IsError {
		t.Errorf("the device already touched, through the other era: %q", text(res))
	}
}

// TestGateCountersStdio: on stdio every call is counted as the process,
// in both eras.
func TestGateCountersStdio(t *testing.T) {
	for _, agent := range []string{v2025, v2026} {
		t.Run(agent, func(t *testing.T) {
			g := &fakeGate{decide: allowAll}
			h := newEraHarness(t, eraSetup{agent: agent, upstream: v2026, policy: g})
			for i, host := range []string{"a-01", "b-01", "a-01"} {
				showOn(t, h.agent, host)
				calls := g.all()
				if got, want := calls[len(calls)-1].DevicesTouched, []int{0, 1, 1}[i]; got != want {
					t.Errorf("call %d: devices_touched %d, want %d", i, got, want)
				}
			}
			h.proxy.counters.mu.Lock()
			keys := slices.Sorted(maps.Keys(h.proxy.counters.keys))
			h.proxy.counters.mu.Unlock()
			if !slices.Equal(keys, []string{"process"}) {
				t.Errorf("counter keys %q, want [process]", keys)
			}
		})
	}
}

// TestGateCountersSerialised (Go review of PR #167, item 3): two concurrent
// calls on one key under max_devices 1, the first held inside Decide until
// the second is waiting for the key's lock: exactly one is forwarded. No
// sleeps: the test hook says when the second call is waiting.
func TestGateCountersSerialised(t *testing.T) {
	entered, release, waiting := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	var mu sync.Mutex
	n := 0
	g := &fakeGate{decide: func(in seam.CallInfo) seam.Verdict {
		mu.Lock()
		n++
		first := n == 1
		mu.Unlock()
		if first {
			close(entered)
			<-release
		}
		return capVerdict(in, 1)
	}}
	h := newEraHarness(t, eraSetup{agent: v2026, upstream: v2026, policy: g})
	h.proxy.testHookCounterWait = func() { waiting <- struct{}{} }
	results := make(chan *mcp.CallToolResult, 2)
	call := func(host string) {
		res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": host}})
		if err != nil {
			res = toolError(err.Error())
		}
		results <- res
	}
	go call("dev-a")
	<-entered
	go call("dev-b")
	<-waiting
	close(release)
	forwarded := 0
	for range 2 {
		if res := <-results; !res.IsError {
			forwarded++
		}
	}
	if forwarded != 1 || len(h.rec.all()) != 1 {
		t.Errorf("forwarded %d, upstream calls %d; want 1 and 1", forwarded, len(h.rec.all()))
	}
}

// TestGateCounterLockHonoursContext: a call waiting for its key's lock
// gives up when its context ends.
func TestGateCounterLockHonoursContext(t *testing.T) {
	sc := (&counters{}).get("process")
	if err := sc.lock(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := sc.lock(ctx, cancel); !errors.Is(err, context.Canceled) {
		t.Errorf("lock with a cancelled context: %v", err)
	}
	sc.unlock()
	if err := sc.lock(context.Background(), nil); err != nil {
		t.Errorf("after unlock: %v", err)
	}
}

// TestCounterKey pins the key rule: the principal over HTTP and the
// process on stdio, whatever the era or session.
func TestCounterKey(t *testing.T) {
	stateful, stateless := agentPeer{version: v2025}, agentPeer{version: v2026}
	for _, tc := range []struct {
		c    call
		want string
	}{
		{call{agent: stateful, sessionKey: "sabc", transport: transportHTTP, principal: "alice"}, "principal:alice"},
		{call{agent: stateful, sessionKey: "l1", transport: transportStdio}, "process"},
		{call{agent: stateful, sessionKey: "r7", transport: transportHTTP, principal: "alice"}, "principal:alice"},
		{call{agent: stateless, sessionKey: "r9", transport: transportHTTP, principal: "bob"}, "principal:bob"},
		{call{agent: stateless, sessionKey: "l1", transport: transportStdio}, "process"},
	} {
		if got := counterKey(tc.c); got != tc.want {
			t.Errorf("%+v: %q, want %q", tc.c, got, tc.want)
		}
	}
}

// TestTouchedCap: past maxTouchedNames the count only grows.
func TestTouchedCap(t *testing.T) {
	sc := &sessionCounter{touched: map[string]struct{}{}}
	for i := range maxTouchedNames {
		sc.touch([]string{"d" + strconv.Itoa(i)})
	}
	before := sc.touchedCount()
	sc.touch([]string{"over-01"})
	sc.touch([]string{"over-01"})
	if got := sc.touchedCount(); got != before+2 || sc.alreadyTouched([]string{"over-01"}) != 0 {
		t.Errorf("past the cap: %d, want %d", got, before+2)
	}
}

// TestGateNarrowsSchema: with a gate, a closed tool is advertised with only
// its named properties, in properties and in required; other tools, and
// every tool without a gate, are advertised as the upstream listed them.
func TestGateNarrowsSchema(t *testing.T) {
	reqSchema := map[string]any{
		"type":       "object",
		"properties": map[string]any{"host": map[string]any{"type": "string"}, "config_path": map[string]any{"type": "string"}},
		"required":   []any{"host", "config_path"},
	}
	extra := func(s *mcp.Server) {
		s.AddTool(&mcp.Tool{Name: "with_required", InputSchema: reqSchema}, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return textResult("ok"), nil
		})
	}
	schemas := func(h *eraHarness) map[string]string {
		lt, err := h.agent.ListTools(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, tl := range lt.Tools {
			b, _ := json.Marshal(tl.InputSchema)
			out[tl.Name] = string(b)
		}
		return out
	}
	g := &fakeGate{decide: allowAll, named: map[string][]string{"run_show_command": {"host"}, "with_required": {"host"}, "get_config": {}}}
	got := schemas(newEraHarness(t, eraSetup{agent: v2025, upstream: v2026, policy: g, extra: extra}))
	for name, want := range map[string]string{
		"netdev-ssh-mcp.run_show_command": `{"additionalProperties":false,"properties":{"host":{"type":"string"}},"type":"object"}`,
		"netdev-ssh-mcp.with_required":    `{"additionalProperties":false,"properties":{"host":{"type":"string"}},"required":["host"],"type":"object"}`,
		"netdev-ssh-mcp.get_config":       `{"additionalProperties":false,"properties":{},"type":"object"}`,
		"netdev-ssh-mcp.failing_tool":     `{"properties":{"command":{"type":"string"},"host":{"type":"string"}},"type":"object"}`,
	} {
		if got[name] != want {
			t.Errorf("%s: %s\nwant %s", name, got[name], want)
		}
	}
	if b, _ := json.Marshal(reqSchema); !strings.Contains(string(b), "config_path") {
		t.Errorf("the upstream's own schema was changed: %s", b)
	}
	plain := schemas(newEraHarness(t, eraSetup{agent: v2025, upstream: v2026, extra: extra}))
	if want := `{"properties":{"config_path":{"type":"string"},"host":{"type":"string"}},"required":["host","config_path"],"type":"object"}`; plain["netdev-ssh-mcp.with_required"] != want {
		t.Errorf("no gate: %s", plain["netdev-ssh-mcp.with_required"])
	}
}

// TestGateRerunsOnRetry: an MRTR retry runs the gate again, and a retry the
// gate refuses never reaches the upstream.
func TestGateRerunsOnRetry(t *testing.T) {
	var mu sync.Mutex
	n := 0
	g := &fakeGate{decide: func(in seam.CallInfo) seam.Verdict {
		mu.Lock()
		defer mu.Unlock()
		n++
		if n == 2 {
			return seam.Verdict{Effect: "deny", RuleID: "changed", Class: "READ_OPERATIONAL", Error: "fathomgate denied netdev-ssh-mcp.ask: rule changed (class READ_OPERATIONAL): the policy changed"}
		}
		return allowAll(in)
	}}
	h := newEraHarness(t, eraSetup{agent: v2026, upstream: v2026, policy: g})
	res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: map[string]any{"host": "core-rtr-01"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError || !strings.Contains(text(res), "rule changed") {
		t.Errorf("retry: %v %q", res.IsError, text(res))
	}
	if len(g.all()) != 2 || len(h.rec.all()) != 1 {
		t.Errorf("gate calls %d (want 2), upstream calls %d (want 1: the first round only)", len(g.all()), len(h.rec.all()))
	}
}

// TestGateRefusesUpstreamPrompts: with a gate, an upstream prompt during a
// call to a closed tool is refused, on both prompt paths, because its answer
// would be an argument the profile never named. A tool whose list is not
// closed (no profile) still relays.
func TestGateRefusesUpstreamPrompts(t *testing.T) {
	direct := func(s *mcp.Server) {
		s.AddTool(&mcp.Tool{Name: "ask_direct", InputSchema: objectSchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if _, err := req.Session.Elicit(ctx, promptFor("pw")); err == nil {
				return textResult("upstream got an answer"), nil
			}
			return textResult("upstream carried on without an answer"), nil
		})
	}
	const reason = "a policy is enforced and fathomgate cannot check an answer against the server profile, so upstream prompts are not relayed"
	for _, e := range eras {
		t.Run(e.agent+"/"+e.upstream, func(t *testing.T) {
			g := &fakeGate{decide: allowAll, named: map[string][]string{"ask": {"host"}, "ask_direct": {"host"}}}
			h := newEraHarness(t, eraSetup{agent: e.agent, upstream: e.upstream, policy: g, extra: direct})
			ctx := context.Background()
			res, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: map[string]any{"host": "core-rtr-01"}})
			got := text(res)
			if err != nil {
				got = err.Error()
			}
			if n := len(h.prompts.all()); n != 0 {
				t.Fatalf("an upstream prompt reached the agent (%d)", n)
			}
			adr0014 := e.agent == v2026 && e.upstream == v2025 // refused by ADR 0014 first
			if !adr0014 && !strings.Contains(got, reason) {
				t.Errorf("ask: %q", got)
			}
			if e.agent == v2025 && e.upstream == v2025 {
				// go-sdk's stateless server cannot send elicitation/create.
				res, err = h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask_direct", Arguments: map[string]any{"host": "core-rtr-01"}})
				if err != nil || !strings.HasPrefix(text(res), "upstream carried on without an answer") || !strings.Contains(text(res), reason) {
					t.Errorf("ask_direct: %v %q", err, text(res))
				}
				if n := len(h.prompts.all()); n != 0 {
					t.Fatalf("an upstream prompt reached the agent (%d)", n)
				}
			}
		})
	}
	// Not closed: relayed as in M0.
	g := &fakeGate{decide: allowAll}
	h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2026, policy: g})
	res, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask", Arguments: map[string]any{"host": "core-rtr-01"}})
	if err != nil || res.IsError || len(h.prompts.all()) != 1 {
		t.Errorf("open tool: %v %q, prompts %d", err, text(res), len(h.prompts.all()))
	}
}

// TestDecisionLine: one Info line per call, msg=decision, with the gate's
// attributes; the trace only at Debug. An agent-chosen argument name with
// a newline in it stays on the one line (threat model, log injection).
func TestDecisionLine(t *testing.T) {
	for _, level := range []slog.Level{slog.LevelInfo, slog.LevelDebug} {
		t.Run(level.String(), func(t *testing.T) {
			logger, buf := bufferLogger(level)
			g := &fakeGate{decide: func(in seam.CallInfo) seam.Verdict {
				return seam.Verdict{Effect: "deny", RuleID: "default:bad_arguments", Class: "READ_OPERATIONAL", Error: "fathomgate denied x",
					Record: []slog.Attr{slog.String("decision", "deny"), slog.Any("unnamed_args", []string{"a\nlevel=ERROR msg=forged"})},
					Trace:  slog.Any("trace", []string{"default:bad_arguments matched"})}
			}}
			h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2025, policy: g, logger: logger})
			if _, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command"}); err != nil {
				t.Fatal(err)
			}
			lines := buf.lines("msg=decision")
			if len(lines) != 1 || !strings.Contains(lines[0], "level=INFO") || !strings.Contains(lines[0], "decision=deny") {
				t.Fatalf("decision lines %q", lines)
			}
			if forged := buf.lines("msg=forged"); len(forged) != 1 || forged[0] != lines[0] {
				t.Errorf("an argument name started a line of its own: %q", forged)
			}
			if hasTrace := strings.Contains(lines[0], "trace="); hasTrace != (level == slog.LevelDebug) {
				t.Errorf("trace at %s: %v", level, hasTrace)
			}
		})
	}
}

// TestNoGateNoDecisionLine: without a gate nothing is decided or logged as a
// decision (M0 pass-through).
func TestNoGateNoDecisionLine(t *testing.T) {
	logger, buf := bufferLogger(slog.LevelDebug)
	h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2025, logger: logger})
	if _, err := h.agent.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "x"}}); err != nil {
		t.Fatal(err)
	}
	if l := buf.lines("msg=decision"); len(l) != 0 {
		t.Errorf("decision lines without a gate: %q", l)
	}
}

func TestReencode(t *testing.T) {
	for _, tc := range []struct{ in, want, err string }{
		{``, ``, ""},
		{`null`, ``, ""},
		{` {} `, `{}`, ""},
		{`{"b":1,"a":"é<"}`, `{"a":"é<","b":1}`, ""},
		{`[]`, ``, "cannot unmarshal"},
		{`{} {}`, ``, "data after"},
	} {
		got, err := reencode(json.RawMessage(tc.in))
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: error %v, want %q", tc.in, err, tc.err)
			}
			continue
		}
		if err != nil || string(got) != tc.want {
			t.Errorf("%s: %s %v, want %s", tc.in, got, err, tc.want)
		}
	}
}
