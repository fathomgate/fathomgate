// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tests for the post-merge security review of T0.40 (T0.42, T0.43, T0.45).

// foreignOrphan makes p's upstream remember that another agent session
// ended a call on it, live for an hour on p's clock, so the orphan rule
// refuses every prompt on it.
func foreignOrphan(p *Proxy) {
	up := p.upstreams[testServer]
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.orphans == nil {
		up.orphans = make(map[string]orphan)
		up.orphansOf = make(map[string]int)
	}
	up.orphans["sforeign"] = orphan{principal: "bob", expires: p.now().Add(time.Hour)}
	up.orphansOf["bob"]++
}

// expireOrphan ages the orphan key left on up to just before now on p's
// clock, as OrphanTTL would.
func expireOrphan(t *testing.T, p *Proxy, up *upstream, key string) {
	t.Helper()
	up.mu.Lock()
	defer up.mu.Unlock()
	o, ok := up.orphans[key]
	if !ok {
		t.Fatalf("no orphan %q on %s", key, up.name)
	}
	o.expires = p.now().Add(-time.Second)
	up.orphans[key] = o
}

// refusedB has agent B call ask_direct while another local agent's call
// has just ended on the upstream, and checks that the upstream's prompt was
// refused by the orphan rule (not as one of two calls in flight) and that
// the upstream's result reached B with the refusal appended.
func refusedB(t *testing.T, agentB *mcp.ClientSession) {
	t.Helper()
	res, err := agentB.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask_direct"})
	if err != nil || res.IsError {
		t.Fatalf("B's call: %v %q", err, text(res))
	}
	got := text(res)
	if !strings.HasPrefix(got, "upstream carried on without an answer") || !strings.Contains(got, errEndedElsewhere.Error()) {
		t.Fatalf("B's result %q, want the upstream's result and the orphan refusal", got)
	}
}

// TestOrphanRefusalNeverReplacesUpstreamError (T0.42, S3): when the orphan
// rule refuses a stateful upstream's prompt and fathomgate words the refusal
// from the one call in flight (the ADR 0014 exception), the refusal is a
// note on that call. An upstream error stays the upstream's own, and a
// result the upstream still completes keeps its content with the refusal
// appended. Before the fix the refusal went in the call's own slot and
// replaced the upstream's error with fathomgate's text.
func TestOrphanRefusalNeverReplacesUpstreamError(t *testing.T) {
	const upstreamErr = "FAKE-device: enable mode is locked"
	extra := func(s *mcp.Server) {
		addAskDirect(s)
		s.AddTool(&mcp.Tool{Name: "ask_then_fail", InputSchema: objectSchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if _, err := req.Session.Elicit(ctx, promptFor("pw")); err == nil {
				return textResult("upstream got an answer"), nil
			}
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: upstreamErr}
		})
	}
	for _, tc := range []struct {
		name  string
		setup eraSetup
		why   string // the reason the refusal names
	}{
		{"stateless agent", eraSetup{agent: v2026, upstream: v2025, extra: extra}, "ADR 0014"},
		{"agent without form elicitation", eraSetup{agent: v2025, upstream: v2025, noElicit: true, extra: extra}, "form elicitation"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newEraHarness(t, tc.setup)
			foreignOrphan(h.proxy)
			ctx := context.Background()

			// The upstream fails the call: the agent gets the upstream's
			// own error, relayed and labelled.
			res, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask_then_fail"})
			var werr *jsonrpc.Error
			if !errors.As(err, &werr) || !strings.HasPrefix(werr.Message, "upstream netdev-ssh-mcp: ") || !strings.Contains(werr.Message, upstreamErr) {
				t.Fatalf("want the upstream's own error, got %v (result %q)", err, text(res))
			}

			// The upstream completes the call: its content first, then the
			// refusal, appended.
			res, err = h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask_direct"})
			if err != nil {
				t.Fatal(err)
			}
			if res.IsError || len(res.Content) != 2 {
				t.Fatalf("result %v %q, want the upstream's content and one note", res.IsError, text(res))
			}
			first := res.Content[0].(*mcp.TextContent).Text
			note := res.Content[1].(*mcp.TextContent).Text
			if first != "upstream carried on without an answer" ||
				!strings.HasPrefix(note, "fathomgate refused an input request (elicitation) from upstream netdev-ssh-mcp during ask_direct: ") ||
				!strings.Contains(note, tc.why) {
				t.Fatalf("content %q, note %q", first, note)
			}
			if n := len(h.prompts.all()); n != 0 {
				t.Fatalf("%d prompts reached the agent", n)
			}
		})
	}
}

// TestLocalAgentOwnOrphanWithListener (T0.43, S1): building the HTTP
// handler (which sets p.limits) does not change how the local stdio agent
// is keyed. Its own ended call is an orphan under its own key, so a later
// prompt for its own call is still relayed. Before the fix the stdio
// session was keyed into the shared entry once p.limits was set, and every
// stateful prompt on the upstream was refused for OrphanTTL after its first
// call.
func TestLocalAgentOwnOrphanWithListener(t *testing.T) {
	h := newEraHarness(t, eraSetup{agent: v2025, upstream: v2025})
	if _, err := h.proxy.HTTPHandler(HTTPOptions{Tokens: map[string][]byte{"alice": tokAlice}}); err != nil {
		t.Fatal(err)
	}
	if h.proxy.limits.Load() == nil {
		t.Fatal("the HTTP handler did not set limits")
	}
	ctx := context.Background()
	if _, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01"}}); err != nil {
		t.Fatal(err)
	}
	up := h.proxy.upstreams[testServer]
	up.mu.Lock()
	_, own := up.orphans[localKeyPrefix+"1"]
	n := len(up.orphans)
	up.mu.Unlock()
	if !own || n != 1 {
		t.Fatalf("after the stdio agent's call: own orphan %v, %d orphans; want its own key only", own, n)
	}
	res, err := h.agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask"})
	if err != nil {
		t.Fatal(err)
	}
	if res.IsError || !strings.Contains(text(res), "pw=accept:"+agentPassword) {
		t.Fatalf("the stdio agent's own prompt: %v %q", res.IsError, text(res))
	}
	if n := len(h.prompts.all()); n != 1 {
		t.Fatalf("agent saw %d prompts, want 1", n)
	}
}

// TestLocalKeyDuringConnect (T0.43, kept at the security reviewer's
// request): a stdio tools/call that go-sdk dispatches while Run is still
// connecting, before it has recorded its session, waits for the record and
// is keyed l1, never a key of its own. The Run is held between Connect and the
// record by a test hook while the agent initialises and calls; the call's
// handler must be seen waiting before the hook lets Run go on.
func TestLocalKeyDuringConnect(t *testing.T) {
	ctx := context.Background()
	rec := &recorder{}
	upSrvT, upCliT := mcp.NewInMemoryTransports()
	if _, err := fakeUpstream(rec, nil).Connect(ctx, upSrvT, nil); err != nil {
		t.Fatal(err)
	}
	p, err := New(ctx, []Upstream{{Server: testServer, NewTransport: reuse(upCliT)}}, Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	waiting := make(chan struct{}, 1)
	p.testHookKeyWaiting = func() {
		select {
		case waiting <- struct{}{}:
		default:
		}
	}
	agSrvT, agCliT := mcp.NewInMemoryTransports()
	var agent *mcp.ClientSession
	callDone := make(chan error, 1)
	p.testHookConnected = func() {
		// Run has connected and not recorded its session yet.
		var err error
		agent, err = mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0"}, nil).Connect(ctx, agCliT, nil)
		if err != nil {
			callDone <- err
			return
		}
		go func() {
			_, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01"}})
			callDone <- err
		}()
		select {
		case <-waiting:
		case <-time.After(5 * time.Second):
			t.Error("the call's handler never waited for Run to record its session")
		}
	}
	runDone := make(chan error, 1)
	go func() { runDone <- p.Run(ctx, agSrvT) }()
	t.Cleanup(func() {
		if agent != nil {
			_ = agent.Close()
		}
		select {
		case <-runDone:
		case <-time.After(5 * time.Second):
			t.Error("Run did not return after the agent disconnected")
		}
		if err := p.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})

	select {
	case err := <-callDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the call did not finish")
	}
	up := p.upstreams[testServer]
	up.mu.Lock()
	_, own := up.orphans[localKeyPrefix+"1"]
	n, over := len(up.orphans), len(up.overflow)
	up.mu.Unlock()
	if !own || n != 1 || over != 0 {
		t.Fatalf("call made during connect: l1 orphan %v, %d orphans, %d overflow records; want l1 only", own, n, over)
	}

	// A request still waiting for a connecting Run when its context ends
	// gets no local key; agentSessionKey then gives it a key of its own
	// (T0.44), foreign to the local agent's, so it fails closed.
	stuck := make(chan struct{})
	p.localMu.Lock()
	p.connecting[stuck] = struct{}{}
	p.localMu.Unlock()
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if got := p.localKey(cctx, &mcp.ServerSession{}); got != "" {
		t.Fatalf("local key %q for a request whose context ended while waiting, want none", got)
	}
	if got := p.agentSessionKey(cctx, call{agent: agentPeer{session: &mcp.ServerSession{}}}); !strings.HasPrefix(got, requestKeyPrefix) {
		t.Fatalf("key %q for a request whose context ended while waiting, want a %q key of its own", got, requestKeyPrefix)
	}
	p.localMu.Lock()
	delete(p.connecting, stuck)
	p.localMu.Unlock()
}

// TestListenerCallNeverWaitsForRun (L1 in the security re-review of
// PR #78): while a Run is connecting (an entry in p.connecting that is
// never released here), a call over the HTTP listener is neither delayed
// nor mis-keyed. A stateful session's call is keyed by its session id and
// a stateless call by a key of its own (T0.44), both without waiting, so no
// listener call sits outside the call caps behind a stdio connect.
func TestListenerCallNeverWaitsForRun(t *testing.T) {
	h := newHTTPHarness(t, httpSetup{upstream: v2025})
	p := h.proxy
	stuck := make(chan struct{})
	p.localMu.Lock()
	if p.connecting == nil {
		p.connecting = make(map[chan struct{}]struct{})
	}
	p.connecting[stuck] = struct{}{}
	p.localMu.Unlock()
	waited := make(chan struct{}, 1)
	p.testHookKeyWaiting = func() {
		select {
		case waited <- struct{}{}:
		default:
		}
	}
	up := p.upstreams[testServer]
	for _, era := range []string{v2025, v2026} {
		cs := h.connect(t, era, tokAlice, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		start := time.Now()
		_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01"}})
		cancel()
		if err != nil {
			t.Fatalf("agent %s: %v", era, err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Errorf("agent %s: the call took %v with a Run connecting", era, d)
		}
		select {
		case <-waited:
			t.Fatalf("agent %s: a listener call waited for a connecting Run", era)
		default:
		}
		up.mu.Lock()
		_, keyed := up.orphans["s"+cs.ID()]
		perRequest := 0
		for key, o := range up.orphans {
			if strings.HasPrefix(key, requestKeyPrefix) && o.principal == "alice" {
				perRequest++
			}
			if strings.HasPrefix(key, localKeyPrefix) {
				t.Errorf("agent %s: listener call keyed %q, a local agent's key", era, key)
			}
		}
		up.mu.Unlock()
		switch {
		case era == v2025 && !keyed:
			t.Errorf("stateful call not keyed by its session id %q", cs.ID())
		case era == v2026 && perRequest != 1:
			t.Errorf("stateless call left %d per-request entries for alice, want 1", perRequest)
		}
	}
}

// TestPOSTBeforeRegistration (T0.45, S7): a POST that arrives on a new
// session before settleSession has registered it (the agent had the
// session id from the response header already) counts as in progress once
// the session is registered, so the idle clock does not run under it. A
// POST that ended before the registration, or another principal's, does
// not count.
func TestPOSTBeforeRegistration(t *testing.T) {
	p := newHarness(t, nil).proxy
	hd := &httpHandler{
		p:      p,
		logger: p.logger,
		opts:   HTTPOptions{SessionTimeout: time.Hour},
		live:   make(map[string]*liveSession),
		early:  make(map[earlySession]int),
	}
	active := func(ls *liveSession) (int, bool) {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		return ls.active, ls.running
	}
	begin := func(sid, principal string) func() {
		t.Helper()
		end, ok := hd.beginPOST(sid, principal)
		if !ok {
			t.Fatalf("beginPOST(%s, %s) refused a session that was never evicted", sid, principal)
		}
		return end
	}

	endDone := begin("s1", "alice") // ends before registration
	endDone()
	endAlice := begin("s1", "alice") // still in progress
	endBob := begin("s1", "bob")     // another principal: go-sdk's 403
	ls := &liveSession{h: hd, sid: "s1", principal: "alice"}
	hd.register(ls)
	ls.arm()
	defer ls.stop()
	if n, running := active(ls); n != 1 || running {
		t.Fatalf("after registration: %d POSTs in progress, idle clock running %v; want 1 and stopped", n, running)
	}

	// A POST after registration pauses the clock as before.
	endLate := begin("s1", "alice")
	if n, _ := active(ls); n != 2 {
		t.Fatalf("%d POSTs in progress, want 2", n)
	}
	endLate()
	endAlice()
	if n, running := active(ls); n != 0 || !running {
		t.Fatalf("after both ended: %d POSTs in progress, idle clock running %v; want 0 and running", n, running)
	}
	endBob()
	hd.mu.Lock()
	left := len(hd.early)
	hd.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d early entries left, want none", left)
	}
}
