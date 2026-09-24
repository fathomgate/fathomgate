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

// localSessions waits until p's Run calls are serving n agent sessions and
// returns them. The agent's connect can return before Run has recorded its
// session, because go-sdk answers initialise on its own.
func localSessions(t *testing.T, p *Proxy, n int) []*mcp.ServerSession {
	t.Helper()
	var out []*mcp.ServerSession
	waitFor(t, "Run to record its agent sessions", func() bool {
		p.localMu.RLock()
		defer p.localMu.RUnlock()
		out = out[:0]
		for ss := range p.locals {
			out = append(out, ss)
		}
		return len(out) == n
	})
	return out
}

// foreignOrphan makes up remember that another agent session ended a call
// on it an hour from now, so the orphan rule refuses every prompt on up.
func foreignOrphan(up *upstream) {
	up.mu.Lock()
	defer up.mu.Unlock()
	if up.orphans == nil {
		up.orphans = make(map[string]orphan)
	}
	up.orphans["sforeign"] = orphan{principal: "bob", expires: time.Now().Add(time.Hour)}
}

// expireOrphan ages the orphan key left on up, as OrphanTTL would.
func expireOrphan(t *testing.T, up *upstream, key string) {
	t.Helper()
	up.mu.Lock()
	defer up.mu.Unlock()
	o, ok := up.orphans[key]
	if !ok {
		t.Fatalf("no orphan %q on %s", key, up.name)
	}
	o.expires = time.Now().Add(-time.Second)
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
// rule refuses a stateful upstream's prompt and netguard words the refusal
// from the one call in flight (the ADR 0014 exception), the refusal is a
// note on that call. An upstream error stays the upstream's own, and a
// result the upstream still completes keeps its content with the refusal
// appended. Before the fix the refusal went in the call's own slot and
// replaced the upstream's error with netguard's text.
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
			foreignOrphan(h.proxy.upstreams[testServer])
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
				!strings.HasPrefix(note, "netguard refused an input request (elicitation) from upstream netdev-ssh-mcp during ask_direct: ") ||
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
	shared := up.orphanOverflow
	up.mu.Unlock()
	if !own || !shared.IsZero() {
		t.Fatalf("after the stdio agent's call: own orphan %v, shared entry until %v; want its own key and no shared entry", own, shared)
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

// TestPOSTBeforeRegistration (T0.45, S7): a POST that arrives on a new
// session before settleSession has registered it (the agent had the
// session id from the response header already) counts as in progress once
// the session is registered, so the idle clock does not run under it. A
// POST that ended before the registration, or another principal's, does
// not count.
func TestPOSTBeforeRegistration(t *testing.T) {
	hd := &httpHandler{
		opts:  HTTPOptions{SessionTimeout: time.Hour},
		live:  make(map[string]*liveSession),
		early: make(map[earlyPOST]int),
	}
	active := func(ls *liveSession) (int, bool) {
		ls.mu.Lock()
		defer ls.mu.Unlock()
		// The timer is stopped while a POST is in progress; Stop reports
		// whether it was still running.
		running := ls.timer != nil && ls.timer.Stop()
		if running {
			ls.timer.Reset(hd.opts.SessionTimeout)
		}
		return ls.active, running
	}

	endDone := hd.beginPOST("s1", "alice") // ends before registration
	endDone()
	endAlice := hd.beginPOST("s1", "alice") // still in progress
	endBob := hd.beginPOST("s1", "bob")     // another principal: go-sdk's 403
	ls := &liveSession{h: hd, sid: "s1", principal: "alice"}
	hd.register(ls)
	ls.arm()
	defer ls.stop()
	if n, running := active(ls); n != 1 || running {
		t.Fatalf("after registration: %d POSTs in progress, idle clock running %v; want 1 and stopped", n, running)
	}

	// A POST after registration pauses the clock as before.
	endLate := hd.beginPOST("s1", "alice")
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
