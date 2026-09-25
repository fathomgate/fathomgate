// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Session-cap eviction (T0.57; ADR 0016 amendment of 2026-09-25,
// profile-schema 8.5 limit 8). An agent that restarts without a DELETE
// leaves its old session behind; when a new initialise from the same
// principal would pass a session cap, the principal's least recently used
// idle session is evicted instead of the initialise getting 503. Idle means
// no POST in progress, no GET stream and no call in flight. Another
// principal's sessions are never candidates.

// rawSession opens a stateful session with raw requests, as an agent that
// never opens a GET stream does, and returns its id.
func rawSession(t *testing.T, h *httpHarness, token []byte) string {
	t.Helper()
	sid, status, body := tryRawSession(t, h, token)
	if status != http.StatusOK {
		t.Fatalf("initialise: status %d, body %q", status, clip(body))
	}
	return sid
}

// tryRawSession sends an initialise and, when it succeeds, the initialised
// notification. It returns the session id, the initialise's status and body.
func tryRawSession(t *testing.T, h *httpHarness, token []byte) (string, int, string) {
	t.Helper()
	ctx := context.Background()
	resp, body := h.do(t, h.request(ctx, "POST", token, nil, initialize2025))
	sid := resp.Header.Get("Mcp-Session-Id")
	if resp.StatusCode != http.StatusOK {
		return sid, resp.StatusCode, body
	}
	note := `{"jsonrpc":"2.0","method":"notifications/initialized"}` //nolint:misspell // MCP wire method name, not prose
	hdr := map[string]string{"Mcp-Protocol-Version": v2025, "Mcp-Session-Id": sid}
	if r, b := h.do(t, h.request(ctx, "POST", token, hdr, note)); r.StatusCode != http.StatusAccepted {
		t.Fatalf("initialised notification: status %d, body %q", r.StatusCode, clip(b))
	}
	waitFor(t, "the new session to be registered", func() bool {
		h.hh.mu.Lock()
		defer h.hh.mu.Unlock()
		return h.hh.live[sid] != nil
	})
	return sid, resp.StatusCode, body
}

// pingSession sends a ping on session sid and returns the status.
func pingSession(t *testing.T, h *httpHarness, token []byte, sid string) int {
	t.Helper()
	hdr := map[string]string{"Mcp-Protocol-Version": v2025, "Mcp-Session-Id": sid}
	resp, _ := h.do(t, h.request(context.Background(), "POST", token, hdr, `{"jsonrpc":"2.0","id":9,"method":"ping"}`))
	return resp.StatusCode
}

// sessionState reads what the listener holds for sid.
func sessionState(h *httpHarness, sid string) (live, evicted bool, gets int) {
	live, evicted, gets, _ = sessionCounts(h, sid)
	return live, evicted, gets
}

// sessionCounts is sessionState with the POSTs in progress.
func sessionCounts(h *httpHarness, sid string) (live, evicted bool, gets, posts int) {
	h.hh.mu.Lock()
	defer h.hh.mu.Unlock()
	ls := h.hh.live[sid]
	if ls == nil {
		return false, false, 0, 0
	}
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return true, ls.evicted, ls.gets, ls.active
}

// waitRetiredEmpty waits until callLimits holds no retired session: every
// session fathomgate retired (evicted or expired) has ended and its watcher
// has forgotten it. A retirement that landed after the forget would leave
// a closed session pinned here for good (Go re-review of PR #121).
func waitRetiredEmpty(t *testing.T, h *httpHarness) {
	t.Helper()
	l := h.proxy.limits.Load()
	waitFor(t, "the retired set to empty", func() bool {
		l.mu.Lock()
		defer l.mu.Unlock()
		return len(l.retired) == 0
	})
}

// openGET opens a GET stream on sid and waits until the listener counts
// it. It returns the function that closes the stream and waits for the
// listener to count it closed; the stream also closes when the test ends.
func openGET(t *testing.T, h *httpHarness, token []byte, sid string) (closeGET func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	stop := func() {
		cancel()
		<-done
	}
	t.Cleanup(stop)
	hdr := map[string]string{"Mcp-Protocol-Version": v2025, "Mcp-Session-Id": sid}
	go func() {
		defer close(done)
		if resp, err := h.raw.Do(h.request(ctx, "GET", token, hdr, "")); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	waitFor(t, "the GET stream to be counted", func() bool {
		_, _, gets := sessionState(h, sid)
		return gets == 1
	})
	return func() {
		t.Helper()
		stop()
		waitFor(t, "the GET stream to be counted closed", func() bool {
			_, _, gets := sessionState(h, sid)
			return gets == 0
		})
	}
}

func TestHTTPSessionCapEviction(t *testing.T) {
	ctx := context.Background()

	t.Run("least recently used idle session of the principal", func(t *testing.T) {
		buf := newSyncBuffer()
		logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		h := newHTTPHarness(t, httpSetup{logger: logger, opts: HTTPOptions{MaxSessionsPerPrincipal: 2}})
		s1 := rawSession(t, h, tokAlice)
		s2 := rawSession(t, h, tokAlice)
		// s1 is used after s2 was opened, so s2 is the least recently used.
		// The order is a sequence, not a clock reading, so no sleep is needed
		// even where the clock is coarse (Windows).
		if st := pingSession(t, h, tokAlice, s1); st != http.StatusOK {
			t.Fatalf("ping s1: %d", st)
		}
		s3 := rawSession(t, h, tokAlice) // a restarted agent: no DELETE for s1 or s2
		if st := pingSession(t, h, tokAlice, s2); st != http.StatusNotFound {
			t.Fatalf("the evicted session answered %d, want 404", st)
		}
		for _, sid := range []string{s1, s3} {
			if st := pingSession(t, h, tokAlice, sid); st != http.StatusOK {
				t.Fatalf("a session that was not evicted answered %d", st)
			}
		}
		waitFor(t, "the evicted session to be closed", func() bool {
			live, _, _ := sessionState(h, s2)
			return !live
		})
		waitRetiredEmpty(t, h)
		h.hh.mu.Lock()
		n := h.hh.sessionsPerPrincipal["alice"]
		h.hh.mu.Unlock()
		if n != 2 {
			t.Fatalf("alice holds %d session slots, want 2 (the cap)", n)
		}
		buf.waitFor(t, "agent session evicted")
		if logs := buf.String(); !strings.Contains(logs, "session="+shortHash(s2)) || strings.Contains(logs, s2) {
			t.Fatalf("the eviction line must name s2 by its hash only:\n%s", logs)
		}
	})

	t.Run("a closed GET stream counts as a use", func(t *testing.T) {
		h := newHTTPHarness(t, httpSetup{opts: HTTPOptions{MaxSessionsPerPrincipal: 2}})
		s1 := rawSession(t, h, tokAlice)
		s2 := rawSession(t, h, tokAlice)
		// s1's stream closes after s2 was opened, so s2 is the least
		// recently used although s1 was opened first.
		openGET(t, h, tokAlice, s1)()
		rawSession(t, h, tokAlice)
		if st := pingSession(t, h, tokAlice, s2); st != http.StatusNotFound {
			t.Fatalf("s2 answered %d, want 404 (evicted)", st)
		}
		if st := pingSession(t, h, tokAlice, s1); st != http.StatusOK {
			t.Fatalf("s1 answered %d; its closed stream should have made it the more recent", st)
		}
	})

	t.Run("a session in use is never evicted", func(t *testing.T) {
		hooks := &blockHooks{blocked: make(chan struct{}, 4), cancelled: make(chan struct{}, 4)}
		buf := newSyncBuffer()
		logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
		h := newHTTPHarness(t, httpSetup{hooks: hooks, logger: logger, opts: HTTPOptions{MaxSessionsPerPrincipal: 3}})

		// 1. A call in flight whose POST was dropped (go-sdk detaches it).
		dropped := rawSession(t, h, tokAlice)
		dctx, drop := context.WithCancel(ctx)
		body, hdr := call2025(dropped, "netdev-ssh-mcp.block", "")
		posted := make(chan struct{})
		go func() {
			defer close(posted)
			if resp, err := h.raw.Do(h.request(dctx, "POST", tokAlice, hdr, body)); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
		recvOrFail(t, hooks.blocked, "the dropped call to reach the upstream")
		drop()
		<-posted

		// 2. A GET stream open.
		streaming := rawSession(t, h, tokAlice)
		openGET(t, h, tokAlice, streaming)

		// 3. A POST in progress that has no call yet: its body is still
		// arriving, so only the POST count keeps the session in use.
		posting := rawSession(t, h, tokAlice)
		pr, pw := io.Pipe()
		req := h.request(ctx, "POST", tokAlice, map[string]string{"Mcp-Protocol-Version": v2025, "Mcp-Session-Id": posting}, "")
		req.Body, req.ContentLength = pr, -1
		open := make(chan struct{})
		go func() {
			defer close(open)
			if resp, err := h.raw.Do(req); err == nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
			}
		}()
		t.Cleanup(func() {
			_ = pw.CloseWithError(io.ErrUnexpectedEOF)
			<-open
		})
		if _, err := pw.Write([]byte(`{"jsonrpc":"2.0",`)); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "the POST to be in progress", func() bool {
			_, _, _, posts := sessionCounts(h, posting)
			return posts == 1
		})

		_, status, reply := tryRawSession(t, h, tokAlice)
		if status != http.StatusServiceUnavailable || !strings.Contains(reply, "for this principal") {
			t.Fatalf("initialise with every session in use: status %d, body %q; want 503 for this principal", status, clip(reply))
		}
		for _, sid := range []string{dropped, streaming, posting} {
			if live, evicted, _ := sessionState(h, sid); !live || evicted {
				t.Fatalf("a session in use was evicted (live %v, evicted %v)", live, evicted)
			}
		}
		if n := h.proxy.limits.Load().inFlight(); n != 1 {
			t.Fatalf("%d calls in flight, want 1: eviction must not cancel a call", n)
		}
		// The 503 is logged with what kept each session in use, so an
		// operator can see a client holding GET streams on sessions it no
		// longer uses (the conformance suite does exactly that).
		buf.waitFor(t, "new session refused")
		want := "principal=alice sessions=3 posting=1 streaming=1 calling=1 closing=0"
		if logs := buf.String(); !strings.Contains(logs, want) {
			t.Fatalf("the refusal line lacks %q:\n%s", want, logs)
		}
	})

	t.Run("another principal's idle sessions are never evicted", func(t *testing.T) {
		h := newHTTPHarness(t, httpSetup{opts: HTTPOptions{MaxSessions: 2, MaxSessionsPerPrincipal: 2}})
		a1 := rawSession(t, h, tokAlice)
		a2 := rawSession(t, h, tokAlice)
		_, status, reply := tryRawSession(t, h, tokBob)
		if status != http.StatusServiceUnavailable || strings.Contains(reply, "for this principal") {
			t.Fatalf("bob with alice holding every slot: status %d, body %q; want 503 for the overall cap", status, clip(reply))
		}
		for _, sid := range []string{a1, a2} {
			if st := pingSession(t, h, tokAlice, sid); st != http.StatusOK {
				t.Fatalf("alice's idle session answered %d after bob's initialise", st)
			}
		}
	})

	t.Run("the overall cap evicts the principal's own idle session", func(t *testing.T) {
		h := newHTTPHarness(t, httpSetup{opts: HTTPOptions{MaxSessions: 2, MaxSessionsPerPrincipal: 2}})
		a1 := rawSession(t, h, tokAlice)
		b1 := rawSession(t, h, tokBob)
		a2 := rawSession(t, h, tokAlice)
		if st := pingSession(t, h, tokAlice, a1); st != http.StatusNotFound {
			t.Fatalf("alice's older session answered %d, want 404 (evicted)", st)
		}
		if st := pingSession(t, h, tokBob, b1); st != http.StatusOK {
			t.Fatalf("bob's session answered %d", st)
		}
		if st := pingSession(t, h, tokAlice, a2); st != http.StatusOK {
			t.Fatalf("alice's new session answered %d", st)
		}
	})

	t.Run("a stateful go-sdk client whose session was evicted reconnects", func(t *testing.T) {
		h := newHTTPHarness(t, httpSetup{opts: HTTPOptions{MaxSessionsPerPrincipal: 1}})
		old := rawSession(t, h, tokAlice) // the crashed agent's session
		cs := h.connect(t, v2025, tokAlice, nil)
		if st := pingSession(t, h, tokAlice, old); st != http.StatusNotFound {
			t.Fatalf("the crashed agent's session answered %d, want 404", st)
		}
		if err := cs.Ping(ctx, nil); err != nil {
			t.Fatalf("the new agent's session: %v", err)
		}
	})
}

// TestEvictedSessionRefusedBeforeSDK: once evicted, a session's own
// principal gets 404 from fathomgate on POST and GET, so nothing can start on
// a session go-sdk is still closing; another principal's request is left to
// go-sdk's 403 and counts nowhere.
func TestEvictedSessionRefusedBeforeSDK(t *testing.T) {
	p := newHarness(t, nil).proxy
	hd := &httpHandler{
		p:                    p,
		logger:               p.logger,
		opts:                 HTTPOptions{SessionTimeout: time.Hour},
		sessionsPerPrincipal: map[string]int{"alice": 1},
		sessions:             1,
		live:                 make(map[string]*liveSession),
		early:                make(map[earlySession]int),
		earlyGets:            make(map[earlySession]int),
		capLog:               make(map[string]*capLogState),
	}
	slot := &sessionSlot{h: hd, principal: "alice"}
	ls := &liveSession{h: hd, sid: "s1", principal: "alice", slot: slot}
	hd.register(ls)
	ls.arm()
	hd.mu.Lock()
	hd.evictLocked(ls)
	sessions, alice := hd.sessions, hd.sessionsPerPrincipal["alice"]
	hd.mu.Unlock()
	if sessions != 0 || alice != 0 {
		t.Fatalf("after eviction: %d sessions, %d for alice; want the slot released", sessions, alice)
	}
	slot.release() // the session's own end later: a no-op
	hd.mu.Lock()
	sessions = hd.sessions
	hd.mu.Unlock()
	if sessions != 0 {
		t.Fatalf("a second release changed the count to %d", sessions)
	}
	if _, ok := hd.beginPOST("s1", "alice"); ok {
		t.Fatal("a POST on the evicted session was let through")
	}
	if _, ok := hd.beginGET("s1", "alice"); ok {
		t.Fatal("a GET on the evicted session was let through")
	}
	for _, begin := range []func(string, string) (func(), bool){hd.beginPOST, hd.beginGET} {
		end, ok := begin("s1", "bob")
		if !ok {
			t.Fatal("another principal's request was refused by fathomgate, not left to go-sdk's 403")
		}
		end()
	}
	ls.mu.Lock()
	active, gets, running := ls.active, ls.gets, ls.running
	ls.mu.Unlock()
	if active != 0 || gets != 0 || running {
		t.Fatalf("evicted session: %d POSTs, %d GETs, idle clock running %v; want none", active, gets, running)
	}
}

// TestGETBeforeRegistration: a GET stream the agent opens on a new session
// before settleSession has registered it (it has the id from the initialise
// response) counts once the session is registered, so the session is not
// idle and cannot be evicted while the stream is open. Another principal's
// GET counts nowhere.
func TestGETBeforeRegistration(t *testing.T) {
	p := newHarness(t, nil).proxy
	hd := &httpHandler{
		p:         p,
		logger:    p.logger,
		opts:      HTTPOptions{SessionTimeout: time.Hour},
		live:      make(map[string]*liveSession),
		early:     make(map[earlySession]int),
		earlyGets: make(map[earlySession]int),
		capLog:    make(map[string]*capLogState),
	}
	endAlice, ok := hd.beginGET("s1", "alice")
	if !ok {
		t.Fatal("a GET before registration was refused")
	}
	endBob, _ := hd.beginGET("s1", "bob")
	ls := &liveSession{h: hd, sid: "s1", principal: "alice"}
	hd.register(ls)
	ls.arm()
	defer ls.stop()
	if _, _, idle := ls.idleState(); idle {
		t.Fatal("a session with a GET stream opened before registration reads as idle")
	}
	endAlice()
	if _, _, idle := ls.idleState(); !idle {
		t.Fatal("the session is not idle after its only stream closed")
	}
	endBob()
	hd.mu.Lock()
	left := len(hd.earlyGets)
	hd.mu.Unlock()
	ls.mu.Lock()
	gets := ls.gets
	ls.mu.Unlock()
	if left != 0 || gets != 0 {
		t.Fatalf("%d early GET entries left and %d GETs on the session; want none", left, gets)
	}
}

// admitGate holds a tool call in Proxy.handler after go-sdk has delivered it
// and before callLimits.admit (Proxy.testHookBeforeAdmit): the window in
// which the agent can drop its POST, leaving a session that looks idle with
// a call about to start on it.
type admitGate struct {
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func newAdmitGate(t *testing.T) *admitGate {
	g := &admitGate{reached: make(chan struct{}, 4), release: make(chan struct{})}
	// Registered before the harness, so it runs after the proxy has closed
	// and no handler is left waiting at the gate.
	t.Cleanup(g.open)
	return g
}

func (g *admitGate) hook() {
	g.reached <- struct{}{}
	<-g.release
}

func (g *admitGate) open() { g.once.Do(func() { close(g.release) }) }

// deliverAndDrop sends a tools/call for "block" on session sid, waits until
// go-sdk has delivered it to the proxy's handler (held at the gate), then
// drops the POST, so the session has no POST in progress and no admitted
// call: it looks idle.
func deliverAndDrop(t *testing.T, h *httpHarness, g *admitGate, sid string) {
	t.Helper()
	ctx, drop := context.WithCancel(context.Background())
	body, hdr := call2025(sid, "netdev-ssh-mcp.block", "")
	posted := make(chan struct{})
	go func() {
		defer close(posted)
		if resp, err := h.raw.Do(h.request(ctx, "POST", tokAlice, hdr, body)); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	recvOrFail(t, g.reached, "the call to be delivered to the proxy's handler")
	drop()
	<-posted
	waitFor(t, "the dropped POST to end", func() bool {
		_, _, _, posts := sessionCounts(h, sid)
		return posts == 0
	})
	if n := h.proxy.limits.Load().inFlight(); n != 0 {
		t.Fatalf("%d calls admitted before the gate opened, want none", n)
	}
}

// assertRefusedBeforeUpstream opens the gate and checks that the held call
// is refused as a call on a retired session and never reaches the upstream.
func assertRefusedBeforeUpstream(t *testing.T, h *httpHarness, g *admitGate, hooks *blockHooks, buf *syncBuffer) {
	t.Helper()
	g.open()
	buf.waitFor(t, "call refused: its agent session is being closed")
	select {
	case <-hooks.blocked:
		t.Fatal("a call on a retired session reached the upstream")
	default:
	}
	if n := h.proxy.limits.Load().inFlight(); n != 0 {
		t.Fatalf("%d calls in flight after the refusal, want none", n)
	}
	waitRetiredEmpty(t, h)
}

// TestEvictionRefusesUnadmittedCall is the admission race in the reviews of
// PR #121: go-sdk has delivered a tools/call but the handler has not reached
// admit, and the agent has dropped the POST. The session looks idle, a new
// initialise evicts it, and without the claim the call would then be
// admitted and run on a closed session with no idle clock while its slot
// served another session. claimIdle retires the session in the same step
// as it checks for calls, so admit refuses the call and nothing reaches the
// upstream.
func TestEvictionRefusesUnadmittedCall(t *testing.T) {
	hooks := &blockHooks{blocked: make(chan struct{}, 4), cancelled: make(chan struct{}, 4)}
	gate := newAdmitGate(t)
	buf := newSyncBuffer()
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	h := newHTTPHarness(t, httpSetup{hooks: hooks, logger: logger, beforeAdmit: gate.hook, opts: HTTPOptions{MaxSessionsPerPrincipal: 1}})

	s1 := rawSession(t, h, tokAlice)
	deliverAndDrop(t, h, gate, s1)
	rawSession(t, h, tokAlice) // evicts s1, the call on it still at the gate
	// s1 is evicted: still listed while go-sdk's Close waits on the held
	// call, or already gone.
	if live, evicted, _ := sessionState(h, s1); live && !evicted {
		t.Fatal("s1 was not evicted")
	}
	assertRefusedBeforeUpstream(t, h, gate, hooks, buf)
}

// TestIdleExpiryRefusesUnadmittedCall: the same window at the idle expiry.
// liveSession.expire retires the session as it cancels its calls, so a call
// delivered before and admitted after is refused rather than run on a
// session that is closing with no idle clock left to cancel it.
func TestIdleExpiryRefusesUnadmittedCall(t *testing.T) {
	hooks := &blockHooks{blocked: make(chan struct{}, 4), cancelled: make(chan struct{}, 4)}
	gate := newAdmitGate(t)
	buf := newSyncBuffer()
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	h := newHTTPHarness(t, httpSetup{hooks: hooks, logger: logger, beforeAdmit: gate.hook, opts: HTTPOptions{SessionTimeout: 200 * time.Millisecond}})

	s1 := rawSession(t, h, tokAlice)
	deliverAndDrop(t, h, gate, s1)
	buf.waitFor(t, "agent session idle; closing it")
	assertRefusedBeforeUpstream(t, h, gate, hooks, buf)
}

// TestEvictedSessionOrphanStillBlocks (L1 in the security review of PR
// #121): an agent's session S1 ends a call on a stateful upstream, the agent
// restarts, and its new initialise evicts S1. S2, same principal, is then
// the only session with a call in flight when the upstream sends
// elicitation/create for S1's call. Evicting S1 must not clear its ended
// call: the prompt is refused (errEndedElsewhere) until OrphanTTL, and
// neither human sees it.
func TestEvictedSessionOrphanStillBlocks(t *testing.T) {
	o := newOrphanHooks(t)
	h := newHTTPHarness(t, httpSetup{upstream: v2025, extra: o.tools, opts: HTTPOptions{MaxSessionsPerPrincipal: 1}})
	up := h.proxy.upstreams[testServer]

	s1 := rawSession(t, h, tokAlice) // no GET stream: evictable once idle
	body, hdr := call2025(s1, "netdev-ssh-mcp.late", "")
	if resp, reply := h.do(t, h.request(context.Background(), "POST", tokAlice, hdr, body)); resp.StatusCode != http.StatusOK || !strings.Contains(reply, "late done") {
		t.Fatalf("S1's call: status %d, body %q", resp.StatusCode, clip(reply))
	}
	waitFor(t, "the proxy to record S1's ended call", func() bool {
		n, idle := orphans(up)
		return n == 1 && idle
	})

	prompts := &promptRecorder{answer: "FAKE-alice-yes"}
	s2 := h.connect(t, v2025, tokAlice, prompts.opts()) // the restarted agent
	if st := pingSession(t, h, tokAlice, s1); st != http.StatusNotFound {
		t.Fatalf("S1 answered %d after S2's initialise, want 404 (evicted)", st)
	}
	if n, _ := orphans(up); n != 1 {
		t.Fatalf("%d orphans after the eviction, want S1's one", n)
	}

	type out struct {
		res *mcp.CallToolResult
		err error
	}
	done := make(chan out, 1)
	go func() {
		res, err := s2.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.b_work"})
		done <- out{res, err}
	}()
	recvOrFail(t, o.bStarted, "S2's call to reach the upstream")

	now := time.Now()
	if f, err := attributed(up, now); f != nil || !errors.Is(err, errEndedElsewhere) {
		t.Fatalf("with S1's ended call live: %v, %v; want errEndedElsewhere", f, err)
	}
	if f, err := attributed(up, now.Add(defaultOrphanTTL+time.Second)); f == nil || err != nil {
		t.Fatalf("after OrphanTTL: %v, %v; want S2's call", f, err)
	}

	o.free()
	var ans orphanAnswer
	select {
	case ans = <-o.answer:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream's prompt was not answered or refused")
	}
	if ans.err == nil || !strings.Contains(ans.err.Error(), "ended recently") {
		t.Fatalf("the upstream's prompt for S1's call: %+v, %v; want the orphan refusal", ans.res, ans.err)
	}
	if got := prompts.prompts(); len(got) != 0 {
		t.Fatalf("the restarted agent's human was shown %q, the prompt of its earlier session's call", got)
	}
	o.bRelease <- struct{}{}
	var b out
	select {
	case b = <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("S2's call did not return")
	}
	if b.err != nil || b.res.IsError || !strings.Contains(text(b.res), "has ended recently") {
		t.Fatalf("S2's call: %v %q; want its result with the refusal note", b.err, text(b.res))
	}
}

// TestCapLogPerPrincipal: the session-cap refusal line is rate-limited per
// principal, so one principal's refusals never hide another's, and the next
// line for a principal reports how many were held back.
func TestCapLogPerPrincipal(t *testing.T) {
	hd := &httpHandler{capLog: make(map[string]*capLogState)}
	t0 := time.Unix(1_000_000, 0)
	step := func(principal string, at time.Time, wantLog bool, wantSuppressed int) {
		t.Helper()
		ok, n := hd.capLogAllowLocked(principal, at)
		if ok != wantLog || n != wantSuppressed {
			t.Fatalf("%s at +%s: log %v, suppressed %d; want %v and %d", principal, at.Sub(t0), ok, n, wantLog, wantSuppressed)
		}
	}
	step("alice", t0, true, 0)
	step("alice", t0.Add(capLogInterval/2), false, 0)
	step("alice", t0.Add(capLogInterval/2), false, 0)
	step("bob", t0.Add(capLogInterval/2), true, 0) // alice's limit does not hold bob back
	step("alice", t0.Add(capLogInterval), true, 2)
	step("alice", t0.Add(3*capLogInterval), true, 0)
}

// TestDeleteWindowBoundedByIdleExpiry pins the DELETE residual (N3 in the
// security re-review of PR #121). A call go-sdk has delivered but fathomgate
// has not admitted when the agent DELETEs its session is not cancelled by
// the DELETE (cancelSession has nothing admitted to cancel), and go-sdk's
// Close, which the DELETE runs synchronously, waits for it. The DELETE does
// not pause fathomgate's idle clock, so after SessionTimeout the expiry
// retires the session and cancels the call; the DELETE then completes. The
// bound is SessionTimeout, as for a call whose POST was dropped.
func TestDeleteWindowBoundedByIdleExpiry(t *testing.T) {
	hooks := &blockHooks{blocked: make(chan struct{}, 4), cancelled: make(chan struct{}, 4)}
	gate := newAdmitGate(t)
	buf := newSyncBuffer()
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	const idle = 300 * time.Millisecond
	h := newHTTPHarness(t, httpSetup{hooks: hooks, logger: logger, beforeAdmit: gate.hook, opts: HTTPOptions{SessionTimeout: idle}})

	s1 := rawSession(t, h, tokAlice)
	deliverAndDrop(t, h, gate, s1)

	deleted := make(chan int, 1)
	go func() {
		hdr := map[string]string{"Mcp-Protocol-Version": v2025, "Mcp-Session-Id": s1}
		resp, err := h.raw.Do(h.request(context.Background(), "DELETE", tokAlice, hdr, ""))
		if err != nil {
			deleted <- -1
			return
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		deleted <- resp.StatusCode
	}()
	// The DELETE has passed cancelSession, with nothing admitted to cancel,
	// and is on its way into go-sdk's Close.
	buf.waitFor(t, "agent session DELETE received")

	gate.open() // the call is admitted: the session was never retired
	recvOrFail(t, hooks.blocked, "the call to reach the upstream")
	select {
	case <-hooks.cancelled:
	case <-time.After(idle + 5*time.Second):
		t.Fatal("the call on the deleted session was never cancelled")
	}
	// The idle expiry cancelled it, not the DELETE.
	buf.waitFor(t, "agent session idle; closing it")
	if !strings.Contains(buf.String(), "calls_cancelled=1") {
		t.Fatalf("the idle expiry did not cancel the call:\n%s", buf.String())
	}
	select {
	case st := <-deleted:
		if st != http.StatusNoContent {
			t.Fatalf("DELETE answered %d, want 204 once the call ended", st)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the DELETE did not complete after the call was cancelled")
	}
	// The DELETE and the expiry both closed the session; the retirement is
	// forgotten all the same.
	waitRetiredEmpty(t, h)
}

// TestSessionRetiredText pins the refusal an agent gets for a call on a
// retired session to the text profile-schema 8.5 quotes (N4 in the security
// re-review of PR #121): change the spec and this test together.
func TestSessionRetiredText(t *testing.T) {
	l := newCallLimits(8, 32)
	ss := &mcp.ServerSession{}
	if !l.claimIdle(ss) {
		t.Fatal("a session with no calls could not be claimed")
	}
	_, _, refused, why := l.admit(context.Background(), "alice", ss, "netdev-ssh-mcp.run_show_command")
	if refused == nil || !errors.Is(why, errSessionRetired) {
		t.Fatalf("a call on a retired session was not refused as retired: %v", why)
	}
	const want = "fathomgate refused netdev-ssh-mcp.run_show_command: its agent session has been closed (evicted at the session cap or idle); start a new session and call again"
	if got := text(refused); got != want || !refused.IsError {
		t.Fatalf("refusal %q (isError %v), want %q", got, refused.IsError, want)
	}
}
