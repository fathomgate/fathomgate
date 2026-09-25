// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"
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

// openGET opens a GET stream on sid and waits until the listener counts
// it. The stream closes when the test ends.
func openGET(t *testing.T, h *httpHarness, token []byte, sid string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		<-done
	})
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
		time.Sleep(20 * time.Millisecond)
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
		early:                make(map[earlyPOST]int),
		earlyGets:            make(map[earlyPOST]int),
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
	if hd.sessions != 0 {
		t.Fatalf("a second release changed the count to %d", hd.sessions)
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
		early:     make(map[earlyPOST]int),
		earlyGets: make(map[earlyPOST]int),
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
	if _, idle := ls.idleSince(); idle {
		t.Fatal("a session with a GET stream opened before registration reads as idle")
	}
	endAlice()
	if _, idle := ls.idleSince(); !idle {
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
