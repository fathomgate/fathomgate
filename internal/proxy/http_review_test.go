package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Regression tests for the security and Go reviews of PR #68 (T0.38).

// orphanHooks drive the "orphan" and "b_work" tools of a stateful upstream
// that ignores cancellation. "orphan" reports that it started, waits for
// release whatever happens to its request, and then asks for input with a
// server-initiated elicitation/create ("confirm-A"), reporting what came
// back. "b_work" reports that it started and returns when bRelease fires or
// its request is cancelled.
type orphanHooks struct {
	started  chan struct{}
	release  chan struct{}
	answer   chan orphanAnswer
	bStarted chan struct{}
	bRelease chan struct{}
	once     sync.Once
}

type orphanAnswer struct {
	res *mcp.ElicitResult
	err error
}

func newOrphanHooks(t *testing.T) *orphanHooks {
	o := &orphanHooks{
		started:  make(chan struct{}, 1),
		release:  make(chan struct{}),
		answer:   make(chan orphanAnswer, 1),
		bStarted: make(chan struct{}, 1),
		bRelease: make(chan struct{}, 1),
	}
	// Registered before the harness, so it runs after the proxy has closed:
	// no upstream handler is left waiting (the leak check).
	t.Cleanup(o.free)
	return o
}

// free lets the orphan go, once.
func (o *orphanHooks) free() { o.once.Do(func() { close(o.release) }) }

const orphanPrompt = "confirm-A"

func (o *orphanHooks) tools(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "orphan", InputSchema: objectSchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		o.started <- struct{}{}
		<-o.release
		// An upstream that ignores notifications/cancelled and asks anyway.
		res, err := req.Session.Elicit(context.WithoutCancel(ctx), &mcp.ElicitParams{
			Message: orphanPrompt,
			RequestedSchema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"confirm": map[string]any{"type": "string"}},
			},
		})
		o.answer <- orphanAnswer{res, err}
		return textResult("orphan done"), nil
	})
	s.AddTool(&mcp.Tool{Name: "b_work", InputSchema: objectSchema}, func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		o.bStarted <- struct{}{}
		select {
		case <-o.bRelease:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return textResult("b done"), nil
	})
}

// promptRecorder is an agent's elicitation handler: it records every prompt
// and accepts with answer.
type promptRecorder struct {
	answer string
	mu     sync.Mutex
	seen   []string
}

func (r *promptRecorder) opts() *mcp.ClientOptions {
	return &mcp.ClientOptions{ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		r.mu.Lock()
		r.seen = append(r.seen, req.Params.Message)
		r.mu.Unlock()
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"confirm": r.answer}}, nil
	}}
}

func (r *promptRecorder) prompts() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

// orphans is the number of live orphans on up, and whether up has no call
// in flight.
func orphans(up *upstream) (n int, idle bool) {
	up.mu.Lock()
	defer up.mu.Unlock()
	return len(up.orphans), len(up.calls) == 0
}

// TestHTTPAbandonedCallPrompt is the proof of concept of H1 in the security
// review of PR #68, kept as a regression test. Principal alice calls
// "orphan" on a stateful upstream and cancels it; the upstream ignores the
// cancellation and later sends elicitation/create "confirm-A". By then
// bob's "b_work" is the only call in flight on the upstream. Before the
// fix, the prompt went to bob's human, and bob's answer went back to the
// upstream as the answer to alice's prompt (a confused deputy, MCP03). Now
// alice's session is remembered as having abandoned a call, the prompt is
// refused (the upstream gets an error), bob sees nothing but the refusal
// note on his result, and alice sees nothing. Alice is a stateful and a
// stateless agent in turn; bob is stateful (only a stateful agent can be
// shown a stateful upstream's prompt at all).
func TestHTTPAbandonedCallPrompt(t *testing.T) {
	for _, aliceEra := range []string{v2025, v2026} {
		t.Run("alice "+aliceEra, func(t *testing.T) {
			o := newOrphanHooks(t)
			h := newHTTPHarness(t, httpSetup{upstream: v2025, extra: o.tools})
			up := h.proxy.upstreams[testServer]
			alicePrompts := &promptRecorder{answer: "FAKE-alice-yes"}
			bobPrompts := &promptRecorder{answer: "FAKE-bob-yes"}
			alice := h.connect(t, aliceEra, tokAlice, alicePrompts.opts())
			bob := h.connect(t, v2025, tokBob, bobPrompts.opts())

			abandonCall(t, alice, o, up)

			bobCtx, cancelBob := context.WithCancel(context.Background())
			defer cancelBob()
			type out struct {
				res *mcp.CallToolResult
				err error
			}
			bobDone := make(chan out, 1)
			go func() {
				res, err := bob.CallTool(bobCtx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.b_work"})
				bobDone <- out{res, err}
			}()
			recvOrFail(t, o.bStarted, "bob's call to reach the upstream")

			o.free()
			var ans orphanAnswer
			select {
			case ans = <-o.answer:
			case <-time.After(5 * time.Second):
				t.Fatal("the upstream's prompt was not answered or refused")
			}
			if ans.err == nil {
				t.Fatalf("the upstream got an answer to alice's prompt: %+v", ans.res)
			}
			if got := bobPrompts.prompts(); len(got) != 0 {
				t.Fatalf("bob's human was shown %q: another session's prompt", got)
			}
			o.bRelease <- struct{}{}
			var b out
			select {
			case b = <-bobDone:
			case <-time.After(5 * time.Second):
				t.Fatal("bob's call did not return")
			}
			if b.err != nil || b.res.IsError || !strings.Contains(text(b.res), "b done") {
				t.Fatalf("bob's call: %v %q", b.err, text(b.res))
			}
			if !strings.Contains(text(b.res), "a call another agent session abandoned may still be running") {
				t.Fatalf("bob's result lacks the refusal note: %q", text(b.res))
			}
			if strings.Contains(text(b.res), orphanPrompt) || strings.Contains(text(b.res), "alice") {
				t.Fatalf("the refusal note quotes the prompt or names the other principal: %q", text(b.res))
			}
			if got := alicePrompts.prompts(); len(got) != 0 {
				t.Fatalf("alice was shown %q after abandoning the call", got)
			}
		})
	}
}

// TestHTTPAbandonedCallPromptSameSession: the orphan rule refuses only
// across agent sessions. When the call in flight belongs to the session
// that abandoned the earlier one, the prompt is relayed to it, labelled
// with its origin, as before.
func TestHTTPAbandonedCallPromptSameSession(t *testing.T) {
	o := newOrphanHooks(t)
	h := newHTTPHarness(t, httpSetup{upstream: v2025, extra: o.tools})
	up := h.proxy.upstreams[testServer]
	prompts := &promptRecorder{answer: "FAKE-alice-yes"}
	alice := h.connect(t, v2025, tokAlice, prompts.opts())

	abandonCall(t, alice, o, up)
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		res, _ := alice.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.b_work"})
		done <- res
	}()
	recvOrFail(t, o.bStarted, "alice's second call to reach the upstream")
	o.free()
	var ans orphanAnswer
	select {
	case ans = <-o.answer:
	case <-time.After(5 * time.Second):
		t.Fatal("the upstream's prompt was not answered")
	}
	if ans.err != nil || ans.res.Action != "accept" || ans.res.Content["confirm"] != "FAKE-alice-yes" {
		t.Fatalf("upstream got %+v, %v; want alice's accept", ans.res, ans.err)
	}
	if got := prompts.prompts(); len(got) != 1 || got[0] != "[from netdev-ssh-mcp] "+orphanPrompt {
		t.Fatalf("alice was shown %q", got)
	}
	o.bRelease <- struct{}{}
	select {
	case res := <-done:
		if res == nil || res.IsError {
			t.Fatalf("alice's second call: %q", text(res))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("alice's second call did not return")
	}
}

// abandonCall has agent call "orphan" and cancel it once it has reached the
// upstream, then waits until the proxy has ended the call and recorded the
// agent's session as having abandoned it.
func abandonCall(t *testing.T, agent *mcp.ClientSession, o *orphanHooks, up *upstream) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.orphan"})
		done <- err
	}()
	recvOrFail(t, o.started, "the orphan call to reach the upstream")
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled call did not return to the agent")
	}
	waitFor(t, "the proxy to record the abandoned call", func() bool {
		n, idle := orphans(up)
		return n == 1 && idle
	})
}

func recvOrFail(t *testing.T, c <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// TestOrphanAttribution: the attribution rule on its own, with a fixed
// clock. A prompt is attributed only to the sole call in flight, and only
// while every live orphan on the upstream is that call's session's; an
// orphan expires, and past maxOrphans one overflow entry blocks every
// session until it expires.
func TestOrphanAttribution(t *testing.T) {
	sA, sB := &mcp.ServerSession{}, &mcp.ServerSession{}
	t0 := time.Unix(1_000_000, 0)
	ttl := time.Minute
	up := &upstream{name: testServer}
	callOn := func(ss *mcp.ServerSession) *inflight {
		return up.begin(context.Background(), call{agent: agentPeer{session: ss}, tool: "t", principal: "p"}, 0)
	}

	if f, err := up.attribute(t0); f != nil || err == nil {
		t.Fatal("a prompt with no call in flight was attributed")
	}
	a := callOn(sA)
	up.end(a, t0, t0.Add(ttl)) // sA abandons a call
	b := callOn(sB)
	if f, err := up.attribute(t0.Add(ttl / 2)); f != nil || !errors.Is(err, errAbandonedElsewhere) {
		t.Fatalf("sB's call got a prompt while sA's abandoned call may be running: %v, %v", f, err)
	}
	if f, err := up.attribute(t0.Add(ttl)); f != b || err != nil {
		t.Fatalf("after the orphan expired: %v, %v; want sB's call", f, err)
	}
	up.end(b, t0.Add(ttl), time.Time{})

	// An orphan of the same session does not block that session.
	a = callOn(sA)
	up.end(a, t0, t0.Add(ttl))
	a2 := callOn(sA)
	if f, err := up.attribute(t0.Add(time.Second)); f != a2 || err != nil {
		t.Fatalf("same session: %v, %v", f, err)
	}
	// Two calls in flight are never attributed.
	b = callOn(sB)
	if f, _ := up.attribute(t0.Add(time.Second)); f != nil {
		t.Fatal("a prompt was attributed with two calls in flight")
	}
	up.end(a2, t0, time.Time{})
	up.end(b, t0, time.Time{})

	// Past maxOrphans, the overflow entry stands for every other session.
	up = &upstream{name: testServer}
	for range maxOrphans + 1 {
		f := callOn(&mcp.ServerSession{})
		up.end(f, t0, t0.Add(ttl))
	}
	if n, _ := orphans(up); n != maxOrphans || !up.orphanOverflow.Equal(t0.Add(ttl)) {
		t.Fatalf("%d orphans, overflow until %v", n, up.orphanOverflow)
	}
	c := callOn(sA)
	up.mu.Lock()
	clear(up.orphans) // only the overflow entry is left
	up.mu.Unlock()
	if f, _ := up.attribute(t0.Add(time.Second)); f != nil {
		t.Fatal("the overflow entry did not block attribution")
	}
	if f, _ := up.attribute(t0.Add(ttl)); f != c {
		t.Fatal("the overflow entry did not expire")
	}
	// A full table of expired orphans is pruned rather than overflowing.
	up = &upstream{name: testServer}
	for range maxOrphans {
		up.end(callOn(&mcp.ServerSession{}), t0, t0.Add(ttl))
	}
	up.end(callOn(sA), t0.Add(ttl), t0.Add(2*ttl))
	if n, _ := orphans(up); n != 1 || !up.orphanOverflow.IsZero() {
		t.Fatalf("after pruning: %d orphans, overflow %v; want 1 and none", n, up.orphanOverflow)
	}
}

// TestHTTPSessionsPerPrincipal (H2): one principal cannot take every
// stateful session slot; the next initialise gets 503 naming the
// per-principal cap while another principal still gets a session.
func TestHTTPSessionsPerPrincipal(t *testing.T) {
	h := newHTTPHarness(t, httpSetup{opts: HTTPOptions{MaxSessions: 3, MaxSessionsPerPrincipal: 2}})
	ctx := context.Background()
	h.connect(t, v2025, tokAlice, nil)
	h.connect(t, v2025, tokAlice, nil)
	resp, body := h.do(t, h.request(ctx, "POST", tokAlice, nil, initialize2025))
	if resp.StatusCode != 503 || resp.Header.Get("Retry-After") != "1" || !strings.Contains(body, "for this principal") {
		t.Fatalf("alice's third initialise: status %d, Retry-After %q, body %q", resp.StatusCode, resp.Header.Get("Retry-After"), body)
	}
	h.connect(t, v2025, tokBob, nil)
	resp, body = h.do(t, h.request(ctx, "POST", tokCarol, nil, initialize2025))
	if resp.StatusCode != 503 || strings.Contains(body, "for this principal") {
		t.Fatalf("carol with every slot taken: status %d, body %q; want the overall cap", resp.StatusCode, body)
	}
}

// TestHTTPIdleExpiryCancelsStuckCall (H2): a 2025-era call whose POST was
// dropped keeps running upstream. go-sdk's idle Close waits for it forever,
// so netguard's own idle expiry cancels the session's calls and then closes
// the session, which frees its slot.
func TestHTTPIdleExpiryCancelsStuckCall(t *testing.T) {
	hooks := &blockHooks{blocked: make(chan struct{}, 4), cancelled: make(chan struct{}, 4)}
	const idle = 300 * time.Millisecond
	h := newHTTPHarness(t, httpSetup{hooks: hooks, opts: HTTPOptions{SessionTimeout: idle, MaxSessions: 1}})
	cs := h.connect(t, v2025, tokAlice, nil)

	ctx, drop := context.WithCancel(context.Background())
	body, hdr := call2025(cs.ID(), "netdev-ssh-mcp.block", "")
	posted := make(chan struct{})
	go func() {
		defer close(posted)
		if resp, err := h.raw.Do(h.request(ctx, "POST", tokAlice, hdr, body)); err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()
	recvOrFail(t, hooks.blocked, "the call to reach the upstream")
	drop()
	<-posted
	if n := h.proxy.limits.Load().inFlight(); n != 1 {
		t.Fatalf("%d calls in flight after the POST dropped, want 1 (go-sdk detaches it)", n)
	}
	select {
	case <-hooks.cancelled:
	case <-time.After(idle + 5*time.Second):
		t.Fatal("the idle session's stuck call was never cancelled")
	}
	waitFor(t, "the expired session's slot to free up", func() bool {
		resp, _ := h.do(t, h.request(context.Background(), "POST", tokBob, nil, initialize2025))
		return resp.StatusCode == 200
	})
}

// TestHTTPIdleExpiryWaitsForOpenPOST: a POST in progress stops the idle
// clock, so a call longer than SessionTimeout whose POST is still open is
// not cancelled.
func TestHTTPIdleExpiryWaitsForOpenPOST(t *testing.T) {
	hooks := &blockHooks{blocked: make(chan struct{}, 4), cancelled: make(chan struct{}, 4)}
	const idle = 200 * time.Millisecond
	h := newHTTPHarness(t, httpSetup{hooks: hooks, opts: HTTPOptions{SessionTimeout: idle}})
	cs := h.connect(t, v2025, tokAlice, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.block"})
		done <- err
	}()
	recvOrFail(t, hooks.blocked, "the call to reach the upstream")
	// A negative check: three idle periods with the POST open. Nothing
	// positive marks "the timer did not fire", so the window is sized from
	// the timeout under test.
	select {
	case <-hooks.cancelled:
		t.Fatal("a call whose POST is open was cancelled at the idle timeout")
	case <-time.After(3 * idle):
	}
	cancel()
	recvOrFail(t, hooks.cancelled, "the agent's own cancellation")
	<-done
}

// TestHTTPRefusalsCloseConnection (H3): every refusal (401, 403, 404, 413,
// 503) carries Connection: close and the server closes the connection, so a
// refused client holds none of the listener's connection slots. A success
// keeps the connection alive.
func TestHTTPRefusalsCloseConnection(t *testing.T) {
	h := newHTTPHarness(t, httpSetup{opts: HTTPOptions{MaxSessions: 1}})
	ctx := context.Background()
	h.connect(t, v2025, tokAlice, nil) // takes the only session slot
	ping, pingHdr := ping2026()
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"pad":"` + strings.Repeat("x", maxRequestBodyBytes) + `"}}`
	cases := []struct {
		name   string
		path   string
		token  []byte
		hdr    map[string]string
		body   string
		status int
	}{
		{"401 no token", "", nil, pingHdr, ping, 401},
		{"403 Origin", "", tokAlice, map[string]string{"Origin": "http://evil.example", "Mcp-Protocol-Version": v2026, "Mcp-Method": "tools/list"}, ping, 403},
		{"403 Host", "", nil, map[string]string{"Host": "evil.example", "Mcp-Protocol-Version": v2026, "Mcp-Method": "tools/list"}, ping, 403},
		{"404 path", "/other", nil, pingHdr, ping, 404},
		{"413 body", "", tokAlice, pingHdr, big, 413},
		{"503 session cap", "", tokBob, nil, initialize2025, 503},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := h.request(ctx, "POST", c.token, c.hdr, c.body)
			if c.path != "" {
				req.URL.Path = c.path
			}
			status, closing := doClose(t, h, req)
			if status != c.status || !closing {
				t.Fatalf("status %d, Connection: close %v; want %d and close", status, closing, c.status)
			}
		})
	}
	t.Run("200 stays open", func(t *testing.T) {
		if status, closing := doClose(t, h, h.request(ctx, "POST", tokAlice, pingHdr, ping)); status != 200 || closing {
			t.Fatalf("status %d, Connection: close %v", status, closing)
		}
	})
	// The server really closes: on a raw connection, the 401 is followed by
	// EOF, not by an idle keep-alive connection.
	t.Run("server closes", func(t *testing.T) {
		conn, err := net.Dial("tcp", strings.TrimPrefix(h.srv.URL, "http://"))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		if err := h.request(ctx, "GET", nil, nil, "").Write(conn); err != nil {
			t.Fatal(err)
		}
		br := bufio.NewReader(conn)
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 401 {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if _, err := br.ReadByte(); !errors.Is(err, io.EOF) {
			t.Fatalf("after the 401 the connection stayed open (read: %v)", err)
		}
	})
}

// doClose sends req and reports the status and whether the response told
// the client to close the connection (net/http's client folds a
// Connection: close header into Response.Close).
func doClose(t *testing.T, h *httpHarness, req *http.Request) (int, bool) {
	t.Helper()
	resp, err := h.raw.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Close
}

// addSlow adds "slow", which returns after d.
func addSlow(d time.Duration) func(*mcp.Server) {
	return func(s *mcp.Server) {
		s.AddTool(&mcp.Tool{Name: "slow", InputSchema: objectSchema}, func(ctx context.Context, _ *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			select {
			case <-time.After(d):
				return textResult("slow done"), nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		})
	}
}

// TestHTTPKeepAliveDeadlines: the per-request deadlines do not leak across
// requests on one keep-alive connection.
//   - A call longer than BodyReadTimeout succeeds, and so does the next
//     request on the same connection: the body read deadline is cleared
//     once the body is read, before net/http's background read, which would
//     otherwise hit it and cancel the request. net/http 1.26 and later also
//     clear the read deadline when they start that read, so this pins the
//     behaviour end to end (a server-wide ReadTimeout, or a deadline re-armed
//     after the body, fails it), not deadlineBody's own clear.
//   - H4: a write deadline left on the connection (finish arms one for
//     net/http's final flush) is cleared when the next request starts, so
//     a write net/http makes on its own before the handler writes (here the
//     100 Continue answer to Expect: 100-continue) cannot fail on it.
//     net/http 1.26 and later also clear it after each response, so the
//     test plants an expired deadline on the idle connection itself: only
//     the handler's clear saves the request.
func TestHTTPKeepAliveDeadlines(t *testing.T) {
	const bodyRead, write = 150 * time.Millisecond, 150 * time.Millisecond
	h := newHTTPHarness(t, httpSetup{extra: addSlow(3 * bodyRead), opts: HTTPOptions{BodyReadTimeout: bodyRead, WriteTimeout: write}})
	tr := &http.Transport{MaxConnsPerHost: 1, ExpectContinueTimeout: 5 * time.Second}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr}
	var local string // the client address of the connection last used
	send := func(what, body string, hdr map[string]string, expect bool, want string) (reused bool) {
		t.Helper()
		req := h.request(context.Background(), "POST", tokAlice, hdr, body)
		if expect {
			req.Header.Set("Expect", "100-continue")
		}
		req = req.WithContext(httptrace.WithClientTrace(req.Context(), &httptrace.ClientTrace{
			GotConn: func(i httptrace.GotConnInfo) { reused, local = i.Reused, i.Conn.LocalAddr().String() },
		}))
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != 200 || strings.Contains(string(b), `"isError":true`) || !strings.Contains(string(b), want) {
			t.Fatalf("%s: status %d, body %q", what, resp.StatusCode, clip(string(b)))
		}
		return reused
	}
	body, hdr := call2026("netdev-ssh-mcp.slow", "")
	send("a call longer than BodyReadTimeout", body, hdr, false, "slow done")
	ping, pingHdr := ping2026()
	if !send("the next request on the connection", ping, pingHdr, false, "netdev-ssh-mcp.slow") {
		t.Fatal("the connection was not reused")
	}
	gc := h.lst.conn(local)
	if gc == nil {
		t.Fatal("the server side of the connection is not known")
	}
	if err := gc.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if !send("an Expect: 100-continue request with a stale write deadline", ping, pingHdr, true, "netdev-ssh-mcp.slow") {
		t.Fatal("the connection was not reused")
	}
}

// TestHTTPCloseJoinsSessionWatchers (G5): Proxy.Close waits for the
// goroutine that watches each stateful session, so its last log line is
// written before Close returns. A session that opens after Close began is
// closed at once and its slot released.
func TestHTTPCloseJoinsSessionWatchers(t *testing.T) {
	buf := newSyncBuffer()
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	h := newHTTPHarness(t, httpSetup{logger: logger})
	h.connect(t, v2025, tokAlice, nil)
	buf.waitFor(t, "agent session opened")
	if err := h.proxy.Close(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "agent session closed") {
		t.Fatalf("Close returned before the session watcher finished:\n%s", buf.String())
	}
}

// TestHTTPSessionAfterClose (G5): once the call limits are closed, a new
// stateful session is closed as soon as go-sdk creates it, no watcher is
// started, and its slot is released.
func TestHTTPSessionAfterClose(t *testing.T) {
	h := newHTTPHarness(t, httpSetup{opts: HTTPOptions{MaxSessions: 1}})
	h.proxy.limits.Load().close()
	ctx := context.Background()
	for range 2 {
		resp, _ := h.do(t, h.request(ctx, "POST", tokAlice, nil, initialize2025))
		if resp.StatusCode != 200 {
			t.Fatalf("initialise while closing: status %d", resp.StatusCode)
		}
		sid := resp.Header.Get("Mcp-Session-Id")
		body, hdr := call2025(sid, "netdev-ssh-mcp.run_show_command", "")
		if resp, _ := h.do(t, h.request(ctx, "POST", tokAlice, hdr, body)); resp.StatusCode != 404 {
			t.Fatalf("the session opened while closing is still there: status %d", resp.StatusCode)
		}
	}
}
