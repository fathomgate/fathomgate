// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
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

// Regression tests for the security and Go reviews of PR #68 (T0.38) and
// their re-review (T0.40).

// orphanHooks drive the "orphan", "late" and "b_work" tools of a stateful
// upstream that ignores cancellation. "orphan" reports that it started,
// waits for release whatever happens to its request, and then asks for
// input with a server-initiated elicitation/create ("confirm-A"), reporting
// what came back. "late" answers at once and asks for input afterwards, as
// a background job on the upstream does. "b_work" reports that it started
// and returns when bRelease fires or its request is cancelled.
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

// confirmSchema is the requested schema of the upstream's prompts.
var confirmSchema = map[string]any{
	"type":       "object",
	"properties": map[string]any{"confirm": map[string]any{"type": "string"}},
}

func (o *orphanHooks) tools(s *mcp.Server) {
	s.AddTool(&mcp.Tool{Name: "orphan", InputSchema: objectSchema}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		o.started <- struct{}{}
		<-o.release
		// An upstream that ignores notifications/cancelled and asks anyway.
		res, err := req.Session.Elicit(context.WithoutCancel(ctx), &mcp.ElicitParams{
			Message:         orphanPrompt,
			RequestedSchema: confirmSchema,
		})
		o.answer <- orphanAnswer{res, err}
		return textResult("orphan done"), nil
	})
	s.AddTool(&mcp.Tool{Name: "late", InputSchema: objectSchema}, func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// A call that finishes normally and whose upstream keeps working:
		// the prompt follows the result (J1).
		ss := req.Session
		go func() {
			<-o.release
			res, err := ss.Elicit(context.Background(), &mcp.ElicitParams{
				Message:         orphanPrompt,
				RequestedSchema: confirmSchema,
			})
			select {
			case o.answer <- orphanAnswer{res, err}:
			default: // the test has what it needs; do not block a shutdown
			}
		}()
		return textResult("late done"), nil
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

// attributed is the call a prompt may be relayed to at now, or nil and the
// reason it may not be: attribute also returns the sole call in flight when
// the orphan rule refuses it, which only upstreamElicitation needs.
func attributed(up *upstream, now time.Time) (*inflight, error) {
	at := up.attribute(now)
	if at.err != nil {
		return nil, at.err
	}
	return at.sole, nil
}

// orphans is the number of orphan table entries on up, and whether up has
// no call in flight.
func orphans(up *upstream) (n int, idle bool) {
	up.mu.Lock()
	defer up.mu.Unlock()
	return len(up.orphans), len(up.calls) == 0
}

// overflows is the number of overflow records on up: principals whose
// ended calls went past maxOrphansPerPrincipal (T0.44).
func overflows(up *upstream) int {
	up.mu.Lock()
	defer up.mu.Unlock()
	return len(up.overflow)
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
			if !strings.Contains(text(b.res), "another agent session's call on this upstream has ended recently") {
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
		// A stateful agent's session is in the table under its session id,
		// a stateless agent's per-request session under a key of its own
		// (T0.44).
		return idle && n == 1
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
// orphan expires. Orphans are keyed by fathomgate's own key for the agent
// session (J5); a call whose session can never own another call (a
// per-request stateless session) has a key of its own, so its record is an
// ordinary table entry (T0.44). Past maxOrphansPerPrincipal, a principal's
// further ended calls go to that principal's overflow record, which blocks
// every session until it expires and is pruned and reported like any
// record.
func TestOrphanAttribution(t *testing.T) {
	const sA, sB = "sA", "sB"
	t0 := time.Unix(1_000_000, 0)
	ttl := time.Minute
	up := &upstream{name: testServer}
	callOn := func(key string) *inflight {
		return up.begin(context.Background(), call{sessionKey: key, tool: "t", principal: "p"}, 0)
	}

	if f, err := attributed(up, t0); f != nil || err == nil {
		t.Fatal("a prompt with no call in flight was attributed")
	}
	a := callOn(sA)
	up.end(a, t0, t0.Add(ttl)) // sA ends a call
	b := callOn(sB)
	if f, err := attributed(up, t0.Add(ttl/2)); f != nil || !errors.Is(err, errEndedElsewhere) {
		t.Fatalf("sB's call got a prompt while sA's ended call may be running: %v, %v", f, err)
	}
	if f, err := attributed(up, t0.Add(ttl)); f != b || err != nil {
		t.Fatalf("after the orphan expired: %v, %v; want sB's call", f, err)
	}
	up.end(b, t0.Add(ttl), time.Time{})

	// An orphan of the same session does not block that session.
	a = callOn(sA)
	up.end(a, t0, t0.Add(ttl))
	a2 := callOn(sA)
	if f, err := attributed(up, t0.Add(time.Second)); f != a2 || err != nil {
		t.Fatalf("same session: %v, %v", f, err)
	}
	// Two calls in flight are never attributed.
	b = callOn(sB)
	if f, _ := attributed(up, t0.Add(time.Second)); f != nil {
		t.Fatal("a prompt was attributed with two calls in flight")
	}
	up.end(a2, t0, time.Time{})
	up.end(b, t0, time.Time{})

	// A per-request session's ended call is an ordinary table entry under
	// its own key (T0.44): it blocks every other session while it is live,
	// and expires.
	up = &upstream{name: testServer}
	up.end(callOn(requestKeyPrefix+"1"), t0, t0.Add(ttl))
	if n, _ := orphans(up); n != 1 || overflows(up) != 0 {
		t.Fatalf("a per-request session left %d table entries and %d overflow records; want 1 and none", n, overflows(up))
	}
	c := callOn(sA)
	if f, err := attributed(up, t0.Add(ttl/2)); f != nil || !errors.Is(err, errEndedElsewhere) {
		t.Fatalf("a per-request session's ended call did not block: %v, %v", f, err)
	}
	if f, _ := attributed(up, t0.Add(ttl)); f != c {
		t.Fatal("a per-request session's ended call did not expire")
	}
	up.end(c, t0.Add(ttl), time.Time{})

	// Past maxOrphansPerPrincipal, the principal's overflow record stands
	// for its further ended calls and blocks every session until it
	// expires.
	up = &upstream{name: testServer}
	for i := range maxOrphansPerPrincipal + 1 {
		up.end(callOn(fmt.Sprintf("s%d", i)), t0, t0.Add(ttl))
	}
	if n, _ := orphans(up); n != maxOrphansPerPrincipal || overflows(up) != 1 {
		t.Fatalf("%d orphans, %d overflow records; want %d and 1", n, overflows(up), maxOrphansPerPrincipal)
	}
	c = callOn(sA)
	up.mu.Lock()
	clear(up.orphans) // only the overflow record is left
	clear(up.orphansOf)
	up.mu.Unlock()
	if f, _ := attributed(up, t0.Add(time.Second)); f != nil {
		t.Fatal("the overflow record did not block attribution")
	}
	if f, _ := attributed(up, t0.Add(ttl)); f != c {
		t.Fatal("the overflow record did not expire")
	}
	up.end(c, t0.Add(ttl), time.Time{})

	// A full quota of expired orphans, and the expired overflow record
	// past it, are pruned rather than blocking, and every one reaped is
	// reported to the caller, which logs it with its principal (J3, K2).
	// The overflow record is reaped too (S4 in the security review of
	// T0.40: the shared entry it replaces was never reaped or logged).
	up = &upstream{name: testServer}
	for i := range maxOrphansPerPrincipal + 2 {
		if reaped, _ := up.end(callOn(fmt.Sprintf("s%d", i)), t0, t0.Add(ttl)); len(reaped) != 0 {
			t.Fatalf("filling the table reaped %d orphans", len(reaped))
		}
	}
	reaped, overflowed := up.end(callOn(sA), t0.Add(ttl), t0.Add(2*ttl))
	var keyed, over int
	for _, o := range reaped {
		if o.principal != "p" {
			t.Fatalf("reaped %+v; want principal p", o)
		}
		if o.overflow > 0 {
			over++
			if o.overflow != 2 {
				t.Fatalf("the overflow record stood for %d ended calls, want 2", o.overflow)
			}
		} else {
			keyed++
		}
	}
	if keyed != maxOrphansPerPrincipal || over != 1 || overflowed {
		t.Fatalf("reaped %d keyed and %d overflow records, overflowed %v; want %d, 1 and false", keyed, over, overflowed, maxOrphansPerPrincipal)
	}
	up.mu.Lock()
	count := up.orphansOf["p"]
	up.mu.Unlock()
	if n, _ := orphans(up); n != 1 || overflows(up) != 0 || count != 1 {
		t.Fatalf("after pruning: %d orphans (counted %d), %d overflow records; want 1, 1 and none", n, count, overflows(up))
	}
}

// TestAgentSessionKey (J5): the key fathomgate gives an agent session for the
// ended-call records. A session Proxy.Run serves (stdio, in-memory) is
// keyed by the key Run gave it, and two Runs on one proxy get two keys
// (T0.43); a call with no session Run serves and no session id (a
// per-request session of the stateless era over the listener, or no session
// at all) gets a key of its own, tagged requestKeyPrefix, that no other
// call gets (T0.44); a stateful session over the listener is keyed by its
// session id.
func TestAgentSessionKey(t *testing.T) {
	ctx := context.Background()
	stdio := newHarness(t, nil)
	// Each local agent's own call leaves an orphan under its own key: l1
	// for the first Run, l2 for a second one on the same proxy (in-process
	// only; fathomgate serve runs one), never one key for both.
	second, _ := connectAgent(t, stdio.proxy, eraSetup{agent: v2025}, &promptLog{})
	for _, agent := range []*mcp.ClientSession{stdio.agent, second} {
		if _, err := agent.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01"}}); err != nil {
			t.Fatal(err)
		}
	}
	sup := stdio.proxy.upstreams[testServer]
	sup.mu.Lock()
	_, l1 := sup.orphans[localKeyPrefix+"1"]
	_, l2 := sup.orphans[localKeyPrefix+"2"]
	n, over := len(sup.orphans), len(sup.overflow)
	sup.mu.Unlock()
	if !l1 || !l2 || n != 2 || over != 0 {
		t.Errorf("two local agents: l1 %v, l2 %v, %d orphans, %d overflow records; want l1 and l2 only", l1, l2, n, over)
	}
	// No session: a key of its own, never a local agent's key (S5), and
	// never the same key twice, so it is foreign to every later call.
	seen := map[string]bool{}
	fresh := func(where, got string) {
		t.Helper()
		if !strings.HasPrefix(got, requestKeyPrefix) || len(got) == len(requestKeyPrefix) || seen[got] {
			t.Errorf("%s: key %q, want a fresh %q key", where, got, requestKeyPrefix)
		}
		seen[got] = true
	}
	fresh("stdio, no session", stdio.proxy.agentSessionKey(ctx, call{}))
	fresh("stdio, no session again", stdio.proxy.agentSessionKey(ctx, call{}))
	h := newHTTPHarness(t, httpSetup{upstream: v2025})
	seen = map[string]bool{} // keys are unique per proxy, whose upstreams hold them
	for _, principal := range []string{"alice", "alice", ""} {
		// Over the listener a call with no session id gets a key of its
		// own, foreign to every other call, whether or not its principal
		// reached this far.
		fresh("listener, principal "+principal, h.proxy.agentSessionKey(ctx, call{principal: principal}))
	}
	cs := h.connect(t, v2025, tokAlice, nil)
	if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01"}}); err != nil {
		t.Fatal(err)
	}
	up := h.proxy.upstreams[testServer]
	up.mu.Lock()
	defer up.mu.Unlock()
	if len(up.orphans) != 1 {
		t.Fatalf("%d orphans after one call, want 1", len(up.orphans))
	}
	for key := range up.orphans {
		// Tagged, so it can collide with neither a per-request key nor a
		// local agent's key, and never the session itself (J5).
		if key != "s"+cs.ID() || strings.HasPrefix(key, localKeyPrefix) || strings.HasPrefix(key, requestKeyPrefix) {
			t.Fatalf("orphan key %q does not name session %q", key, cs.ID())
		}
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
// so fathomgate's own idle expiry cancels the session's calls and then closes
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

// TestHTTPPromptAfterFinishedCall is J1 in the re-review of PR #72. Alice
// calls "late", which returns normally; the upstream keeps working and
// sends elicitation/create for that finished call afterwards, when bob's
// call is the only one in flight. Before J1 fathomgate remembered only
// cancelled calls, so alice's finished call left nothing behind and bob's
// human was shown alice's prompt. Now every ended call is remembered for
// OrphanTTL, so the prompt is refused: the upstream gets an error, bob sees
// only the note on his result, and neither human is prompted.
func TestHTTPPromptAfterFinishedCall(t *testing.T) {
	o := newOrphanHooks(t)
	h := newHTTPHarness(t, httpSetup{upstream: v2025, extra: o.tools})
	up := h.proxy.upstreams[testServer]
	alicePrompts := &promptRecorder{answer: "FAKE-alice-yes"}
	bobPrompts := &promptRecorder{answer: "FAKE-bob-yes"}
	alice := h.connect(t, v2025, tokAlice, alicePrompts.opts())
	bob := h.connect(t, v2025, tokBob, bobPrompts.opts())

	res, err := alice.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.late"})
	if err != nil || res.IsError || !strings.Contains(text(res), "late done") {
		t.Fatalf("alice's call: %v %q", err, text(res))
	}
	waitFor(t, "the proxy to record the finished call", func() bool {
		n, idle := orphans(up)
		return n == 1 && idle
	})

	type out struct {
		res *mcp.CallToolResult
		err error
	}
	bobDone := make(chan out, 1)
	go func() {
		res, err := bob.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.b_work"})
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
		t.Fatalf("the upstream got an answer to the prompt of a finished call: %+v", ans.res)
	}
	if got := bobPrompts.prompts(); len(got) != 0 {
		t.Fatalf("bob's human was shown %q: another session's prompt", got)
	}
	if got := alicePrompts.prompts(); len(got) != 0 {
		t.Fatalf("alice was shown %q after her call had returned", got)
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
	if !strings.Contains(text(b.res), "another agent session's call on this upstream has ended recently") {
		t.Fatalf("bob's result lacks the refusal note: %q", text(b.res))
	}
	if strings.Contains(text(b.res), orphanPrompt) || strings.Contains(text(b.res), "alice") {
		t.Fatalf("the refusal note quotes the prompt or names the other principal: %q", text(b.res))
	}
}

// TestOrphanTTLSeparateFromIdle is J3: the orphan TTL is its own option
// with its own, much shorter default, so a 30-minute idle session does not
// keep an ended call blocking other sessions' prompts for 30 minutes.
func TestOrphanTTLSeparateFromIdle(t *testing.T) {
	h := newHTTPHarness(t, httpSetup{opts: HTTPOptions{SessionTimeout: time.Hour}})
	if got := h.proxy.orphanTTL(); got != defaultOrphanTTL {
		t.Fatalf("orphan TTL %v with SessionTimeout an hour; want the default %v", got, defaultOrphanTTL)
	}
	if defaultOrphanTTL != 5*time.Minute || defaultOrphanTTL >= defaultSessionTimeout {
		t.Fatalf("the orphan TTL default is %v; want 5 minutes, shorter than the idle timeout %v", defaultOrphanTTL, defaultSessionTimeout)
	}
	// On stdio there is no listener, so the same default applies.
	if got := newHarness(t, nil).proxy.orphanTTL(); got != defaultOrphanTTL {
		t.Fatalf("stdio orphan TTL %v, want %v", got, defaultOrphanTTL)
	}
}

// TestOrphanReapedLogsPrincipal is J3's log: when an ended call stops
// blocking cross-session attribution, fathomgate says so at Info and names
// the principal it was blocking for, never the session id.
func TestOrphanReapedLogsPrincipal(t *testing.T) {
	buf := newSyncBuffer()
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	h := newHTTPHarness(t, httpSetup{logger: logger, opts: HTTPOptions{OrphanTTL: 50 * time.Millisecond}})
	// A stateful agent: its session is in the orphan table, so an entry is
	// reaped by name. A stateless agent's per-request sessions are table
	// entries too (T0.44), reaped and logged the same way
	// (TestHTTPStatelessOrphanPerRequest).
	cs := h.connect(t, v2025, tokAlice, nil)
	ctx := context.Background()
	call := func() {
		t.Helper()
		if _, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01"}}); err != nil {
			t.Fatal(err)
		}
	}
	call()
	time.Sleep(100 * time.Millisecond) // past the orphan TTL
	call()                             // its end prunes the first call's record
	buf.waitFor(t, "no longer blocks prompt attribution")
	logs := buf.String()
	if !strings.Contains(logs, "principal=alice") || !strings.Contains(logs, "server=netdev-ssh-mcp") {
		t.Fatalf("the reap log does not name the principal and the server:\n%s", logs)
	}
}

// TestHTTPSessionRegisteredFromResponseHeader is J2: fathomgate registers the
// session a session-less POST's response names, without asking whether it
// initialised, so no session go-sdk kept is left to go-sdk's longer
// backstop timer alone. A session go-sdk did not keep (a session-less POST
// that is not an initialise) frees its slot again.
func TestHTTPSessionRegisteredFromResponseHeader(t *testing.T) {
	h := newHTTPHarness(t, httpSetup{opts: HTTPOptions{MaxSessions: 1, MaxSessionsPerPrincipal: 1}})
	ctx := context.Background()
	hd := h.hh

	// A session-less POST that is not an initialise: go-sdk answers it on a
	// session whose id the response carries and then closes it, so fathomgate
	// keeps nothing and frees the slot.
	ping := `{"jsonrpc":"2.0","id":1,"method":"ping"}`
	hdr := map[string]string{"Mcp-Protocol-Version": v2025}
	if resp, body := h.do(t, h.request(ctx, "POST", tokAlice, hdr, ping)); resp.StatusCode != 200 {
		t.Fatalf("session-less ping: status %d, body %q", resp.StatusCode, clip(body))
	}
	waitFor(t, "the slot of a session go-sdk did not keep to be freed", func() bool {
		hd.mu.Lock()
		defer hd.mu.Unlock()
		return hd.sessions == 0 && len(hd.live) == 0
	})

	// An initialise: the response names the session, go-sdk keeps it, and
	// fathomgate registers it under that id with its own idle clock.
	cs := h.connect(t, v2025, tokAlice, nil)
	hd.mu.Lock()
	ls := hd.live[cs.ID()]
	sessions := hd.sessions
	hd.mu.Unlock()
	if ls == nil || sessions != 1 {
		t.Fatalf("live entry %v, %d sessions; want the session registered", ls, sessions)
	}
	if ls.principal != "alice" {
		t.Fatalf("live session principal %q, want alice", ls.principal)
	}
	ls.mu.Lock()
	armed := ls.timer != nil && !ls.stopped
	ls.mu.Unlock()
	if !armed {
		t.Fatal("the registered session has no idle clock")
	}
}
