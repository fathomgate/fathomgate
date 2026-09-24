// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tests for T0.44 (S2 and S4 in the post-merge security review of T0.40):
// a per-request stateless session's ended call is an ordinary orphan under
// a key of its own, and a principal past its orphan quota overflows into a
// record of its own instead of one shared entry.

// testClock is a clock tests move by hand.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// TestHTTPStatelessOrphanPerRequest: principal alice's stateless requests
// each leave an orphan under a key of their own, attributed to alice, and
// never a shared entry. While one of them may still be running on the
// upstream, bob's stateful prompt is refused, because it truly cannot be
// told apart from a prompt for alice's call, and the log names alice as the
// principal it was refused for. Once alice's orphans expire they are
// reaped and logged with her principal, and bob's next prompt is relayed:
// alice can hold bob's prompts only while her own ended calls are live,
// never past them.
func TestHTTPStatelessOrphanPerRequest(t *testing.T) {
	buf := newSyncBuffer()
	logger := slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	clk := &testClock{now: time.Unix(1_900_000_000, 0)}
	h := newHTTPHarness(t, httpSetup{upstream: v2025, logger: logger, now: clk.Now})
	up := h.proxy.upstreams[testServer]
	ctx := context.Background()

	alice := h.connect(t, v2026, tokAlice, nil)
	for range 2 {
		if _, err := alice.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01"}}); err != nil {
			t.Fatal(err)
		}
	}
	up.mu.Lock()
	keys := make([]string, 0, len(up.orphans))
	for key, o := range up.orphans {
		if o.principal != "alice" || !strings.HasPrefix(key, requestKeyPrefix) {
			t.Errorf("orphan %q of principal %q; want alice's per-request keys only", key, o.principal)
		}
		keys = append(keys, key)
	}
	over := len(up.overflow)
	up.mu.Unlock()
	if len(keys) != 2 || keys[0] == keys[1] || over != 0 {
		t.Fatalf("two stateless requests left orphans %q and %d overflow records; want two distinct keys and none", keys, over)
	}

	// Alice's own 2026-era call to a prompting tool: the orphan rule fires
	// (her earlier requests' records are foreign to this one), but her
	// agent could not be prompted anyway, so the refusal is ADR 0014's.
	// Its one Warn line says that, and names no ended calls (L1 in the
	// security review of PR #82).
	if _, err := alice.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask"}); err == nil || !strings.Contains(err.Error(), "ADR 0014") {
		t.Fatalf("alice's prompt: %v; want the upstream's error quoting the ADR 0014 refusal", err)
	}
	buf.waitFor(t, "ADR 0014")
	if logs := buf.String(); strings.Contains(logs, "ended_calls_of") || !strings.Contains(logs, "in_flight_of=[alice]") {
		t.Fatalf("the ADR 0014 refusal's log line:\n%s\nwant in_flight_of=[alice] and no ended_calls_of", logs)
	}

	var prompts atomic.Int32
	bobOpts := &mcp.ClientOptions{ElicitationHandler: func(context.Context, *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		prompts.Add(1)
		return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"password": agentPassword}}, nil
	}}
	bob := h.connect(t, v2025, tokBob, bobOpts)

	// Within alice's orphan TTL: refused, fail closed.
	res, err := bob.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask"})
	if n := prompts.Load(); n != 0 {
		t.Fatalf("bob's human was shown %d prompts while alice's ended calls were live", n)
	}
	got := fmt.Sprint(err)
	if res != nil {
		got += text(res)
	}
	if !strings.Contains(got, "has ended recently") {
		t.Fatalf("bob's call: %q; want the orphan refusal", got)
	}
	if strings.Contains(got, "alice") {
		t.Fatalf("bob was told the other principal's name: %q", got)
	}
	buf.waitFor(t, "ended_calls_of=[alice]")

	// Past alice's orphan TTL: her orphans are reaped, logged with her
	// principal, and bob's prompt is relayed.
	clk.Add(defaultOrphanTTL)
	res, err = bob.CallTool(ctx, &mcp.CallToolParams{Name: "netdev-ssh-mcp.ask"})
	if err != nil || res.IsError || !strings.Contains(text(res), "pw=accept:"+agentPassword) {
		t.Fatalf("bob's prompt after alice's orphans expired: %v %q", err, text(res))
	}
	if n := prompts.Load(); n != 1 {
		t.Fatalf("bob was shown %d prompts, want 1", n)
	}
	up.mu.Lock()
	for key, o := range up.orphans {
		if o.principal == "alice" {
			t.Errorf("alice's orphan %q outlived its TTL", key)
		}
	}
	up.mu.Unlock()
	reaps := 0
	for line := range strings.SplitSeq(buf.String(), "\n") {
		if strings.Contains(line, "no longer blocks prompt attribution") && strings.Contains(line, "principal=alice") {
			reaps++
		}
	}
	if reaps != 3 {
		t.Fatalf("%d reap lines name alice, want 3 (one per stateless request):\n%s", reaps, buf.String())
	}
}

// TestOrphanQuotaPerPrincipal is the table-full case (T0.44). A principal
// holds at most maxOrphansPerPrincipal keyed records per upstream; past
// that, its further ended calls, a stateful session of its own included,
// go to one overflow record of its own, which fails closed (foreign to
// every call, its own sessions' included), is attributed to it, reaped and
// reported. Another principal is never pushed into overflow by it: bob's
// session keeps its own record, so his own ended call does not block him,
// and he is refused only while alice's ended calls are live.
func TestOrphanQuotaPerPrincipal(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	ttl := time.Minute
	up := &upstream{name: testServer}
	callOn := func(key, principal string) *inflight {
		return up.begin(context.Background(), call{sessionKey: key, tool: "t", principal: principal}, 0)
	}
	endAt := func(f *inflight, at time.Time) bool {
		t.Helper()
		reaped, overflowed := up.end(f, at, at.Add(ttl))
		if len(reaped) != 0 {
			t.Fatalf("%d orphans reaped before any expired", len(reaped))
		}
		return overflowed
	}

	if endAt(callOn("sB", "bob"), t0) {
		t.Fatal("bob's first ended call overflowed")
	}
	for i := range maxOrphansPerPrincipal {
		if endAt(callOn(fmt.Sprintf("%s%d", requestKeyPrefix, i+1), "alice"), t0) {
			t.Fatalf("alice's ended call %d overflowed within her quota", i+1)
		}
	}
	// Alice goes over: reported once, when her overflow record is made.
	if !endAt(callOn(requestKeyPrefix+"over1", "alice"), t0) {
		t.Fatal("alice's first ended call past her quota was not reported")
	}
	if endAt(callOn(requestKeyPrefix+"over2", "alice"), t0.Add(time.Second)) {
		t.Fatal("alice's second ended call past her quota was reported again")
	}
	// A stateful session of alice's own past her quota overflows too.
	if endAt(callOn("sA", "alice"), t0.Add(time.Second)) {
		t.Fatal("alice's session past her quota was reported again")
	}
	// Bob is under his quota whatever alice does: his session keeps its
	// own record, renewed.
	if endAt(callOn("sB", "bob"), t0.Add(ttl/2)) {
		t.Fatal("bob's ended call overflowed because of alice's")
	}
	up.mu.Lock()
	aliceKeyed, bobKeyed := up.orphansOf["alice"], up.orphansOf["bob"]
	ao, aliceOver := up.overflow["alice"]
	_, bobOver := up.overflow["bob"]
	_, sA := up.orphans["sA"]
	sB := up.orphans["sB"]
	up.mu.Unlock()
	switch {
	case aliceKeyed != maxOrphansPerPrincipal || bobKeyed != 1:
		t.Fatalf("keyed records: alice %d, bob %d; want %d and 1", aliceKeyed, bobKeyed, maxOrphansPerPrincipal)
	case !aliceOver || ao.overflow != 3 || !ao.expires.Equal(t0.Add(time.Second+ttl)) || ao.principal != "alice":
		t.Fatalf("alice's overflow record %+v (present %v); want 3 ended calls until t0+1s+ttl", ao, aliceOver)
	case bobOver || sA:
		t.Fatalf("bob overflowed %v, alice's session keyed past her quota %v; want neither", bobOver, sA)
	case !sB.expires.Equal(t0.Add(ttl/2 + ttl)):
		t.Fatalf("bob's record expires %v, want renewed to t0+1.5ttl", sB.expires)
	}

	// Bob, within alice's TTL: truly ambiguous, refused, and the log can
	// name alice (and only alice) as the reason.
	b := callOn("sB", "bob")
	if at := up.attribute(t0.Add(ttl / 2)); !errors.Is(at.err, errEndedElsewhere) || !slices.Equal(at.endedCallsOf, []string{"alice"}) {
		t.Fatalf("bob within alice's TTL: %v, ended calls of %q; want refused for alice's", at.err, at.endedCallsOf)
	}
	// Alice's keyed records have expired; her overflow record still refuses
	// bob's prompts.
	if at := up.attribute(t0.Add(ttl)); !errors.Is(at.err, errEndedElsewhere) || !slices.Equal(at.endedCallsOf, []string{"alice"}) {
		t.Fatalf("bob with only alice's overflow live: %v, ended calls of %q; want refused for alice's", at.err, at.endedCallsOf)
	}
	// Ending bob's call prunes alice's keyed records, each reported with
	// her principal; her overflow record is still live.
	reaped, _ := up.end(b, t0.Add(ttl), time.Time{})
	if len(reaped) != maxOrphansPerPrincipal {
		t.Fatalf("%d records reaped at t0+ttl, want alice's %d keyed ones", len(reaped), maxOrphansPerPrincipal)
	}
	for _, o := range reaped {
		if o.principal != "alice" || o.overflow != 0 {
			t.Fatalf("reaped %+v at t0+ttl; want alice's keyed records only", o)
		}
	}
	// It refuses alice's own session too: fathomgate cannot tell which of her
	// sessions its calls were. Bob's record (live until t0+1.5ttl) refuses
	// her as well, so the exact set is what shows her overflow record
	// counts against her: it fails if attribute skips the caller's own
	// principal's overflow record.
	a := callOn("sA", "alice")
	if at := up.attribute(t0.Add(ttl)); !errors.Is(at.err, errEndedElsewhere) || !slices.Equal(at.endedCallsOf, []string{"alice", "bob"}) {
		t.Fatalf("alice's own session with her overflow live: %v, ended calls of %q; want refused for alice's and bob's", at.err, at.endedCallsOf)
	}
	up.end(a, t0.Add(ttl), time.Time{})
	// Once alice's overflow expires, bob's own live record does not block
	// his own call.
	b = callOn("sB", "bob")
	if f, err := attributed(up, t0.Add(time.Second+ttl)); f != b || err != nil {
		t.Fatalf("bob after alice's overflow expired: %v, %v; want his call", f, err)
	}

	// Pruning (here, when bob's call ends) reaps alice's overflow record,
	// with her principal and the number of ended calls it stood for, and
	// leaves bob's.
	reaped, _ = up.end(b, t0.Add(time.Second+ttl), time.Time{})
	if len(reaped) != 1 || reaped[0].principal != "alice" || reaped[0].overflow != 3 {
		t.Fatalf("reaped %+v; want alice's overflow record of 3 ended calls only", reaped)
	}
	up.mu.Lock()
	defer up.mu.Unlock()
	if _, ok := up.orphansOf["alice"]; ok || len(up.overflow) != 0 || len(up.orphans) != 1 || up.orphansOf["bob"] != 1 {
		t.Fatalf("after pruning: counts %v, %d overflow records, %d orphans; want bob's record only", up.orphansOf, len(up.overflow), len(up.orphans))
	}
}

// TestOrphanQuotaLogged: a principal going over its orphan quota is logged
// at Warn, once, with its principal and the quota; its overflow record is
// logged when it is reaped, with the principal and how many ended calls it
// stood for.
func TestOrphanQuotaLogged(t *testing.T) {
	buf := newSyncBuffer()
	p := &Proxy{logger: slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo}))}
	up := &upstream{name: testServer}
	t0 := time.Unix(1_000_000, 0)
	end := func(principal string, at time.Time) {
		f := up.begin(context.Background(), call{sessionKey: p.requestKey(), tool: "t", principal: principal}, 0)
		p.endCall(up, f, at)
	}
	for range maxOrphansPerPrincipal + 2 {
		end("alice", t0)
	}
	logs := buf.String()
	if n := strings.Count(logs, "exceed its orphan quota"); n != 1 {
		t.Fatalf("%d quota warnings, want 1:\n%s", n, logs)
	}
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, "principal=alice") || !strings.Contains(logs, fmt.Sprintf("quota=%d", maxOrphansPerPrincipal)) {
		t.Fatalf("the quota warning does not name the principal and the quota:\n%s", logs)
	}
	end("bob", t0.Add(defaultOrphanTTL))
	logs = buf.String()
	if !strings.Contains(logs, `orphan quota no longer block prompt attribution on this upstream" server=netdev-ssh-mcp principal=alice calls=2`) {
		t.Fatalf("the overflow reap is not logged with the principal and count:\n%s", logs)
	}
	if n := strings.Count(logs, `an ended call no longer blocks prompt attribution on this upstream" server=netdev-ssh-mcp principal=alice`); n != maxOrphansPerPrincipal {
		t.Fatalf("%d keyed reaps logged for alice, want %d", n, maxOrphansPerPrincipal)
	}
}

// TestEndedCallsOfNamesLocalAgent: the local agent has no principal, so a
// refusal its ended call causes names it "(local)" in the log, a name no
// configured principal can have.
func TestEndedCallsOfNamesLocalAgent(t *testing.T) {
	if validPrincipalName(localPrincipal) == nil {
		t.Fatalf("%q is a valid principal name; the log could not tell it from one", localPrincipal)
	}
	t0 := time.Unix(1_000_000, 0)
	up := &upstream{name: testServer}
	up.end(up.begin(context.Background(), call{sessionKey: localKeyPrefix + "1"}, 0), t0, t0.Add(time.Minute))
	up.begin(context.Background(), call{sessionKey: "sB", principal: "bob"}, 0)
	if at := up.attribute(t0); !errors.Is(at.err, errEndedElsewhere) || !slices.Equal(at.endedCallsOf, []string{localPrincipal}) {
		t.Fatalf("%v, ended calls of %q; want refused for %q", at.err, at.endedCallsOf, localPrincipal)
	}
}

// TestUnattributedRefusalLog (L2 and L4 in the security review of PR #82):
// a prompt refused because more than one call is in flight is logged with
// the principals of those calls (in_flight_of), and the unattributed
// refusal lines are rate-limited per server, class and principal set: one
// line per refusalLogInterval, the next one carrying how many were held
// back.
func TestUnattributedRefusalLog(t *testing.T) {
	buf := newSyncBuffer()
	clk := &testClock{now: time.Unix(1_000_000, 0)}
	p := &Proxy{logger: slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})), now: clk.Now}
	up := &upstream{name: testServer}
	a := up.begin(context.Background(), call{sessionKey: "sA", tool: "t", principal: "alice", agent: agentPeer{version: v2025, canElicit: true}}, 0)
	b := up.begin(context.Background(), call{sessionKey: "sB", tool: "t", principal: "bob"}, 0)
	ask := p.upstreamElicitation(up)
	for range 5 {
		if _, err := ask(context.Background(), &mcp.ElicitRequest{Params: promptFor("pw")}); err == nil {
			t.Fatal("a prompt with two calls in flight was relayed")
		}
	}
	logs := buf.String()
	if n := strings.Count(logs, "fathomgate refused an upstream input request"); n != 1 || !strings.Contains(logs, `in_flight_of="[alice bob]"`) || !strings.Contains(logs, "suppressed=0") {
		t.Fatalf("%d refusal lines within one interval; want 1 with in_flight_of=[alice bob] suppressed=0:\n%s", n, logs)
	}
	clk.Add(refusalLogInterval)
	if _, err := ask(context.Background(), &mcp.ElicitRequest{Params: promptFor("pw")}); err == nil {
		t.Fatal("a prompt with two calls in flight was relayed")
	}
	logs = buf.String()
	if n := strings.Count(logs, "fathomgate refused an upstream input request"); n != 2 || !strings.Contains(logs, "suppressed=4") {
		t.Fatalf("%d refusal lines after the interval; want 2, the second with suppressed=4:\n%s", n, logs)
	}
	// Another principal set is its own line, at once.
	up.end(b, clk.Now(), clk.Now().Add(time.Minute))
	if _, err := ask(context.Background(), &mcp.ElicitRequest{Params: promptFor("pw")}); err == nil {
		t.Fatal("a prompt was relayed while bob's ended call was live")
	}
	if logs := buf.String(); !strings.Contains(logs, "ended_calls_of=[bob]") {
		t.Fatalf("the orphan refusal was held back by the in-flight one's limit:\n%s", logs)
	}
	up.end(a, clk.Now(), time.Time{})
}

// TestRefusalLimiterBounded: the rate limiter keeps at most
// maxRefusalLogKeys entries and making room never holds a line back. The
// stale sweep drops only entries older than the interval, the full clear
// drops the rest, and either way the held-back counts it drops come back
// as lost (L2 in the security re-review of PR #82).
func TestRefusalLimiterBounded(t *testing.T) {
	var l refusalLimiter
	t0 := time.Unix(1_000_000, 0)
	for i := range maxRefusalLogKeys {
		if ok, _, lost := l.allow(strconv.Itoa(i), t0); !ok || lost != 0 {
			t.Fatalf("a new key %d: allowed %v, lost %d", i, ok, lost)
		}
	}
	// Two lines for key 0 are held back.
	for range 2 {
		if ok, _, _ := l.allow("0", t0.Add(time.Second)); ok {
			t.Fatal("a line within the interval was let through")
		}
	}
	// Stale sweep: past the interval every entry is stale, so a new key
	// sweeps them all, reporting key 0's two held-back lines as lost.
	t1 := t0.Add(refusalLogInterval)
	if ok, sup, lost := l.allow("new", t1); !ok || sup != 0 || lost != 2 || len(l.last) != 1 {
		t.Fatalf("stale sweep: allowed %v, suppressed %d, lost %d, %d entries; want true, 0, 2, 1", ok, sup, lost, len(l.last))
	}
	// Refill with fresh entries only: nothing is stale, so a new key clears
	// the table, and "new"'s one held-back line is reported as lost.
	for i := range maxRefusalLogKeys - 1 {
		if ok, _, _ := l.allow("fresh"+strconv.Itoa(i), t1); !ok {
			t.Fatalf("fresh key %d was held back", i)
		}
	}
	if ok, _, _ := l.allow("new", t1.Add(time.Second)); ok {
		t.Fatal("a line within the interval was let through")
	}
	if ok, _, lost := l.allow("another", t1.Add(time.Second)); !ok || lost != 1 || len(l.last) != 1 {
		t.Fatalf("full clear: allowed %v, lost %d, %d entries; want true, 1, 1", ok, lost, len(l.last))
	}
}

// TestAttributedRefusalRateLimited (L1 in the security re-review of
// PR #82): a refusal of a prompt attributed to one call (here, an agent
// that did not declare form elicitation) is rate-limited like the
// unattributed ones, and names the call's principal.
func TestAttributedRefusalRateLimited(t *testing.T) {
	buf := newSyncBuffer()
	clk := &testClock{now: time.Unix(1_000_000, 0)}
	p := &Proxy{logger: slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})), now: clk.Now}
	up := &upstream{name: testServer}
	f := up.begin(context.Background(), call{sessionKey: "sA", tool: "t", principal: "alice", agent: agentPeer{version: v2025}}, 0)
	ask := p.upstreamElicitation(up)
	for range 5 {
		if _, err := ask(context.Background(), &mcp.ElicitRequest{Params: promptFor("pw")}); err == nil {
			t.Fatal("a prompt was relayed to an agent without form elicitation")
		}
	}
	logs := buf.String()
	if n := strings.Count(logs, "fathomgate refused an upstream input request"); n != 1 || !strings.Contains(logs, "attributed=true principal=alice suppressed=0") {
		t.Fatalf("%d attributed refusal lines within one interval; want 1 naming alice:\n%s", n, logs)
	}
	clk.Add(refusalLogInterval)
	if _, err := ask(context.Background(), &mcp.ElicitRequest{Params: promptFor("pw")}); err == nil {
		t.Fatal("a prompt was relayed to an agent without form elicitation")
	}
	if logs := buf.String(); strings.Count(logs, "fathomgate refused an upstream input request") != 2 || !strings.Contains(logs, "suppressed=4") {
		t.Fatalf("after the interval; want a second line with suppressed=4:\n%s", logs)
	}
	up.end(f, clk.Now(), time.Time{})
}

// TestStatelessSessionHasNoID pins what N1 in the security review of
// PR #82 relies on: the session go-sdk's stateless handler gives a
// 2026-era request has no id, so it can never be keyed "s<id>". fathomgate
// also checks the era (agentSessionKey), but a go-sdk bump that gives
// these sessions ids should fail here, loudly.
func TestStatelessSessionHasNoID(t *testing.T) {
	h := newHTTPHarness(t, httpSetup{})
	var mu sync.Mutex
	var ids []string
	h.proxy.server.AddReceivingMiddleware(func(next mcp.MethodHandler) mcp.MethodHandler {
		return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
			if method == "tools/call" {
				mu.Lock()
				ids = append(ids, req.GetSession().ID())
				mu.Unlock()
			}
			return next(ctx, method, req)
		}
	})
	cs := h.connect(t, v2026, tokAlice, nil)
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "netdev-ssh-mcp.run_show_command", Arguments: map[string]any{"host": "lab-sw-01"}}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(ids) != 1 || ids[0] != "" {
		t.Fatalf("stateless tools/call session ids %q, want one empty id", ids)
	}
}
