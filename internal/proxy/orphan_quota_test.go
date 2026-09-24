package proxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
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
	if len(keys) != 2 || over != 0 {
		t.Fatalf("two stateless requests left orphans %q and %d overflow records; want two distinct keys and none", keys, over)
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
	buf.waitFor(t, "blocked_by=[alice]")

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
	if reaps != 2 {
		t.Fatalf("%d reap lines name alice, want 2 (one per stateless request):\n%s", reaps, buf.String())
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
	if at := up.attribute(t0.Add(ttl / 2)); !errors.Is(at.err, errEndedElsewhere) || !slices.Equal(at.blockedBy, []string{"alice"}) {
		t.Fatalf("bob within alice's TTL: %v, blocked by %q; want refused, blocked by alice", at.err, at.blockedBy)
	}
	// Alice's keyed records have expired; her overflow record still blocks
	// bob, and blocks alice's own session too (it cannot tell which of her
	// sessions its calls were).
	if at := up.attribute(t0.Add(ttl)); !errors.Is(at.err, errEndedElsewhere) || !slices.Equal(at.blockedBy, []string{"alice"}) {
		t.Fatalf("bob with only alice's overflow live: %v, blocked by %q; want refused, blocked by alice", at.err, at.blockedBy)
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
	a := callOn("sA", "alice")
	if at := up.attribute(t0.Add(ttl)); !errors.Is(at.err, errEndedElsewhere) {
		t.Fatalf("alice's own session with her overflow live: %v; want refused", at.err)
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

// TestBlockedByNamesLocalAgent: the local agent has no principal, so a
// refusal its ended call causes names it "(local)" in the log, a name no
// configured principal can have.
func TestBlockedByNamesLocalAgent(t *testing.T) {
	if validPrincipalName(localPrincipal) == nil {
		t.Fatalf("%q is a valid principal name; the log could not tell it from one", localPrincipal)
	}
	t0 := time.Unix(1_000_000, 0)
	up := &upstream{name: testServer}
	up.end(up.begin(context.Background(), call{sessionKey: localKeyPrefix + "1"}, 0), t0, t0.Add(time.Minute))
	up.begin(context.Background(), call{sessionKey: "sB", principal: "bob"}, 0)
	if at := up.attribute(t0); !errors.Is(at.err, errEndedElsewhere) || !slices.Equal(at.blockedBy, []string{localPrincipal}) {
		t.Fatalf("%v, blocked by %q; want refused, blocked by %q", at.err, at.blockedBy, localPrincipal)
	}
}
