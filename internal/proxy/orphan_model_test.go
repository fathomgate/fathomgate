package proxy

import (
	"context"
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"
	"time"
)

// TestOrphanModelNeverFailsOpen is the security reviewer's randomised
// reference-model check from the review of PR #82 (T0.44), strengthened in
// its re-review (M1). Random begins, ends and clock steps drive
// upstream.end and upstream.attribute; an oracle remembers every ended
// call on its own, with no quota and no overflow.
//
// After every step, attribute may relay a prompt only when the oracle
// would (one call in flight and no live ended call of another session),
// and only to that call. endedCallsOf must name every principal the oracle
// refuses for, and only principals with a live ended call. netguard may
// refuse where the oracle would not only through a LIVE overflow record of
// the caller's principal, which stands for that principal's ended calls
// whatever their session.
//
// The re-review found the first version almost never reached a state in
// which a prompt could be relayed: the TTL kept some foreign record live
// nearly always. So the model now has three more operations. A flood has
// principal "a" (a busy stateless agent) end more calls at once than its
// quota, so its overflow record is made again and again. A quiet phase
// ends every call in flight, one second apart and "a"'s last, then moves
// the clock by about the TTL, so some records expire and others do not; a
// jump of ttl-3s leaves only the last few ends live, which is how a live
// overflow record comes to be the only thing refusing a prompt. And a
// probe runs whenever nothing is in flight: it begins one call (a fixed
// session's key or a fresh one), checks attribute, and ends the call
// without leaving a record. Every seed must reach enough relays and enough
// probes under a live overflow record, and the seeds together enough
// probes that a live overflow record alone decides. The T0.44 handoff
// records the two mutants this catches.
func TestOrphanModelNeverFailsOpen(t *testing.T) {
	type endedCall struct {
		key, principal string
		expires        time.Time
	}
	fixed := []struct{ key, principal string }{{"l1", ""}, {"sA1", "a"}, {"sA2", "a"}, {"sB1", "b"}}
	const seeds, steps = 16, 3000
	const minAllow, minOverflows, minOverflowProbes, minOverflowDecides = 20, 3, 10, 16
	totalDecides := 0
	for seed := uint64(1); seed <= seeds; seed++ {
		rng := rand.New(rand.NewPCG(seed, seed*7))
		up := &upstream{name: testServer}
		ttl := 90 * time.Minute
		now := time.Unix(1_000_000, 0)
		var ended []endedCall
		var live []*inflight
		rk, overflows := 0, 0
		allows, overflowProbes, overflowDecides := 0, 0, 0

		begin := func(fresh bool) *inflight {
			var k, pr string
			if !fresh {
				x := fixed[rng.IntN(len(fixed))]
				k, pr = x.key, x.principal
			} else {
				rk++
				k = requestKeyPrefix + strconv.Itoa(rk)
				pr = []string{"", "a", "b"}[rng.IntN(3)]
				if rng.IntN(4) != 0 {
					pr = "a"
				}
			}
			return up.begin(context.Background(), call{sessionKey: k, principal: pr, tool: "t"}, 0)
		}
		endAt := func(i int) {
			f := live[i]
			live = slices.Delete(live, i, i+1)
			if _, of := up.end(f, now, now.Add(ttl)); of {
				overflows++
			}
			ended = append(ended, endedCall{f.sessionKey, f.principal, now.Add(ttl)})
		}
		// check compares attribute with the oracle at now and reports
		// whether the oracle relays, whether a live overflow record exists,
		// and whether a live overflow record alone makes the oracle's
		// refusal hold for netguard (no live foreign keyed record).
		check := func(step int) (allow, overflowLive, overflowDecides bool) {
			t.Helper()
			ended = slices.DeleteFunc(ended, func(e endedCall) bool { return !now.Before(e.expires) })
			at := up.attribute(now)
			var want []string
			allow = len(live) == 1
			if allow {
				for _, e := range ended {
					if e.key != live[0].sessionKey {
						allow = false
						if p := logPrincipal(e.principal); !slices.Contains(want, p) {
							want = append(want, p)
						}
					}
				}
			}
			switch {
			case at.err == nil && !allow:
				t.Fatalf("seed %d step %d: fail open: relayed to %s while the oracle refuses (ended calls of %v)", seed, step, at.sole.sessionKey, want)
			case at.err == nil && at.sole != live[0]:
				t.Fatalf("seed %d step %d: relayed to the wrong call", seed, step)
			}
			for _, p := range want {
				if !slices.Contains(at.endedCallsOf, p) {
					t.Fatalf("seed %d step %d: %q missing from ended calls of %v", seed, step, p, at.endedCallsOf)
				}
			}
			for _, p := range at.endedCallsOf {
				if !slices.ContainsFunc(ended, func(e endedCall) bool { return logPrincipal(e.principal) == p }) {
					t.Fatalf("seed %d step %d: ended calls of %v names %q, which has no live ended call", seed, step, at.endedCallsOf, p)
				}
			}
			up.mu.Lock()
			defer up.mu.Unlock()
			for _, o := range up.overflow {
				if now.Before(o.expires) {
					overflowLive = true
				}
			}
			if at.err != nil && allow {
				if o, ok := up.overflow[live[0].principal]; !ok || !now.Before(o.expires) {
					t.Fatalf("seed %d step %d: refused (%v) while the oracle relays, with no live overflow record to explain it", seed, step, at.err)
				}
			}
			if len(live) == 1 && !allow && overflowLive {
				overflowDecides = true
				for key, o := range up.orphans {
					if now.Before(o.expires) && key != live[0].sessionKey {
						overflowDecides = false
						break
					}
				}
			}
			for pr, n := range up.orphansOf {
				if n > maxOrphansPerPrincipal {
					t.Fatalf("seed %d step %d: %d keyed records for %q, quota %d", seed, step, n, pr, maxOrphansPerPrincipal)
				}
			}
			if n := len(up.overflow); n > 3 {
				t.Fatalf("seed %d step %d: %d overflow records for 3 principals", seed, step, n)
			}
			return allow, overflowLive, overflowDecides
		}

		for step := range steps {
			switch op := rng.IntN(100); {
			case op < 1:
				// Flood: "a" ends more calls at once than its quota.
				for range maxOrphansPerPrincipal + 10 + rng.IntN(20) {
					rk++
					live = append(live, up.begin(context.Background(), call{sessionKey: requestKeyPrefix + strconv.Itoa(rk), principal: "a", tool: "t"}, 0))
					endAt(len(live) - 1)
				}
			case op < 3:
				// Quiet phase (see the doc comment).
				slices.SortStableFunc(live, func(x, y *inflight) int {
					switch {
					case x.principal != "a" && y.principal == "a":
						return -1
					case x.principal == "a" && y.principal != "a":
						return 1
					}
					return 0
				})
				for len(live) > 0 {
					endAt(0)
					now = now.Add(time.Second)
				}
				jumps := []time.Duration{ttl / 2, ttl - time.Minute, ttl - 3*time.Second, ttl + time.Second}
				now = now.Add(jumps[rng.IntN(len(jumps))])
			case op < 35:
				// Fewer begins than ends, so the set in flight empties
				// often and the probe runs.
				live = append(live, begin(rng.IntN(3) != 0))
			case op < 85 && len(live) > 0:
				endAt(rng.IntN(len(live)))
			default:
				now = now.Add(time.Duration(rng.IntN(20)) * time.Second)
			}
			if a, _, _ := check(step); a {
				allows++
			}
			if len(live) == 0 {
				// Probe: one call, checked, then ended without a record.
				f := begin(rng.IntN(2) == 0)
				live = append(live, f)
				a, ol, od := check(step)
				if a {
					allows++
				}
				if ol {
					overflowProbes++
				}
				if od {
					overflowDecides++
				}
				live = live[:0]
				up.end(f, now, time.Time{})
			}
		}
		totalDecides += overflowDecides
		if testing.Verbose() {
			t.Logf("seed %d: %d overflows, %d relays, %d probes under a live overflow record, %d decided by it alone", seed, overflows, allows, overflowProbes, overflowDecides)
		}
		if overflows < minOverflows || allows < minAllow || overflowProbes < minOverflowProbes {
			t.Fatalf("seed %d reached %d overflows, %d relays, %d probes under a live overflow record; want at least %d, %d, %d",
				seed, overflows, allows, overflowProbes, minOverflows, minAllow, minOverflowProbes)
		}
	}
	if totalDecides < minOverflowDecides {
		t.Fatalf("%d probes across all seeds where a live overflow record alone refused; want at least %d", totalDecides, minOverflowDecides)
	}
}
