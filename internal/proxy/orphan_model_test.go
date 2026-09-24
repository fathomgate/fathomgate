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
// reference-model check from the review of PR #82 (T0.44). Random begins,
// ends and clock steps drive upstream.end and upstream.attribute; an
// oracle remembers every ended call on its own, with no quota and no
// overflow. attribute may relay a prompt only when the oracle would (one
// call in flight and no live ended call of another session), only to that
// call. endedCallsOf must name every principal the oracle refuses for, and
// only principals with a live ended call; netguard may refuse where the
// oracle would not only through a live overflow record of the caller's
// principal. The per-principal quota must hold throughout. Principal "a" makes most calls, so it overflows often.
func TestOrphanModelNeverFailsOpen(t *testing.T) {
	type endedCall struct {
		key, principal string
		expires        time.Time
	}
	name := func(principal string) string {
		if principal == "" {
			return localPrincipal
		}
		return principal
	}
	fixed := []struct{ key, principal string }{{"l1", ""}, {"sA1", "a"}, {"sA2", "a"}, {"sB1", "b"}}
	const seeds, steps = 16, 3000
	for seed := uint64(1); seed <= seeds; seed++ {
		rng := rand.New(rand.NewPCG(seed, seed*7))
		up := &upstream{name: testServer}
		ttl := 90 * time.Minute
		now := time.Unix(1_000_000, 0)
		var ended []endedCall
		var live []*inflight
		rk, overflows := 0, 0
		for step := range steps {
			switch op := rng.IntN(10); {
			case op < 4:
				var k, pr string
				if rng.IntN(3) == 0 {
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
				live = append(live, up.begin(context.Background(), call{sessionKey: k, principal: pr, tool: "t"}, 0))
			case op < 8 && len(live) > 0:
				i := rng.IntN(len(live))
				f := live[i]
				live = slices.Delete(live, i, i+1)
				if _, of := up.end(f, now, now.Add(ttl)); of {
					overflows++
				}
				ended = append(ended, endedCall{f.sessionKey, f.principal, now.Add(ttl)})
			default:
				now = now.Add(time.Duration(rng.IntN(20)) * time.Second)
			}
			// The oracle forgets what has expired, as the table does; that
			// keeps each step's work bounded by the TTL.
			ended = slices.DeleteFunc(ended, func(e endedCall) bool { return !now.Before(e.expires) })

			at := up.attribute(now)
			var want []string
			allow := len(live) == 1
			if allow {
				for _, e := range ended {
					if e.key != live[0].sessionKey {
						allow = false
						if p := name(e.principal); !slices.Contains(want, p) {
							want = append(want, p)
						}
					}
				}
			}
			slices.Sort(want)
			switch {
			case at.err == nil && !allow:
				t.Fatalf("seed %d step %d: fail open: relayed to %s while the oracle refuses (ended calls of %v)", seed, step, at.sole.sessionKey, want)
			case at.err == nil && at.sole != live[0]:
				t.Fatalf("seed %d step %d: relayed to the wrong call", seed, step)
			}
			// Every principal the oracle refuses for is named; every name
			// has a live ended call. netguard may refuse more than the
			// oracle only through an overflow record, which stands for its
			// principal's ended calls whatever their session.
			for _, p := range want {
				if !slices.Contains(at.endedCallsOf, p) {
					t.Fatalf("seed %d step %d: %q missing from ended calls of %v", seed, step, p, at.endedCallsOf)
				}
			}
			for _, p := range at.endedCallsOf {
				if !slices.ContainsFunc(ended, func(e endedCall) bool { return name(e.principal) == p }) {
					t.Fatalf("seed %d step %d: ended calls of %v names %q, which has no live ended call", seed, step, at.endedCallsOf, p)
				}
			}
			up.mu.Lock()
			if at.err != nil && allow {
				if _, over := up.overflow[live[0].principal]; !over {
					up.mu.Unlock()
					t.Fatalf("seed %d step %d: refused (%v) while the oracle relays, with no overflow record to explain it", seed, step, at.err)
				}
			}
			for pr, n := range up.orphansOf {
				if n > maxOrphansPerPrincipal {
					up.mu.Unlock()
					t.Fatalf("seed %d step %d: %d keyed records for %q, quota %d", seed, step, n, pr, maxOrphansPerPrincipal)
				}
			}
			if n := len(up.overflow); n > 3 {
				up.mu.Unlock()
				t.Fatalf("seed %d step %d: %d overflow records for 3 principals", seed, step, n)
			}
			up.mu.Unlock()
		}
		if seed == 1 && overflows == 0 {
			t.Fatalf("seed 1 never overflowed (%d per-request keys); the model does not reach the table-full case", rk)
		}
	}
}
