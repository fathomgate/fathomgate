// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Tool calls in flight over the HTTP listener (T0.27; T3 in the security
// review of PR #63).
//
// The POST cap in http.go counts HTTP requests. It does not bound calls: a
// 2025-era agent that drops its POST leaves the call running (go-sdk detaches
// a stateful call from its request), so it could open calls without limit
// while holding no request open. callLimits counts the calls themselves, per
// agent session and per token principal, and refuses one over either cap
// before anything reaches the upstream. Each admitted call runs under a
// context callLimits can cancel: when its session is deleted (go-sdk's
// session Close waits for the requests in flight instead of cancelling them)
// and when the proxy closes.

// callLimits is the admission and cancellation state for tool calls. It is
// built by HTTPHandler and read by Proxy.handler; stdio has none.
//
// Lock order: httpHandler.mu, then callLimits.mu (claimIdle during
// eviction, forget in the session watcher); liveSession.mu, then
// callLimits.mu (retire in liveSession.expire). callLimits.mu is a leaf:
// nothing takes another of these locks while holding it.
type callLimits struct {
	perSession, perPrincipal int
	// orphanTTL is how long a call that has ended keeps blocking the
	// attribution of an upstream prompt to another agent session
	// (HTTPOptions.OrphanTTL; input.go).
	orphanTTL time.Duration

	mu         sync.Mutex
	closed     bool
	sessions   map[*mcp.ServerSession]*sessionCalls
	principals map[string]int
	// retired holds the stateful sessions fathomgate is closing (evicted at
	// the session cap, or expired): admit refuses every call on them
	// (claimIdle, retire). An entry is dropped when its session ends.
	retired map[*mcp.ServerSession]struct{}
	// wg tracks the goroutines that wait for a stateful session to end
	// (httpHandler.settleSession); Proxy.Close joins them. Add happens only
	// under mu while closed is false, so it never races with Wait.
	wg sync.WaitGroup
}

// sessionCalls is the calls in flight on one agent session. principal is
// the principal of the call that opened the entry; go-sdk binds a stateful
// session to the principal that initialised it, so every call on it has
// the same one.
type sessionCalls struct {
	principal string
	calls     map[*admittedCall]struct{}
}

// admittedCall is one call callLimits let through.
type admittedCall struct {
	cancel context.CancelFunc
}

func newCallLimits(perSession, perPrincipal int) *callLimits {
	return &callLimits{
		perSession:   perSession,
		perPrincipal: perPrincipal,
		sessions:     make(map[*mcp.ServerSession]*sessionCalls),
		principals:   make(map[string]int),
		retired:      make(map[*mcp.ServerSession]struct{}),
	}
}

// admit lets a call through or refuses it. On success it returns the call's
// context (ctx, also cancelled by cancelSession and close) and the release
// function the caller must run when the call ends; refused is nil. On
// refusal it returns the tool error to send instead, and the call never
// reaches the upstream; why is errSessionRetired when the session is being
// closed (the call arrived on a session evicted or expired while go-sdk was
// delivering it), and nil for the other refusals. tool is the prefixed
// name, for the error text.
func (l *callLimits) admit(ctx context.Context, principal string, ss *mcp.ServerSession, tool string) (_ context.Context, _ func(), refused *mcp.CallToolResult, why error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	sc := l.sessions[ss]
	switch {
	case l.closed:
		return nil, nil, toolError(fmt.Sprintf("fathomgate refused %s: fathomgate is shutting down", tool)), nil
	case l.isRetired(ss):
		return nil, nil, toolError(fmt.Sprintf("fathomgate refused %s: %s", tool, errSessionRetired)), errSessionRetired
	case sc != nil && len(sc.calls) >= l.perSession:
		return nil, nil, toolError(fmt.Sprintf("fathomgate refused %s: %d calls are already in flight on this session (limit %d); retry when one finishes", tool, len(sc.calls), l.perSession)), nil
	case l.principals[principal] >= l.perPrincipal:
		return nil, nil, toolError(fmt.Sprintf("fathomgate refused %s: %d calls are already in flight for principal %s (limit %d); retry when one finishes", tool, l.principals[principal], principal, l.perPrincipal)), nil
	}
	if sc == nil {
		sc = &sessionCalls{principal: principal, calls: make(map[*admittedCall]struct{})}
		l.sessions[ss] = sc
	}
	cctx, cancel := context.WithCancel(ctx)
	a := &admittedCall{cancel: cancel}
	sc.calls[a] = struct{}{}
	l.principals[principal]++
	var once sync.Once
	release := func() {
		once.Do(func() {
			cancel()
			l.mu.Lock()
			defer l.mu.Unlock()
			delete(sc.calls, a)
			if len(sc.calls) == 0 && l.sessions[ss] == sc {
				delete(l.sessions, ss)
			}
			if l.principals[principal]--; l.principals[principal] <= 0 {
				delete(l.principals, principal)
			}
		})
	}
	return cctx, release, nil, nil
}

// errSessionRetired is the reason admit gives for a call on a session
// fathomgate is closing. It is a sentinel so Proxy.handler can log the
// refusal as what it is, not as a call cap. Its text reaches the agent and
// is quoted in profile-schema 8.5 (*Eviction*); change both together
// (TestSessionRetiredText pins it).
var errSessionRetired = errors.New("its agent session has been closed (evicted at the session cap or idle); start a new session and call again")

// isRetired reports whether ss is being closed by fathomgate. Callers hold
// l.mu. A nil session (no agent session) is never retired.
func (l *callLimits) isRetired(ss *mcp.ServerSession) bool {
	if ss == nil {
		return false
	}
	_, ok := l.retired[ss]
	return ok
}

// cancelSession cancels every call in flight on the stateful session whose
// id is sessionID, if that session belongs to principal. It runs before a
// DELETE reaches go-sdk, whose session Close would otherwise wait for those
// calls to end on their own. A DELETE from another principal cancels
// nothing (and go-sdk answers it with 403).
func (l *callLimits) cancelSession(sessionID, principal string) int {
	if sessionID == "" {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for ss, sc := range l.sessions {
		if ss == nil || ss.ID() != sessionID || sc.principal != principal {
			continue
		}
		for a := range sc.calls {
			a.cancel()
			n++
		}
	}
	return n
}

// busy reports whether ss has a call in flight, for the log line of a
// session-cap refusal. Eviction does not use it: it claims the session
// with claimIdle, which checks and retires in one step.
func (l *callLimits) busy(ss *mcp.ServerSession) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	sc := l.sessions[ss]
	return sc != nil && len(sc.calls) > 0
}

// claimIdle retires ss if it has no call in flight and reports whether it
// did (T0.57, the session cap's eviction). The check and the retirement
// happen under one lock, so no call can be admitted in between: a
// tools/call go-sdk has delivered but that has not reached admit yet (its
// agent dropped the POST, so the session looked idle) is refused by admit
// once it gets there, and never reaches the upstream. Callers may hold
// httpHandler.mu (lock order: httpHandler.mu, then callLimits.mu).
func (l *callLimits) claimIdle(ss *mcp.ServerSession) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if sc := l.sessions[ss]; sc != nil && len(sc.calls) > 0 {
		return false
	}
	if ss != nil {
		l.retired[ss] = struct{}{}
	}
	return true
}

// retire retires ss and cancels its calls in flight, in one step, and
// returns how many it cancelled: the idle expiry (liveSession.expire)
// closes the session whatever it is running, and a call admitted after the
// cancellation would otherwise run on a closing session, which go-sdk's
// Close then waits for, with no idle clock left to cancel it. expire calls
// it holding liveSession.mu (the lock order is on callLimits).
func (l *callLimits) retire(ss *mcp.ServerSession) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if ss != nil {
		l.retired[ss] = struct{}{}
	}
	n := 0
	if sc := l.sessions[ss]; sc != nil {
		for a := range sc.calls {
			a.cancel()
			n++
		}
	}
	return n
}

// forget drops ss from the retired set once the session has ended
// (settleSession's watcher), so the set holds only sessions go-sdk has not
// finished closing. The watcher calls it under httpHandler.mu, after
// liveSession.stop. No claimIdle can land after it: an unevicted session
// has left httpHandler.live, and an evicted one (whose entry stays until
// forgetEvicted) is skipped by claimEvictableLocked. No expire's retire can
// either, because expire returns once stop has run.
func (l *callLimits) forget(ss *mcp.ServerSession) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.retired, ss)
}

// track runs fn on a goroutine that Proxy.Close waits for, unless the
// limits are already closed, in which case it reports false and fn does not
// run.
func (l *callLimits) track(fn func()) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return false
	}
	l.wg.Go(fn)
	return true
}

// wait blocks until every goroutine started by track has returned. Call it
// after close, and after the sessions those goroutines wait for are closed.
func (l *callLimits) wait() { l.wg.Wait() }

// close cancels every call in flight and refuses new ones. It is
// idempotent.
func (l *callLimits) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	for _, sc := range l.sessions {
		for a := range sc.calls {
			a.cancel()
		}
	}
}

// inFlight is the number of calls in flight, for tests.
func (l *callLimits) inFlight() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, c := range l.principals {
		n += c
	}
	return n
}
