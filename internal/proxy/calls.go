// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
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
	}
}

// admit lets a call through or refuses it. On success it returns the call's
// context (ctx, also cancelled by cancelSession and close) and the release
// function the caller must run when the call ends; refused is nil. On
// refusal it returns the tool error to send instead, and the call never
// reaches the upstream. tool is the prefixed name, for the error text.
func (l *callLimits) admit(ctx context.Context, principal string, ss *mcp.ServerSession, tool string) (context.Context, func(), *mcp.CallToolResult) {
	l.mu.Lock()
	defer l.mu.Unlock()
	sc := l.sessions[ss]
	switch {
	case l.closed:
		return nil, nil, toolError(fmt.Sprintf("fathomgate refused %s: fathomgate is shutting down", tool))
	case sc != nil && len(sc.calls) >= l.perSession:
		return nil, nil, toolError(fmt.Sprintf("fathomgate refused %s: %d calls are already in flight on this session (limit %d); retry when one finishes", tool, len(sc.calls), l.perSession))
	case l.principals[principal] >= l.perPrincipal:
		return nil, nil, toolError(fmt.Sprintf("fathomgate refused %s: %d calls are already in flight for principal %s (limit %d); retry when one finishes", tool, l.principals[principal], principal, l.perPrincipal))
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
	return cctx, release, nil
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

// busy reports whether ss has a call in flight. The session cap's eviction
// (httpHandler.reserveSession) never takes a session that has one: a
// 2025-era call keeps running after its POST is dropped, and evicting its
// session would cancel it.
func (l *callLimits) busy(ss *mcp.ServerSession) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	sc := l.sessions[ss]
	return sc != nil && len(sc.calls) > 0
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
