package proxy

import (
	"context"
	"crypto/rand"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Progress notifications (T0.17; profile-schema section 8.4, "Progress").
//
// The agent's progressToken is _meta, and no _meta crosses the proxy. So when
// the agent asks for progress, netguard issues its own opaque token for the
// upstream call and keeps the mapping for as long as the call is open. An
// upstream notifications/progress naming that token is rebuilt as netguard's
// own notification to the agent, carrying the agent's token: progress and
// total as numbers, and the message relabelled as upstream text. Nothing
// else of the upstream's notification crosses (its _meta in particular).
// Notifications for any other token, for a finished call, whose progress does
// not increase, or past the rate limit are dropped; the newest one the rate
// limit held back is sent when a rate slot frees up, or before the call's
// result if the call ends first.
//
// Nothing is written to the agent on the upstream's dispatch goroutine
// (T0.28). go-sdk hands an upstream's notifications to their handler one at
// a time, and its later notifications and requests (elicitation/create for
// another call among them) wait until that handler returns. So relay only
// updates the relay's state and queues the rebuilt notification, and a
// sender goroutine per relay writes it. An agent that stops reading stalls
// its own relay's sender, never the upstream.

const (
	// maxProgressMessage caps the upstream part of a relayed progress
	// message, as for a relayed upstream error message: it is a status
	// line, not a prompt.
	maxProgressMessage = maxRelayedMessage
	// progressBurst and progressRate bound how many progress notifications
	// one call relays: progressBurst at once, then progressRate per second.
	// An upstream that floods progress cannot flood the agent's transport.
	// progressBurst is also the length of the send queue, so a slow agent
	// costs at most that many notifications of memory per call.
	progressBurst = 10
	progressRate  = 5.0
	// progressFinalWait bounds how long the end of a call waits for its
	// queued progress (the final held-back update included) to be written
	// to the agent. An agent that reads takes well under a millisecond; one
	// that has stopped reading delays the call's end by this much, and what
	// is still queued is dropped.
	progressFinalWait = time.Second
	// maxExactInt is 2^53-1 (JavaScript's Number.MAX_SAFE_INTEGER): the
	// largest magnitude below which every integer has its own float64. A
	// larger numeric progressToken may have been rounded on the way in
	// (9007199254740993 arrives as 2^53) and would be echoed back as a token
	// the agent never sent, so it is not used.
	maxExactInt = 1<<53 - 1
)

// progressRelay is one call's progress mapping: the token netguard gave the
// upstream, the agent's own token, the rate-limit and ordering state, and
// the queue its sender drains.
//
// mu guards state only and is never held across a write to the agent, so
// relay (on the upstream's dispatch goroutine) and finish (on the call's
// goroutine) never wait on the agent. The sender goroutine (run) is started
// by the first notification relay accepts and is owned by the relay: it
// returns once finish has run and the queue is empty, or once finish has
// given up waiting and the write in progress, if any, has returned. A
// transport write that ignores cancellation (go-sdk's stdio and in-memory
// transports check the context only before writing) returns when the agent
// reads again or its connection closes, so a sender can outlive its call by
// that long, and never more than one per call.
type progressRelay struct {
	server     string
	upToken    string // netguard's token, as sent to the upstream
	agentToken any    // the agent's token, returned verbatim
	session    *mcp.ServerSession
	ctx        context.Context // the agent's request context
	now        func() time.Time
	finalWait  time.Duration // how long finish waits for the sender

	// sendCtx is ctx, also cancelled when finish returns, so a transport
	// that honours cancellation drops a write finish no longer waits for.
	sendCtx    context.Context
	cancelSend context.CancelFunc
	wake       chan struct{} // one-slot doorbell for the sender

	mu        sync.Mutex
	done      bool    // finish has run; nothing more is accepted
	abandoned bool    // finish stopped waiting; the sender starts no write
	started   bool    // a notification has been accepted
	last      float64 // progress of the newest accepted notification
	tokens    float64 // rate-limit bucket
	refilled  time.Time
	held      *mcp.ProgressNotificationParams   // newest one held back by the limit
	queue     []*mcp.ProgressNotificationParams // admitted, oldest first, at most progressBurst
	running   bool                              // the sender has been started
	exited    chan struct{}                     // closed when the sender returns
}

// newProgressRelay returns the relay for one call, with a fresh random token
// for the upstream. It returns nil when the agent sent no usable token.
func newProgressRelay(ctx context.Context, server string, agent agentPeer, agentToken any, now func() time.Time, finalWait time.Duration) *progressRelay {
	if agentToken == nil || agent.session == nil {
		return nil
	}
	t := now()
	sendCtx, cancel := context.WithCancel(ctx)
	return &progressRelay{
		server:     server,
		upToken:    rand.Text(),
		agentToken: agentToken,
		session:    agent.session,
		ctx:        ctx,
		now:        now,
		finalWait:  finalWait,
		sendCtx:    sendCtx,
		cancelSend: cancel,
		wake:       make(chan struct{}, 1),
		tokens:     progressBurst,
		refilled:   t,
	}
}

// relay queues one upstream notification for the agent, holds it back, or
// drops it. It runs on the upstream's dispatch goroutine and never waits on
// the agent.
func (r *progressRelay) relay(in *mcp.ProgressNotificationParams) {
	r.mu.Lock()
	defer r.mu.Unlock()
	// The MCP spec requires progress to increase with every notification.
	if r.done || r.ctx.Err() != nil || (r.started && !(in.Progress > r.last)) {
		return
	}
	r.started, r.last = true, in.Progress
	out := &mcp.ProgressNotificationParams{
		ProgressToken: r.agentToken,
		Progress:      in.Progress,
		Total:         in.Total,
		Message:       progressMessage(r.server, in.Message),
	}
	if !r.running {
		r.running = true
		r.exited = make(chan struct{})
		go r.run()
	}
	if r.take() {
		r.held = nil
		r.push(out)
	} else {
		// The sender queues it when a rate slot frees up, and finish
		// does if the call ends first, unless a newer one replaces it.
		r.held = out
	}
	r.ring()
}

// push appends p to the send queue. When the queue is full (the agent is
// not keeping up), p replaces its newest entry: each entry's progress is
// higher than the one before, so the agent still sees progress increase,
// and the queue stays bounded however slow the agent is. Callers hold mu.
func (r *progressRelay) push(p *mcp.ProgressNotificationParams) {
	if len(r.queue) == progressBurst {
		r.queue[len(r.queue)-1] = p
		return
	}
	r.queue = append(r.queue, p)
}

// ring wakes the sender without blocking.
func (r *progressRelay) ring() {
	select {
	case r.wake <- struct{}{}:
	default:
	}
}

// run is the sender. It writes queued notifications to the agent, oldest
// first, one at a time, and queues the held-back one as soon as a rate slot
// frees up (S4 on PR #53), waking on a timer for that. It returns once
// finish has run and the queue is empty, or once finish has abandoned it.
func (r *progressRelay) run() {
	defer close(r.exited)
	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()
	for {
		r.mu.Lock()
		if !r.done && r.held != nil && r.take() {
			r.push(r.held)
			r.held = nil
		}
		var next *mcp.ProgressNotificationParams
		if !r.abandoned && len(r.queue) > 0 {
			next = r.queue[0]
			r.queue = slices.Delete(r.queue, 0, 1)
		}
		stop := r.abandoned || (r.done && next == nil)
		var wait time.Duration
		if next == nil && !stop && r.held != nil {
			wait = r.untilToken()
		}
		r.mu.Unlock()

		switch {
		case next != nil:
			// Under the agent's request context, so a Streamable HTTP
			// transport puts it on that request's stream. A failed write
			// is not the call's failure; the result decides that.
			_ = r.session.NotifyProgress(r.sendCtx, next)
			continue
		case stop:
			return
		}
		var tick <-chan time.Time
		if wait > 0 {
			timer.Reset(wait)
			tick = timer.C
		}
		select {
		case <-r.wake:
		case <-tick:
		}
		timer.Stop()
	}
}

// finish ends the relay. The newest held-back notification, if any, joins
// the queue, nothing more is accepted, and finish waits up to finalWait for
// the sender to write what is queued, so the call's result follows it. If
// the agent has not read it all by then, the rest of the queue is dropped
// and the sender starts no further write. A write already in progress holds
// the agent transport's write lock, so the result, written next by go-sdk,
// still comes after it. The caller has already removed the relay from its
// upstream, so no new notification can find it.
func (r *progressRelay) finish() {
	defer r.cancelSend()
	r.mu.Lock()
	r.done = true
	if r.held != nil && r.ctx.Err() == nil {
		r.push(r.held)
	}
	r.held = nil
	running, exited := r.running, r.exited
	r.mu.Unlock()
	if !running {
		return
	}
	r.ring()
	t := time.NewTimer(r.finalWait)
	defer t.Stop()
	select {
	case <-exited:
	case <-t.C:
		r.mu.Lock()
		r.abandoned = true
		r.queue = nil
		r.mu.Unlock()
	}
}

// take spends one rate-limit token, refilling the bucket for the time since
// the last refill. It reports false when the bucket is empty. Callers hold
// mu.
func (r *progressRelay) take() bool {
	now := r.now()
	if d := now.Sub(r.refilled); d > 0 {
		r.tokens = math.Min(progressBurst, r.tokens+d.Seconds()*progressRate)
		r.refilled = now
	}
	if r.tokens < 1 {
		return false
	}
	r.tokens--
	return true
}

// untilToken is how long until the bucket holds a whole token again: at
// least a millisecond, so a clock that stands still (or runs backwards)
// cannot spin the sender. Callers hold mu, after a take that failed.
func (r *progressRelay) untilToken() time.Duration {
	d := time.Duration((1 - r.tokens) / progressRate * float64(time.Second))
	return max(d-r.now().Sub(r.refilled), time.Millisecond)
}

// progressMessage is the agent-facing copy of an upstream progress message:
// labelled with its origin and escaped like a relayed prompt (section 8.4),
// capped like a relayed error message. A message that reads as an origin
// label is dropped, and the numbers go on without it.
func progressMessage(server, msg string) string {
	if msg == "" || hasOriginLabel(msg) {
		return ""
	}
	return promptLabel(server) + escapeControl(msg, maxProgressMessage)
}

// agentProgressToken returns the agent's progressToken if it is one netguard
// can return exactly: a string, or an integer (JSON numbers arrive as
// float64) no larger in magnitude than 2^53-1. Anything else, including no
// token, is nil, and the call asks the upstream for no progress.
func agentProgressToken(req *mcp.CallToolRequest) any {
	if req == nil || req.Params == nil {
		return nil
	}
	switch t := req.Params.GetProgressToken().(type) {
	case string:
		return t
	case float64:
		if t == math.Trunc(t) && math.Abs(t) <= maxExactInt {
			return t
		}
	case int, int32, int64:
		return t
	}
	return nil
}

// watchProgress registers r on u, so upstream notifications naming its token
// find it.
func (u *upstream) watchProgress(r *progressRelay) {
	if r == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.progress == nil {
		u.progress = make(map[string]*progressRelay)
	}
	u.progress[r.upToken] = r
}

// unwatchProgress removes r from u and finishes it. After it returns, no
// further notification for r's call starts on its way to the agent. It
// waits at most r.finalWait, however slow the agent.
func (u *upstream) unwatchProgress(r *progressRelay) {
	if r == nil {
		return
	}
	u.mu.Lock()
	delete(u.progress, r.upToken)
	u.mu.Unlock()
	r.finish()
}

// upstreamProgress handles notifications/progress from u. go-sdk runs an
// upstream's notifications one at a time, in order, on one goroutine, so
// this must not block: relay only queues. A notification it dispatches after
// the call's result has been read finds no relay and is dropped.
func (p *Proxy) upstreamProgress(u *upstream) func(context.Context, *mcp.ProgressNotificationClientRequest) {
	return func(_ context.Context, req *mcp.ProgressNotificationClientRequest) {
		if req == nil || req.Params == nil {
			return
		}
		tok, ok := req.Params.ProgressToken.(string)
		if !ok {
			return
		}
		u.mu.Lock()
		r := u.progress[tok]
		u.mu.Unlock()
		if r != nil {
			r.relay(req.Params)
		}
	}
}
