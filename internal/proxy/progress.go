package proxy

import (
	"context"
	"crypto/rand"
	"math"
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
// limit held back is sent before the call's result.

const (
	// maxProgressMessage caps the upstream part of a relayed progress
	// message, as for a relayed upstream error message: it is a status
	// line, not a prompt.
	maxProgressMessage = maxRelayedMessage
	// progressBurst and progressRate bound how many progress notifications
	// one call relays: progressBurst at once, then progressRate per second.
	// An upstream that floods progress cannot flood the agent's transport.
	progressBurst = 10
	progressRate  = 5.0
	// maxExactInt is the largest integer a float64 holds exactly; a numeric
	// progressToken above it would not round-trip, so it is not used.
	maxExactInt = 1 << 53
)

// progressRelay is one call's progress mapping: the token netguard gave the
// upstream, the agent's own token, and the rate-limit and ordering state.
// mu is held while a notification is written to the agent, so finish (run
// before the call's result is returned) waits for a write in progress and no
// notification follows the result.
type progressRelay struct {
	server     string
	upToken    string // netguard's token, as sent to the upstream
	agentToken any    // the agent's token, returned verbatim
	session    *mcp.ServerSession
	ctx        context.Context // the agent's request context
	now        func() time.Time

	mu       sync.Mutex
	done     bool
	started  bool    // a notification has been accepted
	last     float64 // progress of the newest accepted notification
	tokens   float64 // rate-limit bucket
	refilled time.Time
	pending  *mcp.ProgressNotificationParams // newest one held back by the limit
}

// newProgressRelay returns the relay for one call, with a fresh random token
// for the upstream. It returns nil when the agent sent no usable token.
func newProgressRelay(ctx context.Context, server string, agent agentPeer, agentToken any, now func() time.Time) *progressRelay {
	if agentToken == nil || agent.session == nil {
		return nil
	}
	t := now()
	return &progressRelay{
		server:     server,
		upToken:    rand.Text(),
		agentToken: agentToken,
		session:    agent.session,
		ctx:        ctx,
		now:        now,
		tokens:     progressBurst,
		refilled:   t,
	}
}

// relay passes one upstream notification on, holds it back, or drops it.
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
	if !r.take() {
		r.pending = out
		return
	}
	r.pending = nil
	r.send(out)
}

// finish ends the relay: the newest held-back notification, if any, is sent,
// and nothing is sent after it. The caller has already removed the relay
// from its upstream, so no new notification can find it.
func (r *progressRelay) finish() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.done = true
	if r.pending != nil && r.ctx.Err() == nil {
		r.send(r.pending)
	}
	r.pending = nil
}

// take spends one rate-limit token, refilling the bucket for the time since
// the last refill. It reports false when the bucket is empty.
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

// send writes one notification to the agent under its request context, so
// a future Streamable HTTP transport puts it on that request's stream. A
// failed write is not the call's failure; the result decides that.
func (r *progressRelay) send(p *mcp.ProgressNotificationParams) {
	_ = r.session.NotifyProgress(r.ctx, p)
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
// float64) no larger in magnitude than 2^53. Anything else, including no
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
// notification for r's call reaches the agent.
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
// upstream's notifications one at a time, in order, on one goroutine; a
// notification it dispatches after the call's result has been read finds no
// relay and is dropped.
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
