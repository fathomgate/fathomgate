// SPDX-License-Identifier: FSL-1.1-ALv2

package proxy

import (
	"context"
	"fmt"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// statelessVersion is the first MCP protocol version of the stateless era:
// no initialise handshake, every request self-describing through _meta, and
// multi round-trip requests (MRTR) instead of server-initiated elicitation.
// Versions compare as strings (YYYY-MM-DD).
const statelessVersion = "2026-07-28"

// Era names, as logged and as M1 will record them in audit events.
const (
	eraStateful  = "stateful"  // 2025-11-25 and older: initialise handshake, session
	eraStateless = "stateless" // 2026-07-28 and newer: _meta self-description, MRTR
)

// eraOf returns the era of a negotiated protocol version. It is the agent
// side's rule, and the HTTP dispatcher's; an upstream's era is upstreamEra.
func eraOf(version string) string {
	if version >= statelessVersion {
		return eraStateless
	}
	return eraStateful
}

// upstreamEra returns the era label of an upstream session from the protocol
// version it negotiated and from how go-sdk opened it (T0.47, N6). handshake
// reports that the session's initialise request was answered, rather than
// server/discover. A session opened with the initialise handshake is labelled
// stateful whatever version it negotiated. Since M1-32 an upstream that
// answers the initialise request with a later version than was asked for (a
// hybrid, such as 2026-07-28 to a 2025-11-25 request) is refused at connect
// (handshakes.middleware), so a session opened with the handshake never
// carries a stateless version; the rule stays as the conservative direction.
// Only a session opened with server/discover at a stateless version is
// labelled stateless.
//
// The era is a label of the handshake, for logs and the audit, and nothing
// more. It says nothing about what the upstream can send, and no control may
// treat up.era as a capability. The control that refuses a server-initiated
// elicitation/create from an upstream connected with server/discover reads
// upstream.handshake, how the session was opened, not up.era (M1-32).
func upstreamEra(version string, handshake bool) string {
	if handshake {
		return eraStateful
	}
	// upstreamEra("", false) is stateful: the conservative direction, and
	// unreachable after a successful Connect, which always sets a version.
	return eraOf(version)
}

// handshakes records which upstream sessions go-sdk opened with the
// initialise handshake. It is a sending middleware on the upstream's
// mcp.Client, so it sees the handshake request go-sdk sent and had answered
// on each session, over any transport, and not which connect attempt
// fathomgate made (ADR 0018). It holds at most one entry per connect attempt (two),
// and take empties it once the upstream has connected, so a failed first
// attempt's session is not kept alive. go-sdk sends initialise only inside
// Client.Connect, so nothing is recorded after that.
type handshakes struct {
	mu          sync.Mutex
	byHandshake map[mcp.Session]bool
}

// middleware marks a session once its initialise request has been answered
// without a JSON-RPC error, and refuses a hybrid answer (M1-32, ADR 0008).
//
// The requested version is read from the initialise request go-sdk sent on
// the session: 2025-11-25 on go-sdk's own fallback after server/discover
// and on the ADR 0018 restart. An answer naming a later version than that
// is a hybrid: go-sdk would accept it and then attach the stateless era's
// _meta self-description to requests on a session that exists. The
// middleware returns a hybridError in place of the answer, so go-sdk never
// sends its initialised notification and closes the session inside
// Connect; it first aborts the connect attempt (abortAttempt), which kills
// the upstream process at once rather than after go-sdk's close grace.
// There is no flag to accept a hybrid.
//
// The mark is set before go-sdk checks the answered version (client.go:395
// in v1.8.0) and before it sends its initialised notification; go-sdk may
// still reject the answered version, in which case Connect fails and the
// mark is never read. A request that got an error, or a hybrid answer,
// leaves no mark.
func (h *handshakes) middleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if err != nil || method != methodInitialize {
			return res, err
		}
		var requested, answered string
		if ir, ok := req.(*mcp.InitializeRequest); ok && ir.Params != nil {
			requested = ir.Params.ProtocolVersion
		}
		if r, ok := res.(*mcp.InitializeResult); ok && r != nil {
			answered = r.ProtocolVersion
		}
		// Versions compare as strings (YYYY-MM-DD). go-sdk always names a
		// version in its request; were it ever empty, any answer would count
		// as later and be refused: the safe direction. A stateless version
		// is refused even when it equals the request: no session opened
		// with the handshake may carry one (go-sdk keys the _meta
		// self-description on the version), so upstreamEra's stateful label
		// for a handshake session is always true to the version.
		if answered > requested || eraOf(answered) == eraStateless {
			herr := &hybridError{requested: requested, answered: answered}
			abortAttempt(ctx, herr)
			return nil, herr
		}
		h.mu.Lock()
		if h.byHandshake == nil {
			h.byHandshake = make(map[mcp.Session]bool, 1)
		}
		h.byHandshake[req.GetSession()] = true
		h.mu.Unlock()
		return res, nil
	}
}

// hybridError is the refusal of an upstream that answered the initialise
// request with a later protocol version than fathomgate asked for, or with
// a stateless one (M1-32).
// answered is upstream text: it is quoted and clipped here, and connect
// escapes the whole error (escapedError) before it reaches the operator.
type hybridError struct{ requested, answered string }

func (e *hybridError) Error() string {
	kind := "later"
	if e.answered <= e.requested {
		kind = "stateless" // equal to the request, and 2026-07-28 or later
	}
	return fmt.Sprintf("the upstream answered the %s request for protocol %s with the %s version %q; "+
		"fathomgate refuses a hybrid upstream, which opens a stateful session and then speaks a later version on it, "+
		"so the session was closed and the upstream stopped (ADR 0008)",
		methodInitialize, e.requested, kind, clip(e.answered))
}

// abortKey is the context key under which connectAttempt stores its
// attempt's cancel function, for abortAttempt.
type abortKey struct{}

// withAbort returns ctx carrying cancel, the connect attempt's own cancel
// function.
func withAbort(ctx context.Context, cancel context.CancelCauseFunc) context.Context {
	return context.WithValue(ctx, abortKey{}, cancel)
}

// abortAttempt cancels the connect attempt ctx belongs to, with cause,
// which kills its upstream process at once (connectAttempt). A context
// from outside a connect attempt carries no cancel function, and nothing
// happens.
func abortAttempt(ctx context.Context, cause error) {
	if cancel, ok := ctx.Value(abortKey{}).(context.CancelCauseFunc); ok {
		cancel(cause)
	}
	if afterAbort != nil {
		afterAbort()
	}
}

// afterAbort, when not nil, runs once abortAttempt has cancelled the
// attempt and before go-sdk closes the session. It is a test hook, nil
// in production: a test uses it to run the ADR 0018 bound out inside that
// window (TestHybridRefusalIsNotRestarted).
var afterAbort func()

// take reports whether cs was opened with the initialise handshake, and
// forgets every session recorded so far.
func (h *handshakes) take(cs *mcp.ClientSession) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	opened := h.byHandshake[cs]
	h.byHandshake = nil
	return opened
}

// methodInitialize is the MCP handshake method, as go-sdk sends it.
const methodInitialize = "initialize" //nolint:misspell // MCP wire method name, not prose

// agentPeer is what the proxy knows about the agent behind one tools/call.
// Each side's era is detected independently: the agent's here, per request;
// the upstream's once, at connect (upstream.version and upstream.era).
type agentPeer struct {
	session *mcp.ServerSession
	// version is the protocol version the agent speaks: from the initialise
	// handshake for a stateful agent, from the request's _meta for a
	// stateless one.
	version string
	// canElicit reports that the agent declared form elicitation.
	canElicit bool
}

// stateless reports whether the agent takes MRTR input_required results.
// It mirrors go-sdk's own test (the session's negotiated version), because
// go-sdk marks a result input_required only in that case.
func (a agentPeer) stateless() bool { return a.version >= statelessVersion }

// agentOf reads the agent's era and elicitation capability from a request.
func agentOf(req *mcp.CallToolRequest) agentPeer {
	a := agentPeer{session: req.Session}
	if req.Session != nil {
		if ip := req.Session.InitializeParams(); ip != nil {
			a.version = ip.ProtocolVersion
		}
	}
	if a.version == "" {
		a.version = req.ProtocolVersion()
	}
	if caps := req.ClientCapabilities(); caps != nil && caps.Elicitation != nil {
		el := caps.Elicitation
		// Both modes unset means form, for backward compatibility.
		a.canElicit = el.Form != nil || el.URL == nil
	}
	return a
}
