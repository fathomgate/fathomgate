// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"context"
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

// upstreamEra returns the era of an upstream session from the protocol
// version it negotiated and from how go-sdk opened it (T0.47, N6): handshake
// reports that the initialise handshake completed on the session, rather
// than server/discover. A session opened with the initialise handshake is
// stateful whatever version the upstream named in its answer: it has a
// handshake and a session, and the upstream may send it server-initiated
// requests. That happens when an upstream answers the 2025-11-25 initialise
// request, after the ADR 0018 restart or go-sdk's own fallback, with
// 2026-07-28, which go-sdk accepts. Only a session opened with
// server/discover at a stateless version is stateless.
func upstreamEra(version string, handshake bool) string {
	if handshake {
		return eraStateful
	}
	return eraOf(version)
}

// handshakes records which upstream sessions go-sdk opened with the
// initialise handshake. It is a sending middleware on the upstream's
// mcp.Client, so it sees the handshake go-sdk actually completed on each
// session, over any transport, and not which connect attempt fathomgate
// made (ADR 0018). It holds at most one entry per connect attempt (two),
// and take empties it once the upstream has connected, so a failed first
// attempt's session is not kept alive. go-sdk sends initialise only inside
// Client.Connect, so nothing is recorded after that.
type handshakes struct {
	mu          sync.Mutex
	byHandshake map[mcp.Session]bool
}

// middleware marks a session once its initialise request has been answered
// without error. A failed handshake leaves no mark; its session is closed.
func (h *handshakes) middleware(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		res, err := next(ctx, method, req)
		if err == nil && method == methodInitialize {
			h.mu.Lock()
			if h.byHandshake == nil {
				h.byHandshake = make(map[mcp.Session]bool, 1)
			}
			h.byHandshake[req.GetSession()] = true
			h.mu.Unlock()
		}
		return res, err
	}
}

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
