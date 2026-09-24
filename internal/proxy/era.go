package proxy

import "github.com/modelcontextprotocol/go-sdk/mcp"

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

// eraOf returns the era of a negotiated protocol version.
func eraOf(version string) string {
	if version >= statelessVersion {
		return eraStateless
	}
	return eraStateful
}

// agentPeer is what the proxy knows about the agent behind one tools/call.
// Each side's era is detected independently: the agent's here, per request;
// the upstream's once, at connect (upstream.version).
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
