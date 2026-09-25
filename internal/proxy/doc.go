// SPDX-License-Identifier: Apache-2.0

// Package proxy is the MCP transport of Fathomgate: one process that is an MCP
// server toward the agent and an MCP client toward each upstream MCP server,
// built on the official go-sdk (pinned to one minor, currently v1.8; ADR
// 0011).
//
// M0 scope (T0.2): upstreams are spawned over stdio ([Command]); the agent
// side is whatever [mcp.Transport] the caller passes to [Proxy.Run] (stdio
// for `fathomgate serve`). Each upstream tool is exposed as "<server>.<tool>",
// where <server> is the profile's `server` key; tools/call strips the prefix
// and forwards. Unknown or unprefixed names get a JSON-RPC invalid-params
// error with structured data. The prefix rules are in
// docs/specs/profile-schema.md section 8.
//
// Policy (M1-19, ADR 0026): every call goes through Proxy.dispatch. With
// [Options.Gate] set, the gate (internal/gate, through the plain-data types
// of internal/gate/seam) decides it first, with the session counters the
// proxy keeps, and the call is forwarded only when the verdict says so,
// with the arguments re-encoded from the object the gate checked; otherwise
// the agent gets the gate's one-line tool error and the upstream sees
// nothing. Each call writes one Info decision line. With no gate every call
// is forwarded as the agent sent it (M0, serve --no-policy). gate.go and
// hints.go hold this; the proxy imports none of classify, inventory or
// policy.
//
// Dual era (T0.3, ADR 0008): go-sdk negotiates each side's protocol version
// on its own, stateful (2025-11-25, initialise handshake) or stateless
// (2026-07-28, _meta on every request). An upstream that does not connect
// within 5 seconds of starting the first connect, spawn included, is
// restarted once and connected with the initialise handshake only (ADR
// 0018). The proxy records both per call, forwards no _meta in either
// direction, and relays an upstream's form elicitation to the agent only
// relabelled with its origin: as MRTR input_required to a stateless agent,
// behind an AES-GCM sealed requestState bound to the transport and
// principal it was issued to (state.go), or as
// elicitation/create to a stateful one (input.go).
// Progress (T0.17) crosses as fathomgate's own notifications: the upstream gets
// a token fathomgate issued, and its notifications for that token reach the
// agent under the agent's token, rate-limited and with the message labelled,
// written by a sender goroutine per call so a slow agent never stalls the
// upstream's dispatch (progress.go, T0.28). The normative rules are in
// docs/specs/profile-schema.md section 8.4.
//
// Streamable HTTP toward the agent (T0.27, ADR 0016): [Proxy.HTTPHandler]
// serves /mcp for both eras through two go-sdk handlers (stateful and
// stateless) behind a dispatcher, after a Host check, an Origin refusal and
// bearer-token authentication, with caps on POSTs, stateful sessions and
// tool calls per session and per principal, and a deadline on every write
// to the agent (http.go, calls.go; profile-schema section 8.5). A principal
// is attribution only, never an approver.
//
// Everything read from an upstream (tool names, descriptions, schemas,
// annotations, results, error messages) is untrusted data. Names outside the
// MCP character set are refused; everything else passes through unchanged
// until redaction and TOFU pinning land in M2.
package proxy
