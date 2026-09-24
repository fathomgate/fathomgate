// Package proxy is the MCP transport of NetGuard: one process that is an MCP
// server toward the agent and an MCP client toward each upstream MCP server,
// built on the official go-sdk (pinned to one minor, currently v1.8; ADR
// 0011).
//
// M0 scope (T0.2): upstreams are spawned over stdio ([Command]); the agent
// side is whatever [mcp.Transport] the caller passes to [Proxy.Run] (stdio
// for `netguard serve`). Each upstream tool is exposed as "<server>.<tool>",
// where <server> is the profile's `server` key; tools/call strips the prefix
// and forwards. Unknown or unprefixed names get a JSON-RPC invalid-params
// error with structured data. The prefix rules are in
// docs/specs/profile-schema.md section 8.
//
// There is no policy in M0. Every call goes through Proxy.dispatch, which is
// where M1 plugs in normalize, classify, inventory and policy.Evaluate.
//
// Dual era (T0.3, ADR 0008): go-sdk negotiates each side's protocol version
// on its own, stateful (2025-11-25, initialise handshake) or stateless
// (2026-07-28, _meta on every request). The proxy records both per call,
// forwards no _meta in either direction, and relays an upstream's form
// elicitation to the agent only relabelled with its origin: as MRTR
// input_required to a stateless agent, behind an AES-GCM sealed requestState
// (state.go), or as elicitation/create to a stateful one (input.go).
// Progress (T0.17) crosses as netguard's own notifications: the upstream gets
// a token netguard issued, and its notifications for that token reach the
// agent under the agent's token, rate-limited and with the message labelled,
// written by a sender goroutine per call so a slow agent never stalls the
// upstream's dispatch (progress.go, T0.28). The normative rules are in docs/specs/profile-schema.md
// section 8.4.
//
// Everything read from an upstream (tool names, descriptions, schemas,
// annotations, results, error messages) is untrusted data. Names outside the
// MCP character set are refused; everything else passes through unchanged
// until redaction and TOFU pinning land in M2.
package proxy
