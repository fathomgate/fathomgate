# ADR 0008: Dual-era MCP support

- Status: accepted
- Date: 2026-09-23
- Deciders: Josh Scott

## Context

The MCP spec revision 2026-07-28 removed the `initialize` handshake and `Mcp-Session-Id`, made every request self-describing through `_meta`, replaced server-initiated elicitation and sampling with Multi Round-Trip Requests (MRTR), and requires `Mcp-Method` and `Mcp-Name` headers on Streamable HTTP. HTTP+SSE (2024-11-05) is formally deprecated with a 12-month removal window.

Most network MCP servers on GitHub run 2025-era SDKs (FastMCP 1.x, low-level python-sdk 1.x). The clients NetGuard's first users run are a mix. A proxy that speaks only one era is useless on one side. See [research brief 01, section 1](../research/01-mcp-proxy-prior-art.md).

The go-sdk v1.7.0 negotiates the highest mutual version back to 2024-11-05 and exposes `InputRequiredResult` for MRTR.

## Decision

We will speak both the stateful 2025-11-25 era and the stateless 2026-07-28 era on both sides from M0, detect each peer's era per the spec's backward-compatibility fallback, and translate between them.

Translation rules:

- Toward a 2025-era upstream, the proxy performs `initialize` and keeps the session; toward a 2026-era upstream it sends self-describing requests and may call `server/discover`.
- A hold is returned to a 2026-era client as `input_required` with a signed pending id in `requestState`; to a 2025-era client as a tool error naming the pending id, and the agent may poll `check_approval`.
- An upstream server-initiated `elicitation/create` (2025 era) is re-labelled with the upstream's name before forwarding, or converted to an `input_required` result for a 2026-era client.
- Upstream `sampling/createMessage` is blocked and audited, following Docker's gateway.
- On HTTP, header and body must agree; the proxy validates `Mcp-Method` and `Mcp-Name` against the body and decodes Base64-sentinel tool names before comparing.
- Tool names from aggregated upstreams are prefixed with the server id, as the spec recommends.

## Consequences

### Positive

- Works today with FastMCP 1.x upstreams and with 2026-era clients such as Claude Code.
- MRTR gives a clean in-band approval shape for the future without blocking on it.

### Negative

- Two code paths in `internal/proxy` for lifecycle and for holds. Mitigated by the official conformance suite run against the client-facing side in CI, and by tier 2 tests against one upstream per era (netdev-ssh-mcp on go-sdk, upa/mcp-netmiko-server on FastMCP).
- The 2025-era hold shape depends on the agent noticing a tool error and polling. Accepted; CLI and webhook approval do not depend on the client at all.

### Neutral

- When HTTP+SSE leaves the spec the 2024-11-05 path is dropped in a minor release; 2025-11-25 stateful support stays as long as upstreams need it.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| 2026 era only | Cannot front most existing network servers. |
| 2025 era only | Cannot use MRTR; will be deprecated. |
| Separate adapter binaries per era | Two installs, two configs; the translation belongs in one place. |

## Amendments

This section records factual corrections (GOVERNANCE.md). It does not change the decision.

| Date | What changed | Why |
| --- | --- | --- |
| 2026-09-24 | Pointer: [ADR 0018](0018-bound-server-discover-then-initialize-only.md) extends the `server/discover` fallback in this record's first translation rule to the case where the probe is not answered at all, and makes the second attempt a new session on a new upstream process | ADR 0018 (T0.39) changes one clause of this record, not the whole of it: an upstream that answers nothing after the probe hung `netguard serve` until its 30-second startup limit. This record stays `accepted`; the dual-era decision and every other translation rule stand |
| 2026-09-25 | Two facts about the first translation rule, the one this record's detection rests on ("toward a 2025-era upstream, the proxy performs `initialize` and keeps the session; toward a 2026-era upstream it sends self-describing requests"). (1) An upstream that answers `initialize` with a later protocol version than fathomgate asked for (2026-07-28 to a 2025-11-25 request) is neither: go-sdk accepts the answer and then sends self-describing requests on a session that has a handshake. fathomgate refuses such a hybrid upstream at startup: it closes the session before go-sdk sends `notifications/initialized`, kills the upstream at once and exits 1 with an error naming both versions and this record. No flag. (2) An upstream connected with `server/discover` is in the 2026 era, where input comes as MRTR `input_required`; go-sdk's client still accepts a server-initiated `elicitation/create` from it. The third rule's relabel-and-forward applies to 2025-era upstreams only, so fathomgate refuses that request with a JSON-RPC error and a refusal naming the reason, with or without a policy. Sampling was already refused (the fourth rule). Normative text: [profile-schema 8.4](../specs/profile-schema.md#84-protocol-eras-_meta-and-input-requests) and 8.2 | M1-32, from the security review of PR #151 (M1-06): the hybrid had been labelled `era=stateful` at `protocol=2026-07-28`, and F1 showed an upstream labelled stateless could still prompt. No CLI or exported change; the orchestrator judged no new ADR. The dual-era decision and every translation rule stand |

## References

- [Research brief 01, section 1](../research/01-mcp-proxy-prior-art.md)
- [MCP 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- [MCP 2026-07-28 release post](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [Streamable HTTP, backward compatibility](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#backward-compatibility)
- [Elicitation and MRTR](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)
- [go-sdk v1.7.0](https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.7.0)
- [Docker MCP Gateway issue #574](https://github.com/docker/mcp-gateway/issues/574)
