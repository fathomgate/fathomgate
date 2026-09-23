# ADR 0014: Refuse a stateful upstream's prompt to a stateless agent until parking is decided

- Status: proposed
- Date: 2026-09-23
- Deciders: Josh Scott (maintainer); proposed by mcp-protocol-engineer in T0.3

## Context

[ADR 0008](0008-dual-era-mcp-support.md) says a stateful (2025-era) upstream's server-initiated `elicitation/create` is "re-labelled with the upstream's name before forwarding, or converted to an `input_required` result for a 2026-era client". T0.3 implements the relabelling for every agent that can take the prompt. It does not implement the conversion. This record says why and asks for a decision.

The conversion is not a translation of one message. A stateful upstream sends `elicitation/create` while its `tools/call` is still open and waits for the answer on that same connection. A stateless (2026-07-28) agent cannot receive a server-initiated request at all: go-sdk refuses to send one on such a session, as the spec requires. To give that agent an `input_required` result, the proxy would have to answer the agent's `tools/call` now, keep the upstream's call and its pending `elicitation/create` open in proxy memory, and resume both when the agent sends a new `tools/call` with `inputResponses`. That is state the stateless era was designed to remove, held by a goroutine that outlives the agent's request, which the proxy's rules forbid without a documented owner, a bound and an expiry.

Two facts limit how much this matters today. go-sdk upstreams such as `netdev-ssh-mcp` negotiate 2026-07-28 and send MRTR `input_required`, which T0.3 passes to a stateless agent in full. And a stateful agent (most clients today) gets a stateful upstream's prompt relayed directly. The gap is one cell: stateless agent, stateful upstream that elicits mid-call. `upa/mcp-netmiko-server` (FastMCP 1.x) does not elicit. `junos-mcp-server` over streamable HTTP is the case matrix row 17 names for M3.

## Decision

We will refuse a stateful upstream's server-initiated `elicitation/create` while the calling agent is stateless, answering the upstream with a JSON-RPC error and the agent with a labelled tool error, and defer "parking" the upstream call until a real upstream needs it.

- The upstream gets a JSON-RPC error. The agent gets a tool result with `isError: true` and the text `netguard refused an input request (elicitation) from upstream <server> during <tool>: this client speaks 2026-07-28 and cannot receive a server-initiated prompt; see ADR 0014`. The upstream's prompt is never shown.
- netguard never answers `decline` or `cancel` on the user's behalf.
- Everything else in ADR 0008's translation rules is implemented as written. The mechanics (the sealed `requestState` envelope, the `_meta` allow-lists, the limits) are normative in [profile-schema section 8.4](../specs/profile-schema.md#84-protocol-eras-_meta-and-input-requests).
- If accepted, this record amends ADR 0008's clause "or converted to an `input_required` result for a 2026-era client" until a later record decides parking.

**Decision needed from the maintainer:** accept this refusal for M0, or require parking (alternative B below) before M0 closes. The rest of T0.3 does not depend on the answer.

## Consequences

### Positive

- No proxy-held session state toward a stateless agent, so the proxy stays restartable and the stateless era keeps its point.
- No goroutine outlives an agent request; every upstream call is bounded by the agent's context.
- The refusal is explicit and names its reason, so the agent can tell the user to use a 2025-era client or a 2026-era upstream.

### Negative

- A stateless agent cannot complete a call on a stateful upstream that elicits mid-call. Mitigation: that combination is not among M0's validation targets; row 17 (M3) can revisit it with a real upstream.
- ADR 0008 as accepted promises the conversion; accepting this record narrows that promise.

### Neutral

- The same parking machinery, if built, would not serve M3 holds: those live in the approval store and survive restarts (ADR 0004).

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| A. Refuse (this record) | Chosen for M0. |
| B. Park the upstream call: answer the agent with `input_required` and a sealed `requestState` naming a parked call; keep the upstream call and its pending `elicitation/create` open in a Proxy-owned table with a TTL (the envelope's 30 minutes), a cap on parked calls per upstream, and cancel-on-expiry; resume on the agent's retry | Workable and possibly needed for row 17. It adds a stateful component to a stateless path, loses every parked call on restart, needs a DoS bound, and cancelling a parked write tool at expiry may leave device-side state. Needs its own design and tests; better done against a real upstream that elicits. |
| C. Answer the upstream `decline` or `cancel` for the user | The proxy would speak for the human. The upstream may treat `decline` as consent to a fallback path. |
| D. Pin the agent to the stateful era | The agent chooses its era; the proxy serves what it asks for. |
| E. Advertise no elicitation to stateful upstreams | Loses the stateful-agent case, which works today, to avoid one refusal. |

## References

- [ADR 0008, dual-era MCP support](0008-dual-era-mcp-support.md)
- [ADR 0004, approval hold state machine](0004-approval-hold-state-machine.md)
- [profile-schema section 8.4](../specs/profile-schema.md#84-protocol-eras-_meta-and-input-requests)
- [MCP 2026-07-28 elicitation and MRTR](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)
- [Test matrix rows 2, 12 and 17](../testing/test-matrix.md)
- [M0 board](../milestones/M0.yaml), task T0.3
