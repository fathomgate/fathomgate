# ADR 0014: Refuse a stateful upstream's prompt to a stateless agent in M0; defer parking to row 17

- Status: accepted
- Date: 2026-09-23
- Deciders: Josh Scott (maintainer; accepted 2026-09-23); proposed by mcp-protocol-engineer in T0.3, security-reviewer recommended option A

## Context

[ADR 0008](0008-dual-era-mcp-support.md) says a stateful (2025-era) upstream's server-initiated `elicitation/create` is "re-labelled with the upstream's name before forwarding, or converted to an `input_required` result for a 2026-era client". T0.3 implements the relabelling for every agent that can take the prompt, but not the conversion. This record explains why the conversion is left out and when it may be revisited.

The conversion is not a translation of one message. A stateful upstream sends `elicitation/create` while its `tools/call` is still open, and it waits for the answer on that same connection. A stateless (2026-07-28) agent cannot receive a server-initiated request at all: go-sdk refuses to send one on such a session, as the spec requires. To give that agent an `input_required` result, the proxy would have to do three things:

- answer the agent's `tools/call` now;
- keep the upstream's call and its pending `elicitation/create` open in proxy memory;
- resume both when the agent sends a new `tools/call` with `inputResponses`.

That is the kind of state the stateless era was designed to remove. It would also be held by a goroutine that outlives the agent's request, which the proxy's rules forbid without a documented owner, a bound and an expiry.

Two facts limit how much this matters today:

- go-sdk upstreams such as `netdev-ssh-mcp` negotiate 2026-07-28 and send MRTR `input_required`. T0.3 passes that to a stateless agent in full.
- A stateful agent (most clients today) gets a stateful upstream's prompt relayed directly.

So the gap is one cell: a stateless agent calling a stateful upstream that elicits mid-call. `upa/mcp-netmiko-server` (FastMCP 1.x) does not elicit. The case matrix row 17 names for M3 is `junos-mcp-server` over streamable HTTP.

## Decision

In M0 we will refuse a stateful upstream's server-initiated `elicitation/create` while the calling agent is stateless. The upstream gets a JSON-RPC error and the agent gets a labelled tool error. "Parking" the upstream call (option B) is deferred to matrix row 17 and must meet the requirements below before it is built.

- The upstream gets a JSON-RPC error. The agent gets a tool result with `isError: true` and the text `netguard refused an input request (elicitation) from upstream <server> during <tool>: this client speaks 2026-07-28 and cannot receive a server-initiated prompt; see ADR 0014`. The upstream's prompt is never shown.
- netguard never answers `decline` or `cancel` on the user's behalf.
- Everything else in ADR 0008's translation rules is implemented as written. The mechanics (the sealed `requestState` envelope, the schema allow-list, the `_meta` allow-lists and the limits) are normative in [profile-schema section 8.4](../specs/profile-schema.md#84-protocol-eras-_meta-and-input-requests).
- This record amends ADR 0008's clause "or converted to an `input_required` result for a 2026-era client" until a later record decides parking.

Requirements for option B, if row 17 needs it:

1. **Single-use ids.** A parked call is resumed by a single-use id inside the sealed `requestState`, consumed on first use. The M0 envelope may be replayed within its expiry, and that is not acceptable for a held upstream call.
2. **Per-upstream cap with cancel-on-expiry.** At most a fixed number of parked calls per upstream. A parked call that reaches its expiry is cancelled toward the upstream and reported in the audit log. The record must say what a cancelled write tool means on the device.
3. **Parked calls count as in flight.** A parked call counts as in flight on its upstream, so while it waits, no other stateful prompt from that upstream can be attributed, and those prompts are refused, as today.
4. **Cross-request tying.** A parked call must be tied to the later agent request that resumes it after the original request's context has ended. The tie must hold the same agent session (and principal, once Streamable HTTP lands) and the same arguments. A Proxy-owned goroutine must own the upstream call in between, and `Proxy.Close` must end it.

## Consequences

### Positive

- The proxy holds no session state toward a stateless agent, so it stays restartable and the stateless era keeps its point.
- No goroutine outlives an agent request; every upstream call is bounded by the agent's context.
- The refusal is explicit and gives its reason, so the agent can tell the user to use a 2025-era client or a 2026-era upstream.

### Negative

- A stateless agent cannot complete a call on a stateful upstream that elicits mid-call. Mitigation: that combination is not among M0's validation targets, and row 17 (M3) revisits it with a real upstream.
- ADR 0008's promise of the conversion is narrowed until then.

### Neutral

- If the parking machinery is built, it would not serve M3 holds: those live in the approval store and survive restarts (ADR 0004).

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| A. Refuse (this record) | Chosen for M0. |
| B. Park the upstream call: answer the agent with `input_required` and a sealed `requestState` naming a parked call; keep the upstream call and its pending `elicitation/create` open in a Proxy-owned table; resume on the agent's retry | Deferred to row 17. It adds a stateful component to a stateless path, loses every parked call on restart, needs a DoS bound, and cancelling a parked write tool at expiry may leave state on the device. It must meet the four requirements above. |
| C. Answer the upstream `decline` or `cancel` for the user | The proxy would speak for the human, and the upstream may treat `decline` as consent to a fallback path. |
| D. Pin the agent to the stateful era | The agent chooses its era; the proxy serves what it asks for. |
| E. Advertise no elicitation to stateful upstreams | Gives up the stateful-agent case, which works today, to avoid one refusal. |

## References

- [ADR 0008, dual-era MCP support](0008-dual-era-mcp-support.md)
- [ADR 0004, approval hold state machine](0004-approval-hold-state-machine.md)
- [profile-schema section 8.4](../specs/profile-schema.md#84-protocol-eras-_meta-and-input-requests)
- [MCP 2026-07-28 elicitation and MRTR](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)
- [Test matrix rows 2, 12 and 17](../testing/test-matrix.md)
- [M0 board](../milestones/M0.yaml), task T0.3
