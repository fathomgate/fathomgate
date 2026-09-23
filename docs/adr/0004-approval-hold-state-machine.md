# ADR 0004: Approval hold state machine

- Status: accepted
- Date: 2026-09-23
- Deciders: Josh Scott

## Context

A `WRITE_CONFIG` call on a production device should wait for a human. Agent frameworks (Claude Agent SDK `defer`, OpenAI Agents `RunState`, LangGraph `interrupt`) all externalise a serialisable pending state keyed by an id and resume by re-invoking with the decision attached. None owns TTL, notification or approver identity. Ops tooling does: HCP Terraform has a `Needs Confirmation` state with terminal Applied, Discarded and Canceled; AWX approval nodes time out into a terminal `timed out` state. See [research brief 03, section 2](../research/03-policy-and-approval-patterns.md).

The MCP 2026-07-28 spec models human input as MRTR: the server returns `input_required` with an opaque `requestState`, and the client retries with `inputResponses`. 2025-era clients only have server-initiated elicitation, and client support is uneven. An in-band answer comes from the same session as the requester, so it cannot by itself satisfy separation of duties.

LangGraph's documentation warns that a node re-runs from the top on resume, so pre-interrupt side effects must be idempotent. A retried `tools/call` must never push a change twice.

## Decision

We will hold a call by persisting a pending record in SQLite and moving it through a fixed state machine: PENDING, then APPROVED, DENIED, EXPIRED or CANCELLED; APPROVED then EXECUTED or FAILED.

- The pending record is the source of truth. It stores the rendered change, the dry-run output reference and the diff hash.
- TTL is mandatory and expiry is terminal. A late approve or deny is refused and audited.
- On approval the proxy re-runs the dry-run and cancels the record if the diff hash changed (drift guard).
- Approve or deny arrives through `netguard approve <id>` / `netguard deny <id>`, a signed webhook (`POST /approvals/{id}`, HMAC over the body), or an in-band MRTR elicitation for the single-operator case.
- Approver identity is established server-side, never taken from the agent. `approver_must_differ` compares authenticated identities.
- Execution is keyed by pending id, so a retried `tools/call` finds the record EXECUTED and returns the stored result.
- Upstream elicitation prompts are re-labelled with their origin server before reaching the client.

The normative protocol is [approval-protocol.md](../specs/approval-protocol.md).

## Consequences

### Positive

- Same semantics regardless of channel; a Slack button and the CLI write to one store.
- Copying the HCP Terraform and AWX patterns means operators already know the states.
- The words in the UI, CLI, audit log and docs are the state names: Holding, Approved, Denied, Expired, Executed, Failed.

### Negative

- SQLite adds a file the proxy must protect. Mitigated by keeping only hashes and references in it, not raw output.
- Two hold shapes (MRTR result vs tool error) until 2025-era clients disappear. Mitigated by [ADR 0008](0008-dual-era-mcp-support.md).
- Drift guard needs a second dry-run against the device at approval time. Accepted; a stale diff is worse than a slower approval.

### Neutral

- Which clients support MRTR decides whether in-band approval ships in M3 or later; CLI and webhook ship regardless.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| In-memory pending map | Lost on restart; cannot be approved from a CLI in another process. |
| Elicitation as the only channel | Uneven client support; same-session answer cannot satisfy separation of duties. |
| Block the `tools/call` and wait | Ties up the connection for the TTL; 2026-era HTTP is stateless and the response stream may close. |
| No TTL | AWX issue #13465 shows why expiry must be terminal and visible. |

## References

- [Research brief 03, section 2](../research/03-policy-and-approval-patterns.md)
- [MCP elicitation, 2026-07-28](https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation)
- [MCP 2026-07-28 release post, MRTR](https://blog.modelcontextprotocol.io/posts/2026-07-28/)
- [HCP Terraform run states](https://developer.hashicorp.com/terraform/cloud-docs/workspaces/run/states)
- [AWX approval timeout issue](https://github.com/ansible/awx/issues/13465)
- [OpenAI Agents human-in-the-loop](https://openai.github.io/openai-agents-python/human_in_the_loop/)
- [LangGraph interrupts](https://docs.langchain.com/oss/python/langgraph/interrupts)
- [Claude Agent SDK hooks](https://code.claude.com/docs/en/agent-sdk/hooks)
- [Docker MCP Gateway issue #574, unattributed elicitation](https://github.com/docker/mcp-gateway/issues/574)
