# ADR 0018: Bound go-sdk's `server/discover` probe, then restart the upstream and connect with `initialize` only

- Status: accepted
- Date: 2026-09-24
- Deciders: Josh Scott (maintainer; decided 2026-09-23, option A; accepted 2026-09-24); proposed by docs-writer for T0.39; reviewers mcp-protocol-engineer, security-reviewer, go-reviewer

## Context

`netguard serve` cannot start in front of an upstream that does not answer `server/discover`. T0.34 found it while validating matrix row 2 against `upa/mcp-netmiko-server`: with the upstream's own `uv.lock` (`mcp` 1.6.0, protocol 2024-11-05) `netguard serve` exits 1 after 30 seconds with `proxy: upstream upa: connect: context deadline exceeded`. The case is a strict xfail, `test_locked_upstream_initialises_behind_netguard` in `tests/integration/test_upa_netmiko.py`, and row 2 in [the test matrix](../testing/test-matrix.md) records it against T0.39.

Three facts produce the hang. The first two are observed against one upstream, not guarantees; anything an upstream does is untrusted data.

| Fact | Where it is established |
| --- | --- |
| That upstream answers a 2025-11-25 `initialize` with `2024-11-05` in about 1 second | `test_locked_upstream_speaks_2024_11_05`, direct, no netguard |
| After a `server/discover` it answers nothing at all, not even a following `initialize`. Its stderr carries a pydantic `ValidationError` with `input_value='server/discover'`: the Python SDK's receive loop raised on the unknown method instead of replying `-32601` | `test_locked_upstream_stops_answering_after_server_discover`, direct, no netguard |
| go-sdk sends `server/discover` first whenever the requested protocol version is `2026-07-28` or newer, and falls back to `initialize` at `2025-11-25` only on an error reply. A probe that is never answered ends only when the caller's context does | go-sdk v1.8.0, `mcp/client.go`, `Client.Connect` |

netguard passes `nil` for `*mcp.ClientSessionOptions` at `internal/proxy/proxy.go:206`, so go-sdk requests its latest version and the probe always runs. `cmd/netguard/serve.go` gives spawn, handshake and `tools/list` a 30-second budget (`startupTimeout`), and that budget is what expires.

The defect is the upstream SDK's, and newer releases do not have it: with `mcp` 1.30.0 the same server answers the probe with an error and go-sdk's own fallback reaches `2025-11-25`, which is what tier 2 CI runs today. T0.39 records the affected range as Python MCP SDK 1.9.3 and older; netguard does not depend on the exact range, only on the behaviour it can observe. Servers on those releases are a large share of the network MCP servers in [research brief 01](../research/01-mcp-proxy-prior-art.md), so the proxy has to start in front of them.

This record changes upstream-side era detection, which [ADR 0008](0008-dual-era-mcp-support.md) fixes and [profile-schema 8.4](../specs/profile-schema.md#84-protocol-eras-_meta-and-input-requests) states normatively ("Upstream, once at connect: go-sdk sends `server/discover` and, if the upstream answers with any error or names no stateless version, falls back to the initialise handshake"). It also changes the exported `proxy.Upstream` struct that [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md) names.

## Decision

We will bound go-sdk's `server/discover` probe at 5 seconds; when it neither answers nor fails within that, netguard restarts the upstream and connects a second time with `initialize` only.

- The first `Client.Connect` for an upstream gets a 5-second context derived from the startup context. The bound is a constant in `internal/proxy`, with no CLI flag and no profile field in M0.
- Only a deadline exceeded on that first attempt triggers the retry. Every other connect error is returned as it is today, on the first attempt.
- Before the retry, netguard kills the upstream process and closes its connection, through the existing `trackedTransport.kill()` path, and starts the upstream again. The restart is not optional: the probe can leave the upstream answering nothing on that connection (observed above), and go-sdk offers no way to re-drive negotiation on a connected session.
- The second `Client.Connect` passes `&mcp.ClientSessionOptions{ProtocolVersion: "2025-11-25"}`. go-sdk sends `server/discover` only when the requested version is `2026-07-28` or newer, so the second attempt goes straight to `initialize` at `2025-11-25` and negotiates down from there, to `2024-11-05` if that is all the upstream knows.
- The second attempt is the last. If it fails, `netguard serve` reports the error and exits 1, as it does today.
- Before the restart netguard logs one line at `warn`: `upstream <server> did not answer server/discover within 5s; restarting it and connecting with initialize only (protocol 2025-11-25)`. The usual `upstream ready` line then reports the negotiated `protocol` and `era`.
- The bound and the single retry are per upstream. `startupTimeout` (30 seconds) is unchanged and still bounds spawn, both attempts and `tools/list` together.
- Restarting needs a second process, and an `mcp.CommandTransport` holds one `exec.Cmd`, which cannot be started twice. `proxy.Upstream` therefore has to carry something that builds a transport more than once rather than a built transport; `proxy.Command.Transport()` already returns a new `*mcp.CommandTransport` on every call. The exact exported shape is the owning task's to choose and to record in ADR 0012's API list and profile-schema 8.3.
- This record amends ADR 0008's rule that the proxy "may call `server/discover`" toward a 2026-era upstream, and the profile-schema 8.4 bullet quoted above: the fallback now also happens when the probe is not answered, and the second attempt is a new session on a new process.
- **This record supersedes nothing.** It changes one clause of [ADR 0008](0008-dual-era-mcp-support.md) (the `server/discover` fallback) and one of [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md) (the `Upstream{Server, Transport}` shape in its API list), not the whole of either, so both stay `accepted` and in force. Each carries a dated cross-reference row in its `Amendments` section instead, which is what [GOVERNANCE.md](../../GOVERNANCE.md#architecture-decisions) line 28 allows in place: "a factual correction that leaves the decision unchanged (a version, a module row, a stale path) may amend the record in place. The amendment is dated in the record's `Amendments` section with what changed and why." A pointer to this record changes no decision in the record that carries it. Orchestrator ruling, 2026-09-24.
- When this lands, the strict xfail `test_locked_upstream_initialises_behind_netguard` passes and its marker must be removed in the same pull request, and matrix row 2 loses its T0.39 caveat.

## Consequences

### Positive

- netguard starts in front of Python MCP SDK upstreams that predate `server/discover`, which is most of the installed base of network MCP servers. Matrix row 2's remaining case passes and M0 stops carrying it as a known hang.
- A silent upstream costs about 5 seconds instead of 30, and the warn line names the cause, so the operator is not left with `context deadline exceeded`.
- No new configuration. There is nothing for an operator to set, to get wrong, or to keep in step with an upstream's version.

### Negative

- netguard gives up the stateless era toward any upstream whose probe is slow rather than broken. An upstream that would have answered at 6 seconds is connected at `2025-11-25` and stays stateful for the life of the process, with no MRTR toward it, so netguard translates as ADR 0008 says and the agent still works, but the upstream loses a capability it has. Mitigation: 5 seconds is about five times the 1 second a real upstream took to answer a handshake in tier 2; the warn line names the bound; and the flag in alternative 2 stays available if a real upstream needs it.
- The upstream's start-up side effects run twice: a device connection, a licence check, a lock file, its own log lines. netguard cannot know what the first process did before it was killed. Mitigation: it happens only for an upstream that fails to answer the probe, only once per `netguard serve` start, and never mid-session.
- Startup takes up to 5 seconds longer than the upstream needs for these upstreams. The 30-second budget absorbs it; an operator's own start-up timeout, or an MCP host's, may not.
- `proxy.Upstream`'s exported field changes so its transport can be built twice, and every caller and test that constructs one changes with it. The in-memory transports the unit tests use cannot be rebuilt, so the retry path needs a rebuildable test transport of its own.
- One more branch in `connectUpstream`, on the path every other feature depends on.

### Neutral

- Nothing changes for an upstream that answers the probe, with a result or with an error: go-sdk's own negotiation and fallback run as they do today, and `netdev-ssh-mcp` still negotiates `2026-07-28`.
- The capabilities netguard advertises on the second attempt are the ones go-sdk already computes for its own `2025-11-25` fallback, form elicitation included. Passing the version explicitly does not change what the upstream is told.
- This decides how netguard connects, not which eras it speaks. ADR 0008's dual-era commitment stands on both sides.
- If go-sdk bounds the probe itself, or the affected upstream SDKs come to answer `-32601`, the retry becomes dead weight and this record can be superseded.

## Alternatives considered

| Alternative | Why not | Future work |
| --- | --- | --- |
| Leave it: let the 30-second startup limit fail the start | The proxy cannot front a large part of the installed base, and the error it prints (`context deadline exceeded`) names no cause, so the operator cannot act on it. Matrix row 2 stays open and M0 ships a known hang | Closed |
| A CLI flag or a per-upstream profile field that forces the era (`--upstream-protocol-version`) | It asks the operator to diagnose a defect in someone else's SDK before netguard will start, and it adds a CLI and profile-schema surface we then maintain and document. Detection costs 5 seconds and asks the operator for nothing | Stays open. If a real upstream turns out to be slow but alive, the flag is the escape hatch, in its own record |
| Always skip the probe: connect every upstream at `2025-11-25` | It gives up the stateless era on the upstream side for every upstream, `netdev-ssh-mcp` included, which negotiates `2026-07-28` today, and would make ADR 0008 false on the upstream side | Closed |
| Fix it upstream: ask go-sdk to bound its own probe, and the Python SDK to answer `-32601` for an unknown method | Right, and not on M0's clock: netguard controls neither release, and the upstreams already installed would not change | Stays open. T0.36 already addresses the maintainer to report a go-sdk conformance finding; the probe bound is a second report on the same path. When go-sdk bounds the probe, this record can be superseded |
| Keep the connection and send `initialize` on it after the probe times out | Observed behaviour is that the probe can kill the upstream's receive loop, so nothing more is answered on that connection; go-sdk also offers no way to re-drive negotiation on a session it has connected | Closed |
| Probe `server/discover` ourselves on a scratch connection before handing the transport to go-sdk | Same restart cost, plus a hand-written negotiation path outside go-sdk that has to track the spec as it moves | Closed |

## References

- [ADR 0008, dual-era MCP support](0008-dual-era-mcp-support.md) (amended by this record)
- [ADR 0012, `netguard serve` flags and the `internal/proxy` API for M0](0012-serve-cli-and-proxy-api-for-m0.md)
- [ADR 0014, stateful upstream prompts to stateless agents](0014-stateful-upstream-prompts-to-stateless-agents.md)
- [profile-schema 8.3, `netguard serve` flags](../specs/profile-schema.md#83-netguard-serve-flags) and [8.4, protocol eras](../specs/profile-schema.md#84-protocol-eras-_meta-and-input-requests)
- [Test matrix, row 2](../testing/test-matrix.md)
- `tests/integration/test_upa_netmiko.py`: `test_locked_upstream_speaks_2024_11_05`, `test_locked_upstream_stops_answering_after_server_discover`, `test_locked_upstream_initialises_behind_netguard`
- go-sdk v1.8.0 source: `mcp/client.go` (`Client.Connect`, `Client.discover`, `ClientSessionOptions.ProtocolVersion`), `mcp/shared.go` (`supportedProtocolVersions`); the probe is SEP-2575, cited in `Client.Connect`
- `internal/proxy/proxy.go` (`connectUpstream`, `trackedTransport.kill`), `internal/proxy/command.go` (`Command.Transport`), `cmd/netguard/serve.go` (`startupTimeout`)
- [MCP 2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
- [Research brief 01, section 1](../research/01-mcp-proxy-prior-art.md)
- [M0 board](../milestones/M0.yaml): T0.39 (this decision), T0.25 (upstream exit status at startup, done together), T0.34 (where it was found), T0.36 (the upstream report path)
