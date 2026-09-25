# ADR 0023: `serve --listen` binds both loopback families, and three smaller listener changes

- Status: proposed
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer; to accept); proposed by mcp-protocol-engineer for T0.52 (the post-merge security and Go reviews of PR #109); reviewers security-reviewer, go-reviewer
- Amends: [ADR 0016](0016-streamable-http-listener.md), in the four points under *Decision*; everything else in ADR 0016 stands

## Context

[ADR 0016](0016-streamable-http-listener.md) binds `--listen` to one loopback address: `localhost` is bound as `127.0.0.1` and never resolved, and `[::1]` is bound as itself. The security review of PR #109 rated that high (H1) and reproduced it on a Windows host. With fathomgate on `127.0.0.1:P` only, another local user binds `[::1]:P`. An agent configured with `http://localhost:P/mcp` resolves `localhost` to `::1` and `127.0.0.1`, tries `::1` first (as most resolvers order it), reaches the other user's socket and sends its bearer token. The same holds the other way round for `--listen [::1]:P` and a client that tries IPv4 first. The token then works against fathomgate itself, which forwards every call in M0.

The same reviews found three smaller things that also change what ADR 0016 fixed:

- L1: a connection that sends no request holds one of the 128 connection slots for the whole `ReadHeaderTimeout` (10 seconds) without a token.
- Go review, item 1: the shutdown grace waits for every request but GET, so a 2026-era agent's `subscriptions/listen` stream, a POST that never ends on its own, would hold every shutdown to the full 5 seconds. Today go-sdk answers such a request on fathomgate at once, because the proxy declares no `listChanged` capability and so no subscription is kept open; the change is for the day it does.
- N2 and Go review, item 2: a second SIGINT or SIGTERM during shutdown is ignored.

## Decision

We will bind the other loopback family on the same port as the address asked for, refuse to start when it is taken, and make the three smaller changes below.

1. **Both loopback families.** After binding the address asked for (`localhost` still means `127.0.0.1`, never resolved), `serve` binds the other family's loopback on the port it got: `[::1]` for any IPv4 loopback address, `127.0.0.1` for `[::1]`. Both are served by the one `http.Server`, and the 128-connection cap is shared between them. Every failure of that second bind refuses to start (exit 1, before the upstream is started, naming the address and no token), except the errors that mean the host has no loopback of that family (`EADDRNOTAVAIL`, `EAFNOSUPPORT`, `EPROTONOSUPPORT`, and their Winsock equivalents), which log a warning and serve on one family. With port `0`, a taken port is retried with a new one, up to 8 times. `serve` logs one `listening url=...` line per bound address, the address asked for first, and the install guide tells operators to paste a URL from that line, IP literal included, into the client rather than write `localhost`.
2. **First request header timeout.** A new connection must send its first request's headers within 3 seconds of being accepted (`firstHeaderTimeout`). Later requests on a kept-alive connection keep `ReadHeaderTimeout` (10 seconds) and `IdleTimeout` (120 seconds). Every refusal already carries `Connection: close` (T0.27), which the tests now also pin through `cmd/fathomgate`'s server.
3. **Shutdown grace.** A request whose `Mcp-Method` header is `subscriptions/listen` is not counted as in flight, as GET is not. go-sdk answers 400 to a 2026-era request whose header and body disagree, so the header cannot hide a tool call from the grace; a 2025-era request that sends it only gives up its own grace.
4. **Second signal.** Once the first SIGINT or SIGTERM has started the shutdown, fathomgate stops catching signals, so a second one ends it at once with the default action. Nothing is cleaned up after that second signal.

`localhost` stays accepted as a flag value. Binding both families covers what a client may resolve `localhost` to, so there is no reason left to refuse it, and refusing it would break the copy-paste of `http://localhost:P` that most MCP client docs show.

## Consequences

### Positive

- H1 is closed while fathomgate runs: no other user can bind either loopback family on its port, and a squatter that got there first stops it from starting instead of receiving tokens.
- A client can use `localhost`, `127.0.0.1` or `[::1]` and reach fathomgate.
- A client without a token holds a slot for 3 seconds at most before it sends a request, and until the refusal after that.
- Once the proxy keeps listen streams open, shutdown with a 2026-era agent attached will still take as long as the calls in flight, not 5 seconds.

### Negative

- A second port is held. An operator who runs something else on `[::1]:P` next to fathomgate on `127.0.0.1:P` now gets a refusal; the message names the address and says to stop that program or pick another port.
- Nothing stops another user from taking the port while fathomgate is down or restarting, and an agent cannot authenticate fathomgate. That is a separate, open threat-model row, fixed in M1 by TLS with a pinned certificate or by a Unix socket or named pipe protected by file permissions.
- A local user can still keep the 128 slots busy by opening connections faster than they time out: about 43 a second instead of about 13. That raises the cost; it does not remove it. The residual is recorded in the threat model.
- The first-request timeout rests on `net/http` setting the header read deadline as its first read deadline on a new plain-HTTP connection (`conn.serve`, Go 1.26). `TestFirstHeaderTimeout` fails if a Go release changes that.
- A second signal leaves the upstream running when it is a launcher's grandchild or ignores stdin EOF (the orphaned-grandchild threat-model row, [ADR 0021](0021-kill-the-upstream-process-tree.md)).

### Neutral

- `--listen` keeps its syntax and its refusals. Scripts that read the first `listening` line still get the address asked for.
- No change to `internal/proxy`'s exports ([ADR 0022](0022-internal-proxy-export-surface.md)).

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Refuse `localhost` and require `127.0.0.1` or `[::1]` | Closes H1 only for clients configured with an IP literal, and an operator who writes `localhost` in the client (as most MCP docs do) while fathomgate listens on `127.0.0.1` is exposed again. Binding both works whatever the client writes. |
| Bind the other family and keep it closed (accept nothing) | Denies the squatter as well, but a client that tries `::1` first then fails or waits for its fallback. Serving both is as safe and works. |
| Bind a dual-stack `[::]` socket with `IPV6_V6ONLY` off | That is the wildcard address, not loopback: it accepts connections from other hosts. |
| Leave H1 to M1's TLS | M1 is weeks away and M0 ships a listener that forwards every call; H1 is high. |
| A 3-second `ReadHeaderTimeout` for every request | Would also cut slow but authenticated clients on later requests, and changes a limit ADR 0016 set for reasons unrelated to L1. |
| Record L1 as a residual with no code | The code change is small and pinned by a test; a residual alone would leave the 10-second hold. |

## References

- [ADR 0016](0016-streamable-http-listener.md), CLI surface (`--listen`) and limit 8 (`ReadHeaderTimeout`), and its J4 shutdown grace
- [profile-schema 8.3 and 8.5](../specs/profile-schema.md#85-http-listener)
- [docs/install.md, Remote agents over HTTP](../install.md#remote-agents-over-http)
- [Threat model](../security/threat-model.md): rows on the loopback family squat, port squatting while down, and resource exhaustion
- Post-merge security review of PR #109 (H1, L1, N2) and Go review of PR #109 (items 1, 2 and 5), T0.52
- [MCP transports, security warning](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports#security-warning)
