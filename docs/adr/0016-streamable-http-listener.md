# ADR 0016: A Streamable HTTP listener for `netguard serve`, loopback-only and token-authenticated

- Status: proposed
- Date: 2026-09-23
- Deciders: Josh Scott (maintainer; decided that netguard gets an HTTP listener toward the agent); proposed by mcp-protocol-engineer
- Amends: [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md) (adds flags and one exported method; nothing in it is withdrawn) and the sentence "The agent side is stdio" in [profile-schema section 8.3](../specs/profile-schema.md#83-netguard-serve-flags)

## Context

Today `netguard serve` talks to the agent only over stdio ([ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md)). The maintainer has decided that it will also serve Streamable HTTP toward the agent. [ADR 0002](0002-standalone-proxy-not-gateway-plugin.md) and [PLAN.md](../PLAN.md) already promise "stdio and Streamable HTTP on both sides", but no record defines the listener. Four facts force decisions now.

1. **The trust boundary moves.** A stdio pipe is private to the host process that spawned netguard. A TCP socket, even on loopback, can be reached by every local user, every local process and, through DNS rebinding, any web page open in a browser on that host. In M0 netguard forwards every call with no policy. An unauthenticated listener would therefore hand `EXEC_ARBITRARY` on network devices to anything that can open a connection. The MCP transport spec requires servers to validate `Origin` and answer 403 when it is invalid, recommends binding to localhost when running locally, and recommends authentication on every connection.
2. **go-sdk v1.8.0 cannot serve both eras from one handler.** `mcp.NewStreamableHTTPHandler` runs in one of two modes, chosen by `StreamableHTTPOptions.Stateless`:
   - With `Stateless: false`, `serveStatefulPOST` rejects every 2026-07-28 request except `server/discover` with `CodeUnsupportedProtocolVersion` and HTTP 400 ("set StreamableHTTPOptions.Stateless = true to accept it").
   - With `Stateless: true`, 2025-era requests are served on a throwaway session with made-up initialise parameters and no `Mcp-Session-Id`. Server-to-client requests are refused, so a stateful agent loses the relayed `elicitation/create` that [ADR 0008](0008-dual-era-mcp-support.md) and profile-schema 8.4 promise it.
   go-sdk's own `everything-server` avoids the problem by being started once per revision (`-stateless`). [ADR 0008](0008-dual-era-mcp-support.md) needs both eras on one endpoint.
3. **Conformance is HTTP-only.** The official suite tests servers only over Streamable HTTP. Today it reaches netguard through `tests/conformance/relay.py`, so the 12 `server-stateless:sep-2575-*` HTTP checks in `baseline/netguard-2026-07-28.yml` measure the relay, not netguard ([tests/conformance/README.md](../../tests/conformance/README.md)). The suite has no option to send an `Authorization` header or to map tool names, and it calls fixed names (`test_simple_text`) where netguard exposes `conf.test_simple_text` ([profile-schema 8.1](../specs/profile-schema.md#81-tool-name-prefixing)).
4. **Session binding was left for this step.** profile-schema 8.4 ("Accepted for M0") and the [SECURITY.md](../../SECURITY.md#proxy-transport-m0-gaps) gap table say the sealed `requestState` envelope and the attribution of stateful prompts name no agent session, because stdio has one, and that both must be bound "once Streamable HTTP serves several". T0.17 (progress relay) will add a second piece of per-call state, the proxy-issued progress token, and it has the same problem.

What go-sdk v1.8.0 provides and what netguard must add (read from the module source, `mcp/streamable.go`, `mcp/streamable_headers.go`, `auth/auth.go`, `internal/util/net.go`):

| Concern | go-sdk v1.8.0 | netguard adds |
| --- | --- | --- |
| Stateful 2025-11-25 sessions | `Stateless: false`: `Mcp-Session-Id` from `crypto/rand.Text` (130 bits) set on the `initialize` response, GET stream, DELETE, `SessionTimeout` for idle sessions | A cap on concurrent sessions (go-sdk has none) |
| Stateless 2026-07-28 | `Stateless: true`: a session per request, `_meta` and `MCP-Protocol-Version` agreement checks, HTTP 400 and 404 status mapping, `PropagateRequestCancellation` | Nothing |
| Both eras on one endpoint | Not offered (point 2) | A front dispatcher over two go-sdk handlers that share the one `mcp.Server` |
| `MCP-Protocol-Version` | Unsupported pre-2026 value gets 400; absent is treated as 2025-03-26; a 2026 request must carry it and it must equal `_meta` | Routing on it (dispatcher) |
| `Mcp-Method` and `Mcp-Name` | `validateMcpHeaders` compares them with the body for 2026 requests, 400 on mismatch. It compares `Mcp-Name` raw, without decoding Base64-sentinel values | Nothing: exposed tool names are limited to `[A-Za-z0-9_.-]` (8.1), so no client encodes them, and the raw comparison meets ADR 0008 |
| DNS rebinding (Host) | On by default: a request that arrives on a loopback address with a non-loopback `Host` gets 403 | Keep it on |
| `Origin` | Nothing by default. The deprecated `CrossOriginProtection` option wraps the standard library's, which exempts GET, HEAD and OPTIONS and accepts `Origin` equal to `Host`, which is what a rebinding page sends | Its own check on every method: 403 for any `Origin` header or a cross-site `Sec-Fetch-Site` (Decision, step 3) |
| Authentication | `auth.RequireBearerToken(verifier, opts)` middleware; `TokenInfo.UserID` is bound to a session at `initialize`, and a later request from another user gets 403 | The verifier (constant-time comparison with a token loaded from a file or the environment) and the principal name |
| Body size | `MaxRequestBodyBytes`, default 4 MiB, 413 when exceeded | Set it explicitly, so a go-sdk default change does not move it |
| Timeouts, connection and request caps, TLS | Not in the handler | `http.Server` settings, a connection-limiting listener, an in-flight cap; no TLS in this step |
| Compatibility switches | `MCPGODEBUG=allowsessionsinstateless=1` and others, read from the environment at start-up | Refuse to listen while `MCPGODEBUG` is set |

The module graph does not change. `auth` imports only `go-sdk/oauthex` and the standard library. `golang.org/x/oauth2`, already in the graph ([ADR 0011](0011-accept-go-sdk-transitive-modules.md)), stays unreached from the server side.

## Decision

We will add `netguard serve --listen <loopback-ip-or-localhost>:<port>`, which serves Streamable HTTP at `/mcp` instead of stdio. It is bound to loopback only in M0 and needs a bearer token read from a file or the environment on every request. It serves both protocol eras on one endpoint through a dispatcher in front of two go-sdk handlers. The upstream stays one stdio process.

### CLI surface

```text
netguard serve --server <name> --upstream <path> [--upstream-env KEY=VALUE]...
               [--listen <addr>:<port> (--listen-token-file <path> | env NETGUARD_LISTEN_TOKEN)]
               [-- <upstream args>...]
```

| Flag | Meaning |
| --- | --- |
| `--listen` | Serve Streamable HTTP at `http://<addr>:<port>/mcp` instead of stdio. The two agent sides are exclusive: with `--listen`, netguard neither reads stdin nor writes stdout. `<addr>` must be written out and must be `localhost` (bound as `127.0.0.1`, never resolved), an IPv4 address in `127.0.0.0/8`, or `[::1]`. Anything else is refused with exit 2 in M0: `0.0.0.0`, `[::]`, a bare `:port`, a LAN address, a hostname. Port `0` asks the OS for a free port. |
| `--listen-token-file` | Path to the bearer token. The file must be a regular file with one link, owned by the user running netguard and owner-only (the checks `internal/audit` applies to its key since T0.12: mode `0600` on Unix, protected owner-only DACL on Windows). One trailing newline is stripped. |
| `NETGUARD_LISTEN_TOKEN` | The token from the environment, for MCP hosts and containers that inject secrets there. Setting both it and `--listen-token-file` is exit 2. Like every `NETGUARD_*` variable it never reaches the upstream (ADR 0012's allow-list, and ADR 0017 if accepted). |

- `--listen` with no token is exit 2. A token shorter than 32 bytes, or containing white space or control characters, is exit 2. The token never appears in argv, logs, errors or audit lines. README documents generating one (`openssl rand -hex 32`, or PowerShell's `RandomNumberGenerator`).
- Only `/mcp` is served; any other path is 404. There is no path flag. A reverse proxy that needs another path can rewrite it.
- ADR 0012's reserved flags (`--policy`, `--inventory`, `--profiles`, `--audit`) stay refused with or without `--listen`. The listener does not change what M0 enforces, which is nothing. The `--listen*` flags are not added to the reserved scan: an upstream argument after `--` that happens to be named `--listen` belongs to the upstream.
- At start-up netguard logs one line on stderr, `listening url=http://127.0.0.1:<port>/mcp`, with the real port, so scripts and tests read the address instead of racing for a free port.
- Exit status: 0 on SIGINT or SIGTERM; 1 if the address cannot be bound, the upstream cannot be started, or the upstream exits while serving; 2 for a usage error. When the upstream exits, netguard stops accepting, finishes open responses with the existing "upstream is not running" tool error, and exits 1 so a supervisor can restart it. A long-running listener must not keep answering for a dead upstream. Shutdown gives in-flight requests 5 seconds, then closes the sessions, then runs ADR 0012's upstream shutdown.
- If `MCPGODEBUG` is set in netguard's environment, `--listen` is refused with exit 2 and the variable named. Its switches, `allowsessionsinstateless=1` among them, would change transport security without appearing on the command line.

**Reserved for M1, refused in M0:** `--listen-remote` and `--listen-host <name>` (repeatable). From M1, when a policy stands between the listener and the devices, `--listen-remote` allows a non-loopback address, such as `0.0.0.0` inside a container. It requires at least one `--listen-host`: requests whose `Host` is not in that list, or not the literal bound address, get 403. It serves plain HTTP only, and TLS is terminated in front (open question 1). In M0 both flags are refused with exit 2, and the message says the listener is loopback-only until the policy pipeline is wired. So a copied container snippet fails loudly rather than exposing a policy-free proxy to a network, in the same way ADR 0012 refuses `--policy`.

### Request handling, in order

Each request passes these checks in order. The first failure answers, and nothing later runs.

1. **Connection cap.** At most 128 open TCP connections (a small limiting `net.Listener`, standard library only). Further connections wait in the kernel backlog.
2. **Host.** go-sdk's localhost protection stays on (`DisableLocalhostProtection` is never set): a non-loopback `Host` on the loopback bind gets 403.
3. **Origin.** A request carrying any `Origin` header (including `null`), or `Sec-Fetch-Site` with a value other than `none` or `same-origin`, gets 403. This applies to every method, GET and DELETE included, and before authentication. MCP agents are not browsers and do not send `Origin`; a browser always sends it on POST. So this closes DNS rebinding and cross-site POSTs without an allow-list. netguard sends no CORS headers and answers OPTIONS with 405. Browser-hosted clients are out of scope for this step.
4. **Authentication.** Through go-sdk's `auth.RequireBearerToken` with a netguard verifier: `Authorization: Bearer <token>`, compared in constant time over SHA-256 digests, so neither the length nor the content leaks through timing. On failure: 401 with `WWW-Authenticate: Bearer` (no `resource_metadata` until OAuth resource-server mode exists). On success, `TokenInfo.UserID` is the principal `token:<first 12 hex digits of SHA-256(token)>` and `AllowMissingExpiration` is set. Failed attempts are logged at warn with the remote address and the reason, at most once per second. The header is never logged.
5. **In-flight cap.** At most 64 concurrent POSTs across all sessions, counting long-lived 2026 `subscriptions/listen` streams. The 65th gets 503 with `Retry-After: 1`.
6. **Era dispatch.** If `MCP-Protocol-Version` is present and at least `2026-07-28` (string comparison, as `era.go` does), the request goes to the stateless handler (`Stateless: true`, `PropagateRequestCancellation: true`), which ignores `Mcp-Session-Id`. Everything else goes to the stateful handler (`Stateless: false`): `initialize`, requests carrying `Mcp-Session-Id`, 2025-era requests with or without the header, and malformed ones, which get go-sdk's own error. Both handlers serve the one `mcp.Server` that `proxy.New` builds, so tools, middleware (`refuseUndeclared`, `checkToolName`) and the `requestState` sealer are shared, and a 2026 MRTR retry reaches the process that sealed it. Neither handler sets `JSONResponse`, so responses are SSE and upstream prompts and notifications can stream. Neither has an `EventStore`: no resumption, which 2026-07-28 deprecates.
7. **Session cap.** An `initialize` without a session id, when 16 stateful sessions are already open, gets 503 before go-sdk creates the session. netguard counts stateful sessions itself: `Server.Sessions` also lists the per-request sessions of stateless requests. Idle stateful sessions close after 30 minutes (`SessionTimeout`).
8. **Limits in go-sdk and `net/http`.** Body 4 MiB (`MaxRequestBodyBytes`, set explicitly; 413). Headers 64 KiB (`MaxHeaderBytes`). `ReadHeaderTimeout` 10 seconds. The body must arrive within 30 seconds: a per-request read deadline set through `http.ResponseController` and cleared once go-sdk has read the body. This is not the server-wide `ReadTimeout`, which would cut long SSE responses. No `WriteTimeout`, because tool calls and prompts can take minutes; M1's per-call deadline bounds them. `IdleTimeout` 120 seconds.

These limits are constants in this step, not flags. A flag is added when a real deployment needs a different value.

### Protocol eras over HTTP

- **2025-11-25 (stateful).** Initialise handshake, `Mcp-Session-Id`, GET stream and DELETE, all from go-sdk. A stateful upstream's `elicitation/create` is relayed on the POST stream of the call it belongs to (go-sdk routes a request made under the handler's context there). The attribution rule stays as in profile-schema 8.4: exactly one call in flight on that upstream, counted across every agent session, or the prompt is refused. With several agents that refusal becomes more likely. That is accepted, because the alternative is guessing which agent a prompt is for. A 2025 agent that drops its POST does not cancel the call (go-sdk detaches the handler context on stateful streams). The call ends with `notifications/cancelled`, a DELETE of the session, the idle timeout, or `Proxy.Close`. The go-sdk session owns it until then, and that is its documented owner.
- **2026-07-28 (stateless).** No session. `_meta` and `MCP-Protocol-Version` must agree, and `Mcp-Method` and `Mcp-Name` must match the body (go-sdk, 400 otherwise). MRTR `input_required` with netguard's sealed `requestState` as in 8.4. Closing the POST cancels the upstream call (`PropagateRequestCancellation`). A stateful upstream's prompt to a stateless agent is still refused ([ADR 0014](0014-stateful-upstream-prompts-to-stateless-agents.md)).
- Era detection per request, the `_meta` allow-lists and the error table in profile-schema 8.2 and 8.4 do not change. The transport (`stdio` or `http`) and the principal join the era on the `call` that `Proxy.dispatch` receives, for the M1 pipeline and the M4 audit event.

### Principals, sessions and per-call state

- **Approver identity (invariant 6).** The bearer token authenticates the requester, the agent side. Nothing that arrives over the listener establishes an approver: not the token principal, a header, `_meta`, a tool argument or an elicitation answer. ARCHITECTURE.md attributes an MRTR approval to "the client principal" and lets it satisfy `approver_must_differ` only when that principal differs from the requester. With one static token, every agent and every answer is the same principal, so an MRTR answer over this listener can never satisfy `approver_must_differ`. M3 approvals for such rules go through the CLI or the signed webhook until per-user principals exist (open question 3). Approvals never travel as upstream prompts (SECURITY.md).
- **Sealed `requestState`.** The envelope gains the principal. Opening it fails with `invalid_request_state` when the retry comes from another principal, as it does today for another tool or other arguments. Stateless requests have no session to bind to, and a 2025 agent never receives a `requestState` (it gets `elicitation/create`), so the principal is the binding. With one token the check is nominal. It is built now so that multi-token or OAuth principals are bound from their first day. The envelope prefix moves from `ng2.` to `ng3.`; restarts already invalidate envelopes, so nothing migrates.
- **Progress tokens (T0.17).** The agent's `progressToken` is chosen by the agent, and two sessions can pick the same value. When T0.17 relays progress, the token sent upstream must be proxy-generated and random, and must map to exactly one agent request (session or stateless POST, request id, principal). The notification must go out under that request's context, so it reaches only that POST's stream. The mapping is deleted when the call ends. A hostile upstream can still swap progress between two of its own calls. Only progress, total and an escaped, labelled message can cross that way, which is accepted.
- **Session ids.** go-sdk's default `crypto/rand.Text` stays; `ServerOptions.GetSessionID` is never overridden. Logs show a session id as the first 12 hex digits of its SHA-256, never in full.

### Upstream side

The upstream stays one stdio process started by `--upstream`. An HTTP upstream (`junos-mcp-server` over streamable-http, matrix row 17) needs outbound credentials, TLS verification and an egress policy. Those are separate decisions, for a separate record in M1 or M3. `proxy.New` already takes a slice, so that record does not change the API.

### `internal/proxy` API

One export is added to ADR 0012's set: `(*Proxy).HTTPHandler(HTTPOptions) (http.Handler, error)`. It returns the whole chain above, from the Host check to the dispatcher, with the go-sdk handlers created inside. `HTTPOptions` carries the token bytes, and exported fields for the caps and the session timeout whose zero values mean the defaults above. It has no field that turns a check off. `cmd/netguard` owns the listener, the connection cap, the `http.Server` settings, the token file and the lifecycle. `Proxy.Run(ctx, mcp.Transport)` stays for stdio.

### Testing

- **Tier 1** (`internal/proxy`, `cmd/netguard`, `httptest` plus the recording fake upstream, both eras in one table): 401 without a token, with a wrong token and with a truncated one; 403 for any `Origin`, for cross-site `Sec-Fetch-Site`, for a non-loopback `Host`; 413, 503 at both caps; dispatch by header; `requestState` from another principal refused; exit 2 for every refused `--listen` form, an unknown `--listen-token` flag (so no token-on-argv form slips in later), a group- or world-readable token file, both token sources set, and `MCPGODEBUG` set; `goleak` after shutdown.
- **Conformance.** The netguard leg drops `relay.py` and runs against the real listener: `netguard serve --listen 127.0.0.1:0 --listen-token-file <tmp> --server conf --upstream everything-server`, with the URL read from the `listening` line. The suite can send neither a token nor a prefixed tool name, so one shim stays in the path, a successor to `relay.py` that is much smaller. It adds `Authorization` and puts `conf.` in front of an unprefixed `tools/call` name, in `params.name` and `Mcp-Name` alike, so a deliberate mismatch stays a mismatch. Status, headers, session ids and the SSE stream pass through byte for byte. It keeps no sessions, does not renumber ids and does not touch `tools/list`. Expected effect on `baseline/netguard-2026-07-28.yml`: 11 of the 12 HTTP-transport entries clear (the `sep-2575-http-server-*` 400 and 404 checks, `unsupported-version-400`, `request-meta-invalid-missing-meta`, `request-meta-invalid-missing-protocol-version`). `sep-2575-missing-capability-http-400` stays, but moves to the "Pairing and prefix" group with `server-rejects-undeclared-capability`, because the suite looks up `test_missing_capability` in `tools/list` and reports it untestable. The 2025 leg starts exercising go-sdk's real sessions, GET stream and DELETE through netguard. Any new failure there is netguard's to fix or baseline with a reason. The control leg runs `everything-server -http` directly, `-stateless=false` for 2025-11-25 and `true` for 2026-07-28 (as go-sdk's own conformance does), through the same shim without prefix or token. `relay.py` and `tests/unit/test_conformance_relay.py` are then deleted.
- **Tier 2, new matrix row 23, "Streamable HTTP listener toward the agent"**, milestone M0, upstream netdev-ssh-mcp. A python-sdk client over Streamable HTTP in each era lists `netdev-ssh-mcp.*` and runs a read-only `tools/call` against the fake device. The same requests without a token get 401, and with `Origin: http://evil.example` get 403. Claude Code with `"type": "http"` and an `Authorization` header in `.mcp.json` lists the tools. The row is validated only against the real netdev-ssh-mcp, never against the fixture alone.

### Milestone and tasks

The listener goes on the **M0 board**, but it is **not an M0 exit criterion**. M0's criteria are met over stdio and should not wait for it. It belongs in M0 because it is transport work at the same layer as T0.2 and T0.3, it gives the conformance criterion a real HTTP measurement instead of a relay's, and it has to exist before M1 wires the pipeline in behind `Proxy.dispatch`, which is transport-neutral. The security argument for waiting until M1 is met by keeping M0 loopback-only and token-only. Remote binding waits for M1.

Proposed tasks for the orchestrator to add to `docs/milestones/M0.yaml` once this record is accepted:

| Id | Title | Package | Owner | Reviewers | Blocked by | Matrix |
| --- | --- | --- | --- | --- | --- | --- |
| T0.27 | `(*Proxy).HTTPHandler`: era dispatcher over two go-sdk handlers, Host, Origin, bearer auth, in-flight and session caps, body limit | `internal/proxy` | mcp-protocol-engineer | go-reviewer, security-reviewer | this ADR accepted | 23 |
| T0.28 | Bind the sealed `requestState` to the principal (`ng3.`), carry transport and principal on `call`, state the cross-session attribution rule in 8.4 | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | T0.27 | 2, 23 |
| T0.29 | `netguard serve --listen`, `--listen-token-file`, `NETGUARD_LISTEN_TOKEN`; refused M1 flags; `MCPGODEBUG` refusal; `http.Server` limits, connection cap, `listening` line, shutdown and upstream-exit handling | `cmd/netguard` | mcp-protocol-engineer | security-reviewer, go-reviewer, release-engineer | T0.27 | 23 |
| T0.30 | Conformance against the listener: auth-and-prefix shim, control leg on `everything-server -http`, delete `relay.py`, reconcile all four baselines | `tests/conformance` | test-engineer | go-reviewer | T0.29 | 1, 2 |
| T0.31 | Matrix row 23 (tier 2 over HTTP, Claude Code `type: http`), profile-schema 8.5 "HTTP listener", SECURITY.md gap rows, README and install.md snippets | `tests/integration`, `docs` | test-engineer | docs-writer, security-reviewer | T0.29 | 23 |

T0.17 (progress relay) should land after T0.28, or in the same series, so its token map is keyed per request from the start. For M1, the tasks that lift `--listen-remote` and `--listen-host` are added with the M1 board, after the pipeline is wired.

## Consequences

### Positive

- Agents and hosts that prefer a long-running local server (several clients, a desktop app that cannot spawn processes, a service manager) can use netguard without a stdio wrapper.
- Conformance measures netguard's own HTTP behaviour. Eleven baseline entries that excused the relay go away, and the relay's own tests with them.
- The `Mcp-Method` and `Mcp-Name` header checks ADR 0008 requires become real, from go-sdk. The SECURITY.md row "header and body mismatch is accepted on HTTP" can be tested.
- Session and principal binding, left open in M0 because stdio had one session, is decided before a second session can exist.
- Loopback-only plus a mandatory token means that opening the listener gives no more reach than a local user who can read the token file already has. No web page can drive it.

### Negative

- A new attack surface in a proxy that enforces no policy in M0. Mitigated by loopback-only binding, a 256-bit token on every request, `Origin` refusal, caps and timeouts, and by refusing remote binding until M1.
- netguard owns a dispatcher that picks between go-sdk's two handler modes. If go-sdk changes how either mode treats the other era, the dispatcher can break without a compile error. Mitigated by the dual-era tier 1 table, the conformance job on every go-sdk bump (T0.21), and this record pointing at the two code paths it depends on (`serveStatefulPOST`'s 2026 rejection, `ephemeralConnectOpts`).
- A shared static token gives one principal for every agent. The audit cannot tell agents apart, and MRTR answers can never satisfy `approver_must_differ`. Accepted until per-agent tokens or OAuth (open question 3).
- The conformance netguard leg still has a shim in it, though a far thinner one. A bug in it could hide or cause a failure. Mitigated by keeping it to two rewrites, with unit tests, and by running the control leg through the same shim.
- Browser-hosted MCP clients cannot connect (any `Origin` gets 403, and there is no CORS). Accepted for this step.
- Another component can outlive a request. On the 2025 path the go-sdk session owns a call whose POST dropped, and it is bounded by DELETE, the 30-minute idle timeout and `Proxy.Close`.

### Neutral

- Stdio stays the default and is unchanged. Existing `mcp.json` snippets keep working.
- Only one agent side at a time, so a host-launched stdio session and network sessions never share a process.
- The module graph does not change. No new dependency, no cgo; the binary stays static.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Serve stdio and HTTP at once | Stdio implies a parent host that owns netguard's lifetime (stdin EOF ends it). Mixing it with network sessions gives two lifecycles and a confusing exit rule for no demonstrated need. |
| One go-sdk handler with `Stateless: true` for both eras | 2025 agents get no session and no server-to-client requests, so the relayed `elicitation/create` of profile-schema 8.4 stops working for the clients most people run. |
| One go-sdk handler with `Stateless: false` | Every 2026-07-28 request except `server/discover` gets 400; a stateless agent cannot use netguard at all. |
| `MCPGODEBUG=allowsessionsinstateless=1` | A temporary compatibility switch go-sdk plans to remove. It restores sessions only partially, and it is the kind of silent environment switch this record refuses. |
| Token optional on loopback | Loopback is reachable by every local user and process, unlike a stdio pipe. With no policy in M0 that means device access for anyone on the host. The conformance shim can send a token, so no test needs the exemption. |
| Token on argv (`--listen-token`) | Shows in `ps`, in process-creation logs and in the host's config file. T0.23 and ADR 0017 exist to remove exactly this for upstream secrets. |
| OAuth 2.1 resource server now (protected resource metadata, `auth.RequireBearerToken` with a JWT or introspection verifier) | Needs an authorization server and token validation choices that ADR 0002 and ARCHITECTURE.md leave to a gateway in front. The go-sdk middleware used here is the same one that mode would use, so it can be added without reshaping the chain. |
| Mutual TLS or built-in TLS on loopback | TLS on loopback protects nothing a bearer token on loopback does not, and certificate handling is a new operator burden. For remote binding it is open question 1. |
| Non-loopback allowed in M0 behind `--listen-remote` | Puts a policy-free device proxy on a network. The flag is reserved and refused until M1, in the same way ADR 0012 treats `--policy`. |
| Origin allow-list flag (`--listen-allow-origin`) | Useful only to browser clients, which also need CORS preflight handling for `Authorization` and `Mcp-*` headers. That is a separate feature with its own risks. Refusing every `Origin` meets the spec's MUST with no configuration. |
| Standard library `http.CrossOriginProtection` (or go-sdk's deprecated option) | Exempts GET, HEAD and OPTIONS, and treats `Origin` equal to `Host` as same-origin, which is exactly what a DNS-rebinding page presents. |
| Keep `relay.py` for the netguard leg | Measures the relay's HTTP behaviour, not netguard's, which is the problem this record fixes. |
| Baseline every prefix failure and run the suite with no shim | Gives up every scored `tools/call` scenario in both revisions to avoid a two-rule shim, and the suite still cannot send a token. |
| A hidden unprefixed-names mode in netguard for tests | A routing change in the shipped binary that exists only for a test, against profile-schema 8.1. |
| Place the whole listener in M1 | The conformance criterion would keep measuring a relay through M0, and M1 would add a transport and the policy pipeline in the same milestone. Loopback-only in M0 carries no more risk than the stdio path. |
| HTTP upstreams in the same step | Outbound TLS, credentials and egress are separate decisions with a separate validation target (matrix row 17). |

## Open questions for the maintainer

1. **TLS for M1 remote mode.** Built-in TLS (`--listen-tls-cert`, `--listen-tls-key`, standard library only), or TLS always terminated in front (Caddy, nginx, a service mesh), with netguard serving plain HTTP on a private interface?
2. **M0 exit.** Should matrix row 23 and "conformance runs against the listener" become an M0 exit criterion, or stay board tasks outside it as proposed here?
3. **Principals.** Keep one static token until an OAuth resource-server record, or allow several named tokens now (a repeatable `--listen-token-file name=path`)? That would let M4 audit tell agents apart and let an MRTR answer from a second principal count as a different approver.
4. **The conformance shim.** Is a two-rule shim (token and prefix) acceptable in the netguard leg, or should the suite be patched upstream (`--header`, a tool-name map) and the shim dropped when that lands?

## References

- [ADR 0002, standalone proxy](0002-standalone-proxy-not-gateway-plugin.md)
- [ADR 0008, dual-era MCP support](0008-dual-era-mcp-support.md)
- [ADR 0011, go-sdk and its transitive modules](0011-accept-go-sdk-transitive-modules.md)
- [ADR 0012, `netguard serve` flags and the `internal/proxy` API for M0](0012-serve-cli-and-proxy-api-for-m0.md)
- [ADR 0014, stateful upstream prompts to stateless agents](0014-stateful-upstream-prompts-to-stateless-agents.md)
- [profile-schema section 8](../specs/profile-schema.md#8-proxy-config-m0)
- [SECURITY.md, proxy transport gaps](../../SECURITY.md#proxy-transport-m0-gaps) and [ARCHITECTURE.md, trust boundaries](../../ARCHITECTURE.md#trust-boundaries)
- [tests/conformance/README.md](../../tests/conformance/README.md) and `tests/conformance/baseline/netguard-2026-07-28.yml`
- go-sdk v1.8.0 source: `mcp/streamable.go` (`StreamableHTTPOptions`, `ServeHTTP`, `serveStateless`, `serveStatefulPOST`, `ephemeralConnectOpts`), `mcp/streamable_headers.go` (`validateMcpHeaders`), `auth/auth.go` (`RequireBearerToken`), `internal/util/net.go` (`IsLoopback`)
- [MCP Streamable HTTP, security warning (Origin, localhost, authentication)](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports#security-warning)
- [MCP Streamable HTTP, protocol version header](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports#protocol-version-header)
- [MCP security best practices: local server compromise, session hijacking, token passthrough](https://modelcontextprotocol.io/specification/2025-11-25/basic/security_best_practices)
- [MCP authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization)
- [M0 board](../milestones/M0.yaml), tasks T0.17, T0.18, T0.21, T0.23
