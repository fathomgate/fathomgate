# ADR 0029: Remote listening with built-in TLS, and letting an agent authenticate fathomgate on loopback

- Status: accepted in part (M1: Windows exclusive bind); remainder deferred to M2
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer), accepted in part by the maintainer 2026-09-25 with the answers under *Decisions on the open questions*; proposed by the orchestrator for M1 (board task M1-04); owner mcp-protocol-engineer; reviewers security-reviewer, go-reviewer, release-engineer
- Builds on: [ADR 0016](0016-streamable-http-listener.md) (its open question 1, already answered: built-in TLS, standard library only, required off loopback) and [ADR 0023](0023-listener-binds-both-loopback-families.md)

## Context

[ADR 0016](0016-streamable-http-listener.md) reserved `--listen-remote` and `--listen-host` for M1, "when a policy stands between the listener and the devices", and its accepted answer to open question 1 says remote mode needs `--listen-tls-cert` and `--listen-tls-key` (`crypto/tls`, no new dependency), with a non-loopback bind without them exiting 2. What it did not decide is the shape of those flags in detail, or anything about loopback.

The [threat model](../security/threat-model.md) has one row open for M1, owned by mcp-protocol-engineer: **port squatting while fathomgate is down or restarting**. Another local user binds the loopback port first; an agent, which cannot authenticate fathomgate, sends its bearer token; the token then works against the real fathomgate. On Windows no race is even needed, because fathomgate's sockets are not bound with `SO_EXCLUSIVEADDRUSE`, so a wildcard bind by another user receives loopback connections while fathomgate runs. [ADR 0023](0023-listener-binds-both-loopback-families.md) records the row as fixed in M1 "by TLS with a pinned certificate, or by a Unix socket or named pipe protected by file permissions".

Neither fix is free. Most MCP hosts' Streamable HTTP clients verify TLS against the system roots and cannot pin a certificate; few speak HTTP over a Unix socket or named pipe at all. A fix no client can use closes nothing.

This record is not an M1 exit criterion. The criteria are met on stdio. It is on the M1 board because ADR 0016 put remote listening there, and the threat-model row is owned for M1.

## Decision

**Accepted in part, 2026-09-25.** Point 4 (the Windows exclusive bind) is accepted for M1, board task M1-27. Points 1, 2 and 3, and the TLS mitigation in point 5, are deferred to M2 and will be re-decided there; they are not rejected. Until then remote listening stays reserved, as ADR 0016 left it.

We will ship remote listening behind the pipeline with built-in TLS as ADR 0016 decided, allow the same TLS on loopback so an agent that can verify a certificate authenticates fathomgate, bind with `SO_EXCLUSIVEADDRUSE` on Windows, and keep plain-HTTP loopback as the default with the residual recorded.

1. **Flags.** `--listen-tls-cert <file>` and `--listen-tls-key <file>` (PEM; both or neither; the key file opened with the owner-only checks of the listen token file and of [ADR 0028](0028-audit-key-custody.md)). TLS 1.3 only, standard library defaults otherwise. The `listening` line's URL becomes `https://`. Certificates are read once at start; rotation is a restart.
2. **Remote.** `--listen-remote` allows a non-loopback `--listen` address, and requires `--policy` ([ADR 0027](0027-serve-policy-inventory-profiles-flags.md)), `--listen-tls-cert` and `--listen-tls-key`, and at least one `--listen-host <name>`; otherwise exit 2. Requests whose `Host` is not a listed name or the literal bound address get 403, as ADR 0016 said. Everything else in ADR 0016's request handling, including the bearer token on every request, stands.
3. **Loopback with TLS.** The two TLS flags are also accepted with a loopback `--listen`. An agent configured with that certificate's CA (or the certificate itself, where the client allows it) then refuses a squatter that cannot present it. Documented in `docs/install.md` with the clients known to support a custom CA.
4. **Windows exclusive bind.** Every listener socket on Windows is bound with `SO_EXCLUSIVEADDRUSE`, so another user's wildcard bind cannot take fathomgate's loopback connections while it runs. This needs `golang.org/x/sys/windows`, already a dependency (ADR 0011, 0021).
5. **Residual.** Plain-HTTP loopback while fathomgate is down stays open, and the threat-model row says so, with the mitigations: TLS on loopback (3, from M2), a supervisor that restarts at once, one token per agent. The Unix-socket and named-pipe listener is not built in M1 (decision 2).

## Consequences

### Positive

- The remote mode ADR 0016 promised lands with the policy in front of it and cannot be switched on without TLS, a host list and a policy.
- An operator who needs the squatting row closed can close it today with a client that trusts a custom CA.
- The Windows no-race case is closed while fathomgate runs.

### Negative

- Certificate handling is operator burden: issuing, trusting and rotating a certificate for a loopback listener is unusual. Mitigated by keeping it optional on loopback.
- The row stays partly open for the default configuration.

### Neutral

- No new module dependency. `HTTPOptions` may gain a TLS field or `serve` may wrap the listener itself; the owning task decides and, if an export changes, records it against the ADR 0022 table (as replaced by ADR 0026).

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Remote mode with TLS terminated in front (ADR 0016's first draft) | Already overruled by ADR 0016's answer to open question 1. |
| Generate a self-signed certificate at start and print its fingerprint for pinning | Pinning is exactly what most clients cannot do, and a fresh certificate per start forces reconfiguring every agent after each restart. |
| Unix socket or Windows named pipe listener in M1 | Owner-only file permissions would close the row fully, but almost no MCP host speaks Streamable HTTP over either today; it is effort for no user. Kept as open question 2. |
| Require TLS on loopback as well | Breaks every v0.1.0 `--listen` config and every client without custom-CA support, for a local-user attack. |

## Decisions on the open questions

Accepted in part by the maintainer, Josh Scott, on 2026-09-25, with these answers:

1. **Remote listening is not M1.** The Windows exclusive bind (point 4) is accepted for M1 (M1-27): on Windows, another user's wildcard bind can no longer take fathomgate's loopback connections while it runs. TLS, remote listening and TLS on loopback (points 1 to 3) move to M2 and are re-decided there. They are deferred, not rejected.
2. **Unix socket or named pipe:** deferred to M2 with the rest of the listener work.
3. **mTLS:** deferred to M2 with the rest of the listener work.

In M1 the port-squatting row stays open for plain-HTTP loopback while fathomgate is down, with the mitigations a supervisor that restarts at once and one token per agent.

## References

- [ADR 0016](0016-streamable-http-listener.md) (reserved flags, open question 1), [ADR 0022](0022-internal-proxy-export-surface.md), [ADR 0023](0023-listener-binds-both-loopback-families.md), [ADR 0027](0027-serve-policy-inventory-profiles-flags.md), [ADR 0028](0028-audit-key-custody.md)
- [Threat model](../security/threat-model.md), the rows on port squatting and the loopback family squat; security reviews of PR #109 and PR #112
- [profile-schema 8.3 and 8.5](../specs/profile-schema.md#85-http-listener)
- [M1 board](../milestones/M1.yaml): M1-04 (this record), M1-26 and M1-27
