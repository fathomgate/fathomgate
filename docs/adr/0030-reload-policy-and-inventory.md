# ADR 0030: Reloading the policy and inventory without a restart

- Status: proposed, deferred to M2
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer), deferred by the maintainer 2026-09-25 (see *Decisions on the open questions*); proposed by the orchestrator for M1 (board task M1-05, for M1-25); owner mcp-protocol-engineer; reviewers policy-engineer, security-reviewer, go-reviewer

## Context

PRD R33 (P1, M1): "Policy reload on SIGHUP without dropping connections; failed reload keeps the old policy". It is not one of the three M1 exit criteria in [PLAN.md](../PLAN.md#milestones), but it is in M1's requirements.

A restart is costly for Fathomgate in a way it is not for a stateless proxy. It kills the upstream's whole process tree ([ADR 0021](0021-kill-the-upstream-process-tree.md)), ends every 2025-era agent session and every open GET stream, and invalidates every sealed `requestState`, because the sealing key is per process ([ADR 0016](0016-streamable-http-listener.md) amendments). An operator who fixes a rule mid-incident should not pay that.

SIGHUP does not exist on Windows, which Fathomgate supports as a first-class platform, so "on SIGHUP" is not a complete answer. And a reload is a change of what is enforced, so it must be visible: the decision log line (ADR 0026) should say which policy version decided each call.

## Decision

We will reload the `--policy` and `--inventory` files on SIGHUP on Unix and by polling their contents on Windows, swap them atomically only when both load cleanly, and never reload profiles.

1. **Trigger.** Unix: SIGHUP. Windows: Fathomgate checks the two files every 5 seconds and reloads when their SHA-256 changes (standard library only; no file-watch dependency). The same polling is available on Unix with `--reload-poll` (open question 1 asks whether to have it at all).
2. **Atomic swap.** Both files are loaded and validated in full off to the side. Only if both succeed does the gate switch to the new pair, with one atomic pointer store; calls already past step 6 of ADR 0026 finish on the pair that evaluated them. On any error the old pair stays, and Fathomgate logs at Error with the file and the loader's message.
3. **What is not reloaded.** Profiles (embedded or `--profiles`), the upstream, listen tokens and TLS material. Profiles change classification, and a change in classification mid-session is a different risk from a rule edit; a profile change is a restart.
4. **Visibility.** Each policy load gets a version: the first 12 hex characters of the SHA-256 of the file's bytes. The start-up line, each reload line (`msg=policy reloaded old=<v> new=<v> rules=<n>`) and each decision log line carry it (`policy_version`), matching the audit event's policy version field in M4.
5. **Session counters survive.** A reload does not reset `devices_touched`; a tighter `max_devices` applies at once to sessions already over it.

## Consequences

### Positive

- A rule fix takes effect in seconds without killing the upstream or dropping agents.
- A bad edit never leaves Fathomgate without a policy.
- Every decision says which policy made it.

### Negative

- Polling on Windows delays a reload by up to 5 seconds, and reads two small files every 5 seconds.
- Two ways to trigger a reload on Unix if polling is kept.

### Neutral

- `policy.Evaluate` does not change; the gate holds the current pointer.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| A file-watch library (fsnotify) | A new dependency (ADR required, CGO-free but more surface) to save a 5-second poll. |
| A local admin endpoint (`POST /reload`) on the listener | New authenticated surface, and nothing for stdio-only deployments. |
| A Windows named event (`Global\fathomgate-reload-<pid>`) | Needs a companion command (`fathomgate reload`) and ACLs on the event; polling is simpler and works the same under any supervisor. |
| No reload on Windows | Windows is a supported platform; the restart cost above applies there too. |
| Reload profiles too | Mid-session reclassification; keep it a restart until someone needs otherwise. |

## Decisions on the open questions

Deferred by the maintainer, Josh Scott, on 2026-09-25. This record is not accepted.

- **Open question 2, park to M2: yes.** Reload moves to M2, with board task M1-25. The record stays `proposed` and is decided in M2.
- **Open question 1, polling on Unix, and open question 3, the poll interval:** open, decided with the record in M2.
- Until then a changed `--policy` or `--inventory` file takes effect on restart.

## References

- PRD R33; [ADR 0016](0016-streamable-http-listener.md), [ADR 0021](0021-kill-the-upstream-process-tree.md), [ADR 0026](0026-m1-policy-pipeline-at-dispatch.md), [ADR 0027](0027-serve-policy-inventory-profiles-flags.md)
- [policy-schema section 8](../specs/policy-schema.md#8-loader-requirements)
- [M1 board](../milestones/M1.yaml): M1-05 (this record), M1-25 (the reload)
