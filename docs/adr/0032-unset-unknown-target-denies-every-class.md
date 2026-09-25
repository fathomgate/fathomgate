# ADR 0032: An unset `defaults.unknown_target` denies every class

- Status: accepted
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer), decided 2026-09-25; recorded by policy-engineer (board task M1-37); reviewers security-reviewer, go-reviewer
- Supersedes in part: [ADR 0007](0007-role-resolver-chain-sot-optional.md), the sentence on the default for unknown targets only (pointer in its *Amendments*); the resolver chain and the rest of ADR 0007 stand

## Context

A target no inventory provider resolves is `unknown` ([ADR 0007](0007-role-resolver-chain-sot-optional.md), [inventory-schema section 7](../specs/inventory-schema.md#7-unknown-target-semantics)). The policy's `defaults.unknown_target` decides what happens to it. `deny` denies every class and `allow` lets the rules decide; left unset, ADR 0007 denied `WRITE_CONFIG` and `EXEC_ARBITRARY` and let reads and every other class go on to the rules. A rule that matches on class alone, such as `reads-anywhere`, then allowed a read to any host the agent named.

The security reviews of PR #154 (M1-21) and PR #158 (M1-14) showed that a read is not safe on the upstreams fathomgate fronts first. Those servers connect to whatever host the agent names and log in with the operator's device credentials:

- **eos-mcp** falls back to the `[DEFAULT]` section of `config.ini` for a host it does not list (`config.py:62-70`), so any `hostname` receives the fleet's eAPI username and password, over HTTPS with certificate verification off by default and a process-wide TLS context lowered to TLS 1.0 (`eapi.py:17-27`).
- **netdev-ssh-mcp** takes a free-form `host` and opens an SSH session to it with the credentials the operator passed to the upstream.

The credentials leave on connect, before any command runs, so `get_version` to `core-x.attacker.example` hands them over as surely as a write would. The class of the call does not change what the connection gives away. ADR 0031 (PR #157, M1-34, question 4) raised the same gap for hostname patterns: all three example policies set `unknown_target: deny`, but a policy that omits the key still lets reads reach unknown hosts.

## Decision

We will make an unset `defaults.unknown_target` deny every class, exactly as `unknown_target: deny` does.

1. **The default.** When any target of a request is unknown and the policy does not say `unknown_target: allow`, `Evaluate` returns `deny` with rule id `default:unknown_target`, for every class: `READ_OPERATIONAL`, `READ_CONFIG`, `WRITE_CONFIG`, `EXEC_ARBITRARY`, `INVENTORY_READ`, `LAB_LIFECYCLE` and `LOCAL_ADMIN`. The rules do not run.
2. **Explicit settings keep their meaning.** `unknown_target: deny` is unchanged. `unknown_target: allow` still lets the rules decide for every class, for operators who accept the risk (a lab with no inventory). `hold` stays refused at load. The schema gains no class-scoped form and no new value.
3. **Where it lives.** `policy.Parse` fills an unset value in as `deny`, so a loaded policy says what is enforced. `Evaluate` denies on any value other than `allow`, so a `Policy` built in Go without `Parse` also fails closed. `Evaluate` stays pure (invariant 1).
4. **Unchanged.** The rule id `default:unknown_target`, its position as step 1 before the session cap and the rules (invariant 2), the deny text, and the trace entry. Under `allow` the trace entry is recorded unmatched, as before.
5. **Only named targets.** The default applies to a target the request names. A request with no targets, such as an `INVENTORY_READ` that lists the upstream's own devices, has nothing unknown, so step 1 does not apply and the rules decide. A call to a tool that declares a target parameter but arrives with none is refused before `Evaluate` by the normaliser with `default:bad_arguments` (M1-18), so an empty target list is not a way around this default.

[policy-schema section 2.1 and section 4](../specs/policy-schema.md#21-defaults), [inventory-schema section 7](../specs/inventory-schema.md#7-unknown-target-semantics), ARCHITECTURE.md, PLAN.md, the PRD (R12), the glossary, test-matrix row 6 and the threat model change in the implementing PR.

## Consequences

### Positive

- The fleet's device credentials go to no host the operator has not named in an inventory, whatever the class of the call, unless the policy says `unknown_target: allow`.
- The safe behaviour no longer depends on the policy author remembering one key. A new policy, a trimmed copy of an example, or a policy written for a lab and reused in production fails closed.
- One rule for every class is easier to explain and to audit than a split by class.

### Negative

- A policy that relied on the permissive default now denies reads to unknown hosts. In practice no deployment relies on it: v0.1.0 enforced no policy (`serve` refused `--policy`, ADR 0012), so the old default only ever reached `fathomgate policy test` and `policy eval`, and all three example policies already set `unknown_target: deny`. An operator who wants the old behaviour writes `unknown_target: allow` and adds class rules that deny writes and exec, which is exactly what the old default did.
- An agent that reads a device missing from the inventory gets a denial where it used to get output. The deny names `default:unknown_target`, so the fix (add the device to `inventory.yaml`) is discoverable.

### Neutral

- The example policies' decisions do not change, and neither do their test cases.
- `tools/policy-lint` checks the key's values only, not the default, so it does not change.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| A per-server profile flag (for example `credentials_to_any_host: true` on eos-mcp and netdev-ssh-mcp) that forces `deny` for that server, keeping today's permissive default elsewhere | Rejected by the maintainer. It makes safety depend on a profile author spotting the hazard in each upstream's source, and a profile that is missing or not yet audited (the fallback classifier) would get the permissive default. Every upstream that connects to a device authenticates to it, so the flag would be set almost everywhere. |
| Keep the permissive default and document it | The examples already set `deny`, which is the documentation. The finding is that a policy without the key is unsafe on the first upstreams fathomgate supports. |
| Deny reads only for `READ_CONFIG` | The credentials leave on connect, before any command runs; `READ_OPERATIONAL` sends them too. |
| Make `unknown_target` a required key | Refuses every existing policy that omits it, for no gain over a safe default. |

## References

- Security reviews of PR #154 (M1-21) and PR #158 (M1-14); [ADR 0031](0031-hostname-patterns-never-make-a-target-known.md) (PR #157, M1-34), question 4
- [ADR 0003](0003-yaml-policy-dsl-with-obligations.md), [ADR 0007](0007-role-resolver-chain-sot-optional.md), [ADR 0026](0026-m1-policy-pipeline-at-dispatch.md) (the pipeline and the deny text)
- `internal/policy/load.go` (`Parse`), `internal/policy/evaluate.go` (step 1); `TestUnknownTargetDefaults`
- [M1 board](../milestones/M1.yaml): M1-37 (this record and the change), M1-18 (zero-target refusal), M1-34 (hostname patterns)
