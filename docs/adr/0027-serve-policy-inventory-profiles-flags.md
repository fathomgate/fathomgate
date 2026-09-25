# ADR 0027: `fathomgate serve --policy`, `--inventory` and `--profiles` in M1; `--audit` stays refused until M4

- Status: accepted
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer), accepted by the maintainer 2026-09-25 with the answers under *Decisions on the open questions*; proposed by the orchestrator for M1 (board task M1-02); owner mcp-protocol-engineer; reviewers security-reviewer, go-reviewer, design-guardian (CLI copy), release-engineer
- Amends: [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md), its reserved-flag clause only

## Context

[ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md) reserved `--policy`, `--inventory`, `--profiles` and `--audit` and refuses them with exit 2, so that nobody believes a policy is enforced by a proxy that forwards every call. [ADR 0026](0026-m1-policy-pipeline-at-dispatch.md) wires the pipeline in M1, so three of them can now mean something. The fourth cannot: the audit chain and its signed checkpoints are M4 ([PLAN.md](../PLAN.md#milestones), PRD R26), `serve.go` already says so in the comment on `reservedServeFlags`, and the signing key's custody is not settled ([ADR 0028](0028-audit-key-custody.md), T0.55).

The profiles are data the binary needs to classify anything. Today they live in `profiles/` in the repository and ship in no release archive, so an operator who installs v0.1.0 from a release has none. And a `serve` without `--policy` is v0.1.0's pass-through; whether that stays allowed is the choice that decides what "Fathomgate stops `reload`" means on the day of the announcement.

## Decision

We will accept `--policy <file>`, `--inventory <file>` and `--profiles <dir>` on `fathomgate serve` from M1, embed the shipped profiles in the binary, validate everything before the upstream is spawned, keep `--audit` refused with a message that names M4, and require `--policy`, with `--no-policy` as the explicit way to keep v0.1.0's pass-through.

| Flag | Meaning in M1 | Errors (exit 2 before anything is spawned) |
| --- | --- | --- |
| `--policy <file>` | The policy file ([policy-schema](../specs/policy-schema.md)), loaded with `policy.Load` (strict: unknown keys, unknown obligations and `hold` in `defaults.unknown_target` are errors). One file. | Missing, unreadable, or invalid; the message names the file and the loader's error, which never quotes a secret because a policy holds none. |
| `--inventory <file>` | The static inventory with its `roles:` hostname patterns ([inventory-schema](../specs/inventory-schema.md) sections 3 and 4), loaded with `inventory.LoadChain`. Optional: without it every target is `known: false`, and `defaults.unknown_target` decides (unset denies `WRITE_CONFIG` and `EXEC_ARBITRARY`). | As for `--policy`. Only with `--policy`. |
| `--profiles <dir>` | A directory of profile YAML files that **replaces** the embedded set, for an operator's own or patched profiles. Without it the embedded profiles are used. | As for `--policy`. A profile set (embedded or given) with no profile for `--server` is not an error: calls to it take the fallback classifier and `serve` warns once at start (decision 3). |
| `--no-policy` | Keeps v0.1.0's pass-through: every call is forwarded with no policy. | With `--policy`, `--inventory` or `--profiles`. |
| `--audit` | Still refused, exit 2, with a message that says `--audit` arrives in M4 (the audit chain) and that decisions are logged to stderr until then. | Always. |

Rules that go with the table:

- **Embedded profiles.** `profiles/*.yaml` are embedded with `go:embed` at build time, so the release binary classifies the shipped upstreams with no files beside it. `fathomgate version` prints the embedded profile set (server keys and each file's pinned upstream version line). `--profiles` replaces the set, it does not merge, so an operator always knows which file classified a tool.
- **`--policy` is required.** `serve` with neither `--policy` nor `--no-policy` exits 2 before anything is spawned, with a message naming both flags. `--no-policy` keeps v0.1.0's pass-through, with `--inventory` and `--profiles` refused (they configure nothing), the existing start-up line's `policy="none (...)"` kept, and a second Warn line saying every call is forwarded. `--listen-remote` (deferred to M2, [ADR 0029](0029-remote-listener-tls-and-loopback-authentication.md)) refuses `--no-policy`. The exact message texts are fixed in M1-20 with design-guardian's review.
- **Start-up line.** With a policy, the start-up line names the policy file, its rule count, the inventory file and its device count, the profile source (`embedded` or the directory) and whether the upstream's server key has a profile. No policy content is logged.
- **Unenforced obligations.** For each obligation in the loaded policy that M1 does not enforce (ADR 0026), one Warn line at start naming the obligation and the rules that use it.
- **Reserved inside the upstream arguments.** As today, the four names are refused among the arguments after `--`, so an upstream flag of the same name still cannot be passed. The rule does not change.
- **Reload.** Not in this record. PRD R33 (reload on SIGHUP, keep the old policy on a failed reload) is a separate task and a separate record, because SIGHUP does not exist on Windows and the choice of trigger is a CLI surface decision.

The flag table in [profile-schema 8.3](../specs/profile-schema.md#83-fathomgate-serve-flags), `docs/install.md`, the README snippets and the tier 2 fixtures change in the same PR as the code.

## Consequences

### Positive

- A release binary with `--policy policies/examples/read-only.yaml` stops `reload` with nothing else installed: the announcement's first command.
- A copied snippet that passes `--audit` still fails loudly, now with the milestone that brings it.
- Profiles and the binary cannot drift apart in a release; the profile set is part of the version.

### Negative

- A profile fix for a new upstream release needs a fathomgate release, or `--profiles` with a copy of the whole set. Mitigated by `--profiles` and by shipping `profiles/` in the release archive as well.
- Every v0.1.0 config without `--policy` exits 2 on upgrade to v0.2.0. The fix is one flag: `--policy <file>` for a policy, or `--no-policy` to keep the pass-through. The v0.2.0 CHANGELOG entry and upgrade note say so.
- `--profiles` replacing rather than merging means an operator who adds one profile must copy the rest. Deliberate: a merge makes it unclear which file won.

### Neutral

- `--upstream-env`, `--upstream-env-pass`, `--listen` and the token flags do not change.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Keep the pass-through when `--policy` is absent, with a Warn (this record's first draft) | An operator who forgets the flag gets no protection and one stderr line nobody reads in a supervised process. The maintainer chose an explicit `--no-policy` (decision 1); the pass-through's real users (conformance, client testing) add one flag. |
| A built-in default policy (read-only) when `--policy` is absent | Safe, but silent: an operator who forgets the flag gets a policy they never read, and a write that fails looks like an upstream bug. |
| Accept `--audit` in M1 with the existing `audit.Writer` | Puts a hash chain in operators' hands before its key custody (T0.55, ADR 0028), checkpoint cadence and verify story are done, and pulls M4 scope forward. ADR 0026 logs the same fields to stderr instead. |
| A YAML config file (`--config`) | ADR 0012 deferred it until M1 added settings. Three paths are still flags' work; revisit when M2 adds a NetBox URL and credentials. |
| Merge `--profiles` over the embedded set | Two files for one server, with the winner decided by a rule the operator must remember. |

## Decisions on the open questions

Accepted by the maintainer, Josh Scott, on 2026-09-25, with these answers:

1. **Pass-through: `--policy` is required.** `--no-policy` keeps the M0 pass-through explicitly. Existing users add one flag; the v0.2.0 CHANGELOG entry and upgrade note must say so.
2. **Multiple policy files: one `--policy` file.** "First match in file order" stays literal.
3. **Missing profile for `--server`: start** with the fallback classifier and one Warn line, as written.
4. **`--audit` message: name the milestone.** The refusal says `--audit` arrives in M4.

## References

- [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md), [ADR 0016](0016-streamable-http-listener.md), [ADR 0026](0026-m1-policy-pipeline-at-dispatch.md), [ADR 0028](0028-audit-key-custody.md), [ADR 0029](0029-remote-listener-tls-and-loopback-authentication.md)
- [profile-schema 8.3](../specs/profile-schema.md#83-fathomgate-serve-flags), [policy-schema section 8](../specs/policy-schema.md#8-loader-requirements), [inventory-schema section 9](../specs/inventory-schema.md#9-cli)
- PRD R9 to R12, R33; [M1 board](../milestones/M1.yaml): M1-02 (this record), M1-20 (the flags)
