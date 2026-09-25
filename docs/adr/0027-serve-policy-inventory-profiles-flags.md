# ADR 0027: `fathomgate serve --policy`, `--inventory` and `--profiles` in M1; `--audit` stays refused until M4

- Status: proposed
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer; to accept); proposed by the orchestrator for M1 (board task M1-02); owner mcp-protocol-engineer; reviewers security-reviewer, go-reviewer, design-guardian (CLI copy), release-engineer
- Amends on acceptance: [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md), its reserved-flag clause only

## Context

[ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md) reserved `--policy`, `--inventory`, `--profiles` and `--audit` and refuses them with exit 2, so that nobody believes a policy is enforced by a proxy that forwards every call. [ADR 0026](0026-m1-policy-pipeline-at-dispatch.md) wires the pipeline in M1, so three of them can now mean something. The fourth cannot: the audit chain and its signed checkpoints are M4 ([PLAN.md](../PLAN.md#milestones), PRD R26), `serve.go` already says so in the comment on `reservedServeFlags`, and the signing key's custody is not settled ([ADR 0028](0028-audit-key-custody.md), T0.55).

The profiles are data the binary needs to classify anything. Today they live in `profiles/` in the repository and ship in no release archive, so an operator who installs v0.1.0 from a release has none. And a `serve` without `--policy` is v0.1.0's pass-through; whether that stays allowed is the choice that decides what "Fathomgate stops `reload`" means on the day of the announcement.

## Decision

We will accept `--policy <file>`, `--inventory <file>` and `--profiles <dir>` on `fathomgate serve` from M1, embed the shipped profiles in the binary, validate everything before the upstream is spawned, keep `--audit` refused with a message that names M4, and keep `serve` without `--policy` as a pass-through that says so loudly.

| Flag | Meaning in M1 | Errors (exit 2 before anything is spawned) |
| --- | --- | --- |
| `--policy <file>` | The policy file ([policy-schema](../specs/policy-schema.md)), loaded with `policy.Load` (strict: unknown keys, unknown obligations and `hold` in `defaults.unknown_target` are errors). One file. | Missing, unreadable, or invalid; the message names the file and the loader's error, which never quotes a secret because a policy holds none. |
| `--inventory <file>` | The static inventory with its `roles:` hostname patterns ([inventory-schema](../specs/inventory-schema.md) sections 3 and 4), loaded with `inventory.LoadChain`. Optional: without it every target is `known: false`, and `defaults.unknown_target` decides (unset denies `WRITE_CONFIG` and `EXEC_ARBITRARY`). | As for `--policy`. Only with `--policy`. |
| `--profiles <dir>` | A directory of profile YAML files that **replaces** the embedded set, for an operator's own or patched profiles. Without it the embedded profiles are used. | As for `--policy`. A profile set (embedded or given) with no profile for `--server` is not an error: calls to it take the fallback classifier and `serve` warns once at start (open question 3). |
| `--audit` | Still refused, exit 2: `--audit is not available until M4 (the audit chain); decisions are logged to stderr`. | Always. |

Rules that go with the table:

- **Embedded profiles.** `profiles/*.yaml` are embedded with `go:embed` at build time, so the release binary classifies the shipped upstreams with no files beside it. `fathomgate version` prints the embedded profile set (server keys and each file's pinned upstream version line). `--profiles` replaces the set, it does not merge, so an operator always knows which file classified a tool.
- **Without `--policy`.** `serve` keeps v0.1.0's pass-through, with `--inventory` and `--profiles` refused (they configure nothing), the existing start-up line's `policy="none (...)"` kept, and a second Warn line: `no --policy: every call is forwarded; see docs/install.md`. With `--listen-remote` (M1, ADR 0029) `--policy` is required.
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
- v0.1.0 users who never pass `--policy` get a Warn line they did not get before, and no protection. The alternative (below) would break their configs.
- `--profiles` replacing rather than merging means an operator who adds one profile must copy the rest. Deliberate: a merge makes it unclear which file won.

### Neutral

- `--upstream-env`, `--upstream-env-pass`, `--listen` and the token flags do not change.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Make `--policy` required from M1 | Every v0.1.0 config breaks on upgrade, and the pass-through has real users (conformance, client testing). Open question 1 keeps this on the table. |
| A built-in default policy (read-only) when `--policy` is absent | Safe, but silent: an operator who forgets the flag gets a policy they never read, and a write that fails looks like an upstream bug. |
| Accept `--audit` in M1 with the existing `audit.Writer` | Puts a hash chain in operators' hands before its key custody (T0.55, ADR 0028), checkpoint cadence and verify story are done, and pulls M4 scope forward. ADR 0026 logs the same fields to stderr instead. |
| A YAML config file (`--config`) | ADR 0012 deferred it until M1 added settings. Three paths are still flags' work; revisit when M2 adds a NetBox URL and credentials. |
| Merge `--profiles` over the embedded set | Two files for one server, with the winner decided by a rule the operator must remember. |

## Open questions for the maintainer

1. **Pass-through without `--policy`.** Keep it in v0.2.0 with a Warn (this record), or make `--policy` required and offer `--no-policy` for the pass-through? The second is safer for new users and costs one flag for existing ones.
2. **Multiple policy files.** One `--policy` file in M1 (this record), or repeatable with a defined concatenation order? One file keeps "first match in file order" literal.
3. **Missing profile for `--server`.** Fall back to the classifier with a Warn (this record's default), or refuse to start unless `--require-profile` (or the reverse, `--allow-fallback`)? The fallback is deny-by-default for anything that looks like a write or free-form command, so starting is safe; refusing is louder.
4. **`--audit` message.** Name the milestone (`until M4`) or a version (`until v0.5.0`)? Milestones are what the docs use; versions are what users see.

## References

- [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md), [ADR 0016](0016-streamable-http-listener.md), [ADR 0026](0026-m1-policy-pipeline-at-dispatch.md), [ADR 0028](0028-audit-key-custody.md), [ADR 0029](0029-remote-listener-tls-and-loopback-authentication.md)
- [profile-schema 8.3](../specs/profile-schema.md#83-fathomgate-serve-flags), [policy-schema section 8](../specs/policy-schema.md#8-loader-requirements), [inventory-schema section 9](../specs/inventory-schema.md#9-cli)
- PRD R9 to R12, R33; [M1 board](../milestones/M1.yaml): M1-02 (this record), M1-20 (the flags)
