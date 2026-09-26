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

- A profile fix for a new upstream release needs a Fathomgate release, or `--profiles` with a copy of the whole set. Mitigated by `--profiles` and by shipping `profiles/` in the release archive as well.
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
3. **Missing profile for `--server`: start** with the fallback classifier and one Warn line, as written. *Note, 2026-09-25:* as built, the server gets an empty profile, not the fallback classifier (the review-round row *Server without a profile* below), and there is no fallback classifier ([ADR 0036](0036-no-fallback-classifier.md)).
4. **`--audit` message: name the milestone.** The refusal says `--audit` arrives in M4.

## Notes after acceptance

M1-20 (2026-09-25) implemented this record. What the implementation fixed that the record left open, for design-guardian and release-engineer to review with the PR; none changes a decision above:

| Point | As built |
| --- | --- |
| Message texts | Neither flag: `--policy <file> or --no-policy is required: --policy decides every call before it reaches the upstream; --no-policy forwards every call unchecked, as v0.1.0 did`. Both: `--policy and --no-policy cannot be used together: ...`. `--no-policy` with `--inventory` or `--profiles`: `--inventory and --profiles: only with --policy <file>; --no-policy forwards every call unchecked, so leave them out or use --policy <file> instead of --no-policy`. `--inventory` or `--profiles` alone: `--inventory: only with --policy <file>`. A file flag given twice: `--policy is given more than once; give it once`. `--audit`: `--audit arrives in M4 with the signed audit chain; until then serve --policy logs every decision to stderr`. A reserved name among the upstream arguments: `--policy among the upstream arguments: fathomgate's own flags go before --, and a flag of that name is never passed to an upstream`. The start-up Warn lines are in [profile-schema 8.3](../specs/profile-schema.md#83-fathomgate-serve-flags) |
| Order of checks | The combination of the policy flags is checked after every other usage error, so an existing error (a value typed as its own argument, a bad `--listen`) is reported as before. The files are loaded after parsing and before `--listen` binds or the upstream is spawned |
| Where the embed lives | `profiles/embed.go`, package `profiles`, `//go:embed *.yaml`: `go:embed` cannot name a parent directory, so the embedding package sits beside the files and carries their Apache-2.0 SPDX line. The release archive and the `Dockerfile` copy `profiles/*.yaml` and `profiles/LICENSE` only. `TestEmbeddedProfilesAreTheRepo` pins the embedded set to `profiles/*.yaml` byte for byte and fails on a `.yml` or a subdirectory the pattern would miss |
| `fathomgate version` | Lists each embedded profile's server key, tool count, the first 12 hex digits of its SHA-256 and its file name. The record asked for each file's pinned upstream version line; profiles carry the pin only in comments, in no fixed form, so the digest stands in until the planned `verified_version` field (profile-schema section 3, M2) gives a line to print |
| `--profiles` | Loaded like the embedded set (top-level `*.yaml`, name order, strict, validated, each file named `<server>.yaml`). A missing path, a file, a directory with no `*.yaml`, a subdirectory or a `*.yml` exits 2 (see the review-round note below) |
| `--inventory` | Loaded with `inventory.LoadFile` and `File.Chain` (the same chain as `LoadChain`), so the device count and the ADR 0031 decision 5 warning come from the one read. The warning text comes from the new `inventory.File.PatternWarnings`. A `*.csv` path is refused with a pointer to `fathomgate inventory import`; serve reads no CSV |
| Obligation warnings | Only obligations on `allow` rules are warned about: a `hold` is not run in M1 and a `deny` never runs, so their obligations change nothing yet. `dry_run`, `diff` and `timed_rollback` say the call is not run; the others say it is forwarded without them, with `enforced_from` (`M2` for `redact`, `M4` for the rest). One more Warn, not in the record, lists the `hold` rules, since a policy written for M3 (`prod-approval.yaml`) otherwise looks enforced |
| Start-up line | `serving on stdio` (no longer `...; M0 pass-through, no policy enforced`) and each `listening` line carry `policy`, `rules`, `inventory`, `devices`, `profiles` and `profile` (`<server>.yaml`, or `none (every call with arguments is denied)`, review-round note below). With `--no-policy`: `policy="none (--no-policy: every call is forwarded)"` |
| `--listen-remote`, `--listen-host` | Still refused; their text now says M2 (the board moved M1-26 to M2), and the `--listen` address error no longer promises M1 |

### Review round, 2026-09-25 (PR #171)

Recorded from the security, Go and design reviews of PR #171 and the orchestrator's decision on the same day.

| Point | As built |
| --- | --- |
| **Server without a profile (orchestrator decision, 2026-09-25)** | Under `--policy`, a `--server` with no profile in the set is given an **empty** profile, not the fallback classifier. Every tool is then one the profile does not list, so a call carrying any argument is `deny` with `default:bad_arguments` ([ADR 0033](0033-closed-argument-list-per-tool.md) section 2), a call with none is `EXEC_ARBITRARY` for the rules, the advertised `inputSchema` keeps no properties, and upstream prompts are refused. This follows the fail-closed choices of [ADR 0032](0032-unset-unknown-target-denies-every-class.md) and ADR 0033: with the fallback classifier the call named no target, so the unknown-target default and `max_devices` never ran. It replaces decision 3's "start with the fallback classifier" for `serve --policy`; `serve` still starts, and the Warn says what happens and what to do, listing the server keys that have a profile (`servers_with_a_profile`). `fathomgate policy eval` without `--profile` is unchanged |
| Profile file names | Every profile file, embedded or under `--profiles`, is named after its server key; any other name exits 2. `profiles/upa-mcp-netmiko-server.yaml` (key `upa`) is renamed `profiles/upa.yaml`; nothing outside the repository references the old name (issue #100 names it only as history). A subdirectory or a `*.yml` file in `--profiles` exits 2 instead of being skipped |
| Integrity of the files | The policy, the inventory, the `--profiles` directory and each profile file must not be changeable by anyone but their owner and the administrators (`internal/configfile`, checked on the opened file); otherwise exit 2. Rules in [profile-schema 8.3](../specs/profile-schema.md#83-fathomgate-serve-flags). Not `internal/secretfile`'s owner-only rules: the files are not secret |
| Load errors | The policy, inventory and profile decoders share `internal/yamlstrict`: strict, one YAML document only (a second is an error), and errors reduced to `[line:column]` and the message, never the surrounding lines of the file; a message that would quote a value is reduced to its position. `fathomgate policy eval` and `policy test` use the same decoders |
| Repeated flags | `--policy`, `--inventory` and `--profiles` may each be given once; a second occurrence exits 2 rather than letting the last one win |
| Obligations | The warnings iterate `policy.KnownObligations`; `TestObligationsPartitioned` pins that each obligation is either carried (`redact` until M2; `canary_first`, `require_ticket`, `notify` until M4) or cannot be met (`dry_run`, `diff`, `timed_rollback`) |
| Warning texts | Design review's wording, each saying what happens and what to do, in profile-schema 8.3; new: `no --inventory: every target is unknown, so this policy denies every call that names a device (rule default:unknown_target); add --inventory <file>` when `unknown_target` is not `allow`. The `unknown_target: allow` warning keeps policy-lint's text and appends what to do |
| `version` | `embedded profiles (serve --profiles <dir> replaces them):`, and `1 tool` in the singular |
| Not done | A conformance leg under a permissive policy: under `--policy` the conformance server `conf` has no profile, so it would need a test profile covering the suite's tools and their arguments, and new baselines; left for a later task. The gated path is covered by `TestServePolicyEndToEnd` (HTTP and stdio) and tier 2 `test_policy_gate.py` |

## References

- [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md), [ADR 0016](0016-streamable-http-listener.md), [ADR 0026](0026-m1-policy-pipeline-at-dispatch.md), [ADR 0028](0028-audit-key-custody.md), [ADR 0029](0029-remote-listener-tls-and-loopback-authentication.md)
- [profile-schema 8.3](../specs/profile-schema.md#83-fathomgate-serve-flags), [policy-schema section 8](../specs/policy-schema.md#8-loader-requirements), [inventory-schema section 9](../specs/inventory-schema.md#9-cli)
- PRD R9 to R12, R33; [M1 board](../milestones/M1.yaml): M1-02 (this record), M1-20 (the flags)
