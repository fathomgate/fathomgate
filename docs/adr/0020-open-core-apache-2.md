# ADR 0020: Open core under Apache-2.0, with outside contributions by DCO sign-off

- Status: accepted
- Date: 2026-09-24
- Deciders: Josh Scott (maintainer; chose open core, Apache-2.0 and DCO on 2026-09-24); proposed by docs-writer. The boundary table and the contested rows below are recommendations for the maintainer to accept or change. Reviewers: security-reviewer (boundary rule, extension invariants), release-engineer (LICENSE, NOTICE, artefacts), policy-engineer and network-safety-engineer (the core/commercial split of their packages), mcp-protocol-engineer (MRTR approval, `Proxy.dispatch`)
- Console row superseded, and the OCSF and CEF exporter row settled, by: [ADR 0025](0025-split-the-console.md) (see *Amendments*)
- `design/` row settled by: [ADR 0024](0024-local-console-embedded-loopback-only.md) (see *Amendments*)
- Licence, contributions and the "stays open" promise superseded by: [ADR 0034](0034-source-available-under-fsl.md) (see *Amendments*)
- NetBox and Nautobot row settled (live connectors in the paid edition) by: [ADR 0034](0034-source-available-under-fsl.md), *Amendments* (see *Amendments*)

## Context

The release model was open. [ADR 0019](0019-rename-to-fathomgate.md) (proposed) renames the product so the name works whether it stays private or goes public, and leaves the licence to its own record. This is that record. On 2026-09-24 the maintainer chose open core: an open core under Apache-2.0, commercial features in a separate private repository, and outside contributions by DCO sign-off with no CLA.

Three facts shape how that lands:

| Fact | Where |
| --- | --- |
| `LICENSE` is MIT and has never been distributed: no tag, no release, the repository is private | `LICENSE`, `GOVERNANCE.md` *Licence*, `.goreleaser.yaml` (`license: MIT` in the Homebrew formula) |
| Every commit on `main` is the maintainer's, with agent co-authors, or Dependabot's (dependency version bumps). The maintainer can change the licence today without anyone else's consent, and that stops being true with the first outside contribution | `git log origin/main --format='%an'` on 2026-09-24 |
| Every Go package is under `internal/`, so no other module can import any of it. A separate commercial repository cannot plug into the core today | `go.mod`, the repo map in `CLAUDE.md` |

The product is a safety tool on production networks. An operator who puts it between an agent and a core router has to be able to read, build and audit the code that decides what reaches the router. That is what this record keeps open.

## Decision

We will publish the core under Apache-2.0 and keep commercial features in a separate private repository that depends on the core and never the reverse; anything that decides what is allowed, or proves what happened, stays in the core.

### 1. The model

- **Core** (this repository): Apache-2.0. It builds, runs and is fully safe on its own. Every class, decision, obligation and invariant works with no commercial code present.
- **Commercial** (a separate private repository): depends on the core and adds features through the seams in section 3. Its licence and packaging are not decided here.
- **Direction of dependency.** The core's `go.mod` never requires the commercial module. The core's CI never fetches, builds or tests commercial code. A core test never skips because a commercial feature is absent.

### 2. The boundary rule

**Anything that decides what is allowed, or proves what happened, stays open. Convenience, scale and integrations may be commercial.**

"Decides" covers every input to a decision the core makes: classification, the policy, the inventory data format, the approval state machine and the identity rule. "Proves" covers the audit chain and its verification. An integration that feeds the core a value (roles from NetBox, an approval from Slack) may be commercial. The rule the core applies to that value may not.

#### Roadmap mapped to each side

Milestones and requirement ids are from [ROADMAP.md](../../ROADMAP.md), [PLAN.md](../PLAN.md#milestones) and [PRD.md](../PRD.md#6-requirements). Rows marked **contested** are discussed after the table.

| Milestone | Item | Side | Rule it follows |
| --- | --- | --- | --- |
| M0 | Proxy for both protocol eras, tool-name prefixing, sealed `requestState`, the Streamable HTTP listener with named tokens (R1, R2, ADR 0008, 0016) | Core | Everything passes through it |
| M0 | GoReleaser binary and distroless image (R4) | Core | The core must build and run on its own |
| M0 | Official conformance suite, tier 1 and tier 2 tests, fixtures | Core | Proves the core behaves as specified |
| M1 | Normaliser, classification, downgrade rule (R5 to R8, R13); no fallback classifier ([ADR 0036](0036-no-fallback-classifier.md)) | Core | Decides |
| M1 | Policy DSL, `Evaluate`, `fathomgate policy test`, structured deny errors that name the rule (R9 to R11, R33) | Core | Decides |
| M1 | Static inventory, CSV import, hostname patterns, unknown-target default (R12) | Core | Decides |
| M1 | Profile format, loader and the profiles in `profiles/` for the surveyed upstreams | Core | Decides (a profile sets the class) |
| M1 | `tools/policy-lint` (R34) | Core | Tooling for the policy that decides |
| M2 | Upstream `INVENTORY_READ` provider (R14) | Core | Reads the upstream the core already talks to; no integration |
| M2 | `Resolver` chain, snapshot file format, `fathomgate inventory sync` output format, `sot: stale` marking | Core | Decides, and proves which decisions used stale data |
| M2 | NetBox and Nautobot resolvers with TTL cache and sync (R15) | Commercial candidate, **contested** | Integration |
| M2 | Redaction, keyed HMAC tokens, vendor fixture corpus (R16) | Core | Decides what the agent may see |
| M2 | TOFU description pinning and quarantine (R17); sampling refused and audited (R32) | Core | Decides |
| M3 | `ChangeSafety` drivers for Junos and EOS (R18) | Core | Decides whether a change stays |
| M3 | Pending store, TTL, expiry, drift guard, idempotent execution (R19, R22, R23) | Core | Decides |
| M3 | `approver_must_differ` on server-side identities (R24) | Core | Decides; it is a two-person rule |
| M3 | CLI approve and deny over the local socket (R20, CLI half) | Core | The one channel that needs no integration |
| M3 | HMAC-signed generic webhook (R20, webhook half) | **Contested** | Integration primitive, and today the only non-local path to a second approver |
| M3 | MRTR in-band approval (R21) | **Contested** | Protocol feature of the core proxy; identity model unresolved |
| M3 | Slack and Teams apps built on the webhook | Commercial candidate | Integration |
| M3 | Origin labels on upstream prompts (R25) | Core | Decides what a human is shown |
| M4 | Audit hash chain, Ed25519 checkpoints, `fathomgate audit verify` (R26) | Core | Proves |
| M4 | Session counters, fan-out caps, `canary_first`, maintenance windows (R28) | Core | Decides |
| M4 | OCSF and CEF exporters (R27) | Commercial candidate | Integration; reads the chain, never writes it |
| M5 | Approval console and audit viewer (R29) | Commercial candidate, **contested** | Convenience |
| M5 | IOS-XE, NX-OS, PAN-OS, FortiOS drivers and the proxy-owned rollback watchdog (R30) | Core | Decides whether a change stays |
| M5 | Optional OPA backend (R31) | Core | Decides |
| Any | `require_ticket` and `notify` obligations | Core, **contested** in part | Decides; the systems they talk to are integrations |
| Any | SSO, RBAC and multi-approver workflows (N of M, approval chains) | Commercial candidate, **contested** | Scale |
| Any | Fleet and central policy management, multi-tenant and MSP operation | Commercial candidate | Scale |
| Any | A maintained profile library with update service | Commercial candidate, **contested** | Convenience |
| Any | Key custody: file and OS keyring for audit and redaction keys | Core | Proves |
| Any | Key custody: KMS and HSM backends | Commercial candidate | Integration |
| Any | Support | Commercial | Not code |

#### Contested rows: recommendations, not decisions

| Item | Why it is contested | Recommendation |
| --- | --- | --- |
| **Generic HMAC webhook** (R20, P0 in M3, [ADR 0004](0004-approval-hold-state-machine.md)) | With only the CLI, a second approver has to log in to the proxy's host, because the CLI identity is the OS user on the local socket ([approval-protocol 6.1](../specs/approval-protocol.md)). [ADR 0016](0016-streamable-http-listener.md) already rules that an MRTR answer never satisfies `approver_must_differ`, so the webhook is the only non-local way to meet a two-person rule. Making it commercial would push operators who need that rule toward sharing a host login, which is weaker | Keep the generic signed webhook in the core, so the core has at least one non-CLI channel. Slack, Teams, ServiceNow and similar apps built on it are commercial candidates |
| **MRTR in-band approval** (R21, P1 in M3) | The elicitation machinery is already core (T0.3, ADR 0008, 0014). Approval over it is the lab operator's path (PRD user 1). Its identity model is still open: the spec names the approver `mrtr:<session principal>`, while ADR 0016 says a principal is never an approver identity | Keep it in the core, limited to rules without `approver_must_differ`, as ADR 0016 already requires. Resolve its identity model in the M3 approval record whichever side it lands on. Making it commercial would not make it safer, only less available |
| **NetBox and Nautobot resolvers** (R15, P0 in M2) | [ADR 0007](0007-role-resolver-chain-sot-optional.md) made the source of truth optional: the core works with a static file, so a commercial resolver does not break the core. But the M2 exit criterion names NetBox, NetBox is itself open source, and platform teams (PRD user 3) may read a paid resolver as a paywall on basic function | Keep the `Resolver` interface, the snapshot format and `sot: stale` marking in the core. The resolvers may be commercial. `internal/inventory/netbox.go` stays in the core as a stub until a real resolver exists, then moves out; the seam is the `Resolver` interface, not the stub. The M2 exit criterion is restated to use the snapshot, and NetBox validation moves to the commercial repository. ADR 0007 gets a dated cross-reference row when this record is accepted |
| **Approval console** (R29, P0 in M5) | Convenience, but "every held response is explainable from its trace" must hold without it | Commercial candidate, provided the core CLI shows the diff, the trace and the rule for every pending record. No one should approve blind because the console is absent |
| **`require_ticket` and `notify`** | They are obligations in the DSL (core), but each talks to an outside system | Core enforces both on its own: `require_ticket` by a ticket-reference pattern, `notify` by the generic webhook and the audit log. Lookups in ServiceNow or Jira, and delivery to chat, are commercial candidates. A policy that uses either obligation must never be allowed through unenforced because an integration is absent |
| **SSO, RBAC, multi-approver** | Scale features, but the core's two-person rule must stay meaningful | `approver_must_differ` stays core (row above). N-of-M approval and approver groups may be commercial. SSO supplies identities to the core's rule; the rule does not move |
| **Maintained profile library** | A profile sets the class, so profiles decide | The profile format, the loader and profiles for every server in research brief 02 stay core and are tested there. The commercial offer is the maintenance service: faster updates, profiles for commercial or vendor-private servers, drift alerts. An unmapped tool is `EXEC_ARBITRARY`, and under `--policy` any call to it with arguments is denied by rule `default:bad_arguments` ([ADR 0036](0036-no-fallback-classifier.md)), so a missing profile never loosens policy |
| **`design/`** | The Fathom tokens are the maintainer's design system, shared across products. Publishing them in an Apache-2.0 repository licenses them to everyone | Maintainer decision. Keep `design/` in the core for the CLI voice and docs, or move the Fathom files to their own repository under their own licence before the core becomes public. The policy layer (`policy.css`) may follow either way |

### 3. The extension seam

Commercial features plug in through seams the core exports; the core never imports them. The shape is a future ADR. The likely seams:

| Seam | Today | Likely shape |
| --- | --- | --- |
| `Resolver` chain | `internal/inventory.Resolver`, with the NetBox stub | An exported interface; an extension is one provider in the chain |
| Approval channels | Planned: one `Decide(id, verdict, approver, comment)`, where "the channel only establishes the approver's identity" ([approval-protocol 6](../specs/approval-protocol.md)) | An exported channel interface; the core owns the state machine, TTL, drift guard and `approver_must_differ` |
| Audit exporters | Planned: exporters read the JSONL and never write the chain ([audit-event-schema 8](../specs/audit-event-schema.md)) | No in-process seam needed: an exporter reads the file |
| `Proxy.dispatch` | Unexported; the M1 pipeline seam from [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md) | Stays unexported until the M1 record defines the pipeline interface |

Composition is at compile time. A commercial build is its own `main` that imports the core's exported packages plus its extensions, and registers them, in the way Caddy and CoreDNS build plugins in. This keeps one static binary with `CGO_ENABLED=0`. Go's `plugin` package needs cgo and does not run on Windows, so it is ruled out. Out-of-process extensions (gRPC or HTTP) remain an option for the future ADR, at the cost of a dependency and a trust boundary.

Exporting these interfaces moves some code out of `internal/`, which is an API commitment. The future ADR decides which packages and when; the M1 pipeline record and the M3 approval record are the natural points.

Invariants 1 to 7 in `CLAUDE.md` hold for every extension:

1. `Evaluate` stays pure. An extension supplies inputs in the `Request` (a role, a tag); it never runs inside `Evaluate`.
2. Rule order and first match are the core's. An extension never reorders, adds or skips rules.
3. An extension can make a class stricter, never lower it.
4. Redaction runs at the core's serialiser. An extension that shows tool output (the console) sees redacted output only.
5. An extension reads the audit chain; it never writes, rewrites or truncates it.
6. **Approver identity is established server-side, by the channel from its own authenticated transport: an OS user on the socket, a signature from a configured source, an SSO assertion the channel verified. Never by a plugin from data the agent supplied: a tool argument, `_meta`, an elicitation answer or a listen-token principal.** The core records the channel's namespace with the identity (`cli:`, `webhook:<source>:`), so an extension cannot pass one channel's identity off as another's.
7. What an extension reads from an upstream or a source of truth is untrusted data. A resolver that fails or times out yields `unknown`, which denies writes by default. It never yields a guessed role.

An extension may add an obligation or turn `allow` into `hold` or `deny`. It may never turn `deny` or `hold` into `allow`, skip audit, or skip redaction. The future ADR makes this a tested property.

### 4. Licensing mechanics

These land in their own pull request once this record is accepted, before any outside contribution.

- **LICENSE.** Replace MIT with the unmodified Apache-2.0 text. `GOVERNANCE.md` *Licence*, the README's *Licence* section, `CONTRIBUTING.md` and `license:` in `.goreleaser.yaml` change with it.
- **NOTICE.** A `NOTICE` file with the project's copyright line and the third-party attributions the binary carries. On 2026-09-24, `go list -deps ./cmd/fathomgate` across linux, darwin and windows links these modules. The licence is read from each module's `LICENSE` file:

  | Module | Licence |
  | --- | --- |
  | Go standard library | BSD-3-Clause |
  | `github.com/goccy/go-yaml` v1.19.2 | MIT |
  | `github.com/modelcontextprotocol/go-sdk` v1.8.0 | Apache-2.0 for new contributions, MIT for earlier ones not yet relicensed (its `LICENSE` states the transition) |
  | `github.com/google/jsonschema-go` v0.4.3 | MIT |
  | `github.com/segmentio/asm` v1.1.3, `github.com/segmentio/encoding` v0.5.4 | MIT |
  | `github.com/yosida95/uritemplate/v3` v3.0.2 | BSD-3-Clause |
  | `golang.org/x/oauth2`, `x/sync`, `x/sys`, `x/time` | BSD-3-Clause |

  All are compatible with Apache-2.0. The BSD and MIT licences require their notices in binary distributions, so the release archive and the image also carry each module's full licence text (a `THIRD_PARTY_LICENSES` directory), generated at release time from `go list -deps`. CI fails if it is stale, in the way `make status-check` does. The distroless base image carries its own package notices. The release-engineer chooses the generator; a new build-time tool needs no ADR if it never enters `go.mod`.
- **SPDX headers.** Yes: one line, `SPDX-License-Identifier: Apache-2.0`, in every Go, Python and shell source file, checked in CI. The reason is specific to open core: code moves between a public and a private repository, and a file carries its licence with it. Data files users copy and adapt (`policies/`, `profiles/`, `inventory.example.yaml`, fixtures) and Markdown are covered by `LICENSE` without a header. Per-file copyright lines are not added; `NOTICE` and git history carry authorship.
- **DCO, no CLA.** Outside contributions keep coming in under DCO sign-off ([CONTRIBUTING.md](../../CONTRIBUTING.md#sending-a-pull-request)), licensed inbound under Apache-2.0 as they go out. **Without a CLA the project holds no rights to a contribution beyond Apache-2.0, so core contributions cannot later be relicensed, for example to FSL or BSL, without the contributors' consent. The maintainer accepts this.** It is the promise that makes the core safe to depend on. The commercial repository accepts no outside contributions unless it adopts terms of its own.
- **Trademarks.** Apache-2.0 grants no trademark rights (section 6). A `TRADEMARKS.md` says what may be done with the name: forks and modified builds must not ship as "Fathomgate" or use its logo; accurate statements such as "based on Fathomgate" are allowed. It is written together with the professional clearance search [ADR 0019](0019-rename-to-fathomgate.md) recommends, and against the name ADR 0019 settles.

### 5. Visibility

Open core means the core repository becomes public eventually. When is the maintainer's decision, and it goes through [ADR 0019](0019-rename-to-fathomgate.md)'s conditional checklist, *If the repository is made public*. That checklist moves CI to GitHub-hosted runners and deregisters the self-hosted ones before visibility changes, because a pull request from a fork must never run on the maintainer's machine ([ci-runners.md](../ci-runners.md#security)). The licence pull request (section 4) and `TRADEMARKS.md` are on that checklist too.

The commercial repository stays private and keeps self-hosted CI. The security rule in `ci-runners.md` holds there because only the maintainer pushes to it. If it ever accepts outside pull requests, the rule applies to it as well.

## Consequences

### Positive

- An operator can read, build and audit every line that decides what reaches a device or proves what happened, which is what a safety tool on production networks needs in order to be trusted.
- Apache-2.0 carries an explicit patent grant and says outright that it grants no trademark rights. Enterprise legal teams approve it routinely.
- DCO keeps contributing cheap: one `-s` flag, no agreement to sign.
- The boundary rule gives one test for every future feature, instead of a case-by-case argument.
- The core cannot come to depend on commercial code by accident. The dependency direction is visible in `go.mod`, and CI enforces it.

### Negative

- The core cannot be relicensed to FSL, BSL or a proprietary licence without every contributor's consent. That is intended, and the maintainer accepts it. Only the commercial repository can carry other terms.
- Apache-2.0 lets anyone, including a competitor, sell a hosted or modified core. Mitigation: the commercial value is in scale and integrations, which are not in the core, and the name is protected by `TRADEMARKS.md`, not by the licence.
- Exporting seams out of `internal/` creates an API that must stay stable for the commercial repository. Mitigation: seams are exported only when a named record defines them, starting at M1 and M3, and nothing else leaves `internal/`.
- Several contested rows change P0 scope: M2's NetBox exit criterion, M3's webhook, M5's console. If accepted, `ROADMAP.md`, `PRD.md` and `PLAN.md` are updated in the pull request that accepts this record.
- Two repositories to build, test and release in step. Mitigation: the commercial repository pins a tagged core version and runs the core's conformance suite against its own build.
- Relicensing MIT to Apache-2.0 is free only while the maintainer is the sole author. Mitigation: the licence pull request lands before any outside contribution is merged.

### Neutral

- The licence of the commercial repository and its packaging (a separate binary, a licence key, a hosted service) are not decided here.
- Docs in this repository fall under the same licence as the code unless a later record says otherwise.
- The vocabulary, invariants and ADR process apply to the core. The commercial repository adopts them by depending on the core, not by this record.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Fully proprietary | Weak trust for a security tool on production networks: an operator cannot audit the code that stands between an agent and a core router, and the network-automation community this serves builds on open tools |
| FSL or BSL source-available core | Readable, but not open source, and enterprise legal teams review it case by case. The conversion delay (two years for FSL, up to four for BSL) keeps competitors out at the cost of contributors and packagers. The boundary rule already keeps commercial value outside the core |
| MIT core | Permissive like Apache-2.0, but with no explicit patent grant and no trademark clause. Apache-2.0 costs nothing more for users and protects contributors and users against patent claims |
| AGPL core | Many enterprise legal teams ban AGPL outright. That hurts adoption among exactly the platform and security teams the commercial features are for, and it complicates the commercial repository's own linking to the core |
| A CLA | Friction at the first contribution, and many contributors refuse to sign one for an open-core project because it permits the relicensing this record gives up. DCO is enough for inbound=outbound Apache-2.0 |

## Amendments

This section records factual corrections and pointers (GOVERNANCE.md). It does not change the decision.

| Date | What changed | Why |
| --- | --- | --- |
| 2026-09-25 | Pointer: the *Approval console* contested row and the M5 row "Approval console and audit viewer (R29)" are superseded by [ADR 0025](0025-split-the-console.md) (accepted 2026-09-25). A local console for one operator on one machine is core, in M5 (R29); the team console (SSO, RBAC, multi-approver, fleet view, central policy, retention and search, SIEM export) is in the paid edition. The row's condition is kept: the core CLI shows the diff, the rule trace and the rule for every pending record (PRD R35). *Negative*'s "M5's console" item is carried out in ROADMAP.md, PLAN.md and PRD.md by the same pull request. The boundary rule and every other row are unchanged | Maintainer decision, Josh Scott, 2026-09-25. It departs from the row's recommendation (whole console commercial), so it is its own record rather than an amendment here |
| 2026-09-25 | Pointer: the M4 row "OCSF and CEF exporters (R27)", a commercial candidate, is settled as **Commercial** by [ADR 0025](0025-split-the-console.md) decision 2. The audit chain, the Ed25519 checkpoints and `fathomgate audit verify` stay core, as the row above them already says; the exporters read the chain and never write it. The *Audit exporters* seam in section 3 is unchanged | Maintainer decision, Josh Scott, 2026-09-25 |
| 2026-09-25 | Pointer: the `design/` contested row is settled by the maintainer's answer to question 4 of [ADR 0024](0024-local-console-embedded-loopback-only.md) (accepted 2026-09-25). `design/` (`tokens.css`, `policy.css`, `preview.html`, `DESIGN.md` and the reference mockups in `design/reference/`) is under Apache-2.0 like the rest of the core, and the Fathom files do not move to a repository of their own. Fonts keep their own licence, the SIL Open Font License 1.1. The logo in `design/brand/` and the name are governed by [TRADEMARKS.md](../../TRADEMARKS.md), not by the code licence. The boundary rule and every other row are unchanged | Maintainer decision, Josh Scott, 2026-09-25. The row left the choice to the maintainer; a core console built on `design/` (ADR 0024) ships these files in the Apache-2.0 binary, so it had to be made |
| 2026-09-25 | Pointer: section 4 (Apache-2.0 `LICENSE`, the Apache SPDX line, outside contributions by DCO with no CLA), the licence named in section 1, and the promise in section 2 that the core "stays open" are superseded by [ADR 0034](0034-source-available-under-fsl.md) (accepted 2026-09-25). Versions made available from the relicensing commit on are under `FSL-1.1-ALv2`, each converting to Apache-2.0 two years after it is made available; `policies/examples/` and `profiles/` stay Apache-2.0; `v0.1.0` and every commit before the relicensing commit remain Apache-2.0. The project accepts no outside code for now. The boundary rule (now worded "stays in the public repository, source-available and auditable"), the boundary table, section 3 and the dependency direction are unchanged | Maintainer decision, Josh Scott, 2026-09-25. It changes the decision, so it is its own record |
| 2026-09-25 | Pointer: the contested row "NetBox and Nautobot resolvers" and the M2 row "NetBox and Nautobot resolvers with TTL cache and sync (R15)" are settled as **Commercial** for the live connectors (API lookup, auto-sync, caching and freshness checks), as the row recommended, in the *Amendments* of [ADR 0034](0034-source-available-under-fsl.md), the current record of the commercial boundary. The `Resolver` interface, the snapshot format, `sot: stale` marking, the static file, hostname patterns and CSV import stay in the core. `internal/inventory/netbox.go` stays a stub in the core until the paid resolver exists, then leaves; the seam is the `Resolver` interface (section 3). *Negative*'s "M2's NetBox exit criterion" item is carried out in ROADMAP.md, PLAN.md and PRD.md by the same pull request. The boundary rule and every other row are unchanged | Maintainer decision, Josh Scott, 2026-09-25 |

## References

- [ADR 0019, rename to Fathomgate](0019-rename-to-fathomgate.md) (proposed): *If the repository is made public*, the trademark clearance recommendation
- [ADR 0004, approval hold state machine](0004-approval-hold-state-machine.md); [approval-protocol](../specs/approval-protocol.md) sections 6 (decision channels) and 8 (separation of duties)
- [ADR 0007, role resolver chain with the source of truth optional](0007-role-resolver-chain-sot-optional.md)
- [ADR 0012, `netguard serve` flags and the `internal/proxy` API for M0](0012-serve-cli-and-proxy-api-for-m0.md) (`Proxy.dispatch` as the M1 seam)
- [ADR 0016, Streamable HTTP listener](0016-streamable-http-listener.md) (a principal is never an approver identity)
- [audit-event-schema 8, exporters](../specs/audit-event-schema.md); [classification 3, tools with no profile entry](../specs/classification.md#3-tools-with-no-profile-entry); [policy-schema, obligations](../specs/policy-schema.md)
- [ROADMAP.md](../../ROADMAP.md), [PLAN.md milestones](../PLAN.md#milestones), [PRD.md requirements](../PRD.md#6-requirements)
- [ci-runners.md](../ci-runners.md), section *Security*
- [CONTRIBUTING.md, Sending a pull request](../../CONTRIBUTING.md#sending-a-pull-request); [GOVERNANCE.md, Licence](../../GOVERNANCE.md#licence)
- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), section 6 (trademarks); [Developer Certificate of Origin 1.1](https://developercertificate.org/); [SPDX license identifiers](https://spdx.org/licenses/)
- This record is not legal advice. The licence text is used unmodified; the trademark policy is written with the professional clearance ADR 0019 recommends.
