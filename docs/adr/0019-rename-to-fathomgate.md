# ADR 0019: Rename the product from NetGuard to Fathomgate

- Status: accepted
- Date: 2026-09-24
- Deciders: Josh Scott (maintainer; chose the name `fathomgate` on 2026-09-24); accepted with the scope below on 2026-09-24); proposed by docs-writer. Reviewers: release-engineer (module path, artefacts), mcp-protocol-engineer (sealed-state prefix, reserved name), security-reviewer (the checklist in *If the repository is made public*), design-guardian (display name and voice)

## Context

"NetGuard" is a placeholder. [PLAN.md](../PLAN.md#decision-summary) records it as a working name to replace before the first release, because it collides with existing products, and [PRD.md](../PRD.md#7-open-questions) lists the final name as open. On 2026-09-24 the maintainer chose **fathomgate**. The release model is undecided: the product may stay private as a commercial or licensed product, or be made public as open source, source-available or open core. The name was chosen to work on any of those paths, so this record depends on neither visibility nor licence.

The name is more than prose. On `main` at `a8a7be0`, `git grep -i -o netguard | wc -l` counts 1,770 occurrences in 196 tracked files, and these identifiers carry it:

| Identifier | Today | Where |
| --- | --- | --- |
| Go module path | `github.com/joshscott13/netguard` | `go.mod`, every internal import, `Makefile` `MODULE` |
| Binary and command | `netguard` | `cmd/netguard`, `Makefile` `BINARY`, `.goreleaser.yaml`, `Dockerfile`, `Dockerfile.goreleaser`, `.gitignore` |
| MCP implementation name and origin label | `netguard`, `[from netguard]` | `internal/proxy/proxy.go` (`Name`); `internal/proxy/name.go` reserves it as an upstream server name |
| Environment-variable prefix | `NETGUARD_*`: `NETGUARD_REDACT_KEY`, `NETGUARD_LISTEN_TOKEN` (ADR 0016, not yet built), test and CI variables such as `NETGUARD_TIER` and `NETGUARD_BIN`, the repository variable `NETGUARD_WINDOWS_RUNNER` | `cmd/netguard/serve.go` refuses to pass any `NETGUARD_*` variable to an upstream |
| Sealed `requestState` prefix | `ng3.`, with `ng1.` and `ng2.` retired | `internal/proxy/state.go`; [profile-schema 8.2 and 8.4](../specs/profile-schema.md#84-protocol-eras-_meta-and-input-requests) |
| CSS class prefix | `ng-` (`ng-decision`, `ng-redacted`, `ng-trace`, `ng-timeline`) | `design/policy.css`, `design/DESIGN.md` |
| Release artefacts | archive `netguard_<version>_<os>_<arch>`, formula `netguard` in `joshscott13/homebrew-tap`, image `ghcr.io/joshscott13/netguard` | `.goreleaser.yaml`, `.github/workflows/snapshot.yaml` |
| Paths | `/etc/netguard` in the image; `$XDG_RUNTIME_DIR/netguard.sock` (approval CLI, M3, spec only) | `Dockerfile`, [approval-protocol](../specs/approval-protocol.md) |
| Agent slug | `netguard-orchestrator` | `.claude/agents/`, `docs/handoffs/README.md`, `docs/milestones/M0.yaml` |
| Test names | conformance legs `netguard` and `netguard-up2025`, Python class `Netguard`, package `netguard-tests` | `Makefile`, `tests/` |
| Self-hosted runners | label `netguard`, runners `ng-wsl-1` to `ng-wsl-3` | every `runs-on` except tier 3, [ci-runners.md](../ci-runners.md) |

No version has been tagged and no one outside the maintainer runs the binary, so none of these identifiers has a compatibility obligation yet. After the first tag or the first distributed build, each one would.

### Evidence for the name

Searches run by the maintainer on 2026-09-24. They are research, not legal clearance.

| Check | Result |
| --- | --- |
| Domains | `fathomgate.com`, `fathomgate.dev` and `fathomgate.io` unregistered (Verisign RDAP, no record). The `.com` was registered around 2021 and has lapsed |
| GitHub | The user or organisation name `fathomgate` is free |
| Package registries | No Homebrew formula, PyPI package, npm package or Docker official image |
| Existing use | No software product or repository. The only prior use is a 2002 RPG review site |
| Trademarks | No FATHOMGATE mark in the WIPO Global Brand Database, which includes US and EU data |
| Risk | FATHOM on its own is crowded: 117 class-9 records, many live, including FATHOM LABS (Perma Security, US 98717328, classes 9 and 42, pending), Fathom Video (US 99661894, classes 9 and 42, pending) and Helsing (EU 019186329). The Fathom AI notetaker ships an official MCP server, so a search for "fathom mcp" finds it first |

It fits the product: it extends the Fathom design system ([ADR 0009](0009-fathom-design-system-policy-layer.md)), and a gate decides what passes, which is what `allow`, `hold` and `deny` do.

A professional trademark clearance search in classes 9 and 42 is recommended before any commercial or public use of the name. The searches above cannot replace it, and the crowded FATHOM field is the reason.

## Decision

We will rename the product to Fathomgate and its binary, module and identifiers to `fathomgate`, in one pull request that lands after T0.48 merges and before T0.31 opens; the repository's visibility and licence do not change.

### Scope

| Item | Today | After the rename |
| --- | --- | --- |
| Display name in prose, headings and UI | NetGuard | Fathomgate |
| Binary, command, CLI usage text, log and error text | `netguard` | `fathomgate` |
| Go module path | `github.com/joshscott13/netguard` | `github.com/fathomgate/fathomgate` |
| Repository | `joshscott13/netguard` | `fathomgate/fathomgate`, transferred and renamed; GitHub redirects the old web and git URLs |
| MCP implementation name, origin label | `netguard`, `[from netguard]` | `fathomgate`, `[from fathomgate]` |
| Reserved upstream server name | `netguard` | `fathomgate`, same folding rule (`Fathom-Gate`, `fathom_gate2` are reserved); `netguard` is no longer reserved |
| Environment-variable prefix | `NETGUARD_` | `FATHOMGATE_`, including the upstream-refusal rule in `serve.go` and the repository variable `FATHOMGATE_WINDOWS_RUNNER`. `NETGUARD_*` is not read as a fallback |
| Sealed `requestState` prefix | `ng3.` | `fg4.`; `ng1.`, `ng2.` and `ng3.` are retired |
| CSS class prefix | `ng-` | `fg-` |
| Image paths | `/etc/netguard` | `/etc/fathomgate` |
| Approval socket (spec only) | `$XDG_RUNTIME_DIR/netguard.sock` | `$XDG_RUNTIME_DIR/fathomgate.sock` |
| Release archive | `netguard_<version>_<os>_<arch>` | `fathomgate_<version>_<os>_<arch>` |
| Homebrew formula, if the product is distributed through Homebrew | `netguard` in `joshscott13/homebrew-tap` | `fathomgate` in `fathomgate/homebrew-tap` (`brew install fathomgate/tap/fathomgate`) |
| Container image, if one is published | `ghcr.io/joshscott13/netguard` | `ghcr.io/fathomgate/fathomgate` |
| `mcp.json` snippets | `"command": "/usr/local/bin/netguard"` | `"command": "/usr/local/bin/fathomgate"`; the `mcpServers` key stays the upstream's name (`netdev`), since the agent sees the upstream's tools, not the proxy |
| Agent slug | `netguard-orchestrator` | `orchestrator`, so the slug never carries a product name again |
| Test names | legs `netguard`, `netguard-up2025`; class `Netguard`; `netguard-tests` | `fathomgate`, `fathomgate-up2025`; `Fathomgate`; `fathomgate-tests`; conformance baselines are re-keyed to the new leg names |
| Self-hosted runner label and names | `netguard`, `ng-wsl-1` to `ng-wsl-3` | Unchanged. The rename pull request's own CI has to find runners by that label, and the runners are machine-local |

These carry no product name and do not change: the audit event schema, the redaction token format (`hmac:` prefix), rule ids, classes, obligations and tool prefixes (which are upstream server names).

### Display name

The product is **Fathomgate** in prose, headings and UI: one word, capital F only. `fathomgate` in mono is the command, binary, module, image, formula or any other typed value, as `netguard` is today.

- Never "FathomGate", "Fathom Gate", "fathom-gate", or "FATHOMGATE" outside the environment-variable prefix.
- Never shortened to "Fathom". Fathom is the design system (ADR 0009) and another company's product.

Why not "FathomGate": the inner capital splits the coined word back into FATHOM, the crowded part of the name, plus a generic word, which is the reading the evidence above argues against. It is also brand styling, and [DESIGN.md](../../design/DESIGN.md#voice) is plain: sentence-case headings, technical values typed exactly. One word with one capital reads the same at the start of a sentence, in a heading and in running text, and differs from the command only in case.

### Environment-variable prefix

`FATHOMGATE_` is 11 characters against `NETGUARD_`'s 9, and it is typed rarely: once in an `env` block or a CI file. The shorter options fail on a rule `serve` enforces. `serve` refuses to pass any variable with its own prefix to an upstream, so a prefix another tool uses would stop an upstream from receiving its own setting. `FG_` and `FGATE_` read as FortiGate, whose models are named `FG-…` and which is one of the firewall families this proxy fronts. `FATHOMGATE_` collides with nothing. No one has a config that sets `NETGUARD_*`, so there is no fallback read and no deprecation warning.

### Sealed `requestState` prefix and wire compatibility

The prefix changes to `fg4.`, and `ng3.` joins `ng1.` and `ng2.` in `retiredStatePrefixes`.

- Changing it breaks nothing that works today. The sealing key is random per process, so every envelope is already invalid after a restart, and an upgrade is a restart. A retired prefix gets the existing detail, reworded to `requestState was issued by an earlier fathomgate process; call the tool again without it`.
- The prefix is authenticated as additional data, so this is an envelope format change. It lands with profile-schema 8.2 and 8.4 updated and a test that `ng3.` is refused as retired.
- The number continues at 4, so the digit keeps counting formats and the retired list reads in order.
- Keeping `ng3.` costs nothing today, but every `requestState` an agent sees would carry the old name, and changing it after a first release costs the same one retired entry plus a release note. Now is the cheapest time.

### Module path and repository

The module path is `github.com/fathomgate/fathomgate`, which needs the `fathomgate` GitHub organisation. Every package is under `internal/`, so no other module imports this one; the path matters for its own imports and for `go install github.com/fathomgate/fathomgate/cmd/fathomgate@<version>`. A build inside the module never resolves its own path, so the rename pull request can merge before the transfer. The organisation can hold a private repository, so the path is the same on either release path.

- The maintainer creates the organisation, then transfers `joshscott13/netguard` into it and renames it `fathomgate`. GitHub redirects the old URLs for the web and for git.
- The Go module proxy does not redirect: fetching the old path returns a module that declares the new one, and `go` refuses it. No one fetches the old path.
- Self-hosted runners registered to the repository may not follow a transfer. After it, `gh api repos/fathomgate/fathomgate/actions/runners` must list `ng-wsl-1` to `ng-wsl-3`; if it does not, re-register them with the new URL as in [ci-runners.md](../ci-runners.md#one-time-setup-already-done-for-ng-wsl-13).
- The `gh api` and registration URLs in `ci-runners.md` and `tools/ci/wsl-runner-setup.sh` change to `fathomgate/fathomgate` in the rename pull request.

### What is not renamed

A record of what happened stays as written. A document that describes what the software is or does now is renamed.

| Left as written | Renamed |
| --- | --- |
| Git history, commit messages, merged pull request titles | Code, tests, `Makefile`, workflows, GoReleaser and Docker files |
| ADRs 0001 to 0018, titles and bodies (they name `netguard serve`, `NETGUARD_LISTEN_TOKEN` and `ng3.` as decided at the time) | `docs/specs/`, `ARCHITECTURE.md`, `README.md`, `docs/install.md`, `ROADMAP.md`, `docs/PLAN.md`, `docs/PRD.md`, `CLAUDE.md`, `AGENTS.md`, `CONTRIBUTING.md`, `GOVERNANCE.md`, `SECURITY.md`, `docs/security/`, `docs/glossary.md`, `docs/testing/`, `docs/ci-runners.md` |
| Handoff notes in `docs/handoffs/` and their file names | `design/`, `docs/agents/`, `.claude/agents/`, `.claude/commands/` |
| Research briefs in `docs/research/` (dated, cited data) | `CHANGELOG.md` `[Unreleased]`: nothing has been released, so it describes the first release, which ships as `fathomgate` |
| `notes` and titles of `merged` or `validated` tasks in `docs/milestones/M0.yaml` | Titles of `open` and `blocked` tasks, and every `owner` and `reviewers` slug on the board |

The rename pull request adds one sentence to `docs/adr/README.md` and to `docs/handoffs/README.md`: records before ADR 0019 use the placeholder name NetGuard and the identifiers in this record's scope table, and are left as written. The scope table is the map from the old identifiers to the new ones.

### Sequencing

1. This record is accepted.
2. T0.48 (the follow-ups from the T0.30 reviews) merges. It changes `internal/proxy/state.go`, which the rename also changes.
3. The orchestrator adds the rename to the board as its own task. One pull request carries the whole scope table, with a `CHANGELOG.md` line under Changed. It touches `internal/proxy` and `go.mod`, so it needs `make conformance`, and it touches imports in `internal/redact`, `internal/policy`, `internal/classify` and `internal/audit`, so it needs a security review.
4. T0.31 opens after it, so `--listen` and its token variable are built as `fathomgate serve` and `FATHOMGATE_LISTEN_TOKEN` from the start. Open tasks in `internal/proxy` (T0.46, T0.47 today) rebase onto the rename.
5. The maintainer creates the organisation and transfers the repository, then checks the runners (above).

The repository stays private throughout. Nothing in this record changes its visibility or its licence.

### If the repository is made public

Whether the repository is made public is undecided and is not part of this decision. The licence is decided in its own future ADR: the current MIT `LICENSE` has never been distributed, so it can still change. If and when the maintainer decides to make the repository public, these steps come first, in this order:

1. **Move CI to GitHub-hosted runners and deregister the self-hosted ones before visibility changes.** [ci-runners.md](../ci-runners.md#security): a pull request from a fork must never run on the maintainer's machine. Every `runs-on: [self-hosted, …]` in `ci.yaml`, `snapshot.yaml` and `release.yaml` moves to a hosted label, and `ci-runners.md` is rewritten in the same pull request. `gh api repos/fathomgate/fathomgate/actions/runners -q '.runners[]|.name'` must print nothing before visibility changes. A tier 3 runner (`nightly-clab.yaml`, `[self-hosted, clab]`) may exist only if its workflow never runs on `pull_request`; today it runs on `schedule` and `workflow_dispatch` only.
2. **Review what becomes visible.** The full git history, including research briefs, handoff notes, the milestone board and its `notes`, the linked artifacts in `design/DESIGN.md` and `docs/PLAN.md`, local paths from the maintainer's machine, and the Issues that mirror the board. Fixture secrets are all `FAKE`-prefixed; confirm it with a secret scan of the whole history, not the working tree alone.
3. **Register the domains and confirm the GitHub organisation** (maintainer). `fathomgate.com`, `fathomgate.dev` and `fathomgate.io` were unregistered on 2026-09-24; nothing guarantees they still are.
4. **Complete the professional trademark clearance search** in classes 9 and 42, if it has not already been done for commercial use.
5. **Accept the licence ADR.**

## Consequences

### Positive

- The product has a name that no software product, repository, package or registered mark uses, as of the searches above.
- Every identifier changes once, before any has a compatibility obligation. After a first tag or distribution each would need a migration, a fallback or a retired entry.
- The decision holds on every release path: private, commercial, source-available or open source.
- The environment-variable prefix cannot swallow another tool's variables, so `serve`'s refusal rule stays safe to enforce.

### Negative

- FATHOM is a crowded mark in class 9, and the Fathom notetaker's MCP server competes for the same searches. Mitigation: the product is always written as one word, never shortened to "Fathom"; the professional clearance search is recommended before any commercial or public use; this record can be superseded if that search says so.
- The product and its design system now share a root: Fathomgate uses Fathom. Mitigation: the display-name rule above; ADR 0009's name for the design system is unchanged.
- The rename pull request touches about 200 files and conflicts with every open branch. Mitigation: it lands between T0.48 and T0.31, when the fewest branches are open, and open branches rebase onto it mechanically.
- The runner label stays `netguard` until the self-hosted runners go, so one identifier keeps the old name for a while.
- Reading older ADRs and handoff notes needs the scope table as a map.

### Neutral

- Tool prefixes, rule ids, classes, obligations, the audit schema and the redaction token format carry no product name and do not change.
- The `mcp.json` server key the user chooses is unaffected; only the `command` path changes.
- Visibility and licence are unchanged. Each is its own decision.

## Alternatives considered

### Names

Every plain nautical dictionary word checked (belay, bulwark, bollard, portcullis, capstan and others) was taken as a `.com` and as a GitHub owner.

| Alternative | Why not |
| --- | --- |
| Keep NetGuard | Collides with existing products; PLAN.md recorded it as a placeholder from the start |
| heaveto | Clear otherwise, but the `.com` is for sale at $4,965 and the GitHub name is taken |
| stopknot | Sounds like "stop not"; rhymes with Slipknot |
| quaymaster | Confusable with Red Hat Quay, a registered mark with its own MCP server |
| belaypoint | A 2026 MCP proxy, `belay-mcp`, with policies and approvals already exists |
| plimsol | A misspelling of Plimsoll, which several 2026 AI-agent security tools and ITV's trademarks use |
| tideward | Pending USPTO class-9 mark 99800434; sounds like Tidewave, an MCP tool |
| helmgate | Helm's trademark, and an existing Helm security scanner |

### Scope

| Alternative | Why not |
| --- | --- |
| Display name "FathomGate" | Splits the coined word back into the crowded FATHOM plus a generic word; brand styling the voice rules do not use |
| Module path `github.com/joshscott13/fathomgate` | Needs no organisation today, but moving to one later changes the path a second time, and the organisation name could be taken meanwhile |
| Vanity module path `fathomgate.dev/fathomgate` | Independent of the code host, but needs the domain and a `go-import` page kept up for as long as anyone installs it, and a lapsed domain breaks every install; the `.com` has lapsed once already. Stays open if the code ever leaves GitHub |
| Environment prefix `FG_` or `FGATE_` | Reads as FortiGate, and `serve` refuses to pass its own prefix to an upstream, so a FortiGate upstream's `FG_*` setting would be refused |
| Read `NETGUARD_*` as a fallback, with a warning | There are no existing configs to protect; the fallback would be code and a test with no user |
| Keep the `ng3.` prefix | Free today, but leaves the old name in every `requestState` an agent sees; changing it later costs the same plus a release note |
| Restart the prefix at `fg1.` | Works, but loses the count of formats and reads as a sibling of `ng1.` |
| Keep `netguard` reserved as a server name as well | An upstream named `netguard` would be labelled `[from netguard]`, which no longer names the proxy |
| Keep `ng-` CSS classes | `ng-` is also AngularJS's directive prefix, a collision on any page that embeds the console |
| Rename in stages (code first, docs later) | Leaves `main` describing two products at once; docs change in the same pull request as the code |
| Rename history too (past ADRs, handoff notes) | Rewrites records of decisions as they were made; accepted ADRs change only by amendment or supersession ([GOVERNANCE.md](../../GOVERNANCE.md#architecture-decisions)) |

## References

- [PLAN.md, decision summary](../PLAN.md#decision-summary) and [open questions](../PLAN.md#open-questions-and-risks)
- [PRD.md, open questions](../PRD.md#7-open-questions)
- [ADR 0009, Fathom design system plus a policy layer](0009-fathom-design-system-policy-layer.md)
- [ADR 0016, Streamable HTTP listener](0016-streamable-http-listener.md) (`NETGUARD_LISTEN_TOKEN`, the principal binding in `ng3.`)
- [design/DESIGN.md, Voice](../../design/DESIGN.md#voice)
- [docs/ci-runners.md](../ci-runners.md), section *Security*
- [profile-schema 8.2 and 8.4](../specs/profile-schema.md#84-protocol-eras-_meta-and-input-requests)
- `internal/proxy/state.go` (`statePrefix`, `retiredStatePrefixes`), `internal/proxy/name.go` (`ValidateServerName`, `reservedServerName`), `internal/proxy/proxy.go` (`Name`), `cmd/netguard/serve.go` (`isNetguardEnvName`)
- [M0 board](../milestones/M0.yaml): T0.48 (lands before the rename), T0.31 (opens after it), T0.46 and T0.47 (rebase onto it)
- Name searches, 2026-09-24 (maintainer): Verisign RDAP for `.com`, `.dev`, `.io`; GitHub; Homebrew, PyPI, npm, Docker Hub; WIPO Global Brand Database; USPTO and EUIPO records cited by number above
