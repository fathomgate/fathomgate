# ADR 0034: Future versions under the Functional Source License (FSL-1.1-ALv2); everything already published stays Apache-2.0

- Status: accepted
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer), who decided on 2026-09-25 to move future versions from Apache-2.0 open core to a source-available licence, and accepted this record on 2026-09-25 with the answers under *Decisions on the open questions*. Proposed by docs-writer with the orchestrator. Reviewers: release-engineer (LICENSE, NOTICE, SPDX, artefacts), security-reviewer (auditability), design-guardian (voice of the README, ROADMAP and TRADEMARKS rewrites). The relicensing pull request merges only after the maintainer confirms a lawyer's review or waives it (decision 7)
- Supersedes: [ADR 0020](0020-open-core-apache-2.md) section 4 (licensing mechanics: Apache-2.0 `LICENSE`, the Apache SPDX line, outside contributions by DCO with no CLA), the licence named in its section 1, and the promise in its section 2 that the core "stays open". The boundary table, the extension seam, the extension invariants and the dependency direction in ADR 0020 are unchanged. Also supersedes the licence in the answer to question 4 of [ADR 0024](0024-local-console-embedded-loopback-only.md) (`design/` under Apache-2.0): `design/` follows the repository licence (decision 1). The fonts keep OFL-1.1 and the logo stays under [TRADEMARKS.md](../../TRADEMARKS.md)
- Amends: [ADR 0025](0025-split-the-console.md), which describes the core as open and Apache-2.0. The split it decides (local console in the core, team console and OCSF and CEF exporters in the paid edition) is unchanged

## Context

[ADR 0020](0020-open-core-apache-2.md), accepted on 2026-09-24, put the core under Apache-2.0 with DCO sign-off and no CLA, and said the core could not later move to FSL or BSL without every contributor's consent. On 2026-09-25 the maintainer decided that Fathomgate is a commercial product. He wants to stop others reselling it, and to keep the code readable and auditable by the operators who run it in front of their routers.

Whether he can do that depends on who holds copyright, and on what is already published:

| Fact | Where, as of 2026-09-25 |
| --- | --- |
| The repository `fathomgate/fathomgate` has been public since 2026-09-24. GitHub reports its licence as `Apache-2.0` | `gh api repos/fathomgate/fathomgate` |
| `v0.1.0` (M0, pass-through) was tagged at `38d7d6a` and released on 2026-09-25. Its assets have 4 downloads | `gh release view v0.1.0` |
| 0 stars, 0 forks, 0 watchers | `gh api repos/fathomgate/fathomgate` |
| Of 480 commits on `main`, 465 are the maintainer's (under the names `Josh Scott` and `Josh`) and 15 are Dependabot's dependency version bumps. The only `Co-authored-by` trailers name AI models. No outside pull request has been merged | `git log origin/main --format='%an <%ae>'` and `--format='%(trailers:key=Co-authored-by)'` on `8c3299e` |
| M1 code is already on `main` under Apache-2.0: `internal/gate`, `internal/policy`, `internal/classify`, `internal/redact`, `internal/audit` | `ls internal/` on `8c3299e` |

So the maintainer holds the copyright in every line and can license *future* versions on any terms without anyone's consent. The lawyer's review, if the maintainer asks for one, confirms that the Dependabot commits (version strings and checksums) and the AI co-author trailers give no one else a claim (decision 7).

He cannot take back what is published. Apache-2.0 section 2 grants its copyright licence as "perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable", and section 3 grants its patent licence the same way. **`v0.1.0`, and every commit on `main` before the relicensing commit, stay under Apache-2.0 for good.** Anyone may fork the last Apache-2.0 commit, including the M1 policy engine merged so far, and sell it or offer it as a service. The only limit is the name ([TRADEMARKS.md](../../TRADEMARKS.md)). The relicensing protects only work that comes after it, so the later it lands, the more Apache-2.0 code a reseller can start from.

The product is a safety tool on production networks. ADR 0020's reason for publishing the source still holds: an operator who puts Fathomgate between an agent and a core router has to be able to read, build and audit the code that decides what reaches the router. Any new licence must keep that.

## Decision

We will license every version of Fathomgate made available after the relicensing commit under the Functional Source License, Version 1.1, ALv2 Future License (`FSL-1.1-ALv2`), unmodified, except `policies/examples/` and `profiles/`, which stay Apache-2.0. Everything published before that commit stays under Apache-2.0. The paid edition stays proprietary in its private repository.

### 1. The licence

Verified on 2026-09-25 by fetching the sources below:

| Item | Value | Source |
| --- | --- | --- |
| Name | Functional Source License, Version 1.1, ALv2 Future License | [fsl.software/FSL-1.1-ALv2.template.md](https://fsl.software/FSL-1.1-ALv2.template.md) |
| SPDX id | `FSL-1.1-ALv2`, on the SPDX License List 3.29.0 (2026-09-16); not OSI-approved | [spdx.org/licenses/licenses.json](https://spdx.org/licenses/licenses.json) |
| Current version | 1.1. fsl.software offers only 1.1, in two variants: `FSL-1.1-ALv2` and `FSL-1.1-MIT` | [fsl.software](https://fsl.software/) |
| Steward | Sentry, as part of the Fair Source initiative | [fsl.software](https://fsl.software/), [fair.io](https://fair.io/) |

What the text grants, quoted where the wording matters:

- **Licence grant.** "use, copy, modify, create derivative works, publicly perform, publicly display and redistribute the Software for any Permitted Purpose".
- **Permitted Purpose** is "any purpose other than a Competing Use". A Competing Use is "making the Software available to others in a commercial product or service that: 1. substitutes for the Software; 2. substitutes for any other product or service we offer using the Software that exists as of the date we make the Software available; or 3. offers the same or substantially similar functionality as the Software."
- **Named Permitted Purposes:** "your internal use and access", "non-commercial education", "non-commercial research", and use "in connection with professional services that you provide to a licensee using the Software in accordance with these Terms and Conditions".
- **Patents.** A patent licence for Permitted Purposes, which ends for anyone who claims the Software infringes a patent.
- **Redistribution.** Copies and derivatives carry the same terms, a copy of or link to them, and every copyright notice.
- **Trademarks.** No right to the names or marks beyond "displaying the License Details and identifying us as the origin of the Software".
- **Future licence.** "an additional license to use the Software under the Apache License, Version 2.0 that is effective on the second anniversary of the date we make the Software available." The grant is irrevocable.

**When a version converts.** The FSL's FAQ counts "pushing a Git commit" as making a version available. Because the repository is public, each commit on `main` converts to Apache-2.0 two years after it is pushed, not only each tag. Release notes record each tag's conversion date: `v0.2.0` tagged on date D converts on D plus two years.

**What stays Apache-2.0 after the relicensing commit.** Two directories hold data that users copy into their own configuration, and that the community is invited to extend:

| Path | Licence | How it is marked |
| --- | --- | --- |
| `policies/examples/` | Apache-2.0 | Its own `LICENSE` file with the Apache-2.0 text; a path rule in `NOTICE` and the README; an Apache-2.0 SPDX line on any Go, Python or shell file added there |
| `profiles/` | Apache-2.0 | The same |
| Everything else: the proxy, the gate, the policy engine, classification, redaction, audit, inventory, the CLI, the tools, the tests, `design/` and the docs | `FSL-1.1-ALv2` | The root `LICENSE`, and an `FSL-1.1-ALv2` SPDX line on every Go, Python and shell file |

When profiles are embedded in the binary ([ADR 0027](0027-serve-policy-inventory-profiles-flags.md)), the binary carries both licences, and `NOTICE` says which files are which.

**What this means in practice** (rows marked † are on the lawyer's list in decision 7):

| Use | Under `FSL-1.1-ALv2` |
| --- | --- |
| Run Fathomgate in front of your own devices, in production, at any scale | Allowed ("internal use") |
| Read, build, audit and modify it; publish findings; report vulnerabilities | Allowed |
| Redistribute it, changed or not, with the terms and notices | Allowed, for a Permitted Purpose |
| An MSP runs it for a customer's network as part of its services (PRD user 2) | Allowed as "professional services" † |
| Sell or host Fathomgate, or a product with the same or substantially similar function, to others | Not allowed until that version converts |
| Copy, adapt and republish an example policy or a profile, for any purpose | Allowed, under Apache-2.0 |
| Build a competing product from a version more than two years old | Allowed, under Apache-2.0 |
| Build anything from `v0.1.0` or a commit before the relicensing commit | Allowed, under Apache-2.0, now |

**Why FSL fits a security product.** Auditability is the requirement, and FSL meets it in full: every line is public on the day it is written, including the parts that decide and prove. It uses one standard text with no per-project grant, so an enterprise legal team reviews a known licence once, and SBOM scanners recognise its SPDX id. Two years is short enough that operators can see the code become Apache-2.0, patent grant included. It stops resale, and nothing else.

### 2. The paid edition and the boundary

The paid edition (ADR 0025's team console, the OCSF and CEF exporters, and the other commercial rows of ADR 0020 section 2) stays proprietary in its private repository. ADR 0020's boundary stays as the product line:

- ADR 0020 section 2's table, as amended by ADR 0025, still says what is in the public repository and what is in the paid edition. Nothing moves across the line in this record. The M5 local console and the M5 `ChangeSafety` drivers stay in the public repository (answer 4).
- ADR 0020 section 3 (the extension seam, the dependency direction and invariants 1 to 7 for extensions) is unchanged.
- FSL's second Competing Use limb also covers a product that substitutes for the paid edition, where that edition exists on the day a version is made available.

The promise changes wording, not scope:

| ADR 0020 said | This record says |
| --- | --- |
| Anything that decides what is allowed, or proves what happened, stays open. | Anything that decides what is allowed, or proves what happened, stays in the public repository: source-available, auditable and buildable by anyone, and each version converts to Apache-2.0 two years after it is made available. |
| The core is Apache-2.0 "and always will be" ([ROADMAP.md](../../ROADMAP.md#what-we-believe)) | The core was Apache-2.0 up to the relicensing commit and stays so for those versions. Later versions are `FSL-1.1-ALv2` |

The public repository stays public.

### 3. Contributions: no outside code for now

The project does not accept code from outside contributors.

- **Issues are the way in.** Ideas, bug reports, profile requests and redaction gaps come in as issues, through the existing templates. The maintainer writes the code. A profile or policy pasted into an issue is treated as a report: the maintainer writes the file himself rather than committing the pasted text.
- **Pull requests from others are closed kindly**, with thanks and a pointer to open an issue instead.
- **The maintainer's own commits keep DCO sign-off** (`git commit -s`). It costs nothing and keeps the history uniform.

**Why not DCO for outsiders.** With DCO and no CLA, a contribution comes in under the licence of the file it changes. The project then holds only FSL rights to it, as any user does. It cannot relicense that contribution, or move it into the proprietary paid edition, without the contributor's consent. That is ADR 0020's lock again, one contributor at a time. The DCO 1.1 text also certifies the right to submit "under the open source license indicated in the file", and `FSL-1.1-ALv2` is not an open-source licence.

**The future path, recorded now.** Before the project ever accepts outside code, it adopts a CLA that grants a licence, not an assignment, and keeps DCO sign-off alongside it. That change needs its own record. The contributor keeps copyright. They grant the maintainer, and the maintainer's successors and assigns, a perpetual, irrevocable, worldwide, royalty-free copyright and patent licence to the contribution, with the right to sublicense and relicense it on any terms, proprietary included. In return, the contribution stays available under the licence it was contributed under. The candidates:

| Option | What it is | Fit |
| --- | --- | --- |
| An Apache-style Individual CLA (and a Corporate CLA), with the maintainer as recipient | The ASF's ICLA grants a copyright and patent licence with the right to sublicense; widely recognised | Good. Rewrite the recipient and add an explicit relicensing clause. A lawyer drafts |
| Harmony HA-CLA-I and HA-CLA-E, outbound Option Five | Template agreements from Project Harmony. Option Five is "Any license, with the promise back that the contribution will also be licensed under the original licenses" | Good. Built for this choice, with the promise back included |
| FSFE Fiduciary Licence Agreement 2.0 | Assigns to a fiduciary that may license only under free software licences | Does not fit. It forbids the source-available and proprietary licensing this record needs |

| Signing tool | Where signatures live | Note |
| --- | --- | --- |
| CLA Assistant (`cla-assistant.io`, a GitHub App run by SAP) | Outside the repository | No workflow in this repository |
| CLA Assistant Lite (a GitHub Action) | A file in a repository | Runs on `pull_request_target` with a write token. On a public repository the security-reviewer clears it against [ci-runners.md](../ci-runners.md#security) first |

Contributions to `policies/examples/` and `profiles/` follow the same rule for now, although those paths stay Apache-2.0.

### 4. Trademark

Register FATHOMGATE. Neither licence gives rights to the name (FSL's *Trademarks* clause; Apache-2.0 section 6), and after two years every version is Apache-2.0, so the name is the one lasting thing a reseller cannot take. [TRADEMARKS.md](../../TRADEMARKS.md) already sets the policy, but the mark is unregistered. First do the professional clearance search that [ADR 0019](0019-rename-to-fathomgate.md) recommends in Nice classes 9 and 42. Then file where Fathomgate will be sold, for example the USPTO and, through the Madrid Protocol, the UK and EU. Register the logo in `design/brand/` in the same filing if the budget allows.

### 5. Patents

The repository, with its specs, ADRs and code, became public on 2026-09-24. That publication starts clocks:

- **United States:** 35 U.S.C. 102(b)(1)(A) gives the inventor one year from their own disclosure. The last day to file on anything disclosed on 2026-09-24 is before 2027-09-24.
- **Europe:** the EPC requires absolute novelty (Article 54), with no grace period for the inventor's own publication. Rights there for anything already disclosed are most likely gone.
- **Elsewhere:** some countries, among them Japan, Korea and Canada, have a grace period, each with its own conditions.

Apache-2.0 section 3 has already granted users of the published versions a licence under any patent claim that those contributions necessarily infringe. FSL grants a similar licence for Permitted Purposes. So a later patent mostly matters against a competitor who reimplements the method without copying the code. Recommendation: if the maintainer believes any method is novel, consult a patent attorney before 2027-09-24. If none is, do nothing.

**This record is not legal advice.** It is a plan for the maintainer and his lawyer.

### 6. Migration plan

This record lands first, with dated pointer rows in the *Amendments* of ADR 0020, ADR 0024 and ADR 0025, and the index updated. The relicensing is done now, before `v0.2.0` (answer 5), in a separate pull request opened as a draft. It merges only as decision 7 allows. The commit that brings it to `main` is the **relicensing commit**. Its SHA is recorded after the merge in this record's *Amendments*, in `CHANGELOG.md` and in the `v0.2.0` release notes. `NOTICE` names it by description ("the commit that added this paragraph"), because a file cannot contain its own commit's SHA.

| File or place | Change |
| --- | --- |
| `LICENSE` | The unmodified `FSL-1.1-ALv2` text, with the notice `Copyright 2026 Josh Scott`. The file keeps the name `LICENSE`, because `.goreleaser.yaml`, `snapshot.yaml`, the `Dockerfile` and `third_party.py` read that path |
| `policies/examples/LICENSE`, `profiles/LICENSE` | The unmodified Apache-2.0 text |
| `NOTICE` | The Apache boilerplate is replaced by: versions made available from the relicensing commit on are under `FSL-1.1-ALv2`, except `policies/examples/` and `profiles/`, which are Apache-2.0; `v0.1.0` and every commit before the relicensing commit remain under Apache-2.0. The *Third-party software* section is unchanged |
| SPDX lines | Every Go, Python and shell file changes to `SPDX-License-Identifier: FSL-1.1-ALv2`, except under `policies/examples/` and `profiles/`, where the line is `Apache-2.0`. `tools/licences/spdx.py` enforces the per-path rule, and `--fix` replaces a wrong line, not only a missing one. The CI step `licences and SPDX headers` and `make licences-check` run it as before. Code copied from another project keeps its own SPDX line |
| `tools/licences/third_party.py` | The generated index sentence "Fathomgate itself is under the Apache License 2.0" and the comment on `ALLOWED` change. `make licences` regenerates `THIRD_PARTY_LICENSES/README.md`. The module licence texts and the allow-list (MIT, BSD, ISC, Apache-2.0) are unaffected |
| `.goreleaser.yaml` | `license: FSL-1.1-ALv2` in the Homebrew formula. Every archive and image still carries `LICENSE`, `NOTICE`, `TRADEMARKS.md` and `THIRD_PARTY_LICENSES/`, and the archives carry `policies/examples/LICENSE` with the example policies |
| `tests/pyproject.toml`, `tests/conformance/package.json` | `license` changes to `FSL-1.1-ALv2` |
| `README.md` | *Licence* section rewritten: FSL, what it allows, the conversion rule, the Apache-2.0 paths, the Apache-2.0 status of `v0.1.0`, no outside code for now |
| `CONTRIBUTING.md` | Rewritten for "no outside code for now": issues welcome (profiles, redaction gaps, bugs, ideas); pull requests from others are closed kindly with a pointer to issues; no DCO wording aimed at outsiders |
| `GOVERNANCE.md` | *Licence* section rewritten. The "no CLA, cannot relicense" sentence goes. The *Contributor* role reflects that outside code is not accepted |
| `TRADEMARKS.md` | Cites FSL's *Trademarks* clause as well as Apache-2.0 section 6, and points to this record. *If you fork* separates Apache-2.0 versions from FSL versions |
| `ROADMAP.md` | *What we believe*: the last bullet says the parts that keep you safe stay public, source-available and auditable, and become Apache-2.0 after two years. It no longer says "open source" or "always will be". *Open source, and how it's funded* gets a new heading and says in plain words that the licence stops resale and the paid edition is proprietary. *Come build it with us* asks for issues, not pull requests |
| `docs/maintainers.md` | *Licence mechanics* rewritten: the SPDX rule per path, closing outside pull requests, the conversion date in release notes |
| `docs/PLAN.md` | The release-model entry under open questions points to this record |
| `design/reference/README.md` | "under Apache-2.0" becomes the repository licence (the supersession of ADR 0024's answer 4) |
| `.github/PULL_REQUEST_TEMPLATE.md`, issue templates, `.github/dco.yml` | The template says outside pull requests are not accepted. `dco.yml` stays while the DCO app is installed; whether to uninstall the app or drop its required check is the maintainer's repository setting |
| `CLAUDE.md` | The DCO and licence lines match |
| `CHANGELOG.md` | An `[Unreleased]` entry, cut into `[0.2.0]`, under *Changed*: Fathomgate is now under `FSL-1.1-ALv2`; `v0.1.0` and earlier commits remain Apache-2.0; `policies/examples/` and `profiles/` stay Apache-2.0 |
| `docs/releases/v0.2.0.md` and every later release | A *Licence* line: `FSL-1.1-ALv2`, and the date this tag converts to Apache-2.0. `.claude/commands/release.md` gains the step |
| `v0.1.0` | A pinned GitHub Discussion, and a line added to the `v0.1.0` release page: this release is and stays Apache-2.0 |
| GitHub | The repository stays public. Its licence detection is checked after the merge |

`v0.2.0` is the first release under `FSL-1.1-ALv2`.

### 7. Legal review before the relicensing commit

The relicensing pull request is opened as a draft. It merges only after the maintainer confirms that a lawyer has reviewed it, or explicitly waives the review. A review covers:

- the choice of FSL, and the per-commit reading of the conversion date;
- the MSP "professional services" row in the table in decision 1;
- the two Apache-2.0 paths inside an FSL repository, and the binary that embeds both;
- whether the Dependabot commits and the AI co-author trailers raise any third-party claim;
- the `NOTICE` wording for the Apache-2.0 versions and paths;
- the CLA text and its recipient, when outside code is ever accepted (decision 3).

## Consequences

### Positive

- Resale is stopped. Nobody may sell or host Fathomgate, or a substitute built from a post-relicensing version, for two years after that version.
- Auditability is kept. Every line that decides or proves is public on the day it is written, and anyone can build and run it at any scale for their own networks.
- The step can be reversed toward more openness, not less. The maintainer can later shorten the delay, relicense to Apache-2.0, or grant exceptions. Each version converts on its own.
- One standard, SPDX-listed text. Legal teams and scanners recognise it, and there is no custom grant to negotiate.
- With no outside code, the maintainer keeps every right to every line after the relicensing commit, so the paid edition and any later licence change stay free of anyone else's consent.
- Example policies and profiles stay Apache-2.0, so operators and other projects can copy and share them without reading the FSL.

### Negative

- Fathomgate is no longer open source by the OSI definition. Some enterprises ban non-OSI licences. Homebrew core, Debian main and Fedora accept only free or open-source licences, so Fathomgate ships only from its own tap, archives and image. Mitigation: FSL is on the SPDX list and is increasingly familiar; each version becomes Apache-2.0 after two years.
- No outside code means no outside pull requests, including for profiles, the contribution the ROADMAP most wants. Mitigation: profile requests and redaction gaps come in as issues with templates, and the maintainer writes the file. A CLA is the recorded path if that does not scale.
- "Open core", "open source" and "always will be" appear in `ROADMAP.md`, `README.md`, `GOVERNANCE.md`, `CONTRIBUTING.md`, `TRADEMARKS.md` and `docs/maintainers.md`. All must change in the relicensing commit (decision 6). The launch story changes from "open source" to "source-available, Apache-2.0 after two years".
- Reversing a public promise one day after making it costs trust. Mitigation: `v0.1.0` has 4 downloads and there are no outside contributors or forks, so few people relied on the promise. Everything published keeps it. The rewrite says what changed and why, plainly.
- A reseller can start today from the last Apache-2.0 commit. The relicensing does not change that, and every day before it adds more Apache-2.0 code. Mitigation: relicense now, before `v0.2.0` (answer 5).
- Two licences in one repository need a per-path rule, in `spdx.py`, `NOTICE` and the README. A file moved between an Apache-2.0 path and the rest changes licence. Mitigation: `spdx.py` fails CI on a wrong SPDX line for a file's path.
- pkg.go.dev does not render documentation for modules under licences it does not recognise as redistributable. All packages are `internal/` today, so no user sees this until seams are exported (ADR 0020 section 3).

### Neutral

- The paid edition's scope, the boundary table, the extension seam and the invariants are unchanged. Only the licence of the public repository changes.
- `THIRD_PARTY_LICENSES/` module texts, the dependency allow-list and the `NOTICE` attributions are unchanged.
- ADR 0020's reason for SPDX lines, that files carry their licence between the public and private repositories, still holds.
- Docs and `design/` stay under the repository licence, now `FSL-1.1-ALv2`.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Stay on Apache-2.0 (ADR 0020) | Lets anyone resell the product or host it as a service, which is what the maintainer now wants to stop |
| Business Source License 1.1 (`BUSL-1.1`) | Same model, but each licensor writes its own Additional Use Grant and Change Date, up to four years. Every adopter's BSL is effectively a new licence for legal teams to read, and there is more to negotiate |
| Elastic License 2.0 (`Elastic-2.0`) | Forbids offering the software as a hosted or managed service, and forbids circumventing licence keys. It never converts, so no version ever becomes open source, and operators lose the path to Apache-2.0 that FSL gives |
| PolyForm Shield 1.0.0 | Forbids "providing any product that competes with the software", "even when provided free of charge". It never converts, and it is not on the SPDX License List (3.29.0), so scanners and SBOMs cannot name it |
| AGPL-3.0 with a commercial licence | OSI-approved and keeps the code open, but it does not stop resale: a competitor may host it if they publish their changes. Many enterprises ban AGPL outright, and dual licensing needs a CLA anyway |
| Fully proprietary, private repository | Stops resale completely, but operators cannot audit the code that stands between an agent and a core router. ADR 0020 ruled it out for trust, and the maintainer wants the code auditable |
| `FSL-1.1-MIT` | Same terms, but MIT has no patent grant. Apache-2.0 as the future licence keeps the grant that ADR 0020 valued |
| Accept outside code now, under a CLA | Possible, but it needs a CLA text, a signing tool and a lawyer before the first pull request. Issues cover what outsiders offer today |
| Everything under FSL, profiles included | Profiles and example policies are data users copy into their own setup; putting them under FSL adds friction to the one thing the community is asked to extend |

## Decisions on the open questions

Accepted by the maintainer, Josh Scott, on 2026-09-25, with these answers:

1. **FSL or BSL: `FSL-1.1-ALv2`**, the standard text, unmodified.
2. **Conversion: two years**, FSL's fixed term.
3. **Contributions: no outside code for now.** The project does not accept code from others. Pull requests from others are closed with a pointer to issues. Ideas, bug reports, profile requests and redaction gaps come in as issues, and the maintainer writes the code. Before outside code is ever accepted, the project adopts a licence-grant CLA and keeps DCO sign-off, in a record of its own (decision 3).
4. **The M5 local console and the M5 drivers stay in the source-available core.** The maintainer was not asked this question directly. This answer is the orchestrator's default, consistent with [ADR 0024](0024-local-console-embedded-loopback-only.md) and [ADR 0025](0025-split-the-console.md), and the maintainer may change it with a new record.
5. **Timing: relicense now, before `v0.2.0`.** `v0.2.0` is the first release under `FSL-1.1-ALv2`. Code pushed before the relicensing commit stays Apache-2.0.
6. **Lawyer review:** the relicensing pull request is prepared as a draft and merges only after the maintainer confirms a lawyer's review or explicitly waives it (decision 7).
7. **`policies/examples/` and `profiles/` stay Apache-2.0**, each with its own `LICENSE` file and a path rule in `NOTICE` and the README. The engine, the proxy, the CLI, the gate and everything else go to `FSL-1.1-ALv2`.

## Amendments

| Date | What changed | Why |
| --- | --- | --- |
| 2026-09-25 | The maintainer waived the lawyer's review of decision 6 and told the orchestrator to go ahead with the relicensing pull request (#166). `design/` goes under FSL-1.1-ALv2 with the rest of the core, as decision 7 already reads; only `policies/examples/` and `profiles/` stay Apache-2.0. The questions listed for the lawyer (Competing Use and managed service providers, AI co-author trailers) stay open for the maintainer to take up later. | Maintainer decision, recorded so the history shows the review was waived rather than done |
| 2026-09-25 | The DCO GitHub App and its required check stay for now; `.github/dco.yml` is kept. Every commit, today only the maintainer's, keeps a `Signed-off-by` line. | Maintainer decision; it costs nothing and keeps the history ready for a CLA plus DCO later (decision 3) |
| 2026-09-25 | The relicensing commit is `08d0970` (`08d0970762844b7ca1fafcb195e0aedecb9de862`), the merge of pull request #166 into `main` on 2026-09-25. It is the first commit under `FSL-1.1-ALv2`. Every commit on `main` before it, `v0.1.0` included, stays Apache-2.0. `NOTICE` keeps "the commit that added this paragraph" and now gives the SHA beside it; the `CHANGELOG.md` licence entry names it; the `v0.2.0` release notes name it when they are written. GitHub's licence detection shows the repository licence as "Other" (`spdx_id` `NOASSERTION`), because it does not recognise the FSL text. `LICENSE` is authoritative, not the GitHub label | Decision 6 records the SHA after the merge |
| 2026-09-25 | The live NetBox and Nautobot connectors are in the paid edition. This settles ADR 0020's contested row "NetBox and Nautobot resolvers" (R15) along its recommendation. The core keeps the `Resolver` interface, the snapshot format, `sot: stale` marking, the static file, hostname patterns (as [ADR 0031](0031-hostname-patterns-never-make-a-target-known.md) limits them) and CSV import, so any team can export its devices from NetBox or Nautobot and load them at no cost. The paid edition has the live connectors: API lookup, auto-sync, caching and freshness checks. `internal/inventory/netbox.go` stays in the core as a stub that resolves nothing until the paid resolver exists, then leaves the core; the seam is the `Resolver` interface, not the stub. M2 validates the CSV and snapshot path in the core; NetBox and Nautobot validation moves to the paid edition. Carried out in PRD R15 and R37, PLAN M2, ROADMAP stage 3, inventory-schema section 6, ARCHITECTURE.md and README.md, with pointer rows in ADR 0020 and [ADR 0007](0007-role-resolver-chain-sot-optional.md) | Maintainer decision, Josh Scott, 2026-09-25 ("middle ground"). The free path covers a team with a source of truth; what is paid is keeping it in sync live |

## References

- [ADR 0020, open core under Apache-2.0](0020-open-core-apache-2.md): section 2 (boundary rule and table), section 3 (extension seam and invariants), section 4 (licensing mechanics), *Alternatives considered* (FSL and BSL)
- [ADR 0025, split the console](0025-split-the-console.md); [ADR 0024, local console](0024-local-console-embedded-loopback-only.md), answer 4; [ADR 0027, `serve` flags](0027-serve-policy-inventory-profiles-flags.md) (profiles embedded in the binary); [ADR 0019, rename](0019-rename-to-fathomgate.md) (trademark clearance)
- [LICENSE](../../LICENSE), [NOTICE](../../NOTICE), [TRADEMARKS.md](../../TRADEMARKS.md), [GOVERNANCE.md, Licence](../../GOVERNANCE.md#licence), [CONTRIBUTING.md](../../CONTRIBUTING.md), [docs/maintainers.md, Licence mechanics](../maintainers.md#licence-mechanics), [ROADMAP.md](../../ROADMAP.md), `tools/licences/spdx.py`, `tools/licences/third_party.py`, `.goreleaser.yaml`
- [Functional Source License](https://fsl.software/) and the [FSL-1.1-ALv2 text](https://fsl.software/FSL-1.1-ALv2.template.md), fetched 2026-09-25; [Fair Source](https://fair.io/)
- [SPDX License List](https://spdx.org/licenses/) 3.29.0: `FSL-1.1-ALv2`, `BUSL-1.1`, `Elastic-2.0`
- [Business Source License 1.1](https://mariadb.com/bsl11/); [PolyForm Shield 1.0.0](https://polyformproject.org/licenses/shield/1.0.0); [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license)
- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), sections 2, 3 and 6; [Developer Certificate of Origin 1.1](https://developercertificate.org/)
- [Project Harmony contributor agreements](https://www.harmonyagreements.org/); [FSFE Fiduciary Licence Agreement](https://fsfe.org/activities/fla/fla.en.html); [CLA Assistant](https://cla-assistant.io/)
- 35 U.S.C. 102(b)(1)(A); European Patent Convention, Article 54
- This record is not legal advice.
