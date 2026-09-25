# ADR 0034: Future versions under the Functional Source License (FSL-1.1-ALv2); everything already published stays Apache-2.0

- Status: proposed
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer; decided on 2026-09-25 to move future versions from Apache-2.0 open core to a source-available licence). Proposed by docs-writer with the orchestrator. The choice of FSL over the alternatives, the two-year conversion, the CLA and the timing are recommendations for the maintainer to accept or change (*Open questions*). Reviewers: release-engineer (LICENSE, NOTICE, SPDX, artefacts), security-reviewer (auditability, CLA tooling on a public repository), design-guardian (voice of the README, ROADMAP and TRADEMARKS rewrites). A lawyer reviews it before the relicensing commit (decision 7)
- Supersedes: [ADR 0020](0020-open-core-apache-2.md) section 4 (licensing mechanics: Apache-2.0 `LICENSE`, the Apache SPDX line, DCO with no CLA), the licence named in its section 1, and the promise in its section 2 that the core "stays open". The boundary table, the extension seam, the extension invariants and the dependency direction in ADR 0020 are unchanged
- Amends: [ADR 0025](0025-split-the-console.md), which describes the core as open and Apache-2.0. The split it decides (local console in the core, team console and OCSF and CEF exporters in the paid edition) is unchanged

## Context

[ADR 0020](0020-open-core-apache-2.md), accepted on 2026-09-24, put the core under Apache-2.0 with DCO sign-off and no CLA, and said the core could not later move to FSL or BSL without every contributor's consent. On 2026-09-25 the maintainer decided that Fathomgate is a commercial product. He wants to stop others reselling it, and to keep the code readable and auditable by the operators who run it in front of their routers.

Whether he can do that depends on who holds copyright, and on what is already published:

| Fact | Where, as of 2026-09-25 |
| --- | --- |
| The repository `fathomgate/fathomgate` has been public since 2026-09-24. GitHub reports its licence as `Apache-2.0` | `gh api repos/fathomgate/fathomgate` |
| `v0.1.0` (M0, pass-through) was tagged at `38d7d6a` and released on 2026-09-25. Its assets have 4 downloads | `gh release view v0.1.0` |
| 0 stars, 0 forks, 0 watchers | `gh api repos/fathomgate/fathomgate` |
| Of 480 commits on `main`, 465 are the maintainer's (under the names `Josh Scott` and `Josh`) and 15 are Dependabot's dependency version bumps. The only `Co-authored-by` trailers name AI models. No outside pull request has been merged | `git log origin/main --format='%an <%ae>'` and `--format='%(trailers:key=Co-authored-by)'` |
| M1 code is already on `main` under Apache-2.0: `internal/gate`, `internal/policy`, `internal/classify`, `internal/redact`, `internal/audit` | `ls internal/` on `8c3299e` |

So the maintainer holds the copyright in every line and can license *future* versions on any terms without anyone's consent. The lawyer confirms that the Dependabot commits (version strings and checksums) and the AI co-author trailers give no one else a claim (decision 7).

He cannot take back what is published. Apache-2.0 section 2 grants its copyright licence as "perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable", and section 3 grants its patent licence the same way. **`v0.1.0`, and every commit on `main` up to the relicensing commit, stay under Apache-2.0 for good.** Anyone may fork that last Apache-2.0 commit, including the M1 policy engine merged so far, and sell it or offer it as a service. The only limit is the name ([TRADEMARKS.md](../../TRADEMARKS.md)). The relicensing protects only work that comes after it, so the later it lands, the more Apache-2.0 code a reseller can start from.

The product is a safety tool on production networks. ADR 0020's reason for publishing the source still holds: an operator who puts Fathomgate between an agent and a core router has to be able to read, build and audit the code that decides what reaches the router. Any new licence must keep that.

## Decision

We will license every version of Fathomgate made available after the relicensing commit under the Functional Source License, Version 1.1, ALv2 Future License (`FSL-1.1-ALv2`), unmodified. Everything published before that commit stays under Apache-2.0. The paid edition stays proprietary in its private repository.

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

**What this means in practice** (the lawyer confirms the rows marked †):

| Use | Under `FSL-1.1-ALv2` |
| --- | --- |
| Run Fathomgate in front of your own devices, in production, at any scale | Allowed ("internal use") |
| Read, build, audit and modify it; publish findings; report vulnerabilities | Allowed |
| Redistribute it, changed or not, with the terms and notices | Allowed, for a Permitted Purpose |
| An MSP runs it for a customer's network as part of its services (PRD user 2) | Allowed as "professional services" † |
| Sell or host Fathomgate, or a product with the same or substantially similar function, to others | Not allowed until that version converts |
| Build a competing product from a version more than two years old | Allowed, under Apache-2.0 |
| Build anything from `v0.1.0` or a commit before the relicensing commit | Allowed, under Apache-2.0, now |

**Why FSL fits a security product.** Auditability is the requirement, and FSL meets it in full: every line is public on the day it is written, including the parts that decide and prove. It uses one standard text with no per-project grant, so an enterprise legal team reviews a known licence once, and SBOM scanners recognise its SPDX id. Two years is short enough that operators can see the code become Apache-2.0, patent grant included. It stops resale, and nothing else.

### 2. The paid edition and the boundary

The paid edition (ADR 0025's team console, the OCSF and CEF exporters, and the other commercial rows of ADR 0020 section 2) stays proprietary in its private repository. ADR 0020's boundary stays as the product line:

- ADR 0020 section 2's table, as amended by ADR 0025, still says what is in the public repository and what is in the paid edition. Nothing moves across the line in this record.
- ADR 0020 section 3 (the extension seam, the dependency direction and invariants 1 to 7 for extensions) is unchanged.
- FSL's second Competing Use limb also covers a product that substitutes for the paid edition, where that edition exists on the day a version is made available.

The promise changes wording, not scope:

| ADR 0020 said | This record says |
| --- | --- |
| Anything that decides what is allowed, or proves what happened, stays open. | Anything that decides what is allowed, or proves what happened, stays in the public repository: source-available, auditable and buildable by anyone, and each version converts to Apache-2.0 two years after it is made available. |
| The core is Apache-2.0 "and always will be" ([ROADMAP.md](../../ROADMAP.md#what-we-believe)) | The core was Apache-2.0 up to the relicensing commit and stays so for those versions. Later versions are `FSL-1.1-ALv2` |

The public repository stays public.

### 3. Contributions

Accept no outside contribution until a CLA is in place.

**Why DCO alone no longer fits.** With DCO and no CLA, a contribution comes in under the licence of the file it changes. The project then holds only FSL rights to it, as any user does. It cannot relicense that contribution, or move it into the proprietary paid edition, without the contributor's consent. That is ADR 0020's lock again, one contributor at a time. The DCO 1.1 text also certifies the right to submit "under the open source license indicated in the file", and `FSL-1.1-ALv2` is not an open-source licence.

**Recommendation: a CLA that grants a licence, not an assignment.** The contributor keeps copyright. They grant the maintainer, and the maintainer's successors and assigns, a perpetual, irrevocable, worldwide, royalty-free copyright and patent licence to the contribution, with the right to sublicense and relicense it on any terms, proprietary included. In return, the contribution stays available under the licence it was contributed under. Options:

| Option | What it is | Fit |
| --- | --- | --- |
| An Apache-style Individual CLA (and a Corporate CLA), with the maintainer as recipient | The ASF's ICLA grants a copyright and patent licence with the right to sublicense; widely recognised | Good. Rewrite the recipient and add an explicit relicensing clause. The lawyer drafts |
| Harmony HA-CLA-I and HA-CLA-E, outbound Option Five | Template agreements from Project Harmony. Option Five is "Any license, with the promise back that the contribution will also be licensed under the original licenses" | Good. Built for this choice, with the promise back included |
| FSFE Fiduciary Licence Agreement 2.0 | Assigns to a fiduciary that may license only under free software licences | Does not fit. It forbids the source-available and proprietary licensing this record needs |

Tooling for signing, whichever text is chosen:

| Tool | Where signatures live | Note |
| --- | --- | --- |
| CLA Assistant (`cla-assistant.io`, a GitHub App run by SAP) | Outside the repository | No workflow in this repository |
| CLA Assistant Lite (a GitHub Action) | A file in a repository | Runs on `pull_request_target` with a write token. On a public repository the security-reviewer clears it against [ci-runners.md](../ci-runners.md#security) first |

Recommendation: keep DCO sign-off as well. It records per commit that the author had the right to submit. The CLA records the licence grant once per contributor. Whether to keep, reword or drop DCO is open question 3.

Until the CLA exists, a profile or policy pasted into an issue is treated as a report: the maintainer writes the file himself rather than committing the pasted text.

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

This pull request adds the record only. The implementing pull request makes the changes below in one commit, the **relicensing commit**, after the lawyer's review, after this record is accepted, and after the CLA is live. Its SHA is recorded in `NOTICE` and in this record's *Amendments*.

| File or place | Change |
| --- | --- |
| `LICENSE` | The unmodified `FSL-1.1-ALv2` text, with the notice `Copyright 2026 Josh Scott`. The file keeps the name `LICENSE`, because `.goreleaser.yaml`, `snapshot.yaml`, the `Dockerfile` and `third_party.py` read that path |
| `NOTICE` | The Apache boilerplate is replaced by a statement that versions made available after the relicensing commit are under `FSL-1.1-ALv2`, and that `v0.1.0` and every commit up to and including the relicensing commit's parent (by SHA) remain under Apache-2.0. The *Third-party software* section is unchanged |
| SPDX lines | Every Go, Python and shell file changes to `SPDX-License-Identifier: FSL-1.1-ALv2`. `tools/licences/spdx.py` changes its `ID` and docstring, and `--fix` learns to replace an old `Apache-2.0` line, not only add a missing one. The CI step `licences and SPDX headers` and `make licences-check` stay as they are. Code copied from another project keeps its own SPDX line |
| `tools/licences/third_party.py` | The generated index sentence "Fathomgate itself is under the Apache License 2.0" and the comment on `ALLOWED` change. `make licences` regenerates `THIRD_PARTY_LICENSES/README.md`. The module licence texts and the allow-list (MIT, BSD, ISC, Apache-2.0) are unaffected |
| `.goreleaser.yaml` | `license: FSL-1.1-ALv2` in the Homebrew formula. Every archive and image still carries `LICENSE`, `NOTICE`, `TRADEMARKS.md` and `THIRD_PARTY_LICENSES/` |
| `tests/pyproject.toml`, `tests/conformance/package.json` | `license` changes to `FSL-1.1-ALv2` |
| `README.md` | *Licence* section rewritten: FSL, what it allows, the conversion rule, the Apache-2.0 status of `v0.1.0`, the CLA |
| `CONTRIBUTING.md` | *Licence* section: FSL, the CLA and how to sign it, the SPDX line, and DCO as decided in open question 3 |
| `GOVERNANCE.md` | *Licence* section rewritten. The "no CLA, cannot relicense" sentence goes |
| `TRADEMARKS.md` | Cites FSL's *Trademarks* clause instead of Apache-2.0 section 6. *If you fork* separates Apache-2.0 versions (section 4 notices) from FSL versions (terms and notices). *Status of the name* updated once the mark is filed |
| `ROADMAP.md` | *What we believe*: the last bullet says the parts that keep you safe stay public, source-available and auditable, and become Apache-2.0 after two years. It no longer says "open source" or "always will be". *Open source, and how it's funded* gets a new heading and says in plain words that the licence stops resale. *Come build it with us*: the contribution line names FSL and the CLA |
| `docs/maintainers.md` | *Licence mechanics* rewritten: SPDX id, CLA check, the conversion date in release notes |
| `docs/PLAN.md` | The release-model entry under open questions points to this record |
| `design/reference/README.md` | "under Apache-2.0" becomes the repository licence |
| `.github/PULL_REQUEST_TEMPLATE.md`; `.github/dco.yml` | A CLA checkbox. `dco.yml` stays or goes with open question 3 |
| ADR 0020, ADR 0025, `docs/adr/README.md` | Dated pointer rows in their *Amendments* sections; the index shows ADR 0020 as superseded in part by this record |
| `CHANGELOG.md` | A `[0.2.0]` entry under *Changed*: "Licence change: versions after `<SHA>` are under `FSL-1.1-ALv2`; `v0.1.0` and earlier commits stay Apache-2.0", linking this record |
| `docs/releases/v0.2.0.md` and every later release | A *Licence* line: `FSL-1.1-ALv2`, and the date this tag converts to Apache-2.0. `.claude/commands/release.md` gains the step |
| `v0.1.0` | A pinned GitHub Discussion, and a line added to the `v0.1.0` release page: this release is and stays Apache-2.0 |
| GitHub | The repository stays public. Its licence detection is checked after the commit |

`v0.2.0` is the first release under `FSL-1.1-ALv2`.

### 7. Legal review before the relicensing commit

A lawyer reviews, before the relicensing commit:

- the choice of FSL, and the per-commit reading of the conversion date;
- the MSP "professional services" row in the table in decision 1;
- whether the Dependabot commits and the AI co-author trailers raise any third-party claim;
- the CLA text and its recipient (the maintainer as a person, or a company formed later);
- the `NOTICE` wording for the Apache-2.0 versions;
- whether the DCO wording conflicts with a non-open-source licence.

## Consequences

### Positive

- Resale is stopped. Nobody may sell or host Fathomgate, or a substitute built from a post-relicensing version, for two years after that version.
- Auditability is kept. Every line that decides or proves is public on the day it is written, and anyone can build and run it at any scale for their own networks.
- The step can be reversed toward more openness, not less. The maintainer can later shorten the delay, relicense to Apache-2.0, or grant exceptions. Each version converts on its own.
- One standard, SPDX-listed text. Legal teams and scanners recognise it, and there is no custom grant to negotiate.
- A CLA brings the contribution rights the paid edition needs, before the first outside contribution rather than after.

### Negative

- Fathomgate is no longer open source by the OSI definition. Some enterprises ban non-OSI licences. Homebrew core, Debian main and Fedora accept only free or open-source licences, so Fathomgate ships only from its own tap, archives and image. Mitigation: FSL is on the SPDX list and is increasingly familiar; each version becomes Apache-2.0 after two years.
- Fewer contributors: a CLA and a non-open licence both deter them. That hits the ROADMAP's most valuable contribution, profiles for MCP servers. Mitigation: open question 7.
- "Open core", "open source" and "always will be" appear in `ROADMAP.md`, `README.md`, `GOVERNANCE.md`, `CONTRIBUTING.md`, `TRADEMARKS.md` and `docs/maintainers.md`. All must change in the relicensing commit (decision 6). The launch story changes from "open source" to "source-available, Apache-2.0 after two years".
- Reversing a public promise one day after making it costs trust. Mitigation: `v0.1.0` has 4 downloads and there are no outside contributors or forks, so few people relied on the promise. Everything published keeps it. The rewrite says what changed and why, plainly.
- A reseller can start today from the last Apache-2.0 commit. The relicensing does not change that, and every day before it adds more Apache-2.0 code (open question 5).
- pkg.go.dev does not render documentation for modules under licences it does not recognise as redistributable. All packages are `internal/` today, so no user sees this until seams are exported (ADR 0020 section 3).

### Neutral

- The paid edition's scope, the boundary table, the extension seam and the invariants are unchanged. Only the licence of the public repository changes.
- `THIRD_PARTY_LICENSES/` module texts, the dependency allow-list and the `NOTICE` attributions are unchanged.
- ADR 0020's reason for SPDX lines, that files carry their licence between the public and private repositories, still holds.
- Docs stay under the repository licence, as ADR 0020 *Neutral* said.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Stay on Apache-2.0 (ADR 0020) | Lets anyone resell the product or host it as a service, which is what the maintainer now wants to stop |
| Business Source License 1.1 (`BUSL-1.1`) | Same model, but each licensor writes its own Additional Use Grant and Change Date, up to four years. Every adopter's BSL is effectively a new licence for legal teams to read, and there is more to negotiate. Choose it only if the maintainer wants a custom grant or a longer delay (open question 1) |
| Elastic License 2.0 (`Elastic-2.0`) | Forbids offering the software as a hosted or managed service, and forbids circumventing licence keys. It never converts, so no version ever becomes open source, and operators lose the path to Apache-2.0 that FSL gives |
| PolyForm Shield 1.0.0 | Forbids "providing any product that competes with the software", "even when provided free of charge". It never converts, and it is not on the SPDX License List (3.29.0), so scanners and SBOMs cannot name it |
| AGPL-3.0 with a commercial licence | OSI-approved and keeps the code open, but it does not stop resale: a competitor may host it if they publish their changes. Many enterprises ban AGPL outright, and dual licensing needs a CLA anyway |
| Fully proprietary, private repository | Stops resale completely, but operators cannot audit the code that stands between an agent and a core router. ADR 0020 ruled it out for trust, and the maintainer wants the code auditable |
| `FSL-1.1-MIT` | Same terms, but MIT has no patent grant. Apache-2.0 as the future licence keeps the grant that ADR 0020 valued |

## Open questions for the maintainer

1. **FSL or BSL?** Recommended: `FSL-1.1-ALv2`, standard text, no negotiation. BSL only if you want a custom Additional Use Grant (for example, allowing MSPs to host explicitly) or a delay longer than two years.
2. **Two-year conversion, or longer?** FSL fixes two years. A longer delay (BSL, up to four years) protects more but weakens the "becomes Apache-2.0" promise. Recommended: two.
3. **CLA with DCO, CLA alone, or DCO alone?** Recommended: a licence-grant CLA (Apache-style ICLA or Harmony Option Five) plus DCO sign-off. DCO alone recreates the relicensing lock one contributor at a time. Choose also the CLA tool (CLA Assistant app or the Lite action).
4. **Do the M5 local console and the M5 drivers stay in the source-available core?** ADR 0024 and 0025 put the local console in the core, and ADR 0020 puts every `ChangeSafety` driver there, because drivers decide whether a change stays. Recommended: keep both. FSL already stops resale, so moving them into the paid edition would give up auditability of code that touches devices, for little extra protection.
5. **Timing: relicense before or after M1 ships as `v0.2.0`?** Every commit pushed before the relicensing commit is Apache-2.0 for good, including the M1 policy engine. Recommended: relicense as soon as the lawyer has reviewed, before more M1 work lands, so `v0.2.0` is the first FSL release. The alternative is to ship M1 as Apache-2.0 and relicense from `v0.3.0`.
6. **Lawyer review.** Who, and when? The review covers the list in decision 7 and must come before the relicensing commit.
7. **Example policies and profiles** (added by docs-writer). `policies/examples/` and `profiles/` are data that users copy, and profiles are the contribution the ROADMAP most wants. Should they stay under the repository licence, or go under Apache-2.0 or CC0 so that community profiles flow freely? A profile sets a class, so under ADR 0020's rule profiles "decide". They are public either way.

## References

- [ADR 0020, open core under Apache-2.0](0020-open-core-apache-2.md): section 2 (boundary rule and table), section 3 (extension seam and invariants), section 4 (licensing mechanics), *Alternatives considered* (FSL and BSL)
- [ADR 0025, split the console](0025-split-the-console.md); [ADR 0024, local console](0024-local-console-embedded-loopback-only.md); [ADR 0019, rename](0019-rename-to-fathomgate.md) (trademark clearance)
- [LICENSE](../../LICENSE), [NOTICE](../../NOTICE), [TRADEMARKS.md](../../TRADEMARKS.md), [GOVERNANCE.md, Licence](../../GOVERNANCE.md#licence), [CONTRIBUTING.md](../../CONTRIBUTING.md), [docs/maintainers.md, Licence mechanics](../maintainers.md#licence-mechanics), [ROADMAP.md](../../ROADMAP.md), `tools/licences/spdx.py`, `tools/licences/third_party.py`, `.goreleaser.yaml`
- [Functional Source License](https://fsl.software/) and the [FSL-1.1-ALv2 text](https://fsl.software/FSL-1.1-ALv2.template.md), fetched 2026-09-25; [Fair Source](https://fair.io/)
- [SPDX License List](https://spdx.org/licenses/) 3.29.0: `FSL-1.1-ALv2`, `BUSL-1.1`, `Elastic-2.0`
- [Business Source License 1.1](https://mariadb.com/bsl11/); [PolyForm Shield 1.0.0](https://polyformproject.org/licenses/shield/1.0.0); [Elastic License 2.0](https://www.elastic.co/licensing/elastic-license)
- [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0), sections 2, 3 and 6; [Developer Certificate of Origin 1.1](https://developercertificate.org/)
- [Project Harmony contributor agreements](https://www.harmonyagreements.org/); [FSFE Fiduciary Licence Agreement](https://fsfe.org/activities/fla/fla.en.html); [CLA Assistant](https://cla-assistant.io/)
- 35 U.S.C. 102(b)(1)(A); European Patent Convention, Article 54
- This record is not legal advice.
