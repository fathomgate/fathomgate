# Governance

NetGuard is maintained by a single maintainer today and is designed to grow to a small maintainer group. Decisions that are expensive to reverse are made through architecture decision records. Releases are cut when a milestone's exit criteria pass, not on a calendar.

## Roles

| Role | Who | Can |
| --- | --- | --- |
| Maintainer | Listed in `.github/CODEOWNERS` (currently `@joshscott13`) | Merge, release, accept ADRs, triage security reports, add or remove maintainers |
| Reviewer | Named in `MAINTAINERS.md` once it exists | Approve pull requests in a named area (a vendor driver, a profile family, the Python companion); cannot merge |
| Contributor | Anyone with a merged pull request | Open issues and pull requests, propose ADRs |

Adding a maintainer requires a sustained record of merged contributions and review, a proposal by an existing maintainer, and no objection from other maintainers within 14 days. Removing one for inactivity happens after 6 months without activity and a private message; the person is listed as emeritus.

## Decision process

Most decisions happen in pull request review. Three kinds need more.

### Architecture decisions

Anything that changes a spec in `docs/specs/`, the `Decision` type, the class list, the audit hash or token formats, a trust boundary, or adds a dependency to the core, needs an ADR in `docs/adr/` following [0000-template.md](docs/adr/0000-template.md).

1. Open a pull request adding the ADR with status `proposed`.
2. Discussion happens on the pull request for at least 7 days, or less if every maintainer has approved.
3. A maintainer merges it as `accepted`, or closes it with the reasons in a final comment.
4. Code implementing the decision links the ADR.

An accepted ADR is changed only by a new ADR that supersedes it. The index at [docs/adr/README.md](docs/adr/README.md) is the record.

### Security decisions

Security reports follow [SECURITY.md](SECURITY.md). A maintainer may merge a fix for a confirmed policy, redaction or approval bypass without the 7-day period and document the decision afterwards.

### Vocabulary decisions

The words for decisions, states and classes are fixed by [ADR 0009](docs/adr/0009-fathom-design-system-policy-layer.md) and [docs/glossary.md](docs/glossary.md). Adding a fifth decision word or an eighth class requires an ADR and is expected to be refused; the intended path is a new obligation or a new tag.

## Release cadence

- A release is tagged when a milestone's exit criteria in [ROADMAP.md](ROADMAP.md) pass in CI, including tier 2. Tier 3 results are reported in the release notes but do not block until M3.
- Versions before `1.0.0` are `0.<milestone>.<patch>`: M1 ships `0.1.0`, M2 `0.2.0`, and so on. Patch releases carry fixes only.
- `1.0.0` is cut after M5 when the policy schema, profile schema and audit event schema have been stable for one full milestone.
- After `1.0.0`, minor releases are at most monthly and never break a `version: 1` policy, profile or audit consumer. A schema `version: 2` is a major release.
- Security patches are released as soon as ready on the supported lines in [SECURITY.md](SECURITY.md).
- Every release: `CHANGELOG.md` updated, GoReleaser artefacts with checksums and SBOM, distroless image, conformance suite result attached.

## Communication

- Issues and pull requests on GitHub are the record. There is no chat channel of record.
- Roadmap changes are pull requests to `ROADMAP.md`.
- The maintainer posts a short status note in the Discussions tab at each milestone.

## Code of conduct

Everyone participating is bound by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Maintainers enforce it.

## Licence

MIT, see [LICENSE](LICENSE). Contributions are accepted under the same licence with a DCO sign-off ([CONTRIBUTING.md](CONTRIBUTING.md#dco-sign-off)). There is no CLA.
