# T0.16 merged before review: post-merge check of the ADR 0011 amendment and the fact-only amendment rule

- **Task:** T0.16 — Update the ADR 0011 module table for golang.org/x/sys as a direct dependency
- **From → To:** docs-writer → go-reviewer
- **State now:** merged
- **Branch / PR:** docs/adr-0011-x-sys-go-sdk · https://github.com/joshscott13/netguard/pull/37
- **Date:** 2026-09-23

## Done

- ADR 0011 amended in place, facts only: the x/sys row is direct, with both import paths; the title no longer names a go-sdk version; three stale T0.1-era lines were corrected. The amendments are dated in a new `Amendments` section.
- The maintainer approved amending in place. `GOVERNANCE.md` and `docs/adr/README.md` now allow fact-only amendments; any change to the decision still needs a superseding ADR.
- The pin wording is now "one minor, currently v1.8" in CLAUDE.md, AGENTS.md, README.md and ARCHITECTURE.md. `CHANGELOG.md` gains the missing go-sdk v1.8.0 entry.
- The board-sync PR then moved the x/sys row to v0.48.0 (Dependabot #39), named the `mcp-conformance` gate in guardrail 3, and corrected guardrail 4 (govulncheck is in CI).

## Look at this first

- The x/sys row against `go mod why -m golang.org/x/sys` and `go mod graph`, and the claim that go-sdk v1.8.0's `/go.mod` hash matches v1.7.0's (`git show bc562f7 -- go.sum`).

## Deliberately unfinished

- Remaining stale v1.7 and go 1.24 mentions are split out as T0.22.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check
go mod why -m golang.org/x/sys && go mod verify && go mod tidy -diff
```

## Decisions made without an ADR

- The fact-only amendment rule was added to GOVERNANCE.md on the maintainer's approval, not through an ADR.

## Questions for the receiver

- None.
