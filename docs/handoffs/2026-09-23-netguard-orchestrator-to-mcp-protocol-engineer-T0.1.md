# T0.1 is yours: move go.mod to Go 1.25 and pin go-sdk v1.7.x, nothing else

- **Task:** T0.1 — Bump toolchain to Go 1.25 and add github.com/modelcontextprotocol/go-sdk v1.7.x
- **From → To:** netguard-orchestrator → mcp-protocol-engineer
- **State now:** in progress
- **Branch / PR:** `chore/m0-kickoff` (board only) · T0.1 goes on `build/go-1.25-go-sdk` · issue [#3](https://github.com/joshscott13/netguard/issues/3)
- **Date:** 2026-09-23

## Done

- M0 board reconciled: T0.1 in progress; T0.7–T0.9 added for defects found by the kickoff green check; both dependabot PRs recorded as merged.
- GitHub mirror: labels synced from `.github/labels.yml`, issues #3–#11 opened, one per task.
- Green check on `main`: build, vet, 25/25 policy cases, six redaction fixtures and CI (lint included) all pass. Only `TestKeyRoundTrip` fails, and only on Windows (T0.7).

## Look at this first

- `go.mod`: it says `go 1.24`. Every workflow reads `go-version-file: go.mod`, and the `Dockerfile` is already on `golang:1.25-alpine` (PR #1), so `go.mod` is the only toolchain pin that has to change.
- `ROADMAP.md` "Unblocking M0" and ADR 0001.

## Deliberately unfinished

- No `internal/proxy` code. T0.2 creates it. If nothing imports go-sdk, `go mod tidy` removes the require. Pin it with a `tools.go`-style blank import only if go-reviewer agrees. Otherwise land the require in T0.2 and record that here.
- GoReleaser and the containerlab runner image are T0.6 and T0.9.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check
```

## Decisions made without an ADR

- The dependabot go-yaml bump merged before T0.1, so T0.1's diff stays toolchain-only. This answers the scaffold note's question.

## Questions for the receiver

- Does go-sdk v1.7.x pull in any transitive dependency beyond the stdlib? List each one in the PR. Any new module besides go-sdk needs an ADR before merge.
