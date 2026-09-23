# T0.1 ready for review: go.mod on Go 1.25.0 with go-sdk v1.7.0 pinned, but merge waits on a dependency ADR

- **Task:** T0.1 — Bump toolchain to Go 1.25 and add github.com/modelcontextprotocol/go-sdk v1.7.x
- **From → To:** mcp-protocol-engineer → go-reviewer
- **State now:** in review
- **Branch / PR:** `build/go-1.25-go-sdk` (from `bd08fbd`, not pushed) · none yet · issue [#3](https://github.com/joshscott13/netguard/issues/3)
- **Date:** 2026-09-23

## Done

- `go.mod`: `go 1.24` became `go 1.25.0`. The `.0` is required: go-sdk v1.7.0 declares `go 1.25.0`, and `go mod tidy` rewrites a bare `1.25` to match. No `toolchain` line.
- `go.mod` and `go.sum`: `github.com/modelcontextprotocol/go-sdk v1.7.0` is a direct require. v1.7.0 is the latest v1.7 patch; v1.8.0 exists and is deliberately not used.
- `internal/tools/tools.go` (`//go:build tools`) blank-imports `go-sdk/mcp` so tidy keeps the require. The binary's dependency graph is unchanged (`go list -deps ./cmd/netguard` shows no go-sdk). This lands the dependency now so the ADR and this PR cover it, and T0.2 stays code-only.
- `.github/workflows/ci.yaml`: golangci-lint moves from `v2.1` to `v2.4`. v2.1 release binaries are built with Go 1.24 (`GO_VERSION: '1.24'` in its release.yml), and `pkg/goutil/version.go` rejects a module whose go directive is newer. The lint job would go red on this change. v2.4 is the first line built with 1.25.
- Docs: CHANGELOG `[Unreleased]` gets a Changed section, and the Added line is fixed. The Go 1.24 and "one dependency" statements in README, CLAUDE, AGENTS, ROADMAP ("Unblocking M0" steps 1–2 and the M0 row) and ARCHITECTURE are fixed.
- Dockerfile (`golang:1.25-alpine`) and all four `setup-go` steps (`go-version-file: go.mod`) were checked and left unchanged.

## Look at this first

- The dependency list. The `mcp` package build graph adds 8 modules besides go-sdk (all indirect): `github.com/google/jsonschema-go v0.4.3`, `github.com/segmentio/asm v1.1.3`, `github.com/segmentio/encoding v0.5.4`, `github.com/yosida95/uritemplate/v3 v3.0.2`, `golang.org/x/oauth2 v0.35.0`, `golang.org/x/sync v0.20.0`, `golang.org/x/sys v0.41.0`, `golang.org/x/time v0.15.0`. go.sum also gets checksums for `github.com/golang-jwt/jwt/v5 v5.3.1`, `github.com/google/go-cmp v0.7.0` and `golang.org/x/tools v0.42.0`, which only go-sdk's own tests use (`go mod why -m` confirms). **Per the brief, a new ADR is needed before merge.** None is written; next free number is 0011.
- `internal/tools/tools.go`: the handoff from the orchestrator asked for your agreement on this pattern.

## Deliberately unfinished

- ADR for the transitive modules. Out of T0.1 scope; the orchestrator decides who writes it.
- `.claude/agents/go-reviewer.md` still says `go 1.24`. It is agent config, so I left it for the orchestrator.
- `netguard serve` stub, and README's line describing its message: T0.2.
- `TestKeyRoundTrip` fails on Windows only (T0.7). `-race` was not run locally because CGO is off and there is no gcc; CI runs it on Linux.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check
go vet -tags tools ./internal/tools
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags tools ./internal/tools   # SDK builds without cgo
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0 run ./...   # 0 issues locally
```

## Decisions made without an ADR

- Pin go-sdk now through a `tools`-tagged file rather than in T0.2. The alternative would leave a require that tidy removes.
- golangci-lint bumped to v2.4 in a release-engineer-owned workflow. Without it this PR cannot pass CI.

## Questions for the receiver

- Is `internal/tools/tools.go` acceptable, or should the require move to T0.2 (drop the file and let tidy remove it)?
- Pin golangci-lint to v2.4, or jump to a newer line (v2.13.x exists)?
