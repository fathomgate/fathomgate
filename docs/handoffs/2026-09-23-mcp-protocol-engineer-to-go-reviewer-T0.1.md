# T0.1 fix-ups are in: Go 1.25.0, go-sdk v1.7.0, golangci-lint v2.4.0; merge waits on ADR 0011 (proposed)

- **Task:** T0.1 — Bump toolchain to Go 1.25 and add github.com/modelcontextprotocol/go-sdk v1.7.x
- **From → To:** mcp-protocol-engineer → go-reviewer
- **State now:** blocked (on ADR 0011 acceptance, blocker B2); review continues in parallel
- **Branch / PR:** `build/go-1.25-go-sdk` (from `bd08fbd`, not pushed) · none yet · issue [#3](https://github.com/joshscott13/netguard/issues/3)
- **Date:** 2026-09-23

## Done

- `go.mod`: `go 1.24` became `go 1.25.0`. The `.0` is required: go-sdk v1.7.0 declares `go 1.25.0`, and `go mod tidy` rewrites a bare `1.25` to match. No `toolchain` line.
- `go.mod` and `go.sum`: `github.com/modelcontextprotocol/go-sdk v1.7.0` is a direct require. v1.7.0 is the latest v1.7 patch; v1.8.0 exists and is deliberately not used.
- `internal/tools/tools.go` (`//go:build tools`) blank-imports `go-sdk/mcp` so tidy keeps the require. The binary's dependency graph is unchanged (`go list -deps ./cmd/netguard` shows no go-sdk).
- `.github/workflows/ci.yaml`: golangci-lint is pinned to `v2.4.0` (was `v2.1`). v2.1 release binaries are built with Go 1.24 and refuse a module that declares Go 1.25. v2.4 is the first line built with 1.25.
- ADR 0011, `docs/adr/0011-accept-go-sdk-transitive-modules.md`, is **proposed** (commit `5d6d300`). It covers go-sdk and its 8 indirect modules. Blocker B2 tracks its acceptance by a maintainer.
- Review fix-ups, all in the `fix(build)` commit on top of `5d6d300`:
  - golangci-lint pinned to `v2.4.0` instead of the floating `v2.4`.
  - B1 text now reads "clears when T0.1 merges".
  - T0.10 (govulncheck in CI, from ADR 0011) is on the board.
  - T0.8's notes now cover the cp1252 encoding problem.
  - CHANGELOG `[Unreleased]` has one Added and one Changed section.
  - `STATUS.md` is re-rendered as UTF-8.
- Docs: the Go 1.24 and "one dependency" statements in README, CLAUDE, AGENTS, ROADMAP and ARCHITECTURE are fixed.

## Look at this first

- `docs/adr/0011-accept-go-sdk-transitive-modules.md`. It lists these modules:
  - `github.com/google/jsonschema-go v0.4.3`
  - `github.com/segmentio/asm v1.1.3`
  - `github.com/segmentio/encoding v0.5.4`
  - `github.com/yosida95/uritemplate/v3 v3.0.2`
  - `golang.org/x/oauth2 v0.35.0`
  - `golang.org/x/sync v0.20.0`
  - `golang.org/x/sys v0.41.0`
  - `golang.org/x/time v0.15.0`

  go.sum also carries `golang-jwt/jwt/v5`, `google/go-cmp` and `x/tools`, which only go-sdk's own tests use.
- `internal/tools/tools.go`: the handoff from the orchestrator asked for your agreement on this pattern.

## Deliberately unfinished

- Accepting ADR 0011 is a maintainer call (B2).
- `.claude/agents/go-reviewer.md` still says `go 1.24`. The orchestrator will handle it.
- The `netguard serve` stub, and README's line describing its message, belong to T0.2.
- `TestKeyRoundTrip` fails on Windows only (T0.7). `-race` was not run locally because CGO is off and there is no gcc; CI runs it on Linux.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check
go vet -tags tools ./internal/tools
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -tags tools ./internal/tools   # SDK builds without cgo
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0 run ./...   # 0 issues locally
PYTHONUTF8=1 python tools/status/render.py --check   # Windows: force UTF-8 until T0.8
```

## Decisions made without an ADR

- The go-sdk pin goes in now, through a `tools`-tagged file, instead of waiting for T0.2. The alternative would leave a require that tidy removes.
- golangci-lint is bumped in a workflow the release-engineer owns. Without the bump this PR cannot pass CI.

## Questions for the receiver

- Is `internal/tools/tools.go` acceptable, or should the require move to T0.2 (drop the file and let tidy remove it)?
