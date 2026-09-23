# T0.13 ready for review: the Go build toolchain is pinned in go.mod and every workflow reads it

- **Task:** T0.13 — Pin the Go build toolchain in go.mod and read it from there in every workflow
- **From → To:** release-engineer → go-reviewer; security-reviewer reviews second (supply chain, release job)
- **State now:** in review
- **Branch / PR:** `build/toolchain-pin`, stacked on PR #20 (`b0a102f`), which is stacked on #19 and #15. Not pushed · none yet
- **Date:** 2026-09-23

## Done

- `go.mod`: `toolchain go1.25.14`, the newest Go 1.25 patch per `go.dev/dl/?mode=json&include=all`. The `go 1.25.0` floor is unchanged. `go.sum` is unchanged.
- `ci.yaml` (all four Go jobs), `release.yaml`, `snapshot.yaml` and `nightly-clab.yaml` now use `go-version-file: go.mod` with `actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16 # v6.5.0`. `env.GO_VERSION`, `go-version: 1.25.x` and `check-latest` are removed.
- **I checked setup-go instead of assuming.** In v5.6.0 (`40f1582b`), `src/installer.ts` `parseGoVersionFile` reads only `/^go (\d+(\.\d+)*)/m`, so it would install go1.25.0. v6.0.0 lists "Improve toolchain handling" (#460) as a breaking change. v6.5.0 reads `/^toolchain go(1\.\d+(?:\.\d+|rc\d+)?)/m` first, unless GOTOOLCHAIN is already `local`, and `main.ts` `setGoToolchain()` exports `GOTOOLCHAIN=local`. Result: go1.25.14 is installed and no step switches toolchains.
- `Makefile`: `GO_TOOLCHAIN` is read from `go.mod`. New `toolchain-check` target fails unless `go env GOVERSION` matches it; it runs in the ci `go` job and in `release.yaml` before govulncheck. `vulncheck` now runs with `GOTOOLCHAIN=$(GO_TOOLCHAIN)`, so the local and CI scans cover the same stdlib.
- **Dependabot:** the `gomod` updater does not bump `toolchain`. Its `file_parser.rb` parses only `require` entries. dependabot-core#13520 ("Bump Go toolchain directive") is open. The manual bump procedure is in `CONTRIBUTING.md` and in ADR 0013, decision 6.
- ADR 0013 (accepted) and its entry in the ADR index; `CONTRIBUTING.md`; the `ARCHITECTURE.md` toolchain note; a `CHANGELOG.md` Security entry; T0.13 on the M0 board.

## Look at this first

- `docs/adr/0013-pin-go-toolchain-in-go-mod.md`, Decision 3 and Negative. **Go 1.25 is out of support.** go1.27.0 shipped 2026-08-19, and go1.25.14 is expected to be the last 1.25 patch. The next reachable stdlib advisory therefore needs a go1.26 toolchain, not a Dependabot-style patch bump.

## Deliberately unfinished

- No move to go1.26 yet. That also changes golangci-lint v2.4.0, govulncheck v1.7.0 → v1.8.0 and the `Dockerfile` builder, so it needs its own task.
- `Dockerfile` stays on `golang:1.25-alpine`, which sets `GOTOOLCHAIN=local`. Today that image is go1.25.14, the same as the pin. Pinning the image by digest is a follow-up.
- `CLAUDE.md` "Toolchain facts" does not mention the `toolchain` line yet. I left agent config alone; it needs a one-line edit, for the orchestrator or maintainer to decide.
- **The inherited base is not green on Linux `-race`.** `go test -race ./internal/proxy/` in `golang:1.25` (go1.25.14, the same as CI) fails `TestConnectFailureKillsUpstream`. `proxy.killCommand` (`proxy.go:201`) calls `cmd.Wait()` while go-sdk's `pipeRWC.Close` (`mcp/cmd.go:79`) calls `Wait()` on the same `*exec.Cmd`. This comes from PR #20 (T0.2), which this branch does not touch, and it is T0.2's merge gate. It is not fixed here. Everything else in the green gate passes in that container, including `make policy-test` (25/25) and `make fixtures-check`.
- The workflows have not run on GitHub yet. On the PR, `snapshot.yaml` runs because `go.mod` changed. Expect `Go in use is go1.25.14, the go.mod toolchain`.

## Reproduce green

```sh
go mod tidy -diff                                          # no output
GOTOOLCHAIN=go1.25.14 go build ./... && GOTOOLCHAIN=go1.25.14 go vet ./... && GOTOOLCHAIN=go1.25.14 go test -count=1 ./...
GOMODCACHE=$(mktemp -d) GOTOOLCHAIN=go1.25.0+auto go version   # go: downloading go1.25.14 ... go version go1.25.14
make toolchain-check                                        # under go1.25.14; exits 2 under GOTOOLCHAIN=go1.25.0
make vulncheck                                              # No vulnerabilities found. (1 module-only: GO-2026-5024, x/sys, T0.12)
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -config-file .github/actionlint.yaml   # exit 0
python tools/status/render.py --check
```

## Decisions made without an ADR

- None outside ADR 0013. The setup-go v5 → v6 major bump and the `toolchain-check` guard are recorded there.

## Questions for the receiver

- go-reviewer: should `make test` and `make build` also force `GOTOOLCHAIN=$(GO_TOOLCHAIN)`? I kept them on the contributor's Go. Only `vulncheck` and `toolchain-check` pin it.
- security-reviewer: is a weekly govulncheck failure plus a manual bump enough, given that Dependabot raises no alert for a vulnerable `toolchain` line?
