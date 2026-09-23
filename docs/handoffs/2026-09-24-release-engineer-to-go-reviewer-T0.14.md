# T0.14 ready for review: the build toolchain moves to go1.26.8, with golangci-lint v2.9.0 and govulncheck v1.8.0

- **Task:** T0.14 — Move the build toolchain to Go 1.26 now that Go 1.25 is out of support (issue #23)
- **From → To:** release-engineer → go-reviewer; security-reviewer reviews second (toolchain, vuln gate, supply chain)
- **State now:** in review
- **Branch / PR:** `build/go-1.26-toolchain`, off `origin/land/m0-stack` (PR #25, `8a1e877`). Not pushed · none yet
- **Date:** 2026-09-24

## Done

- `go.mod`: `toolchain go1.26.8`. This is the newest Go 1.26 patch (released 2026-09-01). I checked it against `go.dev/dl/?mode=json&include=all`, which lists go1.26.0 to go1.26.8 and then go1.27.x. The `go 1.25.0` floor is unchanged, so no new ADR is needed (ADR 0013 decision 6). `go mod tidy -diff` prints nothing, and `go.sum` is unchanged.
- `ci.yaml` `lint`: golangci-lint moves from `v2.4.0` to `v2.9.0`. I tested it under go1.26.8:
  - v2.4.0 (built with go1.25.0) and v2.8.0 (built with go1.25.5) exit 3 with "the Go language version (go1.25) used to build golangci-lint is lower than the targeted Go version (1.26.8)".
  - v2.9.0 is the first release built with Go 1.26 (go1.26.0, commit `72798d34`). The release tarball and the Docker image both report this. It finds 0 issues, and `.golangci.yaml` is unchanged.
  - The version is an input to `golangci-lint-action` (still SHA-pinned at v7.0.1; its minimum is v2.1), so there is no action SHA to change.
- `Makefile`: `GOVULNCHECK_VERSION` moves from v1.7.0 to v1.8.0. x/vuln v1.8.0's `go.mod` declares `go 1.26.0`, which the toolchain now satisfies. The `release.yaml` comment is updated to match.
- `Dockerfile`: the builder moves from `golang:1.25-alpine` to `golang:1.26-alpine` (go1.26.8 today). I added a comment explaining that it builds with its own Go (`GOTOOLCHAIN=local`), so its minor must track the `toolchain` line.
- `CONTRIBUTING.md` bump procedure, step 5, now says three more things:
  - golangci-lint must be built with a Go at least as new as the toolchain minor.
  - The Dockerfile builder must match the new minor.
  - Dependabot's monthly `docker` update can propose a newer `golang` minor than the toolchain; hold it until the toolchain moves.
- `CHANGELOG.md`: a Security entry (no advisory; reason: 1.25 is end of life) and three Changed entries. `docs/milestones/M0.yaml`: T0.14 is `in review` and `blocked_by` is removed, because T0.13 is merged. `STATUS.md` is re-rendered.

## Look at this first

- The `CHANGELOG.md` Security entry says **no advisory**. I computed this from the Go vulnerability DB: for every `stdlib` and `toolchain` entry (index modified 2026-09-16), I checked whether its range covers go1.25.14 or go1.26.8. None covers either. Every go1.26.x advisory was fixed by go1.26.6, together with its 1.25.13 backport. The one advisory that was 1.26-only (GO-2026-5942, `net` via vendored dnsmessage) covers only 1.26.0 to 1.26.5. go1.26.7 and go1.26.8 contain bug fixes only. The reason for this bump is support status, not a CVE.

## Deliberately unfinished

- The `golang:1.26-alpine` image is referenced by tag, not by digest. That matches the repo today: #19 SHA-pinned actions but not images, and the T0.13 note lists pinning by digest as a follow-up. Today's digests, if you want them: `golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c`, `golang:1.26@sha256:6c2a5538f964f1c82f97ad14988bf05de100d922d159d0e398b54c7b0ca0c6c9`.
- ADR 0013's body still says go1.25.14 and `golang:1.25-alpine`. I left the accepted record as written, because the version lives only in `go.mod`. If you want a dated "Updated by T0.14" line added, say so.
- GO-2026-5024 (`golang.org/x/sys` v0.41.0, Windows, module-level only, not reachable) is still owned by T0.12. It does not change here.
- The workflows have not run on GitHub yet. On the PR, `snapshot.yaml` runs because `go.mod` and `Dockerfile` changed. Expect `Go in use is go1.26.8, the go.mod toolchain`.
- golangci-lint found nothing, so there are no findings to fix and none to list for other owners.

## Reproduce green

```sh
D='docker run --rm -v <repo>:/src -w /src -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local golang:1.26'
$D make toolchain-check          # Go in use is go1.26.8, the go.mod toolchain
$D go build ./... && $D go vet ./... && $D go test -race -count=1 ./...   # 7 packages ok
$D make policy-test              # 25 cases, 25 passed, 0 failed
$D make fixtures-check           # fixtures ok
$D make vulncheck                # govulncheck@v1.8.0: No vulnerabilities found. (1 module-only: GO-2026-5024)
GOTOOLCHAIN=go1.26.5 go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...   # exit 1: 4 reachable stdlib vulns, so the gate still fails
docker run --rm -e GOTOOLCHAIN=local golang:1.25 make toolchain-check        # exit 2: go1.25.14 != go1.26.8
docker run --rm -v <repo>:/src -w /src golangci/golangci-lint:v2.9.0 golangci-lint run ./...   # 0 issues
docker run --rm -v <repo>:/repo -w /repo rhysd/actionlint:1.7.12 -config-file .github/actionlint.yaml   # 0 errors in 4 files
GOTOOLCHAIN=go1.26.8 goreleaser release --snapshot --clean --skip=publish,sign   # v2.18.2, exit 0
python tools/status/render.py --check
```

## Decisions made without an ADR

- I did not raise the `go` floor. It stays at `go 1.25.0`, and nothing forced a change.
- I picked golangci-lint v2.9.0, the smallest release built with Go 1.26, rather than the newest (v2.13.2). This keeps new linter behaviour out of a toolchain PR. Moving to a newer version can be a separate Dependabot-style bump.

## Questions for the receiver

- go-reviewer: should the Dockerfile builder be pinned to `golang:1.26.8-alpine` (patch-exact, same determinism as the `toolchain` line), or by digest, instead of the floating `1.26-alpine`?
- security-reviewer: with golangci-lint at v2.9.0, is a checksum-verified install (the release `checksums.txt`, sha256 `493aaaca…6091` for linux-amd64) worth adding to the lint job, given that the action downloads the binary by version tag? In v7.0.1, `src/install.ts` fetches it with `tc.downloadTool` and does not verify a checksum.
