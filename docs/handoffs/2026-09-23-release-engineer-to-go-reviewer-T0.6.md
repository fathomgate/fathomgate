# T0.6, T0.10, T0.11 ready for review: govulncheck, actionlint and a GoReleaser snapshot job in CI

- **Task:** T0.6 — Verify GoReleaser snapshot and distroless image build with the new toolchain; T0.10 — Add govulncheck to CI; T0.11 — Run actionlint on every PR in ci.yaml
- **From → To:** release-engineer → go-reviewer (T0.6, T0.11); T0.10 → **security-reviewer for sign-off** (mandatory per the review rules; go-reviewer approved with nits)
- **State now:** in review
- **Branch / PR:** `ci/m0-release-hardening`, stacked on T0.1 (PR #14 head `64bf8b7`), not pushed · none yet. One commit per task: T0.10 `d7e4253`, T0.11 `c7af910`, T0.6 `9b127a2`; note renamed by the orchestrator in `3c4731b`; review fixes in the head commit `ci: address T0.6/T0.10 review`.
- **Date:** 2026-09-23

## Done

- **T0.10.** New `govulncheck` job in `ci.yaml` runs `make vulncheck`, which is `go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...`. `go.mod` and `go.sum` stay unchanged. A vulnerability reachable from our code fails the job (exit 3). I pinned v1.7.0, not v1.8.0, because v1.8.0 needs Go 1.26 and would switch toolchains, so it would scan a stdlib we don't ship.
- **T0.10 finding.** `go-version-file: go.mod` installs exactly go1.25.0. Under go1.25.0, govulncheck reports 4 reachable stdlib vulnerabilities via `internal/audit/key.go`: GO-2025-4007, GO-2025-4009, GO-2025-4011 and GO-2026-5972. Release binaries would have shipped with them. `ci.yaml`, `release.yaml` and `nightly-clab.yaml` now use `go-version: 1.25.x` with `check-latest: true`. Under go1.25.14 the result is `No vulnerabilities found.`
- **T0.11.** New `actionlint` job in `ci.yaml` runs `make actionlint`: `go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -config-file .github/actionlint.yaml`. shellcheck is preinstalled on `ubuntu-latest`. Locally, the `rhysd/actionlint:1.7.12` image (which includes shellcheck) reports 0 errors in 4 files. It fails the pre-T0.9 `nightly-clab.yaml` at `40:27`, as it should.
- **T0.6.** GoReleaser v2.18.2, built with go1.25.14, ran `release --snapshot --clean --skip=publish,sign` and exited 0. It produced 6 archives (linux, darwin and windows, each amd64 and arm64), 6 SPDX SBOMs, `checksums.txt`, the Homebrew formula and the amd64 image. `go version -m` shows go1.25.14, `CGO_ENABLED=0` and `-trimpath=true` on every binary. The linux binaries are statically linked, and the darwin binaries link only libSystem, which is normal for Go on darwin. The image runs `version`, its user is `nonroot:nonroot` and its filesystem contains no shell. The root `Dockerfile` (golang:1.25-alpine builder on `distroless/static-debian12:nonroot`) builds a static go1.25.14 binary. `.goreleaser.yaml` needed no change.
- **T0.6 CI.** New `snapshot.yaml` runs on `workflow_dispatch`, and on pull requests only when `.goreleaser.yaml`, the Dockerfiles, `go.mod`, `go.sum` or the release workflows change. It repeats the checks above and uploads `dist/` for 7 days. `release.yaml` now pins GoReleaser v2.18.2 instead of `~> v2`.
- `Makefile` has new `vulncheck` and `actionlint` targets. `CONTRIBUTING.md` and `CHANGELOG.md` `[Unreleased]` are updated.

## Review round 1 (go-reviewer: T0.11 approved; T0.6, T0.10 approved with nits)

- `ci.yaml` gains a weekly `schedule` (Mondays 05:23 UTC), so govulncheck sees new advisories without a push. The comment now says `go run` turns govulncheck's exit 3 into exit 1.
- `CONTRIBUTING.md`: a local go1.25.0 fails `make vulncheck`; use `GOTOOLCHAIN=go1.25.14 make vulncheck`.
- Every third-party action in all four workflows is pinned by full commit SHA with a `# vX.Y.Z` comment. The pins are the newest release inside the major version already in use, resolved with `gh api .../git/ref/tags/<tag>`, and annotated tags are dereferenced to their commit. `anchore/sbom-action` `v0.24.2` was the only annotated tag. Its floating `v0` tag sat 73 commits behind `v0.24.2`, so this pin is a real move for `download-syft`. `.github/dependabot.yml` already has `github-actions` weekly, so Dependabot keeps the pins current.
- `snapshot.yaml` checks out with `persist-credentials: false` and asserts all six archives, `windows_arm64` included. The CHANGELOG says six.
- The toolchain approach is unchanged (`1.25.x` + `check-latest`). The `toolchain` line in `go.mod` is now the maintainer's decision.

## For security-reviewer (T0.10 sign-off)

- Open `.github/workflows/ci.yaml`, job `vuln`, and the `vulncheck` target in `Makefile`. The job has `contents: read` only, and govulncheck is fetched through the Go module proxy and checked against the sumdb (`go run pkg@v1.7.0`).
- Supply-chain hardening is in the same commit: SHA-pinned actions everywhere, with `release.yaml` done first because it holds `contents: write` and `id-token: write`.
- Open finding: GO-2026-5024 in `golang.org/x/sys` v0.41.0 is present at module level only (Windows) and is not reachable. T0.12 should bump it.

## Look at this first

- `.github/workflows/ci.yaml`: the `env.GO_VERSION` comment and the two new jobs. Then `.github/workflows/snapshot.yaml`.

## Deliberately unfinished

- Exit criterion 4 ("binaries on a tag") is **not** proven. Only a pushed tag proves it. The public tag also waits on the naming ADR.
- The new jobs have not run on GitHub yet. On the PR, expect the `govulncheck` step to print `No vulnerabilities found.` and the `actionlint` step to print nothing (exit 0). `snapshot.yaml` will run because the PR touches `release.yaml`.
- GoReleaser v2.18 prints two deprecation warnings, one for `brews` and one for `dockers`, and `goreleaser check` exits 2 because of them. Neither is a Go 1.25 break, so I will move them to `homebrew_casks` and `dockers_v2` in a separate change.
- Drift from `.claude/agents/release-engineer.md`, left alone because it is not in this task's scope:
  - The builds also produce `windows/arm64`.
  - The image is single-arch amd64, is not signed and has no policies or profiles (`Dockerfile.goreleaser`).
  - `checksums.txt` is not signed.
  - `netguard version` does not print the Go or go-sdk version.
- The `serve` stub message still says "requires Go 1.25 + go-sdk v1.7". That belongs to T0.2.
- govulncheck on `-tags tools` (go-sdk) finds one issue at module level only: GO-2026-5024 in `golang.org/x/sys` v0.41.0 (windows), fixed in v0.44.0, not reachable. T0.12 uses `x/sys/windows`, so it should bump to v0.44.0 or later under ADR 0011.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check
GOTOOLCHAIN=go1.25.14 go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...   # No vulnerabilities found.
GOTOOLCHAIN=go1.25.0  go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...   # 4 stdlib vulns, exit 3: why 1.25.x
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -config-file .github/actionlint.yaml   # exit 0
GOTOOLCHAIN=go1.25.14 goreleaser release --snapshot --clean --skip=publish,sign   # v2.18.2, needs syft + docker
git diff --exit-code go.mod go.sum
python tools/status/render.py --check
```

## Decisions made without an ADR

- Workflows pin `go-version: 1.25.x` instead of reading `go.mod`. The alternative is a `toolchain go1.25.14` line in `go.mod`, which is a `go.mod` change and so needs an ADR. The cost is that a Go minor bump now edits the workflows as well as `go.mod`.
- GoReleaser pinned to v2.18.2 in `release.yaml`.

## Questions for the receiver

- The `toolchain` line in `go.mod` has gone to the maintainer as a decision. Nothing is open for go-reviewer.
- security-reviewer: is the `govulncheck` gate (reachable only, weekly plus every push) enough for ADR 0011 guardrail 4?
