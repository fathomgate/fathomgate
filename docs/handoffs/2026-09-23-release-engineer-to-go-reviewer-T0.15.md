# T0.15 merged before review: post-merge check of the base image digest pins

- **Task:** T0.15 — Pin the Dockerfile builder and distroless base images by digest
- **From → To:** release-engineer → go-reviewer, security-reviewer
- **State now:** merged
- **Branch / PR:** build/pin-image-digests · https://github.com/joshscott13/netguard/pull/36
- **Date:** 2026-09-23

## Done

- `Dockerfile` builder: `golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c` (go1.26.8, matching the `go.mod` toolchain).
- `Dockerfile` runtime and `Dockerfile.goreleaser`: `gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab`.
- Both digests are multi-arch OCI index digests (amd64 and arm64) from `docker buildx imagetools inspect`, each cross-checked with a direct registry request.
- `CONTRIBUTING.md` has a new "Base image pins" section; `CHANGELOG.md` has an Unreleased/Security entry.

## Look at this first

- Confirm each digest is the index, not one platform's manifest, and that the distroless digest is identical in both Dockerfiles.

## Deliberately unfinished

- golangci-lint via `go run` is split out as T0.20.
- The no-shell image check and the GoReleaser snapshot ran in CI only, not locally.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check
docker buildx imagetools inspect golang:1.26-alpine | head -3
docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot | head -3
docker build -t netguard:t015 . && docker run --rm netguard:t015 version
```

## Decisions made without an ADR

- The existing Dependabot `docker` entry for `/` covers both files, so no Dependabot config change was needed.

## Questions for the receiver

- None.
