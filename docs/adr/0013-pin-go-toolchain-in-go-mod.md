# ADR 0013: Pin the Go build toolchain in go.mod

- Status: accepted
- Date: 2026-09-23
- Deciders: Josh Scott (maintainer; accepted 2026-09-23)

## Context

`go.mod` declares `go 1.25.0`, the floor that go-sdk v1.7.0 sets ([ADR 0011](0011-accept-go-sdk-transitive-modules.md)). When CI read that line with `go-version-file: go.mod`, it installed exactly go1.25.0. govulncheck found standard-library vulnerabilities in go1.25.0 that NetGuard code reaches: four through `internal/audit/key.go` at T0.10 (GO-2025-4007, GO-2025-4009, GO-2025-4011, GO-2026-5972). With `internal/proxy` linked, the count is now 24. T0.10 worked around this by setting `go-version: "1.25.x"` with `check-latest: true` in `ci.yaml`, `release.yaml`, `snapshot.yaml` and `nightly-clab.yaml`. That fixed the vulnerabilities but caused two new problems:

- The Go version used by CI and release builds was whatever 1.25 patch was newest on the day of the run. Two runs of the same commit could build with different compilers and standard libraries, so a release binary was not reproducible from its tag.
- The version was set in four workflow files, separately from `go.mod`. Bumping it meant editing all four, and nothing checked that they agreed.

Go 1.21 and later read a `toolchain` line in `go.mod`. It names the Go release to use for this module, and it does not raise the `go` floor for anyone who imports the module. go-reviewer proposed pinning the build toolchain there (T0.6 handoff note). The maintainer approved the approach for T0.13.

We need to check three things. First, the setup-go action that CI pins must honour the `toolchain` line. Second, Dependabot might bump it for us. Third, the pin must not hide a new standard-library advisory.

## Decision

We will pin the build toolchain with `toolchain go1.25.14` in `go.mod`, keep `go 1.25.0` as the floor, and make every workflow read the version from `go.mod` through `actions/setup-go` v6.5.0, pinned by commit SHA.

1. **`go.mod` is the only place the version is written.** `go 1.25.0` is still the minimum for anyone who builds or imports the module. `toolchain go1.25.14` is the release CI and GoReleaser build with. go1.25.14 is the newest Go 1.25 patch (released 2026-08-19, checked against `https://go.dev/dl/?mode=json&include=all` on 2026-09-23).
2. **Workflows read `go-version-file: go.mod`.** `ci.yaml` (all four Go jobs), `release.yaml`, `snapshot.yaml` and `nightly-clab.yaml` use `actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16 # v6.5.0`. The `env.GO_VERSION`, `go-version: "1.25.x"` and `check-latest: true` settings are removed.
3. **We move to setup-go v6 because v5 ignores the `toolchain` line.** In the v5.6.0 commit CI used before (`40f1582b`), `parseGoVersionFile` in `src/installer.ts` reads only the `go` line:

   ```ts
   const match = contents.match(/^go (\d+(\.\d+)*)/m);
   ```

   v6.0.0 lists "Improve toolchain handling" (actions/setup-go#460) as a breaking change. In v6.5.0 (`924ae3a1`), `parseGoVersionFile` returns the `toolchain` line first, unless the caller has set `GOTOOLCHAIN=local`:

   ```ts
   if (process.env[GOTOOLCHAIN_ENV_VAR] !== GOTOOLCHAIN_LOCAL_VAL) {
     const matchToolchain = contents.match(/^toolchain go(1\.\d+(?:\.\d+|rc\d+)?)/m);
   ```

   `src/main.ts` `setGoToolchain()` then exports `GOTOOLCHAIN=local` for the rest of the job. The installed Go is the one that builds, and no step downloads a different toolchain behind our back.
4. **A guard checks the Go version.** The new `make toolchain-check` target fails unless `go env GOVERSION` equals the `toolchain` line. It runs in the `ci.yaml` `go` job and in `release.yaml` before govulncheck and GoReleaser. If setup-go is ever downgraded to a version that installs the `go` floor under `GOTOOLCHAIN=local`, the job fails instead of shipping a go1.25.0 binary.
5. **`make vulncheck` uses the pinned toolchain.** It runs with `GOTOOLCHAIN=<toolchain line>`, so a contributor's local scan checks the standard library that ships, whether their installed Go is older or newer. In CI the installed Go is already that version, so nothing is downloaded.
6. **Toolchain bumps are manual.** Dependabot's `gomod` ecosystem does not update the `toolchain` line (see Consequences). A bump is a `build(ci)` pull request that runs `go mod edit -toolchain=go1.25.N`, `make toolchain-check` under that toolchain, `make vulncheck`, and the green gate. go-reviewer and security-reviewer review it. It needs no new ADR as long as the `go` floor does not change. The weekly govulncheck run (Mondays 05:23 UTC, `ci.yaml`) triggers a bump: a new reachable standard-library advisory fails CI until someone merges the bump.

## Consequences

### Positive

- A tag builds with the same compiler and standard library as the CI run on its commit. `go version -m` on a release binary shows the `toolchain` line.
- There is one place to bump. Workflows, the Makefile and `toolchain-check` all read `go.mod`.
- A new advisory is a visible, reviewed change. Previously `check-latest` absorbed Go patches silently.
- Contributors whose Go is older than go1.25.14 get the pinned toolchain automatically with the default `GOTOOLCHAIN=auto`. The Go command downloads it once through the module proxy and checks it against the checksum database.

### Negative

- **Dependabot does not bump the `toolchain` line.** Its `go_modules` file parser (`go_modules/lib/dependabot/go_modules/file_parser.rb`) reads only `require` entries. It runs `go version` only to report the package-manager version. The feature request, dependabot/dependabot-core#13520 "Bump Go toolchain directive in go.mod files", has been open since 2025-11. GitHub also raises no Dependabot alert for a vulnerable `toolchain` version (per the same thread). Mitigation: the weekly govulncheck gate and the manual procedure in decision 6 and `CONTRIBUTING.md`. Revisit when #13520 ships.
- **Go 1.25 is out of support.** Go supports a release until two newer major releases exist, and go1.27.0 shipped on 2026-08-19. go1.25.14 came out the same day and is expected to be the last 1.25 patch. There has been no go1.25.15 alongside go1.26.8 (2026-09-01). The next standard-library advisory that NetGuard code reaches will therefore need a go1.26 toolchain, not a 1.25 patch. That bump also affects `GOVULNCHECK_VERSION` (v1.8.0 needs Go 1.26), the golangci-lint version, the `golang:1.25-alpine` builder in `Dockerfile` and `CONTRIBUTING.md`. It stays under this record while the `go` floor stays at 1.25.0, but it should be planned now, not during an advisory.
- setup-go v6 runs on `node24`, so self-hosted runners must be actions/runner v2.327.1 or later. This affects only the `[self-hosted, clab]` runner for `nightly-clab.yaml`, which is not registered yet. The note is in the workflow.
- A contributor whose Go is newer than the pin (for example go1.26.7) still builds and tests with their own Go under `GOTOOLCHAIN=auto`, because Go switches only upward. `make vulncheck` and `make toolchain-check` use the pinned toolchain and match CI. `make test` does not.

### Neutral

- The root `Dockerfile` builds on `golang:1.25-alpine`, which sets `GOTOOLCHAIN=local`. The `toolchain` line does not change that build: it uses the image's Go, which is go1.25.14 today (the Debian-based `golang:1.25` checked on 2026-09-23 reports go1.25.14). Release binaries come from GoReleaser in `release.yaml`, not from this Dockerfile.
- setup-go v6 is a major-version move of an already SHA-pinned action. Dependabot's `github-actions` updates keep the pin current as before.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Keep `go-version: "1.25.x"` with `check-latest: true` (status quo from T0.10) | Not reproducible: the Go version depends on the day of the run. The version is written in four files that nothing keeps in step with `go.mod`. |
| Keep setup-go v5.6.0 with `go-version-file: go.mod` and let `GOTOOLCHAIN=auto` switch | v5.6.0 installs go1.25.0, and Go's own `auto` switch then downloads go1.25.14 at the first `go` command. That works, but the job starts on a vulnerable Go and the build depends on an implicit download. Any step or tool that sets `GOTOOLCHAIN=local` would build with go1.25.0 without an error. |
| Keep setup-go v5.6.0 and set `GOTOOLCHAIN: go1.25.14` in workflow `env` | Deterministic, but the version is written in the workflows again, which is the duplication this record removes. |
| Raise the `go` line to `go 1.25.14` | Pins the build, but also forces every importer and contributor to Go 1.25.14 or later. That puts a security-patch policy into a compatibility floor. The `toolchain` line exists for this case. |
| Pin a go1.26 toolchain now, because 1.25 is out of support | Out of scope for T0.13. It changes the Go minor under `golangci-lint` v2.4.0 and govulncheck v1.7.0, and nothing reachable needs it today. Recorded as the next planned bump under Negative. |

## References

- [ADR 0011, Accept go-sdk v1.7.0 and its transitive modules](0011-accept-go-sdk-transitive-modules.md), guardrail 4 (vulnerability scan)
- [T0.6 / T0.10 / T0.11 handoff note](../handoffs/2026-09-23-release-engineer-to-go-reviewer-T0.6.md), "Decisions made without an ADR"
- [M0 board](../milestones/M0.yaml), tasks T0.10 and T0.13
- Go toolchains: <https://go.dev/doc/toolchain>; `toolchain` directive: <https://go.dev/ref/mod#go-mod-file-toolchain>; release policy: <https://go.dev/doc/devel/release#policy>
- actions/setup-go v6.0.0 release notes: <https://github.com/actions/setup-go/releases/tag/v6.0.0>; actions/setup-go#460
- actions/setup-go `src/installer.ts` at [v5.6.0](https://github.com/actions/setup-go/blob/40f1582b2485089dde7abd97c1529aa768e1baff/src/installer.ts) and [v6.5.0](https://github.com/actions/setup-go/blob/924ae3a1cded613372ab5595356fb5720e22ba16/src/installer.ts)
- dependabot/dependabot-core#13520, "Bump Go toolchain directive in go.mod files" (open)
