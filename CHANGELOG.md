# Changelog

All notable changes to NetGuard are recorded here. The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once tagged. Until `0.1.0`, `main` is the only line.

Entries use the project vocabulary: decisions are allow, hold, deny, expired; classes are spelled as in [docs/glossary.md](docs/glossary.md).

## [Unreleased]

### Added

- `internal/proxy` (T0.2): an MCP server toward the agent and a go-sdk client toward one stdio upstream. `tools/list` exposes each upstream tool as `<server>.<tool>`; `tools/call` strips the prefix and forwards under the agent's context, so cancellation reaches the upstream. Unknown or unprefixed names get JSON-RPC `-32602` with `reason` `unprefixed`, `unknown_server` or `unknown_tool`. An exited upstream yields a tool error naming it. Upstream JSON-RPC errors are relayed with the label `upstream <server>:`, control characters escaped, a 512-byte cap, and non-standard codes (and `-32602`) mapped to `-32603`. Upstream input requests (elicitation, sampling, roots) are refused by netguard. Upstream tool names outside `[A-Za-z0-9_.-]` are not exposed. No policy runs yet. Rules in `docs/specs/profile-schema.md` section 8.
- `netguard serve --server <name> --upstream <path> [--upstream-env K=V]... [-- args]` runs the proxy on stdio. `--policy`, `--inventory`, `--profiles` and `--audit` are refused until M1, wherever they appear on the command line. The upstream inherits only an allow-listed environment (`PATH`, `HOME`, locale and temp variables; the Windows equivalents) plus `--upstream-env`. Its stderr is prefixed `upstream <server>: ` and escaped, and it is killed if startup fails. Decision record `docs/adr/0012-serve-cli-and-proxy-api-for-m0.md` (accepted).
- Decision record `docs/adr/0011-accept-go-sdk-transitive-modules.md` (accepted): accepts go-sdk v1.7.0 and its eight indirect modules, with `go mod why` reasons, `CGO_ENABLED=0` cross-builds and the `govulncheck` follow-up.
- CI job `govulncheck` in `ci.yaml` runs `make vulncheck` on every push, pull request and weekly schedule (Mondays 05:23 UTC): `golang.org/x/vuln/cmd/govulncheck` v1.7.0 via `go run`, so `go.mod` is unchanged. A vulnerability reachable from NetGuard code, standard library included, fails the build (ADR 0011 guardrail 4, T0.10).
- CI job `actionlint` in `ci.yaml` runs `make actionlint`: `github.com/rhysd/actionlint` v1.7.12 via `go run`, with `.github/actionlint.yaml` and shellcheck, on every push and pull request, so a broken workflow file fails its pull request instead of `main` (T0.11).
- Workflow `snapshot.yaml`: `goreleaser release --snapshot --clean --skip=publish,sign` on pull requests that touch `.goreleaser.yaml`, the Dockerfiles, `go.mod`, `go.sum` or the release workflows, and on demand. It checks six platform archives (linux, darwin and windows, each amd64 and arm64), one SPDX SBOM per archive, `checksums.txt`, static `CGO_ENABLED=0` `-trimpath` binaries, a `nonroot` image with no shell, the root `Dockerfile` build, and that the `go mod tidy` hook left `go.mod` unchanged. A snapshot is not a tagged release (T0.6).
- Status tracking for agent handoffs: `docs/milestones/<Mn>.yaml` board (source of truth), `STATUS.md` rendered by `tools/status/render.py` (`make status`; CI job `STATUS.md is current`), `docs/handoffs/` protocol, template and first note, `/status` and `/handoff` slash commands, `.github/labels.yml` for the GitHub issue mirror. `/milestone` now writes the YAML board and `STATUS.md`.
- Go module `github.com/joshscott13/netguard` (Go 1.25; see Changed), MIT licence, `Makefile`, `.goreleaser.yaml`, distroless `Dockerfile`, CI workflows `ci.yaml`, `nightly-clab.yaml`, `release.yaml`.
- `internal/policy`: YAML policy loader with strict keys, `Evaluate(policy, request) -> Decision` with first-match-wins, unknown-target and session caps, reserved `default:` rule ids, the seven-obligation vocabulary, and the `*.test.yaml` runner.
- `internal/classify`: the seven-class enum, per-server profiles (`server`, `tools`, `target_params`, `targets_params`, `group_params`, `command_params`, `config_params`), `Normalize`, and the fallback command classifier with allow-list downgrade.
- `internal/inventory`: static `inventory.yaml` with `devices` and `roles` patterns, CSV import, resolver chain, NetBox stub.
- `internal/redact`: ordered vendor rules (Cisco, NX-OS, Junos, EOS, PAN-OS, FortiOS) plus generic patterns, keyed truncated HMAC-SHA256 tokens.
- `internal/audit`: hash-chained JSONL `call` records, Ed25519 `checkpoint` records, canonicalisation, `Verify`, key generation.
- CLI `cmd/netguard`: `version`, `serve`, `policy test`, `policy eval`, `audit verify`, `audit keygen`, `redact`, `inventory import`.
- Profiles: `netdev-ssh-mcp`, `junos-mcp-server`, `eos-mcp`, `ntunes-netmiko-mcp-server`.
- Example policies `read-only`, `lab-open`, `prod-approval` with 25 test cases across their `*.test.yaml` files.
- Redaction fixture corpus under `tests/fixtures/configs/` for IOS-XE, NX-OS, EOS, Junos, PAN-OS and FortiOS, each with an `.expect.json`.
- Python companion under `tests/`: `policy_lint` (shape validator, also exposed at `tools/policy-lint/`), unit tests, and a skipped tier 2 pass-through test.
- Agent roster: eleven agent definitions in `.claude/agents/`, six slash commands in `.claude/commands/`, and `docs/agents/README.md`.
- Plan and research: `docs/PLAN.md` and the four briefs under `docs/research/`.
- `ARCHITECTURE.md`, `docs/PRD.md`, `ROADMAP.md`, decision records `docs/adr/0001` through `0010` with index, and specs under `docs/specs/` (policy schema, profile schema, inventory schema, audit event schema, classification, approval protocol, change safety drivers, redaction patterns).
- Test strategy and the 22-case matrix under `docs/testing/`; governance files `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md`, `GOVERNANCE.md`, `docs/glossary.md`; `.github` issue and pull request templates and CODEOWNERS.
- Design system policy layer under `design/`: `tokens.css`, `policy.css`, `DESIGN.md`, `preview.html`.

### Changed

- Go 1.25 toolchain: `go.mod` declares `go 1.25.0`, the minimum go-sdk v1.7.0 sets. CI, release and the `Dockerfile` builder follow it (Dockerfile already on golang:1.25-alpine, PR #1).
- go-sdk v1.7.x pinned: `github.com/modelcontextprotocol/go-sdk v1.7.0` is in `go.mod` and imported by `internal/proxy`, so it is linked into `bin/netguard`. The interim `//go:build tools` pin `internal/tools/tools.go` is removed.
- `release.yaml` pins GoReleaser to v2.18.2 instead of `~> v2`, the version `snapshot.yaml` runs, so a tag releases with the tool the last snapshot exercised (T0.6).
- Every third-party action in `ci.yaml`, `release.yaml`, `snapshot.yaml` and `nightly-clab.yaml` is pinned by full commit SHA with a `# vX.Y.Z` comment; Dependabot `github-actions` updates keep the pins current. `anchore/sbom-action/download-syft` moves from the floating `v0` tag (73 commits behind) to v0.24.2. `snapshot.yaml` checks out with `persist-credentials: false`.
- CI `golangci-lint` moves from v2.1 to v2.4.0. v2.1 is built with Go 1.24 and refuses to lint a module that declares Go 1.25.

### Fixed

- `TestKeyRoundTrip` no longer fails on Windows; the 0600 key-mode assertion runs on Unix only.
- `make status` and `render.py --check` now produce UTF-8 with LF on Windows; `PYTHON` overrides the interpreter.
- `nightly-clab.yaml` is valid YAML again: the unquoted `run: echo "TODO(M3): ..."` in the destroy step is now a block scalar, so GitHub no longer records a failed "push" run for it on every push. The job stays skipped until `vars.NETGUARD_CLAB_ENABLED == 'true'` and a `[self-hosted, clab]` runner exists; `.github/actionlint.yaml` declares the `clab` label (T0.9).

### Security

- The audit checkpoint private key and the audit log are owner-only on every OS (T0.12). `audit.SaveKey` (and so `netguard audit keygen`) creates the key exclusively and never overwrites an existing file or symlink. On Unix it uses `O_EXCL` and `Chmod(0600)` on the descriptor, so `keygen --out` onto an existing `0644` file is refused instead of leaving the key world-readable. On Windows, where `0600` did nothing and the key inherited its folder's ACL (for example `BUILTIN\Users` read under `C:\ProgramData`), it is created by `CreateFile` with a protected DACL granting only the current user and `SYSTEM`, so a local non-admin user can no longer read the key and re-sign checkpoints over a rewritten log. `audit.NewWriter` creates a new log the same way and sets an existing log back to owner-only (mode `0600` or the protected DACL) on every open; it never truncates. The interim `icacls` guidance in `SECURITY.md` is replaced by what the code guarantees.
- `golang.org/x/sys` v0.41.0 → v0.47.0, now a direct dependency (`internal/audit` imports `x/sys/windows`). This fixes GO-2026-5024 (`NewNTUnicodeString` overflow in `x/sys/windows`, fixed in v0.44.0), which the import would otherwise bring into the Windows build graph. v0.47.0 is the newest release that keeps the `go 1.25.0` floor (v0.48.0 needs Go 1.26). The module was already accepted in ADR 0011; `go.sum` changes only its two lines.
- Go build toolchain pinned in `go.mod` (ADR 0013, T0.13): `toolchain go1.25.14`, with `go 1.25.0` kept as the floor. `ci.yaml`, `release.yaml`, `snapshot.yaml` and `nightly-clab.yaml` read it with `go-version-file: go.mod` through `actions/setup-go` v6.5.0 (SHA-pinned; v5 ignored the `toolchain` line), replacing `go-version: 1.25.x` with `check-latest: true`, so a tag builds with the same Go as CI on its commit. New `make toolchain-check` fails CI and the release job if the Go in use differs from the pin; `make vulncheck` runs govulncheck with the pinned toolchain. Dependabot does not bump the `toolchain` line; the weekly govulncheck run fails on a new standard-library advisory until the manual bump in `CONTRIBUTING.md` merges. Go 1.25 is out of support since go1.27.0, so the next such bump moves to a go1.26 toolchain.
- `ci.yaml`, `release.yaml` and `nightly-clab.yaml` install the newest Go 1.25 patch (`go-version: 1.25.x`, `check-latest: true`) instead of reading `go.mod`. `go-version-file: go.mod` installed exactly go1.25.0, whose standard library has four vulnerabilities govulncheck traces to `internal/audit` (GO-2025-4007, GO-2025-4009, GO-2025-4011, GO-2026-5972), and release binaries would have shipped with them. `go.mod` keeps `go 1.25.0` as the floor (T0.10).
- `release.yaml` runs `make vulncheck` before GoReleaser, so a reachable vulnerability stops a release; its permissions move to the job (`contents: write`, `packages: write`), `id-token: write` is dropped until cosign signing lands, and setup-go runs with `cache: false`.

[Unreleased]: https://github.com/joshscott13/netguard/compare/main...HEAD
