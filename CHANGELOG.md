# Changelog

All notable changes to NetGuard are recorded here. The format follows [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/), and the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once tagged. Until `0.1.0`, `main` is the only line.

Entries use the project vocabulary: decisions are allow, hold, deny, expired; classes are spelled as in [docs/glossary.md](docs/glossary.md).

## [Unreleased]

### Added

- Go module `github.com/joshscott13/netguard` (Go 1.24; go-sdk v1.7 will need 1.25), MIT licence, `Makefile`, `.goreleaser.yaml`, distroless `Dockerfile`, CI workflows `ci.yaml`, `nightly-clab.yaml`, `release.yaml`.
- `internal/policy`: YAML policy loader with strict keys, `Evaluate(policy, request) -> Decision` with first-match-wins, unknown-target and session caps, reserved `default:` rule ids, the seven-obligation vocabulary, and the `*.test.yaml` runner.
- `internal/classify`: the seven-class enum, per-server profiles (`server`, `tools`, `target_params`, `targets_params`, `group_params`, `command_params`, `config_params`), `Normalize`, and the fallback command classifier with allow-list downgrade.
- `internal/inventory`: static `inventory.yaml` with `devices` and `roles` patterns, CSV import, resolver chain, NetBox stub.
- `internal/redact`: ordered vendor rules (Cisco, NX-OS, Junos, EOS, PAN-OS, FortiOS) plus generic patterns, keyed truncated HMAC-SHA256 tokens.
- `internal/audit`: hash-chained JSONL `call` records, Ed25519 `checkpoint` records, canonicalisation, `Verify`, key generation.
- CLI `cmd/netguard`: `version`, `serve` (exits 2 until go-sdk is available), `policy test`, `policy eval`, `audit verify`, `audit keygen`, `redact`, `inventory import`.
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

- Nothing yet.

### Security

- Nothing yet. Security fixes will be listed here with their advisory id.

[Unreleased]: https://github.com/joshscott13/netguard/compare/main...HEAD
