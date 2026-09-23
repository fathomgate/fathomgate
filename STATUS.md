# Status

<!-- GENERATED from docs/milestones/M0.yaml by tools/status/render.py. Edit the YAML, then `make status`. -->

**Current milestone:** M0 — Pass-through proxy · **state:** blocked · opened 2026-09-23

Tasks: open 1 · blocked 8 · in review 3

## Blockers

- **B1** (mcp-protocol-engineer): Go 1.25 toolchain and go-sdk v1.7.0 on build/go-1.25-go-sdk; clears when T0.1 merges.
- **B2** (joshscott13): ADR 0011 (go-sdk transitive modules) must be accepted by a maintainer before T0.1 merges.

## In flight

| Task | Title | Package | Owner | Reviewers | State | Blocked by | Matrix | ADR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T0.1 | Bump toolchain to Go 1.25 and add github.com/modelcontextprotocol/go-sdk v1.7.x | `go.mod` | mcp-protocol-engineer | go-reviewer | blocked | — | — | [0011](docs/adr/0011-accept-go-sdk-transitive-modules.md) |
| T0.2 | internal/proxy — spawn one stdio upstream, forward tools/list and tools/call with server prefix | `internal/proxy` | mcp-protocol-engineer | go-reviewer, security-reviewer | blocked | T0.1 | 1 | [0002](docs/adr/0002-standalone-proxy-not-gateway-plugin.md) |
| T0.3 | Dual-era negotiation (initialize handshake vs _meta self-description, MRTR passthrough) | `internal/proxy` | mcp-protocol-engineer | go-reviewer, security-reviewer | blocked | T0.2 | 2 | [0008](docs/adr/0008-dual-era-mcp-support.md) |
| T0.4 | Conformance suite in CI against the client-facing side; make conformance target | `.github/workflows` | test-engineer | go-reviewer | blocked | T0.2 | 1, 2 | — |
| T0.5 | Client smoke — Claude Code and Cursor mcp.json snippets, PATH-stripped launcher case | `tests/integration` | test-engineer | release-engineer | blocked | T0.3 | 22 | — |
| T0.6 | Verify GoReleaser snapshot and distroless image build with the new toolchain | `.goreleaser.yaml` | release-engineer | go-reviewer | blocked | T0.1 | — | — |
| T0.7 | Make TestKeyRoundTrip portable — file-mode assertion fails on Windows (-rw-rw-rw-) | `internal/audit` | policy-engineer | go-reviewer, security-reviewer | in review | — | — | — |
| T0.8 | tools/status/render.py writes CRLF on Windows, so status-check reports STATUS.md stale | `tools/status` | docs-writer | go-reviewer | in review | — | — | — |
| T0.9 | nightly-clab.yaml fails with a workflow file error on every push to main | `.github/workflows` | release-engineer | go-reviewer | in review | — | — | — |
| T0.10 | Add govulncheck to CI | `.github/workflows` | release-engineer | go-reviewer, security-reviewer | blocked | T0.1 | — | [0011](docs/adr/0011-accept-go-sdk-transitive-modules.md) |
| T0.11 | Run actionlint on every PR in ci.yaml | `.github/workflows` | release-engineer | go-reviewer | open | — | — | — |
| T0.12 | Restrict the audit key file to its owner on Windows (DACL) and open keys with O_EXCL plus chmod on every OS | `internal/audit` | policy-engineer | security-reviewer, go-reviewer | blocked | T0.1 | — | [0011](docs/adr/0011-accept-go-sdk-transitive-modules.md) |

## Exit criteria

- [ ] Official MCP conformance suite passes on the client-facing side
- [ ] Claude Code and one other client list and call tools through the proxy against netdev-ssh-mcp
- [ ] Both protocol eras negotiate (2025-11-25 stateful, 2026-07-28 stateless MRTR)
- [ ] GoReleaser produces linux/darwin/windows binaries on a tag

Validated against: `netdev-ssh-mcp`, `upa/mcp-netmiko-server`

## External

- pr: #2 dependabot go-yaml 1.18.0 -> 1.19.2 — merged. Merged 2026-09-23 before T0.1, so T0.1's diff stays toolchain-only.
- pr: #1 dependabot golang 1.24-alpine -> 1.25-alpine — merged. Dockerfile builder already on Go 1.25; T0.1 does not need to touch it.

## Last handoffs

| Date | From | To | Task | Note |
| --- | --- | --- | --- | --- |
| 2026-09-23 | release-engineer | go-reviewer | T0.9 | [T0.9 ready for review: nightly-clab.yaml was invalid YAML, now parses and stays skipped](docs/handoffs/2026-09-23-release-engineer-to-go-reviewer-T0.9.md) |
| 2026-09-23 | policy-engineer | security-reviewer | T0.7 | [T0.7 for security review: 0600 key-mode assertion now runs on Unix only; SaveKey unchanged](docs/handoffs/2026-09-23-policy-engineer-to-security-reviewer-T0.7.md) |
| 2026-09-23 | netguard-orchestrator | mcp-protocol-engineer | T0.1 | [T0.1 is yours: move go.mod to Go 1.25 and pin go-sdk v1.7.x, nothing else](docs/handoffs/2026-09-23-netguard-orchestrator-to-mcp-protocol-engineer-T0.1.md) |
| 2026-09-23 | mcp-protocol-engineer | go-reviewer | T0.1 | [T0.1 fix-ups are in: Go 1.25.0, go-sdk v1.7.0, golangci-lint v2.4.0; merge waits on ADR 0011 (proposed)](docs/handoffs/2026-09-23-mcp-protocol-engineer-to-go-reviewer-T0.1.md) |
| 2026-09-23 | joshscott13 | netguard-orchestrator | M0 | [Scaffold complete; M0 is yours and it starts with a toolchain bump](docs/handoffs/2026-09-23-joshscott13-to-netguard-orchestrator-M0.md) |

## How to update

Edit `docs/milestones/M0.yaml` (task `state`, `blocked_by`, blockers), write a note in `docs/handoffs/` when you hand work on, then `make status`. Never edit this file by hand. Full protocol: [docs/handoffs/README.md](docs/handoffs/README.md).
