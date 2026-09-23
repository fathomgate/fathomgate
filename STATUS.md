# Status

<!-- GENERATED from docs/milestones/M0.yaml by tools/status/render.py. Edit the YAML, then `make status`. -->

**Current milestone:** M0 — Pass-through proxy · **state:** blocked · opened 2026-09-23

Tasks: open 1 · blocked 5

## Blockers

- **B1** (mcp-protocol-engineer): go-sdk v1.7.x requires Go 1.25; go.mod is 1.24. Toolchain bump is its own PR (T0.1).

## In flight

| Task | Title | Package | Owner | Reviewers | State | Blocked by | Matrix | ADR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T0.1 | Bump toolchain to Go 1.25 and add github.com/modelcontextprotocol/go-sdk v1.7.x | `go.mod` | mcp-protocol-engineer | go-reviewer | open | — | — | [0001](docs/adr/0001-go-core-with-python-companion.md) |
| T0.2 | internal/proxy — spawn one stdio upstream, forward tools/list and tools/call with server prefix | `internal/proxy` | mcp-protocol-engineer | go-reviewer, security-reviewer | blocked | T0.1 | 1 | [0002](docs/adr/0002-standalone-proxy-not-gateway-plugin.md) |
| T0.3 | Dual-era negotiation (initialize handshake vs _meta self-description, MRTR passthrough) | `internal/proxy` | mcp-protocol-engineer | go-reviewer, security-reviewer | blocked | T0.2 | 2 | [0008](docs/adr/0008-dual-era-mcp-support.md) |
| T0.4 | Conformance suite in CI against the client-facing side; make conformance target | `.github/workflows` | test-engineer | go-reviewer | blocked | T0.2 | 1, 2 | — |
| T0.5 | Client smoke — Claude Code and Cursor mcp.json snippets, PATH-stripped launcher case | `tests/integration` | test-engineer | release-engineer | blocked | T0.3 | 22 | — |
| T0.6 | Verify GoReleaser snapshot and distroless image build with the new toolchain | `.goreleaser.yaml` | release-engineer | go-reviewer | blocked | T0.1 | — | — |

## Exit criteria

- [ ] Official MCP conformance suite passes on the client-facing side
- [ ] Claude Code and one other client list and call tools through the proxy against netdev-ssh-mcp
- [ ] Both protocol eras negotiate (2025-11-25 stateful, 2026-07-28 stateless MRTR)
- [ ] GoReleaser produces linux/darwin/windows binaries on a tag

Validated against: `netdev-ssh-mcp`, `upa/mcp-netmiko-server`

## External

- pr: dependabot go-yaml 1.18.0 -> 1.19.2 — open. Trivial first merge to exercise the pipeline; not part of M0 scope.

## Last handoffs

| Date | From | To | Task | Note |
| --- | --- | --- | --- | --- |
| 2026-09-23 | joshscott13 | netguard-orchestrator | M0 | [Scaffold complete; M0 is yours and it starts with a toolchain bump](docs/handoffs/2026-09-23-joshscott13-to-netguard-orchestrator-M0.md) |

## How to update

Edit `docs/milestones/M0.yaml` (task `state`, `blocked_by`, blockers), write a note in `docs/handoffs/` when you hand work on, then `make status`. Never edit this file by hand. Full protocol: [docs/handoffs/README.md](docs/handoffs/README.md).
