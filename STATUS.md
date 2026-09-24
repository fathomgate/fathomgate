# Status

<!-- GENERATED from docs/milestones/M0.yaml by tools/status/render.py. Edit the YAML, then `make status`. -->

**Current milestone:** M0 — Pass-through proxy · **state:** in progress · opened 2026-09-23

Tasks: open 5 · blocked 2 · in review 1 · merged 21

## In flight

| Task | Title | Package | Owner | Reviewers | State | Blocked by | Matrix | ADR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| T0.1 | Bump toolchain to Go 1.25 and add github.com/modelcontextprotocol/go-sdk v1.7.x | `go.mod` | mcp-protocol-engineer | go-reviewer | merged | — | — | [0011](docs/adr/0011-accept-go-sdk-transitive-modules.md) |
| T0.2 | internal/proxy — spawn one stdio upstream, forward tools/list and tools/call with server prefix | `internal/proxy` | mcp-protocol-engineer | go-reviewer, security-reviewer | merged | T0.1 | 1 | [0002](docs/adr/0002-standalone-proxy-not-gateway-plugin.md) |
| T0.3 | Dual-era negotiation (initialize handshake vs _meta self-description, MRTR passthrough) | `internal/proxy` | mcp-protocol-engineer | go-reviewer, security-reviewer | merged | T0.2 | 2 | [0008](docs/adr/0008-dual-era-mcp-support.md) |
| T0.4 | Conformance suite in CI against the client-facing side; make conformance target | `.github/workflows` | test-engineer | go-reviewer | merged | T0.2 | 1, 2 | — |
| T0.5 | Client smoke — Claude Code and Cursor mcp.json snippets, PATH-stripped launcher case | `tests/integration` | test-engineer | release-engineer | merged | T0.3 | 22 | — |
| T0.6 | Verify GoReleaser snapshot and distroless image build with the new toolchain | `.goreleaser.yaml` | release-engineer | go-reviewer | merged | T0.1 | — | — |
| T0.7 | Make TestKeyRoundTrip portable — file-mode assertion fails on Windows (-rw-rw-rw-) | `internal/audit` | policy-engineer | go-reviewer, security-reviewer | merged | — | — | — |
| T0.8 | tools/status/render.py writes CRLF on Windows, so status-check reports STATUS.md stale | `tools/status` | docs-writer | go-reviewer | merged | — | — | — |
| T0.9 | nightly-clab.yaml fails with a workflow file error on every push to main | `.github/workflows` | release-engineer | go-reviewer | merged | — | — | — |
| T0.10 | Add govulncheck to CI | `.github/workflows` | release-engineer | go-reviewer, security-reviewer | merged | T0.1 | — | [0011](docs/adr/0011-accept-go-sdk-transitive-modules.md) |
| T0.11 | Run actionlint on every PR in ci.yaml | `.github/workflows` | release-engineer | go-reviewer | merged | T0.1 | — | — |
| T0.12 | Restrict the audit key file to its owner on Windows (DACL) and open keys with O_EXCL plus chmod on every OS | `internal/audit` | policy-engineer | security-reviewer, go-reviewer | merged | — | — | [0011](docs/adr/0011-accept-go-sdk-transitive-modules.md) |
| T0.13 | Pin the Go build toolchain in go.mod and read it from there in every workflow | `go.mod` | release-engineer | go-reviewer, security-reviewer | merged | T0.10 | — | [0013](docs/adr/0013-pin-go-toolchain-in-go-mod.md) |
| T0.14 | Move the build toolchain to Go 1.26 now that Go 1.25 is out of support | `go.mod` | release-engineer | go-reviewer, security-reviewer | merged | — | — | [0013](docs/adr/0013-pin-go-toolchain-in-go-mod.md) |
| T0.15 | Pin the Dockerfile builder and distroless base images by digest | `Dockerfile` | release-engineer | go-reviewer, security-reviewer | merged | T0.14 | — | — |
| T0.16 | Update the ADR 0011 module table for golang.org/x/sys as a direct dependency | `docs/adr` | docs-writer | go-reviewer | merged | T0.12 | — | — |
| T0.17 | Relay upstream progress notifications to the agent with a proxy-issued progress token | `internal/proxy` | mcp-protocol-engineer | go-reviewer, security-reviewer | merged | T0.4 | 2 | — |
| T0.18 | Decide input_required retry handling (SEP-2322 SHOULD vs the proxy's strict -32602) | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | merged | T0.4 | 2 | — |
| T0.19 | Conformance coverage for a 2025-11-25 upstream behind netguard | `tests/conformance` | test-engineer | go-reviewer | open | T0.4 | 2 | — |
| T0.20 | Evaluate installing golangci-lint via go run so the checksum database verifies it | `.github/workflows` | release-engineer | go-reviewer, security-reviewer | merged | — | — | — |
| T0.21 | Mark mcp-conformance as a required status check on main | `.github/workflows` | joshscott13 | release-engineer | blocked | T0.4 | — | — |
| T0.22 | Sweep remaining stale go-sdk v1.7 and go 1.24 mentions | `docs` | docs-writer | go-reviewer | merged | — | — | — |
| T0.23 | Keep device passwords off the netguard command line (upstream secrets from a file or the environment) | `cmd/netguard` | mcp-protocol-engineer | security-reviewer, go-reviewer | open | — | 22 | — |
| T0.24 | Fix the platform-dependent nolint in internal/audit/key_unix.go so make lint passes on darwin and linux/arm64 | `internal/audit` | policy-engineer | security-reviewer, go-reviewer | merged | — | — | — |
| T0.25 | Report the upstream's exit status when it dies at startup, not only EOF | `internal/proxy` | mcp-protocol-engineer | go-reviewer, security-reviewer | open | — | 22 | — |
| T0.26 | Replace the synthetic fake-device transcript with a sanitised real EOS capture | `tests/fixtures/device` | network-safety-engineer | test-engineer | in review | — | 22 | — |
| T0.27 | Streamable HTTP listener for netguard serve | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | blocked | T0.28 | 1, 2 | 0016 (missing) |
| T0.28 | Stop a slow agent from stalling an upstream's notification queue (progress relay writes off the dispatch goroutine) | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | open | — | 2 | — |
| T0.29 | Record in the netdev-ssh-mcp profile that its secret obfuscation is an unkeyed hash | `profiles` | upstream-server-scout | security-reviewer | open | — | 15 | — |

## Exit criteria

- [x] Official MCP conformance suite passes on the client-facing side, every remaining failure baselined against an ADR or a board task — met 2026-09-23 (T0.4 PR
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
| 2026-09-23 | test-engineer | joshscott13 | T0.5 | [T0.5 merged: exit criterion 2 needs one manual tool call in Claude Code and one in Cursor](docs/handoffs/2026-09-23-test-engineer-to-joshscott13-T0.5.md) |
| 2026-09-23 | test-engineer | go-reviewer | T0.4 | [T0.4 merged before review: post-merge review of the MCP conformance job, and the baseline for exit criterion 1](docs/handoffs/2026-09-23-test-engineer-to-go-reviewer-T0.4.md) |
| 2026-09-23 | release-engineer | go-reviewer | T0.9 | [T0.9 ready for review: nightly-clab.yaml was invalid YAML, now parses and stays skipped](docs/handoffs/2026-09-23-release-engineer-to-go-reviewer-T0.9.md) |
| 2026-09-23 | release-engineer | go-reviewer | T0.6 | [T0.6, T0.10, T0.11 ready for review: govulncheck, actionlint and a GoReleaser snapshot job in CI](docs/handoffs/2026-09-23-release-engineer-to-go-reviewer-T0.6.md) |
| 2026-09-23 | release-engineer | go-reviewer | T0.15 | [T0.15 merged before review: post-merge check of the base image digest pins](docs/handoffs/2026-09-23-release-engineer-to-go-reviewer-T0.15.md) |

## How to update

Edit `docs/milestones/M0.yaml` (task `state`, `blocked_by`, blockers), write a note in `docs/handoffs/` when you hand work on, then `make status`. Never edit this file by hand. Full protocol: [docs/handoffs/README.md](docs/handoffs/README.md).
