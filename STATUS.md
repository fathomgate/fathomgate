# Status

<!-- GENERATED from docs/milestones/M0.yaml by tools/status/render.py. Edit the YAML, then `make status`. -->

**Current milestone:** M0 — Pass-through proxy · **state:** in progress · opened 2026-09-23

Tasks: open 6 · blocked 4 · in progress 1 · merged 36

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
| T0.19 | Conformance coverage for a 2025-11-25 upstream behind netguard | `tests/conformance` | test-engineer | go-reviewer | merged | T0.4 | 2 | — |
| T0.20 | Evaluate installing golangci-lint via go run so the checksum database verifies it | `.github/workflows` | release-engineer | go-reviewer, security-reviewer | merged | — | — | — |
| T0.21 | Mark mcp-conformance as a required status check on main | `.github/workflows` | joshscott13 | release-engineer | blocked | T0.4 | — | — |
| T0.22 | Sweep remaining stale go-sdk v1.7 and go 1.24 mentions | `docs` | docs-writer | go-reviewer | merged | — | — | — |
| T0.23 | Keep device passwords off the netguard command line (upstream secrets from a file or the environment) | `cmd/netguard` | mcp-protocol-engineer | security-reviewer, go-reviewer | merged | — | 22 | — |
| T0.24 | Fix the platform-dependent nolint in internal/audit/key_unix.go so make lint passes on darwin and linux/arm64 | `internal/audit` | policy-engineer | security-reviewer, go-reviewer | merged | — | — | — |
| T0.25 | Report the upstream's exit status when it dies at startup, not only EOF | `internal/proxy` | mcp-protocol-engineer | go-reviewer, security-reviewer | merged | — | 22 | — |
| T0.26 | Replace the synthetic fake-device transcript with a sanitised real EOS capture | `tests/fixtures/device` | network-safety-engineer | test-engineer | merged | — | 22 | — |
| T0.27 | (*Proxy).HTTPHandler — era dispatcher over two go-sdk handlers, Host and Origin checks, bearer auth, in-flight and session caps, body limit | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | merged | T0.28 | 23 | [0016](docs/adr/0016-streamable-http-listener.md) |
| T0.28 | Stop a slow agent from stalling an upstream's notification queue (progress relay writes off the dispatch goroutine) | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | merged | — | 2 | — |
| T0.29 | Record in the netdev-ssh-mcp profile that its secret obfuscation is an unkeyed hash | `profiles` | upstream-server-scout | security-reviewer | merged | — | 15 | — |
| T0.30 | Bind the sealed requestState to the principal (ng3.), carry transport and principal on call, state the cross-session attribution rule in 8.4 | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | open | T0.27, T0.40 | 2, 23 | [0016](docs/adr/0016-streamable-http-listener.md) |
| T0.31 | netguard serve --listen, repeatable --listen-token-file name=path, NETGUARD_LISTEN_TOKEN; refused M1 flags; MCPGODEBUG refusal; server limits, shutdown and upstream-exit handling | `cmd/netguard` | mcp-protocol-engineer | security-reviewer, go-reviewer, release-engineer | blocked | T0.27, T0.30, T0.38, T0.40, T0.42, T0.43, T0.44 | 23 | [0016](docs/adr/0016-streamable-http-listener.md) |
| T0.32 | Conformance against the HTTP listener — auth-and-prefix shim, control leg on everything-server -http, delete relay.py, reconcile all four baselines | `tests/conformance` | test-engineer | go-reviewer | blocked | T0.31 | 1, 2 | [0016](docs/adr/0016-streamable-http-listener.md) |
| T0.33 | Matrix row 23 (tier 2 over HTTP, Claude Code type http), profile-schema 8.5 HTTP listener, SECURITY.md gap rows, README and install.md snippets | `tests/integration` | test-engineer | docs-writer, security-reviewer | blocked | T0.31 | 23 | [0016](docs/adr/0016-streamable-http-listener.md) |
| T0.34 | Run upa/mcp-netmiko-server (FastMCP, 2025-11-25) behind netguard in tier 2 and validate matrix row 2 | `tests/integration` | test-engineer | mcp-protocol-engineer, go-reviewer | merged | — | 2 | — |
| T0.35 | Decide whether the elicitation allow-list accepts titled multi-select (items.anyOf with const and title) and enumNames | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | open | — | 2 | — |
| T0.36 | Report upstream that go-sdk's conformance everything-server sends a titled multi-select its own client rejects | `docs` | joshscott13 | mcp-protocol-engineer | open | — | — | — |
| T0.37 | Note in the Command.Secrets godoc that the built transport holds passed values in its Env | `internal/proxy` | mcp-protocol-engineer | security-reviewer | merged | — | — | — |
| T0.38 | Apply the post-merge security and Go reviews of PR #68 (prompt attribution across sessions, session caps, connection close, exports, shutdown) | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | merged | — | 23 | [0016](docs/adr/0016-streamable-http-listener.md) |
| T0.39 | Stop netguard hanging at startup on upstreams that never answer server/discover (probe timeout, restart, straight to initialize) | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | merged | — | 2 | [0018](docs/adr/0018-bound-server-discover-then-initialize-only.md) |
| T0.40 | Apply the PR #72 re-review findings (prompts after a finished call, idle-timer gaps, orphan TTL and memory, ADR 0016 principal text) | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | merged | — | 23 | [0016](docs/adr/0016-streamable-http-listener.md) |
| T0.41 | Reconcile matrix row 2's status word across the matrix cell, its own prose and the CHANGELOG | `docs/testing` | test-engineer | docs-writer | open | — | 2 | — |
| T0.42 | Put the ADR 0014 refusal in the note slot, not the refused slot, so an upstream error is never replaced (S3) | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | merged | — | 2, 23 | [0014](docs/adr/0014-stateful-upstream-prompts-to-stateless-agents.md) |
| T0.43 | Key the local stdio agent session explicitly so a built HTTP listener cannot push it into the shared orphan bucket (S1) | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | merged | — | 2, 23 | — |
| T0.44 | Bound, reap and log the shared orphan entry so cross-principal refusal is neither indefinite nor silent (S2, S4) | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | in progress | — | 23 | — |
| T0.45 | Correct the agentSessionKey comment and record the register-after-flush idle-timer window (S5, S7) | `internal/proxy` | mcp-protocol-engineer | go-reviewer | merged | — | — | — |
| T0.46 | Kill the upstream's whole process tree so a launcher's grandchild cannot outlive a restart or shutdown (S2) | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | open | — | 2, 22 | — |
| T0.47 | Label the upstream era from the negotiated protocol version, not from how netguard connected, before M1 audits it (N6) | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | open | — | 2 | — |

## Exit criteria

- [x] Official MCP conformance suite passes on the client-facing side, every remaining failure baselined against an ADR or a board task — met 2026-09-23 (T0.4 PR
- [x] Claude Code and one other client list and call tools through the proxy against netdev-ssh-mcp — met 2026-09-23 (Claude Code 2.1.236 and Claude Desktop 2.7032.0 called show version through netguard in front of netdev-ssh-mcp v1.6.6, by the maintainer; client-smoke CI green; matrix rows 1 and 22 passing)
- [x] Both protocol eras negotiate (2025-11-25 stateful, 2026-07-28 stateless MRTR) — met 2026-09-23 (maintainer decision; netdev-ssh-mcp v1.6.6 at 2026-07-28 and upa/mcp-netmiko-server 96e8ff3 at 2025-11-25 behind netguard in tier 2 CI with both agent eras, T0.34 PR
- [ ] GoReleaser produces linux/darwin/windows binaries on a tag

Validated against: `netdev-ssh-mcp`, `upa/mcp-netmiko-server`

## External

- pr: #2 dependabot go-yaml 1.18.0 -> 1.19.2 — merged. Merged 2026-09-23 before T0.1, so T0.1's diff stays toolchain-only.
- pr: #1 dependabot golang 1.24-alpine -> 1.25-alpine — merged. Dockerfile builder already on Go 1.25; T0.1 does not need to touch it.

## Last handoffs

| Date | From | To | Task | Note |
| --- | --- | --- | --- | --- |
| 2026-09-24 | mcp-protocol-engineer | security-reviewer | T0.42 | [T0.42, T0.43, T0.45 and the T0.44 doc part ready for review: the post-merge security review of T0.40 applied](docs/handoffs/2026-09-24-mcp-protocol-engineer-to-security-reviewer-T0.42.md) |
| 2026-09-24 | mcp-protocol-engineer | security-reviewer | T0.40 | [T0.40 ready for re-review: an upstream prompt for a call that ended normally no longer reaches another session's human](docs/handoffs/2026-09-24-mcp-protocol-engineer-to-security-reviewer-T0.40.md) |
| 2026-09-24 | mcp-protocol-engineer | security-reviewer | T0.39.review | [T0.39 review fixes are in PR #79 (PR #77 had merged): answered handshakes no longer restart, the budget bounds both attempts, the probe tests are deterministic](docs/handoffs/2026-09-24-mcp-protocol-engineer-to-security-reviewer-T0.39.review.md) |
| 2026-09-24 | mcp-protocol-engineer | security-reviewer | T0.39 | [T0.39 and T0.25 are in PR #77: 5 s probe bound, one restart with initialize only, exit status at startup](docs/handoffs/2026-09-24-mcp-protocol-engineer-to-security-reviewer-T0.39.md) |
| 2026-09-24 | docs-writer | mcp-protocol-engineer | T0.39 | [T0.39's decision record is proposed in PR #74; the code waits on its acceptance](docs/handoffs/2026-09-24-docs-writer-to-mcp-protocol-engineer-T0.39.md) |

## How to update

Edit `docs/milestones/M0.yaml` (task `state`, `blocked_by`, blockers), write a note in `docs/handoffs/` when you hand work on, then `make status`. Never edit this file by hand. Full protocol: [docs/handoffs/README.md](docs/handoffs/README.md).
