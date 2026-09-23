# ADR 0011: Accept go-sdk v1.7.0 and its transitive modules

- Status: proposed
- Date: 2026-09-23
- Deciders: Josh Scott (maintainer; acceptance pending)

## Context

M0 needs `github.com/modelcontextprotocol/go-sdk v1.7.0` for the proxy transport ([ADR 0001](0001-go-core-with-python-companion.md), [ADR 0008](0008-dual-era-mcp-support.md)). Before T0.1, `go.mod` had one dependency, `github.com/goccy/go-yaml`, and the repo rule is no new dependency without an ADR ([CLAUDE.md](../../CLAUDE.md#toolchain-facts)). ADR 0001 chose go-sdk but did not record the modules it brings with it. This record does.

go-sdk v1.7.0 declares `go 1.25.0`, so `go.mod` moves from `go 1.24` to `go 1.25.0`. T0.1 (branch `build/go-1.25-go-sdk`) adds the SDK as a direct require. The `mcp` package build graph adds eight indirect modules, and `go.sum` also records three modules used only by go-sdk's own tests. The table below lists them all, checked against `go.mod` and `go.sum` at commit `0a17503`.

| Module | Version | In | Why (`go mod why -m`, shortest path from `go-sdk/mcp`) |
| --- | --- | --- | --- |
| `github.com/google/jsonschema-go` | `v0.4.3` | `go.mod` indirect | `mcp` → `jsonschema-go/jsonschema` (tool input and output schemas) |
| `github.com/segmentio/encoding` | `v0.5.4` | `go.mod` indirect | `mcp` → `go-sdk/internal/json` → `segmentio/encoding/json` |
| `github.com/segmentio/asm` | `v1.1.3` | `go.mod` indirect | `segmentio/encoding/json` → `segmentio/asm/base64` |
| `github.com/yosida95/uritemplate/v3` | `v3.0.2` | `go.mod` indirect | `mcp` → `uritemplate/v3` (resource templates) |
| `golang.org/x/oauth2` | `v0.35.0` | `go.mod` indirect | `mcp` → `golang.org/x/oauth2` (Streamable HTTP client, `mcp/streamable.go`) |
| `golang.org/x/sync` | `v0.20.0` | `go.mod` indirect | `mcp` → `golang.org/x/sync/errgroup` |
| `golang.org/x/sys` | `v0.41.0` | `go.mod` indirect | `segmentio/asm/cpu/x86` → `golang.org/x/sys/cpu` |
| `golang.org/x/time` | `v0.15.0` | `go.mod` indirect | `mcp` → `golang.org/x/time/rate` (log rate limiting, `mcp/logging.go`) |
| `github.com/golang-jwt/jwt/v5` | `v5.3.1` | `go.sum` only | `go-sdk/oauthex.test` (go-sdk tests only) |
| `github.com/google/go-cmp` | `v0.7.0` | `go.sum` only | `go-sdk/mcp.test` (go-sdk tests only) |
| `golang.org/x/tools` | `v0.42.0` | `go.sum` only | `go-sdk/mcp.test` → `golang.org/x/tools/txtar` (go-sdk tests only) |

## Decision

We will accept go-sdk v1.7.0 and the eleven modules above as they are, and hold them in place with four guardrails.

1. **No cgo.** `CGO_ENABLED=0` builds of `go-sdk/mcp` and `./internal/tools` (`-tags tools`) succeed for `linux/amd64`, `linux/arm64`, `darwin/arm64` and `windows/amd64`. Verified 2026-09-23 with `go1.26.7` against the Go 1.25.0 module floor. A module that breaks this property is a regression, and fixing it needs a new ADR.
2. **Recorded justification.** The "Why" column above is the `go mod why -m` output. Any PR that adds or removes a module in `go.mod` updates this table or supersedes this record.
3. **Update watch.** `.github/dependabot.yml` already watches `gomod` weekly and groups all modules under `go-deps`. The transitive modules are covered with no config change. A go-sdk minor bump is still its own PR (CLAUDE.md).
4. **Vulnerability scan.** `govulncheck ./...` belongs in CI as a follow-up. This record does not add it.

## Consequences

### Positive

- The proxy gets a maintained transport for both protocol eras, including `CommandTransport` and `InputRequiredResult`, with no hand-written JSON-RPC layer.
- Every module is pure Go and cross-compiles without cgo, so the single-static-binary property holds.
- Each module has a named reason to be there. A later audit can compare `go.mod` against the table above.

### Negative

- Supply-chain surface grows from one third-party module (`goccy/go-yaml`) to ten in the build graph: go-yaml, go-sdk and eight indirect modules. Four come from `golang.org/x`, maintained by the Go team. Four come from single-vendor or single-maintainer projects (`google/jsonschema-go`, `segmentio/encoding`, `segmentio/asm`, `yosida95/uritemplate`). Mitigated by guardrails 2 to 4 and by go.sum checksum verification.
- `golang.org/x/oauth2` is in the build graph although M0 uses stdio only. It is linked only where `internal/proxy` reaches it, and the Go linker drops unreachable code.
- Binary size grows. Measured on `linux/amd64` with `-trimpath -ldflags="-s -w"`: a hello-world binary is 1.59 MB, and a minimal go-sdk stdio server is 6.05 MB. `bin/netguard` today, without go-sdk linked, is 4.78 MB. The proxy will add at most about 4.5 MB, less wherever go-sdk and `netguard` already share standard-library packages (`net/http`, `crypto`). This stays inside ADR 0001's 10 to 20 MB distroless image.
- The toolchain floor rises to Go 1.25. `golangci-lint` in CI moves from v2.1 to v2.4, because v2.1 release binaries are built with Go 1.24 and refuse a module that declares `go 1.25.0`.

### Neutral

- The three test-only modules appear in `go.sum` but never in the build graph of `bin/netguard`.
- Until `internal/proxy` imports go-sdk, `internal/tools/tools.go` (`//go:build tools`) keeps the require in `go.mod`, and `go list -deps ./cmd/netguard` shows no go-sdk.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Hand-roll the MCP transport on the standard library only | Keeps one dependency but makes NetGuard own JSON-RPC framing, the stdio and Streamable HTTP transports, and both protocol eras, and keep them conformant as the spec moves. [ADR 0008](0008-dual-era-mcp-support.md) makes dual-era support a requirement, and the official conformance suite (T0.4) would test our code instead of the SDK's. |
| Vendor a fork of go-sdk trimmed of `golang.org/x/oauth2` and the auth packages | Removes one module and some code, but NetGuard would own a fork and rebase it on every go-sdk release, including security fixes. The Streamable HTTP authorization that M1 and later need would come back anyway. |

## References

- [ADR 0001, Go core with a Python companion](0001-go-core-with-python-companion.md)
- [ADR 0008, Dual-era MCP support](0008-dual-era-mcp-support.md)
- [T0.1 handoff note](../handoffs/2026-09-23-mcp-protocol-engineer-to-go-reviewer-T0.1.md)
- [M0 board](../milestones/M0.yaml), task T0.1 and blocker B2
- [go-sdk v1.7.0 release](https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.7.0)
- [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck)
