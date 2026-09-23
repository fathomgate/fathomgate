# ADR 0001: Go core with a Python companion

- Status: accepted
- Date: 2026-09-23
- Deciders: Josh Scott

## Context

The proxy must speak MCP on both sides (stdio and Streamable HTTP, 2025-11-25 and 2026-07-28 eras), spawn and manage upstream MCP servers as subprocesses, hold calls for approval with TTLs, and install in one step for a network engineer whose MCP host launches it. Python, Go, Rust and TypeScript were scored against those requirements in [research brief 04](../research/04-language-evaluation.md).

Two requirements discriminate most. First, the go-sdk v1.7.0 (2026-07-28) is an additive minor on a v1 line stable for a year, with `CommandTransport` for subprocesses and `InputRequiredResult` for MRTR. The python-sdk v2 and typescript-sdk v2 were about eight weeks old at decision time and showed churn. Second, two Python peer projects (sparfenyuk/mcp-proxy, Trail of Bits mcp-context-protector) document Claude Desktop stripping `PATH` and failing with ENOENT; a single static binary has no such failure.

Python is better at domain libraries (netmiko, napalm, pynetbox) and has the widest contributor base among network engineers. Those advantages apply to upstream servers and test tooling, not to the proxy core, which only needs YAML, regex, HTTP and SQLite.

## Decision

We will write the proxy core in Go using the official `github.com/modelcontextprotocol/go-sdk`, released as a single static binary through GoReleaser, and keep a Python package under `tests/` and `tools/` for FastMCP fixture servers, fake SSH devices, containerlab assertion helpers and `policy-lint`.

The weighted score was Go 79, Python 70, Rust 60, TypeScript 57 out of 90. Go is also the only language that embeds OPA in-process, which keeps the optional Rego backend ([ADR 0003](0003-yaml-policy-dsl-with-obligations.md)) free of a sidecar.

## Consequences

### Positive

- One binary in the `command` field of `mcp.json`; no interpreter, venv or `PATH` dependency.
- Goroutine-per-upstream with `context` cancellation is the idiomatic pattern for multiplexing many upstreams and timing out pending approvals.
- Distroless Docker image of 10 to 20 MB.
- Contributors who only know Python can still add fixture servers, device assertions, profiles, policies and redaction patterns.

### Negative

- Smaller Go contributor pool for core code. Mitigated by keeping profiles, policies, redaction patterns and role mappings as data with a `netguard policy test` subcommand.
- go-sdk is younger than python-sdk. Mitigated by pinning minor versions and running the official conformance suite in CI.
- `gopkg.in/yaml.v3` is unmaintained. Use `go.yaml.in/yaml/v3` or `goccy/go-yaml` from day one.
- go-sdk v1.7 requires Go 1.25 (netdev-ssh-mcp, on the same SDK, requires Go 1.26). See [ROADMAP.md](../../ROADMAP.md).

### Neutral

- The Python companion has its own `pyproject.toml` and is not published to PyPI in v1.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Python core | Documented launcher friction; python-sdk v2 churn; ContextForge's SDK v2 migration ([issue #6218](https://github.com/IBM/mcp-context-forge/issues/6218)) shows the cost of tracking spec changes in a Python gateway; Docker image ten times larger. |
| Rust core | Solo-author velocity, thin domain libraries, near-zero network-engineer contributor base. Performance headroom is irrelevant for a proxy fronting a handful of SSH sessions. |
| TypeScript core | Node runtime dependency, weak networking ecosystem, minimal overlap with target contributors. |
| Python now, Go later | Security components rarely get rewritten; two audit and policy implementations during transition. |

## References

- [Research brief 04, language evaluation](../research/04-language-evaluation.md)
- [go-sdk v1.7.0 release](https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.7.0)
- [MCP SDK tiers](https://modelcontextprotocol.io/community/sdk-tiers)
- [sparfenyuk/mcp-proxy](https://github.com/sparfenyuk/mcp-proxy) and [Trail of Bits mcp-context-protector](https://github.com/trailofbits/mcp-context-protector), PATH workarounds
- [GoReleaser](https://goreleaser.com/blog/homebrew-gofish/)
- [OPA Go rego package](https://pkg.go.dev/github.com/open-policy-agent/opa/v1/rego)
- [yaml.v3 migration discussion](https://github.com/go-task/task/issues/2171)
