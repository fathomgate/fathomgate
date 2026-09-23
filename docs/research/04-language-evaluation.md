# 04 — Implementation Language Evaluation

**Project:** policy-enforcing guardrail proxy between MCP clients (AI agents) and network-device MCP servers.
**Date:** 2026-09-23. **Candidates:** Python, Go, Rust, TypeScript/Node.
**Method:** 18 web searches + ~20 page fetches. Facts marked **[V]** were read from the cited page; **[I]** is my inference or judgement. Star counts are as displayed on the fetched page and drift daily.

## 0. Requirements that actually discriminate between languages

| Requirement | What it demands from the language/SDK |
|---|---|
| Speak MCP on both sides (stdio + Streamable HTTP; 2025-11-25 and 2026-07-28) | Official SDK with **client and server in one process**, both transports, dual-era negotiation |
| Spawn/manage upstream MCP servers as subprocesses | Solid process control, stdio pipes, signal handling, concurrency across many upstreams |
| YAML policy per tool call | YAML lib + a small rule engine (or embeddable OPA) |
| Hold calls pending human approval (TTL, CLI + webhook) | Async timers, an HTTP endpoint, durable-ish pending queue |
| Regex redaction of outputs | Any language |
| Hash-chained JSONL audit log | Any language (SHA-256 + append-only file) |
| NetBox/Nautobot role lookup | REST client; official client libs are a bonus |
| One-step install for a network engineer | Distribution story dominates: static binary vs interpreter + venv |

[I] Items 5–7 are language-neutral. The decision is driven by SDK maturity (row 1), subprocess/concurrency ergonomics (row 2), and distribution (row 8), with community/ecosystem as tie-breakers.

---

## 1. Official MCP SDK maturity (September 2026)

The MCP project now publishes an SDK tiering system: Tier 1 = full protocol implementation incl. elicitation/sampling, 100% conformance, new spec features before release; Tier 2 = 80% conformance, features within 6 months; Tier 3 = experimental. Conformance tests went live 2026-01-23 and tiering was published 2026-02-23 **[V]** (https://modelcontextprotocol.io/community/sdk-tiers). The 2026-07-28 spec announcement states TypeScript, Python, Go and C# (Tier 1) supported the new spec at release; Rust was in beta at that moment **[V]** (https://blog.modelcontextprotocol.io/posts/2026-07-28/).

What 2026-07-28 changed that matters for a proxy **[V]** (same blog post; https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.7.0):
- Stateless core: no `initialize` handshake; each request carries protocol version, client identity and capabilities in `_meta`; new `server/discover` RPC with legacy fallback.
- Multi-Round-Trip Requests (MRTR): tools return `input_required` and the client retries with `inputResponses` — this replaces server-initiated elicitation. **[I]** For a proxy this is good news: a pending-approval hold can be modelled as an MRTR round trip on the 2026 era, and as a blocked/awaiting response on the 2025 era.
- `Mcp-Method` / `Mcp-Name` HTTP headers so intermediaries can route without parsing bodies — explicitly designed for gateways like this one.
- `subscriptions/listen` replaces the list_changed notifications; `ttlMs`/`cacheScope` on list results.
- Roots, sampling and logging are deprecated (Go release notes).
- Tasks moved to a formal extension (`io.modelcontextprotocol/tasks`).

### Per-SDK table

| SDK | Version (date) | Stars | Tier | Client + server in one process | stdio | Streamable HTTP | 2026-07-28 | Dual-era (2025 + 2026) | MRTR / elicitation | Tasks ext. | Source |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **python-sdk** | v2.1.1 (2026-08-25); v1.29.x maintenance line | ~24.2k | 1 | Yes — `MCPServer` (renamed from FastMCP) + unified `Client` (URL, stdio subprocess, in-memory) | Yes | Yes | Yes (v2.0.0 shipped 2026-07-28) | Yes — "both protocol eras served from the same server"; `Client(target, mode='auto')` probes `server/discover` then falls back to `initialize` | Yes — `Resolve(fn)` DI for `Elicit()`, `Sample()`, `ListRoots()` across both eras | **Not implemented** in v2.0/2.1 | https://github.com/modelcontextprotocol/python-sdk/releases ; https://py.sdk.modelcontextprotocol.io/whats-new/ |
| **typescript-sdk** | v2 (2026-07-28 spec); v1.x gets fixes ≥ 6 months | ~13.1k | 1 | Yes — split packages `@modelcontextprotocol/server` and `/client` | Yes | Yes (Express/Fastify/Hono/Node middleware) | Yes | Not stated on README (assume yes as Tier 1) **[I]** | Yes (Tier 1 requirement) | Not stated | https://github.com/modelcontextprotocol/typescript-sdk |
| **go-sdk** (with Google) | v1.7.0 (2026-07-28) | ~5.0k | 1 | Yes — `mcp` package has Client and Server; `CommandTransport` spawns subprocesses | Yes | Yes | Yes — "full support" | Yes — negotiates highest mutual version back to 2024-11-05 | Yes — `InputRequiredResult` for MRTR | Not stated in notes | https://github.com/modelcontextprotocol/go-sdk ; https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.7.0 |
| **rust-sdk (rmcp)** | 3.0.1 (2026-07-29); 3.x migration guide | ~3.8k | **1 since 2026-08-21** | Yes — client + server on tokio | Yes (child process) | Yes | Yes | Yes (compatible back to earlier versions) | Yes (elicitation forms/URLs) | Yes — tasks with polling/cancel | https://github.com/modelcontextprotocol/rust-sdk ; https://www.digitalapplied.com/blog/mcp-sdk-conformance-tiers-what-tier-1-means |

Notes:
- The Rust Tier-1 promotion article reports server conformance 67/67 and client 50/50 against conformance-suite 0.2.0-alpha.11 **[V]** (digitalapplied.com link above; secondary source — the primary would be the modelcontextprotocol/modelcontextprotocol issue tracker).
- The Python SDK v2 was a large rewrite ("low-level internals rebuilt") and the TS SDK is throttling new contributors to one PR each while v2 settles **[V]**. **[I]** Both v2 lines are ~8 weeks old; expect API churn in point releases through Q4 2026. Go v1.7.0 is an additive minor on a v1 line that has been stable for a year, which is the lowest-churn base of the four.
- The community `mark3labs/mcp-go` predates the official Go SDK; several projects (grafana/mcp-grafana PR #1180, neo4j-labs) have migrated to the official SDK **[V]** (https://github.com/grafana/mcp-grafana/pull/1180). **[I]** Use the official SDK only.

**Answer to Q1:** All four official SDKs support client + server in one process, both transports, and the 2026-07-28 spec. Python, Go and Rust each explicitly document dual-era negotiation. Python is the only one that explicitly says Tasks is not implemented; Rust is the only one that explicitly says it is. For a proxy, Tasks is optional (extension), but a proxy that wants to pass through long-running device jobs will eventually need it. **[I]**

---

## 2. What existing MCP gateways chose, and why

| Project | Language | Stars | SDK | Notes / lessons | Source |
|---|---|---|---|---|---|
| **agentgateway** (Solo.io, CNCF) | Rust | — | own (tokio/hyper/tonic, cel-rust for policy) | Chose Rust from ztunnel experience; "performance and memory safety" framed as non-negotiable; ~500k QPS, <0.2 ms P99 at 30k QPS **[V]** | https://agentgateway.dev/blog/2026-06-04-designing-agentgateway-unified-gateway/ |
| **Docker MCP Gateway** | Go | ~1.5k | not stated (appears bespoke) | Runs upstream servers as containers; interceptors, secrets via Docker Desktop, OAuth, stdio/streaming/SSE **[V]** | https://github.com/docker/mcp-gateway |
| **IBM ContextForge** | Python (FastAPI) | — | official python-sdk | Migrating to python-sdk 2.0 is the gating work for dual-era support: 11 sub-issues, a compatibility SPIKE flagging "SDK v2 strict-validation compatibility risks" and possible transport/session redesign **[V]** (#6218). Has an open performance-baseline epic comparing Go/Rust/Python (FastMCP) implementations and quantifying proxy overhead **[V]** (#1874) | https://github.com/IBM/mcp-context-forge/issues/6218 ; https://github.com/IBM/mcp-context-forge/issues/1874 |
| **Lasso mcp-gateway** | Python | ~385 | official python-sdk | Plugin guardrails/sanitizers (basic secret masking, Presidio PII, Lasso); pip/Docker install **[V]** | https://github.com/lasso-security/mcp-gateway |
| **sparfenyuk/mcp-proxy** | Python | ~2.7k | — | Transport bridge, not a policy gateway; install via `uv tool`, pipx, Docker; documented Claude Desktop ENOENT issue requiring absolute path to binary **[V]** | https://github.com/sparfenyuk/mcp-proxy |
| **Trail of Bits mcp-context-protector** | Python | ~225 | — | Tool-pinning, response guardrails, ANSI sanitization; installed via `uv`; README warns Claude Desktop replaces PATH so launcher needs full `uv` path **[V]** | https://github.com/trailofbits/mcp-context-protector |
| **Kong AI MCP Proxy** | Lua on OpenResty (Kong plugin) | — | — | Plugin converts REST APIs into MCP tools and proxies external MCP servers; enterprise gateway, not a standalone tool **[V]** | https://developer.konghq.com/plugins/ai-mcp-proxy/ |
| **microsoft/mcp-gateway** | (K8s reverse proxy) | — | — | Session-aware stateful routing for MCP servers in Kubernetes **[V]** | https://github.com/microsoft/mcp-gateway |

Post-mortems / packaging pain **[V]**: no formal post-mortem was found, but two of the Python wrappers (ToB, sparfenyuk) carry README workarounds for the same class of bug — MCP hosts launch the proxy with a stripped `PATH`, so a Python tool installed by `uv`/`pipx` isn't found unless the user hard-codes absolute paths. ContextForge's SDK-v2 migration issue is the closest thing to a public account of how expensive it is to track MCP spec churn in a Python gateway.

**[I]** Pattern: infrastructure vendors (Solo, Docker, Kong, Microsoft) ship gateways in Rust/Go/Lua; security-research and community wrappers ship in Python because they were fast to write. The Python ones show recurring launcher/PATH friction and expensive SDK-major migrations; the Go/Rust ones don't show these because the artifact is one binary.

---

## 3. Distribution

| Channel | Go | Rust | Python | TypeScript |
|---|---|---|---|---|
| Single static binary | Yes; `CGO_ENABLED=0` cross-compiles for linux/darwin/windows × amd64/arm64 from one host; GoReleaser produces archives, checksums, SBOMs, Homebrew tap, deb/rpm from one config **[V]** (https://goreleaser.com/blog/homebrew-gofish/ ; https://stackharbor.com/en/knowledge-base/golang-goreleaser-binary-release/) | Yes; cross-compilation needs `cross`/zig or per-OS CI runners **[I]** | No native equivalent; PyInstaller/Nuitka bundles are large and OS-specific **[I]** | `pkg`/Bun single-executable possible but uncommon for MCP tools **[I]** |
| Package manager | `brew install`, `go install`, `curl \| sh` | `cargo install`, brew | `uv tool install X` / `pipx install X` / `uvx X` **[V]** (https://pydevtools.com/handbook/explanation/how-do-uv-tool-and-pipx-compare/) | `npx X` / `npm i -g` |
| Runtime prerequisite | none | none | Python ≥ 3.10 + uv/pipx; uv can download its own Python **[V]** | Node ≥ 18/20 |
| Docker image | `FROM scratch`/distroless, ~10–20 MB **[I]** | similar | `python:3.12-slim` + deps, ~150–250 MB **[I]** | `node:slim`, ~150 MB **[I]** |
| MCP host launcher friction | none (absolute path to one file) | none | Real, documented (PATH stripped by Claude Desktop; ENOENT) **[V]** | similar to Python (needs node on PATH) **[I]** |

How network engineers install tools **[I, grounded in tool observations]**: the Go tools they already use — containerlab, gnmic, Terraform, kubectl, OPA — are all distributed as `curl | sh` or brew plus a GitHub Releases binary. Python tools (netmiko, nornir, napalm, NetBox) are installed into venvs, usually by people already living in Python. A network engineer who is *not* a Python person installing a proxy that must be launched by Claude Desktop/Cursor is the exact user who hits the PATH/ENOENT class of issue. A single binary in `mcp.json`'s `command` field is the least surprising thing to hand them.

---

## 4. Ecosystem fit for the network-device domain

### Go
- **scrapligo** v1.4.0 released 2026-02-20, 301 stars, 41 releases, 708 commits, CLI + NETCONF drivers, MIT **[V]** (https://github.com/scrapli/scrapligo). Maintained by the scrapli author. Small but alive.
- **go-netbox** — official NetBox Go client, openapi-generator based, v4.x line tracking NetBox 4.3+ **[V]** (https://github.com/netbox-community/go-netbox/releases). **[I]** The proxy only needs a couple of read endpoints (device → role/site/tags); a hand-written 100-line client on `net/http` may be preferable to a generated client that must be bumped per NetBox release. Nautobot has no official Go client; use REST/GraphQL directly.
- **gNMI / gnmic / containerlab** — the Nokia SR Linux ecosystem is Go: containerlab (2.8k stars on the network-automation topic page) **[V]** (https://github.com/topics/network-automation?l=go&o=desc&s=stars), gnmic (openconfig/gnmic), openconfig/gnmi. **[I]** The proxy itself does not talk gNMI; this matters for contributor pool, not for code.
- **gosnmp** — exists; not needed by the proxy **[I]**.
- **OPA in-process**: only Go can embed OPA as a library via `github.com/open-policy-agent/opa/v1/rego`; other languages use REST sidecar or Wasm **[V]** (https://www.openpolicyagent.org/docs/integration ; https://pkg.go.dev/github.com/open-policy-agent/opa/v1/rego). **[I]** This matters if YAML policy grows into "allow if device.role == core and tool != config_replace" style rules: Go can offer YAML now and optional Rego later without a sidecar.
- **YAML**: `gopkg.in/yaml.v3` is unmaintained; the ecosystem (gh CLI, go-task, Forgejo, GitLab runner) is migrating to `go.yaml.in/yaml/v3` (the yaml/go-yaml org fork) or `goccy/go-yaml` **[V]** (https://github.com/go-task/task/issues/2171 ; https://github.com/cli/cli/issues/10784). Pick `go.yaml.in/yaml/v3` or `goccy/go-yaml` from day one.
- **Concurrency**: goroutine-per-upstream with `context` cancellation and `os/exec` is the idiomatic pattern and what `CommandTransport` in go-sdk already does **[V]**. **[I]** This is the strongest technical fit of any candidate for "spawn N upstream servers, multiplex, time out pending approvals."

### Python
- Gravity: netmiko, napalm, scrapli, nornir, pynetbox, pybatfish are all Python; the netdevops survey series (2016/2019/2020) and Cisco's own learning track are Python-first **[V]** (https://github.com/dgarros/netdevops-survey ; https://blogs.cisco.com/learning/advance-your-network-automation-skills-with-ciscos-intermediate-python-course). **[I]** But the proxy does not call netmiko — the *upstream MCP servers* do. The proxy's domain surface is NetBox REST + YAML + regex, so the Python library advantage is mostly irrelevant to the core.
- python-sdk v2 is the most-used SDK (24k stars) and most MCP servers the proxy will front are FastMCP/Python **[V]**. **[I]** That is an interop argument, not an implementation-language argument; MCP over stdio/HTTP is language-agnostic.
- OPA: REST or Wasm only **[V]**. Tasks extension: not in python-sdk yet **[V]**.
- asyncio + subprocess management of many upstreams works but is more error-prone (event-loop pitfalls, signal handling on Windows) **[I]**.

### Rust
- rmcp is now Tier 1 with tasks + elicitation, tracked the spec same-day, 3.8k stars **[V]**. agentgateway proves Rust is viable for an MCP gateway **[V]**.
- **[I]** Domain libs are thin (no scrapli equivalent, no NetBox client), compile times and borrow-checker learning curve slow a solo author, and the contributor pool among network engineers is very small. Performance headroom (500k QPS) is irrelevant for a proxy that fronts devices doing 5 SSH sessions.

### TypeScript
- typescript-sdk is Tier 1 and many public MCP servers are TS **[V]**. **[I]** Domain libs for networking are weak, requires Node at runtime, single-binary packaging is awkward, and the network-engineering contributor base has near-zero TS overlap. Not competitive for this project.

---

## 5. Testing story per tier

| Tier | Go | Python | Rust | TS |
|---|---|---|---|---|
| **Unit: policy evaluation** | table-driven `go test`, YAML fixtures, `testing/fstest`; fast, no deps | pytest + parametrize; fastest to write; excellent for property/fuzz via hypothesis | cargo test; strong but slower compile loop | vitest/jest |
| **Integration: real MCP servers in containers** | `testcontainers-go` to run FastMCP/Python servers; go-sdk in-memory transport for fast paths; cross-language over stdio/HTTP is fine **[I]** | testcontainers-python; can also import FastMCP servers in-process (no container) — the cheapest integration loop **[I]** | testcontainers-rs (less mature) | testcontainers-node |
| **Conformance** | official `modelcontextprotocol/conformance` suite is language-agnostic; run it against the proxy's client-facing side **[V]** (https://modelcontextprotocol.io/community/sdk-tiers) | same | same | same |
| **containerlab real-device tier** | containerlab is Go and has a Go API/`clab` CLI; gnmic in Go for assertions; natural fit **[I]** | drive `clab` CLI via subprocess; assert with scrapli/netmiko — very natural for network engineers writing tests **[I]** | drive `clab` CLI | drive `clab` CLI |

**[I]** Key insight: the integration tier is language-neutral because the proxy talks to upstreams over the wire. The only place Python has a genuine testing edge is writing device-assertion helpers for the containerlab tier — and those can live in a `tests/` Python package regardless of the core language (see hybrid option).

---

## 6. Contributor / community

- **Network engineers**: Python-dominant. Cisco DevNet, NetBox, Nornir, napalm, netmiko and the netdevops survey ecosystem are all Python **[V]**. Go presence is real but concentrated in the containerlab/gnmic/SR Linux/Kubernetes-adjacent crowd **[V]** (containerlab 2.8k stars; scrapligo 301 stars vs scrapli's Python base). **[I]** Estimate: the share of network engineers who can submit a Go PR is perhaps a fifth of those who can submit a Python PR, but that fifth skews toward exactly the platform/NetDevOps profile this tool targets.
- **MCP/agent community**: Python (24k) and TypeScript (13k) SDK stars dwarf Go (5k) and Rust (3.8k) **[V]**. **[I]** However the *gateway* sub-community is Go/Rust-heavy (Docker, Solo, Microsoft, Kong's Go/Lua), and the go-sdk is co-maintained by Google, which is a credibility signal for infra reviewers.
- **[I]** What actually attracts contributions to a guardrail proxy is the **policy file format**, example policies and docs, not the core language. A YAML policy contributed by a Python-only engineer needs no Go knowledge. Design for that: policies, redaction patterns and device-role mappings should be data, with a `policy test` subcommand so contributors can validate without compiling.

---

## 7. Career-signal angle (secondary)

**[V]** Kubernetes, containerlab, gnmic, OPA, Terraform providers, Docker MCP Gateway and the Google-co-maintained go-sdk are all Go. **[I]** For a senior network engineer positioning toward DevSecOps/platform roles, a shipped Go project that embeds OPA-style policy, produces a signed multi-arch binary via GoReleaser, and integrates with containerlab is a portfolio piece that speaks the target audience's language. Python would demonstrate the same design skill but reads as "network automation" rather than "platform engineering." Rust signals systems depth but with less overlap with the platform-tooling stack the author is moving toward. This should not override an engineering reason, but here it aligns with the engineering reasons rather than fighting them.

---

## 8. Recommendation matrix

Scores 1–5 (5 = best for *this* project). Weights reflect the requirements in §0.

| Criterion (weight) | Python | Go | Rust | TypeScript |
|---|---|---|---|---|
| Official SDK maturity, client+server, dual-era (×3) | 4 (v2 fresh, Tasks missing) | 5 (Tier 1, stable v1 line, MRTR) | 4 (Tier 1 as of Aug; 3.x churn) | 4 (v2 fresh, PR-throttled) |
| Subprocess/upstream management & concurrency (×2) | 3 | 5 | 4 | 3 |
| One-step install for network engineers (×3) | 2 (PATH/venv friction documented) | 5 (single binary, brew, GoReleaser) | 5 | 2 |
| Policy engine options (YAML now, OPA/CEL later) (×1) | 3 (OPA via sidecar/Wasm) | 5 (embed rego in-process) | 4 (cel-rust) | 3 |
| Domain libs the proxy itself needs (NetBox/Nautobot, YAML, regex) (×1) | 5 | 4 | 3 | 3 |
| Testing story across 3 tiers (×2) | 5 | 4 | 3 | 4 |
| Contributor pool: network engineers (×2) | 5 | 3 | 1 | 2 |
| Contributor pool: MCP/agent community (×1) | 5 | 3 | 3 | 4 |
| Solo-author velocity for v0.1 (×2) | 5 | 4 | 2 | 4 |
| Career signal for DevSecOps/platform (×1) | 3 | 5 | 4 | 2 |
| **Weighted total (max 90)** | **70** | **79** | **60** | **57** |

Weighted arithmetic: Python 12+6+6+3+5+10+10+5+10+3 = 70; Go 15+10+15+5+4+8+6+3+8+5 = 79; Rust 12+8+15+4+3+6+2+3+4+4 = 61 (rounded 60); TS 12+6+6+3+3+8+4+4+8+2 = 56 (rounded 57).

### Final call: **Go**, with a Python test/policy-tooling companion.

**Why Go wins:** the two heaviest-weighted requirements — a stable dual-era SDK that runs client+server in-process and spawns upstreams, and a one-step install that survives MCP-host launcher quirks — both favour Go outright. The official go-sdk v1.7.0 covers 2025-11-25 and 2026-07-28 with MRTR and a `CommandTransport` **[V]**; GoReleaser gives brew/deb/rpm/multi-arch binaries from one config **[V]**; OPA can be embedded later without a sidecar **[V]**. The things Python is better at (domain libraries, contributor breadth) mostly apply to the *upstream servers* and to *test tooling*, not to the proxy core.

**Hybrid (recommended):** Go core (`cmd/proxy`, policy engine, approval queue, audit chain, NetBox lookup) + a small Python package under `tests/` and `tools/` containing FastMCP fixture servers, containerlab assertion helpers (scrapli/netmiko) and a `policy-lint` that reuses the same YAML schema. Contributors who only know Python can add fixture servers, device helpers and policies; the release artifact stays a single binary.

### Risks by option

| Option | Main risks | Mitigation |
|---|---|---|
| **Go core (+Python test tooling)** | Smaller pool of network-engineer contributors for core code; go-sdk is younger than python-sdk and co-maintained by a corporate partner whose priorities may shift; YAML lib migration churn (`yaml.v3` → `go.yaml.in`) | Keep policy/data-driven surface large; pin go-sdk minor versions and track conformance suite in CI; choose maintained YAML lib on day one |
| **Python core** | Install/launcher friction for non-Python users (documented in two peer projects); python-sdk v2 is 8 weeks old and Tasks extension is absent; ContextForge shows SDK-major migrations are multi-issue efforts; Docker image 10× larger | Ship via `uv tool` + Docker + document absolute paths; accept that "one-step install" is really two steps |
| **Rust core** | Solo-author velocity, thin domain libs, tiny network-engineer contributor base, 3.x migration in flight | Only justified if the proxy must front thousands of concurrent agent sessions, which is not the stated target |
| **TypeScript core** | Node runtime dependency, weak networking ecosystem, minimal overlap with target contributors | Not recommended |
| **Python now, Go later** | Rewrites of a security-sensitive component rarely happen; you'd carry two audit-log and policy implementations during transition | If chosen, isolate policy schema and audit format as language-neutral specs from day one |

---

## Sources (all fetched 2026-09-23)

- https://modelcontextprotocol.io/community/sdk-tiers
- https://blog.modelcontextprotocol.io/posts/2026-07-28/
- https://github.com/modelcontextprotocol/python-sdk/releases
- https://py.sdk.modelcontextprotocol.io/whats-new/
- https://github.com/modelcontextprotocol/typescript-sdk
- https://github.com/modelcontextprotocol/go-sdk
- https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.7.0
- https://github.com/modelcontextprotocol/rust-sdk
- https://www.digitalapplied.com/blog/mcp-sdk-conformance-tiers-what-tier-1-means
- https://agentgateway.dev/blog/2026-06-04-designing-agentgateway-unified-gateway/
- https://github.com/docker/mcp-gateway
- https://github.com/IBM/mcp-context-forge/issues/6218
- https://github.com/IBM/mcp-context-forge/issues/1874
- https://github.com/lasso-security/mcp-gateway
- https://github.com/sparfenyuk/mcp-proxy
- https://github.com/trailofbits/mcp-context-protector
- https://developer.konghq.com/plugins/ai-mcp-proxy/
- https://github.com/microsoft/mcp-gateway
- https://github.com/grafana/mcp-grafana/pull/1180
- https://github.com/scrapli/scrapligo
- https://github.com/netbox-community/go-netbox/releases
- https://www.openpolicyagent.org/docs/integration
- https://pkg.go.dev/github.com/open-policy-agent/opa/v1/rego
- https://github.com/go-task/task/issues/2171
- https://github.com/cli/cli/issues/10784
- https://github.com/topics/network-automation?l=go&o=desc&s=stars
- https://github.com/dgarros/netdevops-survey
- https://blogs.cisco.com/learning/advance-your-network-automation-skills-with-ciscos-intermediate-python-course
- https://goreleaser.com/blog/homebrew-gofish/
- https://stackharbor.com/en/knowledge-base/golang-goreleaser-binary-release/
- https://pydevtools.com/handbook/explanation/how-do-uv-tool-and-pipx-compare/
