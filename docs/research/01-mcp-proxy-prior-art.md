# Prior Art: Policy-Enforcing Guardrail Proxies for Network-Device MCP Servers

Research brief, compiled 22–23 September 2026. Sources were fetched live; star counts and activity are approximate snapshots as of that date.

Legend: **[V]** = verified against the cited URL. **[I]** = inference / my own analysis, not directly stated by a source.

---

## 1. MCP protocol essentials relevant to a proxy

### 1.1 Spec version timeline **[V]**

| Revision | Key changes for a proxy | Source |
|---|---|---|
| 2024-11-05 | Original; HTTP+SSE transport | https://modelcontextprotocol.io/specification/2024-11-05 |
| 2025-03-26 | Streamable HTTP introduced; HTTP+SSE deprecated; tool annotations added | https://modelcontextprotocol.io/specification/2025-03-26 |
| 2025-06-18 | Elicitation added (form mode); structured tool output; JSON-RPC batching removed; `MCP-Protocol-Version` header required on HTTP; resource links | https://modelcontextprotocol.io/specification/2025-06-18/changelog |
| 2025-11-25 | URL-mode elicitation; sampling gains `tools`/`toolChoice`; experimental Tasks; icons; tool-name guidance; JSON Schema 2020-12 default; SSE polling clarifications | https://modelcontextprotocol.io/specification/2025-11-25/changelog |
| **2026-07-28 (current)** | Stateless core: `initialize`/`initialized` handshake and `Mcp-Session-Id` removed; every request carries version + client capabilities in `_meta`; new `server/discover` RPC; MRTR replaces server-initiated elicitation/sampling; `Mcp-Method`/`Mcp-Name` headers required; `resultType` required on results; `ttlMs`/`cacheScope` on list results; Tasks moved to an extension; Roots/Sampling/Logging deprecated; SSE resumability (`Last-Event-ID`) removed; formal 12-month deprecation lifecycle | https://modelcontextprotocol.io/specification/2026-07-28/changelog and https://blog.modelcontextprotocol.io/posts/2026-07-28/ |

The 2026-07-28 changelog compares against 2025-11-25 and lists these as the major items (SEP-2567, SEP-2575, SEP-2322, SEP-2243, SEP-2549, SEP-2596). **[V]**

**Implication for a proxy [I]:** Any proxy built today must speak two "eras": legacy stateful (initialize handshake, sessions, server-initiated requests on SSE) for 2025-xx clients/servers, and the stateless 2026-07-28 shape. The spec's Streamable HTTP page describes a fallback strategy for detecting which era a peer implements (https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#backward-compatibility). **[V]** The Python SDK v2 claims support for 2026-07-28 and every earlier revision (https://github.com/modelcontextprotocol/python-sdk). **[V]**

### 1.2 JSON-RPC message types **[V]**

- `initialize` / `notifications/initialized`: the lifecycle handshake in 2024-11-05 through 2025-11-25. **Removed in 2026-07-28**; replaced by per-request `_meta` fields (`io.modelcontextprotocol/protocolVersion`, `clientInfo`, `clientCapabilities`) plus an optional `server/discover` call. Source: https://modelcontextprotocol.io/specification/2026-07-28/changelog
- `tools/list`: paginated via `cursor`; in 2026-07-28 the result must include `ttlMs` and `cacheScope` and servers SHOULD return deterministic ordering; the set MUST NOT vary per-connection but MAY vary by the authorization presented. Source: https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- `tools/call`: `params.name`, `params.arguments`; result has `content[]`, optional `structuredContent`, `isError`; in 2026-07-28 also `resultType: "complete" | "input_required"`. Same URL.
- `notifications/tools/list_changed`: emitted when the tool set changes if server declared `tools.listChanged`. In 2026-07-28 it is only delivered on a `subscriptions/listen` response stream that opted in with `toolsListChanged: true`. Same URL.
- Error split: protocol errors (JSON-RPC `error`, e.g. `-32602` unknown tool) vs tool-execution errors (`isError: true` in `result`), the latter intended for model self-correction. Same URL.
- Tool-name collisions across aggregated servers: the spec explicitly says proxies that aggregate multiple servers SHOULD disambiguate, e.g. by prefixing with a server identifier, and that `serverInfo.name` is not unique. Same URL. **[V]**

### 1.3 Transports **[V]**

- **stdio**: still first-class. The only client-to-server notification in the 2026-07-28 core (`notifications/cancelled`) is stdio-only; on HTTP, closing the response stream is the cancellation signal. https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- **Streamable HTTP** (since 2025-03-26): single POST endpoint; each JSON-RPC message is its own POST; server replies with `application/json` or a request-scoped `text/event-stream`. In 2026-07-28: no GET stream, no sessions, no `Last-Event-ID`; long-lived change notifications come from a `subscriptions/listen` POST whose SSE response stays open. Required headers on every POST: `MCP-Protocol-Version`, `Mcp-Method`, and `Mcp-Name` (for `tools/call`, `resources/read`, `prompts/get`). Servers MUST reject header/body mismatch with HTTP 400 and JSON-RPC `-32020 HeaderMismatch`. Tool params can be mirrored to `Mcp-Param-{Name}` headers via `x-mcp-header` in the input schema. Same URL.
- **HTTP+SSE (2024-11-05)**: deprecated since 2025-03-26, formally classed Deprecated under the new feature lifecycle (SEP-2596), eligible for removal after a 12-month window. Same URL and https://modelcontextprotocol.io/specification/2026-07-28/changelog
- Intermediary guidance in the spec: a proxy that enforces policy on mirrored headers SHOULD verify the protocol version requires header–body validation, and reject if the version is older. Same transport URL. **[V]**

**Implication [I]:** The `Mcp-Method`/`Mcp-Name` headers make L7 routing and coarse tool allow/deny possible without body parsing, but a guardrail that inspects *arguments* (device target, CLI text, config payload) still needs the body. Also, because tool names can be Base64-sentinel encoded in headers, the proxy must decode before comparing.

### 1.4 Elicitation (human-in-the-loop) **[V]**

- Added in 2025-06-18 (PR #382) as a server-initiated `elicitation/create` request over the open stream. https://modelcontextprotocol.io/specification/2025-06-18/changelog
- 2025-11-25 added URL mode (SEP-1036) and richer enum schemas (SEP-1330). https://modelcontextprotocol.io/specification/2025-11-25/changelog
- 2026-07-28 reshaped it under **MRTR** (SEP-2322): the server returns a result with `resultType: "input_required"`, an `inputRequests` map keyed by an arbitrary id, and an opaque `requestState`; the client gathers input and *re-issues the original request* (new JSON-RPC `id`) with `inputResponses` and the echoed `requestState`. Three response actions: `accept`, `decline`, `cancel`. Form mode is limited to flat objects of primitives (string/number/boolean/enum). Clients MUST declare `elicitation: {form:{}, url:{}}` in `_meta.io.modelcontextprotocol/clientCapabilities` on each request; an empty object means form-only. https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation
- Security text relevant to a guardrail: servers MUST NOT use form mode for secrets; clients SHOULD implement user approval controls and make clear which server is asking. Same URL.
- Client support: the spec does not enumerate clients. An AAIF blog (post-2026-07-28) demonstrates MRTR-based HITL approval with a LangGraph client but does not list which production clients implement it. https://aaif.io/blog/non-blocking-human-in-the-loop-agents-re-engineering-agentic-runloops-and-state-machines-with-mr **[V]** — I could not find an authoritative client support matrix. **[I]** Treat client elicitation support as *optional* and design the proxy to fall back (e.g. deny-with-explanation or out-of-band approval) when the client capability is absent.

**Implication [I]:** A proxy can implement approval by intercepting a `tools/call`, returning its own `input_required` with an `elicitation/create` ("Approve `configure` on core-rtr-01? yes/no"), and only forwarding upstream after an `accept`. `requestState` is the natural place to carry a signed snapshot of the pending call. With legacy 2025-xx clients the proxy must instead send a server-initiated `elicitation/create` on the SSE stream. Docker's gateway issue #574 notes that elicitation prompts from upstream servers reach clients *unattributed*, which is an impersonation risk a guardrail proxy should handle by prefixing/annotating origin (https://github.com/docker/mcp-gateway/issues/574). **[V]**

### 1.5 Sampling **[V]**

`sampling/createMessage` let servers ask the client's LLM for completions; 2025-11-25 added tool calling to it. In 2026-07-28 it is deprecated (SEP-2577), with guidance to call LLM APIs directly instead, and any remaining use flows through MRTR rather than server-initiated requests. https://modelcontextprotocol.io/specification/2026-07-28/changelog **[I]** A guardrail proxy should block or at least log upstream sampling attempts; Docker's gateway already blocks `CreateMessage` for trust-boundary reasons (https://github.com/docker/mcp-gateway/issues/574).

### 1.6 Tool annotations **[V]**

From the 2026-07-28 TypeScript schema (https://raw.githubusercontent.com/modelcontextprotocol/modelcontextprotocol/main/schema/2026-07-28/schema.ts):

| Annotation | Type | Default | Meaning |
|---|---|---|---|
| `title` | string | — | display name |
| `readOnlyHint` | boolean | `false` | tool does not modify its environment |
| `destructiveHint` | boolean | `true` | may perform destructive (vs additive) updates; only meaningful if not read-only |
| `idempotentHint` | boolean | `false` | repeated calls with same args have no extra effect |
| `openWorldHint` | boolean | `true` | interacts with external entities |

The spec warns that clients MUST treat annotations as untrusted unless from trusted servers (https://modelcontextprotocol.io/specification/2026-07-28/server/tools). **[V]** **[I]** A guardrail proxy can *use* annotations as one input but must not rely on them; for network devices it should classify by inspecting the actual CLI/config payload.

### 1.7 Official SDKs **[V]**

- Python SDK: https://github.com/modelcontextprotocol/python-sdk, ~24.3k stars, v2 line targets 2026-07-28 and earlier revisions, Python 3.10+, `pip install "mcp[cli]"`. It ships a client: `from mcp import Client`; `async with Client("http://host/mcp") as c: await c.call_tool(name, args)`; it can also spawn a stdio subprocess or accept a custom transport. Client docs: https://py.sdk.modelcontextprotocol.io/client/. The README excerpt did not show a client-side elicitation/input_required handler; check the client docs before relying on it. **[V]/[I]**
- TypeScript SDK: https://github.com/modelcontextprotocol/typescript-sdk (listed as updated for 2026-07-28 in the release blog https://blog.modelcontextprotocol.io/posts/2026-07-28/). Go, C# also updated; Rust in beta. **[V]**
- Conclusion for tests: yes, the Python SDK's `Client` is scriptable for integration tests (list tools, call tools over stdio or HTTP), so a pytest harness can drive proxy → fake upstream end to end. **[V]**

---

## 2. Existing generic MCP proxies / gateways

Star counts are approximate as of 22–23 Sept 2026.

| Project | Repo / docs | Stars | Lang | Tool allow/deny | Audit log | Approval / HITL | Secret redaction | Multi-upstream | Activity | Notes |
|---|---|---|---|---|---|---|---|---|---|---|
| **IBM ContextForge** | https://github.com/IBM/mcp-context-forge | ~4.3k | Python | Yes (RBAC, virtual servers, 40+ plugins incl. guardrails) | Yes (OTel, admin log viewer) | Not documented as a first-class feature | Stored-credential encryption; plugin-based filters | Yes (MCP, A2A, REST/gRPC federation) | 1.0.0-RC-3, ~3.1k commits | Apache-2.0. Heaviest option; Postgres/Redis. **[V]** |
| **Docker MCP Gateway** | https://github.com/docker/mcp-gateway | ~1.5k | Go | Yes but policy is `{catalog, server, tool, action}` only — no argument visibility (issue #574) | Partial (interceptors, OTel) | No | `--block-secrets` regex, post-execution | Yes (catalog, containers) | ~1k commits, active | MIT. Blocks upstream sampling; issue #574 (2026) admits policy is payload-blind. **[V]** https://github.com/docker/mcp-gateway/issues/574 |
| **Lasso mcp-gateway** | https://github.com/lasso-security/mcp-gateway | ~385 | Python | Server-level block via reputation scanner; plugin guardrails | Yes (xetrack → DuckDB/SQLite) | No | Yes (basic + Presidio PII, Lasso cloud) | Yes | ~40 commits | MIT. **[V]** |
| **sparfenyuk/mcp-proxy** | https://github.com/sparfenyuk/mcp-proxy | ~2.7k | Python | No | Log levels only | No | No | Yes (named servers) | v0.12.0 | MIT. Pure transport bridge stdio↔SSE/Streamable HTTP; good reference for transport plumbing, zero policy. **[V]** |
| **Azure API Management** | https://learn.microsoft.com/en-us/azure/api-management/mcp-server-overview | n/a | SaaS | Generic APIM policies (JWT, IP filter, rate limit); Build 2026 added MCP content safety | Yes (APIM tracing) | No | Not MCP-specific | Yes (REST→MCP, proxy existing MCP) | GA; page updated 2026-09-11 | Tools only, no resources/prompts. **[V]** https://www.infoq.com/news/2026/06/azure-apim-ai-gateway-build/ |
| **Kong AI Gateway (`ai-mcp-proxy`)** | https://developer.konghq.com/plugins/ai-mcp-proxy/ | n/a (Kong ~40k+) | Lua/Go | Yes: default + per-tool ACL by consumer/group, deny-first | Yes (v3.13+ audit of access attempts) | No | No | Yes (listener mode aggregates) | Kong 3.12+ | Commercial/OSS gateway; tool-name ACL, no argument inspection documented. **[V]** |
| **Traefik Hub MCP Gateway (TBAC)** | https://doc.traefik.io/traefik-hub/mcp-gateway/guides/understanding-tbac | n/a | Go | Yes, JWT-claim driven per-server tool lists; expression policy on `mcp.params.name`; parameter-level constraints claimed | Not on that page | No | No | Yes | Commercial | The only generic gateway found that documents *argument-level* constraints. **[V]** |
| **Cloudflare MCP Server Portals** | https://blog.cloudflare.com/zero-trust-mcp-server-portals/ | n/a | SaaS | Yes, per user/group, tool-level | Yes (prompts + tools invoked) | No | No | Yes | Open beta since 2025-08-26 | Proprietary, Cloudflare One. **[V]** |
| **agentgateway (Linux Foundation / Solo.io)** | https://github.com/agentgateway/agentgateway | ~4.6k | Rust | Yes, CEL RBAC on tools | Yes (OTel) | No | Guardrail content filters | Yes (federation, stdio/SSE/HTTP) | ~2.5k commits, active | Apache-2.0. Strong candidate to reuse as data plane. **[V]** |
| **Invariant mcp-scan (now "Agent Scan", Snyk)** | https://github.com/invariantlabs-ai/mcp-scan | ~3.1k | Python | Scan-time detection, not runtime policy | — | Consent before contacting servers | — | Scans all configured servers | ~750 commits | Apache-2.0. Detects tool poisoning, destructive capabilities, etc. Proxy/guardrail mode docs: https://invariantlabs-ai.github.io/docs/mcp-scan/guardrails/ **[V]** |
| **Trail of Bits mcp-context-protector** | https://github.com/trailofbits/mcp-context-protector | ~225 | Python | No per-tool ACL; TOFU pinning at server level | Not documented | Yes: CLI review of changed tool descriptions; quarantine release | ANSI sanitisation; guardrail providers on responses | Wraps one server | ~139 commits | Apache-2.0. Best prior art for **rug-pull** defence. **[V]** |
| **Pomerium** | https://github.com/pomerium/pomerium | large | Go | Yes, per-tool access policy | Yes | No | No | Yes | Active | Listed in awesome-mcp-gateways. **[V]** |
| **Kuadrant mcp-gateway** | https://github.com/Kuadrant/mcp-gateway | — | Go/Envoy | AuthZ via policy attachment | Envoy logs | No | No | Yes | — | K8s/Istio. **[V]** (listing only) |
| **Microsoft mcp-gateway** | https://github.com/microsoft/mcp-gateway | — | — | Routing/lifecycle focus | — | No | No | Yes | — | Session-aware K8s reverse proxy. **[V]** (listing only) |
| **Gate22** | https://github.com/aipotheosis-labs/gate22 | ~178 | — | Function-level allow-list | Roadmap | Roadmap | Credential modes | Yes (bundles) | ~164 commits | Apache-2.0; policy-as-code on roadmap. **[V]** |
| **Open Edison** | https://github.com/Edison-Watch/open-edison | ~288 | Python | Tool ACL levels PUBLIC/PRIVATE/SECRET | Session monitor | No | Exfiltration "lethal trifecta" tracking | Yes | ~593 commits | GPL-3.0. **[V]** |
| **Peta / PolicyLayer / KYDE / mcpgate** | https://peta.io, https://policylayer.com, https://kyde.com, https://mcpgate.de | — | — | Per-tool policies | Signed ledger (KYDE) | Peta advertises HITL approvals | DLP (KYDE), PII pseudonymisation (mcpgate) | Yes | — | Commercial; from https://github.com/keysersoft/awesome-mcp-gateways. **[V]** (listing only, not independently checked) |

Also seen but not evaluated: Peeyushm3980/mcp-intercepter (audit, allow/deny, redaction, OTel; https://github.com/Peeyushm3980/mcp-intercepter), speakeasy-api/gram, decocms/mesh, gebruder/wirken.

**Pattern across all of the above [I]:** policy is expressed on *tool name + caller identity*. Argument-aware policy is rare (Traefik TBAC claims it; Docker explicitly lacks it). Human approval is essentially absent from the open-source gateways except mcp-context-protector's description-change review and Peta's commercial HITL. None knows what a "device", "config", or "commit" is.

---

## 3. Is there any network-infrastructure-aware MCP guardrail / broker?

Searches run: "network MCP guardrail", "MCP policy proxy network devices", "safe agentic network operations MCP", "command allowlist MCP network", "NetOps AI agent guardrails", plus vendor-specific (Cisco pyATS, netmiko, Juniper, Arista, PAN-OS, OPNsense, UniFi, Itential).

**Found (adjacent, not a proxy):**

- **Juniper junos-mcp-server** (https://github.com/Juniper/junos-mcp-server, ~108 stars, Apache-2.0, Python): tools for op commands, config diff, load/commit. Has *in-server* guardrails: `block.cfg` regex list rejecting config lines before load/commit, and `block.cmd` blocking dangerous op commands (e.g. reboot). Auth required for streamable-http. **[V]** This is the closest thing to "vendor CLI command classification" found — but it is regex denylist, single-vendor, inside one server.
- **OPNSenseMCP PR #105** (merged 2026-09-19): adds `OPNSENSE_READ_ONLY` (blocks POST/PUT/DELETE and non-allowlisted SSH, hides write tools) and `OPNSENSE_DRY_RUN` (logs intent, returns synthetic success). Enforced at the API-client and SSH chokepoints. https://github.com/vespo92/OPNSenseMCP/pull/105 **[V]**
- **unifi-mcp-server PR #153**: opt-in read-only mode. https://github.com/enuno/unifi-mcp-server/pull/153 **[V]** (title only)
- **Itential MCP** (https://www.itential.com/itential-mcp/, code at https://github.com/itential/itential-mcp): exposes Itential Platform workflows as tools; markets RBAC, SSO, audit, blast-radius limits, pre/post checks, rollback and HITL approvals — but these live in the Itential platform, and it is a *server*, not a proxy in front of other MCP servers. **[V]**
- **InfrastructureSentinel** (HPE, AAAI-26, https://ojs.aaai.org/index.php/AAAI/article/view/41468/45429): a security middleware with four layers (input filtering, tool-sequence validation, execution gating, post-action audit) using a "guardian LLM" to interpret natural-language policies such as role-based VM deprovision limits. Validated on HPE HPC/GreenLake compute MCP servers, not network devices; no code release mentioned. **[V]** This is the strongest academic precedent for a policy middleware between agent and infra MCP servers.
- Curated list https://github.com/hecisaza/network-mcp-servers enumerates ~58 network MCP servers (Cisco Catalyst Center/Meraki/pyATS, Arista CloudVision, Juniper, PAN-OS, Fortinet, NetBox, Nautobot, Scrapli, Netmiko, etc.) and identifies no dedicated guardrail/proxy layer for them beyond Itential's platform governance. **[V]**
- Essay "MCP with a blast radius" (https://nika.sh/blog/mcp-with-a-blast-radius, Aug 2026) argues for separately reviewed boundaries (server, network egress, tool ids, schema pin, trace); not a product. **[V]**

**Not found:** No open-source or commercial project that is (a) a protocol-level MCP proxy, (b) vendor-agnostic across network MCP servers, and (c) aware of network semantics (device role/site, config vs operational, commit/rollback, blast radius). Safety features that do exist are being bolted into *individual* servers one PR at a time (Junos block lists, OPNsense read-only/dry-run, UniFi read-only), which is exactly the fragmentation a proxy would remove. **[V for the individual findings; I for the conclusion]**

---

## 4. MCP security research

1. **Invariant Labs — Tool Poisoning Attacks** (2025-04-01). Hidden instructions in tool descriptions; rug-pull (description changes after approval); cross-server shadowing where a malicious server's description redirects a trusted server's tool. Mitigations: show full descriptions, pin with checksums, cross-server dataflow limits. https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks and repro code https://github.com/invariantlabs-ai/mcp-injection-experiments **[V]**
2. **Invariant Labs — GitHub MCP private-repo exfiltration** via prompt injection in an issue body (toxic agent flow). https://invariantlabs.ai/blog/mcp-github-vulnerability **[V]** (title/summary)
3. **Trail of Bits series** (April 2025): line jumping (attack via descriptions before any call), conversation-history theft via trigger phrases, ANSI escape deception in descriptions/outputs, plaintext credential storage; plus the mcp-context-protector tool. Index: https://trailofbits.com/mcp/ ; e.g. https://blog.trailofbits.com/2025/04/21/jumping-the-line-how-mcp-servers-can-attack-you-before-you-ever-use-them/ and https://blog.trailofbits.com/2025/04/29/deceiving-users-with-ansi-terminal-codes-in-mcp/ **[V]**
4. **Official spec Security Best Practices**: confused-deputy in MCP proxy servers (static client id + DCR + consent cookie → code theft; mitigation: per-client consent before third-party auth), token passthrough forbidden, SSRF via OAuth metadata, session hijacking (why 2026-07-28 removed sessions), local server compromise, stdio-in-proxy escalation, scope minimisation. https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices (also at /2025-11-25/ and /docs/2026-07-28/tutorials/security/security_best_practices) **[V]**
5. **OWASP MCP Top 10** (beta, project lead Vandana Verma Sehgal): MCP01 token/secret exposure, MCP02 privilege escalation via scope creep, MCP03 tool poisoning, MCP04 supply chain, MCP05 command injection, MCP06 prompt injection via contextual payloads, MCP07 insufficient authN/authZ, MCP08 lack of audit/telemetry, MCP09 shadow MCP servers, MCP10 context injection/over-sharing. https://owasp.org/www-project-mcp-top-10/ and https://github.com/OWASP/www-project-mcp-top-10 **[V]**
6. **Academic**: Huang, Huang, Tran, Milani Fard, "Model Context Protocol Threat Modeling and Analyzing Vulnerabilities to Prompt Injection with Tool Poisoning" (arXiv 2603.22489, March 2026): STRIDE/DREAD over five MCP components; empirical test of seven clients finds weak static validation and parameter visibility. https://arxiv.org/abs/2603.22489 **[V]** Also InfrastructureSentinel (AAAI-26, §3 above) and Simon Willison's early analysis https://simonwillison.net/2025/Apr/9/mcp-prompt-injection/ **[V]**
7. **Docker — MCP Horror Stories: GitHub prompt-injection data heist** https://www.docker.com/blog/mcp-horror-stories-github-prompt-injection/ **[V]** (title)

**Mapping to a network guardrail [I]:** MCP05 (command injection) and MCP03/rug-pull are the two that map most directly to CLI-executing network servers: an injected `show` output or a poisoned description could steer an agent into `write erase` or a config commit. A proxy that pins tool descriptions (TOFU), classifies the *actual command text*, and gates commits behind approval addresses both.

---

## 5. Gap analysis: what a network-aware guardrail proxy needs that generic gateways do not provide

| Capability | Provided by any generic gateway? | Evidence | Status |
|---|---|---|---|
| Tool-name allow/deny per caller | Yes (Kong, Traefik, Cloudflare, agentgateway, Pomerium, ContextForge) | §2 | **[V]** — not a differentiator |
| Argument-level policy (inspect `arguments` before forwarding) | Rare. Docker: explicitly no (#574). Traefik TBAC: claims parameter constraints. ContextForge/agentgateway: possible via plugins/CEL but no network vocabulary | https://github.com/docker/mcp-gateway/issues/574 | **[V]** partial gap |
| **Vendor CLI command classification** (read-only `show`/`display`/`get` vs. config-mode vs. disruptive `reload`/`request system reboot`/`clear`), across IOS-XE/NX-OS/EOS/Junos/PAN-OS | None. Only Junos server has a per-server regex denylist. | https://github.com/Juniper/junos-mcp-server | **[V]** gap |
| **Device-role / site / tier-aware policy** (e.g., core and border routers require approval; lab devices are open) sourced from NetBox/Nautobot | None. Gateways key on user identity and tool name, not on the *target* argument. | §2, §3 | **[V]** gap; **[I]** design: resolve `hostname`/`device` arg against a source-of-truth to derive role, then apply policy |
| **Config-diff dry-run before commit** (proxy forces `load ... | compare`/`commit check`/`config replace` diff, shows diff in approval prompt) | None generic. OPNsense dry-run is per-server and synthetic. | https://github.com/vespo92/OPNSenseMCP/pull/105 | **[V]** gap |
| **Blast-radius limits** (max devices per call/session, max config lines, no bulk changes across sites) | Generic gateways are stateless per call (Docker #574 says cross-call policy is impossible). Itential advertises blast-radius limits but inside its own platform. InfrastructureSentinel demonstrates count-based policies via LLM. | §2, §3 | **[V]** gap for proxies |
| **Human approval via MRTR/elicitation with diff + device context** | Essentially absent from OSS gateways; mcp-context-protector reviews *description* changes only; Peta commercial | §2 | **[V]** gap |
| Rug-pull / description pinning of upstream network servers | mcp-context-protector (single server) | https://github.com/trailofbits/mcp-context-protector | **[V]** exists; can be reused/adapted |
| Secret redaction on the *return path* (device configs contain `enable secret`, SNMP communities, BGP passwords, TACACS keys) | Generic regex (Docker `--block-secrets`, Lasso Presidio) — no network-config-aware patterns (`password 7`, `snmp-server community`, `key-string`) | §2 | **[V]** partial gap; **[I]** needs a vendor-config secret grammar |
| Maintenance-window / change-freeze awareness | None found | — | **[I]** gap |
| Idempotency / rollback binding (require `commit confirmed` or `configure replace` with revert timer for risky changes) | None | — | **[I]** gap |
| Structured audit tying agent identity → device → exact command/config → diff → approver | Gateways log tool calls generically; OWASP MCP08 flags audit gaps | https://owasp.org/www-project-mcp-top-10/ | **[V]** partial gap |
| Multi-vendor upstream aggregation with prefixing | Spec explicitly recommends proxies prefix tool names; ContextForge/agentgateway do this | https://modelcontextprotocol.io/specification/2026-07-28/server/tools | **[V]** — reuse, not build |

**Recommended positioning [I]:** Do not compete with agentgateway/ContextForge on generic gateway features (auth, federation, OTel). Build the network-semantic policy layer — command classifier, device-role resolver, dry-run/diff, blast-radius counters, config-secret redaction, MRTR approval — either as a standalone stdio/Streamable-HTTP proxy (simplest to test with the Python SDK client) or as a plugin/ext-proc for agentgateway or ContextForge later. Support both protocol eras (2025-11-25 stateful and 2026-07-28 stateless) from day one, since vendor network MCP servers on GitHub are mostly still on 2025-era SDKs. **[I]**

---

## Appendix: additional sources consulted

- Spec GA blog: https://blog.modelcontextprotocol.io/posts/2026-07-28/
- Streamable HTTP (2026-07-28): https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http
- Elicitation (2026-07-28): https://modelcontextprotocol.io/specification/2026-07-28/client/elicitation
- Tools (2026-07-28): https://modelcontextprotocol.io/specification/2026-07-28/server/tools
- Docker gateway interceptors overview: https://dasroot.net/posts/2026/01/docker-mcp-gateway-interceptors-security/
- Docker gateway announcement: https://www.docker.com/blog/docker-mcp-gateway-secure-infrastructure-for-agentic-ai/
- ContextForge docs: https://ibm.github.io/mcp-context-forge/architecture/
- Lasso launch: https://www.lasso.security/resources/lasso-releases-first-open-source-security-gateway-for-mcp
- Azure APIM Build 2026 (MCP content safety): https://techcommunity.microsoft.com/blog/integrationsonazureblog/whats-new-in-azure-api-management-at-microsoft-build-2026/4524683
- Kong MCP traffic gateway: https://developer.konghq.com/mcp/
- Traefik MCP gateway: https://doc.traefik.io/traefik-hub/mcp-gateway/mcp
- Cloudflare changelog: https://developers.cloudflare.com/changelog/post/2025-08-26-mcp-server-portals/
- Awesome MCP gateways: https://github.com/keysersoft/awesome-mcp-gateways
- Pomerium comparison: https://www.pomerium.com/blog/top-5-agentic-gateways-for-securing-mcp-tool-calls-in-2026
- Vulnerable MCP database: https://vineethsai.github.io/vulnerablemcp/
- CSA Agentic MCP best practices: https://labs.cloudsecurityalliance.org/agentic/agentic-mcp-security-best-practices-v1/
- Itential 58-server guide: https://www.itential.com/resource/guide/the-ultimate-mcp-guide-for-network-automation/
- pyATS MCP: https://github.com/automateyournetwork/pyATS_MCP
