# ADR 0002: Standalone proxy, not a gateway plugin

- Status: accepted
- Date: 2026-09-23
- Deciders: Josh Scott

## Context

Generic MCP gateways already exist and are well maintained: agentgateway (Rust, CEL RBAC, about 4.6k stars), IBM ContextForge (Python, RBAC and plugins, about 4.3k), Docker MCP Gateway (Go, about 1.5k), Kong `ai-mcp-proxy`, Traefik Hub TBAC, Cloudflare MCP Server Portals. They do authentication, federation, tool-name allow and deny lists and OpenTelemetry. [Research brief 01](../research/01-mcp-proxy-prior-art.md) surveyed them.

None knows what a device, a config or a commit is. Policy is expressed on tool name plus caller identity. Argument-level policy is rare (Docker admits it is impossible in [issue #574](https://github.com/docker/mcp-gateway/issues/574); Traefik claims it). Human approval is essentially absent from open-source gateways. Cross-call state such as fan-out counters is not modelled.

The network-semantic layer could be built as a plugin for one of those gateways (ContextForge plugin, agentgateway ext-proc) or as a standalone proxy that speaks MCP on both sides.

## Decision

We will build NetGuard as a standalone MCP proxy that is an MCP server toward the agent and an MCP client toward each upstream, over stdio and Streamable HTTP, and will not rebuild generic gateway features (auth federation, OTel, catalogues).

Two things from the generic gateways are reused as patterns, not rebuilt: tool-name prefixing for aggregated upstreams (the spec recommends it), and Trail of Bits' TOFU description pinning for rug-pull defence.

## Consequences

### Positive

- A network engineer installs one binary and points `mcp.json` at it. No gateway, database or Kubernetes required.
- Testable end to end with the Python SDK client and a fake upstream, with no gateway in the loop.
- The pipeline (normalize, classify, resolve, evaluate) is one package boundary away from becoming a plugin later.

### Negative

- Shops that already run agentgateway or ContextForge get two hops. Mitigated by keeping the policy layer behind a stable `Evaluate` interface so an ext-proc adapter is a later milestone, not a rewrite (open question in [PLAN.md](../PLAN.md)).
- NetGuard must handle the dual-era transport itself ([ADR 0008](0008-dual-era-mcp-support.md)).

### Neutral

- NetGuard sits behind a generic gateway when both are present; auth happens in front, network policy in NetGuard.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| ContextForge plugin | Ties the project to a Python gateway that needs Postgres and Redis; ContextForge's own SDK v2 migration was still in progress. Excludes the single-binary user. |
| agentgateway ext-proc | Strong data plane, but the plugin surface was not stable enough to build a first release on, and the target user does not run a gateway. Kept as a later option. |
| Fork Docker MCP Gateway | Policy is payload-blind by design (issue #574); adding argument inspection means rewriting the policy path anyway. |
| Claude Agent SDK hooks (`PreToolUse`) | Client-specific; would not protect Cursor, LangGraph or any other client. |

## References

- [Research brief 01, prior art](../research/01-mcp-proxy-prior-art.md)
- [agentgateway](https://github.com/agentgateway/agentgateway) and [design post](https://agentgateway.dev/blog/2026-06-04-designing-agentgateway-unified-gateway/)
- [IBM ContextForge](https://github.com/IBM/mcp-context-forge)
- [Docker MCP Gateway issue #574](https://github.com/docker/mcp-gateway/issues/574)
- [Traefik Hub TBAC](https://doc.traefik.io/traefik-hub/mcp-gateway/guides/understanding-tbac)
- [Trail of Bits mcp-context-protector](https://github.com/trailofbits/mcp-context-protector)
- [MCP tools spec, name collisions](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [Claude Agent SDK hooks](https://code.claude.com/docs/en/agent-sdk/hooks)
