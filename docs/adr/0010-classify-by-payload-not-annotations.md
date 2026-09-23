# ADR 0010: Classify by payload, not by annotations

- Status: accepted
- Date: 2026-09-23
- Deciders: Josh Scott

## Context

MCP tools carry annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`). The spec says clients MUST treat them as untrusted unless the server is trusted. Tool names are also unreliable as a signal: eos-mcp's `run_command` forwards `configure` and `reload` verbatim to eAPI; ntunes' `send_command` has no filter; Meraki's official server exposes only `execute_api(capability_id, parameters)`, where the name carries no semantics at all. See [research brief 02](../research/02-network-mcp-servers.md).

The free-form "run a command" tool is present in almost every CLI-backed server. Only three of 25 servers enforce a positive allow-list on it. Tool poisoning (OWASP MCP03) and command injection (MCP05) map directly onto these tools: a poisoned description or injected show output can steer an agent into `write erase`.

## Decision

We will classify every call by inspecting its normalised payload, using a per-server profile as the primary mapping and a fallback classifier for unmapped tools, and will treat annotations as one input that can only make a class stricter, never looser.

- A profile maps each tool to one class: `READ_OPERATIONAL`, `READ_CONFIG`, `WRITE_CONFIG`, `EXEC_ARBITRARY`, `INVENTORY_READ`, `LAB_LIFECYCLE`, `LOCAL_ADMIN`.
- A tool profiled as `EXEC_ARBITRARY` is downgraded to `READ_OPERATIONAL` only if every command in `commands[]` passes the allow-prefix list, matches no blocklist regex, and contains no pipe or redirect that the allow-list does not permit.
- A command that reads configuration through a free-form tool (`show running-config`, `show configuration`, `show full-configuration`) is reclassified `READ_CONFIG` so mandatory redaction applies.
- Meta-tools are classified from a capability table keyed on `capability_id`.
- A `WRITE_CONFIG` tool with a `dry_run` or `apply_config` parameter is `READ_CONFIG` when the payload says dry-run only; the proxy also forces a dry-run pass before any real commit when the tool offers one.
- An annotation of `readOnlyHint: false` on a tool profiled as read raises the class to `EXEC_ARBITRARY`; `readOnlyHint: true` never lowers it.

The normative rules and worked examples are in [classification.md](../specs/classification.md).

## Consequences

### Positive

- Policy is on what the call does, not what the tool says it does.
- `EXEC_ARBITRARY` downgrade means an agent running `show ip bgp summary` through an unfiltered tool still works, while `reload` through the same tool is denied by rule id.
- The same classifier serves servers with and without their own filters, so NetGuard is defence in depth, not a replacement.

### Negative

- Allow-lists and blocklists are per vendor and will have gaps. Mitigated by unions of the strongest existing filters (mcp-telecom, pyATS, netdev-ssh-mcp) and by test cases per vendor.
- Profiles are data that drifts when upstreams change tool schemas. Mitigated by TOFU pinning that quarantines a changed server, and by weekly tier 2 CI.

### Neutral

- Palo-MCP's `[READ-ONLY]` / `[MODIFIES CONFIG]` / `[ADVANCED]` description labels are parsed into a profile suggestion but are still treated as untrusted.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Trust `readOnlyHint` | Explicitly untrusted in the spec; absent on most surveyed servers. |
| Classify by tool name only | Fails on `run_command`, `send_command`, `execute_api`. |
| Rely on upstream filters | Only three servers have allow-lists; blocklists such as upa's `--secured` are partial. |
| LLM-based classification (InfrastructureSentinel) | Non-deterministic; not testable with table tests; adds a model call to every tool call. |

## References

- [Research brief 02, section 2](../research/02-network-mcp-servers.md)
- [MCP tools spec, annotations untrusted](https://modelcontextprotocol.io/specification/2026-07-28/server/tools)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
- [Invariant Labs tool poisoning](https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks)
- [eos-mcp](https://github.com/shigechika/eos-mcp), [ntunes/netmiko-mcp-server](https://github.com/ntunes/netmiko-mcp-server), [Cisco Meraki MCP official](https://github.com/CiscoDevNet/cisco-meraki-mcp-official)
- [mcp-telecom safety.py](https://github.com/Avinash-Amudala/MCP-Telecom), [pyATS MCP](https://github.com/automateyournetwork/pyATS_MCP), [netdev-ssh-mcp](https://github.com/krisiasty/netdev-ssh-mcp)
- [InfrastructureSentinel, AAAI-26](https://ojs.aaai.org/index.php/AAAI/article/view/41468/45429)
