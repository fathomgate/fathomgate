# ADR 0007: Role resolver chain with the source of truth optional

- Status: accepted
- Date: 2026-09-23
- Deciders: Josh Scott

## Context

Role-aware policy ("core routers need approval, lab devices are open") needs a lookup from target hostname to `{role, site, tags, status}`. NetBox and Nautobot model exactly that. But requiring a source of truth would exclude most shops, every MSP fronting a client's devices, and anyone with a spreadsheet. It would also make the proxy fail closed, or worse fail open, when NetBox is unreachable.

Several upstream servers already carry an inventory with tags: ntunes `devices.yaml`, eos-mcp `config.ini`, junos `devices.json`. Many networks have a naming convention that encodes role.

Unknown targets matter most for servers whose target argument is free-form, such as netdev-ssh-mcp's `host`.

## Decision

We will resolve roles through an ordered provider chain, first hit wins, with NetBox and Nautobot as one provider in the chain rather than a dependency.

| Order | Provider | Needs |
| --- | --- | --- |
| 1 | Static `inventory.yaml`, or `netguard inventory import devices.csv` | Nothing |
| 2 | Hostname patterns in the policy file (`^core-|^border-` → role `core`) | A naming convention |
| 3 | The upstream server's own inventory, read through its `INVENTORY_READ` tools at startup | The server already configured |
| 4 | NetBox or Nautobot REST, cached with a TTL; `netguard inventory sync` snapshots it into the static file | A source of truth |

A target no provider resolves is `unknown`. Default policy for unknown targets denies `WRITE_CONFIG` and `EXEC_ARBITRARY` and allows reads; `defaults.unknown_target` flips it. When the source of truth is configured but unreachable, the proxy uses the last snapshot and marks every decision made from it with `sot: stale` in the audit event.

The normative schema is [inventory-schema.md](../specs/inventory-schema.md).

## Consequences

### Positive

- Works on day one with a ten-line YAML file.
- An MSP can run one proxy per client with one inventory file each.
- A NetBox outage never loosens policy silently; the audit trail shows exactly which decisions were made from stale data.

### Negative

- Four code paths to test. Mitigated by the M2 exit criterion: one policy resolves roles from a static file, from NetBox, and from a stale snapshot, with identical decisions.
- Hostname patterns can misclassify a badly named device. Accepted; patterns are one provider and the operator can pin a device in the static file, which wins.
- Whether the stale window should be capped is an open question.

### Neutral

- A hand-written 100-line HTTP client is preferred over the generated `go-netbox` client that must be bumped per NetBox release.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| NetBox required | Excludes most of the target users; makes availability a policy input. |
| Inventory only inside the policy file | Mixes data and rules; a spreadsheet import has no natural home. |
| Ask the upstream server for everything | Only some servers expose inventory, and a free-form `host` server exposes none. |

## References

- [Research brief 02, inventory shapes](../research/02-network-mcp-servers.md)
- [Research brief 03, section 5.1](../research/03-policy-and-approval-patterns.md)
- [netbox-mcp-server](https://github.com/netboxlabs/netbox-mcp-server)
- [go-netbox](https://github.com/netbox-community/go-netbox/releases)
- [Nautobot](https://networktocode.com/nautobot/)

## Amendments

This section records factual corrections and pointers (GOVERNANCE.md). It does not change the decision.

| Date | What changed | Why |
| --- | --- | --- |
| 2026-09-25 | Pointer: provider row 2 (hostname patterns) is superseded by [ADR 0031](0031-hostname-patterns-never-make-a-target-known.md) (accepted 2026-09-25). A hostname pattern no longer makes a target known on its own; it only fills in role and site where they are empty, and adds tags, on a device a name authority lists (the static file or CSV import in M1; the M2 providers as ADR 0031 sets out). The chain order, first hit wins among name authorities, the unknown-target rule and the `sot: stale` marking are unchanged here. The default for an unset `unknown_target` is decided separately, in board task M1-37 | Security review of PR #154 (H1, H2): a pattern made any agent-chosen name that matched it a known device. Maintainer decision, Josh Scott, 2026-09-25 |
