# Inventory schema

Normative specification for how `internal/inventory` turns a target name into `{role, site, tags, status, vendor}`. Resolution runs through an ordered provider chain; the first provider that knows the target wins. A target no provider knows is `unknown`. A source of truth is optional.

Decision record: [ADR 0007](../adr/0007-role-resolver-chain-sot-optional.md). The live NetBox and Nautobot connectors are in the paid edition ([ADR 0034](../adr/0034-source-available-under-fsl.md), *Amendments*, 2026-09-25); section 6 says what stays in the core.

## 1. Device record

Every provider returns the same shape.

| Field | Type | Required | Values |
| --- | --- | --- | --- |
| `name` | string | yes | Canonical hostname as the upstream expects it. Resolvers match case-insensitively (and duplicates are case-insensitive), but the proxy counts a target as known only when the name the agent sent equals the stored form byte for byte (section 7). |
| `role` | string | yes | Free text; `core`, `border`, `access`, `firewall` are conventions, not an enum. `unknown` is reserved. |
| `site` | string | no | Free text. |
| `tags` | list of string | no | Free text. `lab`, `canary`, `change-frozen` are conventions used by the example policies. |
| `status` | string | no | `active` (default), `planned`, `staged`, `failed`, `offline`, `decommissioning`. NetBox and Nautobot values map one to one. |
| `vendor` | string | no | `ios`, `iosxe`, `nxos`, `eos`, `junos`, `panos`, `fortios`, `srlinux`, `iosxr`, `other`. Selects the `ChangeSafety` driver and the redaction pattern set. |
| `mgmt_addr` | string | no | Accepted for import; never written to the audit log. |
| `source` | string | set by resolver | `static`, `pattern`, `upstream:<id>`, `netbox`, `nautobot`, `snapshot`. `netbox` and `nautobot` are set only by the paid edition's live connectors (section 6). |
| `stale` | boolean | set by resolver | True when `source` is `snapshot` because the live source of truth was unreachable. |

## 2. Resolver chain

| Order | Provider | Enabled when | Wins when |
| --- | --- | --- | --- |
| 1 | Static `inventory.yaml` | File configured | Target name present |
| 2 | Hostname patterns | `roles:` in `inventory.yaml` is non-empty | A pattern matches |
| 3 | Upstream inventory | The upstream profile has `inventory_tool` (planned, M2) | The upstream listed the target at startup or last refresh |
| 4 | Source of truth (live connector in the paid edition; the core ships a stub that resolves nothing, section 6) | A resolver registered through the `Resolver` interface | REST lookup succeeds, or a snapshot exists |

Merging: the first provider that returns a record supplies `role`, `site`, `status` and `vendor`. `tags` are the union from every provider that knows the target, so a pattern can add `lab` to a device the static file already describes. A field the winning provider leaves empty is filled from the next provider that has it.

The chain is evaluated per target. A batch call with four targets may resolve two from the static file, one from a pattern and one as `unknown`.

## 3. Static file

```yaml
version: 1
devices:
  - name: core-rtr-01
    role: core
    site: lon1
    vendor: junos
    tags: [canary]
  - name: lab-sw-01
    role: access
    site: lab
    vendor: eos
    tags: [lab]
    status: active
  - name: fw-edge-01
    role: firewall
    site: lon1
    vendor: panos
```

`version` is required. Duplicate names are a load error. Unknown keys are a load error.

### 3.1 CSV import

`fathomgate inventory import devices.csv [--out inventory.yaml]` reads a header row and the columns below. Column names are case-insensitive. Unrecognised columns are ignored with a warning.

| Column | Maps to | Notes |
| --- | --- | --- |
| `name`, `hostname`, `device` | `name` | First present is used |
| `role`, `device_role` | `role` | |
| `site`, `location` | `site` | |
| `tags` | `tags` | Split on `;` or `,` or whitespace |
| `status` | `status` | |
| `vendor`, `platform`, `os` | `vendor` | Netmiko `device_type` values are mapped: `cisco_ios` → `ios`, `cisco_xe` → `iosxe`, `cisco_nxos` → `nxos`, `arista_eos` → `eos`, `juniper_junos` → `junos`, `paloalto_panos` → `panos`, `fortinet` → `fortios`, `nokia_srl` → `srlinux`, `cisco_xr` → `iosxr` |
| `mgmt_addr`, `ip`, `primary_ip` | `mgmt_addr` | Kept in the file, never audited |

Import merges into an existing file by `name`; the CSV row wins for every column it supplies.

CSV import is the core's path from NetBox or Nautobot (section 6). A round trip from a real export of each is M2 work, and the column list above grows there if an export needs it.

## 4. Hostname patterns

Patterns are optional. They live under `roles:` in `inventory.yaml` (`internal/inventory/patterns.go`), next to the devices they describe, and are not part of the policy file. `inventory.example.yaml` ships none active: every device it knows is listed by name (section 3). Read the hazard below before turning one on.

```yaml
roles:                                  # the shape; anchored at both ends
  - match: "^dfw1-acc-sw-[0-9]{2}$"
    site: dfw1
```

| Field | Type | Meaning |
| --- | --- | --- |
| `match` | RE2 regex | Applied to the lower-cased target name. Anchor explicitly. |
| `role`, `site`, `status`, `vendor` | string | Set if the pattern is the winning provider or the field is otherwise empty |
| `tags` | list | Always unioned |

Every matching pattern contributes. The first pattern that sets `role` wins `role`. A target matched only by a pattern that sets no role remains `unknown` for `role`, and `device_roles: [unknown]` matches it.

Current code: any matching pattern, whatever it sets, makes the target known (`known: true`, `status: pattern`), so the unknown-target default does not apply to it. The original intent, that a pattern match alone never resolves a target, is not implemented; whether it should be is for the follow-up inventory ADR named in the [threat model](../security/threat-model.md) (row "Pattern-resolved target").

**Hazard.** The target name comes from the agent, and a pattern resolves any string the agent sends that matches it:

- **Reads reach it.** Every shipped example allows reads on a known device. With `^core-` active, `core-x.attacker.example` is known, `get_config` is `allow` `reads-anywhere`, and an upstream that takes a free-form host (netdev-ssh-mcp) logs in to that host with the operator's device password or SSH agent. Config output is not redacted until M2.
- **Matching is loose.** Patterns are case-insensitive and not anchored at the end unless you add `$`; names with `.`, `@` or `:` still match (`^lab-` matches `LAB-x`, `lab-x.attacker.example` and `lab-x@core-rtr-01`).
- **Writes.** A tag or role that a rule allowing writes matches on must never come from a pattern: with `^lab-` adding `tags: [lab]`, any such name satisfies `lab-open`'s `device_tags: [lab]` and the write is allowed.

Turn a pattern on only if every name it can match is a device the agent may read, anchor it at both ends, and give it no write-unlocking tag or role. List every device a policy allows writes to by name (section 3).

## 5. Upstream inventory provider

At startup, and every `refresh` interval (default 10m), the proxy calls the profile's `inventory_tool` and extracts names, tags and vendors through `inventory_map`. The result is a provider that knows exactly the devices that upstream can reach.

Sources per upstream: ntunes `list_devices` (names, tags, `device_type`), eos-mcp `get_router_list` (names, tags), junos `get_router_list` (names), upa `get_network_device_list` (names, `device_type`), mcp-telecom `list_devices`.

A record from this provider has `role: unknown` unless the upstream carries a role field, which none of the surveyed servers do. It exists so that `tags` such as ntunes `lab` can drive policy, and so that `targets_all_when_empty` and `@group` expansion have a device list to expand into.

## 6. Source of truth

A source of truth such as NetBox or Nautobot reaches the chain in one of two ways. The export path is in the core; the live connectors are in the paid edition ([ADR 0034](../adr/0034-source-available-under-fsl.md), *Amendments*, 2026-09-25).

| Path | Edition | What it does |
| --- | --- | --- |
| Export and import | Core | Export the devices from NetBox or Nautobot as CSV and load them with `fathomgate inventory import` (section 3.1). The result is a static file, served by provider 1 |
| Live connector | Paid edition | API lookup, auto-sync, caching and freshness checks against NetBox or Nautobot, plugged into the chain at order 4 through the `Resolver` interface |

The core keeps what makes any connector behave the same:

- the `Resolver` interface and the chain order (section 2);
- the snapshot format: the static-file format of section 3, with every record from it carrying `source: snapshot`;
- `stale` marking: a record served from a snapshot because the live source was unreachable has `stale: true`, and every decision that used one carries `sot: stale` in its audit event;
- failing closed: a resolver that fails or times out yields `unknown`, never a guessed role ([ADR 0020](../adr/0020-open-core-apache-2.md) section 3, invariant 7).

`internal/inventory/netbox.go` is a stub in the core. It satisfies `Resolver` and resolves nothing, so a chain that includes it fails closed. It stays until the paid resolver exists, then leaves the core.

### 6.1 Live connector (paid edition)

The rest of this section describes the paid edition's connector, so that its records and its `sot: stale` marking match the core's. The core does not read the `sot` block.

```yaml
sot:
  kind: netbox           # or nautobot
  url: https://netbox.example.net
  token_env: NETBOX_TOKEN
  cache_ttl: 5m
  snapshot: ./inventory.snapshot.yaml
  stale_max_age: 0       # 0 = unlimited (open question in PLAN.md)
  filters:
    status: active
```

| Field | Meaning |
| --- | --- |
| `kind` | `netbox` uses `/api/dcim/devices/?name=`; `nautobot` uses `/api/dcim/devices/?name=`. Both return `role`, `site` (or `location`), `tags[]`, `status`, `platform`. |
| `cache_ttl` | Per-target positive and negative cache. |
| `snapshot` | Written by `fathomgate inventory sync`, which pages through every device and writes the static-file format with `source: snapshot`. |
| `stale_max_age` | If non-zero and the snapshot is older, resolution from it fails and the target is `unknown`. |

Lookup order inside the connector: cache, then live REST, then snapshot. A live failure (connection error, 5xx, timeout) is logged once per `cache_ttl` and the snapshot is used. Every record from the snapshot has `stale: true`, and every decision that used one carries `sot: stale` in its audit event. A 404 from a live lookup is a definitive `unknown` and is not overridden by the snapshot.

Platform mapping to `vendor`: NetBox `platform.slug` or `manufacturer.slug` are matched case-insensitively against `ios|iosxe|ios-xe|nxos|nx-os|eos|junos|panos|pan-os|fortios|srlinux|sr-linux|iosxr|ios-xr`. Anything else is `other`.

## 7. Unknown-target semantics

- A target is unknown when no provider resolved its name. The policy request carries it as `known: false`.
- `Evaluate` step 1 ([policy-schema.md](policy-schema.md#4-evaluation-order)): with `defaults.unknown_target: deny`, any unknown target denies the call for every class. With `unknown_target` unset the same happens: every class is denied ([ADR 0032](../adr/0032-unset-unknown-target-denies-every-class.md)). With `allow`, the rules decide for every class. A request that names no target has no unknown target and is not affected.
- An unknown target has no role, so it never matches a `device_roles` rule. Under `unknown_target: allow`, a read to it is allowed only by a rule that matches on class alone (such as `reads-anywhere`); that setting sends the upstream's device credentials to any host the agent names on upstreams such as eos-mcp and netdev-ssh-mcp, so use it only where that is acceptable.
- The audit event lists the target in `targets[]` with an empty entry in `roles[]`; an `unknown_target` flag is planned (M4).
- A free-form `host` value that is an IP address is looked up as a name first; if no provider matches, it is `unknown`. There is no implicit IP-to-name resolution through DNS, because DNS is not a source of truth.
- Matching at the proxy is exact ([profile-schema section 2.2](profile-schema.md#22-targets-at-the-gate)). `internal/gate` looks the name up as sent and counts it as known only when the record's stored name is the same string, case included, and the record did not come from a hostname pattern alone ([ADR 0031](../adr/0031-hostname-patterns-never-make-a-target-known.md)). `CORE-rtr-01`, ` core-rtr-01` and `core-rtr-01.corp.example` are not `core-rtr-01`: the first and last are `unknown`, the second is refused as a bad argument. DNS would treat the case variant as the same host, but an upstream that keys its own device table by name may not, and fathomgate cannot tell which the upstream does, so it fails closed. An operator who needs two spellings lists both.

## 8. Expansion before resolution

`internal/normalize` expands these forms before the chain runs:

| Form | Example | Expansion |
| --- | --- | --- |
| Array | `["r1", "r2"]` | As is |
| CSV string | `"r1, r2"` | Split on comma, trimmed |
| Group token | `"@core"` | Members from the upstream inventory provider's groups; unknown group is a deny with reason `unknown group` |
| Tags | `tags: [lab]` on eos-mcp batch tools | Devices with that tag from the upstream inventory provider |
| Empty with `targets_all_when_empty` (planned profile field) | `hostnames: null` | Every device the upstream inventory lists |

After expansion, `targets_count` in `when` conditions is the expanded count, so a fan-out cap sees the real blast radius.

In M1 there is no upstream inventory provider, so only the first two rows apply, and a CSV string is split but not trimmed (`"r1, r2"` is refused). A group token or a tag selector on a tool that reaches devices is refused with `default:bad_arguments`, and so is an empty selection on such a tool ([profile-schema section 2.2](profile-schema.md#22-targets-at-the-gate)). The proxy never expands a group or tag from its own inventory for an upstream that expands it itself: the upstream's idea of the group is what reaches devices.

## 9. CLI

| Command | Effect |
| --- | --- |
| `fathomgate inventory import <csv> [--out file]` | Section 3.1 |
| `fathomgate inventory sync` | Paid edition (section 6.1): writes the snapshot from the live source of truth |
| `fathomgate inventory resolve <name>...` | Prints the record and which provider supplied each field; the debugging tool for "why was this denied as unknown" |
| `fathomgate inventory lint <file>` | Validates the static file |
