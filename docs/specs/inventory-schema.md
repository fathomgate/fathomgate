# Inventory schema

Normative specification for how `internal/inventory` turns a target name into `{role, site, tags, status, vendor}`. Resolution runs through an ordered provider chain. Name authorities decide whether a target is known, and the first to list it wins; hostname patterns only add attributes to a target an authority lists. A target no authority lists is `unknown`. A source of truth is optional.

Decision records: [ADR 0007](../adr/0007-role-resolver-chain-sot-optional.md), and [ADR 0031](../adr/0031-hostname-patterns-never-make-a-target-known.md) for hostname patterns (it supersedes ADR 0007's provider row 2). The live NetBox and Nautobot connectors are in the paid edition ([ADR 0034](../adr/0034-source-available-under-fsl.md), *Amendments*, 2026-09-25); section 6 says what stays in the core.

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
| `source` | string | set by resolver | The name authority that listed the target: `static`, `upstream:<id>`, `netbox`, `nautobot`, `snapshot`. Never `pattern`: a pattern never lists a target (section 4). `netbox` and `nautobot` are set only by the paid edition's live connectors (section 6). |
| `sources` | map | set by resolver | Which provider supplied each field: `name`, `role`, `site`, `status`, and one entry per tag. Values are those of `source`, plus `pattern` for a field or tag a hostname pattern filled in. `fathomgate inventory resolve` prints it; the audit event records it (M4). |
| `stale` | boolean | set by resolver | True when a record that contributed has `source: snapshot` because the live source of truth was unreachable. |

`source`, `sources` and `stale` are set by the chain and never read from a file: a device record in `inventory.yaml` that carries one is an unknown key, a load error. `status` is device status only: the chain never writes `pattern` into it, and a device record with `status: pattern` (any case) is a load error (in code, `inventory.Target.Source`, `Sources` and `Stale`; `NewStatic`).

## 2. Resolver chain

| Order | Provider | Kind | Enabled when | Contributes when |
| --- | --- | --- | --- | --- |
| 1 | Static `inventory.yaml` (including what `fathomgate inventory import` writes) | Name authority | File configured | Target name present |
| 2 | Hostname patterns | Enricher | `roles:` in `inventory.yaml` is non-empty | An authority listed the target and a pattern matches the listed name |
| 3 | Upstream inventory | Name authority (standing for writes: M2 upstream-provider ADR) | The upstream profile has `inventory_tool` (planned, M2) | The upstream listed the target at startup or last refresh |
| 4 | Source of truth (live connector in the paid edition; the core ships a stub that resolves nothing, section 6) | Name authority | A resolver registered through the `Resolver` interface | REST lookup succeeds, or a snapshot exists |

Two kinds of provider ([ADR 0031](../adr/0031-hostname-patterns-never-make-a-target-known.md) decision 1). A *name authority* decides whether a target is known. An *enricher* runs only after an authority has listed the target, and never makes a target known on its own; hostname patterns are the only enricher. In M1 the only name authority is the static file (with CSV import); a target no authority lists is `unknown` whatever patterns it matches.

Merging (ADR 0031 decision 2): an authority's record counts only when its `name` is the name looked up (case-insensitively, as the static file matches); a record for another name is ignored. The first authority that lists the target supplies its `name`, `source`, its `tags` and every field its record sets. A later authority that lists the same target only fills a `role`, `site` or `status` still empty; it never adds tags. The reason: from M2 the later authorities include the upstream's own device list, which is untrusted data (invariant 7), and a tag such as `lab` unlocks writes, so a tag reaches a target only from the first authority that lists it or from an operator-written pattern (security review of PR #184, L1). Then the enrichers run on the name as the authority stores it: each fills a field still empty (`role`, `site`; the first matching pattern in file order wins each field) and adds its `tags`. `tags` are the union of the first authority's and the patterns', without duplicates, in that order, so a pattern can add `lab` to a device the static file already describes. An enricher never sets `status`. Each field's provider is recorded in `sources` (section 1).

A role or tags a pattern gives a listed target count for every rule, write rules included (ADR 0031, decision 2 of its open questions): the operator vouched for the name by listing it.

The chain is evaluated per target. A batch call with four targets may resolve three from the static file (one of them with its role from a pattern) and one as `unknown`.

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

Patterns are optional. They live under `roles:` in `inventory.yaml` (`internal/inventory/patterns.go`), next to the devices they describe, and are not part of the policy file. A pattern is an enricher (section 2): it never makes a target known, and only fills in `role` and `site` and adds `tags` on a device a name authority lists ([ADR 0031](../adr/0031-hostname-patterns-never-make-a-target-known.md)). Its job is a naming convention: a CSV of 800 names and a few patterns give every device a role and site without editing 800 lines. `inventory.example.yaml` ships none active, with the shape commented out.

```yaml
roles:
  - match: "^core-|^border-"
    role: core
  - match: "^lab-[a-z]+-[0-9]{2}$"          # anchored at both ends
    tags: [lab]
```

| Field | Type | Meaning |
| --- | --- | --- |
| `match` | RE2 regex | Tested case-insensitively against the listed device's name as the authority stores it. Required. |
| `role`, `site` | string | Fill the field if the device's record and every earlier matching pattern leave it empty |
| `tags` | list | Always unioned with the device's tags |

A pattern sets at least one of `role`, `site`, `tags`; one that sets none, has no `match` or does not compile is a load error. A pattern has no `status` or `vendor`: those come from a name authority.

Every matching pattern contributes, in file order: the first that sets `role` wins `role`, the first that sets `site` wins `site`, and tags accumulate. The device's own record wins over every pattern. A listed device whose record and patterns set no role has no role, and `device_roles: [unknown]` matches it.

**A pattern that matches no listed device** resolves and enriches nothing, so an operator who wrote it probably expected something it does not do (ADR 0031 decision 5; `File.PatternWarnings`). The message is `inventory: roles[<i>] "<match>" matches no listed device and makes nothing known (ADR 0031); list the device under devices`. It is a warning when `fathomgate serve --inventory` loads the file, so a stale pattern never stops the proxy, and an error in `fathomgate inventory lint` (section 9). `inventory lint` also warns, without failing, for every role, site or tag a pattern adds to a listed device, one line per device and pattern, and says the device's own role where a pattern adds a tag to it or offers a different role (`File.PatternEffects`): `inventory: devices[<j>] "<name>": roles[<i>] "<match>" adds tag lab; the device's own record says role core`.

**What a pattern can still get wrong.** The target name comes from the agent, but a name no authority lists is `unknown` whatever it matches, so `core-x.attacker.example`, `lab-ghost-99` and `LAB-core-rtr-01` never reach the rules through a pattern. What a loose pattern can do is mislabel a device you listed, and the role and tags it gives count for write rules too: `^lab-` with `tags: [lab]` makes a listed `lab-core-01` writable under `lab-open` even if it is a core router (the misclassification ADR 0007 accepted). Patterns are case-insensitive and not anchored at the end unless you add `$`; anchor them as tightly as the naming convention allows, and put a role or tag that unlocks writes on the device itself when in doubt. `fathomgate inventory resolve` shows which provider set each field.

## 5. Upstream inventory provider

At startup, and every `refresh` interval (default 10m), the proxy calls the profile's `inventory_tool` and extracts names, tags and vendors through `inventory_map`. The result is a provider that knows exactly the devices that upstream can reach.

Sources per upstream: ntunes `list_devices` (names, tags, `device_type`), eos-mcp `get_router_list` (names, tags), junos `get_router_list` (names), upa `get_network_device_list` (names, `device_type`), mcp-telecom `list_devices`.

A record from this provider has `role: unknown` unless the upstream carries a role field, which none of the surveyed servers do, or a hostname pattern gives it one (section 4). It exists so that `tags` such as ntunes `lab` can drive policy, and so that `targets_all_when_empty` and `@group` expansion have a device list to expand into.

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

### 6.1 Rules for a live connector

A resolver registered at order 4, such as the paid edition's connector, follows two rules so that its records and decisions read the same as the core's:

1. **`source`.** A record from a live lookup carries `source: netbox` or `source: nautobot`. A record served from the connector's snapshot carries `source: snapshot`.
2. **Stale fallback.** When the live source is unreachable, the resolver may serve the last snapshot. Every record from it has `stale: true`, and every decision that used one carries `sot: stale` in its audit event. A definitive not-found from a live lookup is `unknown` and is not overridden by the snapshot. With no usable snapshot the target is `unknown`.

## 7. Unknown-target semantics

- A target is unknown when no name authority lists its name, whatever hostname patterns it matches (section 4). The policy request carries it as `known: false`.
- `Evaluate` step 1 ([policy-schema.md](policy-schema.md#4-evaluation-order)): with `defaults.unknown_target: deny`, any unknown target denies the call for every class. With `unknown_target` unset the same happens: every class is denied ([ADR 0032](../adr/0032-unset-unknown-target-denies-every-class.md)). With `allow`, the rules decide for every class. A request that names no target has no unknown target and is not affected.
- An unknown target has no role, so it never matches a `device_roles` rule. Under `unknown_target: allow`, a read to it is allowed only by a rule that matches on class alone (such as `reads-anywhere`); that setting sends the upstream's device credentials to any host the agent names on upstreams such as eos-mcp and netdev-ssh-mcp, so use it only where that is acceptable.
- The audit event lists the target in `targets[]` with an empty entry in `roles[]`; an `unknown_target` flag is planned (M4).
- A free-form `host` value that is an IP address is looked up as a name first; if no provider matches, it is `unknown`. There is no implicit IP-to-name resolution through DNS, because DNS is not a source of truth.
- Matching at the proxy is exact ([profile-schema section 2.2](profile-schema.md#22-targets-at-the-gate)). `internal/gate` looks the name up as sent and counts it as known only when a name authority lists it and the record's stored name is the same string, case included; a hostname pattern never makes a name known ([ADR 0031](../adr/0031-hostname-patterns-never-make-a-target-known.md)). `inventory.Known` is that rule; the gate, `fathomgate policy eval --inventory` and `fathomgate inventory resolve` all use it. `policy eval` also refuses a `--target` the gate would refuse (`default:bad_arguments`), so it shows what the gate does. `CORE-rtr-01`, ` core-rtr-01` and `core-rtr-01.corp.example` are not `core-rtr-01`: the first and last are `unknown`, the second is refused as a bad argument. DNS would treat the case variant as the same host, but an upstream that keys its own device table by name may not, and fathomgate cannot tell which the upstream does, so it fails closed. An operator who needs two spellings lists both.

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
| `fathomgate inventory import --csv <csv> [--out file]` | Section 3.1 |
| `fathomgate inventory sync` | Paid edition: writes the snapshot from the live source of truth |
| `fathomgate inventory resolve [--inventory file] [--json] <name>...` | Prints, for each name, whether it is known exactly as `serve` counts it (`inventory.Known`, section 7), the authority that listed it, and which provider supplied each field and tag (`static`, `pattern`, ...). For an unknown name it says why (no authority lists it, or it is listed with another spelling) and which patterns it matches, which never make it known. A name or stored value that is not printable ASCII is printed Go-quoted, so no control, escape or bidi character or homoglyph reaches the terminal raw. `--inventory` defaults to `inventory.yaml` and is read as `serve --inventory` reads it (a `.csv` is refused; the owner and write-permission checks and size limit of `internal/configfile`). Exit 0 when every name is known, 1 when any is unknown, 2 on a usage or load error. The debugging tool for "why was this denied as unknown" |
| `fathomgate inventory lint <file>` | Reads the file as `serve --inventory` does (see `resolve`) and validates it. Errors (exit 1): everything a load checks (unknown keys, duplicate names, `status: pattern`, patterns that do not compile or set nothing); a pattern that matches no listed device (section 4), which `serve` only warns about; a listed device whose name the gate refuses as a target (not a hostname or IP address, for example a trailing dot, a space, or a non-ASCII character), which no call can reach. Warnings (exit 0): each role, site or tag a pattern adds to a listed device (section 4). Exit 2 when the file cannot be read |

In M1 the core has `import`, `lint` and `resolve`.
