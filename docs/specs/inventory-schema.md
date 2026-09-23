# Inventory schema

Normative specification for how `internal/inventory` turns a target name into `{role, site, tags, status, vendor}`. Resolution runs through an ordered provider chain; the first provider that knows the target wins. A target no provider knows is `unknown`. A source of truth is optional.

Decision record: [ADR 0007](../adr/0007-role-resolver-chain-sot-optional.md).

## 1. Device record

Every provider returns the same shape.

| Field | Type | Required | Values |
| --- | --- | --- | --- |
| `name` | string | yes | Canonical hostname as the upstream expects it. Matching is case-insensitive; the stored form is what the upstream receives. |
| `role` | string | yes | Free text; `core`, `border`, `access`, `firewall` are conventions, not an enum. `unknown` is reserved. |
| `site` | string | no | Free text. |
| `tags` | list of string | no | Free text. `lab`, `canary`, `change-frozen` are conventions used by the example policies. |
| `status` | string | no | `active` (default), `planned`, `staged`, `failed`, `offline`, `decommissioning`. NetBox and Nautobot values map one to one. |
| `vendor` | string | no | `ios`, `iosxe`, `nxos`, `eos`, `junos`, `panos`, `fortios`, `srlinux`, `iosxr`, `other`. Selects the `ChangeSafety` driver and the redaction pattern set. |
| `mgmt_addr` | string | no | Accepted for import; never written to the audit log. |
| `source` | string | set by resolver | `static`, `pattern`, `upstream:<id>`, `netbox`, `nautobot`, `snapshot`. |
| `stale` | boolean | set by resolver | True when `source` is `snapshot` because the live source of truth was unreachable. |

## 2. Resolver chain

| Order | Provider | Enabled when | Wins when |
| --- | --- | --- | --- |
| 1 | Static `inventory.yaml` | File configured | Target name present |
| 2 | Hostname patterns | `roles:` in `inventory.yaml` is non-empty | A pattern matches |
| 3 | Upstream inventory | The upstream profile has `inventory_tool` (planned, M2) | The upstream listed the target at startup or last refresh |
| 4 | Source of truth | `sot` configured | REST lookup succeeds, or a snapshot exists |

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

`netguard inventory import devices.csv [--out inventory.yaml]` reads a header row and the columns below. Column names are case-insensitive. Unrecognised columns are ignored with a warning.

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

## 4. Hostname patterns

Patterns live under `roles:` in `inventory.yaml` (`internal/inventory/patterns.go`), next to the devices they describe. They are not part of the policy file.

```yaml
roles:
  - match: "^(core|border)-"
    role: core
  - match: "^fw-"
    role: firewall
    vendor: panos
  - match: "^lab-"
    tags: [lab]
    site: lab
  - match: "-canary$"
    tags: [canary]
```

| Field | Type | Meaning |
| --- | --- | --- |
| `match` | RE2 regex | Applied to the lower-cased target name. Anchor explicitly. |
| `role`, `site`, `status`, `vendor` | string | Set if the pattern is the winning provider or the field is otherwise empty |
| `tags` | list | Always unioned |

Every matching pattern contributes. The first pattern that sets `role` wins `role`. A pattern that sets only `tags` never makes the target resolved on its own: a target matched only by a tags-only pattern remains `unknown` for `role`, and `device_roles: [unknown]` matches it. This keeps a stray `lab-` prefix from turning an unlisted device into a known one.

## 5. Upstream inventory provider

At startup, and every `refresh` interval (default 10m), the proxy calls the profile's `inventory_tool` and extracts names, tags and vendors through `inventory_map`. The result is a provider that knows exactly the devices that upstream can reach.

Sources per upstream: ntunes `list_devices` (names, tags, `device_type`), eos-mcp `get_router_list` (names, tags), junos `get_router_list` (names), upa `get_network_device_list` (names, `device_type`), mcp-telecom `list_devices`.

A record from this provider has `role: unknown` unless the upstream carries a role field, which none of the surveyed servers do. It exists so that `tags` such as ntunes `lab` can drive policy, and so that `targets_all_when_empty` and `@group` expansion have a device list to expand into.

## 6. Source of truth provider

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
| `snapshot` | Written by `netguard inventory sync`, which pages through every device and writes the static-file format with `source: snapshot`. |
| `stale_max_age` | If non-zero and the snapshot is older, resolution from it fails and the target is `unknown`. |

Lookup order inside the provider: cache, then live REST, then snapshot. A live failure (connection error, 5xx, timeout) is logged once per `cache_ttl` and the snapshot is used. Every record from the snapshot has `stale: true`, and every decision that used one carries `sot: stale` in its audit event. A 404 from a live lookup is a definitive `unknown` and is not overridden by the snapshot.

Platform mapping to `vendor`: NetBox `platform.slug` or `manufacturer.slug` are matched case-insensitively against `ios|iosxe|ios-xe|nxos|nx-os|eos|junos|panos|pan-os|fortios|srlinux|sr-linux|iosxr|ios-xr`. Anything else is `other`.

## 7. Unknown-target semantics

- A target is unknown when no provider resolved its name. The policy request carries it as `known: false`.
- `Evaluate` step 1 ([policy-schema.md](policy-schema.md#4-evaluation-order)): with `defaults.unknown_target: deny`, any unknown target denies the call for every class. With `unknown_target` unset, `WRITE_CONFIG` and `EXEC_ARBITRARY` are denied and every other class continues to the rules. With `allow`, the rules decide for every class.
- An unknown target has no role, so it never matches a `device_roles` rule, and a read to it is allowed only by a rule that matches on class alone (such as `reads-anywhere`). Operators who want reads to unknown targets denied set `unknown_target: deny`.
- The audit event lists the target in `targets[]` with an empty entry in `roles[]`; an `unknown_target` flag is planned (M4).
- A free-form `host` value that is an IP address is looked up as a name first; if no provider matches, it is `unknown`. There is no implicit IP-to-name resolution through DNS, because DNS is not a source of truth.

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

## 9. CLI

| Command | Effect |
| --- | --- |
| `netguard inventory import <csv> [--out file]` | Section 3.1 |
| `netguard inventory sync` | Section 6, writes the snapshot |
| `netguard inventory resolve <name>...` | Prints the record and which provider supplied each field; the debugging tool for "why was this denied as unknown" |
| `netguard inventory lint <file>` | Validates the static file |
