# Policy schema

Normative specification for the Fathomgate policy file and its test format. A policy is one YAML document evaluated by a pure function `Evaluate(policy, request) -> Decision`. Rules evaluate in order and the first match wins; there is no ranking by specificity. A request that matches no rule is denied. The words MUST, SHOULD and MAY are used as in RFC 2119.

This document describes what `internal/policy` (`types.go`, `load.go`, `evaluate.go`, `testfile.go`) implements. Where a feature is planned but not parsed, it is marked as such. Decision record: [ADR 0003](../adr/0003-yaml-policy-dsl-with-obligations.md).

## 1. Example

`policies/examples/prod-approval.yaml`:

```yaml
version: 1
defaults:
  unknown_target: deny
  session:
    max_devices: 5
    max_pending: 2
rules:
  - id: reads-anywhere
    match: { class: [READ_OPERATIONAL, READ_CONFIG, INVENTORY_READ] }
    effect: allow
  - id: lab-writes-free
    match: { class: [WRITE_CONFIG], device_tags: [lab] }
    effect: allow
    obligations: [dry_run, diff]
  - id: prod-core-needs-approval
    match: { class: [WRITE_CONFIG], device_roles: [core, border] }
    effect: hold
    obligations: [dry_run, diff, timed_rollback]
    approval: { ttl: 15m, approver_must_differ: true }
  - id: fleet-cap
    match: { class: [WRITE_CONFIG] }
    when: { targets_count: { gt: 3 } }
    effect: deny
    reason: "fan-out above 3 devices needs a change ticket"
  - id: no-exec
    match: { class: [EXEC_ARBITRARY] }
    effect: deny
```

Because the first match wins, `lab-writes-free` fires for four `lab`-tagged devices before `fleet-cap` is reached. Write the narrow rules first and the broad caps after, or move `fleet-cap` above `lab-writes-free` to cap lab fan-out too.

## 2. Top-level fields

The loader is strict: an unknown key at any level is an error.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `version` | integer | yes | Schema version. Only `1` is accepted. |
| `defaults` | object | no | Behaviour applied before and after the rules. See 2.1. |
| `rules` | list of rule | yes | Ordered. MUST NOT be empty. |

Hostname patterns are not part of the policy file. They live under `roles:` in `inventory.yaml`; see [inventory-schema.md](inventory-schema.md#4-hostname-patterns).

### 2.1 `defaults`

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `unknown_target` | `allow`, `deny`, or unset | `deny` | What happens when any target the request names is unknown (no inventory provider resolved it). `deny`, or the key left unset, denies every class ([ADR 0032](../adr/0032-unset-unknown-target-denies-every-class.md)); the loader fills an unset value in as `deny`. `allow` lets the rules decide for every class. `hold` is rejected at load. There is no class-scoped form. A request with no targets is not affected (section 4, step 1). `policy-lint` warns on an explicit `allow`, and `serve` will log the same warning at startup (M1-19). |
| `session.max_devices` | integer, 0 or more | `0` (unlimited) | Cap on distinct devices one session may touch, counting the targets of the request being evaluated. |
| `session.max_pending` | integer, 0 or more | `0` (unlimited) | Cap on simultaneously pending holds in one session. |

There is no default effect per class. A request no rule matches is denied (section 4, step 5).

## 3. Rule

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `id` | string, non-empty | yes | Unique in the file. MUST NOT start with `default:`, which is reserved for decisions made by defaults. Appears in every decision, trace, error and audit event. |
| `match` | matcher | no | All keys present MUST hold (logical AND). An empty or absent `match` matches every request. |
| `when` | condition | no | Numeric conditions. |
| `effect` | `allow`, `hold` or `deny` | yes | The decision if the rule matches. |
| `reason` | string | no | Returned to the agent and written to audit. |
| `obligations` | list of obligation | no | Side conditions the proxy must honour when forwarding. Accepted on any effect; meaningful on `allow` and `hold`. |
| `approval` | approval | no | Only valid when `effect` is `hold`; the loader rejects it otherwise. |

### 3.1 `match` keys

These are the only match keys. Each holds a list; an empty list matches everything.

| Key | Matches against | Semantics |
| --- | --- | --- |
| `class` | `request.class` | Request class MUST be in the list. Class names as spelled in [classification.md](classification.md); the loader also accepts lower case and `-` for `_`. |
| `servers` | `request.server` | Any pattern MUST match. Shell-style globs (`path.Match`): `*`, `?`, `[...]`. |
| `tools` | `request.tool` | Any pattern MUST match either the bare tool name (`get_config`) or the prefixed form (`netdev-ssh-mcp.get_config`). Globs as above. |
| `device_roles` | every target's `role` | Every target's role MUST be in the list. A request with no targets does not match. |
| `device_tags` | every target's `tags` | Every target MUST carry at least one tag in the list. A request with no targets does not match. |

"Every target" is deliberate: a fan-out mixing one `lab` device and one `core` device does not match `device_tags: [lab]`, so it cannot inherit the lab rule. Matchers are equality, set membership and glob only; there is no regex in `match`.

### 3.2 `when` conditions

| Key | Operand | Operators |
| --- | --- | --- |
| `targets_count` | `len(request.targets)` | `gt`, `gte`, `lt`, `lte`, `eq`. Every operator given MUST hold. At least one MUST be given. `gt` MUST be less than `lt` when both are given. |

`targets_count` is the only condition today. Session counters are compared by `defaults.session`, not by `when`.

### 3.3 `obligations`

The closed vocabulary. The loader rejects anything else, so a typo cannot silently drop a safeguard.

| Obligation | Meaning |
| --- | --- |
| `dry_run` | The driver's `Prepare` MUST run and succeed before any apply. |
| `diff` | The diff from `Prepare` MUST be attached to the pending record or the audit event. |
| `timed_rollback` | `Apply` MUST use the platform's timed rollback or the proxy watchdog. |
| `redact` | Output redaction is mandatory for this call regardless of class defaults. |
| `canary_first` | For a multi-target write, the `canary`-tagged target MUST execute and be confirmed before the rest. |
| `require_ticket` | The request MUST reference a change ticket before it executes. |
| `notify` | The proxy MUST send a notification when the call is held or executed. |

Enforcement of `dry_run`, `diff`, `timed_rollback` is specified in [change-safety-drivers.md](change-safety-drivers.md). `redact`, `canary_first`, `require_ticket` and `notify` are accepted by the loader and carried in the decision; their enforcement lands with M2 to M4.

### 3.4 `approval`

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `ttl` | duration in Go syntax (`15m`, `1h30m`, `90s`) | `0` (the approval store's default) | Time from PENDING to EXPIRED. MUST NOT be negative. |
| `approver_must_differ` | boolean | `false` | Approver identity MUST differ from the requesting principal. |

## 4. Evaluation order

`Evaluate` is deterministic and has no side effects. Session counters are inputs on the request, supplied by the proxy. A nil policy denies with rule id `default:no-match` and reason `no policy loaded`.

1. Unknown targets. If any target has `known: false`:
   - if `defaults.unknown_target` is `allow`: record an unmatched trace entry and continue, for every class.
   - otherwise (`deny` or unset, for every class; ADR 0032): return deny with rule id `default:unknown_target`. Rules do not run. `Evaluate` treats any value other than `allow` as `deny`, so a policy built without the loader also fails closed.

   The step applies only to targets the request names. A request with no targets (an `INVENTORY_READ` that lists the upstream's own devices, a `LOCAL_ADMIN` call) has no unknown target, skips this step and records no trace entry for it. A call to a tool that declares a target parameter but arrives with no targets is to be refused before `Evaluate` by the normaliser with `default:bad_arguments` (open, M1-18). A target a hostname pattern matches is known and never reaches this step (open until the ADR 0031 change lands, M1-34).
2. Session device cap. If `defaults.session.max_devices` is greater than 0 and `session.devices_touched + len(targets)` exceeds it: return deny with rule id `default:session.max_devices`.
3. Rules, in file order. For each rule, test `match` then `when`. The first rule that matches supplies `effect`, `id`, `reason`, `obligations` and `approval`. Later rules are not evaluated. There is no specificity ranking and no precedence between effects; order in the file is the only priority.
4. Pending cap. If the winning effect is `hold`, `defaults.session.max_pending` is greater than 0, and `session.pending_holds` is already at or above it: the decision becomes deny with rule id `default:session.max_pending` and `approval` is cleared. The rule's obligations are kept in the decision.
5. Implicit deny. If no rule matched: return deny with rule id `default:no-match` and reason `no rule matched`.

The trace lists every check performed, in order, with `matched` and a note explaining the first failing matcher for rules that did not match.

## 5. Decision

```go
type Decision struct {
    Effect      Effect       // "allow" | "hold" | "deny"
    RuleID      string       // a rule id, or one of the default: ids
    Reason      string
    Obligations []string     // subset of the obligation vocabulary
    Approval    *Approval    // non-nil only when Effect == "hold"
    Trace       []TraceEntry // {rule_id, matched, note} for every check
}
```

Reserved rule ids: `default:unknown_target`, `default:session.max_devices`, `default:session.max_pending`, `default:no-match`, and `default:bad_arguments`. `Evaluate` never returns `default:bad_arguments`. The gate produces it before `Evaluate` runs, in two cases: the arguments are not a JSON object ([ADR 0026](../adr/0026-m1-policy-pipeline-at-dispatch.md) step 1), or they fail the profile's closed argument list ([ADR 0033](../adr/0033-closed-argument-list-per-tool.md), [profile-schema 2.2](profile-schema.md#22-closed-argument-list)). `fathomgate policy eval --profile` shows the second case the same way (`policy.RuleBadArguments`).

`expired` is a fourth decision word that appears in the audit log and console. It is never returned by `Evaluate`; it is produced by the approval store when a hold's TTL elapses.

## 6. Request

The request `Evaluate` receives, after normalisation, classification and role resolution.

| Field | Type | Meaning |
| --- | --- | --- |
| `server` | string | Profile `server` name. |
| `tool` | string | Bare or prefixed tool name. |
| `class` | class | One of the seven classes. |
| `targets[]` | list of target | `name`, `role`, `tags[]`, `site`, `known`. `known` is false when no provider resolved the name. |
| `session.devices_touched` | integer | Distinct devices already touched in this session. |
| `session.pending_holds` | integer | Holds currently pending in this session. |

## 7. Test file format

Files named `*.test.yaml` are read by `fathomgate policy test <file>...`. The Python `policy_lint` checks shape only; behaviour is asserted here.

```yaml
policy: prod-approval.yaml        # relative to this file's directory, or absolute
cases:
  - name: core write is held for approval
    request:
      server: junos-mcp-server
      tool: load_and_commit_config
      class: WRITE_CONFIG
      targets: [{name: core-rtr-01, role: core, tags: [prod]}]
    expect: {effect: hold, rule: prod-core-needs-approval, obligations: [dry_run, diff, timed_rollback]}

  - name: unknown host is denied even for a read
    request:
      server: netdev-ssh-mcp
      tool: run_show_command
      class: READ_OPERATIONAL
      targets: [{name: 10.99.99.99, known: false}]
    expect: {effect: deny, rule: default:unknown_target}

  - name: a third pending hold is refused
    request:
      server: junos-mcp-server
      tool: load_and_commit_config
      class: WRITE_CONFIG
      targets: [{name: core-rtr-02, role: core}]
      session: {pending_holds: 2}
    expect: {effect: deny, rule: default:session.max_pending}
```

### 7.1 File fields

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `policy` | string | yes | Path to the policy under test. Relative paths resolve against the test file's directory. |
| `cases[]` | list | yes, non-empty | |
| `cases[].name` | string | yes, non-empty | |
| `cases[].request.server` | string | no | |
| `cases[].request.tool` | string | no | |
| `cases[].request.class` | class | yes | Tests supply the class directly; classification has its own tests. |
| `cases[].request.targets[]` | list of target | no | `name`, `role`, `tags`, `site`, `known`. `known` defaults to `true`; set `known: false` to model an unresolved device. |
| `cases[].request.session` | object | no | `devices_touched`, `pending_holds`. Default 0. |
| `cases[].expect.effect` | effect | yes | |
| `cases[].expect.rule` | string | no | When present, the decision's rule id MUST equal it. |
| `cases[].expect.obligations` | list | no | When present, MUST equal the decision's obligations as a set (order-insensitive). |

Unknown keys are errors. A case fails on the first mismatch in the order effect, rule, obligations, and the message names what was got and what was wanted.

## 8. Loader requirements

Implemented in `load.go`:

- Reject unknown keys at every level (strict YAML).
- Reject `version` other than `1`.
- Reject `defaults.unknown_target` that is not `allow` or `deny` (including `hold`); fill an unset value in as `deny` (ADR 0032).
- Reject negative `session.max_devices` or `session.max_pending`.
- Reject an empty `rules` list.
- Reject a rule with an empty id, a duplicate id, or an id starting with `default:`.
- Reject an invalid `effect` or `class`.
- Reject a `tools` or `servers` entry that is not a valid glob.
- Reject an obligation outside the vocabulary in 3.3.
- Reject `approval` on a rule whose effect is not `hold`, and a negative `approval.ttl`.
- Reject `when.targets_count` with no bound, or with `gt` at or above `lt`.

Planned, not yet implemented: reload on SIGHUP with the previous policy kept on validation failure, and a policy file hash in every audit event.

## 9. Example policies shipped

| File | Purpose | Test cases |
| --- | --- | --- |
| `policies/examples/read-only.yaml` | Allow the three read classes, deny everything else. The M1 announcement policy. | 12 |
| `policies/examples/lab-open.yaml` | Writes allowed on `lab`-tagged devices; everything else read-only. Until M3 its `lab-writes-free` rule carries no `dry_run` or `diff`: an `allow` with an obligation fathomgate cannot meet is not forwarded ([ADR 0026](../adr/0026-m1-policy-pipeline-at-dispatch.md)), so with them every lab write would be refused. They return in M3. Lab devices must be listed statically by name (inventory-schema section 4). | 13 |
| `policies/examples/prod-approval.yaml` | The example in section 1. Safe to load before M3: its holds, and its `lab-writes-free` allows (which carry `dry_run` and `diff`), are not forwarded until M3 (ADR 0026). | 20 |

Run them all with `make policy-test` or `fathomgate policy test policies/examples/*.test.yaml`.

Each suite carries cases for the M1 rows of the [test matrix](../testing/test-matrix.md): row 3 (`show ip bgp summary`, `READ_OPERATIONAL`, `reads-anywhere`), row 4 (`reload`, `EXEC_ARBITRARY`, `no-exec`, through netdev-ssh-mcp, upa and eos-mcp) and row 6 (unknown host, `default:unknown_target`, for writes and exec). A test case takes its class as given: `server` and `tool` name the call but are not classified, and a case cannot carry arguments or commands. The classification half of each row is pinned by the tier 1 tests in `internal/classify`, and `fathomgate policy eval --profile … --arg command=…` shows it for one call.
