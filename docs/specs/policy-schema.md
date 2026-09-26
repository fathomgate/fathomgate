# Policy schema

Normative specification for the Fathomgate policy file and its test format. A policy is one YAML document evaluated by a pure function `Evaluate(policy, request) -> Decision`. Rules evaluate in order and the first match wins; there is no ranking by specificity. A request that matches no rule is denied. The words MUST, SHOULD and MAY are used as in RFC 2119.

This document describes what `internal/policy` (`types.go`, `load.go`, `evaluate.go`) and, for the test file format, `internal/policytest` implement. Where a feature is planned but not parsed, it is marked as such. Decision record: [ADR 0003](../adr/0003-yaml-policy-dsl-with-obligations.md).

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

   The step applies only to targets the request names. A request with no targets (an `INVENTORY_READ` that lists the upstream's own devices, a `LOCAL_ADMIN` call) has no unknown target, skips this step and records no trace entry for it. A call to a tool that declares a target parameter but arrives with no targets is to be refused before `Evaluate` by the normaliser with `default:bad_arguments` (open, M1-18). A target only a hostname pattern matches is unknown and is decided here: a pattern never makes a target known ([ADR 0031](../adr/0031-hostname-patterns-never-make-a-target-known.md), M1-34).

   Before this step, and before classification, `internal/gate` refuses a call over its per-call caps with `default:bad_arguments` ([profile-schema section 2.4](profile-schema.md#24-per-call-caps), M1-39): more than 64 commands (`maxCommandsPerCall`) or more than 256 target names and group selectors (`maxTargetsPerCall`), counted as sent. Such a call never becomes a `Request`, so a `Request` from the gate has at most 256 targets. The reason names the cap and nothing the call sent.
2. Session device cap. If `defaults.session.max_devices` is greater than 0 and `session.devices_touched + len(targets)` exceeds it: return deny with rule id `default:session.max_devices`. The gate passes a `devices_touched` that leaves out the request's own targets the session has already touched, so each device counts once (ADR 0026 notes, M1-39).
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

Reserved rule ids: `default:unknown_target`, `default:session.max_devices`, `default:session.max_pending`, `default:no-match`, and `default:bad_arguments` ([ADR 0026](../adr/0026-m1-policy-pipeline-at-dispatch.md)). `Evaluate` never returns `default:bad_arguments`: `internal/gate` produces it before `Evaluate` runs, for arguments that are not one JSON object (or give a key twice, or are not UTF-8), a target that is not a hostname or IP literal, a tool with a target source called with no target or with a tag or group selector ([profile-schema section 2.1](profile-schema.md#21-normalisation-rules)), and arguments that fail the profile's closed argument list ([ADR 0033](../adr/0033-closed-argument-list-per-tool.md), [profile-schema 2.3](profile-schema.md#23-closed-argument-list)). `fathomgate policy eval --profile` decides through the gate ([ADR 0035](../adr/0035-policy-test-cases-run-the-gate-path.md)), so it shows every one of these refusals as the proxy makes it, and a gate case in a `*.test.yaml` file asserts them (section 7.2). The proxy also produces `default:bad_arguments` itself for arguments over 64 KiB, before the gate runs, and `default:internal_error` for a call it could not decide (the gate failed); both carry class `EXEC_ARBITRARY` with `class_source` `proxy`, since the classifier never ran; `Evaluate` and `policy eval` never produce `default:internal_error` ([ADR 0026](../adr/0026-m1-policy-pipeline-at-dispatch.md), *Notes after acceptance*, M1-19). A policy rule may not use the `default:` prefix.

The agent never sees `Evaluate`'s own reasons for the `default:` ids, which name targets and counts. `internal/gate` gives each a fixed text: `default:unknown_target` is "target not in inventory", `default:session.max_devices` "this session would touch more devices than its cap allows", `default:session.max_pending` "this session already has as many held calls as its cap allows", `default:no-match` "no rule matched" (or "no policy loaded"). A rule with no `reason` is shown as "the policy does not allow this call". The one-line tool error shape is in [ADR 0026, "The deny tool error"](../adr/0026-m1-policy-pipeline-at-dispatch.md#the-deny-tool-error); profile-schema section 8.2 gets the row when the gate is wired (M1-19).

An `allow` is forwarded only when every obligation it carries is one M1 carries and enforces later: `redact`, `notify`, `require_ticket`, `canary_first`. Any other obligation stops the call with the verb `cannot run`: `dry_run`, `diff` and `timed_rollback` are named ("obligation dry_run cannot be met until change-safety drivers exist"); a name outside the vocabulary, which only a policy built in Go without `Validate` can hold, is not ("an obligation fathomgate does not know cannot be met").

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

Files named `*.test.yaml` are read by `fathomgate policy test [--profiles <dir>] [-v] <file>...`. The Python `policy_lint` skips them; behaviour is asserted here. A file holds two kinds of case ([ADR 0035](../adr/0035-policy-test-cases-run-the-gate-path.md)):

- A **class-given case** (`request.class`) gives the class and the resolved targets directly and runs `Evaluate` on them. It proves what the rules do with a class.
- A **gate case** (`request.arguments` or `request.arguments_json`) gives a `tools/call` as an agent sends it: the server, the tool and the raw arguments. It runs `internal/gate`, the steps `fathomgate serve --policy` runs on every call: parse, the per-call caps, normalise, classify (with the annotation raise), the closed argument list, targets, resolve, `Evaluate`. It proves the classification and the resolution as well as the rules. Its profile comes from the run's profile set, and its targets resolve through the file's `inventory`.

```yaml
policy: prod-approval.yaml        # relative to this file's directory, or absolute
inventory:                        # gate cases only: a path, or the document inline
  devices:
    - {name: core-rtr-01, role: core, tags: [prod]}
    - {name: lab-sw-01, role: access, tags: [lab]}
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

  - name: reload after a line break is not a read (gate case)
    request:
      server: upa
      tool: send_command_and_get_output
      arguments: {name: lab-sw-01, command: "show clock\nreload"}
    expect:
      effect: deny
      rule: no-exec
      class: EXEC_ARBITRARY
      tool_error: "fathomgate denied upa.send_command_and_get_output: rule no-exec (class EXEC_ARBITRARY): EXEC_ARBITRARY is denied: the call runs commands outside the read allow-list or outside configuration mode"

  - name: a key given twice (gate case)
    request:
      server: netdev-ssh-mcp
      tool: run_show_command
      arguments_json: '{"host": "lab-sw-01", "command": "show version", "host": "192.0.2.99"}'
    expect: {effect: deny, rule: default:bad_arguments, parse_error: duplicate_key}
```

### 7.1 File fields

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `policy` | string | yes | Path to the policy under test. Relative paths resolve against the test file's directory. |
| `inventory` | string or mapping | no | For gate cases. A path (relative to the test file) to an inventory in the [inventory-schema section 3](inventory-schema.md#3-static-file) format, read exactly as `serve --inventory` reads it (`internal/configset`: the `internal/configfile` owner and write-permission checks, a `.csv` refused, strict decoding), or the same document inline, decoded by the same strict decoder. It builds the same chain: a hostname pattern only enriches a listed device ([ADR 0031](../adr/0031-hostname-patterns-never-make-a-target-known.md)). Without it every name a gate case sends is unknown, as under `serve` without `--inventory`. Class-given cases ignore it. |
| `cases[]` | list | yes, non-empty | |
| `cases[].name` | string | yes, non-empty | |
| `cases[].request.server` | string | class-given: no; gate: yes | For a gate case, the profile's server key. It must name a profile in the run's set (7.3). |
| `cases[].request.tool` | string | class-given: no; gate: yes | For a gate case, the upstream's own tool name without the prefix, looked up exactly as the gate looks it up. |
| `cases[].request.class` | class | class-given: yes; gate: not allowed | |
| `cases[].request.targets[]` | list of target | class-given: no; gate: not allowed | `name`, `role`, `tags`, `site`, `known`. `known` defaults to `true`; set `known: false` to model an unresolved device. |
| `cases[].request.arguments` | mapping | gate: one of the two | The arguments object, encoded with `encoding/json` into the bytes the gate receives. Keys are strings; values are strings, numbers, booleans, null, lists and mappings. A non-string key, a merge key (`<<`), a tag, an anchor or an alias is a load error. An unquoted value must reach the gate as written: a decimal integer (no `+`, leading zero, `_`, `0x`, `0o` or `0b`), a decimal fraction with digits on both sides of the point, `true`, `false`, `null`, or a string that does not look like a number, a date or a time. Anything else (`0x1F`, `017`, `1e3`, `2026-09-25`, `12:30:00`, `True`, `~`, `.inf`) is a load error that names the line and says to quote the value or use `arguments_json`. YAML double-quoted escapes (`\n`, `\r`, `\v`, `\u2028`, `\u200b`) carry control and look-alike characters. `{}` is a call with no arguments. |
| `cases[].request.arguments_json` | string | gate: one of the two | The arguments exactly as the agent's bytes: for a key given twice, trailing data, a top-level array or JSON cut short. Invalid UTF-8 cannot be written in a YAML file; the `internal/gate` tests cover it. |
| `cases[].request.annotations` | mapping | gate: no | `readOnlyHint` and `destructiveHint`, booleans; absent is none. They can only raise a class (invariant 3). |
| `cases[].request.session` | object | no | `devices_touched`, `pending_holds`. Default 0. A gate case's targets all count as new devices. |
| `cases[].expect.effect` | effect | yes | For a gate case, what `Evaluate` returned, or `deny` for a refusal before it: a `hold` stays `hold`, as the decision log line records it. |
| `cases[].expect.rule` | string | class-given: no; gate: yes | When present, the decision's rule id MUST equal it. Required on a gate case: the gate fails closed, so `effect: deny` alone would pass for any refusal. |
| `cases[].expect.obligations` | list | no | When present, MUST equal the decision's obligations as a set (order-insensitive). |
| `cases[].expect.class` | class | gate only | The final class, after the downgrade, reclassify and the annotation raise. |
| `cases[].expect.class_source` | string | gate only | `profile`, `capability_table`, `fallback`, `annotation_raise`, `downgrade` or `reclassify`. |
| `cases[].expect.targets` | list | gate only | The target names after validation, exactly as the upstream receives them, in order, repeats removed. `[]` asserts none. |
| `cases[].expect.unknown_target` | boolean | gate only | The decision log line's `unknown_target`. |
| `cases[].expect.parse_error` | string | gate only | The log line's code: `invalid_utf8`, `invalid_json`, `not_object`, `duplicate_key`, `trailing_data`, `too_many_commands`, `too_many_targets`. Only with `rule: default:bad_arguments`. |
| `cases[].expect.unnamed_args`, `malformed_args` | list | gate only | The log line's lists, compared as sets (the log line keeps at most 8 names of at most 64 bytes). Only with `rule: default:bad_arguments`. `[]` asserts none. |
| `cases[].expect.forwarded` | boolean | gate only | Whether `serve` in this milestone sends the call upstream: `false` for a `hold`, and for an `allow` carrying `dry_run`, `diff` or `timed_rollback`, in M1. |
| `cases[].expect.tool_error` | string | gate only | The one line the agent sees ([ADR 0026, "The deny tool error"](../adr/0026-m1-policy-pipeline-at-dispatch.md#the-deny-tool-error)), compared exactly. `""` asserts that there is none. Use it where the text is the point; `rule` everywhere else. |

Unknown keys are errors. A case fails on the first mismatch in the order effect, rule, class, class_source, obligations, targets, unknown_target, parse_error, unnamed_args, malformed_args, forwarded, tool_error, and the message names what was got and what was wanted.

### 7.2 Load errors

A file that breaks one of these rules does not run; `policy test` exits 2 and names the case. Each is a case that could never pass, or could pass for the wrong reason:

- a case with both `class` and an arguments field, or neither; both `arguments` and `arguments_json`;
- `targets` or `annotations` on the wrong kind of case; a gate-only `expect` field on a class-given case;
- a gate case with no `server`, `tool` or `expect.rule`;
- a gate case whose `server` has no profile in the run's set: `serve` would give that server an empty profile, which denies every call carrying arguments with `default:bad_arguments`, so a deny case would pass for any reason;
- a gate case whose arguments are over 64 KiB: the proxy refuses such a call before the gate runs, so the gate path cannot say what `serve` does;
- `parse_error`, `unnamed_args` or `malformed_args` with a rule other than `default:bad_arguments`; a `parse_error` or `class_source` outside its vocabulary;
- an `inventory` that `serve --inventory` would refuse;
- an unquoted value in `arguments` that would reach the gate as something other than what is written (7.1);
- a YAML anchor (`&`) or alias (`*`) anywhere in the file, a case name over 256 bytes, or a test file or policy over 16 MiB: aliases let a few kilobytes repeat a large value thousands of times into the output.

`default:internal_error` and the proxy's 64 KiB refusal happen outside the gate and are pinned by the `internal/proxy` tests.

### 7.3 Profiles

A gate case never names a profile file. `policy test` uses the profiles built into the binary, the set `serve` uses without `--profiles`; `policy test --profiles <dir>` replaces that set for the whole run, never merging with it, loaded by the same function `serve --profiles` uses (`internal/configset`: every top-level `*.yaml`, strict, validated, each file named after its server key, the `configfile` checks). So the shipped suites prove the shipped binary's profiles, and an operator can prove a patched profile set against them before `serve --profiles`.

### 7.4 Output

`policy test` prints one `PASS` or `FAIL` line per case and a count. It prints no argument value other than validated target names, and it quotes a case name, argument name, target name, rule id, trace note or path that is not printable ASCII (`internal/termsafe`, the one helper the CLI and the runner share): a suite that carries injection inputs is itself injection text. An error is printed through `termsafe.Text`, which escapes every C0 control except line feed and tab, DEL, C1 controls, the line and paragraph separators and the bidirectional formatting characters. `-v` adds, for a failing case, the class and `class_source` of a gate case and the rule trace. Exit 0 when every case passes, 1 when any fails, 2 when a file cannot be loaded.

`fathomgate policy eval --profile <file> --tool <tool> (--arg k=v ... | --arguments-json '<json>')` decides one call through the same function (`gate.Explain`), with the profile as a set of one, so an operator can reproduce a gate case with one command. It reads `--profile` and `--inventory` as `serve` reads a profile and an inventory (`internal/configset`: the `configfile` checks, the size cap, a profile file named after its server key, no CSV). `--class` and `--target` are usage errors with `--profile`. Its output adds `class_source`, `parse_error`, `unnamed_args` and `malformed_args` when set, `forwarded`, and the tool error line; `--json` adds a `gate` object with the same fields.

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

| File | Purpose | Class-given cases | Gate cases |
| --- | --- | --- | --- |
| `policies/examples/read-only.yaml` | Allow the three read classes, deny everything else. The M1 announcement policy. | 12 | 76 |
| `policies/examples/lab-open.yaml` | Writes allowed on `lab`-tagged devices; everything else read-only. Until M3 its `lab-writes-free` rule carries no `dry_run` or `diff`: an `allow` with an obligation fathomgate cannot meet is not forwarded ([ADR 0026](../adr/0026-m1-policy-pipeline-at-dispatch.md)), so with them every lab write would be refused. They return in M3. Lab devices must be listed statically by name (inventory-schema section 4). | 13 | 22 |
| `policies/examples/prod-approval.yaml` | The example in section 1. Safe to load before M3: its holds, and its `lab-writes-free` allows (which carry `dry_run` and `diff`), are not forwarded until M3 (ADR 0026). | 20 | 15 |

Each policy has two suites beside it: `<name>.test.yaml` (class-given) and `<name>.gate.test.yaml` (gate cases, with the inventory inline). Run them all with `make policy-test` or `fathomgate policy test policies/examples/*.test.yaml`; `go test ./internal/policytest` runs them too (`TestRepoExamplePolicies`), and `cmd/fathomgate` `TestPolicyEvalMatchesGateCases` checks that `policy eval --profile` gives every gate case's decision, rule and class.

Each gate suite carries cases for the M1 rows of the [test matrix](../testing/test-matrix.md), from the command the agent sends: row 3 (`show ip bgp summary`, `READ_OPERATIONAL`, `reads-anywhere`, through netdev-ssh-mcp `run_show_command` and downgraded through upa `send_command_and_get_output`, eos-mcp `run_command` and ntunes `send_command`), row 4 (`reload`, `EXEC_ARBITRARY`, `no-exec`, with the tool error that names the rule) and row 6 (an unlisted host, `default:unknown_target`, for reads, writes and exec). `read-only.gate.test.yaml` also carries the PR #152 injection inputs (line breaks, Unicode separators and look-alikes, shell-quoted options, config dumps through short forms) and the PR #154 attacker-chosen names under an inventory with active hostname patterns; the three suites together carry the closed argument list, the parse and cap refusals, the annotation raise, config lines that leave the session, and the M1 fail-closed rows (`hold` and `cannot run`). These are tier 1 evidence: a row is validated only against the named real upstream server (M1-28).
