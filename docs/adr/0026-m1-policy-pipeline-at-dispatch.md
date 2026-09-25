# ADR 0026: The M1 policy pipeline at `Proxy.dispatch`

- Status: accepted
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer), accepted by the maintainer 2026-09-25 with the answers under *Decisions on the open questions*; proposed by the orchestrator for M1 (board task M1-01); owners mcp-protocol-engineer (wiring) and policy-engineer (stages); reviewers security-reviewer, go-reviewer, design-guardian (the deny text)
- Supersedes: [ADR 0022](0022-internal-proxy-export-surface.md), for the export table only (restated below); ADR 0012 and ADR 0016 stand

## Context

M0 forwards every call. [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md) left one seam for the pipeline, the unexported `Proxy.dispatch`, and said the M1 record decides whether a pipeline interface is exported. [ADR 0022](0022-internal-proxy-export-surface.md) froze the export list until a record supersedes it. The stages already exist as stand-alone packages behind CLI commands: `internal/classify` (`Normalize`, `Classify`, `ClassifyCommand`, profiles), `internal/inventory` (`Chain`, static file, hostname patterns), `internal/policy` (`Load`, `Evaluate`, test runner). Nothing calls them from the proxy.

M1's exit criteria ([PLAN.md](../PLAN.md#milestones)) and [ROADMAP stage 2](../../ROADMAP.md#2-say-no-m1--next) need four things the stages do not decide on their own: the order they run in and what each one sees; what the agent gets back on `deny` (PRD R11: a tool error that names the rule id, so the agent can self-correct); what happens to a `hold` or to an obligation (`dry_run`, `diff`, `timed_rollback`) when the approval store and the `ChangeSafety` drivers do not exist until M3; and where redaction (M2) and the audit chain (M4) attach, so those milestones add a sink instead of reordering the pipeline. Invariants 1 to 4, 6 and 7 of [CLAUDE.md](../../CLAUDE.md#invariants-you-must-not-break) constrain every answer.

Two facts from M0 shape the seam. A call reaching `dispatch` already carries both negotiated eras, the agent transport and the principal (T0.30); the era label can be wrong after an `initialize`-only reconnect (T0.47, carried to M1 as M1-06), so it must be fixed before anything records it. And `newCall` has already cleared any `inputResponses` the agent sent without fathomgate's `requestState`, so no stage sees agent-supplied answers.

## Decision

We will run one fixed pipeline inside `Proxy.dispatch`, before `forward`, implemented by a new package `internal/gate` that the proxy reaches through one small exported interface, and fail closed on every decision M1 cannot carry out.

### Order

For every `tools/call`, first calls and MRTR retries alike:

| Step | Stage | Input | Output | Fails closed as |
| --- | --- | --- | --- | --- |
| 1 | Parse | `call.arguments` (raw JSON) | `map[string]any` | `deny`, rule `default:bad_arguments` (not JSON, or not an object) |
| 2 | Normalise | profile for `call.up.Server`, tool, arguments | `targets[]` (expanded per inventory-schema 8, CSV only in M1), `commands[]`, `config_payload` | a missing profile means the fallback classifier (step 3), not an error |
| 3 | Classify | profile, tool, normalised arguments, the tool's annotations from the upstream `tools/list` | class, `class_source` (`profile`, `capability_table`, `fallback`, `annotation_raise`, `downgrade`, `reclassify`) | unknown means `EXEC_ARBITRARY` (classification spec section 3) |
| 4 | Resolve | each target name | `policy.Target{name, role, tags, site, known}` through the inventory `Chain` | a name no resolver knows is `known: false` |
| 5 | Session counters | the call's counter key | `policy.Session{devices_touched, pending_holds}` | not a failure; the counters are proxy state, read before and updated after |
| 6 | Evaluate | `*policy.Policy`, `policy.Request` | `policy.Decision` | nil policy denies with `default:no-match` (policy-schema 4) |
| 7 | Enforce | `Decision` | forward, or a tool error | see *What M1 does with each effect* |
| 8 | Record | the call, its classification, targets, `Decision`, outcome | one decision log line (M1), one audit event (M4) | a record that cannot be written is logged at Error; in M4 the audit writer decides, not this record |
| 9 | Redact (M2) | the upstream result | the result the agent sees | position fixed here; the stage is wired in M2 |

Steps 1 to 6 do no I/O except the inventory lookup, which in M1 is in-memory (static file and patterns). `Evaluate` stays pure (invariant 1): the gate reads the counters and passes them in. Annotations can only raise a class (invariant 3, ADR 0010). The upstream's tool list and annotations are untrusted data (invariant 7); they are read once at `proxy.New`, as today, and never re-read from a call.

An MRTR retry (a call with fathomgate's `requestState`) runs the whole pipeline again on its tool and arguments, which the sealed state already binds to the first call. A policy change between the two calls therefore applies to the retry. The cost is one more evaluation per round, well inside the PRD's 5 ms p99 budget.

### What M1 does with each effect

| Effect from `Evaluate` | Obligations | M1 behaviour | Agent sees |
| --- | --- | --- | --- |
| `allow` | none, or only `redact`, `notify`, `require_ticket`, `canary_first` | forward as M0 does | the upstream result |
| `allow` | any of `dry_run`, `diff`, `timed_rollback` | **not forwarded**: nothing in M1 can meet them (M3 drivers) | a tool error, rule id of the matching rule, reason `obligation <name> cannot be met until change-safety drivers exist` |
| `hold` | any | **not forwarded** and no pending record (M3 store) | a tool error, rule id of the holding rule, the fixed hold reason below |
| `deny` | any | not forwarded | a tool error naming the rule id and its reason |

The effect `Evaluate` returned is what is recorded: a `hold` is logged as `hold`, not rewritten to `deny`, so the M3 change is to the enforcement column only. Obligations fathomgate cannot yet enforce (`redact` before M2, `notify`, `require_ticket`, `canary_first` before M4) are carried in the log line and not enforced; `serve` warns once at start for each such obligation that appears in the loaded policy (ADR 0027). Only `dry_run`, `diff` and `timed_rollback` gate a write, because they are the ones whose absence changes a device.

### The deny tool error

A call that is not forwarded gets a `CallToolResult` with `isError: true`, never a JSON-RPC error, so the agent's model sees it and can try something safer (PRD R11). One text content block, fathomgate's own text only, first line fixed so it can be parsed:

```text
fathomgate denied netdev-ssh-mcp.run_show_command: rule no-exec (class EXEC_ARBITRARY): command did not pass the read allow-list
```

There is one shape: `fathomgate <denied|cannot run|held> <server>.<tool>: rule <rule_id> (class <CLASS>): <reason>`. The verb is `denied` for `deny`, `cannot run` for an `allow` whose obligations cannot be met, and `held` for `hold`. A `hold` carries the maintainer's fixed reason (decision 3):

```text
fathomgate held junos.load_and_commit_config: rule prod-core-needs-approval (class WRITE_CONFIG): needs approval, and approvals aren't available yet, so this call was not run.
```

One parser reads the verb and the rule id from every refusal. design-guardian reviews the exact copy in M1-18 and M1-19. For a `deny`, the reason is the policy author's `reason`, or fathomgate's fixed text for a `default:` rule. Nothing from the upstream and no argument value is quoted: the agent already has its arguments, and a target name, command or payload echoed back is a place for injected text to ride. For an unknown target the text adds `; target not in inventory` without naming it. The trace is **not** sent to the agent (it describes the whole policy); it goes to the decision log line, and to the audit event in M4.

The error-table row "Policy denials arrive in M1 as tool errors that name the rule id" in [profile-schema 8.2](../specs/profile-schema.md#82-errors-toward-the-agent) becomes a full row with this text in the wiring PR.

### Reserved rule ids

Added beside the four in policy-schema section 5, produced by the gate, never by `Evaluate`: `default:bad_arguments` (step 1). The two fail-closed rows keep the id of the rule that matched, because that rule is what the operator must change.

### The decision log line (M1) and the audit seam (M4)

`--audit` stays refused until M4 (ADR 0027). In M1 the record step writes one `slog` line per call at Info, `msg=decision`, with: `server`, `tool`, `class`, `class_source`, `targets` (names), `roles`, `unknown_target` (bool), `decision` (the effect `Evaluate` returned), `rule_id`, `reason` (the policy author's or fathomgate's fixed text), `obligations`, `forwarded` (bool), `agent_protocol`, `agent_era`, `upstream_protocol`, `upstream_era`, `transport`, `principal`, `session_id` (fathomgate's short session hash, as the eviction log uses), and, only when set, `parse_error` (a fixed code: `invalid_utf8`, `invalid_json`, `not_object`, `duplicate_key`, `trailing_data`), `unnamed_args` and `malformed_args` (argument names, at most 8, each cut at 64 bytes); `trace` at Debug only. `forwarded`, the protocol and era fields, `parse_error`, `unnamed_args` and `malformed_args` are log-only in M1: they have no field in audit-event-schema section 2, and M4 adds each to its section 2.1 or drops it before the audit sink changes. No argument value, command or result text is logged; the command is represented by the class. The line is the event M4 will write, field for field where [audit-event-schema section 2](../specs/audit-event-schema.md#2-call-record) already names one, so M4 swaps the sink behind the same record step.

### Where the code lives, and what is exported

`internal/gate` owns steps 1 to 6 and the text of the tool error. It imports `classify`, `inventory` and `policy`; `internal/proxy` imports none of them. The proxy owns steps 5 (the counters, because it owns sessions), 7 and 8.

`internal/proxy` gains, in `Options`, one field:

```go
// Gate decides every tools/call before it is forwarded. nil keeps M0 pass-through.
Gate Gate
```

with an exported interface and two plain structs:

```go
type Gate interface {
    Decide(ctx context.Context, in CallInfo) Verdict
}
type CallInfo struct { Server, Tool string; Arguments json.RawMessage; Annotations *mcp.ToolAnnotations;
    AgentEra, UpstreamEra, Transport, Principal, Session string; DevicesTouched, PendingHolds int }
type Verdict struct { Forward bool; Effect, RuleID, Class, ClassSource string; Targets []string; Record []slog.Attr; Error string }
```

The field lists are a sketch: the owning task (M1-18) fixes them, keeps them to plain data (no `policy` or `classify` types cross the seam), and records the final table. `Verdict` returns the counted targets so the proxy updates the session counters only for a forwarded call. A nil `Gate` keeps today's pass-through, so every M0 test stands unchanged and `serve --no-policy` behaves as v0.1.0 ([ADR 0027](0027-serve-policy-inventory-profiles-flags.md)).

This record replaces ADR 0022's table with that table plus `Options.Gate`, `Gate`, `CallInfo` and `Verdict`; ADR 0022's rules (a new export needs a new record; `go doc ./internal/proxy` must match) carry over unchanged.

### Session counters

`devices_touched` and `pending_holds` are counted per counter key: the agent session for a 2025-11-25 agent (stdio or HTTP), and for a 2026-07-28 agent, which has no session, the principal over HTTP or the process on stdio. `pending_holds` is always 0 in M1. Counters live in memory and reset with the process.

## Consequences

### Positive

- One order, written down, for every stage M1 to M4 adds; M2 and M4 plug into steps 9 and 8 without moving anything.
- Every refused call names a rule the operator can find in the policy file, and the agent gets enough to retry differently without seeing the policy.
- A policy written for M3 (`prod-approval`) is safe to load in M1: holds and change-safety obligations stop the call instead of letting it through.
- `internal/proxy` stays free of policy types, so the gate is tested without a transport and the proxy without a policy.

### Negative

- Under the fail-closed rule, `lab-open`'s `lab-writes-free` rule (obligations `dry_run`, `diff`) would refuse every lab write in M1. The example changes instead (decision 1, board task M1-21): lab writes carry no `dry_run` or `diff` until M3, with a comment in the file saying the obligations return in M3.
- Four new exports and a superseded ADR 0022.
- A deny text with a fixed first line is an interface agents and scripts will parse; changing it later needs a record.

### Neutral

- `Evaluate`, `policy.Decision` and the class and obligation sets do not change.
- The decision log line goes to stderr like every other fathomgate log; with `--listen` nothing new reaches stdout.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Call `classify`, `inventory` and `policy` directly from `internal/proxy` | Couples the transport package to every stage and makes each proxy test build a policy; the seam ADR 0012 left would disappear into `dispatch`. |
| Return a JSON-RPC error on `deny` | Most hosts show JSON-RPC errors to the user, not to the model, so the agent cannot self-correct; PRD R11 asks for a tool error. |
| Put the rule trace in the tool error | Tells the agent the order and shape of every rule, which is a map for getting around them. The operator has it in the log. |
| Forward an `allow` whose obligations cannot be met, with a warning | A lab write with `dry_run` would reach the device without a dry run. Nothing reaches a device that the rules did not allow as written. |
| Refuse to load a policy that can produce `hold` or needs `dry_run` until M3 | Safe, but makes the shipped `prod-approval` and `lab-open` examples unusable for their read and deny rules in M1, which is the announcement's story. |
| Structured error in `structuredContent` or `_meta` | `structuredContent` is validated against the upstream tool's `outputSchema` by some clients; fathomgate sends no `_meta` of its own to the agent today. A `_meta` key can be added later compatibly (decision 2). |
| Evaluate once per MRTR exchange and let retries through | A policy reload between the prompt and the answer would not apply, and the saving is microseconds. |

## Decisions on the open questions

Accepted by the maintainer, Josh Scott, on 2026-09-25, with these answers:

1. **Fail closed on unmet obligations: accepted.** An `allow` carrying `dry_run`, `diff` or `timed_rollback` is not forwarded in M1. The `lab-open` example changes in M1-21 so that lab writes do not require those obligations until M3, with a comment in the file saying they return in M3.
2. **Machine-readable deny: text only in M1.** No `_meta` decision key yet. One can be added later without breaking a client that reads the text.
3. **Hold wording: accepted.** The maintainer's sentence, "Held by rule `<id>`: needs approval, and approvals aren't available yet, so this call was not run.", is carried in the one fixed first-line shape with the verb `held`: `fathomgate held <server>.<tool>: rule <rule_id> (class <CLASS>): needs approval, and approvals aren't available yet, so this call was not run.` (orchestrator, 2026-09-25, so agents and scripts parse one shape). design-guardian reviews the exact copy in M1-18 and M1-19. The recorded effect stays `hold`.
4. **Counter key for 2026-era agents: accepted as written.** The principal over HTTP, the process on stdio.
5. **Decision log level: Info for every decision line.** Until M4 the log line is the only record of a decision.

## Amendments

This section records factual corrections (GOVERNANCE.md). It does not change the decision.

| Date | What changed | Why |
| --- | --- | --- |
| 2026-09-25 | Decision log line: `effect` is spelled `decision` and `session` is spelled `session_id`. | The line is the M4 audit event field for field, and [audit-event-schema section 2](../specs/audit-event-schema.md#2-call-record) and DESIGN.md (log fields are the console's labels) name them so. Design review of PR #162 (M1-18). |
| 2026-09-25 | `CallInfo` and `Verdict` live in the leaf package `internal/gate/seam`, which imports nothing from fathomgate; M1-18 fixed their fields (`go doc ./internal/gate/seam`). | So the proxy can name them without importing `classify`, `inventory` or `policy`, as this record requires. The proxy's `Gate` interface and `Options.Gate` remain M1-19's. |
| 2026-09-25 | The decision log line's field list above also names `reason`, `agent_protocol`, `upstream_protocol`, and when set `parse_error`, `unnamed_args` and `malformed_args`, and says which fields are log-only until M4. | M1-18 records them (agent and upstream protocol beside the era labels from M1-06; the parse failure kind and the closed argument list's findings from ADR 0033), and the list must say which fields have no audit-event-schema section 2 field yet. Design and security re-reviews of PR #162. |
| 2026-09-25 | **Decision 4's counter key is superseded by the maintainer (Josh Scott, 2026-09-25).** Over the HTTP listener, `devices_touched` and `pending_holds` are counted per principal for both eras; the per-era split (a 2025-11-25 agent counted per session) is removed. On stdio the key stays the process. | Security review of PR #167 (M1): a 2025-era agent could reset `max_devices` by closing its session and opening another, or by having it evicted (T0.57), and one principal could double its cap by mixing eras. A principal's count now survives session churn. This row changes the decision, by the maintainer's word; the *Session counters* section above is read with it |
| 2026-09-25 | The decision log line's `forwarded` means that the gate allowed the call and fathomgate sent it upstream. A retry whose `requestState` does not verify, and a call to an upstream that has already exited, are refused before the gate runs and write no decision line; a call whose upstream then fails still reads `forwarded=true` and is counted (the count errs high). | Security review of PR #167, L2: the line said `forwarded=true`, and the targets were counted, for retries the proxy then refused. M1-19 notes, *Step 8* |

## Notes after acceptance

**2026-09-25, M1-19 (wiring, [PR #167](https://github.com/fathomgate/fathomgate/pull/167)).** The record left the final export table and the proxy's `Gate` interface to the wiring task. This is what was built, and the choices the task made inside this record's decision. Three choices went beyond the sketch and were marked for review: `Gate.Arguments`, `default:internal_error` and refusing upstream prompts under a policy. **The maintainer (Josh Scott) accepted all three on 2026-09-25** (security review of PR #167); none needs a record of its own.

The export table of `internal/proxy`, replacing ADR 0022's (its rules stand: a new export needs a new record, and `go doc ./internal/proxy` must match):

| Export | Kind | Purpose | First decided in |
| --- | --- | --- | --- |
| every row of ADR 0022's table | | unchanged | ADR 0022 |
| `Options.Gate Gate` | field | Decides every `tools/call` before it is forwarded. nil keeps the M0 pass-through: nothing is checked, counted or logged as a decision, and the agent's argument bytes cross unchanged | this record |
| `Gate` interface: `Decide(ctx, seam.CallInfo) seam.Verdict`; `Arguments(server, tool string) (named []string, closed bool)` | interface | `Decide` is steps 1 to 6. `Arguments` gives the profile's named set for one tool; the proxy calls it once per tool in `New` and keeps the answer on the route, one snapshot that both narrows the advertised `inputSchema` ([ADR 0033](0033-closed-argument-list-per-tool.md) section 4) and decides whether upstream prompts during a call to the tool are refused (below). `*gate.Gate` implements both | this record; `Arguments` added in M1-19, accepted by the maintainer 2026-09-25 |

`CallInfo` and `Verdict` are not re-exported: they stay in `internal/gate/seam` (amendment above), which the proxy imports. `internal/proxy` imports none of `classify`, `inventory` or `policy`; only its external test package does, to run the real gate behind the proxy.

How the proxy does its steps:

| Item | Built as |
| --- | --- |
| Step 7, what is forwarded | Only when `Verdict.Forward` is true. The upstream receives the arguments object re-encoded from the one the gate checked (keys sorted, a nested duplicate key collapsed to the value Go kept, strings as Go decoded them, numbers as written), never the agent's bytes. The gate also refuses a duplicate top-level key (`parse_error=duplicate_key`), so both defences apply. The sealed MRTR `requestState` still binds the agent's bytes (profile-schema 8.4). Every other verdict returns `Verdict.Error` as a tool result with `isError: true` and one text block; no upstream call is made. A verdict that refuses with no text gets `fathomgate denied <server>.<tool>: rule <rule_id> (class <CLASS>): the policy does not allow this call` |
| Argument cap | Arguments longer than 64 KiB (65,536 bytes, as the agent sent them) are denied before `Decide` with `default:bad_arguments`, class `EXEC_ARBITRARY` (unclassified) with `class_source` `proxy` (the classifier never ran), reason `the arguments are larger than 64 KiB`, and `parse_error=too_large` in the log line |
| A panic in `Decide` or the resolver | Recovered and denied: `fathomgate denied <server>.<tool>: rule default:internal_error (class EXEC_ARBITRARY): fathomgate could not decide this call, so it was not run`. An Error line names the panic's kind: the runtime's own error text when the panic value's type is in package `runtime`, and otherwise only the value's Go type, never the value. `default:internal_error` is a new reserved id, produced by the proxy, never by `Evaluate` or the gate; accepted by the maintainer 2026-09-25. A panic in `Gate.Arguments` at `New` leaves the tool closed with no named arguments |
| Step 5, counters | Counter key, as amended by the maintainer on 2026-09-25 (amendment row above): the principal over HTTP, for both eras; the process on stdio. No key names a session, so no entry outlives what it counts, and the map holds at most the configured principals plus one. `devices_touched` counts distinct target names; the proxy decides a second time when the call names a device the key has already touched, so that device is counted once (policy-schema: max_devices counts distinct devices). The read, the decision and the update of one key run under one lock, taken with the call's context (a one-slot channel), so two concurrent calls cannot both pass `max_devices` on the same count, and a call whose agent gives up stops waiting. Only calls the gate allows count. A key remembers at most 4,096 names; past that every other target is counted again on each call, so the count can only run high. `pending_holds` is 0. **M2 precondition:** the lock is held across up to two `Decide` calls, which in M1 do no I/O (in-memory inventory). Before a resolver does I/O (NetBox, the upstream inventory provider, M2), the M2 record must bound it (a per-call deadline, or resolving outside the lock), since every call of one principal waits behind it, and each I/O lookup is then paid twice when a device repeats |
| Step 8, the log line | `p.logger`, Info, `msg=decision`, the gate's attributes; the trace is added to the same line when the logger is enabled at Debug. The proxy adds no handler of its own; `TestDecisionLine` and `TestRealGateLogInjection` pin that an argument name with a newline stays on the one line. `forwarded` means the gate allowed the call and fathomgate sent it upstream: before deciding, the proxy opens and verifies an MRTR retry's `requestState` (a forged, expired or rebound state is the JSON-RPC error of profile-schema 8.2, logged by its own Warn line, with no decision line and nothing counted) and returns the not-running tool error for an upstream that has already exited. An upstream that exits between that check and the send, or fails the call, leaves `forwarded=true` and the targets counted: the count errs high, never low |
| Annotations | `DestructiveHint` is go-sdk's `*bool`, passed as is. go-sdk v1.8 decodes `readOnlyHint` into a plain `bool`, so the proxy reads it from the raw `tools/list` answers on the wire while `New` lists the tools (`hints.go`), keeping an absent hint nil. It matches the keys `tools`, `name`, `annotations` and `readOnlyHint` byte for byte, as go-sdk's decoder does, so a key in another case (`READONLYHINT`, `NAME`) cannot make the two parsers read different values. That works on the connections the proxy already wraps (stdio and in-memory upstreams, so every `serve` upstream). For any other upstream transport every `readOnlyHint` is nil, the raise rests on `destructiveHint`, and `New` logs a Warn when a gate is set |
| `tools/list` | With a gate, a tool whose argument list is closed (its server has a profile) is advertised with only the named properties, in `properties` and in `required`, and with `additionalProperties: false`. Only the top level is trimmed: a property offered through `allOf`, `anyOf`, `oneOf`, `$defs`, `patternProperties` or `dependentSchemas` stays in the advertised schema, and `Decide` refuses it when it is sent. A tool the profile does not list is advertised with no properties. The upstream's own schema is not changed and the check at call time does not change |
| Upstream prompts under a policy | With a gate, an upstream's input request (MRTR `input_required` or `elicitation/create`) during a call to a tool whose argument list is closed is refused with the profile-schema 8.2 refusal text, reason `a policy is enforced and fathomgate cannot check an answer against the server profile, so upstream prompts are not relayed`. An answer is an argument the profile never named ([ADR 0033](0033-closed-argument-list-per-tool.md) *Notes after acceptance*, N1), so it is refused like one. A server with no profile, whose arguments are not checked either, still has its prompts relayed; so does every server with no gate (M0). ADR 0014 records the same note. Accepted by the maintainer 2026-09-25; the way back to relaying is a new record in which a profile declares, per tool, the answer fields it accepts, checked like `args` |
| MRTR retries | Run the whole gate again (step order above); a retry the gate refuses never reaches the upstream |

**2026-09-25, M1-39 (per-call caps and one `Decide`, PR for board task M1-39).** Two changes inside this record's decision, both from the M1-23 overhead findings; neither changes a decision.

- **One `Decide` per call.** `seam.CallInfo` gains `Counted func(target string) bool`. The proxy sets it, with the counter key's lock held, to a read of the key's remembered names, and `DevicesTouched` to the key's count as before. The gate takes each of the call's targets that `Counted` reports off the count it passes to `Evaluate` (never below 0), so a device already touched is counted once, as the second `Decide` did. `decideLocked` now runs `Decide` once; before, it ran it again whenever the call named a device the key had touched, paying parsing, classification and resolution twice. The *Step 5, counters* row above is read with this: "the proxy decides a second time" is replaced by "the gate subtracts the targets `Counted` reports", and the M2 precondition's lock is held across one `Decide`, so an I/O lookup is paid once. The read, the decision and the update of one key still run under the one lock; a name past the 4,096 the key remembers is not `Counted`, so it is counted again and the count still errs high. `Counted` is valid only during that `Decide`; a gate must not keep it.
- **Per-call caps.** Before step 2, the gate denies a call to a profiled tool with more than 64 commands or more than 256 target names and group selectors with `default:bad_arguments`, reasons `a call may carry at most 64 commands; split it into smaller calls` and `a call may name at most 256 targets; split it into smaller calls`, and two new `parse_error` codes for the log line, `too_many_commands` and `too_many_targets` (log-only, like the others). Counting and the reasons for the numbers: [profile-schema section 2.4](../specs/profile-schema.md#24-per-call-caps).

Accepted by the maintainer, Josh Scott, on 2026-09-25, keeping both caps as constants rather than tying the target cap to the policy's `max_devices` (security review of PR #185).

## References

- [ADR 0003](0003-yaml-policy-dsl-with-obligations.md), [ADR 0007](0007-role-resolver-chain-sot-optional.md), [ADR 0010](0010-classify-by-payload-not-annotations.md), [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md), [ADR 0016](0016-streamable-http-listener.md), [ADR 0022](0022-internal-proxy-export-surface.md)
- [ARCHITECTURE.md, pipeline](../../ARCHITECTURE.md#pipeline); [classification](../specs/classification.md); [policy-schema sections 4 to 6](../specs/policy-schema.md#4-evaluation-order); [inventory-schema sections 7 and 8](../specs/inventory-schema.md#7-unknown-target-semantics); [profile-schema 8.2](../specs/profile-schema.md#82-errors-toward-the-agent); [audit-event-schema section 2](../specs/audit-event-schema.md#2-call-record)
- [PRD R5 to R13](../PRD.md), and the M1 success metrics
- [M1 board](../milestones/M1.yaml): M1-01 (this record), M1-06 (era label), M1-18 (gate), M1-19 (wiring)
