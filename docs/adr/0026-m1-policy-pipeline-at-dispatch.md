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

`--audit` stays refused until M4 (ADR 0027). In M1 the record step writes one `slog` line per call at Info, `msg=decision`, with: `server`, `tool`, `class`, `class_source`, `targets` (names), `roles`, `unknown_target` (bool), `effect`, `rule_id`, `obligations`, `forwarded` (bool), `agent_era`, `upstream_era`, `transport`, `principal`, `session` (fathomgate's short session hash, as the eviction log uses), and `trace` at Debug only. No argument value, command or result text is logged; the command is represented by the class. The line is the event M4 will write, field for field where [audit-event-schema section 2](../specs/audit-event-schema.md#2-call-record) already names one, so M4 swaps the sink behind the same record step.

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

## References

- [ADR 0003](0003-yaml-policy-dsl-with-obligations.md), [ADR 0007](0007-role-resolver-chain-sot-optional.md), [ADR 0010](0010-classify-by-payload-not-annotations.md), [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md), [ADR 0016](0016-streamable-http-listener.md), [ADR 0022](0022-internal-proxy-export-surface.md)
- [ARCHITECTURE.md, pipeline](../../ARCHITECTURE.md#pipeline); [classification](../specs/classification.md); [policy-schema sections 4 to 6](../specs/policy-schema.md#4-evaluation-order); [inventory-schema sections 7 and 8](../specs/inventory-schema.md#7-unknown-target-semantics); [profile-schema 8.2](../specs/profile-schema.md#82-errors-toward-the-agent); [audit-event-schema section 2](../specs/audit-event-schema.md#2-call-record)
- [PRD R5 to R13](../PRD.md), and the M1 success metrics
- [M1 board](../milestones/M1.yaml): M1-01 (this record), M1-06 (era label), M1-18 (gate), M1-19 (wiring)
