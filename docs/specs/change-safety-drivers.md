# Change safety drivers

Normative specification for the `ChangeSafety` interface in `internal/safety` and the per-platform drivers behind it. A driver turns the obligations `dry_run`, `diff` and `timed_rollback` into vendor commands. Where the platform has no native timed rollback, the proxy runs a watchdog that issues the vendor rollback if `Confirm` is not called before the deadline.

Decision records: [ADR 0003](../adr/0003-yaml-policy-dsl-with-obligations.md) (obligations), [ADR 0004](../adr/0004-approval-hold-state-machine.md) (drift guard). Companion: [approval-protocol.md](approval-protocol.md), [audit-event-schema.md](audit-event-schema.md).

## 1. Interface

```go
type ChangeSafety interface {
    // Prepare stages the change without committing it and returns the diff.
    // It MUST be safe to call twice; the second call is the drift guard.
    Prepare(ctx context.Context, req Change) (Prepared, error)

    // Apply commits the staged change. If timedRollback > 0 the driver MUST
    // arrange for automatic rollback at deadline unless Confirm is called.
    Apply(ctx context.Context, p Prepared, timedRollback time.Duration) (Applied, error)

    // Confirm cancels the pending rollback and makes the change durable
    // (write memory, second commit, configure confirm).
    Confirm(ctx context.Context, a Applied) error

    // Abort discards a prepared change, or rolls back an applied one before
    // Confirm. It MUST be idempotent.
    Abort(ctx context.Context, a Applied) error

    // Supports reports which obligations this driver can honour for a tool.
    Supports(tool string) Obligations
}

type Change struct {
    Target   string
    Vendor   string
    Payload  ConfigPayload // format: set | text | xml | cli; lines []string
    Upstream Executor      // sends commands through the upstream MCP server
}

type Prepared struct {
    Diff      string // redacted before storage
    DiffHash  string // sha256 over the unredacted normalised diff
    Handle    string // session name, checkpoint name, candidate id
    Mechanism string // see audit-event-schema.md rollback_mechanism
}

type Applied struct {
    Prepared
    Deadline  time.Time // zero when no timed rollback
    Watchdog  bool      // true when the proxy owns the timer
}
```

Drivers only see the upstream through `Executor`, which calls the upstream's tools. A driver never opens its own SSH session. That keeps credentials with the upstream and keeps every command inside the audit chain.

## 2. Diff normalisation and hash

`DiffHash` is computed over the diff after: trimming trailing whitespace per line; removing lines that carry only timestamps, commit ids, session names or the `## Last commit:` header; sorting nothing (order matters). Redaction runs after hashing so two dry-runs with the same secret hash equal. The redacted diff is what the pending record and the console show.

## 3. Obligation mapping

| Obligation | Driver call | Refused when |
| --- | --- | --- |
| `dry_run` | `Prepare` | `Supports(tool)` lacks it; result is deny with `error_class: obligation_unsupported` |
| `diff` | `Prepare` output attached to pending record or audit event | Same |
| `timed_rollback` | `Apply(timedRollback)` with the rule's `rollback.timer` or the driver default | Same |

Default timer is 5 minutes for allow with `timed_rollback`, and the approval TTL for a hold, capped at 30 minutes. A driver MUST reject a timer longer than the platform allows and report the platform maximum.

## 4. Per-platform command table

| Platform | Prepare (dry-run, diff) | Apply with timed rollback | Confirm | Abort | Mechanism |
| --- | --- | --- | --- | --- | --- |
| Junos | `configure private`; `load <format>` payload; `show \| compare`; `commit check`; `rollback 0`; `exit` | `configure private`; `load`; `commit confirmed <min> comment "fathomgate <id>"` | `commit` | `rollback 0` then `commit` (or let the timer fire) | `commit_confirmed` |
| Arista EOS | `configure session fg-<id>`; payload lines; `show session-config diffs`; `abort` | `configure session fg-<id>`; payload; `commit timer <hh:mm:ss>` | `configure session fg-<id> commit` then `write` | `configure session fg-<id> abort` | `commit_timer` |
| Cisco IOS-XE | Requires `archive` with `path` configured; `configure terminal revert timer <min>` not yet issued; payload staged in a candidate file via `copy` to `flash:fg-<id>.cfg`; `show archive config differences system:running-config flash:fg-<id>.cfg` | `configure terminal revert timer <min>`; payload lines; `end` | `configure confirm` | `configure revert now` | `revert_timer` |
| Cisco NX-OS | `checkpoint fg-<id>`; payload applied to a scratch copy is not possible, so Prepare applies to running config only when `Apply` is imminent; otherwise diff is proxy-side against `show running-config` with the payload rendered | `checkpoint fg-<id>`; `configure terminal`; payload; `end`; proxy watchdog starts | n/a (proxy marks confirmed and deletes the checkpoint later) | `rollback running-config checkpoint fg-<id> atomic` | `checkpoint_watchdog` |
| PAN-OS | `configure`; `set`/`delete` payload into candidate; `validate full`; `show config diff`; `exit` (candidate remains) | Save running snapshot `save config to fg-<id>.xml`; `commit description "fathomgate <id>"`; proxy watchdog starts | n/a | `load config from fg-<id>.xml` then `commit` | `snapshot_watchdog` |
| FortiOS | Record `execute revision list config` top id; proxy-side diff of `show full-configuration` against the rendered payload | `config ...` payload with `end`; changes apply immediately; proxy watchdog starts | n/a | `execute restore config flash <revision-id>` (device reboots) | `revision_watchdog` |

Notes:

- Junos `commit confirmed` takes minutes, 1 to 65535. EOS `commit timer` takes `hh:mm:ss`. IOS-XE `revert timer` takes minutes, 1 to 120 on most releases; IOS-XE also warns on `reload in`, which Fathomgate never uses.
- NX-OS allows at most 10 checkpoints and one rollback user at a time; the driver deletes `fg-*` checkpoints after Confirm and refuses Apply when 10 exist.
- PAN-OS commits are jobs; Apply polls `show jobs id <n>` until `FIN` and treats `FAIL` as `Apply` failure with automatic Abort.
- FortiOS Abort reboots the device. The driver requires `rollback.allow_reboot: true` in the rule, or it reports `timed_rollback` unsupported.
- Drivers for IOS-XR (`commit confirmed <sec>`) and Nokia SR Linux (`commit confirmed`) are candidates for the first set; both have native timers. See [PLAN.md](../PLAN.md) open questions.

## 5. Watchdog

For `checkpoint_watchdog`, `snapshot_watchdog` and `revision_watchdog`, the proxy owns the timer.

1. On `Apply`, insert a row into `watchdog` (`approval.db`): `{id, target, vendor, handle, deadline, state: armed}`.
2. A single goroutine wakes at the earliest deadline. It is also run at startup, so a proxy restart does not lose a pending rollback.
3. At deadline, if `state` is still `armed`, the goroutine calls `Abort` through the upstream, records `rollback_fired: true` on a follow-up audit event, and sets `state: fired`.
4. `Confirm` sets `state: confirmed` and, for NX-OS, schedules checkpoint deletion after 24 hours.
5. If `Abort` fails (upstream down), the watchdog retries with exponential backoff up to `watchdog.max_retries` (default 5) and then writes an audit event with `error_class: rollback_failed` and `status: failed`. The console shows it as Failed with the rollback command the operator must run by hand.

The watchdog uses the upstream MCP server to send the rollback, so an upstream outage at the deadline is the one case the proxy cannot save alone. That is recorded, never hidden.

## 6. Driver selection

`vendor` from the resolved device record selects the driver. When `vendor` is `other` or empty, no driver applies: `Supports` returns nothing, and any rule with obligations denies with `obligation_unsupported`. The profile's `vendor_hint` fills the gap for single-vendor upstreams.

A tool with its own two-phase shape (eos-mcp `push_config`, `confirm_config_session`, `abort_config_session`) is driven through those tools rather than raw commands: the profile's `dry_run_param`, `commit_timer` argument and the confirm and abort tool names are declared in the profile's `safety` block, and the EOS driver uses them when present.

## 7. Tests

| Tier | What is asserted |
| --- | --- |
| 1 | Each driver renders the expected command sequence for Prepare, Apply, Confirm and Abort against a recording fake upstream; `DiffHash` is stable across timestamp changes; watchdog fires on a fake clock. |
| 2 | Junos and EOS drivers against junos-mcp-server and eos-mcp with the fake SSH device echoing config lines. |
| 3 | EOS on cEOS: unconfirmed session reverts at the timer. NX-OS on a licensed image: checkpoint restored at the watchdog deadline. |
