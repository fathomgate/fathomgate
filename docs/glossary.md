# Glossary

The words NetGuard uses, in the UI, CLI, audit log, specs and docs. One word per concept; no synonyms. Technical values are set in mono.

## Decisions

A call has exactly one decision.

| Word | Meaning |
| --- | --- |
| `allow` | Policy permits the call. It is forwarded upstream, possibly with obligations. Shown as Allowed. |
| `hold` | Policy requires a human. A pending record is created and the call waits. Shown as Holding while the TTL is live. |
| `deny` | Policy refuses the call. The agent gets a tool error naming the rule id and reason. Shown as Denied. |
| `expired` | A hold whose TTL ran out before anyone acted. Terminal. Shown as Expired. Produced by `internal/approval`, never by `Evaluate`. |

## Pending record states

| Word | Meaning |
| --- | --- |
| PENDING | Created by a hold; waiting. Human word: Holding. |
| APPROVED | A server-side-identified approver approved it and the diff hash was unchanged. |
| DENIED | An approver denied it. Terminal. |
| EXPIRED | TTL elapsed. Terminal. |
| CANCELLED | Diff drifted at approval time, the requester cancelled, or a policy reload invalidated it. Terminal. |
| EXECUTED | The change was applied and confirmed. Terminal. |
| FAILED | Apply or confirm failed, or a rollback fired. Terminal. |

## Classes

Every tool call has exactly one class. Spelled in upper snake case everywhere.

| Class | Meaning |
| --- | --- |
| `READ_OPERATIONAL` | Device or controller state; nothing persistent changes. |
| `READ_CONFIG` | Running, startup or candidate configuration, diffs, backups, dry runs. Mandatory redaction. |
| `WRITE_CONFIG` | Any change to device or controller configuration, including commit, confirm, abort, rollback. |
| `EXEC_ARBITRARY` | Command execution the server does not filter with an allow-list; shells; XML op commands. |
| `INVENTORY_READ` | Device, group, tag and capability listings; source-of-truth reads. |
| `LAB_LIFECYCLE` | Deploy or destroy labs. |
| `LOCAL_ADMIN` | Changes to the proxy or server host, not the device. |

## Obligations

Things an `allow` or `hold` decision requires before or during execution.

| Obligation | Meaning |
| --- | --- |
| `dry_run` | Run the driver's `Prepare` (and the tool's own dry-run parameter if it has one) before any apply. |
| `diff` | Attach the diff from `Prepare` to the pending record or audit event. |
| `timed_rollback` | Apply with a platform timer or the proxy watchdog so the change reverts unless confirmed. |

## Components

| Term | Meaning |
| --- | --- |
| Proxy | The NetGuard process. MCP server toward the agent, MCP client toward upstreams. |
| Upstream | A network-device MCP server NetGuard fronts, such as netdev-ssh-mcp or junos-mcp-server. |
| Agent | The MCP client and the model behind it. Untrusted. |
| Profile | A YAML file in `profiles/` describing one upstream: tool to class, parameter mapping, capability tables. |
| Policy | The YAML file with `defaults` and ordered `rules` that `Evaluate` reads. |
| Rule | One entry in `rules`, with an `id`, `match`, optional `when`, and `effect`. |
| Rule id | The identifier of the rule that decided a call. Every denial names one. Set in mono. |
| `Evaluate` | The pure function `Evaluate(policy, request) -> Decision`. |
| Decision | The struct returned by `Evaluate`: effect, rule id, reason, obligations, approval, trace. |
| Rule trace | The ordered list of rules evaluated and whether each matched; shown on denied and held calls. |
| Normaliser | `internal/normalize`; turns raw arguments into `target`, `targets[]`, `commands[]`, `config_payload`. |
| Classifier | `internal/classify`; assigns the class from profile, capability table or fallback, then applies downgrade and reclassification. |
| Downgrade | `EXEC_ARBITRARY` becoming `READ_OPERATIONAL` because every command passed the allow-list, blocklist and pipe rules. |
| Reclassify | A `READ_OPERATIONAL` free-form command becoming `READ_CONFIG` because it reads configuration. |
| Meta-tool | A tool whose name carries no semantics and whose operation is chosen by a parameter, such as Meraki `execute_api(capability_id)`. |
| Capability table | Profile section mapping meta-tool capability ids to classes. |
| Resolver chain | The ordered inventory providers: static file, hostname patterns, upstream inventory, source of truth. |
| Source of truth (SoT) | NetBox or Nautobot. Optional. |
| Unknown target | A target no provider resolved. Denied for writes and exec by default. |
| Stale | A device record served from a snapshot because the source of truth was unreachable. Marked `sot: stale` in audit. |
| Snapshot | The static-format file written by `netguard inventory sync`. |
| Pending record | The SQLite row that is the source of truth for a held call. |
| TTL | Time from PENDING to EXPIRED. |
| Drift guard | Re-running `Prepare` at approval and cancelling if the diff hash changed. |
| Diff hash | SHA-256 over the normalised unredacted diff. |
| Channel | How an approval arrived: `cli`, `webhook`, `mrtr`. |
| `approver_must_differ` | Rule flag requiring the approver's server-side identity to differ from the requester's. |
| `ChangeSafety` | The driver interface: `Prepare`, `Apply`, `Confirm`, `Abort`. |
| Driver | A `ChangeSafety` implementation for one platform. |
| Watchdog | The proxy-owned timer that issues the vendor rollback when a platform has no native timed rollback. |
| Redaction | Replacing a secret in output with an HMAC token before the agent sees it. Not a decision. |
| Redacted token | `<redacted:hmac:3f9a1b2c4d5e>`; keyed HMAC-SHA256 truncated to 12 hex characters. |
| Fixture corpus | `tests/fixtures/configs/`, annotated sanitised configs used to test redaction. |
| Audit event | One JSONL line in the chain. |
| Chain | The sequence of events linked by `prev_hash` and `hash`. |
| Checkpoint | A signed chain record anchoring the hash at a `seq`. |
| Blob store | Content-addressed files holding redacted output and diffs outside the chain. |
| TOFU pinning | Trust on first use: upstream tool descriptions are hashed at first `tools/list`; a later change quarantines the server. |
| Quarantine | An upstream whose descriptions changed; its tools are denied until an operator re-pins. |
| Era | Which MCP spec shape a peer speaks: 2025-11-25 stateful or 2026-07-28 stateless. |
| MRTR | Multi Round-Trip Requests; the 2026-07-28 mechanism where a server returns `input_required` and the client retries with `inputResponses`. |
| Elicitation | A request for human input; server-initiated in the 2025 era, carried by MRTR in the 2026 era. |
| Blast radius | How many devices a call or session can change; bounded by `targets_count`, `session.max_devices` and the canary-first rule. |
| Canary | A device tagged `canary` that must be changed and confirmed before the rest of a fleet change proceeds. |
| Fan-out | The number of expanded targets in one call. |
| Tier 1, 2, 3 | Test tiers: unit with nothing real; real server with fake device; real server with real device. |

## Words not used

| Avoid | Use |
| --- | --- |
| blocked, rejected, refused (as a decision) | deny, Denied |
| pending review, awaiting, queued | hold, Holding |
| approved-and-run, done | Executed |
| timed out | Expired |
| mask, scrub, sanitise (for output) | redact |
| whitelist, blacklist | allow-list, blocklist |
| device type, platform (in policy) | vendor |
| firewall rule, ACL (for NetGuard rules) | rule |
