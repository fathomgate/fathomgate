# Audit event schema

Normative specification for the Fathomgate audit log. The log is JSONL: one canonicalised record per line. Tool-call records have `type: "call"` and carry `seq`, `prev_hash` and `hash`. A checkpoint record `{type: checkpoint, seq, hash, sig}` is appended every N events, signed with Ed25519. `fathomgate audit verify` replays the chain. OCSF and CEF are exporters, never the native format; the ready-made exporters are in the paid edition ([ADR 0025](../adr/0025-split-the-console.md)). Raw device output never enters the log.

This document describes what `internal/audit` (`event.go`, `hash.go`, `writer.go`, `verify.go`) implements. Fields the plan calls for but the Go struct does not yet carry are listed separately and marked planned (M4). Decision record: [ADR 0005](../adr/0005-hash-chained-jsonl-audit.md).

## 1. Field names

Field names are the console's meta labels lowercased with underscores, so a screenshot and a log line describe one event in one vocabulary ([ADR 0009](../adr/0009-fathom-design-system-policy-layer.md)). Decision words are exactly `allow`, `hold`, `deny`, `expired`.

## 2. Call record

Every field below is present on every `call` record except those marked `omitempty`. The writer forces `targets`, `roles` and `obligations` to `[]` rather than `null`.

| Field | JSON type | Set by | Meaning |
| --- | --- | --- | --- |
| `type` | string | writer | Always `call`. The verifier also accepts the older spelling `event` and a missing type. |
| `event_id` | string | writer if empty | 32 hex characters (16 random bytes). |
| `seq` | integer | writer | 1-based position in the chain. |
| `ts` | string | writer if empty | RFC 3339 UTC with nanosecond precision. |
| `principal` | string | caller | Authenticated client identity. |
| `session_id` | string | caller | Proxy-assigned session identifier. |
| `server` | string | caller | Upstream profile `server` name. |
| `tool` | string | caller | Tool name. |
| `class` | string | caller | One of the seven classes. |
| `args_sha256` | string | caller | SHA-256 hex over the canonical unredacted arguments. |
| `targets` | array of string | caller | Expanded target names. |
| `roles` | array of string | caller | Resolved roles, same order as `targets`. |
| `decision` | string | caller | `allow`, `hold`, `deny`, `expired`. |
| `rule_id` | string | caller | Winning rule id or a `default:` id. |
| `reason` | string, `omitempty` | caller | |
| `obligations` | array of string | caller | |
| `approval` | object, `omitempty` | caller | `{id, approver, channel}`; `channel` is `cli`, `webhook` or `mrtr`. Present only when the call was held. |
| `status` | string | caller | Outcome: `executed`, `failed`, `denied`, `held`, `expired`, `cancelled`. |
| `duration_ms` | integer | caller | From receipt to response. |
| `redactions` | integer | caller | Count of replacements made in the output. |
| `prev_hash` | string | writer | 64 hex characters. Genesis is 64 zeros. |
| `hash` | string, `omitempty` | writer | 64 hex characters. See section 4. Present on every written record; omitted only while hashing. |

The verifier decodes with unknown fields disallowed, so a record with a field outside this list fails verification. Adding a field is a schema change and needs this document updated first.

### 2.1 Planned fields (M4)

These appear in the plan and the exporter mappings below but are not in the Go struct yet. They are not written today and must not appear in a record.

| Field | Meaning |
| --- | --- |
| `schema_version` | Integer schema version. |
| `proxy_instance` | Stable id of this install. |
| `client_name`, `client_version`, `protocol_version` | From `initialize` or `_meta`. |
| `class_source` | `profile`, `fallback`, `capability_table`, `annotation_raise`, `downgrade`, `reclassify` ([classification.md](classification.md) section 2; `classify.Source`). |
| `args_redacted` | Redacted arguments, truncated. |
| `tags`, `sites`, `vendors` | Per-target lists parallel to `targets`. |
| `unknown_target`, `sot` | Whether any target was unresolved; `live`, `stale` or `none`. |
| `policy_hash`, `engine`, `trace` | Policy file hash, `yaml` or `opa`, and the rule trace. |
| `approved_at`, `expires_at` | Approval timestamps. |
| `dry_run_ok`, `diff_sha256`, `diff_ref`, `rollback_mechanism`, `rollback_deadline`, `rollback_fired` | Change safety. |
| `error_class`, `output_sha256`, `output_ref`, `output_bytes`, `redaction_rules` | Outcome detail and blob store references. |

## 3. Example line

One `call` record, a denied `reload`. Wrapped here for reading; on disk it is one line as `encoding/json` marshals the struct (struct field order, not sorted; sorting happens only inside the hash computation).

```json
{"type":"call","event_id":"7f3a9c1e2b4d6f8091a2b3c4d5e6f708","seq":4182,"ts":"2026-09-23T14:02:11.417338201Z","principal":"josh","session_id":"s-2b9c","server":"upa-mcp-netmiko-server","tool":"send_command_and_get_output","class":"EXEC_ARBITRARY","args_sha256":"9f2c...e1","targets":["core-rtr-01"],"roles":["core"],"decision":"deny","rule_id":"no-exec","reason":"","obligations":[],"status":"denied","duration_ms":3,"redactions":0,"prev_hash":"a1c0...09","hash":"3f9a...c7"}
```

(`reason` is `omitempty`, so an empty reason is absent on disk; it is shown here for completeness.)

## 4. Canonicalisation and hash

Canonicalisation (`Canonical` in `event.go`):

1. Marshal the value with `encoding/json`.
2. Decode it back generically with `UseNumber`, so numbers keep their source text.
3. Re-emit compactly: object keys sorted bytewise at every level, no insignificant whitespace, arrays in order, strings encoded by `encoding/json` with HTML escaping off (`<`, `>`, `&` are literal).

Hash (`HashEvent` in `hash.go`):

1. Set `prev_hash` to the previous record's `hash` (or the genesis value) and clear `hash`. If `type` is empty, set it to `call`.
2. `hash = hex(SHA-256(canonical(record) || prev_hash))`, where `prev_hash` is appended as its 64 ASCII hex characters.
3. Set `hash` on the record and write the line.

The writer holds a mutex while assigning `seq` and `prev_hash`. A new log is created exclusively (`O_CREATE | O_EXCL`; `CREATE_NEW` with `FILE_FLAG_OPEN_REPARSE_POINT` on Windows, so a symlink at the path, dangling or not, is never followed) for append-only writing and is owner-only from creation: mode `0600` on Unix, the protected owner-only DACL described in section 5 on Windows. An existing log is never truncated. It is opened once for read and append without following links (`O_NOFOLLOW`; `FILE_FLAG_OPEN_REPARSE_POINT` on Windows) and refused unless the open handle is a regular file with exactly one link (no reparse point on Windows) owned by the current user (`st_uid == geteuid()`; the token user on Windows). The chain is then replayed and verified by reading that same handle, so a file swapped in at the path is never what gets verified, and the writer refuses to append to a broken chain. Only after the chain verifies is the log set back to the owner-only protection, through the handle.

## 5. Checkpoint record

Written after every `CheckpointEvery` events (a writer option; `0` disables checkpoints, and enabling them requires a key). The checkpoint is a separate line, not part of the `seq` numbering.

```json
{"type":"checkpoint","seq":5000,"hash":"3f9a...c7","sig":"base64..."}
```

| Field | Meaning |
| --- | --- |
| `type` | `checkpoint` |
| `seq` | The `seq` of the last `call` record covered. MUST equal the chain's current `seq`. |
| `hash` | That record's `hash`. MUST equal the chain's current hash. |
| `sig` | Base64 (standard alphabet) Ed25519 signature over `canonical({"type":"checkpoint","seq":<seq>,"hash":"<hash>"})`, that is over the bytes `{"hash":"<hash>","seq":<seq>,"type":"checkpoint"}`. |

Keys are generated with `fathomgate audit keygen --out audit.key [--pub audit.pub]` (`key.go`). The private key MUST live outside the log directory. `SaveKey` guarantees:

- It never overwrites. An existing path, including a symlink, fails with an error wrapping `fs.ErrExist` and the file is left untouched. There is no `--force`.
- Unix (`key_unix.go`): created with `O_CREATE | O_EXCL` and mode `0600`, then `Chmod(0600)` on the open descriptor, so the umask cannot widen it.
- Windows (`key_windows.go`): created with `CREATE_NEW` and `FILE_FLAG_OPEN_REPARSE_POINT` (a dangling symlink at the path is not followed to create the file elsewhere) and a security descriptor passed to `CreateFile`, so it is protected from the first instant. The descriptor is `O:<user>D:P(A;;FA;;;<user>)(A;;FA;;;SY)`: owned by the current process user, a protected DACL (no inherited ACEs), full control for that user and `LocalSystem`, nothing for Administrators, `Everyone`, `BUILTIN\Users` or `Authenticated Users`. The handle is not inheritable.
- A failed write deletes the partial file through its handle (`FILE_DISPOSITION_INFO` on Windows; on Unix, unlink only if the path still has the descriptor's device and inode).

The public key (`SavePublicKey`) is also created exclusively and never overwrites; it is `0644` and inherits its folder's ACL on Windows, by design. `keygen` calls `WriteKeyPair`, which writes the public key first and deletes it again if the private key cannot be written, so a failure never leaves a private key without its public half.

Loading the private key ([ADR 0028](../adr/0028-audit-key-custody.md)). `LoadKey`, and whatever signs checkpoints for `serve --audit` in M4, reads the key with `internal/secretfile`, the same owner-only check the listen token files use. The file is opened without following a final symbolic link, and the checks run on the open descriptor or handle, not the path. It MUST be:

- Unix: opened with `O_NOFOLLOW` and `O_NONBLOCK`; a regular file with exactly one link, owned by the effective user, with no group or other permission bits (mode `0600` or `0400`), and on macOS no extended ACL (`internal/fileacl`).
- Windows: opened with `FILE_FLAG_OPEN_REPARSE_POINT`, `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` (a named-pipe server at the path cannot impersonate fathomgate) and share mode `FILE_SHARE_READ`; a disk file, not a directory or reparse point (symbolic link, junction), with exactly one link, owned by the current user, with a protected DACL (nothing inherited from the folder) whose allow entries name only that user and `SYSTEM`. Deny entries are allowed; any other entry type is refused.
- Other platforms: refused; the checks cannot be made.

A key owned by a group, or readable by a group (`0640`, `0440`), is refused: there is no group-owned key. There is no flag to skip a check. A refusal matches `secretfile.ErrUnsafe` and its message names the path and the failed check (for example `audit: the signing key /etc/fathomgate/audit.key has mode 0640, so other users can read or change it; make it owner-only with chmod 600`), never the key. A refusal caused by a failed system call (reading an ACL or DACL) also unwraps to that cause. The file must hold exactly one `PRIVATE KEY` PEM block (PKCS#8, Ed25519), with only white space around it, and at most 16 KiB. Not checked, by decision: NFSv4 ACLs outside macOS, and the directories above the file (someone who can write to one can make the load fail or move another of fathomgate's own owner-only files into place, but cannot substitute a key they hold); see the threat model. A key `keygen` wrote passes as it is. The redaction key (`FATHOMGATE_REDACT_KEY`, [ADR 0006](../adr/0006-keyed-hmac-redaction.md)) gets the same check when M2 wires redaction into `serve`.

Planned (M4): time-based checkpoint interval, `key_id` for rotation, a `ts` on the checkpoint, rotation with `prev_file`, and a checkpoint written at clean shutdown.

## 6. Verify algorithm

`fathomgate audit verify <audit.jsonl> [--key audit.pub] [--json]` (`verify.go`).

1. Start with `last_seq = 0`, `last_hash = genesis`. A missing file is an empty, valid chain.
2. For each non-blank line, read `type` and `seq`.
   - Not JSON: fail, `broken_seq = last_seq + 1`.
   - `checkpoint`: fail if `seq != last_seq`, or `hash != last_hash`, or (when `--key` is given) the signature does not verify. Otherwise count it.
   - `call`, `event` or missing type: decode with unknown fields disallowed; fail if `seq != last_seq + 1`, or `prev_hash != last_hash`, or the recomputed hash differs from the recorded one. Otherwise advance `last_seq`, `last_hash`.
   - Any other type: fail.
3. Stop at the first failure and report `ok: false`, `broken_seq`, and a one-line `problem` prefixed with the line number. Otherwise report `ok: true`, `events`, `checkpoints`, `last_seq`, `last_hash`, `signatures_checked`.

Verify never needs the private key, and never accepts it ([ADR 0028](../adr/0028-audit-key-custody.md)). `--key` (`LoadPublicKey`) opens the file without blocking (`O_NONBLOCK` on Unix; `SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION` on Windows, so a named-pipe server cannot impersonate the verifier) and takes it only if the open file is a regular file of at most 16 KiB. It must hold exactly one `PUBLIC KEY` PEM block with an Ed25519 key: `-----BEGIN ` exactly once, with only white space before it and after the END line (`pem.Decode` alone skips text it cannot parse), and no PEM headers (a `Comment:` header could carry another key). The private key file follows the same one-block, no-header rule. A file that contains the text `PRIVATE KEY` anywhere, whether as a block (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, `OPENSSH PRIVATE KEY`, ...), a corrupted block or loose text before or after the public block, is refused with `audit.ErrPrivateKey` before anything is decoded, and the CLI exits 2 with `fathomgate: --key must be the public key (<path>.pub); a verifier never needs the signing key`. The public key needs no owner check: it is not secret, and that it is the right key is the operator's to establish (for example by comparing it with the one published beside the log). The tier 1 tamper test edits one character in one line and asserts `ok: false` naming that line.

## 7. Blob store (planned, M4)

Redacted output and diffs will go to a content-addressed directory keyed by their SHA-256, referenced from the record by `output_ref` and `diff_ref`. Until then the record carries only `redactions`; output stays out of the log by construction.

## 8. Exporters (paid edition)

The ready-made OCSF and CEF exporters are in the paid edition, not the core ([ADR 0025](../adr/0025-split-the-console.md), R27; until 2026-09-25 they were planned for M4). The JSONL is standard JSON that any log shipper can forward without them. Exporters read the JSONL and emit one record per `call` record. They never write to the chain. Rows whose source is a planned field are marked.

### 8.1 OCSF `API Activity` (class_uid 6003)

| OCSF field | Source |
| --- | --- |
| `class_uid` | `6003` |
| `category_uid` | `6` (Application Activity) |
| `activity_id` | `1` Create for `WRITE_CONFIG`, `2` Read for read classes, `99` Other for `EXEC_ARBITRARY`, `LAB_LIFECYCLE`, `LOCAL_ADMIN` (from `class`) |
| `severity_id` | `1` Informational for allow, `3` Medium for hold, `4` High for deny (from `decision`) |
| `status_id` | `1` Success for executed, `2` Failure for failed or denied, `99` Other for held, expired, cancelled (from `status`) |
| `time` | `ts` as epoch milliseconds |
| `metadata.product.name` | `Fathomgate` |
| `metadata.product.version` | proxy version |
| `metadata.version` | `1.3.0` |
| `metadata.uid` | `event_id` |
| `actor.user.name` | `principal` |
| `actor.session.uid` | `session_id` |
| `actor.app_name` | `client_name` (planned, M4) |
| `api.operation` | `tool` |
| `api.service.name` | `server` |
| `api.request.uid` | `args_sha256` |
| `api.response.code` | `error_class` (planned, M4) |
| `resources[]` | one per target: `{name: targets[i], type: "network_device", data: {role: roles[i]}}`; `labels` from `tags` (planned, M4) |
| `unmapped` | `class`, `decision`, `rule_id`, `reason`, `obligations`, `approval`, `redactions`, `hash`, `seq`; plus `diff_sha256`, `rollback_mechanism`, `rollback_deadline`, `sot` (planned, M4) |

### 8.2 CEF

Header: `CEF:0|Fathomgate|Fathomgate|<version>|<class>|<decision> <tool>|<severity>|` where severity is 3 for allow, 6 for hold, 8 for deny.

| CEF extension | Source |
| --- | --- |
| `rt` | `ts` epoch ms |
| `suser` | `principal` |
| `sproc` | `client_name` (planned, M4) |
| `dhost` | `targets` joined by space |
| `act` | `decision` |
| `outcome` | `status` |
| `reason` | `reason` |
| `cs1` / `cs1Label=rule_id` | `rule_id` |
| `cs2` / `cs2Label=class` | `class` |
| `cs3` / `cs3Label=approval_id` | `approval.id` |
| `cs4` / `cs4Label=approver` | `approval.approver` |
| `cs5` / `cs5Label=roles` | `roles` joined by space |
| `cs6` / `cs6Label=chain_hash` | `hash` |
| `cn1` / `cn1Label=redactions` | `redactions` |
| `cn2` / `cn2Label=seq` | `seq` |
| `externalId` | `event_id` |

Pipes and equals signs in values are escaped per the CEF specification.

## 9. Other record types (planned, M4)

`approval` (state transitions), `quarantine` (TOFU mismatch), `policy_reload` and `startup` records are planned. Today the verifier rejects any type other than `call`, `event` (legacy) and `checkpoint`; adding a type requires updating `verify.go` and this document together.
