# Security policy

NetGuard is a security control. A bug that lets a call reach a device against policy, lets a secret reach an agent, or lets an approval be forged is a vulnerability, not a defect. Report it privately. Do not open a public issue.

## Reporting

- Use GitHub private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). This is the preferred channel.
- If that is unavailable, email SECURITY_CONTACT_EMAIL_PLACEHOLDER with the subject `netguard security`.
- Include: version or commit, the upstream server and profile involved, the policy file (with any secrets replaced), the exact `tools/call` arguments, what you expected and what happened. For a redaction gap, include the shape of the line with the secret characters replaced by a made-up value of the same length. Never send a real secret.
- You will get an acknowledgement within 3 days and a first assessment within 10 days. Fixes for confirmed policy, approval or redaction bypasses are released as a patch as soon as they are ready; the advisory is published with the release.
- Credit is given in the advisory and the changelog unless you ask otherwise.

Until the first tagged release, report against `main`.

## Supported versions

| Version | Supported |
| --- | --- |
| `main` | Yes, during pre-release development |
| Latest minor release (`0.x.y` with highest `x`) | Yes |
| Previous minor release | Security fixes only, for 90 days after the next minor |
| Anything older | No |

Dependency advisories for the pinned go-sdk are tracked and re-pinned on every security release of the SDK.

## What counts as a vulnerability

| Class | Example |
| --- | --- |
| Policy bypass | A `WRITE_CONFIG` or `EXEC_ARBITRARY` call reaches an upstream without the decision the policy specifies; a command passes the `EXEC_ARBITRARY` downgrade that should have been blocked; a config read through a free-form tool is not reclassified `READ_CONFIG` |
| Redaction bypass | A secret matching a documented pattern, or of a documented vendor form, reaches the agent in any tool result, elicitation text, error message, diff or audit `args_redacted` |
| Approval bypass | An approval is accepted without server-side identity; `approver_must_differ` can be satisfied by the requester; an EXPIRED or DENIED record can be executed; a retried call executes twice; the webhook accepts an unsigned or replayed request |
| Drift guard bypass | A change different from the approved diff is applied after approval |
| Audit integrity | An event can be inserted, altered or removed without `netguard audit verify` failing; a checkpoint verifies against the wrong key; raw output or a secret enters the chain |
| Inventory | An unknown target is treated as known; a stale snapshot is used without `sot: stale`; a live 404 is overridden by a snapshot |
| Upstream trust | A changed tool description is not quarantined; an upstream elicitation is forwarded without origin; upstream sampling is not blocked; header and body mismatch is accepted on HTTP |
| Watchdog | A rollback deadline passes without the rollback being issued or a `rollback_failed` event being written |
| Key handling | The redaction key or checkpoint key is written to the log, blob store, audit event or console |

Not vulnerabilities, but welcome as issues: false-positive redaction, a missing pattern for an undocumented vendor form (use the [redaction gap template](.github/ISSUE_TEMPLATE/redaction_gap.yml)), performance, and upstream servers' own bugs.

## Threat model summary

The full trust boundaries are in [ARCHITECTURE.md](ARCHITECTURE.md#trust-boundaries). In short:

- The agent is untrusted. It may be prompt-injected by device output or by a poisoned tool description. NetGuard classifies by payload, never by the agent's or the tool's claims, and never takes approver identity from the agent.
- Upstream tool descriptions, annotations and output are untrusted. Descriptions are pinned; annotations only raise a class; output is redacted before the agent sees it.
- Approvers are authenticated server-side: OS user for the CLI, HMAC for the webhook, client principal for MRTR.
- The source of truth is trusted data with unreliable availability; stale data is marked, never hidden.
- The proxy host is trusted. NetGuard does not defend against an attacker with write access to its keys, database or log directory; frequent checkpoints and an external log sink limit what such an attacker can hide.

### Proxy transport (M0) gaps

Recorded from the T0.2 security review. M0 forwards every call with no policy; these are the known gaps and when they close.

| Threat | M0 status | Closes |
| --- | --- | --- |
| MCP03 tool poisoning: upstream tool descriptions reach the agent verbatim | Open. Names outside `[A-Za-z0-9_.-]` are refused, but descriptions are not pinned or checked | M2 (TOFU pinning, quarantine) |
| Argument parser differential: the proxy and the upstream may parse the same arguments differently (duplicate JSON keys, for example) | Open. M0 forwards the raw bytes and inspects nothing | M1, when `internal/normalize` parses arguments; it must reject duplicate keys |
| Hung upstream: a call that never returns holds the agent's request | Accepted for M0. The agent can cancel, and cancellation reaches the upstream | M1 adds a per-call deadline |
| Payload size: large arguments or results pass through uncapped | Note only | Revisit with redaction (M2) |
| Result `_meta` from the upstream is forwarded unchanged | Open | Recheck in T0.3 (dual-era) |
| MCP05 injection through results: tool result content, including ANSI escapes and prompt-like text, reaches the agent unchanged | Open. Only error messages and stderr are escaped in M0 | M2 (redaction at the response serialiser) |
| Grandchildren survive a kill: `killCommand` and shutdown signal only the direct child, so the server behind `npx` or `uvx` can outlive the proxy | Open. There is no Job Object (Windows) or process group (Unix) | M1 |
| MCP08 key custody: another local user reads the checkpoint key (inherited ACL on Windows, a pre-existing `0644` file on Unix) and re-signs checkpoints over a rewritten log; or a pre-created, linked or foreign-owned log makes the writer change another file's permissions (confused deputy) or append to a chain someone else controls | Open, being closed by T0.12. Key, public key and log are created exclusively and owner-only without following symlinks, dangling ones included; the resume path refuses links, reparse points and logs owned by another user, and verifies the chain through the held handle before changing permissions. The Windows symlink and foreign-owner tests need privileges this repo's CI does not have yet | Closes when T0.12 merges with the round 2 fix and a `windows-latest` CI job running with `NETGUARD_REQUIRE_PRIVILEGED_TESTS=1` is green |

Closed in M0: upstream input requests are refused, not forwarded. Upstream error messages and stderr are labelled with their origin and have control, bidi, zero-width and line-separator characters escaped. The upstream inherits only an allow-listed environment. Reserved `serve` flags are refused wherever they appear.

The corpus this design answers: Invariant Labs tool poisoning and rug-pulls, Trail of Bits line-jumping and ANSI deception, the MCP specification's security best practices (confused deputy in proxies, token passthrough), OWASP MCP Top 10 (MCP03 tool poisoning, MCP05 command injection, MCP08 missing audit), and arXiv 2603.22489. Links are in [docs/PLAN.md](docs/PLAN.md#sources).

## Hardening guidance for operators

- Run one proxy per credential scope. Upstreams read credentials from their environment; the proxy cannot scope them per call.
- Keep `redact.key_file` and `audit.checkpoint_key` outside the log and blob directories, readable by the proxy user only.
- `netguard audit keygen` creates the checkpoint private key owner-only and never overwrites an existing file, symlink or public key. On Unix the key is created with `O_EXCL` and set to mode `0600` regardless of the umask. On Windows it is created with a protected DACL, applied atomically by `CreateFile`, that grants full control to the creating user and `SYSTEM` only and inherits nothing from its folder, so a key under `C:\ProgramData` is not readable by `BUILTIN\Users`. The public key (`<out>.pub`) is written first, is readable by everyone by design, and is deleted again if the private key cannot be written.
- Excluding `BUILTIN\Administrators` from the key's DACL is intentional. Backup software that uses `SeBackupPrivilege` (VSS, `robocopy /B`) still copies the key, and an administrator who needs it recovers it by taking ownership, which is explicit and shows in the file's owner.
- The audit log gets the same owner-only protection when NetGuard creates it. An existing log is used only if it is a regular file with exactly one link (no symlink, junction or other reparse point, no hard link) and is owned by the user running NetGuard; anything else is refused with an error naming the reason. Its chain is verified through the open handle first, and only then is it reset to owner-only (mode `0600`, or the owner-only DACL). That reset strips read access you gave a log shipper or any other account: run the shipper as the proxy user, or have it read a copy.
- Elevated on Windows: NetGuard sets the owner of the files it creates to your user SID, not `BUILTIN\Administrators`, so its own logs still resume when it runs elevated. A log created by another elevated tool is owned by `BUILTIN\Administrators` and is refused (the error names the owner). If you trust that file, give it to the proxy user with `icacls <log> /setowner <user>` and start again.
- What the code cannot do for you: an administrator or root can still take ownership of the key and read it, and a backup or sync tool copies it with the destination's permissions. Keep the key off synced folders (OneDrive, Dropbox) and out of general-purpose backups. To replace a key, delete the old one (and its `.pub`) deliberately; `keygen` refuses to overwrite either. Keys created before T0.12 on Windows keep their inherited ACL: generate a new key, or remove inherited entries with `icacls <file> /inheritance:r /grant:r <user>:F`. On Windows, key and log paths longer than 260 characters currently fail to open (closed, not open).
- Ship checkpoint hashes to syslog or a SIEM so the chain is anchored outside the host.
- Bind the webhook listener to loopback or a private interface, behind TLS termination you control, and rotate the HMAC key with the `key_id` mechanism.
- Start with `policies/examples/read-only.yaml`. Widen from there.
