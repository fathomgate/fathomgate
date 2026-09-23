# ADR 0005: Hash-chained JSONL audit log

- Status: accepted
- Date: 2026-09-23
- Deciders: Josh Scott

## Context

OWASP MCP Top 10 lists lack of audit and telemetry (MCP08). Generic gateways log tool calls without tying agent identity to device, exact command, diff and approver. The log must be tamper-evident, small enough to keep for years, free of secrets, and consumable by SIEMs.

Three mechanisms were compared in [research brief 03, section 3](../research/03-policy-and-approval-patterns.md). A per-record hash chain detects modification or deletion after the fact but not a rewrite of the whole chain by whoever controls the host. AWS CloudTrail anchors its chain with hourly signed digest files, each embedding the previous digest's signature. Sigstore Rekor adds Merkle inclusion proofs, which are efficient but more than a proxy writing thousands of events a day needs.

OCSF and CEF are what SIEMs ingest, but OCSF is verbose and awkward to hash-chain line by line.

## Decision

We will write the audit log as JSONL, one canonicalised event per line, with `seq`, `prev_hash` and `hash` on every record and a signed Ed25519 checkpoint record every N events or T minutes, verified by `netguard audit verify`. OCSF `API Activity` and CEF are exporters, never the native format.

- `hash = SHA-256(canonical_json(record without hash) || prev_hash)`; genesis `prev_hash` is 64 zeros.
- Checkpoints carry `{type: checkpoint, seq, hash, signature}` signed with a key held outside the log directory.
- Raw device output stays out of the log. Redacted output goes to a blob store keyed by its hash; the event carries the hash.
- Every event carries who, what, where, policy, approval, change safety, outcome and integrity fields, with the same names the console uses.

The normative field list is [audit-event-schema.md](../specs/audit-event-schema.md).

## Consequences

### Positive

- `grep`, `jq` and `diff` work on the log. A single edited line fails `verify`.
- Checkpoint hashes can be shipped to syslog, a ticket or later to Rekor as an external anchor.
- The log never carries secrets, so retention policy is simpler.

### Negative

- A host attacker can rewrite the chain up to the last anchored checkpoint. Mitigated by frequent checkpoints and by encouraging an external sink; not solvable in the proxy alone.
- Key custody for the checkpoint key is an open question (file, OS keyring, KMS).
- Exporters must be kept in step with two external schemas. Mitigated by mapping tables in the spec and fixture tests.

### Neutral

- Append-only file opened with `O_APPEND`, rotated by size; `chattr +a` or object lock where available.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| OCSF as native format | Verbose; per-line canonicalisation and hashing awkward; ties the on-disk shape to an external schema's release cycle. |
| Per-record signatures | Costly and unnecessary; CloudTrail's batch-digest pattern is the proven shape. |
| Merkle tree (Rekor-style) | Efficient proofs are not needed at this volume; a later checkpoint-to-Rekor anchor gets most of the benefit. |
| Database table | Harder to ship to a SIEM, harder to verify offline, easier to edit silently. |

## References

- [Research brief 03, section 3](../research/03-policy-and-approval-patterns.md)
- [CloudTrail log file validation](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-intro.html)
- [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/)
- [OCSF in Security Lake](https://docs.aws.amazon.com/security-lake/latest/userguide/open-cybersecurity-schema-framework.html)
- [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/)
