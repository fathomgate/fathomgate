# ADR 0028: Audit signing key custody: an owner-only file checked on every open, and a verifier that trusts only a public key

- Status: accepted
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer), accepted by the maintainer 2026-09-25 with the answers under *Decisions on the open questions*; proposed by the orchestrator for M1 (board task M1-03, for M1-09, carried from T0.55); owner policy-engineer; reviewers security-reviewer, go-reviewer
- Answers in part: the [PLAN.md open question](../PLAN.md#open-questions-and-risks) "Key custody for audit checkpoints and the redaction HMAC: file, OS keyring or KMS", for the audit signing key only

## Context

`fathomgate audit keygen` writes an Ed25519 private key (PKCS#8 PEM, `0600`, a protected owner-only DACL on Windows since T0.12) and its public half. Writing is careful; reading is not. The security review of PR #112 (medium, predating that PR, MCP08) found:

- `audit.LoadKey` (`internal/audit/key.go`) calls `os.ReadFile`. It follows a symbolic link and checks no owner, mode, link count, Windows DACL or macOS extended ACL. Another local user who can replace or link the file can make fathomgate sign with a key they hold, and a key file left group-readable is used without a word.
- `audit.LoadPublicKey` accepts a private key file and derives the public half, so `fathomgate audit verify --key <signing key>` trusts the very file the signer uses. A verifier should never need, or be handed, the secret; and a check that passes with the signer's own file proves nothing to a third party.

Nothing signs in production yet: `serve --audit` stays refused until M4 ([ADR 0027](0027-serve-policy-inventory-profiles-flags.md)). The fix is cheap now and expensive after operators have key files in the field. The same owner-only open already exists twice: `openExistingLog` for the audit log and `readTokenFile` for listen tokens ([ADR 0016](0016-streamable-http-listener.md), T0.31), with `internal/fileacl` for macOS ACLs.

## Decision

We will keep the audit signing key in a file for the open-source core, open it with the same owner-only checks as the audit log and the listen token file on every load, and make every verification path accept a public key only.

1. **Loading the private key** (`LoadKey`, and whatever `serve --audit` uses in M4) opens the file without following a final symbolic link (`O_NOFOLLOW` on Unix; `FILE_FLAG_OPEN_REPARSE_POINT` on Windows) and refuses it unless it is a regular file with one link, owned by the current user, with no group or other permission bits (`0600` or `0400`), no macOS extended ACL (`fileacl.Extended`), and on Windows a protected DACL whose allow entries name only the owner and `SYSTEM`. The checks run on the open handle, not the path. The error names the path and the failed check, never the content. There is no flag to skip the checks.
2. **Verification** (`LoadPublicKey`, `audit verify --key`) accepts only a `PUBLIC KEY` PEM block. A `PRIVATE KEY` block is refused with `--key must be the public key (<path>.pub); a verifier never needs the signing key`. The public key file needs no owner check: it is not secret, and its integrity is the operator's to establish (for example by comparing it with the one published beside the log).
3. **Custody beyond a file.** OS keyrings, PKCS#11 and cloud KMS are not in the core for now. When one is added it goes behind a `Signer` seam in `internal/audit` (a `crypto.Signer`), decided by its own record, and the file stays the default.
4. **The redaction HMAC key** (`FATHOMGATE_REDACT_KEY`, ADR 0006) is not built here. When it lands in M2, the file checks in point 1 apply to it whenever it is read from a file (decision 1); the M2 record decides how the key reaches `serve`, not whether it is checked.

`docs/specs/audit-event-schema.md` (key handling and verify), the `audit` CLI help, `docs/security/threat-model.md` (a row for key substitution and for verifying with the signing key) and `SECURITY.md` change in the implementing PR.

## Consequences

### Positive

- Key substitution through a link or a loose mode is refused before a single checkpoint is signed.
- Verification cannot quietly depend on the secret; an auditor is handed a `.pub` file and nothing else.
- One owner-only check in three places, so a fix to one (a new ACL form) is a fix to all.

### Negative

- An operator who stored the key on a filesystem without ownership (FAT, some network shares, a Windows share mapped into WSL) cannot use it. Mitigated by the error naming the check; the answer is to move the key.
- Anyone who has been running `audit verify --key` with the private key must switch to the `.pub` file. No production users exist before M4, so the cost is scripts in the tree and docs.

### Neutral

- `audit keygen` output and file modes do not change.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| OS keyring now (macOS Keychain, Windows DPAPI, Secret Service) | Three platform integrations and a new dependency for a feature nobody signs with before M4; the file checks are needed anyway for the default path. |
| Cloud KMS in the core | ADR 0020 keeps the core small and dependency-light; a `Signer` seam lets a KMS signer live outside it. |
| Warn instead of refusing a loose key file | A warning on stderr in a supervised process is read by nobody; a signing key with the wrong owner is a compromise, not a nit. |
| Keep accepting a private key in `verify` for convenience | It is the finding: a verification that needs the signer's secret is not independent. |

## Decisions on the open questions

Accepted by the maintainer, Josh Scott, on 2026-09-25, with these answers:

1. **The redaction key: same checks.** The file checks in point 1 apply to the redaction key when it lands in M2 (point 4).
2. **`0400` as well as `0600`: accepted,** as written and as the listen token file allows.
3. **Group-owned service accounts: refused for now.** No group-owned keys; a later record may add them.

## References

- Security review of PR #112 (T0.55 notes in [M0.yaml](../milestones/M0.yaml)); T0.12 (Windows DACL on write)
- [ADR 0005](0005-hash-chained-jsonl-audit.md), [ADR 0006](0006-keyed-hmac-redaction.md), [ADR 0016](0016-streamable-http-listener.md) (the listen token file checks), [ADR 0020](0020-open-core-apache-2.md)
- `internal/audit/key.go`, `key_unix.go`, `key_windows.go`; `cmd/fathomgate/listen_token.go`; `internal/fileacl`
- [M1 board](../milestones/M1.yaml): M1-03 (this record), M1-09 (the fix)
