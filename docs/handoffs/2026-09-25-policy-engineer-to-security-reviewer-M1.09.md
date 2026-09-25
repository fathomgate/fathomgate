# M1-09: the audit signing key gets the owner-only check on every load, and audit verify refuses a private key

- **Task:** M1-09 — Check the audit signing key like every other secret file, and stop audit verify trusting a private key
- **From → To:** policy-engineer → security-reviewer (go-reviewer is the second reviewer)
- **State now:** in review. This PR does not edit `docs/milestones/M1.yaml` or ADR 0028; the orchestrator moves the task.
- **Branch / PR:** `fix/audit-key-custody` · PR link in the PR description (opened with this note)
- **Date:** 2026-09-25

## Done

- New `internal/secretfile` (`Read(path, what, limit)`, `ErrUnsafe`): the owner-only open that `cmd/fathomgate/token_unix.go` and `token_windows.go` had, moved so one copy serves the token files, the audit key and (M2) the redaction key. Unix: `O_NOFOLLOW|O_NONBLOCK`, then on the descriptor regular file, `Nlink == 1`, uid == euid, `perm&0o077 == 0`, `fileacl.Extended` false. Windows: `FILE_FLAG_OPEN_REPARSE_POINT`, share `FILE_SHARE_READ`, then on the handle disk file, no reparse or directory attribute, one link, owner == token user, `SE_DACL_PROTECTED`, allow ACEs only for the user and `SYSTEM`, deny ACEs allowed, any other ACE type refused. Other OSes: refused.
- `cmd/fathomgate/token_file.go` (`unix || windows`) calls it; token error texts are the same words.
- `internal/audit/key.go`: `LoadKey` reads through `secretfile.Read(path, "the signing key "+path, 16 KiB)`; errors name the path and the check. `LoadPublicKey` accepts exactly one `PUBLIC KEY` block, returns `ErrPrivateKey` for any `*PRIVATE KEY*` block before parsing. Both refuse a second PEM block.
- `cmd/fathomgate/audit.go`: `loadVerifyKey` maps `ErrPrivateKey` to the ADR 0028 message; exit 2.
- Tests: `key_load_test.go` (all OSes), `key_load_unix_test.go`, `key_load_darwin_test.go`, `key_load_windows_test.go`, `internal/secretfile/*_test.go`, `TestKeyRoundTrip` and `TestAuditVerifyAndKeygen` updated. CI proof lists in `ci.yaml` (Windows elevated, macOS) name the new tests.
- Docs: `docs/specs/audit-event-schema.md` section 5 and 6, SECURITY.md (row and two bullets), threat model (two rows appended, row 38 file names, MCP08 mapping), ARCHITECTURE.md helper paragraph, CHANGELOG Unreleased Security.

## Look at this first

- `internal/secretfile/secretfile_windows.go` `check` and `secretfile_unix.go` `check`: the only place the rules live now.
- `internal/audit/key.go` `LoadPublicKey`: `strings.Contains(block.Type, "PRIVATE KEY")` is the trust-anchor refusal.

## Deliberately unfinished

- `openExistingLog` keeps its own checks: it opens read-write, has no mode check (it resets the mode after the chain verifies) and uses `errUnsafeLog`. Folding it into `secretfile` would change that contract; not needed for ADR 0028.
- The redaction key (`redact --key-file`, `FATHOMGATE_REDACT_KEY`) is unchanged: M2, per ADR 0028 decision 4.
- Not run locally: the Unix and macOS tests (no Linux or macOS host here; cross-vetted and linted for linux, darwin and freebsd), `-race` (no C compiler). The Windows symlink and other-owner tests skipped locally (unelevated); the elevated CI job runs them with `FATHOMGATE_REQUIRE_PRIVILEGED_TESTS=1`.
- `CLAUDE.md` says `cmd/fathomgate` imports `x/sys/windows` "for the `--listen-token-file` DACL check"; that check is now in `internal/secretfile` (cmd still imports it for Winsock codes). Left for the orchestrator.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check && make licences-check
go test -count=1 -v -run 'LoadKey|LoadPublicKey|Keygen|TestRead' ./internal/audit/ ./internal/secretfile/ ./cmd/fathomgate/
FATHOMGATE_REQUIRE_PRIVILEGED_TESTS=1 go test -count=1 -v -run Windows ./internal/audit/   # elevated Windows
```

## Decisions made without an ADR

- The shared checker is a new internal package (`internal/secretfile`), not unexported code in `internal/audit`: token files live in `cmd/fathomgate` and the redaction key in `internal/redact`, so an unexported helper cannot serve all three. It exports only `Read` and `ErrUnsafe`.
- A failed macOS ACL read is now a refusal (`ErrUnsafe`) for token files too, not a plain error; both fail closed.
- Both key loaders refuse a file with more than one PEM block, and cap the file at 16 KiB. ADR 0028 does not ask for this; it stops a `.pub` that also carries a private key.

## Questions for the receiver

- Is `strings.Contains(block.Type, "PRIVATE KEY")` wide enough, given that any non-`PUBLIC KEY` type is refused anyway (only the message differs)?
- Should `LoadPublicKey` open with `O_NOFOLLOW` too? ADR 0028 says the public key needs no owner check, so it does not.
