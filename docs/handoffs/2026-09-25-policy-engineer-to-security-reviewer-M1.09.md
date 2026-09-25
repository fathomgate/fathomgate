# M1-09: the audit signing key gets the owner-only check on every load, and audit verify refuses a private key

- **Task:** M1-09 — Check the audit signing key like every other secret file, and stop audit verify trusting a private key
- **From → To:** policy-engineer → security-reviewer (go-reviewer is the second reviewer)
- **State now:** in review. This PR does not edit `docs/milestones/M1.yaml` or ADR 0028; the orchestrator moves the task.
- **Branch / PR:** `fix/audit-key-custody` · [PR #155](https://github.com/fathomgate/fathomgate/pull/155)
- **Date:** 2026-09-25 (fix round the same day)

## Done

- New `internal/secretfile` (`Read(path, what, limit)`, `ErrUnsafe`): the owner-only open that `cmd/fathomgate/token_unix.go` and `token_windows.go` had, moved so one copy serves the token files, the audit key and (M2) the redaction key. Unix: `O_NOFOLLOW|O_NONBLOCK`, then on the descriptor regular file, `Nlink == 1`, uid == euid, `perm&0o077 == 0`, `fileacl.Extended` false. Windows: `FILE_FLAG_OPEN_REPARSE_POINT`, share `FILE_SHARE_READ`, then on the handle disk file, no reparse or directory attribute, one link, owner == token user, `SE_DACL_PROTECTED`, allow ACEs only for the user and `SYSTEM`, deny ACEs allowed, any other ACE type refused. Other OSes: refused.
- `cmd/fathomgate/token_file.go` (`unix || windows`) calls it; token error texts are the same words.
- `internal/audit/key.go`: `LoadKey` reads through `secretfile.Read(path, "the signing key "+path, 16 KiB)`; errors name the path and the check. `LoadPublicKey` accepts exactly one `PUBLIC KEY` block, returns `ErrPrivateKey` for any `*PRIVATE KEY*` block before parsing. Both refuse a second PEM block.
- `cmd/fathomgate/audit.go`: `loadVerifyKey` maps `ErrPrivateKey` to the ADR 0028 message; exit 2.
- Tests: `key_load_test.go` (all OSes), `key_load_unix_test.go`, `key_load_darwin_test.go`, `key_load_windows_test.go`, `internal/secretfile/*_test.go`, `TestKeyRoundTrip` and `TestAuditVerifyAndKeygen` updated. CI proof lists in `ci.yaml` (Windows elevated, macOS) name the new tests.
- Docs: `docs/specs/audit-event-schema.md` section 5 and 6, SECURITY.md (row and two bullets), threat model (two rows appended, row 38 file names, MCP08 mapping), ARCHITECTURE.md helper paragraph, CHANGELOG Unreleased Security.

## Fix round (security: approve with lows; Go: request changes)

- Merged `origin/main`, `STATUS.md` re-rendered with `tools/status/render.py`.
- L1 / Go 3: `LoadPublicKey` refuses with `ErrPrivateKey` any file containing `PRIVATE KEY` (`bytes.Contains`, before decoding). `onePEMBlock` needs `-----BEGIN ` exactly once, only white space before it and after the END line. Tests: private block before and after, leading private-key text, corrupted private block before the public block, bare base64 before it, text after it, a malformed block.
- L2 / Go 8: `openPublicKey` (`key_unix.go` `O_NONBLOCK`; `key_windows.go` SQOS) and a regular-file check on the open file. `TestKeyLoadersRefuseFIFO`, `TestLoadPublicKeyRefusesDirectory`.
- L3: `secretfile_windows.go` `CreateFile` adds `SECURITY_SQOS_PRESENT|SECURITY_IDENTIFICATION`.
- `Read` refuses `limit <= 0` (`TestReadLimit`). N2: owner refusal names `icacls <file> /setowner "%USERNAME%"`.
- Go 5: `refusal.Unwrap() []error` returns `ErrUnsafe` and the cause (ACL or DACL read errors); `TestRefusalUnwrap`.
- Go 6: `key_load_test.go` is `unix || windows`. Optional `t.Parallel` added to the new cross-platform tests.
- Go 7 / N3: the macOS proof list adds `TestLoadKeyUnixRefusesDirectory`, `TestReadHardLink`, `TestReadFIFO` and `TestKeyLoadersRefuseFIFO` (new `TestReadFIFO`). The Linux job builds the `internal/audit` test binary as the runner user and runs `-test.run OtherOwner` under `sudo`, requiring `--- PASS` for `TestNewWriterRefusesOtherOwner` and `TestLoadKeyUnixRefusesOtherOwner`. No root-owned file lands in the Go caches.
- Go 4: `CLAUDE.md` toolchain line and repo map, and a dated ADR 0011 amendment row. The `x/sys/windows` importers are `internal/audit`, `internal/secretfile`, `internal/proxy` and `cmd/fathomgate` (`listen_windows.go`, Winsock codes).
- Threat model rows: L1, L2 and L3 mitigated; L4 (NFSv4 ACLs outside macOS) and N1 (parent directories) accepted. SECURITY.md, the spec and CHANGELOG match.

## Look at this first

- `internal/secretfile/secretfile_windows.go` `check` and `secretfile_unix.go` `check`: the only place the rules live now.
- `internal/audit/key.go` `LoadPublicKey` and `onePEMBlock`: the trust-anchor refusal and the one-block rule.
- `.github/workflows/ci.yaml` "other-owner tests ran as root": the only `sudo` in CI.

## Deliberately unfinished

- `openExistingLog` keeps its own checks: it opens read-write, has no mode check (it resets the mode after the chain verifies) and uses `errUnsafeLog`. Folding it into `secretfile` would change that contract; not needed for ADR 0028.
- The redaction key (`redact --key-file`, `FATHOMGATE_REDACT_KEY`) is unchanged: M2, per ADR 0028 decision 4.
- Not run locally: the Unix and macOS tests (no Linux or macOS host here; cross-vetted and linted for linux, darwin and freebsd), `-race` (no C compiler). The Windows symlink and other-owner tests skipped locally (unelevated); the elevated CI job runs them with `FATHOMGATE_REQUIRE_PRIVILEGED_TESTS=1`.
- The SQOS flags are not tested against a live named-pipe server; they are pinned by review.

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

- Is running the test binary under `sudo` in the Linux job acceptable as the answer to N3, or should it stay a recorded skip?
