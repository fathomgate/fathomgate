# T0.12 for security review: audit key and log are owner-only on every OS (protected DACL on Windows, O_EXCL + 0600 on Unix)

- **Task:** T0.12 — Restrict the audit key file to its owner on Windows (DACL) and open keys with O_EXCL plus chmod on every OS
- **From → To:** policy-engineer → security-reviewer (go-reviewer also listed)
- **State now:** in review (round 1 findings addressed)
- **Branch / PR:** `fix/audit-key-perms` on `origin/land/m0-stack` (PR #25) · none yet (not pushed) · issue [#18](https://github.com/joshscott13/netguard/issues/18) · commits `970c1f5` (round 0), round 1 on top
- **Date:** 2026-09-23

## Done

- `internal/audit/key.go`: `SaveKey`, `SavePublicKey` and the new `WriteKeyPair` all create exclusively through `createExclusive`; a failed write deletes the file through its handle (`fill`/`discard`). The OS contract (`createExclusive`, `removeCreated`, `openExistingLog`, `restrictOpenFile`) is documented at the top of the file.
- `internal/audit/key_windows.go`: key and new log are created with `CreateFile(CREATE_NEW)` and `SECURITY_ATTRIBUTES` holding `O:<user>D:P(A;;FA;;;<user>)(A;;FA;;;SY)`, so the DACL is in place from the first instant. Handles are not inheritable and have `DELETE` for delete-through-handle.
- `internal/audit/key_unix.go` (`//go:build unix`): `O_CREATE|O_EXCL`, then `f.Chmod` on the descriptor (0600 private, 0644 public). `key_other.go` fails closed (`errors.ErrUnsupported`) on any other GOOS.
- `internal/audit/writer.go`: `NewWriter` = `openLog` (create, or open existing with the checks below) + `resumeLog` (verify through the held handle, then restrict).
- `cmd/netguard/audit.go`: `keygen` refuses an existing `--out` or `<out>.pub` and calls `audit.WriteKeyPair`. No `--force`.
- `golang.org/x/sys` v0.41.0 → v0.47.0, now direct (GO-2026-5024; newest release with the `go 1.25.0` floor). `go.sum`: only the two x/sys lines change.
- Docs: `SECURITY.md` (hardening, threat-model row), `docs/specs/audit-event-schema.md` sections 4 and 5, `CHANGELOG.md` [Unreleased] Security, `CLAUDE.md` toolchain facts.

## Review round 1

Findings from security-reviewer (REQUEST CHANGES), each fixed:

| Finding | Fix |
| --- | --- |
| H1 resume path follows links | Unix: `O_RDWR\|O_APPEND\|O_NOFOLLOW`, then fstat: regular file, `nlink == 1`, `uid == geteuid()`; ELOOP/EMLINK reported as a symlink. Windows: `OPEN_EXISTING` with `FILE_FLAG_OPEN_REPARSE_POINT`, then `GetFileType == FILE_TYPE_DISK`, `GetFileInformationByHandle`: no `FILE_ATTRIBUTE_REPARSE_POINT`, no directory, `NumberOfLinks == 1`. All refusals wrap `errUnsafeLog`. |
| H2 foreign owner keeps WRITE_DAC | Windows: `GetSecurityInfo(OWNER)` on the handle must equal the token user. Unix: `st_uid == geteuid()`. Otherwise refused; nothing is changed. |
| M3 TOCTOU in verify-by-path | The log is opened once for read and append; `resumeLog` runs `VerifyReader` on that handle. `restrictOpenFile` (chmod / `SetSecurityInfo(DACL\|PROTECTED_DACL)`) runs only after the chain verifies. The misleading comment is gone. |
| L4 remove-by-path | Fixed, not just documented. Windows: `SetFileInformationByHandle(FileDispositionInfo, DeleteFile=TRUE)` on the handle we created (exact, no race). Unix: unlink only if `Lstat(path)` is `os.SameFile` as `f.Stat()` (same dev/ino); the residual Lstat→unlink window needs write access to the directory, which already allows deleting that entry, so it gives an attacker nothing. Comment in `key_unix.go`. |
| Q1 `.pub` overwrite | `SavePublicKey` is exclusive. `WriteKeyPair` writes `.pub` first, keeps it open, writes the private key, and deletes `.pub` through its handle if that fails. |
| Q2 correct only after checks | Existing logs are corrected only after H1, H2 and chain verification pass; everything else is refused with a reason. `SECURITY.md` says log-shipper read access is stripped. |
| Q3 long paths | Recorded as a follow-up below. Fails closed. |
| SECURITY.md | Administrators exclusion explained (SeBackupPrivilege backup still works, recovery by take-ownership); new threat-model row "MCP08 key custody", closed by T0.12. |

New regression tests:

- `TestNewWriterRefusesSymlink` (Unix; target mode stays 0644), `TestNewWriterWindowsRefusesSymlink` (skips unelevated: "A required privilege is not held by the client"), `TestNewWriterWindowsRefusesJunction` (runs without privilege; `CREATE_NEW` on the junction returns Access denied, target dir DACL unchanged).
- Hard link: `TestNewWriterRefusesHardLink` (all OS), `TestNewWriterHardLinkKeepsMode` (Unix), `TestNewWriterWindowsHardLinkKeepsDACL`.
- Other owner: `TestNewWriterRefusesOtherOwner` (Unix, root only; ran as root in Docker, skipped as uid 1000), `TestNewWriterWindowsRefusesOtherOwner` (skips unelevated: "This security ID may not be assigned as the owner of this object").
- Verify before restrict: `TestNewWriterBrokenChainKeepsMode`, `TestNewWriterWindowsBrokenChainKeepsDACL`.
- Swap before verify: `TestResumeVerifiesThroughHeldHandle` replaces the path between `openLog` and `resumeLog`. Linux: the rename succeeds, the writer resumes the original chain (seq 3), and the swapped-in file is untouched. Windows: the rename fails (no `FILE_SHARE_DELETE` on the held handle), the writer still resumes.
- Q1: `TestSavePublicKeyRefusesExisting`, `TestWriteKeyPair` (existing pub: no private key written; existing key: pub deleted again), `TestSavePublicKeyMode` (Unix), and the `keygen` case in `cmd/netguard/main_test.go`.
- Mutation check: letting `NumberOfLinks > 1` through makes `TestNewWriterWindowsHardLinkKeepsDACL` fail.

## Look at this first

- `internal/audit/writer.go` `openLog` / `resumeLog`, then `openExistingLog` and `checkLogFile` in `key_unix.go` and `key_windows.go`.

## Deliberately unfinished

- Follow-up (Q3): raw `CreateFile` does not add the `\\?\` prefix, so Windows key and log paths over `MAX_PATH` fail to open (closed). Fix by prefixing absolute paths with `\\?\` as `os.OpenFile` does.
- ADR 0011's x/sys row (`v0.41.0`, reached only via `segmentio/asm`) is stale. Not edited here by instruction; it gets a separate docs PR.
- The Windows symlink and other-owner tests skip on an unelevated host (this one). They run on an elevated host or with Developer Mode.
- No `--force` on `keygen` (CLI surface outside ADR 0012).

## Reproduce green

```sh
gofmt -l . && go build ./... && go vet ./... && go test -count=3 ./...        # Windows go1.26.7: 7 packages ok
go test -count=1 -v ./internal/audit/                                          # Windows: 2 SKIP (symlink, other owner) with reasons
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/src -w /src -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local golang:1.25 \
  bash -c 'make toolchain-check && go test -race ./... && make vulncheck'    # root: all ok incl. TestNewWriterRefusesOtherOwner; No vulnerabilities found.
# same image with --user 1000:1000 -e HOME=/tmp -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath:
go test -race ./internal/audit/ ./cmd/netguard/                                # ok; other-owner test skips (needs root)
GOOS=windows go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...          # No vulnerabilities found.
docker run --rm -v "$(pwd -W)":/src -w /src golangci/golangci-lint:v2.4.0 golangci-lint run ./...   # 0 issues (also -e GOOS=windows)
CGO_ENABLED=0 GOOS={windows,linux,darwin,freebsd} go build ./cmd/netguard   # ok
python tools/status/render.py --check
```

## Decisions made without an ADR

- DACL principals: current user and `SYSTEM`, not Administrators (see `SECURITY.md`).
- Owner set explicitly to the process user at creation. A consequence of H2: a log created by other tools while elevated (owner `BUILTIN\Administrators`) is refused on resume; the error names the owner.
- `WriteKeyPair` is a new exported function in `internal/audit` (internal package, not public API).

## Questions for the receiver

- Is failing closed on a non-Unix, non-Windows GOOS (`key_other.go`) acceptable, given no such target is built?
