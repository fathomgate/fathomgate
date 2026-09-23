# T0.12 for security review: audit key and log are owner-only on every OS (protected DACL on Windows, O_EXCL + 0600 on Unix)

- **Task:** T0.12 — Restrict the audit key file to its owner on Windows (DACL) and open keys with O_EXCL plus chmod on every OS
- **From → To:** policy-engineer → security-reviewer (go-reviewer also listed)
- **State now:** in review
- **Branch / PR:** `fix/audit-key-perms` on `origin/land/m0-stack` (PR #25) · none yet (not pushed) · issue [#18](https://github.com/joshscott13/netguard/issues/18)
- **Date:** 2026-09-24

## Done

- `internal/audit/key.go` `SaveKey`: exclusive create through `createOwnerOnly`, write, `Sync`, close; a failed write removes the file. An existing path (file or symlink) fails with an error wrapping `fs.ErrExist` and is left untouched.
- `internal/audit/key_windows.go`: `CreateFile(CREATE_NEW)` with `SECURITY_ATTRIBUTES` holding `O:<user>D:P(A;;FA;;;<user>)(A;;FA;;;SY)`, so the DACL is in place from the first instant (no window for another user to open a handle). Handle not inheritable. Resume path: `OPEN_EXISTING` with append access plus `WRITE_DAC`, then `SetSecurityInfo(DACL|PROTECTED_DACL)`; the owner is left unchanged.
- `internal/audit/key_unix.go` (`//go:build !windows`): `O_CREATE|O_EXCL`, `0600`, then `f.Chmod(0o600)`; resume path opens `O_WRONLY|O_APPEND` and `f.Chmod(0o600)`.
- `internal/audit/writer.go` `NewWriter`: creates the log exclusively; on `fs.ErrExist` opens it for append and resets it to owner-only. Verification now runs after the open, on the file the writer holds; a broken chain closes the handle and refuses as before.
- `golang.org/x/sys` v0.41.0 → v0.47.0, now a direct require. `go.sum`: only the two x/sys lines change.
- Tests: `TestSaveKeyRefusesExisting` (all OS); `key_unix_test.go` (existing `0644` refused and not chmodded, symlink refused and its target not created, new log `0600`, existing `0644` log corrected on resume); `key_windows_test.go` (reads the DACL back and asserts protected, no inherited ACEs, no Everyone / Users / Authenticated Users, only user and SYSTEM allow ACEs, owner is the user, inside a folder whose inheritable DACL grants those groups read like `C:\ProgramData`). The T0.7 skip of the `0600` assertion on Windows stays.
- Docs: `SECURITY.md` hardening (interim `icacls` advice replaced; residual advice kept), `docs/specs/audit-event-schema.md` sections 4 and 5, `CHANGELOG.md` [Unreleased] Security, `CLAUDE.md` toolchain facts, `keygen --out` help text.

## Look at this first

- `internal/audit/key_windows.go` `ownerOnlySDDL` and `createOwnerOnly`: the whole guarantee is that SDDL string plus `CREATE_NEW`.

## Deliberately unfinished

- No `--force` on `keygen`: it would be CLI surface outside ADR 0012's scope (that record covers `serve` only). `keygen` already refused an existing `--out`; now `SaveKey` enforces it too, without a race.
- `SavePublicKey` still uses `os.WriteFile` `0644`, so `keygen` overwrites an existing `<out>.pub` silently. Not a confidentiality issue, but it can swap a verifier's key. Left for a follow-up if you agree.
- ADR 0011's table still says x/sys `v0.41.0`, reached only through `segmentio/asm`. The module was not added or removed, so guardrail 2 does not strictly trigger; I did not edit an accepted record.
- Windows paths longer than `MAX_PATH` are not prefixed with `\\?\` (os.OpenFile does this; raw `CreateFile` does not). Operators' key paths are short; noted in case you want it.

## Reproduce green

```sh
gofmt -l . && go build ./... && go vet ./... && go test -count=3 ./...        # Windows, go1.26.7: 7 packages ok
go test -count=1 -v -run 'Key|Writer|DACL' ./internal/audit/                  # Windows: TestSaveKeyWindowsDACL, TestWriterWindowsDACL PASS
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/src -w /src -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local golang:1.25 \
  bash -c 'make toolchain-check && go test -race ./... && make vulncheck'    # go1.25.14: all ok, "No vulnerabilities found."
GOOS=windows go run golang.org/x/vuln/cmd/govulncheck@v1.7.0 ./...          # No vulnerabilities found.
docker run --rm -v "$(pwd -W)":/src -w /src golangci/golangci-lint:v2.4.0 golangci-lint run ./...   # 0 issues (also with -e GOOS=windows)
CGO_ENABLED=0 GOOS=windows go build ./cmd/netguard && CGO_ENABLED=0 GOOS=linux go build ./cmd/netguard
```

Mutation check done locally: dropping `PROTECTED_DACL_SECURITY_INFORMATION` from the resume path, or passing no security attributes to `CreateFile`, makes the Windows tests fail. (Dropping only the `P` from the creation SDDL does not: Windows marks an explicitly supplied creation DACL protected anyway. The `P` stays as intent.)

## Decisions made without an ADR

- DACL principals: current user and `SYSTEM`, not Administrators. `SYSTEM` covers services running as LocalSystem and OS components; granting Administrators adds nothing the proxy needs, and an administrator who wants the key must take ownership explicitly, which is visible in the owner field and auditable.
- Owner set explicitly to the process user at creation, so an elevated process does not leave `BUILTIN\Administrators` as owner.
- Existing audit logs are reset to owner-only on every open (brief: "refused or corrected"). This drops any read access an operator granted a log shipper; documented in `SECURITY.md`.

## Questions for the receiver

- Should resuming a log correct its permissions (current behaviour) or refuse a log that is readable or writable by others?
- Do you want `SavePublicKey` to refuse an existing file too (the silent `.pub` overwrite)?
