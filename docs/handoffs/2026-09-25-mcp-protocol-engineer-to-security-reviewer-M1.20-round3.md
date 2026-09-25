# M1-20 round 3: Windows refusal names every writer and prints a working fix

- **Task:** M1-20 — fathomgate serve --policy, --inventory, --profiles with embedded profiles; --audit refused until M4
- **From → To:** mcp-protocol-engineer → security-reviewer (then go-reviewer, design-guardian, release-engineer)
- **State now:** merged (PR #171); round 3 in review as a follow-up PR
- **Branch / PR:** `fix/serve-policy-round3` · follow-up to [PR #171](https://github.com/fathomgate/fathomgate/pull/171), which merged before this round was pushed
- **Date:** 2026-09-25

## Done

- `internal/configfile/configfile_windows.go`: one message names every account that can write, with `LookupAccount` and the SID as a fallback. It prints a Command Prompt command with the real path: `icacls "<path>" /inheritance:r /grant:r "%USERNAME%:F" SYSTEM:F Administrators:F && icacls "<path>" /remove:g *<SID>...`. The `/remove:g` step is needed because `/grant:r` leaves other accounts' explicit entries in place. It also says that users who can write the directory can still replace the file. The redundant owner test is gone.
- Unix messages carry the same directory clause. A comment and `TestLinuxPOSIXACLWrite` show that a named-user write ACL appears as `g+w` through the mask and is refused.
- `ErrUnsafe` text is now "the file's integrity cannot be established". Refusals unwrap to `ErrUnsafe` and to the system call's error.
- `yamlstrict`: empty documents are detected with `d.Body == nil`, and a comment explains why `isKey` compiles on the error path. `TestObligationsPartitioned` also checks that every `cannotMeet` entry is in `policy.KnownObligations`.
- Docs:
  - ADR 0011 has a dated amendment adding `internal/configfile` to the importers.
  - profile-schema 8.3 now says what errors quote: only decode errors are sanitised; validation errors quote ids, names and patterns by design. It also records the directory advice and the fix command.
  - install.md covers file placement for Unix (0700, `chmod go-w`, the umask 002 note for Debian and Ubuntu) and Windows (the Command Prompt fix).
  - The threat-model rows are updated, including residuals, the M2 follow-up for parent directories, and the open conformance leg owned by M1-28.

## Look at this first

- `TestWindowsRefusalNamesEveryWriterAndFixes`: it runs the printed command through `cmd /c` and then checks that the file passes.

## Deliberately unfinished

- The parent-directory check (like OpenSSH `StrictModes`) is left to M2, per the threat-model row.

## Reproduce green

```sh
go test -count=1 ./internal/configfile/ ./cmd/fathomgate/ ./internal/yamlstrict/
GOOS=windows ~/go/bin/golangci-lint run ./...; GOOS=linux ~/go/bin/golangci-lint run ./...; GOOS=darwin ~/go/bin/golangci-lint run ./...
```

## Decisions made without an ADR

- The fix command targets Command Prompt, not PowerShell, because PowerShell does not expand `%USERNAME%`. The message and install.md both say so.

## Questions for the receiver

- None.
