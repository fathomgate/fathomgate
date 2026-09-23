# T0.7 for security review: 0600 key-mode assertion now runs on Unix only; SaveKey unchanged

- **Task:** T0.7 — Make TestKeyRoundTrip portable — file-mode assertion fails on Windows (-rw-rw-rw-)
- **From → To:** policy-engineer → security-reviewer (go-reviewer also listed)
- **State now:** in review
- **Branch / PR:** `test/audit-key-mode-windows` · none yet (not pushed) · issue [#9](https://github.com/joshscott13/netguard/issues/9)
- **Date:** 2026-09-23

## Done

- `internal/audit/audit_test.go` `TestKeyRoundTrip`: the `Perm() == 0o600` check is guarded by `runtime.GOOS != "windows"`, with a one-line comment giving the reason (Windows ignores Unix permission bits; ACLs govern access). It stays strict on Linux and macOS.
- Same test: the `os.Stat` error is now checked. It was discarded before, so a failed stat would have panicked on a nil `info`.
- No other test in the package asserts a file mode. The `0o600` values in `os.WriteFile` calls are test fixtures, not assertions. Nothing else needed changing.
- `SaveKey` (`key.go:24`, `0o600`) and `NewWriter` (`writer.go:53`, `0o600`) are unchanged.
- `CHANGELOG.md` [Unreleased]: new `### Fixed` entry.

## Look at this first

- `internal/audit/audit_test.go`, `TestKeyRoundTrip`: the diff is 7 lines.

## Deliberately unfinished

- Private-key protection on Windows. On Windows, `SaveKey`'s `0o600` only controls the read-only attribute. The key file inherits the ACL of its parent directory. Hardening it (an explicit DACL through `golang.org/x/sys/windows`) would change production code and add a dependency, so it is out of scope for this test-only task and would need an ADR.

## Reproduce green

```sh
gofmt -l . && go build ./... && go vet ./... && go test -count=1 ./...
# Windows host (go1.26.7, no cgo): all six packages ok. Linux CI still runs the 0600 assertion under -race.
```

## Decisions made without an ADR

- Skip the assertion on Windows rather than approximate it (for example by checking only the owner-write bit): Go's Windows `Mode()` does not reflect access control, so any check there would be meaningless.

## Questions for the receiver

- Should Windows key-file ACL hardening become a tracked task (M1 or later, with an ADR), or should the docs just tell operators to keep `audit.key` in a directory only they can access?
