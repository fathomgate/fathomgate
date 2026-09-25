# M1-40 fix round 1: OS-level wildcard release proof restored, retries only on address in use

- **Task:** M1-40 — Deflake the loopback bind tests (other family taken, release after refusal)
- **From → To:** mcp-protocol-engineer → go-reviewer
- **State now:** in review
- **Branch / PR:** `test/deflake-listen-bind` · https://github.com/fathomgate/fathomgate/pull/186
- **Date:** 2026-09-25

## Done

- **Blocker:** new `TestHeldSocketsCloseReleasesWindows` (`cmd/fathomgate/listen_windows_test.go`). It binds `localhost:0` with `holdWildcards` and closes the listeners, then runs `checkReleased`. It then re-binds `127.0.0.1:P` and `[::1]:P` with `net.Listen`, and each wildcard kind with `bindWildcard`. A rebind that fails with address in use tries a fresh port, up to `squatAttempts` (50), so a genuine leak fails every attempt. `ExclusiveWindows` keeps `checkReleased` and the `heldSockets` length check. The new test is in the Windows CI "H1 loopback tests ran" `-run` list and `--- PASS` grep.
- **Item 2:** `refusesTakenOtherFamily` and `refusesHeldWildcard` now `defer rec.checkReleased(t)`, so every return path, retry included, checks that what bindLoopback bound was closed.
- **Item 3:** added per-OS `addrTaken(err)`:
  - `listen_unix_test.go`: `EADDRINUSE`
  - `listen_windows_test.go`: `WSAEADDRINUSE` or `WSAEACCES`
  - `listen_other_test.go`: always false

  A first-bind error that is not address in use is `t.Fatalf` at once. The serve variants keep the stderr match.
- **Item 4:** godoc on `recordedHold.Close`, and a line saying that `bindRecorder` sees only sockets bound through the listenFunc and holdFunc it injects.

## Look at this first

- `heldSocketsCloseReleases` in `listen_windows_test.go`.

## Mutations (Windows 11, local)

| Mutation | Result |
| --- | --- |
| `heldSockets.Close` breaks at `i == 2` (your mutation) | `TestHeldSocketsCloseReleasesWindows` fails: 50 fresh ports each report `[::]:P (dual-stack) still bound` |
| drop `first.Close()` (listen.go other-family refusal) | `RefusesTakenOtherFamily` fails 3/3 subtests |
| drop the loopback closes before a hold refusal | `RefusesHeldWildcardWindows` fails |
| drop `l.held.close()` in `heldListener.Close` | `ExclusiveWindows` and `HeldSocketsCloseReleasesWindows` fail |

## Deliberately unfinished

- None of the new retry paths has fired in any stress run: 0 retries in 200x locally, and 0 in the earlier CI stress on Linux, macOS and Windows. They cover a rare race.
- On platforms that are neither Unix nor Windows, `addrTaken` is always false, so any first-bind collision fails the test there at once.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check
go test -v -run 'Bind|Listen|HeldSockets' -count=200 ./cmd/fathomgate/   # 200x, 0 retries, 0 fails locally
```

## Decisions made without an ADR

- The OS-level release proof lives in its own test rather than inside `ExclusiveWindows`, so that the retry loop does not repeat the squat matrix and the reachability checks on every attempt.
- The new test also re-binds both loopbacks, not only the wildcards.

## Questions for the receiver

- None.
