# M1-41: the serve listener tests retry only when the bind error is address in use

- **Task:** M1-41 — Retry the serve listener tests only on address in use (typed error from run)
- **From → To:** mcp-protocol-engineer → go-reviewer
- **State now:** in review
- **Branch / PR:** test/serve-listen-typed-retry · PR link in the PR's first comment and on the board
- **Date:** 2026-09-25

## Done

- `cmd/fathomgate/serve.go`: `serveContext` calls the new `serveBinding` with `binder{listen: listenTCP, hold: holdWildcards}`, which is what it bound with before. `serveBinding` is the old body, and it passes `b.listen` and `b.hold` to `bindLoopback`. Nothing else changed: flags, exit codes, stderr text and the order of steps are the same.
- `cmd/fathomgate/listen_bind_test.go`: `serveListenOtherFamilyTaken` calls `serveBinding` with a `bindRecorder`. It retries only when the one recorded bind is `127.0.0.1:<port>` and `addrTaken(err)` is true. Any other error on that bind fails the attempt. It still asserts the exit code and stderr text, and it now also asserts the bind sequence and the release of every socket, like `refusesTakenOtherFamily` does.
- `cmd/fathomgate/listen_windows_test.go`: the same change to `serveListenWildcardHeld`. It retries only when a recorded loopback bind error is `addrTaken`. Otherwise it expects both loopbacks bound and the hold refused.
- `checkReleasedOnReturn` is new: a deferred `checkReleased` that is skipped once `t.Failed()`. The two deferred sites (`refusesTakenOtherFamily`, `refusesHeldWildcard`) and both serve attempts use it. The direct `checkReleased` calls in `TestBindLoopbackExclusiveWindows` and `heldSocketsCloseReleases` are unchanged.

## Look at this first

- The `binder` doc comment in `serve.go`. The seam is how serve binds, not a returned error. The retry is decided on each bind's own error, which `bindRecorder` already records, so `run()` and `serveContext` keep their signatures. Returning the error from `serveContext` would not have been enough: the other-family and wildcard refusals wrap the same errno, so `addrTaken` on the returned error cannot tell the first bind from the refusal.

## Deliberately unfinished

- Nothing.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check && make licences-check
go test -count=3 -v -run 'TestServeListenOtherFamilyTaken|TestServeListenWildcardHeldWindows|TestBindLoopbackRefusesTakenOtherFamily|TestBindLoopbackRefusesHeldWildcardWindows' ./cmd/fathomgate
make conformance   # serve.go changed; run by hand on Windows: 8 legs and era pairs green
```

Mutation: making `serveBinding` bind with `listenTCP, holdWildcards` instead of `b.listen, b.hold` fails both serve tests (`binds [], holds 0`).

## Decisions made without an ADR

- `serveBinding` and `binder` are unexported and change no interface: the CLI, the flags and the text are untouched.

## Questions for the receiver

- Should the `checkReleased` calls in `TestBindLoopbackExclusiveWindows` and `heldSocketsCloseReleases`, which are not deferred, also skip once `t.Failed()`? I left them alone: they run after `t.Errorf` (not `Fatalf`) checks, and their lines there are real information.
