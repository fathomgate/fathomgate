# T0.39 and T0.25 are in PR #77: 5 s probe bound, one restart with initialize only, exit status at startup

- **Task:** T0.39 — Stop netguard hanging at startup on upstreams that never answer server/discover (probe timeout, restart, straight to initialize); with T0.25 — Report the upstream's exit status when it dies at startup, not only EOF
- **From → To:** mcp-protocol-engineer → security-reviewer (then go-reviewer)
- **State now:** in review
- **Branch / PR:** `fix/proxy-discover-probe-timeout` · https://github.com/joshscott13/netguard/pull/77
- **Date:** 2026-09-24

## Done

- `internal/proxy/proxy.go`: `connect` / `probeConnect` implement the ADR 0018 Decision. The first `Connect` is bounded at `discoverProbeTimeout` (5 s). The retry happens only when that bound runs out while the startup ctx is live. The first process is killed at the deadline by `context.AfterFunc`, then reaped, and one `warn` line is logged. A new transport is then connected with `ProtocolVersion: "2025-11-25"`. There is no third attempt.
- `proxy.Upstream` is now `{Server string; NewTransport func() mcp.Transport}`. It is recorded in ADR 0012 (API list, plus an amendment row) and in profile-schema 8.3. Profile-schema 8.4's "Upstream, once at connect" bullet is updated.
- T0.25: `trackedTransport.kill(grace)` gives the process up to 2 s to end on its own after a failed connect or `tools/list`. The error then ends with `; upstream process ended: exit status N`, which is exec's text taken from the error go-sdk's `Close` returns.
- `internal/proxy/connect_test.go`: probe answered or refused (no restart); probe unanswered (restart, initialize only); second attempt hangs up or is silent (clear error, no third attempt); startup budget inside the bound (no restart); a stdio restart with a real child; exit status 3 at spawn and exit status 4 on `tools/list`.
- `tests/integration/test_upa_netmiko.py`: the strict xfail is removed, and the test asserts one `WARN` restart line. Matrix row 2 loses its T0.39 caveat.

## Look at this first

- `trackedTransport.Connect`, `killProcess` and `kill` in `internal/proxy/proxy.go`. The process is now recorded under the mutex because the `AfterFunc` goroutine can fire during `Start`. `kill(grace)` runs go-sdk's `Close` in a goroutine and kills the process after the grace. Check that no path reads `ProcessState` or calls `Wait`, and that the grace can never outlive the startup budget (`graceFor` returns 0 once ctx is done).

## Deliberately unfinished

- `docs/milestones/M0.yaml`: not edited (the orchestrator syncs the board). Row 2's status word and its "Why the row is not `passing`" run-note bullet are T0.41's.
- `-race` was not run locally: there is no gcc on this Windows machine, so CI's `go test -race` is the race gate. Tier 2 `tier2-upa` was not run locally either (its install needs a POSIX venv layout); CI runs it on the PR.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check
go test ./internal/proxy/ -count=5 -run 'TestDiscoverProbe|TestStartupExitStatus|TestStdioUpstream|TestConnectFailure'
make conformance
```

## Decisions made without an ADR

- Exporting `NewTransport func() mcp.Transport` rather than an interface or a second optional field. ADR 0018 leaves the shape to this task; the reasons are in ADR 0012's amendment row.
- T0.25 reports the status of any process that ends within the grace, including `exit status 0` after netguard closed its stdin, and `signal: terminated` after go-sdk's own shutdown. That text is accurate but can be noisy. A process that netguard kills gets no status.
- `tools/list` failures get the exit status too (T0.25 says "at startup"; `tools/list` is inside the startup budget).

## Questions for the receiver

- Security: before the restart, the first process's partial stderr line is flushed through the same Redactor and escaping. Is relaying a killed upstream's last line acceptable, as it is today on `Close`?
- An upstream that is slow rather than broken (for example `uvx` resolving dependencies on first run for more than 5 s) is restarted and stays stateful. ADR 0018 accepts this; say so if you want it called out in the README install snippet.
