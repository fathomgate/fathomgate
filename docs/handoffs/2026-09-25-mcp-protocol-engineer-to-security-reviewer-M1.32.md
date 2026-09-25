# M1.32: hybrid upstream refused at startup; elicitation/create from a discovered upstream refused; security review

- **Task:** M1.32, Refuse a hybrid upstream at startup, and refuse server-initiated input from an upstream connected via server/discover
- **From → To:** mcp-protocol-engineer → security-reviewer (go-reviewer is the second reviewer)
- **State now:** in review
- **Branch / PR:** `fix/refuse-hybrid-upstream` · [PR #181](https://github.com/fathomgate/fathomgate/pull/181)
- **Date:** 2026-09-25

## Done

- `internal/proxy/era.go`: `handshakes.middleware` compares the answered `initialize` version with the requested one, read from the request go-sdk sent. When the answer is later, it returns `*hybridError` (both versions, answered one quoted and `clip`ped, ADR 0008) and calls `abortAttempt`, which cancels the attempt's context through `withAbort`.
- `internal/proxy/proxy.go`: `connectAttempt` puts its cancel function in the attempt's context. A timeout now counts only when the cancel cause is `errProbeExpired`, so a hybrid refusal is never restarted. New field `upstream.handshake` (`atomic.Bool`) is set at connect.
- `internal/proxy/input.go`: `upstreamElicitation` refuses when `!u.handshake.Load()`, on an attributed call, before `promptable` and the M1-19 check. The refusal is `errDiscoveredUpstream`.
- Tests: the `TestDiscoverProbe` hybrid rows now expect refusal, and `TestRestartedStdioUpstreamAnswering2026IsRefused` replaces `...IsStateful` (the child lingers past EOF and SIGTERM; the refusal must come within `terminateDuration`; both processes reaped). New `discover_input_test.go` holds `TestDiscoveredUpstreamElicitationRefused`. Both new assertions were mutation-checked, then reverted.
- Docs: ADR 0008 amendment row; profile-schema 8.2, 8.3 and 8.4; threat-model rows for both findings now Mitigated (M1-32), with the MCP03 summary updated; CHANGELOG Security.

## Look at this first

- `handshakes.middleware` and `abortAttempt` in `internal/proxy/era.go`, then the `timedOut` condition at the end of `connectAttempt`. Together they carry the kill-at-once and the no-restart guarantees.

## Deliberately unfinished

- If zero or several calls are in flight, a discovered upstream's prompt still gets the attribution refusal, not the ADR 0008 text. It is refused either way.
- No tier 2 run. Real servers never send a hybrid answer or a stateless `elicitation/create`, so no matrix row changes state.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... -count=1        # all ok; no cgo on this host, so no -race locally
~/go/bin/golangci-lint run ./...                                 # 0 issues (also GOOS=linux, darwin for internal/proxy)
python tools/licences/spdx.py                                    # exit 0
# make conformance by hand: bin/fathomgate.exe, bin/conformance/everything-server{,-2025}.exe, npm ci in tests/conformance,
# then tests/conformance/run.sh <leg> <rev> for 4 legs x 2 revs (all pass, baselines unchanged), and
python tests/conformance/era_pairs.py --fathomgate <abs>/bin/fathomgate.exe --upstream <abs>/bin/conformance/everything-server-2025.exe   # 4 ok
```

## Decisions made without an ADR

- The hybrid refusal lives inside the middleware, not after `Connect`. That way the upstream never gets `notifications/initialized` and the session is never published.
- Any answer greater than the requested version counts as a hybrid, including one go-sdk would reject as unsupported. The refusal is then fathomgate's error, not go-sdk's.
- The discovered-upstream check runs before the ADR 0014 stateless-agent check, so the refusal names the upstream's fault first.

## Questions for the receiver

- Should the discovered-upstream refusal also replace the attribution reason when zero or several calls are in flight?
