# M1-19 round 2: counters per principal, exact-key hints, retries verified before the gate

- **Task:** M1-19 — Wire the gate into Proxy.dispatch - tool errors on deny, decision log line, session counters, annotations from tools/list
- **From → To:** mcp-protocol-engineer → security-reviewer (then go-reviewer)
- **State now:** in review
- **Branch / PR:** `feat/wire-gate` · [PR #169](https://github.com/fathomgate/fathomgate/pull/169) (round 2; PR #167 merged at `4ffc2ab` before it)
- **Date:** 2026-09-25

## Done

- **Security M1 (maintainer decision a):** `counterKey` is now the principal over HTTP for both eras, and the process on stdio. No key names a session, so `forgetSession` is gone. This also closes Go item 1 (the entry leak). The map holds at most the principals plus one, and its comment now says so. Recorded in a dated ADR 0026 amendment row and in the threat model *Session counters dodged* row.
- **Maintainer decision b:** ADR 0026 and ADR 0014 now say the three review items were accepted on 2026-09-25. ADR 0014 records the way back: a profile-declared set of answer fields, checked like `args`, in a new record.
- **L1:** `readOnlyHintsOf` decodes into `map[string]json.RawMessage` and reads only the exact keys `tools`, `name`, `annotations` and `readOnlyHint`.
- **L2:** `gated` opens and verifies a retry's `requestState`, and checks for an exited upstream, before it decides. Neither case writes a decision line or counts anything. `forwarded` is defined in an ADR 0026 amendment row and in the *Step 8* note.
- **L3:** two new CHANGELOG *Security* entries: the elicitation argument channel, and `max_devices` session churn.
- **Security notes:**
  - The proxy's own refusals now carry `class_source` `proxy` (policy-schema 5; audit-event-schema lists it as planned).
  - `route.closed` is a snapshot taken at `New`. `Gate.Arguments` is never called per call or per prompt, and a panic in it leaves the tool closed.
  - `narrowSchema` sets `additionalProperties: false`. The ADR 0026 notes say that composition keywords are not trimmed.
- **Go reviews:**
  - Item 2: the counter lock is a one-slot channel taken with the call's context. The M2 precondition is recorded in the notes, together with item 10 (double Decide cost).
  - Item 3: `TestGateCountersSerialised` uses a test hook (`testHookCounterWait`) and no sleeps.
  - Item 4: the `Run` goroutine is joined in `TestRealGateLogInjection`.
  - Item 5: runtime error text is logged only for types in package `runtime`.
  - Item 6: an `atomic.Bool` fast path in `hintCapture`.
  - Item 8: the `Arguments` godoc is fixed.

## Look at this first

- `internal/proxy/gate.go`: `gated`, `counterKey`, `sessionCounter.lock`.
- `internal/proxy/hints.go`: `readOnlyHintsOf`.
- Tests:
  - `TestGateCountersSurviveSessionChurn`
  - `TestGateCountersSerialised`
  - `TestGateRetryVerifiedFirst`
  - `TestReadOnlyHintsExactKeys`
  - `TestGateAnnotationCaseSplit`

## Deliberately unfinished

- The resolver I/O bound under the counter lock is an M2 precondition, recorded in ADR 0026 notes, *Step 5*.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./...          # -race in CI
GOOS=windows ~/go/bin/golangci-lint run ./...; GOOS=linux ~/go/bin/golangci-lint run ./...; GOOS=darwin ~/go/bin/golangci-lint run ./...
go test -count=20 -run 'TestGateCountersSerialised|TestGateCountersSurviveSessionChurn|TestGateRetryVerifiedFirst' ./internal/proxy/
bin/fathomgate policy test policies/examples/*.test.yaml   # 45 of 45
# conformance: tests/conformance/run.sh <leg> <rev> for all 4 legs x 2 revs, then era_pairs.py: all green, baselines unchanged
python tools/licences/spdx.py && python tools/licences/third_party.py --check && python tools/status/render.py --check
```

## Decisions made without an ADR

- A retry whose state does not verify writes no decision line. It is logged by the existing `warnState` Warn line only.

## Questions for the receiver

- None.
