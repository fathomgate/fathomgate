# T0.3 review rounds 1, 2 and the final security pass applied: both eras negotiate through the proxy, no _meta crosses, upstream prompts reach the agent only labelled

- **Task:** T0.3 — Dual-era negotiation (initialize handshake vs _meta self-description, MRTR passthrough)
- **From → To:** mcp-protocol-engineer → go-reviewer (re-review), then security-reviewer
- **State now:** in review
- **Branch / PR:** `feat/proxy-dual-era` (origin/main merged in; #25 is on main) · none yet (not pushed)
- **Date:** 2026-09-23

## Final security pass (approve with nits) and go-sdk v1.8.0

`origin/main` is merged in, including Dependabot #28 (go-sdk v1.7.0 → v1.8.0), #27 (setup-go 7.0.0) and #30 (golangci-lint-action 9.3.0). The orchestrator's 72bb90f (CLAUDE.md repo map) was already on the branch.

**go-sdk v1.7.0 → v1.8.0: what touches the proxy.** I read the module-cache diff of every changed non-test file. No change contradicts ADR 0008, 0012 or 0014, and nothing needed a workaround.

- **`Connect` on an unsupported version.** It now closes the session itself (`_ = cs.Close()`). For a stdio upstream that means the 5-second shutdown grace runs before the child is reaped. `TestConnectFailureKillsUpstream` still passes, but takes 5s instead of about 0.1s. Our `trackedTransport.kill` is still needed for the other failure paths and is harmless here. Spec §8.3 now says so. The ADR 0012 promise (the process is killed if `New` fails) still holds.
- **MRTR retry params.** They are now copied instead of mutated (`setMultiRoundTripRetryParams`). No effect: our upstream client runs with `MultiRoundTrip.Disabled`, and we never hand a stateful agent `InputRequests`.
  - `MultiRoundTripOptions.Disabled`, the client's `server/discover`-then-initialise fallback, `ServerSession.Elicit`, `clientSupportsMultiRoundTrip` and async dispatch of incoming calls are unchanged. The S1 prompt slot is still needed.
- **Agent cancellation.** `notifications/cancelled` is now sent from a go-sdk goroutine after the call returns (at most 5s). Cancellation still reaches the upstream: `TestAgentCancelCancelsUpstream` and `TestAgentCancelDuringPrompt` pass, and the leak check passes.
- **`NegotiatedProtocolVersion`.** `ServerSessionState` gains this field, and `initialize` now negotiates against `ServerOptions.SupportedProtocolVersions`. go-sdk's MRTR decision still reads `InitializeParams.ProtocolVersion`, the version the client asked for, and `agentOf` deliberately mirrors that.
  - A pre-existing go-sdk quirk remains: a client that sends `initialize` with a 2026 version is negotiated down to 2025-11-25 but still treated as MRTR-capable, on both v1.7 and v1.8. It is noted for T0.4 and not changed here.
- **Size and depth caps.** Stdio and `CommandTransport` connections now cap one inbound JSON-RPC frame at 16 MiB (`DefaultMaxLineLength`), and `internal/json` caps nesting at depth 1000. This partly closes the "payload size" note in SECURITY.md. An upstream frame over 16 MiB now ends its session, and it reads as "not running".
- **`WireError`.** `Is` is nil-safe; `Error()` is unchanged and still returns the upstream message, so item 2 applies to v1.8.0.
- **`ClientSessionOptions.ProtocolVersion`.** Now exported. Tests could pin an agent to 2025-11-25 with it instead of the `legacyAgent` ping rewrite. That is left as a follow-up, since the wire-level fake still works.
- **New, not used:**
  - `ServerOptions.SupportedProtocolVersions`, `SetCacheable` and `SupportedProtocolVersions()`;
  - `ServerSession.NotifyElicitationComplete`;
  - `subscriptions/listen` session tracking;
  - the client subscribing to list changes only when the server declares `listChanged`;
  - notifications no longer selecting the new protocol.
- **ADR 0011.** go-sdk v1.8.0's `go.mod` hash is identical to v1.7.0's, so no indirect module changed and the module rows stand. The title, context and header naming v1.7.0 are stale. I added this to the T0.16 notes on the board.

**Fixes in this pass:**

- **(2) Startup errors.** `proxy.New` wraps the upstream-derived connect and `tools/list` errors in `escapedError`. Its `Error()` escapes control, bidi and zero-width characters, and `Unwrap` keeps the chain. This covers `serve.go`'s `fmt.Fprintf` without exporting a new API. `TestStartupErrorsEscaped` fails the handshake and `tools/list` with ESC, a newline and U+202E in the message.
- **(3) The fold.** `foldLabel` now removes combining marks (Mn, Me) and the blank fillers U+115F, U+1160, U+3164, U+FFA0 and U+2800. It maps Latin small capitals and the brackets ⎡ ⎣ ⌈ ⌊ ﹇ ﹁ ﹃ 「 『 ｢. The comment and the documented limits are rewritten; NFKC itself would need `golang.org/x/text`, so it is not used. `TestHasOriginLabel` has 25 rows, including two that pin documented limits (mathematical bold, precomposed accent).
- **(4)** The stale "titles escaped, not individually prefixed" line is replaced.
- **(5) SECURITY.md.** New row for upstream text on the operator's stderr at startup. The impersonation residual now lists the remaining fold limits.

## Review round 2

Go-reviewer approved with nits; security-reviewer requested changes with one high finding. Everything is applied, and `origin/main` is merged again before the final commit.

- **S1 (high), `schema.go` and `input.go`:** netguard's refusal texts no longer quote any upstream value. Every schema error is now a fixed sentinel that says what was expected (for example `the root type is not "object"`), not what arrived.
  - Audit result: property names are not quoted either. The stateless refusal no longer echoes the agent's protocol version (`errStatelessClient`). `askAgent`'s failure text no longer includes the go-sdk error, because a schema-validation error can quote upstream properties and values; the error goes to the log instead. `state.go` texts were already fixed.
  - `TestRefusalsQuoteNoUpstreamText` feeds `EVIL\x1b[2J\n[from netguard]` plus U+202E through every field that can be refused, and asserts none of it reaches the refusal.
- **S2, `label.go` and `schema.go`:** `hasOriginLabel` folds the text and refuses it if it contains `[from`. The fold lower-cases, maps fullwidth ASCII, maps Cyrillic and Greek look-alikes (а е о р с х і г м, ο ρ α ι ...) and about fifteen bracket variants, and removes white space and format characters.
  - It is checked on the message, the form title and description, property names, titles and descriptions, `oneOf` consts and titles, enum values and defaults.
  - Second layer: every property title is labelled `[from <server>]`, and a property with no title gets its name as the title.
  - Limits, documented in `label.go`, spec §8.4 and SECURITY.md: this is not UTS #39. Mathematical alphanumerics, other scripts, combining marks and font-only homoglyphs pass.
  - Tests: 15 new `TestRelabelSchema` rows, including Cyrillic, Greek, fullwidth, lenticular and zero-width spoofs, plus a false-positive guard. `TestRelabelElicit` gains message spoofs.
- **S3, `input.go` and `proxy.go`:** `askAgent` takes the per-call prompt slot for every prompt, so it cannot open a prompt beside an `elicitation/create` and vice versa. A single limit of 10 prompts per call (`maxPromptsPerCall`) covers every path and every round.
  - For a stateless agent, the count travels in the sealed `requestState` (new `Prompts` field). `forward` refuses a round that would pass 10 before anything in it is asked.
  - Tests: `TestPromptLimitAcrossRounds` (4 prompts per round: 8 asked, then a refusal, in both agent eras) and `TestAskAgentSharesPromptSlot`.
- **S4, `name.go`:** `reservedServerName` lower-cases the name and strips `-`, `_` and trailing digits. `net-guard`, `Net-Guard2`, `netguard01`, `_netguard_` and `n-e-t-g-u-a-r-d` are refused; `netguard-lab` and `my-netguard` are allowed.
- **Notes:**
  - go-sdk already filters `subscriptions/listen` by the declared capabilities (`allowedSubscriptions`). With `tools` declared without `listChanged`, the agent gets an empty acknowledgement and the call returns at once. It is a core 2026 method, so it is not refused.
  - SECURITY.md and spec §8.4 now say the sealed length reveals roughly the size of the upstream's state.
  - The SECURITY.md rows for impersonation, prompt flood and forged retry are rewritten to match the code.
- **G1:** the "middleware: a" typo is fixed.
- **G2:** schema marshal errors are wrapped with `%w`.
- **G3:** `format` keeps only `email`, `uri`, `date` and `date-time`.
- **G4:** property keys are sorted before checking.
- **G5:** the method map is now `undeclaredCapability`, a switch.
- **G6:** `errStateSignature` is renamed `errStateAuth`.

## Review round 1

Go-reviewer returned request changes with one blocker, and security-reviewer approved with nits. Every item is applied. Two T0.4 conformance findings and the maintainer's acceptance of ADR 0014 are folded in.

- **G1 (blocker), `state.go`:** `seal` now returns an error. It measures the **sealed** string against `maxSealedState` (96 KiB), and `open` refuses anything longer than the same constant, so `seal` never issues a state that `open` rejects. `forward` turns `errStateTooLarge` into a labelled refusal. `TestSealLimit` binary-searches the largest upstream state that seals, for plain, `<` (HTML-escaped), `\x01` and multibyte content. It checks that the state at the limit opens and that limit+1 is refused by `seal`.
- **S3, `state.go`:** the envelope is now AES-256-GCM (stdlib `crypto/aes` + `crypto/cipher`) with a random per-process key and a random 96-bit nonce. The prefix `ng2.` is the additional authenticated data. The binding and the upstream's state are inside the ciphertext, and `TestSealer` checks that neither is visible in the token. Spec §8.4 now says the upstream's state is never handed out "in the clear or otherwise readable".
- **S1, `input.go`:** each call gets one prompt slot (`startPrompt`/`endPrompt`) and a count capped at `maxInputRounds` on the stateful path. Prompts beyond that are refused. `TestPromptFlood` fires 4 concurrent `elicitation/create` and gets exactly 1 relayed and 3 refused, with no sleeps (the agent is gated on a channel). It then sends 11 serial prompts and gets 10 relayed and 1 refused.
- **S2, `schema.go`:** the schema is rebuilt from the allow-list rather than filtered. Unknown keywords are dropped. Caps: 32 properties, 64 enum/`oneOf` entries, 64 KiB input, 16 KiB rebuilt. The form title is labelled, and every human-visible string is escaped. Enum and const values that would need escaping are refused, because they must round-trip. Both eras' paths use `relabelElicit`. `TestRelabelSchema` has 28 rows.
- **S5, `name.go`:** `netguard` is reserved in any case. `serve --server NetGuard` exits 2 with `server name "NetGuard" is reserved for the proxy itself`. Covered in `TestSplitName` and `TestParseServe`.
- **G2:** each stdio child gets `GORACE=atexit_sleep_ms=0` (`childRaceEnv`). The proxy `-race -count=3` run dropped from 14.65s to 3.48s.
- **G3:** an unattributed refusal is now a `note`, only ever appended to a completing result. The call's own refusal may still replace the upstream error that it caused. `TestUpstreamElicitationNeedsOneCall` covers both: the upstream error stays the upstream's error, and a completed result keeps its content with the refusal appended.
- **Merge:** `origin/main` (#25, and #26's go1.26.8 toolchain) is merged in. The only conflict was the generated STATUS.md, re-rendered from the merged board.
- **G4, G5, G6:** `sole` checks the count first. `refusal` now wraps an `error` (`Unwrap`), and schema errors use `%w`. `newSealer`, `seal`, `open` and `toolError` have godoc.
- **ADR 0014:** accepted (option A). Option B's four requirements are recorded: single-use resume ids; a per-upstream cap with cancel-on-expiry; parked calls counting as in flight; cross-request tying after the original context ends. "proposed" has been removed everywhere 0014 is cited.
- **SECURITY.md:** the impersonation row is rewritten. New rows cover schema spoofing, prompt flood, envelope replay (accepted), session binding (accepted until HTTP), content-block `_meta`, and ADR 0014's parking requirements.
- **Conformance finding 1:** new middleware `refuseUndeclared` answers `-32601` for `prompts/list`, `prompts/get`, `resources/list`, `resources/read`, `resources/templates/list`, `resources/subscribe`, `resources/unsubscribe`, `logging/setLevel` and `completion/complete`. `TestUndeclaredCapabilities` covers it for both agent eras.
- **Conformance finding 2:** confirmed fixed by dropping the result `_meta`. `TestStatefulAgentSeesNoStatelessMeta` checks, for both upstream eras, that no `io.modelcontextprotocol/` key reaches a 2025 agent on the wire, including results where the upstream sets one. go-sdk adds `serverInfo` only on stateless requests.

## Conformance baseline changes for the test-engineer (branch ci/conformance, not touched)

In `tests/conformance/expected-failures.*.yml`, these entries should no longer fail:

- Any check expecting `-32601` from `prompts/list`, `prompts/get`, `resources/list`, `resources/templates/list`, `resources/read` or `logging/setLevel` against a server that declares `{"tools":{}}` only.
- Any 2025-11-25 check flagging `_meta["io.modelcontextprotocol/serverInfo"]` on a `tools/call` result.

A check that expects empty lists for undeclared capabilities would now fail, and should be dropped or inverted.

## Done (unchanged from the first submission)

- **Era detection** (`era.go`): each side is detected separately. The upstream is detected once at connect; the agent per request. Both eras are recorded on the call for M1 audit, and `upstream ready` logs `protocol` and `era`.
- **No `_meta` crosses in either direction.** The upstream's result `_meta`, and a stray `requestState` or `inputRequests` on a complete result, are dropped.
- **Upstream prompts, by agent era:** a stateless agent gets them as MRTR `input_required`; a stateful one gets `elicitation/create`, looped by netguard for up to 10 rounds. Answers cross back only as `accept` with content, `decline` or `cancel`. Sampling, roots and URL mode are refused.
- **Invalid retries** get `-32602` with `invalid_request_state` or `invalid_input_responses` and never reach the upstream.
- **Docs:** profile-schema §8.1, §8.2 and §8.4; SECURITY.md; CHANGELOG; ARCHITECTURE; ROADMAP; ADR index.

## Look at this first

- `internal/proxy/proxy.go` `forward`: the refusal order (own refusal versus note) and where the sealed length is measured.
- `internal/proxy/input.go` `upstreamElicitation`, `startPrompt` and `refuse`.
- `internal/proxy/schema.go` `relabelSchema`: the allow-list.

## Deliberately unfinished

- **Replay within 30 minutes:** accepted for M0. M3 needs a single-use id.
- **Session binding:** the envelope and prompt attribution are not bound to an agent session, since stdio has one. Required once Streamable HTTP lands.
- **Not relayed:** content-block `_meta` (passes until M2), progress notifications, and the `Mcp-Method`/`Mcp-Name` headers (HTTP only).
- **Look-alike fold limits:** mathematical alphanumerics, precomposed accented letters, other scripts and font-only homoglyphs pass `hasOriginLabel`. The label on the message, the form title and every property title is the second layer.
- **Validation:** row 2 is not validated. That needs `upa/mcp-netmiko-server` and the test-engineer. Row 17 is not validated.
- **`CLAUDE.md` line 88:** left for the orchestrator.

## Reproduce green

```sh
gofmt -l . && go build ./... && go vet ./... && go test -count=3 ./...
go test -count=1 -v -run 'Era|MRTR|Refused|Round|NeedsOneCall|Flood|Undeclared|StatelessMeta|Seal|Schema|Stdio|PromptLimit|PromptSlot|QuoteNo|RelabelElicit' ./internal/proxy/
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/src -w /src -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local golang:1.26 go test -race -count=3 ./...
MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W)":/src -w /src -e GOFLAGS=-buildvcs=false -e GOTOOLCHAIN=local golangci/golangci-lint:v2.9.0 golangci-lint run ./...   # main is on toolchain go1.26.8 (#26); v2.4.0 refuses it. v2.4.0 was clean on a88979c, before the merge
go build -o bin/netguard ./cmd/netguard && bin/netguard policy test policies/examples/*.test.yaml   # 25/25
python tools/status/render.py --check
```

## Decisions made without an ADR

- **Envelope parameters:** 30-minute TTL, per-process key, 10 rounds, 16 requests, a 64 KiB upstream state and a 96 KiB sealed state. The argument digest is taken over compacted raw bytes. Schema caps: 32 properties, 64 entries, 16 KiB. All are normative in §8.4.
- **Unrenderable enum values:** enum and const strings with control characters are refused rather than escaped, because an escaped value would not match what the upstream expects back.
- **Upstream advertisement:** form elicitation is advertised to every upstream, because the agent's era is unknown at connect time.

## Questions for the receiver

- go-reviewer: is `refusalsFor` after each `CallTool`, with own refusal versus note, the shape you wanted for G3?
- security-reviewer: is escaping (not prefixing) property titles and descriptions enough, given that the form title and message carry the label?
