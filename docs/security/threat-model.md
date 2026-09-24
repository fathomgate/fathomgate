# NetGuard threat model

Maintained by security-reviewer (`.claude/agents/security-reviewer.md`); each PR review adds or updates rows here. [SECURITY.md](../../SECURITY.md#threat-model-summary) keeps the short public summary. This file was created in the T0.17/T0.18 review (PR #53), so its catalogue holds the rows that review touched; earlier findings live in SECURITY.md and the review handoffs under `docs/handoffs/` until they are folded in.

## Assets

- The network devices behind each upstream, and their configuration.
- The human's approval: an answer to a prompt, and from M3 an approval of a held call. Only a human may give it (invariant 6).
- The agent's view of what netguard itself said, as opposed to what an upstream said (origin labels).
- The audit chain and its signing key (M1 onward).

## Trust boundaries

| Boundary | Trusted side | Untrusted side |
| --- | --- | --- |
| Agent ↔ proxy | proxy | agent (a model; can be steered by anything it reads) |
| Proxy ↔ upstream | proxy | upstream process and everything it returns (invariant 7) |
| Proxy ↔ approver | proxy (server-side identity) | nothing the agent or upstream supplies |
| Proxy ↔ source of truth | proxy | inventory data (M2) |
| Proxy ↔ operator | operator | none; local files are owner-only |

## Attack catalogue

Status: mitigated (package and test), accepted (with scope), or open (with owner or board task).

| Attack | OWASP MCP | Status | Where |
| --- | --- | --- | --- |
| Progress spoofing: an upstream uses a progress `message` to put text the agent reads as netguard's own (a `[from netguard]` line, ANSI or bidi tricks, a spelled escape that a decoding reader turns into a newline followed by a fake label) | MCP03, MCP05 | Mitigated | `internal/proxy/progress.go` (`progressMessage`: `[from <server>]` label, `escapeControl`, 512-byte cap, dropped if it folds to an origin label); `sanitize.go` doubles every backslash so only netguard's escapes read as escapes; `label.go` decodes escape sequences before the `[from` check. Tests: `TestProgressMessage`, `TestHasOriginLabel`, `TestRelabelElicit`, `TestRelayUpstreamError`, `TestRelabelSchema`. The same path serves prompts, relayed errors and stderr. Since the PR #58 re-review (R1, R4) the fold also decodes HTML character references (numeric and the named brackets, amp, lt, gt), `\u{...}` escapes and percent-encoding, strips HTML tags and markdown punctuation, and fails closed past eight nested layers; tests `TestMarkupSpoofs`, `TestDecodeFailsClosed`, and the same inputs in `TestProgressMessage` and `TestRelabelElicit`. Residual, accepted and listed in label.go and SECURITY.md: homoglyphs outside the fold (mathematical alphanumerics, precomposed accents, other scripts), encodings it does not decode (other HTML named references, octal and named backslash escapes, quoted-printable, LaTeX, base64), and a label split across two fields. The `[from <server>]` label on netguard's own text is the second layer |
| Progress flood: an upstream sends notifications faster than the agent can use them | MCP05 | Mitigated | `progress.go`: per call 10 at once, then 5 per second; the newest held-back one is sent when a rate slot frees up (S4, T0.28) or before the result. Tests: `TestProgressRateLimit`, `TestProgressBucket`, `TestProgressFlushOnTimer`, `TestUntilToken` |
| Progress token scope: an upstream injects progress into another call | MCP03 | Mitigated, residual accepted | Tokens are 128 random bits (`crypto/rand.Text`) in a per-upstream map, so an upstream cannot reach calls on another upstream. It can target another call in flight to itself only, under its own label, which is no more than it could say in that call's result. The agent's token never goes upstream. Tests: `TestProgressRelay` (foreign token dropped, no mapping outlives its call), `TestProgressAfterCall` |
| Upstream notification queue blocked by a slow agent: go-sdk dispatches an upstream's notifications and requests one at a time, so a progress write to an agent that stops reading, made on that goroutine, would stall every later message from that upstream (another call's `elicitation/create` and every later notification), and the call's end would wait on the stalled write, leaving a stale in-flight entry that breaks prompt attribution | MCP05 (availability) | Mitigated (T0.28) | `internal/proxy/progress.go`: `relay` only updates state and queues, under a mutex never held across a write; one sender goroutine per call writes, from a queue of at most 10 (newest replaced when full); `finish` waits at most 1 s (`progressFinalWait`), then drops the rest and starts no new write, so `end` runs and the in-flight entry goes. Test: `TestProgressStuckAgent` (two agents on one stateful upstream; the stuck one's flood is read in full, its call leaves the in-flight set, the other's `elicitation/create` and result flow, nothing follows the stuck agent's result once it reads again, and its sender returns); it hangs on the pre-T0.28 relay. `TestProgressQueueBounded`. Residual, accepted: go-sdk's stdio transport cannot abandon a write in progress, so a sender stuck on a non-reading agent lives until that agent reads or disconnects (one per call, holding at most one notification), and the stuck agent's own calls end up to 1 s late. Spec: profile-schema section 8.4, "Delivery" |
| Prompt schema round-trip: a value that crosses a prompt verbatim (property name, `enum` or `const` value, default) carries text a reader decodes differently from what the upstream gets back, or a default reaches the human altered and is sent back altered | MCP03, MCP05 | Mitigated | `internal/proxy/schema.go`: such values cannot be escaped without changing what the upstream receives, so property names and `enum`/`const` values that `escapeControl` would change (a control character or backslash) are refused, and such defaults are dropped (the human types the value). Tests: `TestRelabelSchema` ("default with a backslash dropped", "array default with a backslash dropped", "property name with a backslash", "enum value with a backslash") |
| Unsolicited `inputResponses`: an agent pre-answers an upstream prompt no human was shown, or a later stage mistakes agent-supplied answers for a human's | MCP03 (confused deputy) | Mitigated | `internal/proxy/proxy.go`: `newCall` clears answers sent without netguard's `requestState` before `Proxy.dispatch` (the M1 seam), and `forward` sends a first call; `resume` drops answers to ids that are not outstanding. Invariant 6. Tests: `TestNewCallClearsUnsolicited`, `TestUnsolicitedInputResponses`, `TestRetryIgnoresUnknownIDs`; strict cases in `TestMRTRWire`. Conformance `ignore-extra-params` stays baselined for this reason |

## OWASP MCP Top 10 mapping (rows above)

| OWASP MCP | Rows |
| --- | --- |
| MCP03 tool poisoning (and confused deputy through relayed prompts) | Progress spoofing, progress token scope, prompt schema round-trip, unsolicited `inputResponses` |
| MCP05 command injection through output | Progress spoofing, progress flood, notification queue blocked, prompt schema round-trip |
| MCP08 missing or tamperable audit | Not touched by PRs #53 and #58 |
