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
| Progress spoofing: an upstream uses a progress `message` to put text the agent reads as netguard's own (a `[from netguard]` line, ANSI or bidi tricks, a spelled escape that a decoding reader turns into a newline followed by a fake label) | MCP03, MCP05 | Mitigated | `internal/proxy/progress.go` (`progressMessage`: `[from <server>]` label, `escapeControl`, 512-byte cap, dropped if it folds to an origin label); `sanitize.go` doubles every backslash so only netguard's escapes read as escapes; `label.go` decodes escape sequences before the `[from` check. Tests: `TestProgressMessage`, `TestHasOriginLabel`, `TestRelabelElicit`, `TestRelayUpstreamError`, `TestRelabelSchema`. The same path serves prompts, relayed errors and stderr. Fold limits (mathematical alphanumerics and others) are in SECURITY.md |
| Progress flood: an upstream sends notifications faster than the agent can use them | MCP05 | Mitigated | `progress.go`: per call 10 at once, then 5 per second, newest held-back one sent before the result. Test: `TestProgressRateLimit`, `TestProgressBucket` |
| Progress token scope: an upstream injects progress into another call | MCP03 | Mitigated, residual accepted | Tokens are 128 random bits (`crypto/rand.Text`) in a per-upstream map, so an upstream cannot reach calls on another upstream. It can target another call in flight to itself only, under its own label, which is no more than it could say in that call's result. The agent's token never goes upstream. Tests: `TestProgressRelay` (foreign token dropped, no mapping outlives its call), `TestProgressAfterCall` |
| Upstream notification queue blocked by a slow agent: the progress write runs on the upstream's single notification goroutine, so an agent that stops reading stalls that upstream's notifications and requests | MCP05 (availability) | Accepted for M0 stdio (the result write would stall too); **open** for Streamable HTTP | Board task T0.28: move the write off the notification goroutine before the HTTP listener lands. Spec: profile-schema section 8.4, "Limits of this section" |
| Unsolicited `inputResponses`: an agent pre-answers an upstream prompt no human was shown, or a later stage mistakes agent-supplied answers for a human's | MCP03 (confused deputy) | Mitigated | `internal/proxy/proxy.go`: `newCall` clears answers sent without netguard's `requestState` before `Proxy.dispatch` (the M1 seam), and `forward` sends a first call; `resume` drops answers to ids that are not outstanding. Invariant 6. Tests: `TestNewCallClearsUnsolicited`, `TestUnsolicitedInputResponses`, `TestRetryIgnoresUnknownIDs`; strict cases in `TestMRTRWire`. Conformance `ignore-extra-params` stays baselined for this reason |

## OWASP MCP Top 10 mapping (rows above)

| OWASP MCP | Rows |
| --- | --- |
| MCP03 tool poisoning (and confused deputy through relayed prompts) | Progress spoofing, progress token scope, unsolicited `inputResponses` |
| MCP05 command injection through output | Progress spoofing, progress flood, notification queue blocked |
| MCP08 missing or tamperable audit | Not touched by PR #53 |
