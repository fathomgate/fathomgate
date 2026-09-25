# T0.32 ready for review: the conformance suite drives `fathomgate serve --listen`, relay.py is gone

- **Task:** T0.32 — Conformance against the HTTP listener — auth-and-prefix shim, control leg on everything-server -http, delete relay.py, reconcile all four baselines
- **From → To:** test-engineer → go-reviewer
- **State now:** in review (fix round 1 applied, see the end). `docs/milestones/M0.yaml` is not edited here; the orchestrator syncs the board.
- **Branch / PR:** `test/conformance-over-listener` · see the PR that carries this note
- **Date:** 2026-09-25

## Done

- **`tests/conformance/shim.py` (new, stdlib):** the ADR 0016 shim. It makes two rewrites. (1) With `CONFORMANCE_SHIM_TOKEN` set, it sets `Authorization: Bearer`. (2) With `--tool-prefix conf`, it puts `conf.` on an unprefixed `tools/call` name, in `params.name` (body `method`) and in `Mcp-Name` (`Mcp-Method` header), each separately. Other bodies cross as the same bytes. `Host`, `Origin`, session ids, status and headers pass through. Responses are streamed chunk by chunk. When the client leaves a streamed response, the upstream socket is shut. It keeps no sessions and does not renumber ids. It logs the request line and status only. It binds 127.0.0.1:0 and prints `shim listening url=`.
- **`tests/unit/test_conformance_shim.py` (new, 21 tests):** covers both rewrites, the mismatch staying a mismatch, a base64 `Mcp-Name` left alone, 8 body shapes crossing byte for byte, the control shim changing nothing, Host/Origin/status/header pass-through, SSE arriving before the target finishes, the upstream stream ending when the client leaves, and the token never logged.
- **`run.sh`:** the fathomgate legs run `FATHOMGATE_LISTEN_TOKEN=<FAKE-conformance-…> fathomgate serve --listen 127.0.0.1:0 --server conf --upstream <fixture>`. The target is the first `listening url=` line (ADR 0023). The control legs run `everything-server -http 127.0.0.1:<port>`, `-stateless=false` for 2025-11-25 and `true` for 2026-07-28 (v1.6.1 has no such flag and is always stateful). The shim sits in front of every leg. The script unsets any inherited token first. The token is never on argv or printed, and a run whose results or logs contain it fails. Logs are now `chain.log` and `shim.log`.
- **`era_pairs.py`:** both cells now also run over the listener, as a minimal HTTP client with its own FAKE token and no shim. That gives 4 cells, all passing on the 2025 upstream and all failing on the current one, as before. The HTTP 2025 cell is the only place the relabelled `[from conf]` prompt is now checked over the listener (see the orphan rule below).
- **Deleted:** `tests/conformance/relay.py` and `tests/unit/test_conformance_relay.py`. The Makefile target is unchanged apart from comments, since it already calls `run.sh`. Also updated: the CI `mcp-conformance` job (name kept; comment and step name only), `tests/conformance/README.md` (rewritten: legs, "The shim", "One process", baseline groups), `docs/testing/test-strategy.md`, `tests/README.md`, CHANGELOG `Unreleased` (Changed).

### Baselines, entry by entry

| File | Change | Reason |
| --- | --- | --- |
| `control-2025-11-25` | none (empty) | go-sdk's own handler passes everything |
| `control-up2025-2025-11-25` | none (empty) | same, v1.6.1 |
| `control-2026-07-28` | **−12**, now empty | They measured relay.py. go-sdk's handler passes all 12 |
| `fathomgate-2026-07-28` | **−11** HTTP-transport entries | They pass on the listener, as ADR 0016 predicted: 8× `sep-2575-http-server-*` 400/404, `unsupported-version-400`, `request-meta-invalid-missing-meta`, `…-missing-protocol-version` |
| | `sep-2575-missing-capability-http-400` **moved** to "Pairing and prefix" | It looks up the unprefixed `test_missing_capability` in `tools/list`, so it is untestable (ADR 0012, ADR 0016) |
| | **+** `dns-rebinding-protection:localhost-host-valid-accepted` | It sends `Origin: http://127.0.0.1:<port>` and wants 2xx. fathomgate answers 403 to any Origin (ADR 0016 request handling step 3; profile-schema 8.5 limit 3) |
| `fathomgate-up2025-2026-07-28` | **−11**, **move** of 1, **+** dns-rebinding | Same as above. The moved entry sits beside `server-rejects-undeclared-capability` |
| `fathomgate-2025-11-25` | **+** dns-rebinding | Same Origin rule |
| | comments on the resources/prompts entries | From `resources-read-text` on, they fail with 503 before reaching the `-32601` (the session cap, below) |
| `fathomgate-up2025-2025-11-25` | **+** `tools-call-elicitation`, `elicitation-sep1034-defaults:elicitation-sep1034-general` | The orphan rule (ADR 0016 amendments T0.40 and T0.44; profile-schema 8.4): another scenario's session ended a call less than `OrphanTTL` ago. Warn line in `chain.log`. Since the fix round both scenarios also run alone on a fresh fathomgate and must pass |
| | **+** dns-rebinding; 503 comments | as above |

Outcome: 11 of the 12 HTTP-transport entries clear, as ADR 0016 expected. Every remaining or new entry cites an ADR or a board task.

## Look at this first

- `tests/conformance/README.md` "One process". The suite does not DELETE the session of a scenario that throws. On a single fathomgate, the first four scenarios that fail on an undeclared method use up the principal's 4 stateful sessions, and every later `initialize` in the 2025-11-25 run gets 503. After that point run the already-baselined resources and prompts scenarios, `dns-rebinding-protection` (whose entry therefore cannot go stale on the 2025 legs), and the unscored `server-session-lifecycle`, `json-schema-2020-12` and `server-sse-polling`. The fresh-process step (fix round) recovers `server-session-lifecycle` and the two elicitation scenarios.
- `shim.py` `_watch_client` and `test_client_leaving_ends_the_upstream_stream`. Without the watcher, a GET stream the suite dropped stayed open on fathomgate's side.

## Findings for other owners (not fixed here)

- **mcp-protocol-engineer, proposed board task:** the per-principal cap of 4 stateful sessions and the 30-minute idle timeout can lock out a client that never DELETEs. A crashing or restarting agent is one example (the TypeScript SDK's `close()` does not DELETE; only `terminateSession()` does). The fifth `initialize` gets 503 for up to 30 minutes. Conformance shows it: 13 × 503 per 2025 run. Options: evict the oldest idle session of that principal, or a shorter idle timeout for a session with no POST in flight and no GET stream. The same task should cover the orphan rule's effect on one principal that reconnects. With `ended_calls_of=[env]`, a reconnected client's new session has its stateful upstream's prompts refused for 5 minutes, because of calls its own earlier session ended.
- **mcp-protocol-engineer, SHOULD gap:** on the fathomgate 2025-11-25 legs the unscored `server-sse-polling` scenario reports a `server-sse-retry-field` WARNING (no `retry:` field on the SSE stream), found by the Go reviewer; in the shared run the 503 hides it, and I have not reproduced it separately. Both control legs pass that check but warn on `server-sse-priming-event` (no priming event with an id on the POST SSE stream), a go-sdk SHOULD gap that fathomgate inherits.
- The Origin rule refuses a same-host `Origin`, which the suite's `localhost-host-valid-accepted` treats as valid. ADR 0016 decides this deliberately, so it is recorded, not a defect.

## Upstream requests for the maintainer to file (modelcontextprotocol/conformance). Not filed.

1. **Title:** `server`: option to add request headers (e.g. `--header "Authorization: Bearer $TOKEN"`).
   **Body:** Servers that require authentication on every request, as the transport spec recommends for local servers, cannot be tested without a proxy in front. Please add a repeatable `--header NAME:VALUE` (or `--header-env NAME=ENVVAR`, so a secret stays off argv) to `conformance server`, applied to every request of every scenario, except where a scenario sets that header itself on purpose. We run a two-rule shim today only for this and for (2).
2. **Title:** `server`: map tool names for servers that namespace their tools.
   **Body:** Scenarios call fixed tool names (`test_simple_text`) and look them up in `tools/list` (`test_missing_capability`). A gateway or proxy that exposes upstream tools as `<server>.<tool>` cannot pass `tools/call` scenarios or be tested for `sep-2575-server-rejects-undeclared-capability` and `sep-2575-missing-capability-http-400`, which then report "Not testable". Please add `--tool-prefix P` (or a `--tool-map FILE` of `name: mapped`) applied to `params.name`, `Mcp-Name` and every `tools/list` lookup.
3. **Title:** close the session of a scenario that fails (DELETE in a `finally`).
   **Body:** When a scenario throws (for example on `-32601`), its Streamable HTTP session is never terminated. A server with a per-client session cap then answers every later scenario with 503, so their results reflect the harness and not the server. Please call `terminateSession()` / close the client on every exit path.

When (1) and (2) exist, delete `shim.py` and its tests (ADR 0016).

## Deliberately unfinished

- Matrix rows 1 and 2: no status change. The upstreams here are go-sdk fixtures, and a row is validated only against its named real server. Row 23 is T0.33's.
- The whole suite stays on one fathomgate per leg, as ADR 0016 describes and an operator runs it. Only three scenarios get a fresh process (fix round). Running every scenario that way would mean re-implementing the suite's scoring, because `--scenario` cannot be combined with `--requirements`.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && (cd tests && uv run --extra dev pytest unit -q)   # 59 passed
make conformance          # 8 leg/rev pairs pass their baselines, then 4 era-pair cells
# Windows without make (as run here): build bin/fathomgate and bin/conformance/*, copy each to *.exe, then
#   CONFORMANCE_SERVER=…/everything-server.exe CONFORMANCE_SERVER_2025=…/everything-server-2025.exe PYTHON=python tests/conformance/run.sh <leg> <rev>
#   python tests/conformance/era_pairs.py --fathomgate <abs>\bin\fathomgate.exe --upstream <abs>\bin\conformance\everything-server-2025.exe
actionlint .github/workflows/ci.yaml   # v1.7.12
uv run --with pyyaml python tools/status/render.py --check
```

## Decisions made without an ADR

- The shim passes `Host` through instead of setting the target's. Otherwise it would mask the DNS-rebinding probe, which it did on the first run.
- The shim closes the upstream side when the suite leaves a stream. ADR 0016 says "the SSE stream passes through". An HTTP proxy that kept the stream open would change what fathomgate sees.
- The shim token is a separate variable, `CONFORMANCE_SHIM_TOKEN`, so an operator's `FATHOMGATE_LISTEN_TOKEN` can never reach a control-leg fixture.
- Both era_pairs cells run over HTTP as well as stdio. This replaces the listener coverage the suite lost to the orphan rule.

## Questions for the receiver

- Is baselining the 2025 elicitation checks on `fathomgate-up2025` (orphan rule) acceptable when era_pairs.py carries the path, or should the proposed session-cap task also look at the orphan rule's effect on sequential single-agent clients?

## Fix round (Go review of PR #116)

The reviewer ran all 8 legs and era_pairs locally and confirmed every baseline reason. Applied on the same branch; main had not moved.

1. **Blocking, `shim.py`:** a request is a tool call when the `Mcp-Method` header **or** the body says `tools/call`. `_forward` passes `body_is_call` into `rewrite_headers`. Before, a tools/call body under `Mcp-Method: tasks/get` (the suite's `tasks-headers-reject-mismatched-method`) or with no `Mcp-Method` got `conf.greet` in the body and `greet` in `Mcp-Name`, a mismatch the suite never sent. New tests: `test_tools_call_body_under_another_mcp_method_keeps_names_matched`, `test_tools_call_body_without_mcp_method_keeps_names_matched`, and `test_other_method_in_header_and_body_leaves_mcp_name` (a tasks/get taskId is never prefixed).
2. **README "One process" and both 2025 fathomgate baseline headers:** they now say that `dns-rebinding-protection` runs after the 503s start. So `localhost-host-valid-accepted` cannot go stale on the 2025 legs (it would fail on the 503 even if the Origin rule changed), and only the 2026 legs would notice.
3. **Coverage recovered, `run.sh`:** after the shared run, a 2025-11-25 fathomgate leg runs these again, each alone on a fresh fathomgate and shim, as `--scenario X --spec-version 2025-11-25`, scored by the suite's exit code with no baseline:
   - `server-session-lifecycle` on both legs (3/3 checks);
   - `tools-call-elicitation` (2/2) and `elicitation-sep1034-defaults` (6/6) on `fathomgate-up2025`.
   Output goes to `isolated-<scenario>/`. I checked that a failing scenario exits 1 (`tools-call-sampling` through fathomgate) and a passing one exits 0. The baseline comment that said era_pairs covers the SEP-1034 defaults is corrected: era_pairs checks the `[from conf]` label, which no suite check looks at. The README era table, the orphan-rule group, test-strategy and CHANGELOG say the same.
4. **`era_pairs.py` `main()`:** `try/finally` always stops fathomgate. A listener that prints no `listening url=` line raises a Failure that carries fathomgate's stderr (checked with a missing upstream path).
5. **`run.sh`:** `${prefix[@]+"${prefix[@]}"}` (and the same for the new `isolated` array), for bash < 4.4 on macOS `/bin/bash`.
6. **Nits:**
   - The token reaches grep on stdin (`printf '%s\n' "$token" | grep -rqF -f - "$out"`), never on its command line.
   - `stop_pid` sends SIGTERM, waits up to 10 s, then sends SIGKILL.
   - `prefixed()` returns the name itself when it leaves it alone, so `prefixed("")` is `""` (`test_prefixed`).
   - Malformed chunked framing (bad hex, a negative size) and a negative `Content-Length` get 400 (`test_malformed_chunked_body_gets_400`).
   - The 502 for an unreachable target is tested (`test_unreachable_target_gets_502`).
   - The sleep in the logging test is gone.
   - The two unused `noqa` comments are removed; `ruff check --extend-select RUF100` passes.
7. **ADR 0016:** a dated 2026-09-25 amendment row says the harness passes the token in `FATHOMGATE_LISTEN_TOKEN`, not `--listen-token-file`, and why. It also records the shim's tool-call rule and the fresh-process step.
8. Handoff findings updated above: the reconnecting principal and the orphan rule, `server-sse-retry-field`, and `server-sse-priming-event` on both control legs (also in the README).

Re-run after the round (Windows):
- Unit tests: 69 passed (3 runs).
- `run.sh`: all 8 leg/rev pairs exit 0, and all 4 fresh-process runs pass.
- `era_pairs.py`: 4/4 ok.
- `render.py --check`: current.
