# MCP conformance suite against `fathomgate serve --listen` (T0.4, T0.19, T0.32)

`make conformance` runs the official MCP conformance suite against the
client-facing side of `fathomgate serve`, the MCP server Fathomgate shows the
agent, for both protocol eras, in front of two upstreams: one that speaks
both eras and one that speaks only 2025-11-25. Since T0.32 the suite drives
Fathomgate's own Streamable HTTP listener (`--listen`, ADR 0016 and ADR
0023), with a bearer token, through a two-rule shim. CI runs it as the
`mcp-conformance` job on every push to `main` and every pull request. It
backs M0 exit criterion 1 and the "conformance suite green on the
client-facing side" half of test-matrix row 2. It does **not** validate row
1 or row 2: those name real upstream servers (netdev-ssh-mcp,
upa/mcp-netmiko-server), and both upstreams here are fixtures.

```sh
make conformance                       # all legs, both revisions (needs Go, Node.js and npm (CI uses Node 22), python3)
make conformance CONFORMANCE_REVS=2026-07-28 CONFORMANCE_LEGS=fathomgate
tests/conformance/run.sh fathomgate-up2025 2025-11-25   # one leg, after `make conformance-deps build`
python3 tests/conformance/era_pairs.py --fathomgate bin/fathomgate \
  --upstream bin/conformance/everything-server-2025  # the two upstream-prompt cells, stdio and HTTP
```

`make conformance` runs every leg for every revision, then `era_pairs.py`,
and fails at the end if any of them failed.

Results are written to `tests/conformance/results/<leg>-<revision>/`: one
`checks.json` per scenario, `chain.log` (Fathomgate's stderr with the
upstream's relayed into it, or on a control leg the upstream's own) and
`shim.log` (one line per request: request line and status, never a header).
A 2025-11-25 `fathomgate` leg also has `isolated-<scenario>/` for each
fresh-process scenario ("One process" below), with its own logs and the
suite's output in `suite.log`. CI uploads them when the job fails.

## What runs

| Piece | What it is | Pinned where |
| --- | --- | --- |
| Suite | [`@modelcontextprotocol/conformance`](https://github.com/modelcontextprotocol/conformance) `0.2.0-alpha.11` (npm, git `c321dd32035556e6769d3724a8ee97d87c3faaac`), run as `conformance server --requirements <revision>` | `package.json` and `package-lock.json` (integrity hash); installed with `npm ci --ignore-scripts` |
| Revisions | `2025-11-25` (stateful, `initialize` handshake) and `2026-07-28` (stateless, `_meta` on every request). Each revision's frozen requirement set decides what is scored. | `CONFORMANCE_REVS` in the `Makefile` |
| Upstream fixture (current) | go-sdk's own conformance server, `github.com/modelcontextprotocol/go-sdk/conformance/everything-server`. Behind Fathomgate it runs over stdio, speaks both eras and negotiates 2026-07-28 with Fathomgate. On the control leg it serves HTTP itself (`-http`). | Built from the go-sdk version in `go.mod`: no new dependency, and a go-sdk bump rebuilds it |
| Upstream fixture (2025) | The same server at go-sdk **v1.6.1**, the last go-sdk release before 2026-07-28 support (v1.7.0 added it). Speaks 2025-11-25 and older only: it answers `server/discover` with `-32601`, so Fathomgate falls back to `initialize` and keeps a stateful session, as it would with FastMCP 1.x. Its `-http` handler is always stateful (v1.6.1 has no `-stateless` flag). Built to `bin/conformance/everything-server-2025`. | `upstream-2025/go.mod` and `go.sum`: a separate, test-only module whose only content is a `tool` line for the everything-server. See "The 2025 upstream" below. |
| Shim | `shim.py`: a reverse proxy that adds the bearer token and the `conf.` tool prefix, standard library only. See "The shim" below. | This directory; unit tests in `tests/unit/test_conformance_shim.py` |
| Era pairs | `era_pairs.py`: drives the two upstream-prompt cells the suite cannot reach for a 2025 upstream, over stdio and over the listener, standard library only | This directory |
| Baselines | `baseline/<leg>-<revision>.yml`, one entry per expected failing check with the reason | This directory |

0.2.0-alpha.11 is a pre-release. It is the only published version that
carries the 2026-07-28 requirement set (0.1.16, the `latest` tag, has
2025-era scenarios only), and it is the version go-sdk v1.8.0 pins in its
own conformance workflow. When go-sdk is bumped, compare its
`.github/workflows/conformance.yml` `CONFORMANCE_VERSION` and move this pin in
a separate PR if it changed.

## Legs

A leg is a chain (with or without Fathomgate) and an upstream; `run.sh`
picks the two separately. The suite always reaches the chain through the
shim.

| Leg | Chain | Upstream | Proves |
| --- | --- | --- | --- |
| `control` | suite → shim → `everything-server -http` | current | The upstream's own HTTP result, and that the shim is transparent: `-stateless=false` for 2025-11-25 and `-stateless=true` for 2026-07-28, as go-sdk's own conformance workflow runs it. Both revisions pass every scored scenario with an empty baseline. |
| `fathomgate` | suite → shim → `fathomgate serve --listen 127.0.0.1:0 --server conf` → upstream over stdio | current | The client-facing side of the real binary, its HTTP listener included: Host and Origin checks, bearer token, era dispatch, go-sdk's sessions, GET stream and DELETE, and the 2026 status mapping. A failure here that the control leg does not have is Fathomgate's. |
| `control-up2025` | suite → shim → `everything-server -http` | 2025 | The 2025 fixture passes every scored 2025-11-25 scenario on its own (empty baseline). No 2026-07-28 run: a 2025-only server cannot answer a stateless agent with nothing in between, so `run.sh` prints `skipped` and exits 0. |
| `fathomgate-up2025` | suite → shim → `fathomgate serve --listen …` → upstream over stdio | 2025 | Both agent eras through Fathomgate to a stateful upstream. |
| `fathomgate-policy` | suite → shim → `fathomgate serve --listen … --policy … --profiles …` → upstream over stdio | current | The same chain as `fathomgate` with the gate loaded (M1-28): every tool call is decided, the deny tool error and the narrowed `inputSchema` meet the suite. See "The policy leg" below. |

Every `fathomgate` leg except `fathomgate-policy` runs `--no-policy`, the
pass-through (ADR 0027), so its baseline measures the protocol and not a
policy.

### The policy leg

`policy/profiles/conf.yaml` is a test profile for the current fixture
(go-sdk v1.8.0's everything-server; its header cites the source), and
`policy/policy.yaml` allows `READ_OPERATIONAL` by rule `conf-reads` and
denies `EXEC_ARBITRARY` by `conf-no-exec`. `run.sh` copies both to a fresh
directory only the owner can write (on Windows, `icacls` as in install.md
step 1), because `serve` refuses a policy or profile others may change. The
profile lists every fixture tool, so none falls to the unlisted-tool
refusal, and makes two choices that put the gate in front of the suite:

- `test_error_handling` is `EXEC_ARBITRARY`, so `tools-call-error` scores
  Fathomgate's deny (`isError`, one text block: `fathomgate denied
  conf.test_error_handling: rule conf-no-exec (class EXEC_ARBITRARY): ...`)
  as a tool error. It passes in both revisions.
- `test_x_mcp_header` names `region` and leaves `level` unnamed, so the tool
  is advertised narrowed (ADR 0033 section 4: `properties` `{region}`,
  `additionalProperties: false`). The 2026-07-28 scenario
  `http-custom-header-server-validation` reads that schema from `tools/list`
  and passes all its checks through the gate.

After the suite, `run.sh` checks `chain.log`: a decision line denying
`test_error_handling` by `conf-no-exec` with `forwarded=false`, every other
decision `allow` by `conf-reads` (so no call the suite makes falls to
`default:bad_arguments`), at least one such allow, and exactly one
`advertising only the arguments the profile names` line, for
`test_x_mcp_header` with `dropped=[level]`. At 2026-07-28 it also checks
for the log line refusing an upstream prompt under the policy, and runs
`policy_prompts.py`: that script calls each fixture tool behind an MRTR
baseline entry on a fresh gated `fathomgate serve` process over stdio, as a 2026-07-28 agent
declaring every input capability, and requires the exact refusal text for
each. The log line alone cannot do that, because it is throttled per reason
rather than per tool. Any miss fails the leg.

What the gate changes in the score is in the two
`baseline/fathomgate-policy-*.yml` files: nothing on 2025-11-25; on
2026-07-28 the MRTR scenarios whose tool asks the agent for input fail,
because with a policy loaded Fathomgate does not relay an upstream prompt
(profile-schema section 8.2, last row), and one check that fails on the
`fathomgate` leg passes. The leg runs against the current upstream only: the
2025 upstream's fresh-process elicitation runs must pass, which a gated
chain never can.

On a `fathomgate` leg `run.sh` generates a fresh token
(`FAKE-conformance-` and 32 random hex digits), passes it to Fathomgate in
`FATHOMGATE_LISTEN_TOKEN` (principal `env`) and to the shim in
`CONFORMANCE_SHIM_TOKEN`, and unsets both first so a token from the caller's
shell never enters the harness. The token is never on a command line and
never printed; a run whose results or logs contain it fails. Fathomgate
binds both loopback families (ADR 0023) and prints one `listening url=` line
per address, the address asked for first; the shim targets that one
(`127.0.0.1`). One Fathomgate process serves the whole leg, every scenario's
session included (see "One process" under Baselines).

## The shim

The suite has no option to send an `Authorization` header or to map tool
names, and it calls fixed names (`test_simple_text`) where Fathomgate
exposes `conf.test_simple_text` (profile-schema section 8.1). ADR 0016
therefore keeps one shim in the path, much smaller than the `relay.py` it
replaces. It changes requests in exactly two ways (module docstring in
`shim.py`, pinned by `tests/unit/test_conformance_shim.py`):

1. **Token.** With `CONFORMANCE_SHIM_TOKEN` set, every request gets
   `Authorization: Bearer <token>`, replacing any the suite sent.
2. **`--tool-prefix conf`.** A request whose `Mcp-Method` header is
   `tools/call` gets `conf.` in front of an `Mcp-Name` with no `.`, and a
   JSON-RPC body whose `method` is `tools/call` gets `conf.` in front of a
   `params.name` with no `.`. The two are rewritten separately by the same
   rule, so a deliberate header and body mismatch stays a mismatch. A body
   is re-serialised only when its name changes; every other body crosses as
   the bytes that arrived. `tools/list` and every response are untouched,
   so the suite sees Fathomgate's prefixed names.

Everything else passes through: method, path and query, `Host` as the suite
sent it (so the DNS-rebinding probe reaches Fathomgate), `Origin`, session
ids, status, reason, response headers, and the response body, streamed as
it arrives. When the suite closes a streamed response (a GET stream, an
aborted POST), the shim closes its upstream connection too, so the server
sees the stream end. Hop-by-hop headers are dropped as by any HTTP/1.1
proxy. The shim keeps no sessions and does not renumber ids. The control
legs run it with neither token nor prefix, where it changes nothing.

It goes when the suite can send a header and map tool names. The requests
for both are drafted in `docs/handoffs/2026-09-25-test-engineer-to-go-reviewer-T0.32.md`.

## Upstream era

Fathomgate's upstream client tries `server/discover` first, so the current
fixture always negotiates 2026-07-28 with Fathomgate, and the 2025 fixture
answers `-32601` and gets an `initialize` session at 2025-11-25 (Fathomgate
logs `upstream ready ... protocol=2025-11-25 era=stateful`). The four era
pairs:

| Agent (suite) | Upstream | Leg | What it adds |
| --- | --- | --- | --- |
| 2025-11-25 | 2026-07-28 | `fathomgate` | The stateful agent over a stateless upstream |
| 2026-07-28 | 2026-07-28 | `fathomgate` | MRTR `input_required` through Fathomgate |
| 2025-11-25 | 2025-11-25 | `fathomgate-up2025` | A stateful agent over a stateful upstream: an upstream `elicitation/create` relabelled and relayed to the agent. Since T0.32 `tools-call-elicitation` and `elicitation-sep1034-defaults` fail in the shared run (the orphan rule, below) and must pass in the fresh-process step |
| 2026-07-28 | 2025-11-25 | `fathomgate-up2025` | A stateless agent over a stateful upstream: listing, calls, content types, errors and progress cross the era boundary |

`era_pairs.py` drives two cells the suite does not score, against the 2025
fixture, each twice: over stdio, and over the listener as its own minimal
HTTP client (token, prefixed name and 2026 routing headers set by itself,
no shim), each cell in a Fathomgate process of its own:

- **agent 2025-11-25 x upstream 2025-11-25**: the prompt reaches the agent
  as `[from conf] <message>`, its field title labelled too; the agent's
  `accept` goes back and the tool completes with it. No suite check looks
  at the label.
- **agent 2026-07-28 x upstream 2025-11-25**: no server-initiated request
  reaches the agent; the call ends with `isError` and Fathomgate's refusal,
  checked word for word: `fathomgate refused an input request (elicitation)
  from upstream conf during test_elicitation: this client speaks the
  stateless era (2026-07-28) and cannot receive a server-initiated prompt;
  see ADR 0014`. The upstream's prompt text appears nowhere in the result.
  No 2026-07-28 scenario calls a stateful elicitation tool.

Run against the current fixture, all four fail: the check does not pass
without a 2025 upstream.

### The 2025 upstream

`upstream-2025/` is a Go module of its own
(`github.com/fathomgate/fathomgate/tests/conformance/upstream-2025`) that
contains only `go.mod` (a `tool` line naming go-sdk v1.6.1's
`conformance/everything-server`) and `go.sum`. The Makefile builds it with
`go -C tests/conformance/upstream-2025 build`.

- It adds no dependency to Fathomgate. The root `go.mod` does not change;
  `go build ./...`, `go vet ./...`, `go test ./...` and golangci-lint in the
  root skip nested modules; nothing in it is linked into the Fathomgate
  binary. Its module graph is the root module's minus `goccy/go-yaml`,
  `x/sync` and `x/time`, with go-sdk at v1.6.1 instead of v1.8.0 and
  `x/sys` held at the root's v0.48.0. Like the npm suite pin and
  `tests/pyproject.toml`, it is test tooling, which CLAUDE.md's "no new
  dependency without an ADR" rule does not cover.
- Keep it at v1.6.1. Any later go-sdk speaks 2026-07-28 and would make the
  leg a copy of `fathomgate`. Dependabot watches only the root module, so it
  will not propose a bump. A security fix in a shared module (`x/sys`,
  `x/oauth2`) may be applied here by hand; go-sdk must stay at v1.6.1.
- It is go-sdk's server, not FastMCP. The real 2025-era upstream for matrix
  row 2, upa/mcp-netmiko-server, runs behind Fathomgate in tier 2
  (`tests/integration/test_upa_netmiko.py`, CI job `tier2-upa`).

## Baselines

The suite's `--expected-failures` file lists failures that are allowed. A run
fails on a scored failure that is not listed, **and on a listed entry that
passes** (a stale baseline). So a fix deletes its entry in the same PR.
Entries name a single check (`<scenario>:<check-id>`), never a whole
scenario, so the other checks in the scenario are still enforced. In a
baseline run a scored `WARNING` (a SHOULD) counts like a failure, so SHOULD
gaps are listed too. Scenarios the requirement set marks `not_scored` (the
tasks extension, `pending` scenarios, `added-after-release`) run and are
reported but cannot fail the run, so they are not listed.

Both control baselines are empty, so every entry on a `fathomgate` leg is a
difference Fathomgate makes. Every entry says why it fails, in one of these
groups, and names the ADR or board task that decided it or owns the gap:

| Group | Scenarios (leg) | Why | ADR or task |
| --- | --- | --- | --- |
| Undeclared capabilities | prompts, resources, completion, logging, caching hints on those lists, `sep-2164-resource-not-found`, `non-tool-request` (both `fathomgate` legs) | Fathomgate declares `tools` only and answers `-32601` (profile-schema section 8.2) | T0.3 |
| Refused input requests | `tools-call-sampling` (2025, both `fathomgate` legs); `input-required-result-basic-sampling`, `basic-list-roots`, `multiple-input-requests`, `capability-check` (2026, `fathomgate`) | Sampling and roots from an upstream are refused; only form elicitation is relayed (profile-schema section 8.4) | ADR 0008, T0.3 |
| Not relayed | `tools-call-with-logging` (2025, both `fathomgate` legs) | No logging capability, so no log messages are relayed | T0.3 |
| Unsolicited answers (SHOULD) | `ignore-extra-params` (2026, `fathomgate`) | `inputResponses` sent without Fathomgate's `requestState` are ignored and never forwarded, so the upstream asks again instead of completing (profile-schema section 8.2) | T0.18, ADR 0014 |
| Pairing and prefix | `tools-call-elicitation`, `elicitation-sep1034-defaults`, `elicitation-sep1330-enums` (2025, `fathomgate`); `server-stateless:sep-2575-server-rejects-undeclared-capability` and `sep-2575-missing-capability-http-400` (2026, both `fathomgate` legs) | The current fixture's legacy elicitation tools refuse on the 2026 session it has with Fathomgate. The suite looks up the unprefixed `test_missing_capability` in `tools/list` (profile-schema section 8.1) and reports both checks untestable; the shim renames only `tools/call`, as ADR 0016 decides | ADR 0008 (pairing); ADR 0012, ADR 0016, T0.32 (prefix) |
| Orphan rule | `tools-call-elicitation`, `elicitation-sep1034-defaults` (2025, `fathomgate-up2025`) | A stateful upstream's prompt names no call, so Fathomgate refuses it while another agent session's call on that upstream ended less than `OrphanTTL` (5 minutes) ago. Every scenario is a new session of the same Fathomgate, and earlier scenarios' calls have just ended. Both scenarios run again in the fresh-process step, where they must pass (profile-schema section 8.4) | ADR 0016 amendments (T0.40, T0.44) |
| Origin refused | `dns-rebinding-protection:localhost-host-valid-accepted` (every `fathomgate` leg and revision) | The check sends `Origin: http://127.0.0.1:<port>` with a matching `Host` and wants 2xx; Fathomgate answers 403 to any request with an `Origin`, a same-host one included, since a DNS-rebinding page sends exactly that and MCP agents are not browsers (profile-schema 8.5 limit 3). The scenario's other check, a foreign `Host`, passes | ADR 0016 (request handling, step 3) |
| Elicitation schema | `elicitation-sep1330-enums` (2025, `fathomgate-up2025`) | The fixture's `titledMulti` field has `items.type: "string"` and `items.anyOf` but no `items.enum`. go-sdk v1.8.0's client (Fathomgate's upstream side) refuses the request with `-32602` before Fathomgate sees it; behind that, Fathomgate's allow-list needs `items.enum` on an array and drops the deprecated `enumNames` (profile-schema section 8.4) | T0.3, T0.35 |
| Upstream predates 2026-07-28 | 13 checks on `fathomgate-up2025` 2026-07-28: the `input-required-result-*` scenarios and two `server-stateless` checks | go-sdk v1.6.1's server has none of the 2026-era diagnostic tools (`test_input_required_result_*`, `test_streaming_elicitation`, `test_logging_tool`, `test_missing_capability`); a 2025 server cannot return `input_required` at all. MRTR is scored on the `fathomgate` leg | T0.19 |

The HTTP-transport group is gone. Until T0.32 every 2026-07-28 baseline
opened with 12 `server-stateless` checks (HTTP 400 and 404 mapping, the
`MCP-Protocol-Version` header) that measured `relay.py`, not Fathomgate. On
Fathomgate's own listener 11 of them pass, as ADR 0016 predicted, and on the
control leg all 12 pass on go-sdk's handler. The twelfth,
`sep-2575-missing-capability-http-400`, moved to "Pairing and prefix".

### One process

A `fathomgate` leg is one `fathomgate serve --listen` for every scenario of a
revision, as an operator would run it. Two per-process rules then show in
the 2025-11-25 runs, both deliberate:

- **Session cap.** At most 4 stateful sessions per principal and 16 in all;
  an idle session closes after 30 minutes (ADR 0016 limit 7, profile-schema
  8.5 limit 8). Since T0.57 an `initialize` past the cap first evicts the
  principal's least recently used idle session, but a session with a GET
  stream open is in use, not idle. The suite DELETEs the session of a
  scenario that passes but not of one that throws, and it leaves that
  client's standalone GET stream open, so the first four scenarios that
  fail on an undeclared method (`logging-set-level`, `completion-complete`,
  `tools-call-with-logging`, `resources-list`) leave four sessions that are
  still streaming, none can be evicted, and every later `initialize` gets
  503. `chain.log` shows it: `listener: new session refused: too many
  sessions open for this principal and none of the principal's sessions is
  idle principal=env sessions=4 posting=0 streaming=4 calling=0`. A crashed
  or restarted agent's stream closes with its connection, and that case
  is what the eviction is for (unit tests in
  `internal/proxy/session_cap_test.go`). The upstream request drafted in
  the T0.32 handoff (terminate the session on every exit path) would clear
  these 503s. The resources and prompts
  scenarios after that point fail with 503 before the `-32601` they would
  get anyway, so their baseline entries hold for both reasons (the files
  say so). One more scored scenario runs after that point,
  `dns-rebinding-protection`. So on the 2025-11-25 legs its
  `localhost-host-valid-accepted` entry cannot go stale: if the Origin rule
  changed, the check would still fail there, on the 503. Only the
  2026-07-28 legs, which have no sessions, would notice. A suite bump that
  reorders scenarios shows any other casualty as an unexpected failure.
  The unscored `server-session-lifecycle`, `json-schema-2020-12` and
  `server-sse-polling` are among the 503s, so they report nothing useful in
  the shared run. On the control legs `server-session-lifecycle` and
  `json-schema-2020-12` pass, and `server-sse-polling` passes but for a
  `server-sse-priming-event` WARNING (a SHOULD: no priming event with an id
  on the POST SSE stream), on both control legs; it is unscored, so no
  baseline lists it. Run alone on a fresh `fathomgate serve` process (T0.57, by hand),
  `server-sse-polling` gives the same warning and a second one,
  `server-sse-retry-field` (a SHOULD: no `retry:` field). The fixture's
  `test_reconnection` tool closes its SSE stream mid-call with a `retry:`
  delay (go-sdk `CloseSSEStream`), but that is the upstream's stream to
  Fathomgate. go-sdk v1.8 writes `retry:` only in that close event, which
  asks the client to reconnect and resume from an event store, and ADR
  0016 gives the listener none, so Fathomgate sends neither. Recorded in
  ADR 0016's amendments, not changed. `json-schema-2020-12` run alone
  fails on the prefix: the suite looks up the unprefixed tool name in
  `tools/list`.
- **Orphan rule.** See the group above.

**Fresh-process step.** After the shared run, `run.sh` runs some scenarios
again on a 2025-11-25 `fathomgate` leg, each alone against a Fathomgate process of its
own, as `conformance server --scenario <name> --spec-version 2025-11-25`
(the suite does not combine `--scenario` with `--requirements`). No
baseline applies: the scenario must pass outright, scored by the suite's
exit code, and a failure fails the leg.

| Scenario | Legs | Recovers |
| --- | --- | --- |
| `server-session-lifecycle` | `fathomgate`, `fathomgate-up2025` | `initialized` accepted on the issued session id, DELETE accepted, 404 for the terminated session, through Fathomgate's listener |
| `tools-call-elicitation` | `fathomgate-up2025` | The upstream's `elicitation/create` relayed to a 2025 agent over the listener and the answer returned (hidden by the orphan rule in the shared run) |
| `elicitation-sep1034-defaults` | `fathomgate-up2025` | The same path with SEP-1034 default values |

The relay started one Fathomgate process per 2025 session, so neither rule could
show before T0.32.

A baseline entry is not a pass. "The conformance suite passes on the
client-facing side" (M0 exit criterion 1) means: every scored check passes
except those listed here, and each listed check points at an ADR or a
board task. A reason that is only a gap, not a design choice, needs a task.

## Changing things

- **A Fathomgate change fixes a baselined check:** the run fails as stale;
  delete the entry.
- **A Fathomgate change breaks a check:** the run fails as unexpected; fix
  the code. Add a baseline entry only for a deliberate, documented decision,
  with its reason and reference.
- **go-sdk bump:** the current fixture and Fathomgate both move; the 2025
  fixture stays at v1.6.1. The job must pass before the bump merges
  (docs/maintainers.md). A changed control leg means the fixture's own HTTP
  handler or the shim changed, not Fathomgate. A changed `fathomgate-up2025`
  leg with an unchanged `control-up2025` is Fathomgate's upstream client
  (the new go-sdk) meeting a 2025 server: read it before re-baselining.
- **Suite bump:** edit the version in `package.json`, run `npm install
  --ignore-scripts --save-exact` here, then `make conformance`, and
  reconcile every leg's baseline in the same PR. Check whether the suite can
  now send a header and map tool names; if so, drop the shim (ADR 0016).
- **Listener limits change** (session caps, `OrphanTTL`, the Origin rule):
  re-read the "One process" section and the groups that cite them.
