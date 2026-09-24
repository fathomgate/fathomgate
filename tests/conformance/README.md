# MCP conformance suite against `netguard serve` (T0.4, T0.19)

`make conformance` runs the official MCP conformance suite against the
client-facing side of `netguard serve`, the MCP server NetGuard shows the
agent, for both protocol eras, in front of two upstreams: one that speaks
both eras and one that speaks only 2025-11-25. CI runs it as the
`mcp-conformance` job on every push to `main` and every pull request. It backs M0 exit criterion 1 and
the "conformance suite green on the client-facing side" half of test-matrix
row 2. It does **not** validate row 1 or row 2: those name real upstream
servers (netdev-ssh-mcp, upa/mcp-netmiko-server), and both upstreams here
are fixtures.

```sh
make conformance                       # all legs, both revisions (needs Go, Node.js and npm (CI uses Node 22), python3)
make conformance CONFORMANCE_REVS=2026-07-28 CONFORMANCE_LEGS=netguard
tests/conformance/run.sh netguard-up2025 2025-11-25   # one leg, after `make conformance-deps build`
python3 tests/conformance/era_pairs.py --netguard bin/netguard \
  --upstream bin/conformance/everything-server-2025  # the two upstream-prompt cells
```

`make conformance` runs every leg for every revision, then `era_pairs.py`,
and fails at the end if any of them failed.

Results (one `checks.json` per scenario, plus `relay.log` with the relay's,
netguard's and the fixture's stderr) are written to
`tests/conformance/results/<leg>-<revision>/`; CI uploads them when the job
fails.

## What runs

| Piece | What it is | Pinned where |
| --- | --- | --- |
| Suite | [`@modelcontextprotocol/conformance`](https://github.com/modelcontextprotocol/conformance) `0.2.0-alpha.11` (npm, git `c321dd32035556e6769d3724a8ee97d87c3faaac`), run as `conformance server --requirements <revision>` | `package.json` and `package-lock.json` (integrity hash); installed with `npm ci --ignore-scripts` |
| Revisions | `2025-11-25` (stateful, `initialize` handshake) and `2026-07-28` (stateless, `_meta` on every request). Each revision's frozen requirement set decides what is scored. | `CONFORMANCE_REVS` in the `Makefile` |
| Upstream fixture (current) | go-sdk's own conformance server, `github.com/modelcontextprotocol/go-sdk/conformance/everything-server`, over stdio. Speaks both eras and negotiates 2026-07-28 with netguard. | Built from the go-sdk version in `go.mod`: no new dependency, and a go-sdk bump rebuilds it |
| Upstream fixture (2025) | The same server at go-sdk **v1.6.1**, the last go-sdk release before 2026-07-28 support (v1.7.0 added it). Speaks 2025-11-25 and older only: it answers `server/discover` with `-32601`, so netguard falls back to `initialize` and keeps a stateful session, as it would with FastMCP 1.x. Built to `bin/conformance/everything-server-2025`. | `upstream-2025/go.mod` and `go.sum`: a separate, test-only module whose only content is a `tool` line for the everything-server. See "The 2025 upstream" below. |
| Era pairs | `era_pairs.py`: drives the two upstream-prompt cells the suite cannot reach for a 2025 upstream, over stdio, standard library only | This directory |
| Relay | `relay.py`: Streamable HTTP in front of a stdio server, standard library only | This directory |
| Baselines | `baseline/<leg>-<revision>.yml`, one entry per expected failing check with the reason | This directory |

0.2.0-alpha.11 is a pre-release. It is the only published version that
carries the 2026-07-28 requirement set (0.1.16, the `latest` tag, has
2025-era scenarios only), and it is the version go-sdk v1.8.0 pins in its
own conformance workflow. When go-sdk is bumped, compare its
`.github/workflows/conformance.yml` `CONFORMANCE_VERSION` and move this pin in
a separate PR if it changed.

## Legs

The suite tests servers only over Streamable HTTP, and `netguard serve` only
speaks stdio in M0. `relay.py` bridges the two. A leg is a chain (with or
without netguard) and an upstream; `run.sh` picks the two separately, so
the transport (the relay today, netguard's HTTP listener in T0.32) and the
upstream can each change without touching the other:

| Leg | Chain | Upstream | Proves |
| --- | --- | --- | --- |
| `control` | suite → relay → upstream | current | The relay is transparent. For 2025-11-25 the control passes every scored scenario with an empty baseline. For 2026-07-28 it fails only HTTP-transport checks, listed in `baseline/control-2026-07-28.yml`. |
| `netguard` | suite → relay → `netguard serve --server conf` → upstream | current | The client-facing side of the real binary, stdio transport included. A failure here that the control leg does not have is netguard's. |
| `control-up2025` | suite → relay → upstream | 2025 | The 2025 fixture passes every scored 2025-11-25 scenario on its own (empty baseline). No 2026-07-28 run: a 2025-only server cannot answer a stateless agent with nothing in between, so `run.sh` prints `skipped` and exits 0. |
| `netguard-up2025` | suite → relay → `netguard serve --server conf` → upstream | 2025 | Both agent eras through netguard to a stateful upstream. |

The relay changes messages in exactly two ways (module docstring in
`relay.py`, pinned by `tests/unit/test_conformance_relay.py`):

1. It renumbers request ids, because several HTTP requests share one child,
   and puts the client's id back on the response and on a notification's
   `io.modelcontextprotocol/subscriptionId`.
2. With `--tool-prefix conf` (netguard leg only), a `tools/call` whose name
   has no `.` gets `conf.` in front. The suite calls fixed names
   (`test_simple_text`); netguard exposes `conf.test_simple_text`
   (profile-schema section 8.1). `tools/list` is not rewritten, so the suite
   sees netguard's prefixed names.

A 2025 `initialize` starts one child per session (`Mcp-Session-Id`). 2026
requests without a session share one child, because netguard seals
`requestState` under a per-process key and an MRTR retry must reach the
process that issued it.

## Upstream era

netguard's upstream client tries `server/discover` first, so the current
fixture always negotiates 2026-07-28 with netguard, and the 2025 fixture
answers `-32601` and gets an `initialize` session at 2025-11-25 (netguard
logs `upstream ready ... protocol=2025-11-25 era=stateful`). The four era
pairs:

| Agent (suite) | Upstream | Leg | What it adds |
| --- | --- | --- | --- |
| 2025-11-25 | 2026-07-28 | `netguard` | The stateful agent over a stateless upstream |
| 2026-07-28 | 2026-07-28 | `netguard` | MRTR `input_required` through netguard |
| 2025-11-25 | 2025-11-25 | `netguard-up2025` | An upstream `elicitation/create` relabelled and relayed to the agent: `tools-call-elicitation` and `elicitation-sep1034-defaults` pass here, and are baselined on the `netguard` leg |
| 2026-07-28 | 2025-11-25 | `netguard-up2025` | A stateless agent over a stateful upstream: listing, calls, content types, errors and progress cross the era boundary |

The suite cannot reach two cells, because no 2026-07-28 scenario calls a
stateful elicitation tool and no 2025-11-25 check looks at the prompt's
label. `era_pairs.py` drives them against the 2025 fixture:

- **agent 2025-11-25 x upstream 2025-11-25**: the prompt reaches the agent
  as `[from conf] <message>`, its field title labelled too; the agent's
  `accept` goes back and the tool completes with it.
- **agent 2026-07-28 x upstream 2025-11-25**: no server-initiated request
  reaches the agent; the call ends with `isError` and netguard's refusal,
  checked word for word: `netguard refused an input request (elicitation)
  from upstream conf during test_elicitation: this client speaks the
  stateless era (2026-07-28) and cannot receive a server-initiated prompt;
  see ADR 0014`. The upstream's prompt text appears nowhere in the result.

Run against the current fixture, both cells fail: the check does not pass
without a 2025 upstream.

### The 2025 upstream

`upstream-2025/` is a Go module of its own
(`github.com/joshscott13/netguard/tests/conformance/upstream-2025`) that
contains only `go.mod` (a `tool` line naming go-sdk v1.6.1's
`conformance/everything-server`) and `go.sum`. The Makefile builds it with
`go -C tests/conformance/upstream-2025 build`.

- It adds no dependency to netguard. The root `go.mod` does not change;
  `go build ./...`, `go vet ./...`, `go test ./...` and golangci-lint in the
  root skip nested modules; nothing in it is linked into the netguard
  binary. Its module graph is the root module's minus `goccy/go-yaml`,
  `x/sync` and `x/time`, with go-sdk at v1.6.1 instead of v1.8.0 and
  `x/sys` held at the root's v0.48.0. Like the npm suite pin and
  `tests/pyproject.toml`, it is test tooling, which CLAUDE.md's "no new
  dependency without an ADR" rule does not cover.
- Keep it at v1.6.1. Any later go-sdk speaks 2026-07-28 and would make the
  leg a copy of `netguard`. Dependabot watches only the root module, so it
  will not propose a bump. A security fix in a shared module (`x/sys`,
  `x/oauth2`) may be applied here by hand; go-sdk must stay at v1.6.1.
- It is go-sdk's server, not FastMCP. Matrix row 2 still needs
  upa/mcp-netmiko-server (FastMCP, 2025 era) behind netguard.

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

Every entry says why it fails, in one of eight groups, and names the ADR or
board task that decided it or owns the gap:

| Group | Scenarios (leg) | Why | ADR or task |
| --- | --- | --- | --- |
| Undeclared capabilities | prompts, resources, completion, logging, caching hints on those lists, `sep-2164-resource-not-found`, `non-tool-request` (both netguard legs) | netguard declares `tools` only and answers `-32601` (profile-schema section 8.2) | T0.3 |
| Refused input requests | `tools-call-sampling` (2025, both netguard legs); `input-required-result-basic-sampling`, `basic-list-roots`, `multiple-input-requests`, `capability-check` (2026, `netguard`) | Sampling and roots from an upstream are refused; only form elicitation is relayed (profile-schema section 8.4) | ADR 0008, T0.3 |
| Not relayed | `tools-call-with-logging` (2025, both netguard legs) | No logging capability, so no log messages are relayed | T0.3 |
| Unsolicited answers (SHOULD) | `ignore-extra-params` (2026, `netguard`) | `inputResponses` sent without netguard's `requestState` are ignored and never forwarded, so the upstream asks again instead of completing (profile-schema section 8.2) | T0.18, ADR 0014 |
| Pairing and prefix | `tools-call-elicitation`, `elicitation-sep1034-defaults`, `elicitation-sep1330-enums` (2025, `netguard` leg only); `server-stateless:sep-2575-server-rejects-undeclared-capability` (2026, both netguard legs) | The current fixture's legacy elicitation tools refuse on the 2026 session it has with netguard; that path is scored on `netguard-up2025`. The suite looks up an unprefixed tool name in `tools/list` (profile-schema section 8.1) | ADR 0008 (pairing, scored on `netguard-up2025` since T0.19); ADR 0012, T0.4 (prefix) |
| Elicitation schema | `elicitation-sep1330-enums` (2025, `netguard-up2025`) | The fixture's `titledMulti` field has `items.type: "string"` and `items.anyOf` but no `items.enum`. go-sdk v1.8.0's client (netguard's upstream side) refuses the request with `-32602` before netguard sees it; behind that, netguard's allow-list needs `items.enum` on an array and drops the deprecated `enumNames` (profile-schema section 8.4) | T0.3 |
| Upstream predates 2026-07-28 | 13 checks on `netguard-up2025` 2026-07-28: the `input-required-result-*` scenarios and two `server-stateless` checks | go-sdk v1.6.1's server has none of the 2026-era diagnostic tools (`test_input_required_result_*`, `test_streaming_elicitation`, `test_logging_tool`, `test_missing_capability`); a 2025 server cannot return `input_required` at all. MRTR is scored on the `netguard` leg | T0.19 |
| HTTP transport (every 2026 leg) | 12 `server-stateless` checks: HTTP 400/404 status mapping and the `MCP-Protocol-Version` header | The relay's HTTP behaviour, not netguard's; netguard has no HTTP listener in M0 | ADR 0012, T0.4 |

Progress (`tools-call-with-progress`) passes in both eras since T0.17:
netguard gives the upstream its own progress token and relays the
upstream's notifications under the agent's token (profile-schema section
8.4). `missing-input-response` passes since T0.18.

A baseline entry is not a pass. "The conformance suite passes on the
client-facing side" (M0 exit criterion 1) means: every scored check passes
except those listed here, and each listed check points at an ADR or a
board task. A reason that is only a gap, not a design choice, needs a task.

## Changing things

- **A netguard change fixes a baselined check:** the run fails as stale;
  delete the entry.
- **A netguard change breaks a check:** the run fails as unexpected; fix
  the code. Add a baseline entry only for a deliberate, documented decision,
  with its reason and reference.
- **go-sdk bump:** the current fixture and netguard both move; the 2025
  fixture stays at v1.6.1. The job must pass before the bump merges
  (CONTRIBUTING.md). A changed control leg means the fixture or the relay
  changed, not netguard. A changed `netguard-up2025` leg with an unchanged
  `control-up2025` is netguard's upstream client (the new go-sdk) meeting a
  2025 server: read it before re-baselining.
- **Suite bump:** edit the version in `package.json`, run `npm install
  --ignore-scripts --save-exact` here, then `make conformance`, and
  reconcile every leg's baseline in the same PR.
