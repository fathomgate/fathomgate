# MCP conformance suite against `netguard serve` (T0.4)

`make conformance` runs the official MCP conformance suite against the
client-facing side of `netguard serve`, the MCP server NetGuard shows the
agent, for both protocol eras. CI runs it as the `mcp-conformance` job on
every push to `main` and every pull request. It backs M0 exit criterion 1 and
the "conformance suite green on the client-facing side" half of test-matrix
row 2. It does **not** validate row 1 or row 2: those name real upstream
servers (netdev-ssh-mcp, upa/mcp-netmiko-server), and the upstream here is a
fixture.

```sh
make conformance                       # all legs, both revisions (needs Go, Node.js and npm (CI uses Node 22), python3)
make conformance CONFORMANCE_REVS=2026-07-28 CONFORMANCE_LEGS=netguard
tests/conformance/run.sh netguard 2025-11-25   # one leg, after `make conformance-deps build`
```

Results (one `checks.json` per scenario, plus `relay.log` with the relay's,
netguard's and the fixture's stderr) are written to
`tests/conformance/results/<leg>-<revision>/`; CI uploads them when the job
fails.

## What runs

| Piece | What it is | Pinned where |
| --- | --- | --- |
| Suite | [`@modelcontextprotocol/conformance`](https://github.com/modelcontextprotocol/conformance) `0.2.0-alpha.11` (npm, git `c321dd32035556e6769d3724a8ee97d87c3faaac`), run as `conformance server --requirements <revision>` | `package.json` and `package-lock.json` (integrity hash); installed with `npm ci --ignore-scripts` |
| Revisions | `2025-11-25` (stateful, `initialize` handshake) and `2026-07-28` (stateless, `_meta` on every request). Each revision's frozen requirement set decides what is scored. | `CONFORMANCE_REVS` in the `Makefile` |
| Upstream fixture | go-sdk's own conformance server, `github.com/modelcontextprotocol/go-sdk/conformance/everything-server`, over stdio | Built from the go-sdk version in `go.mod`: no new dependency, and a go-sdk bump rebuilds it |
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
speaks stdio in M0. `relay.py` bridges the two, so every run has two legs:

| Leg | Chain | Proves |
| --- | --- | --- |
| `control` | suite → relay → everything-server | The relay is transparent. For 2025-11-25 the control passes every scored scenario with an empty baseline. For 2026-07-28 it fails only HTTP-transport checks, listed in `baseline/control-2026-07-28.yml`. |
| `netguard` | suite → relay → `netguard serve --server conf` → everything-server | The client-facing side of the real binary, stdio transport included. A failure here that the control leg does not have is netguard's. |

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

netguard's upstream client tries `server/discover` first, so everything-server
always negotiates 2026-07-28 with netguard. On the netguard leg the pairs are:

| Agent (suite) | Upstream (fixture) | Covered |
| --- | --- | --- |
| 2025-11-25 | 2026-07-28 | yes |
| 2026-07-28 | 2026-07-28 | yes |
| 2025-11-25 or 2026-07-28 | 2025-11-25 | **no**: go-sdk has no switch that keeps a server on 2025, and the Python SDK (`mcp` 2.2.0) also negotiates 2026-07-28. The tier 1 tests in `internal/proxy` cover all four pairs; a 2025-only upstream leg is a follow-up. |

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

Every entry says why it fails, in one of six groups, and names the ADR or
board task that decided it or owns the gap:

| Group | Scenarios (netguard leg) | Why | ADR or task |
| --- | --- | --- | --- |
| Undeclared capabilities | prompts, resources, completion, logging, caching hints on those lists, `sep-2164-resource-not-found`, `non-tool-request` | netguard declares `tools` only and answers `-32601` (profile-schema section 8.2) | T0.3 |
| Refused input requests | `tools-call-sampling`; `input-required-result-basic-sampling`, `basic-list-roots`, `multiple-input-requests`, `capability-check` | Sampling and roots from an upstream are refused; only form elicitation is relayed (profile-schema section 8.4) | ADR 0008, T0.3 |
| Not relayed | `tools-call-with-logging` (2025) | No logging capability, so no log messages are relayed | T0.3 |
| Unsolicited answers (SHOULD) | `ignore-extra-params` (2026) | `inputResponses` sent without netguard's `requestState` are ignored and never forwarded, so the upstream asks again instead of completing (profile-schema section 8.2) | T0.18, ADR 0014 |
| Pairing and prefix | `tools-call-elicitation`, `elicitation-sep1034-defaults`, `elicitation-sep1330-enums` (2025); `server-stateless:sep-2575-server-rejects-undeclared-capability` (2026) | The fixture's legacy elicitation tools refuse on a 2026 upstream session; the suite looks up an unprefixed tool name in `tools/list` (profile-schema section 8.1) | T0.19 (pairing); ADR 0012, T0.4 (prefix) |
| HTTP transport (both legs, 2026) | 12 `server-stateless` checks: HTTP 400/404 status mapping and the `MCP-Protocol-Version` header | The relay's HTTP behaviour, not netguard's; netguard has no HTTP listener in M0 | ADR 0012, T0.4 |

Progress (`tools-call-with-progress`) passes in both eras since T0.17:
netguard gives the upstream its own progress token and relays the
upstream's notifications under the agent's token (profile-schema section
8.4). `missing-input-response` passes since T0.18.

A baseline entry is not a pass. "The conformance suite passes on the
client-facing side" means: every scored check passes except those listed
here, each for a recorded reason.

## Changing things

- **A netguard change fixes a baselined check:** the run fails as stale;
  delete the entry.
- **A netguard change breaks a check:** the run fails as unexpected; fix
  the code. Add a baseline entry only for a deliberate, documented decision,
  with its reason and reference.
- **go-sdk bump:** the fixture and netguard both move. The job must pass
  before the bump merges (CONTRIBUTING.md). A changed control leg means the
  fixture or the relay changed, not netguard.
- **Suite bump:** edit the version in `package.json`, run `npm install
  --ignore-scripts --save-exact` here, then `make conformance`, and
  reconcile both legs' baselines in the same PR.
