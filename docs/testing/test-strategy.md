# Test strategy

Three tiers. Tier 1 runs on every commit with no network and proves the policy, classifier, redactor and audit chain are correct. Tier 2 runs on every pull request against the real open-source MCP servers in containers and proves Fathomgate speaks to them correctly. Tier 3 runs nightly on a self-hosted runner with containerlab and proves that dry-run, rollback and watchdog behaviour is real on a device. Every case in the [test matrix](test-matrix.md) names the real server it is validated against, so nothing is tested only against a mock.

## Tiers

| Tier | What is real | What is faked | How it runs | Speed | Gate |
| --- | --- | --- | --- | --- | --- |
| 1 Policy unit | Nothing; synthetic `tools/call` requests | Upstream server (recording fake over go-sdk in-memory transport), device, clock | `go test ./...` table tests; `fathomgate policy test policies/`; Python `pytest tests/unit` for `policy-lint` parity | Seconds | Every commit |
| 2 Real server, fake device | The upstream MCP server: its tool schemas, transport, error shapes, era | The device: a Python asyncssh fake SSH server returning canned show output and echoing config lines; a fake eAPI HTTP server for eos-mcp | testcontainers-go starts each server image over Streamable HTTP; pytest drives the proxy with the python-sdk `Client` | Minutes | Every pull request |
| 3 Real server, real device | Everything | Nothing | containerlab topology with cEOS and Nokia SR Linux; Python assertion helpers over scrapli confirm device state | Nightly | `nightly-clab` workflow, self-hosted runner |

## Tier 1: what it proves

- `Evaluate` returns the expected decision for every `*.test.yaml` case, including unknown-target, session-cap and implicit-deny cases ([policy-schema.md](../specs/policy-schema.md#7-test-file-format)).
- Every row in the [classification worked examples](../specs/classification.md#9-worked-examples) classifies as stated; every allow-list and blocklist entry has a positive and a negative case.
- Every annotated line in `tests/fixtures/configs/` is redacted by exactly the named pattern and nothing else changes ([redaction-patterns.md](../specs/redaction-patterns.md#6-fixture-corpus)).
- The audit writer produces a chain that `verify` accepts; editing one character makes `verify` fail naming the line.
- Each `ChangeSafety` driver renders the expected command sequence against a recording fake upstream; the watchdog fires on a fake clock.
- The proxy's own MCP surface, tested through go-sdk's in-memory transport with a fake upstream that records calls, returns tool errors with rule ids and `input_required` results with `requestState`.
- Property tests: no policy in `policies/examples/` ever yields allow for `EXEC_ARBITRARY` on a target with role `core`; no `deny` decision ever carries obligations.

- The gate's overhead stays inside the PRD budget (classify plus evaluate under 5 ms at p99). See [Overhead budget](#overhead-budget-m1-23).

Run: `make test` (equals `go test ./... && fathomgate policy test policies/ && pytest tests/unit`).

## Overhead budget (M1-23)

Two tier 1 tests hold the PRD's M1 metric, *under 5 ms at p99 for classify plus evaluate*. Both use the repo profiles, `prod-approval.yaml` and `inventory.example.yaml`, and time every call on its own after a warm-up. The corpus is in `internal/gate/gatetest`, and each case must first get its expected decision word and rule id, so a change that turns a costly path into a cheap early refusal fails instead of making the numbers look better.

- `TestDecideOverhead` (`internal/gate`) times `Gate.Decide` alone.
- `TestDispatchOverhead` (`internal/proxy`) times `Proxy.decideAndRespond`, the decision stage the proxy runs before it forwards or refuses a call: the 64 KiB argument cap, the counter lock and counters, `Decide` (once per call since M1-39), re-encoding the arguments, the decision line and the tool error. The counters are those of one stdio agent in steady state. As a cross-check it sends every call end to end through an agent session to a gated proxy and to a pass-through proxy over the same no-op upstreams, and logs the paired difference.

What fails the run:

| Corpus | Check | Limit | Enforced in |
| --- | --- | --- | --- |
| Typical: the 12 calls of `gatetest.Typical` (typed reads, downgraded exec, config dumps, `no-exec`, holds, unknown and malformed targets, fan-out, group selectors) | p99 of 24,000 calls | 5 ms | Every run |
| Worst: arguments within 1 KiB of the 64 KiB cap, at the gate's per-call caps (64 show commands of 1 KiB, one multi-line command, a multi-line config string, config lines, 256 targets of 250 bytes, 64 commands of 1 KiB to every known target), the same 64 KiB as 1,900 short commands and 3,300 short targets (refused by the caps), and, in the proxy, one byte over the cap | p50 of each case, 200 calls | 5 ms. A case in `gatetest.KnownOverBudget` passes while over it and fails once it is back under it, so its entry comes out | Only with `FATHOMGATE_OVERHEAD_STRICT=1` |
| End to end, typical, gated minus pass-through | p50 | 5 ms | Every run |

`FATHOMGATE_OVERHEAD_STRICT=1` is set only in the `gate overhead budget (M1-23)` steps of the Linux, Windows and macOS CI jobs. Those steps run the two tests alone, with `-p 1 -v` and without `-race`. In a full `go test ./...`, other packages' tests share the CPU, so a worst case's p50 of a few milliseconds is not the gate's alone and is only logged. The go-reviewer's round on PR #183 caught `TestDecideOverhead` failing 1 run in 3 that way, with the 3,300-target case at a p50 of 5.74 ms.

A worst case's p99 over the budget is logged as `OVER BUDGET AT p99`, not failed, because the garbage collector sets it rather than the call. Each worst case allocates 0.4 to 3.4 MB, so a collection starts every call or two. On Windows the pause lands on a random call and adds 10 to 18 ms. With `GOGC=off`, or on Linux, p99 sits close to p50. The end-to-end p99 is logged for the same kind of reason: it is set by the in-memory transport's scheduling jitter, which is as large on the pass-through proxy.

Under `-race` the limit is 10 times higher (`gatetest.RaceFactor`), because the race detector slows this map, regexp and JSON code by up to 20 times. Only the typical corpus is timed there, for 100 rounds. Each worst case is checked once for its decision word and rule id, and the end-to-end worst cases are skipped, as they are under `-short`. The 1x budget is held by the strict steps, and the numbers below come from the Linux step's log. The threshold never moves to make a run pass. A case over it goes into `KnownOverBudget` with its finding and owner, and comes out when the finding is fixed.

Run: `FATHOMGATE_OVERHEAD_STRICT=1 go test -count=1 -p 1 -v -run 'TestDecideOverhead|TestDispatchOverhead' ./internal/gate/ ./internal/proxy/`. Per-case means and allocations: `go test -run '^$' -bench BenchmarkDecideOverhead ./internal/gate/`.

### Measured, 2026-09-25

GitHub-hosted `ubuntu-latest` (4 vCPU, go1.26.8, no `-race`, `-p 1`), [PR #183 run](https://github.com/fathomgate/fathomgate/actions/runs/36186989951/job/108242702823):

| Case | `Decide` p50 / p99 | Proxy decision stage p50 / p99 | End-to-end added p50 |
| --- | --- | --- | --- |
| Typical corpus | 7.8 µs / 33 µs | 21 µs / 131 µs | under 0 (noise) |
| 1,900 show commands (`eos-mcp.run_commands`) | **9.7 ms / 10.7 ms** (known) | **20.9 ms / 26.0 ms** (known) | 21.3 ms |
| One 64 KiB multi-line command (`upa`) | 0.46 ms / 0.88 ms | 0.90 ms / 1.4 ms | under 0 |
| 64 KiB config string, core (`upa`) | 0.98 ms / 1.4 ms | 2.4 ms / 4.0 ms | under 0 |
| 64 KiB config lines, lab (`eos-mcp.push_config`) | 1.3 ms / 1.9 ms | 3.3 ms / 3.6 ms | 0.42 ms |
| 3,300 targets (`eos-mcp.daily_brief`) | 3.5 ms / 3.9 ms | **9.4 ms / 10.1 ms** (known) | 5.9 ms |
| Batch, every known target (`run_commands_batch`) | **9.8 ms / 11.5 ms** (known) | **20.1 ms / 21.5 ms** (known) | 17.3 ms |
| One byte over the cap | not reached | 4.0 µs / 13 µs | under 0 |

Maintainer's workstation (Windows 11, Ryzen 7 7700X, 16 threads, go1.26.8, no `-race`, other builds running). The clock here moves in steps of about 0.5 ms, so any time under that reads 0 s. Typical corpus: p99 under one clock step for `Decide` and 0.5 to 1.0 ms for the proxy stage. `BenchmarkDecide` gives a mean of 5.1 µs a call. Worst-case p50s are about half the Linux runner's: 5.5 ms for 1,900 show commands (known), 1.0 ms for config lines and 2.0 to 3.0 ms for 3,300 targets. In the proxy stage they are 12.5 ms, 2.0 ms and 5.6 to 6.0 ms (known). Worst-case p99s reach 8 to 18 ms because of the collector pauses described above.

Findings of M1-23, both fixed in M1-39 (below) and removed from `KnownOverBudget`, which is now empty:

1. **Command classification costs about 3 µs a command** (policy-engineer, `internal/classify`). `classifyCommand` checks each command against the read allow-list with backtracking regular expressions, which takes about 70% of the CPU. The 1,900 show commands that fit in 64 KiB take 5 to 10 ms in `Decide`. Nothing caps the number of commands in a call below the 64 KiB argument cap.
2. **The proxy runs `Decide` twice when a target is already counted** (mcp-protocol-engineer, `internal/proxy`). `decideLocked` runs the gate again with a lower `devices_touched`, which repeats parsing, classification and resolution. Every worst case costs about twice as much in the proxy as in `Decide`, and 3,300 targets go over the budget only because of this.

### After M1-39, 2026-09-25

M1-39 fixed both findings. The gate refuses a call with more than 64 commands or 256 targets before it classifies anything ([profile-schema section 2.4](../specs/profile-schema.md#24-per-call-caps)). The blocklist and shell-metacharacter checks run as a word-set lookup and a byte loop instead of unanchored regular expressions, checked against the old expressions by `FuzzBlocklistWords` and `FuzzShellMeta`; a 1 KiB command went from 61 µs to 5.5 µs (`BenchmarkClassifyCommand`). The proxy runs `Decide` once: the gate takes already-counted targets off `devices_touched` through `seam.CallInfo.Counted` (ADR 0026 notes). The worst cases now sit at the caps, since nothing larger reaches classification, and two more cases fill 64 KiB with short commands and names to time the refusal. `KnownOverBudget` is empty.

Maintainer's workstation, as above (no `-race`, `-p 1`, `FATHOMGATE_OVERHEAD_STRICT=1`; 0 s means under one 0.5 ms clock step). Before is the M1-23 corpus on the M1-23 code; after is the M1-39 corpus, at the default `GOMAXPROCS` of 16 and, for the p99, at 4:

| Case | `Decide` before, p50 / p99 | `Decide` after, p50 / p99 (p99 at `GOMAXPROCS=4`) | Proxy stage before, p50 / p99 | Proxy stage after, p50 / p99 (p99 at `GOMAXPROCS=4`) |
| --- | --- | --- | --- | --- |
| Typical corpus | 0 s / 0.51 ms | 0 s / 0 s | 0 s / 0.53 ms | 0 s / 0 s |
| Show commands: 1,900 short before, 64 of 1 KiB after | 7.7 ms / 9.9 ms | 1.0 ms / 1.5 ms (1.5 ms) | 15.0 ms / 26.7 ms | 1.0 ms / 12.3 ms (2.0 ms) |
| One 64 KiB multi-line command | 0.51 ms / 4.1 ms | 0 s / 1.5 ms (1.5 ms) | 1.0 ms / 7.8 ms | 0 s / 3.0 ms (1.5 ms) |
| 64 KiB config string | 0.52 ms / 4.2 ms | 1.0 ms / 7.0 ms (1.5 ms) | 1.6 ms / 11.6 ms | 1.0 ms / 11.0 ms (1.5 ms) |
| 64 KiB config lines | 1.0 ms / 8.1 ms | 1.0 ms / 9.3 ms (2.0 ms) | 2.1 ms / 12.7 ms | 1.0 ms / 13.0 ms (1.6 ms) |
| Targets: 3,300 short before, 256 of 250 bytes after | 2.6 ms / 16.4 ms | 0 s / 1.5 ms (1.5 ms) | 5.8 ms / 28.7 ms | 1.0 ms / 12.5 ms (2.1 ms) |
| Batch to every known target: 64 KiB of short commands before, 64 of 1 KiB after | 8.3 ms / 21.5 ms | 1.0 ms / 9.3 ms (1.9 ms) | 18.0 ms / 38.4 ms | 1.0 ms / 12.0 ms (1.5 ms) |
| 1,900 short commands, refused by the cap | | 0 s / 2.0 ms (1.2 ms) | | 0 s / 12.5 ms (1.5 ms) |
| 3,300 short targets, refused by the cap | | 0 s / 12.5 ms (1.8 ms) | | 0.50 ms / 10.2 ms (1.7 ms) |

Every worst-case p50 is now about 1 ms or less, in `Decide` and in the proxy stage. The p99s at 16 threads are still over 5 ms on this machine, and they are not the call's cost. With `GOGC=off`, every worst case's p99 is 1.5 to 2.0 ms. With the collector on and `GOMAXPROCS` at 2 or 4 it is 1.2 to 2.1 ms. At `GOMAXPROCS` 8 or 16, a collection cycle stalls the timed call for 10 to 13 ms on Windows, although the cycle itself takes under 1 ms (`GODEBUG=gctrace=1`). Even the refusal of 3,300 short targets, which does no more than parse and count, shows it. Each worst case now allocates 0.4 to 1.0 MB, against 0.4 to 3.4 MB before; that makes collections less frequent, but not rare enough to move a p99 of 200 samples. The Linux runner showed p99 close to p50 before M1-39.

## Tier 2: what it proves

- `tools/list` from each real upstream matches its profile: every listed tool has a profile entry and every profiled tool exists. A mismatch fails the build and is the drift signal for upstream schema changes.
- Both eras initialise: netdev-ssh-mcp (go-sdk, 2026 era; `tests/integration/test_passthrough.py`, CI job `client-smoke`) and upa/mcp-netmiko-server (FastMCP, 2025 era; `tests/integration/test_upa_netmiko.py`, CI job `tier2-upa`), each asserted from fathomgate's `upstream ready` log line, with a 2025-11-25 and a 2026-07-28 agent in front of the 2025 upstream.
- The official conformance suite passes against the proxy's client-facing side, with every remaining failure baselined against an ADR or a board task (see "Conformance suite" below; it runs on every pull request and needs no Docker).
- End-to-end decisions: a `reload` through eos-mcp `run_command` is denied with `no-exec`; a `show running-config` through ntunes `send_command` comes back redacted; an unknown `host` on netdev-ssh-mcp is denied.
- Approval flow against junos-mcp-server with the fake SSH device standing in for the router: hold, approve via CLI, approve after TTL refused, drift cancelled, MRTR accept forwards.
- A modified tool description quarantines the server and writes a `quarantine` event.
- The PATH-stripped launcher case: the proxy is started with an empty `PATH` (and with `env -i`) and absolute binary paths, as Claude Desktop does, and must serve `tools/list`; a bare upstream name or a PATH-dependent wrapper must fail fast with the cause on stderr (`tests/integration/test_launcher_path.py`, CI job `client-smoke`, no Docker).

Run: `make test-integration` (needs Docker). Images are built from pinned upstream commits in `tests/images/`; the pin is bumped by a weekly scheduled workflow that opens a pull request when tier 2 still passes, and an issue when it does not.

Fake device: `tests/fixtures/device/fake_ssh.py` is a Python asyncssh server. Today (T0.5) it serves the SSH exec channel with one vendor persona chosen by `--vendor`, answers `show` commands from `tests/fixtures/device/transcripts/<vendor>/`, and logs every command so a test can prove what reached the device. Still planned for the M3 drivers: interactive prompts, echoing config lines, and simulated `commit confirmed`, `configure session` and `checkpoint` state, so drift and rollback paths can be tested without an image. It never needs a licence.

## Conformance suite

The official MCP conformance suite (`@modelcontextprotocol/conformance`, pinned in `tests/conformance/package-lock.json`) runs against the client-facing side of the real `fathomgate serve` binary for both protocol eras, `2025-11-25` and `2026-07-28`, each scored by that revision's frozen requirement set. Two upstreams stand behind fathomgate, both go-sdk's own conformance everything-server: one built from the go-sdk version in `go.mod`, which negotiates `2026-07-28` with fathomgate, and one built from go-sdk v1.6.1, the last release without `2026-07-28`, which speaks only `2025-11-25` (pinned in the test-only module `tests/conformance/upstream-2025`; the root `go.mod` does not change). Between them all four agent-era x upstream-era pairs run through the real binary. The suite speaks only Streamable HTTP, and since T0.32 it drives fathomgate's own listener: `fathomgate serve --listen 127.0.0.1:0` with a FAKE bearer token, through `tests/conformance/shim.py`, which adds the token and the `conf.` tool prefix the suite cannot send (ADR 0016) and changes nothing else. A control leg runs each fixture's own `-http` handler behind the same shim with neither: a failure only on a fathomgate leg is fathomgate's. `tests/conformance/era_pairs.py` covers the two upstream-prompt cells the suite cannot reach for the 2025 upstream, over stdio and over the listener: the `[from <server>]` label on a relayed prompt, and the ADR 0014 refusal to a stateless agent, checked word for word.

- Passes means every scored check passes except those in `tests/conformance/baseline/`, each listed per check with its reason: capabilities fathomgate does not declare, input requests it refuses, log messages it does not relay, answers it will not forward without its `requestState`, the era pairing and tool prefix, the orphan rule for a stateful upstream's prompts across agent sessions, the refusal of any `Origin` header, the elicitation schema allow-list, and 2026-era checks a 2025 upstream cannot serve. Each names the ADR or board task behind it. A baseline entry that starts passing fails the run.
- It needs Go, Node.js, npm and `python3`, and no network beyond installing the suite. It runs as the `mcp-conformance` job in `ci.yaml` on every push and pull request, including Dependabot's, so a go-sdk bump cannot merge without it.
- One fathomgate serves a whole leg. The suite does not DELETE the session of a scenario that throws, so on the 2025-11-25 fathomgate legs the per-principal cap of 4 sessions answers later scenarios with 503, and the orphan rule refuses the elicitation scenarios' prompts. `run.sh` therefore runs `server-session-lifecycle`, `tools-call-elicitation` and `elicitation-sep1034-defaults` again, each alone on a fresh fathomgate, and they must pass (tests/conformance/README.md, "One process").
- Not covered: a FastMCP upstream (the 2025 fixture is go-sdk's server held on an older release, not a different SDK).
- It proves the proxy's MCP surface, not an upstream: matrix rows 1 and 2 still need their named real servers.

Run: `make conformance`. Details, legs and how to change a baseline: [tests/conformance/README.md](../../tests/conformance/README.md).

## Tier 3: what it proves

- eos-mcp `push_config` on cEOS: the configure session commit timer reverts an unconfirmed change at the deadline; `confirm_config_session` cancels it; the diff shown at hold matches what the device applied.
- netdev-ssh-mcp on NX-OS (when a licensed image is available): the proxy watchdog restores the checkpoint at the deadline.
- Redaction on a real `show running-config` from each device in the topology.
- Nokia SR Linux as the freely pullable second target for the SR Linux driver when it lands.

Run: `make test-clab` on a host with containerlab, Docker and the images. The workflow is `.github/workflows/nightly-clab.yaml` on a self-hosted runner labelled `clab`.

## Containerlab notes

- Topology: `tests/clab/fathomgate.clab.yml` with two cEOS nodes (`lab-sw-01`, `lab-sw-02`) and one SR Linux node (`lab-srl-01`). Management network `172.20.20.0/24`.
- Startup: cEOS takes 60 to 120 seconds to reach a usable CLI; the helper `tests/clab/wait_ready.py` polls `show version` over scrapli before tests begin.
- Assertion helpers: `tests/clab/assert_device.py` exposes `running_config_contains`, `session_exists`, `checkpoint_exists`, `commit_timer_active`. They connect with scrapli, never through the proxy, so a proxy bug cannot hide a device fact.
- Cleanup: `containerlab destroy --cleanup` runs in an `always()` step so a failed night does not leave nodes for the next.
- Resources: two cEOS nodes need about 4 GB RAM; the runner has 16 GB.

## cEOS licensing

cEOS-lab images are downloaded from arista.com with an Arista account and cannot be pulled from a public registry or redistributed. Consequences:

- Tier 3 cannot run on public GitHub-hosted runners. It runs on a self-hosted runner where the image is loaded into Docker by hand.
- The image tag is pinned in `tests/clab/.env` and documented in `tests/clab/README.md`; nothing in the repository contains the image.
- Contributors without an Arista account run tier 3 against SR Linux only with `make test-clab CLAB_TARGETS=srlinux`, which covers the SR Linux driver and the redaction path but not the EOS timer.
- Cisco NX-OS 9000v and IOS-XE images have their own licence terms; the NX-OS watchdog case is marked `skip` in the matrix until an image is loaded on the runner.
- Juniper vJunos images are free to download with a Juniper account and are a candidate for a later Junos tier 3 case; today the Junos driver is validated in tier 2 against junos-mcp-server with the fake device.

## What is not tested

- Performance under many concurrent agents. The target is a handful of sessions; a benchmark in tier 1 guards classify plus evaluate latency only.
- Real NetBox and Nautobot. The live connectors are paid-edition work and are tested there (ADR 0034 amendment). The core tests the `Resolver` interface, snapshots, stale marking and CSV import of an export; shops with NetBox validate with `fathomgate inventory resolve`.
- The console's visual output beyond rendering both themes without console errors. Design review uses `design/preview.html`.

## Adding a test

- A new policy behaviour: add a case to the relevant `*.test.yaml`. No Go needed.
- A new classification rule: add a row to the worked examples in the spec and a matching table entry in `internal/classify`.
- A new redaction pattern: add an annotated line to the fixture for that vendor.
- A new upstream: add a profile, a tier 2 image build, and one matrix case that names it.
- A new driver: tier 1 command-sequence test, tier 2 against the fake device, and a tier 3 case if an image is available.
