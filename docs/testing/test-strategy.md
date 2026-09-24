# Test strategy

Three tiers. Tier 1 runs on every commit with no network and proves the policy, classifier, redactor and audit chain are correct. Tier 2 runs on every pull request against the real open-source MCP servers in containers and proves NetGuard speaks to them correctly. Tier 3 runs nightly on a self-hosted runner with containerlab and proves that dry-run, rollback and watchdog behaviour is real on a device. Every case in the [test matrix](test-matrix.md) names the real server it is validated against, so nothing is tested only against a mock.

## Tiers

| Tier | What is real | What is faked | How it runs | Speed | Gate |
| --- | --- | --- | --- | --- | --- |
| 1 Policy unit | Nothing; synthetic `tools/call` requests | Upstream server (recording fake over go-sdk in-memory transport), device, clock | `go test ./...` table tests; `netguard policy test policies/`; Python `pytest tests/unit` for `policy-lint` parity | Seconds | Every commit |
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

Run: `make test` (equals `go test ./... && netguard policy test policies/ && pytest tests/unit`).

## Tier 2: what it proves

- `tools/list` from each real upstream matches its profile: every listed tool has a profile entry and every profiled tool exists. A mismatch fails the build and is the drift signal for upstream schema changes.
- Both eras initialise: netdev-ssh-mcp (go-sdk, 2026 era) and upa/mcp-netmiko-server (FastMCP, 2025 era).
- The official conformance suite passes against the proxy's client-facing side, with every remaining failure baselined against an ADR or a board task (see "Conformance suite" below; it runs on every pull request and needs no Docker).
- End-to-end decisions: a `reload` through eos-mcp `run_command` is denied with `no-exec`; a `show running-config` through ntunes `send_command` comes back redacted; an unknown `host` on netdev-ssh-mcp is denied.
- Approval flow against junos-mcp-server with the fake SSH device standing in for the router: hold, approve via CLI, approve after TTL refused, drift cancelled, MRTR accept forwards.
- A modified tool description quarantines the server and writes a `quarantine` event.
- The PATH-stripped launcher case: the proxy is started with an empty `PATH` (and with `env -i`) and absolute binary paths, as Claude Desktop does, and must serve `tools/list`; a bare upstream name or a PATH-dependent wrapper must fail fast with the cause on stderr (`tests/integration/test_launcher_path.py`, CI job `client-smoke`, no Docker).

Run: `make test-integration` (needs Docker). Images are built from pinned upstream commits in `tests/images/`; the pin is bumped by a weekly scheduled workflow that opens a pull request when tier 2 still passes, and an issue when it does not.

Fake device: `tests/fixtures/device/fake_ssh.py` is a Python asyncssh server. Today (T0.5) it serves the SSH exec channel with one vendor persona chosen by `--vendor`, answers `show` commands from `tests/fixtures/device/transcripts/<vendor>/`, and logs every command so a test can prove what reached the device. Still planned for the M3 drivers: interactive prompts, echoing config lines, and simulated `commit confirmed`, `configure session` and `checkpoint` state, so drift and rollback paths can be tested without an image. It never needs a licence.

## Conformance suite

The official MCP conformance suite (`@modelcontextprotocol/conformance`, pinned in `tests/conformance/package-lock.json`) runs against the client-facing side of the real `netguard serve` binary for both protocol eras, `2025-11-25` and `2026-07-28`, each scored by that revision's frozen requirement set. The upstream behind netguard is go-sdk's own conformance everything-server, built from the go-sdk version in `go.mod`. The suite speaks only Streamable HTTP, so `tests/conformance/relay.py` fronts the stdio proxy, and a control leg runs the same relay in front of the fixture alone: a failure only on the netguard leg is netguard's.

- Passes means every scored check passes except those in `tests/conformance/baseline/`, each listed per check with its reason: capabilities netguard does not declare, input requests it refuses, progress it does not relay, strict `requestState` retries, the era pairing, and HTTP-transport checks that belong to the relay. A baseline entry that starts passing fails the run.
- It needs Go, Node.js, npm and `python3`, and no network beyond installing the suite. It runs as the `mcp-conformance` job in `ci.yaml` on every push and pull request, including Dependabot's, so a go-sdk bump cannot merge without it.
- Not covered: a 2025-era upstream behind netguard (the fixture always negotiates `2026-07-28` with netguard; tier 1 covers all four era pairs), and anything about netguard's own HTTP handling, which does not exist in M0.
- It proves the proxy's MCP surface, not an upstream: matrix rows 1 and 2 still need their named real servers.

Run: `make conformance`. Details, legs and how to change a baseline: [tests/conformance/README.md](../../tests/conformance/README.md).

## Tier 3: what it proves

- eos-mcp `push_config` on cEOS: the configure session commit timer reverts an unconfirmed change at the deadline; `confirm_config_session` cancels it; the diff shown at hold matches what the device applied.
- netdev-ssh-mcp on NX-OS (when a licensed image is available): the proxy watchdog restores the checkpoint at the deadline.
- Redaction on a real `show running-config` from each device in the topology.
- Nokia SR Linux as the freely pullable second target for the SR Linux driver when it lands.

Run: `make test-clab` on a host with containerlab, Docker and the images. The workflow is `.github/workflows/nightly-clab.yaml` on a self-hosted runner labelled `clab`.

## Containerlab notes

- Topology: `tests/clab/netguard.clab.yml` with two cEOS nodes (`lab-sw-01`, `lab-sw-02`), one SR Linux node (`lab-srl-01`) and a Linux node running the fake NetBox stub. Management network `172.20.20.0/24`.
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
- Real NetBox. Tier 2 uses a recorded-response stub; the resolver's HTTP client is small enough for that to be sufficient. Shops with NetBox validate with `netguard inventory resolve`.
- The console's visual output beyond rendering both themes without console errors. Design review uses `design/preview.html`.

## Adding a test

- A new policy behaviour: add a case to the relevant `*.test.yaml`. No Go needed.
- A new classification rule: add a row to the worked examples in the spec and a matching table entry in `internal/classify`.
- A new redaction pattern: add an annotated line to the fixture for that vendor.
- A new upstream: add a profile, a tier 2 image build, and one matrix case that names it.
- A new driver: tier 1 command-sequence test, tier 2 against the fake device, and a tier 3 case if an image is available.
