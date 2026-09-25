# Status

<!-- GENERATED from docs/milestones/M1.yaml by tools/status/render.py. Edit the YAML, then `make status`. -->

**Current milestone:** M1 — Classify + allow/deny · **state:** open; ADRs 0026 to 0028 accepted, 0029 accepted in part, 0030 deferred to M2 · opened 2026-09-25

Tasks: open 13 · blocked 3 · in review 3 · merged 17 · dropped 3

## In flight

| Task | Title | Package | Owner | Reviewers | State | Blocked by | Matrix | ADR |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| M1-01 | Accept ADR 0026, the M1 policy pipeline at Proxy.dispatch | `docs/adr` | joshscott13 | mcp-protocol-engineer, policy-engineer, security-reviewer, go-reviewer, design-guardian | merged | — | 3, 4, 6 | [0026](docs/adr/0026-m1-policy-pipeline-at-dispatch.md) |
| M1-02 | Accept ADR 0027, serve --policy, --inventory and --profiles; --audit refused until M4 | `docs/adr` | joshscott13 | mcp-protocol-engineer, security-reviewer, design-guardian, release-engineer | merged | — | 3, 4, 6 | [0027](docs/adr/0027-serve-policy-inventory-profiles-flags.md) |
| M1-03 | Accept ADR 0028, audit signing key custody | `docs/adr` | joshscott13 | policy-engineer, security-reviewer | merged | — | — | [0028](docs/adr/0028-audit-key-custody.md) |
| M1-04 | Accept ADR 0029, remote listening with built-in TLS and loopback authentication | `docs/adr` | joshscott13 | mcp-protocol-engineer, security-reviewer, release-engineer | merged | — | 23 | [0029](docs/adr/0029-remote-listener-tls-and-loopback-authentication.md) |
| M1-06 | Label the upstream era from the negotiated protocol version, not from how fathomgate connected (N6) | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | merged | — | 2 | — |
| M1-07 | Record the PR #108 review's upstream-content findings in the threat model and route them to M1 and M2 | `docs/security` | security-reviewer | docs-writer | open | — | 15, 16 | — |
| M1-08 | Write the product name as Fathomgate in prose across docs (ADR 0019 voice rule) | `docs` | docs-writer | design-guardian | open | — | — | — |
| M1-09 | Check the audit signing key like every other secret file, and stop audit verify trusting a private key | `internal/audit` | policy-engineer | security-reviewer, go-reviewer | merged | — | — | [0028](docs/adr/0028-audit-key-custody.md) |
| M1-10 | Decide whether the elicitation allow-list accepts titled multi-select (items.anyOf with const and title) and enumNames | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | open | — | 2 | — |
| M1-11 | Report upstream that go-sdk's conformance everything-server sends a titled multi-select its own client rejects | `docs` | joshscott13 | mcp-protocol-engineer | open | — | — | — |
| M1-12 | Revisit retiring an agent session on DELETE, so a call delivered but not yet admitted cannot run on it | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | open | M1-19 | 23 | [0016](docs/adr/0016-streamable-http-listener.md) |
| M1-13 | Profile for upa/mcp-netmiko-server, every surveyed tool mapped | `profiles` | upstream-server-scout | policy-engineer, security-reviewer | merged | — | 4 | — |
| M1-14 | Audit the netdev-ssh-mcp and eos-mcp profiles against brief 02 and their pinned releases; add a profile-coverage test | `profiles` | upstream-server-scout | policy-engineer, security-reviewer, go-reviewer | merged | M1-13 | 3, 4 | — |
| M1-15 | Tier 1 fallback-classification tests for every other surveyed tool in brief 02 | `internal/classify` | test-engineer | policy-engineer, security-reviewer, go-reviewer | open | — | — | — |
| M1-16 | Classifier - downgrade and config-read cases from classification sections 5 and 6, class_source on the result, whitespace variants | `internal/classify` | policy-engineer | security-reviewer, go-reviewer | merged | — | 3, 5 | — |
| M1-17 | Meta-tool classification through capability tables (Meraki execute_api) | `internal/classify` | policy-engineer | security-reviewer, go-reviewer, upstream-server-scout | open | — | 18 | [0010](docs/adr/0010-classify-by-payload-not-annotations.md) |
| M1-18 | internal/gate - parse, normalise, classify, resolve, Evaluate and the deny text, per ADR 0026 | `internal/gate` | policy-engineer | security-reviewer, go-reviewer | merged | M1-16 | 3, 4, 6 | [0026](docs/adr/0026-m1-policy-pipeline-at-dispatch.md) |
| M1-19 | Wire the gate into Proxy.dispatch - tool errors on deny, decision log line, session counters, annotations from tools/list | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer, design-guardian | merged | M1-06, M1-18 | 3, 4, 6 | [0026](docs/adr/0026-m1-policy-pipeline-at-dispatch.md) |
| M1-20 | fathomgate serve --policy, --inventory, --profiles with embedded profiles; --audit refused until M4 | `cmd/fathomgate` | mcp-protocol-engineer | security-reviewer, go-reviewer, design-guardian, release-engineer | merged | M1-19 | 3, 4, 6 | [0027](docs/adr/0027-serve-policy-inventory-profiles-flags.md) |
| M1-21 | Example policy cases for the M1 matrix rows, and the M1 behaviour of lab-open and prod-approval | `policies` | policy-engineer | security-reviewer | merged | — | 3, 4, 6 | — |
| M1-22 | Tier 2 harness for eos-mcp run_command behind fathomgate, with a fake eAPI device | `tests/integration` | test-engineer | upstream-server-scout, release-engineer | open | — | 4 | — |
| M1-23 | Classify plus evaluate overhead under 5 ms at p99, measured in tier 1 | `internal/gate` | test-engineer | go-reviewer | in review | M1-18 | — | — |
| M1-24 | Reconcile the M1 test-matrix rows and specs with the code and PLAN | `docs` | docs-writer | policy-engineer, test-engineer | open | — | 5, 6 | — |
| M1-27 | Bind listener sockets with SO_EXCLUSIVEADDRUSE on Windows; update the port-squatting threat-model row | `cmd/fathomgate` | mcp-protocol-engineer | security-reviewer, go-reviewer | merged | — | 23 | [0029](docs/adr/0029-remote-listener-tls-and-loopback-authentication.md) |
| M1-28 | Validate rows 3, 4 and 6 through serve --policy against netdev-ssh-mcp, upa/mcp-netmiko-server and eos-mcp run_command | `tests/integration` | test-engineer | go-reviewer, security-reviewer | blocked | M1-13, M1-14, M1-20, M1-21, M1-22 | 3, 4, 6 | — |
| M1-29 | Release v0.2.0 from the M1 CHANGELOG section | `.goreleaser.yaml` | release-engineer | go-reviewer, docs-writer | blocked | M1-28 | — | — |
| M1-30 | Announce M1 - a proxy that lets an assistant read everything and stops reload | `docs` | docs-writer | design-guardian, release-engineer | blocked | M1-29 | — | — |
| M1-31 | Let the status renderer read handoff notes whose task id has a hyphen (M1-06) | `tools/status` | docs-writer | test-engineer | open | — | — | — |
| M1-32 | Refuse a hybrid upstream at startup, and refuse server-initiated input from an upstream connected via server/discover | `internal/proxy` | mcp-protocol-engineer | security-reviewer, go-reviewer | open | M1-06 | 2 | [0008](docs/adr/0008-dual-era-mcp-support.md) |
| M1-33 | Policy test cases that carry a profile, arguments and an inventory and run the gate path (ADR) | `internal/policy` | policy-engineer | security-reviewer, go-reviewer | open | M1-18 | 3, 4, 6 | — |
| M1-34 | Decide whether a hostname pattern alone may make a target known (inventory ADR) | `internal/inventory` | network-safety-engineer | security-reviewer, policy-engineer | open | — | 6 | — |
| M1-35 | Refuse tool arguments the profile does not name (eos-mcp config_path) (ADR) | `internal/classify` | policy-engineer | security-reviewer, go-reviewer | merged | — | 4 | — |
| M1-36 | Config lines that leave the configure session make a write EXEC_ARBITRARY | `internal/classify` | policy-engineer | security-reviewer, go-reviewer | merged | — | 4 | — |
| M1-37 | Make an unset unknown_target deny every class (ADR) | `internal/policy` | policy-engineer | security-reviewer, go-reviewer | merged | — | 6 | — |
| M1-38 | Issue hygiene - GitHub issues follow the board automatically | `tools/status` | release-engineer | security-reviewer, docs-writer | in review | — | — | — |
| M1-39 | Bring the worst cases at the 64 KiB argument cap under the 5 ms budget (per-call caps, one Decide) | `internal/gate` | policy-engineer | security-reviewer, go-reviewer, mcp-protocol-engineer | in review | M1-23 | — | — |

## Done this milestone

- M1-05 Accept ADR 0030, reloading the policy and inventory without a restart — dropped
- M1-25 Reload the policy and inventory without a restart (SIGHUP on Unix, polling on Windows) — dropped
- M1-26 serve --listen-remote, --listen-host, --listen-tls-cert and --listen-tls-key (remote and loopback TLS) — dropped

## Exit criteria

- [ ] 100 percent of surveyed tools mapped
- [ ] policy test suite green
- [ ] `EXEC_ARBITRARY` downgrade works on show commands

Validated against: `netdev-ssh-mcp`, `upa/mcp-netmiko-server`, `eos-mcp run_command`

## Last handoffs

| Date | From | To | Task | Note |
| --- | --- | --- | --- | --- |
| 2026-09-25 | upstream-server-scout | policy-engineer | M1.14 | [M1.14: netdev-ssh-mcp and eos-mcp profiles checked against their pinned source; upa added to the coverage test](docs/handoffs/2026-09-25-upstream-server-scout-to-policy-engineer-M1.14.md) |
| 2026-09-25 | upstream-server-scout | policy-engineer | M1.13 | [M1.13: upa/mcp-netmiko-server profile drafted from source at 96e8ff3; verify and sign](docs/handoffs/2026-09-25-upstream-server-scout-to-policy-engineer-M1.13.md) |
| 2026-09-25 | test-engineer | security-reviewer | T0.51 | [T0.51: tier 2 and the docs on netdev-ssh-mcp v1.7.1, which fixes the T0.29 report; review the claims about the upstream's fixes](docs/handoffs/2026-09-25-test-engineer-to-security-reviewer-T0.51.md) |
| 2026-09-25 | test-engineer | go-reviewer | T0.32 | [T0.32 ready for review: the conformance suite drives `fathomgate serve --listen`, relay.py is gone](docs/handoffs/2026-09-25-test-engineer-to-go-reviewer-T0.32.md) |
| 2026-09-25 | test-engineer | go-reviewer | M1.23 | [Tier 1 overhead budget tests for the gate and the proxy's dispatch path, ready for Go review](docs/handoffs/2026-09-25-test-engineer-to-go-reviewer-M1.23.md) |

## How to update

Edit `docs/milestones/M1.yaml` (task `state`, `blocked_by`, blockers), write a note in `docs/handoffs/` when you hand work on, then `make status`. Never edit this file by hand. Full protocol: [docs/handoffs/README.md](docs/handoffs/README.md).
