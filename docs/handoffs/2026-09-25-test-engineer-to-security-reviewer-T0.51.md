# T0.51: tier 2 and the docs on netdev-ssh-mcp v1.7.1, which fixes the T0.29 report; review the claims about the upstream's fixes

- **Task:** T0.51 — Move tier 2 and the docs to netdev-ssh-mcp v1.7.1, which fixes the keyed-hash issue Fathomgate reported
- **From → To:** test-engineer → security-reviewer (docs-writer is the second reviewer)
- **State now:** in review. T0.51 is on the board only on PR #106's branch. This PR does not edit `docs/milestones/M0.yaml`.
- **Branch / PR:** `test/netdev-ssh-mcp-1.7.1` · [PR #108](https://github.com/fathomgate/fathomgate/pull/108)
- **Date:** 2026-09-25

## Done

- Read the upstream at `v1.7.1` (`6fc6ab0`) against `v1.6.6` (`be3e363`), and both advisories.
  - [GHSA-8g43-jrf3-q9vq](https://github.com/krisiasty/netdev-ssh-mcp/security/advisories/GHSA-8g43-jrf3-q9vq): medium, `<= 1.6.6`, fixed in v1.7.0 by upstream PR #22 (`682e2e1`). The credited reporter is `joshscott13`.
  - [GHSA-h47r-329w-6p9h](https://github.com/krisiasty/netdev-ssh-mcp/security/advisories/GHSA-h47r-329w-6p9h): high, `<= 1.7.0`, fixed in v1.7.1 by upstream PR #23 (`ce2206b`). The upstream maintainer reported it himself.
- Release pin: the linux_amd64 sha256 `f90795b45c3fff89aabe56b6327f53ddda15825db60a8cde0d1b23b6be30c9e7` comes from the release's `checksums.txt`. It matches the downloaded binary, and CI's `sha256sum -c` also passed. Updated in `ci.yaml`, `tests/integration/conftest.py` and `tests/README.md`.
- `tests/integration/test_passthrough.py`:
  - the keyed token asserted exactly (FAKE key file);
  - the per-run random key (distinct tokens, not the unkeyed hash, plus the notice block);
  - six injected commands refused with nothing sent.
  - All eight cases fail against v1.6.6.
- The upstream obfuscator, unchanged, over `tests/fixtures/configs/`: v1.7.1 leaves 0/71 in clear with the annotations stripped. v1.6.6, as a control, leaves 20/71, the T0.29 totals.
- Profile notes (T0.29 kept as history), research brief 02 (new dated section), `docs/install.md` (v1.7.1, both advisories; key file optional since the fix round), matrix rows 1, 2, 15 and 22 with a run note, and CHANGELOG.
- CI [run 36087378002](https://github.com/fathomgate/fathomgate/actions/runs/36087378002) is all green. `client-smoke`: 23 passed, 2 skipped (M1), 1 xfailed (row 15).

## Look at this first

- `profiles/netdev-ssh-mcp.yaml`, the v1.7.x section: every claim about the upstream, with file and commit.
- `docs/install.md` "Leave netdev-ssh-mcp's obfuscation on": the advice that users now act on.

## Deliberately unfinished

- No `fathomgate` code changes. The upstream's keyed tokens and its command checks do not replace M1 classification or M2 redaction. Row 15 stays `planned`, and its Expected cell now says the upstream's tokens do not count.
- The upstream's no-key notice reaches the agent as a second content block, forwarded unchanged in M0. fathomgate does not relay upstream `instructions` at all. Nothing in fathomgate handles either one yet.
- In the annotated corpus as committed, 3 IOS-XE lines defeat the upstream's end-of-line-anchored patterns because of the `! rule-id` comment. That is a corpus artefact, so the fixtures were not changed.
- The real-client check (Claude Code, Claude Desktop) was not repeated with v1.7.1.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check
cd tests && uv run --extra dev pytest unit -q
# tier 2 (release binary checked against v1.7.1 checksums.txt)
FATHOMGATE_UPSTREAM=/abs/netdev-ssh-mcp_1.7.1_<os>_<arch> uv run --extra integration pytest integration -m "tier2 and netdev_ssh_mcp" -v
```

## Decisions made without an ADR

- Superseded in the fix round (security M1): install.md keeps the default per-run key, and a key file is optional.
- The notice-block test pins the opening words of an upstream string. It is compared as data, never acted on (invariant 7).

## Questions for the receiver

- Should M1 or M2 strip or label the upstream's appended notice block, or is forwarding it as tool output enough under invariant 7?
- Is "keep obfuscation on, with a key file" still the right M0 advice, now that the upstream's tokens are keyed?

## Fix round (2026-09-25)

Security approved with one medium; the docs review requested changes. Where they conflicted, security won. Commit `d40bb64`, CI [run 36088442110](https://github.com/fathomgate/fathomgate/actions/runs/36088442110) all green; `client-smoke` 23 passed, 2 skipped (M1), 1 xfailed (row 15).

- **M1:** `docs/install.md` keeps the upstream's default per-run key, and says why it is the safest setting and that its notice block is harmless. A key file is optional, only for tokens that must match across runs. Keep it where the agent's tools cannot read it, and never put the key in a client `env` block. The three examples stay keyless, with one sentence on adding the flag. Table rows updated. The profile and the test comments say the same.
- **L2:** each injection case asserts the upstream's exact refusal text, taken from `command_safety.go` at `6fc6ab0`. **N4:** the per-run-key case asserts that the agent's `initialize` result carries no upstream `instructions`. **L3:** added a CHANGELOG `### Security` entry.
- Profile note, checked against the source: `show  running-config` (two spaces) passes the upstream's `show ru` prefix check, so the `get_config` redirect can be bypassed (the output is still obfuscated), and `run_ping` / `run_traceroute` arguments may start with `-`.
- Docs findings 1 to 3 and 5 to 15 applied. Finding 4 was replaced by M1. The review text was not on the PR, so the wording for findings 3, 5, 10 and 13 is mine, written to the brief. Please check it.
- Not touched, as asked: the threat-model rows and the Fathomgate-in-prose sweep.
