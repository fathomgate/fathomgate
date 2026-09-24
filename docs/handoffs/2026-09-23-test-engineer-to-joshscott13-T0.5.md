# T0.5 merged: exit criterion 2 needs one manual tool call in Claude Code and one in Cursor

- **Task:** T0.5 — Client smoke — Claude Code and Cursor mcp.json snippets, PATH-stripped launcher case
- **From → To:** test-engineer → joshscott13
- **State now:** merged
- **Branch / PR:** tests/client-smoke · https://github.com/joshscott13/netguard/pull/51
- **Date:** 2026-09-23

## Done

- The `client-smoke` CI job runs netguard in front of the real `netdev-ssh-mcp` v1.6.6 with a fake SSH device. It checks `tools/list`, a read-only call, and a refused `reload`, on every PR.
- Claude Code 2.1.236 listed all five tools through netguard, with an empty `PATH`. Its tool call did not run because the client's login had expired.
- `docs/install.md` covers setup for both clients and the stripped-PATH case.

## Look at this first

- `docs/install.md`, section "Check it works". These are the steps that tick exit criterion 2.

## Deliberately unfinished

- A tool call through Claude Code and through Cursor. No agent can drive Cursor, and the Claude Code login is yours.

## Reproduce green

```sh
make build
cd tests && uv run --extra integration python fixtures/device/fake_ssh.py --state-dir /tmp/fakedev --port 22022
# then, in each client: ask for `show version` on 127.0.0.1 port 22022, device type eos
# pass = the reply contains FAKE0000SN01 and /tmp/fakedev/commands.log has one `show version` line
```

## Decisions made without an ADR

- Integration Python dependencies are pinned exactly (`mcp==2.2.0`, `pytest-asyncio==1.4.0`, `asyncssh==2.24.0`).

## Questions for the receiver

- Once both clients pass, reply here or on the board. Rows 1 and 22 then move to `passing`, and exit criterion 2 is ticked.
