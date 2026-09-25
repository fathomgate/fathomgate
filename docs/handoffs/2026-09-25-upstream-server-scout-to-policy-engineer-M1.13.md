# M1.13: upa/mcp-netmiko-server profile drafted from source at 96e8ff3; verify and sign

- **Task:** M1.13, Profile for upa/mcp-netmiko-server, every surveyed tool mapped
- **From → To:** upstream-server-scout → policy-engineer (security-reviewer is the second reviewer)
- **State now:** in review. M1.13 is on the board only on PR #125's branch; this PR does not edit `docs/milestones/`.
- **Branch / PR:** `feat/profile-upa-netmiko` · [PR #150](https://github.com/fathomgate/fathomgate/pull/150) (closes #100)
- **Date:** 2026-09-25

## Done

- `profiles/upa-mcp-netmiko-server.yaml`, `server: upa`. `upa` is the tier 2 `--server` value, `UPA_SERVER` in `tests/integration/conftest.py`. Three tools, all read [src] from `main.py` at `96e8ff321cc839eeb525474736439ddc2ebc795c`, with sha256 `07e55298…7babb` (the same as `UPA_MAIN_SHA256`):
  - `send_command_and_get_output`: `EXEC_ARBITRARY`; `name` is the target, `command` is the command.
  - `set_config_commands_and_commit_or_save`: `WRITE_CONFIG`; `name` is the target, `commands` is the config payload.
  - `get_network_device_list`: `INVENTORY_READ`.
- `docs/specs/profile-schema.md` §6: the upa rows added, and upa removed from the "planned" sentence.
- `docs/research/02-network-mcp-servers.md` §1.3a: the pinned commit, the missing licence, the `--secured` bypasses, the error shapes, the stderr logging and the host-key default.
- `CHANGELOG.md`, under Unreleased > Added.

## Look at this first

- The profile header, then `main.py:184-188` (`--secured`) and `main.py:88-101` (send, commit, save):
  https://github.com/upa/mcp-netmiko-server/blob/96e8ff321cc839eeb525474736439ddc2ebc795c/main.py

## Deliberately unfinished

- `internal/classify/profiles_repo_test.go` has no `upa` entry in `want` and no `reload` case through `send_command_and_get_output`. The scout does not edit Go. M1-14 adds the profile-coverage test, so both belong there.
- No `docs/upstreams/upa.md`. The hazards are in the profile header and in brief 02 §1.3a, the same as for netdev-ssh-mcp.
- Matrix row 4 is still `planned`. Its tier 2 run behind `serve --policy` is M1-28's job.

## Reproduce green

```sh
go build -o bin/fathomgate ./cmd/fathomgate && go vet ./... && go test ./...
for f in policies/examples/*.test.yaml; do bin/fathomgate policy test "$f"; done
P="--inventory inventory.example.yaml --server upa --profile profiles/upa-mcp-netmiko-server.yaml --tool send_command_and_get_output --arg name=lab-leaf-01"
bin/fathomgate policy eval --policy policies/examples/read-only.yaml $P --arg "command=show version"   # allow READ_OPERATIONAL reads-anywhere
bin/fathomgate policy eval --policy policies/examples/read-only.yaml $P --arg "command= reload"        # deny EXEC_ARBITRARY no-exec
bin/fathomgate policy eval --policy policies/examples/prod-approval.yaml --inventory inventory.example.yaml --server upa \
  --profile profiles/upa-mcp-netmiko-server.yaml --tool set_config_commands_and_commit_or_save \
  --arg name=core-rtr-01 --arg "commands=interface Ethernet1,description x"                        # hold, dry_run diff timed_rollback
```

## Decisions made without an ADR

- The file is named `upa-mcp-netmiko-server.yaml` (issue #100's name), but `server:` is `upa`. This is the first profile whose file name and key differ. The loader keys on `server`, so this works.
- `commands` on the write tool goes in `config_params`, not `command_params`, following ntunes `send_config`. The payload is config lines, and a `command_params` entry would send them through the read allow-list.

## Questions for the receiver

- Matrix row 6 names the rule `defaults.unknown_target`, but `policy eval` prints `default:unknown_target`. Which one should the row use?
- For tier 2 fixtures (test-engineer): error shapes are plain-text results, not `isError`. An unknown name returns `Error: no device named '<name>'`. With `--secured`, a blocked command returns `Error: destructive command '<cmd>' is prohibited.`. With `--disable-config`, the write tool returns `changing configuration is prohibited`. A netmiko `ConnectionException` returns `Connection Error: …`. Any other exception comes back as an MCP tool error. Should a later task pass these through to the agent unchanged?
