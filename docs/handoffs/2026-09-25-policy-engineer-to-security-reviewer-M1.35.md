# Closed argument list per tool (ADR 0033): eos-mcp config_path refused, ready for security review

- **Task:** M1-35 — Refuse tool arguments the profile does not name (eos-mcp config_path) (ADR)
- **From → To:** policy-engineer → security-reviewer (then go-reviewer)
- **State now:** in review
- **Branch / PR:** `feat/closed-argument-list` · https://github.com/fathomgate/fathomgate/pull/161 (branched from `feat/profile-coverage`, PR #158, still open; base retargets to `main` when #158 merges)
- **Date:** 2026-09-25

## Done

- `docs/adr/0033-closed-argument-list-per-tool.md`, accepted. It records the maintainer's 2026-09-25 decision: a closed list, deny, never strip. Numbered 0033 because 0031 is PR #157 and 0032 is expected from the concurrent unknown_target ADR (M1-37).
- `internal/classify/profile.go`: `ToolSpec.Args` (required, `[]` allowed) and `RefusedArgs`, with loader checks for a missing list, empty names, duplicates, and refused-and-named. `ToolSpec.Named`.
- `internal/classify/normalize.go`: `CheckArguments`, plus `Result.UnnamedArgs`, `Result.MalformedArgs` and `Result.ArgumentsOK()`. The class is unchanged; `Evaluate` is untouched.
- `cmd/fathomgate/policy.go`: `policy eval --profile` prints `deny default:bad_arguments` for these calls, with the argument names in the trace only.
- All five profiles name every argument of every tool. Refused: eos-mcp `config_path` (all 17 tools) and `session_name`; netdev-ssh-mcp `username`; ntunes `send_config` `enter_config_mode`.
- Docs: profile-schema §2, §2.2, §7 and the §4/§5 examples; threat-model (the config_path row plus one new row); glossary; ARCHITECTURE; CHANGELOG with a migration note.

## Look at this first

- `CheckArguments` in `internal/classify/normalize.go`. Then the refusal table in ADR 0033 section 6: each refusal is a security judgement, `username` above all.
- `TestRepoProfileArguments`, which holds the upstream parameter tables read from source.

## Deliberately unfinished

- The gate's deny: M1-18. The `tools/list` inputSchema filtering: M1-19 (ADR 0033 §4). The no-profile Warn text: M1-20.
- Tier 2 comparison of `tools/list` inputSchema with the named set plus `refused_args` (test-engineer, with M1-28).
- junos-mcp-server and ntunes are unpinned. Their argument lists were read at main HEAD (`75fe90a`, `4cc59d6`). The junos v1.1.1 tag has `add_device` and `reload_devices`, which main has dropped.
- Board YAML not edited (M1-35 is on PR #159).

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && golangci-lint run ./... && make policy-test && make fixtures-check && make status-check && make licences-check
go test -run 'TestRepoProfileArguments|TestEOSConfigPathRefused|TestCheckArguments|TestParseProfileArgs' -v ./internal/classify/
bin/fathomgate policy eval --policy policies/examples/read-only.yaml --inventory inventory.example.yaml \
  --profile profiles/eos-mcp.yaml --tool get_version --arg hostname=lab-leaf-01 --arg config_path=/proc/self/stat   # deny default:bad_arguments
```

`-race` was not run locally, because there is no C compiler on this Windows host. CI runs it.

## Decisions made without an ADR

- None outside ADR 0033. Inside it, these calls are mine to defend: `username`, `session_name` and `enter_config_mode` are refused; an unknown tool has every key unnamed; with no profile, nothing is checked.

## Questions for the receiver

- Is refusing netdev-ssh-mcp `username` right, or too strict? Operators must set `DEVICE_USERNAME` instead.
- Should `port` (netdev) or `timeout` (junos) be refused too, or limited later by a value range (M2)?
