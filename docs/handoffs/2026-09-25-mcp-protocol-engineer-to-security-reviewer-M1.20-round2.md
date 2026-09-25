# M1-20 round 2: empty profile for an unknown server, file integrity, quiet load errors, gated tier 2

- **Task:** M1-20 — fathomgate serve --policy, --inventory, --profiles with embedded profiles; --audit refused until M4
- **From → To:** mcp-protocol-engineer → security-reviewer (then go-reviewer, design-guardian, release-engineer)
- **State now:** in review
- **Branch / PR:** `feat/serve-policy` · [PR #171](https://github.com/fathomgate/fathomgate/pull/171) (round 2; main with #168 and #170 merged in)
- **Date:** 2026-09-25

## Done

- **Orchestrator decision:** under `--policy`, a `--server` with no profile gets an empty profile, so a call with any argument is `default:bad_arguments`; the Warn lists `servers_with_a_profile`. ADR 0027 note, review round. `TestNoProfileServerDeniesArguments`.
- **M2:** `TestServePolicyEndToEnd` gains a `stdio` subtest, with fathomgate as a child process. Tier 2 `tests/integration/test_policy_gate.py` runs `serve --policy read-only.yaml` over stdio in front of netdev-ssh-mcp v1.7.1 and the fake device. The CI job's marker already selects it; only the step name changed. The fake device now writes `sessions.log`, which shows that denied calls (`reload`, `localhost`, `10.99.99.99`) open no SSH session.
- **M1:** `internal/yamlstrict` is the decoder for `policy.Parse`, `inventory.ParseFile` and `classify.ParseProfile`. Errors keep `[line:column]` and the message, and the message is dropped when it quotes a value. Each loader has a FAKE-canary test.
- **M4:** `internal/configfile` checks the policy, inventory, `--profiles` directory and each profile file on the opened file.
  - Unix: owner is the euid or root; `mode & 0o022 == 0`; no macOS ACL.
  - Windows: owner is the user, SYSTEM or Administrators; no write ACE for anyone else.
- **L1:** `--policy`, `--inventory` and `--profiles` are set-once flags.
- **L2:** subdirectories and `*.yml` files in `--profiles` are refused. Each profile file must be `<server>.yaml`, so `profiles/upa-mcp-netmiko-server.yaml` was renamed to `profiles/upa.yaml`.
- **L3:** a second YAML document is refused in all three loaders.
- **Go review:**
  - `policy.KnownObligations` is iterated, and `TestObligationsPartitioned` checks each obligation is handled.
  - `profiles.FS()` now wraps an unexported `embed.FS`.
  - Loader error paths name the file; the pattern compile is shared.
  - The end-to-end test checks the index into results and waits for `done` in `t.Cleanup`.
- **Design:** items 1 to 15 applied: messages, warnings, install.md, README, CHANGELOG, `version` output and profile-schema 8.3.
- **#170:** the tests and docs pin the new `no-exec` reason.

## Look at this first

- `cmd/fathomgate/serve_policy.go`: `loadPipeline`, the empty-profile branch, and `loadProfiles`.
- `internal/configfile/configfile_windows.go` (`writeRights`, `trusted`) and `configfile_unix.go`.
- `internal/yamlstrict/yamlstrict.go` `clean`: which quoted text survives. Snake_case keys found in the file, and UPPER_SNAKE words (class names), are kept. Both are recorded as residuals.

## Deliberately unfinished

- No conformance leg under a permissive policy. Under `--policy` the server `conf` has no profile, so every call with arguments would be denied. The leg needs a test profile for the suite's tools and new baselines. This is recorded in the ADR 0027 note.
- `classify.LoadProfileFS` was not added. `loadProfiles` in `cmd/fathomgate` is still the one serve loader, and `classify.LoadProfileDir` stays as it was for tests and `policy eval`.
- The directories above a config file are not checked, and symbolic links are followed. Both are recorded in the threat-model row.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./...          # -race in CI
GOOS=windows ~/go/bin/golangci-lint run ./...; GOOS=linux ~/go/bin/golangci-lint run ./...; GOOS=darwin ~/go/bin/golangci-lint run ./...
go test -count=1 -run 'Pipeline|Embedded|ProfilesReplace|LoadPipeline|PolicyEndToEnd|NoProfile|Obligations' ./cmd/fathomgate/
go test ./internal/yamlstrict/ ./internal/configfile/ ./internal/policy/ ./internal/inventory/ ./internal/classify/
cd tests && FATHOMGATE_BIN=... FATHOMGATE_UPSTREAM=<netdev-ssh-mcp v1.7.1> uv run --extra integration pytest integration -m "tier2 and netdev_ssh_mcp"
# conformance: tests/conformance/run.sh for 4 legs x 2 revs, then era_pairs.py; baselines unchanged
```

## Decisions made without an ADR

- None beyond the ADR 0027 review-round note.

## Questions for the receiver

- On a machine whose user profile grants another group Modify, serve refuses every config file under that profile until the ACL is fixed. The dev box this ran on grants `CodexSandboxUsers` Modify on `C:\Users\joshs`. This is intended; please confirm.
