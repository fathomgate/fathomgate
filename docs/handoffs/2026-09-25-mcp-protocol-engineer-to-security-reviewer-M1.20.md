# M1-20: serve --policy, --inventory, --profiles with embedded profiles; --no-policy; --audit refused until M4

- **Task:** M1-20 — fathomgate serve --policy, --inventory, --profiles with embedded profiles; --audit refused until M4
- **From → To:** mcp-protocol-engineer → security-reviewer (then go-reviewer, design-guardian, release-engineer)
- **State now:** in review
- **Branch / PR:** `feat/serve-policy` · [PR #171](https://github.com/fathomgate/fathomgate/pull/171)
- **Date:** 2026-09-25

## Done

- `cmd/fathomgate/serve_policy.go`: `pipelineFlags.check` (ADR 0027 combinations), `loadPipeline` (policy, inventory chain, profiles, `gate.New`), start-up attributes and Warn lines, embedded and `--profiles` loading, `fathomgate version` profile lines.
- `cmd/fathomgate/serve.go`: `--policy`, `--inventory`, `--profiles`, `--no-policy` parsed; `--audit` refused naming M4; the four pipeline names refused among the upstream arguments; policy-flag check last; the pipeline loads before `--listen` binds or the upstream starts; `opts.Gate` set only for a non-nil gate.
- `profiles/embed.go` (package `profiles`, `//go:embed *.yaml`, Apache-2.0 SPDX).
- `internal/inventory`: `File.PatternWarnings` (ADR 0031 decision 5 text).
- `listen.go`: `listening` line carries the pipeline attributes; listener refusals say M2.
- Tier 2 `serve_args`, `test_upa_netmiko.py`, `era_pairs.py`, `tests/conformance/run.sh`: `--no-policy`. `.goreleaser.yaml` and `Dockerfile` copy `profiles/*.yaml` and `LICENSE` only.
- Docs: profile-schema 8.3 and 8.5, install.md (snippets, Claude Desktop, upgrade note), README, ARCHITECTURE, CLAUDE.md, inventory-schema 4, CHANGELOG (Added; Changed, breaking), ADR 0027 *Notes after acceptance*.

## Look at this first

- `loadPipeline` and `pipelineFlags.check` in `cmd/fathomgate/serve_policy.go`.
- `serveContext` in `cmd/fathomgate/serve.go`: load order, and the nil-interface guard on `opts.Gate`.
- Tests: `TestServePolicyEndToEnd`, `TestServePipelineExitCodes`, `TestEmbeddedProfilesAreTheRepo`, `TestProfilesReplaceNotMerge`, `TestLoadPipelineStartup`.

## Deliberately unfinished

- `fathomgate version` prints each profile's SHA-256 prefix, not a "pinned upstream version line": profiles hold the pin only in free-form comments. Waits for `verified_version` (profile-schema 3, M2).
- Rows 3, 4 and 6 are validated in M1-28, not here. This PR ran them by hand only.
- `fathomgate policy eval --inventory` still counts a pattern-only name as known, unlike the gate (pre-existing, M1-34 follow-up).
- Symlinks are not refused for the policy, inventory or profile files: they hold no secret and no spec asks for it.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./...          # -race in CI
GOOS=windows ~/go/bin/golangci-lint run ./...; GOOS=linux ~/go/bin/golangci-lint run ./...; GOOS=darwin ~/go/bin/golangci-lint run ./...
go test -count=1 -run 'Pipeline|Embedded|ProfilesReplace|LoadPipeline|PolicyEndToEnd|PatternWarnings' ./cmd/fathomgate/ ./internal/inventory/
bin/fathomgate policy test policies/examples/*.test.yaml   # 45 of 45
# conformance: tests/conformance/run.sh <leg> <rev> for all 4 legs x 2 revs, then era_pairs.py: all green, baselines unchanged
python tools/licences/spdx.py && python tools/licences/third_party.py --check && python tools/status/render.py --check
bin/fathomgate serve --server netdev-ssh-mcp --upstream x          # exit 2, names --policy and --no-policy
```

## Decisions made without an ADR

- All recorded in ADR 0027 *Notes after acceptance*: message texts; order of checks; embed in `profiles/`; empty `--profiles` directory is an error; `*.csv` inventory refused; obligation warnings only for `allow` rules; an extra Warn listing `hold` rules; listener texts moved to M2.

## Questions for the receiver

- Is naming the policy, inventory and profile paths in errors and the start-up line acceptable? ADR 0027 says the message names the file, and none holds a secret.
