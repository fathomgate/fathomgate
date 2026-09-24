# T0.49 ready for review: NetGuard renamed to Fathomgate per ADR 0019

- **Task:** T0.49: Rename NetGuard to Fathomgate per ADR 0019 (module path, binary, FATHOMGATE_ env prefix, fg4. state prefix, fg- CSS prefix, reported server name, docs and design)
- **From → To:** orchestrator → security-reviewer (go-reviewer, release-engineer and design-guardian also review)
- **State now:** in review. The board's state for T0.49 is left to the board sync (PR #91 moves it to `in progress`); this PR edits `docs/milestones/M0.yaml` only where ADR 0019 requires it.
- **Branch / PR:** `refactor/rename-fathomgate` · see the PR that carries this note
- **Date:** 2026-09-24

## Done

- **Module and binary:** `github.com/fathomgate/fathomgate` in `go.mod`, every import and `.golangci.yaml`; `cmd/netguard` is `cmd/fathomgate` (`git mv`); binary `fathomgate` in `Makefile`, `.goreleaser.yaml`, both Dockerfiles, `.gitignore` and the workflows. The ldflags stay `-X main.*`, so no path changed there.
- **Wire names (`internal/proxy`):** `Name = "fathomgate"` (serverInfo, `[from fathomgate]`); the reserved upstream name folds to `fathomgate`, and `netguard` is no longer reserved (`TestSplitName` cases both ways).
- **Sealed state (`state.go`):** `statePrefix = "fg4."`. `retiredStatePrefixes` is `ng1.`, `ng2.`, `ng3.`, with the detail ADR 0019 gives: `requestState was issued by an earlier fathomgate process; call the tool again without it`. The envelope format, AAD layout and key handling do not change; only the prefix, which is part of the AAD, does. Tests: `retired ng3` in `TestSealer` (`state_test.go`), and `TestHTTPRequestStateBoundToPrincipal` now presents both `ng2.` and `ng3.`.
- **Env prefix (`cmd/fathomgate/serve.go`):** `isFathomgateEnvName` refuses `FATHOMGATE_*` (case-insensitive on Windows) on `--upstream-env` and `--upstream-env-pass`. There is no fallback read of `NETGUARD_*`, and it is not refused either: the new case `NETGUARD_ is an ordinary name` pins that it passes like any other name. `redact` reads `FATHOMGATE_REDACT_KEY` only.
- **Release and CI:** archives `fathomgate_<version>_<os>_<arch>`, formula `fathomgate` in `fathomgate/homebrew-tap`, image `ghcr.io/fathomgate/fathomgate`, image paths `/etc/fathomgate`; repository variables `FATHOMGATE_WINDOWS_RUNNER` and `FATHOMGATE_CLAB_ENABLED` (neither is set today, `gh variable list` is empty). The runner label `netguard` is unchanged in every `runs-on`, `actionlint.yaml` and `ci-runners.md`.
- **Tests:** conformance legs `fathomgate` and `fathomgate-up2025` with re-keyed baseline files; `era_pairs.py --fathomgate`, class `Fathomgate`; Python package `fathomgate-tests`; `FATHOMGATE_BIN`, `FATHOMGATE_UPSTREAM`, `FATHOMGATE_TIER2_REQUIRED`, `FATHOMGATE_UPA_*`.
- **Docs, design, agents:** as in the commit messages. CSS prefix `fg-`. Agent slug `orchestrator`, including `.github/labels.yml` (`agent:orchestrator`). One-line notes in `docs/adr/README.md` and `docs/handoffs/README.md`.
- **Board:** only the ADR's column: titles of open tasks T0.31 and T0.47, T0.31's `package` (`cmd/fathomgate`, the path it will edit), and T0.49's `owner` slug. `STATUS.md` re-rendered.

## Look at this first

- `internal/proxy/state.go`: the prefix and retired list, and that a retired prefix is still checked before any decode or decrypt.
- `cmd/fathomgate/serve.go` `isFathomgateEnvName` and `serve_env_test.go`: the refusal rule moved to the new prefix, and nothing else in the environment allow-list changed.
- `internal/proxy/name.go` `reservedServerName` and the cases in `proxy_test.go`.

## Deliberately unfinished

- ADRs 0001 to 0018, handoff notes, research briefs and merged task notes keep NetGuard (ADR 0019). ADR 0019 keeps it too, since its scope table is the map. ADR 0020 is left as written: it is a decision record, and PR #91 is accepting it.
- Historical CI run links in `docs/testing/test-matrix.md` now point at `github.com/fathomgate/fathomgate/actions/...`. They resolve after the transfer, which moves the runs with the repository.
- Prose that used lower-case `fathomgate` for the running process (inherited from `netguard`) is not restyled to "Fathomgate"; that is a design-guardian pass, not a rename.
- After the merge, the maintainer transfers the repository to `fathomgate/fathomgate` and checks that `gh api repos/fathomgate/fathomgate/actions/runners` lists `ng-wsl-1` to `ng-wsl-3` (ADR 0019 *Sequencing* step 5).

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && python tools/status/render.py --check
go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.9.0 run ./...   # 0 issues
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 -config-file .github/actionlint.yaml
make conformance   # all 8 leg/rev pairs pass their baselines, era pairs ok, no baseline entry changed
```

Local runs were on Windows without cgo, so no `-race` there; CI on the self-hosted WSL runners runs it. Tier 2 against netdev-ssh-mcp v1.6.6 passed locally through `bin/fathomgate.exe` (7 passed, 11 skipped as POSIX-only or M1, 1 xfailed); the upa leg runs in CI.

## Decisions made without an ADR

- None beyond ADR 0019. Where this PR reads the ADR, it says so in the PR description.
