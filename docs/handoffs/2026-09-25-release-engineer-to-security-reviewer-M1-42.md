# M1-42: gitleaks runs in CI over the repository and fixtures; review the allow-list, the ignore entries and the threat-model wording

- **Task:** M1-42 — Secret scanner (gitleaks) in CI for the repository and fixtures
- **From → To:** release-engineer → security-reviewer (test-engineer also reviews)
- **State now:** in review
- **Branch / PR:** `ci/gitleaks` · https://github.com/fathomgate/fathomgate/pull/198
- **Date:** 2026-09-25

## Done

- `.github/workflows/ci.yaml` job `gitleaks`: `ubuntu-latest`, `contents: read`, no secrets, `fetch-depth: 0`. `make secrets-control`, then `make secrets-scan`: `GITLEAKS_LOG_OPTS=base..head` on a pull request, full history (`--full-history HEAD`) on a push to main and weekly.
- `Makefile`: gitleaks 8.30.1 release binary, with sha256 pinned per linux/darwin x64/arm64 and checked before unpacking. Targets `secrets-scan` and `secrets-control`.
- `.gitleaks.toml`: the built-in rules plus five `netdev-*` rules scoped to `^tests/fixtures/`. One allow-list, `targetRules` = those five, `condition = "AND"`, with named fixture files and secret regex `^(?:\$(?:1|5|6|8|9)\$|-AQ==|0x)?FAKE[!-~]*$`.
- `.gitleaksignore`: four fingerprints, each with its reason (see the PR table).
- `tools/secrets/control.sh`: a negative control in git and dir mode, mutation-checked.
- `tests/fixtures/configs/ios-xe.txt` and the expect file: `0822455D0A16FAKE7` → `FAKE0822455D0A16`.
- The hand-run gitleaks step in the release, `release-engineer` and `/security-review` checklists is replaced by the make targets. `test-strategy.md`, `maintainers.md`, `tests/fixtures/README.md` and `CHANGELOG.md` are updated.

## Look at this first

- The `[[allowlists]]` block in `.gitleaks.toml` and its comment. The allow-list is rule-bound, not global, because gitleaks 8.30.1 `shouldSkipPath` skips any file a global allow-list's `paths` match in dir mode, ignoring `condition`. `tools/secrets/control.sh` proves both modes.

## Deliberately unfinished

- **Threat-model row.** PR #194 (which adds the row "Secret scanner not in CI") has not merged, so I did not edit `docs/security/threat-model.md`. Wording to apply once #194 is in:
  - **Row, status column:** `Mitigated for the repository and fixtures (M1-42, PR #198): CI job gitleaks scans each pull request's commits and, on every push to main and weekly, the full history, with gitleaks 8.30.1 pinned by sha256; .gitleaks.toml adds network-config rules on tests/fixtures/, where a secret that does not start with FAKE fails the build, and make secrets-control proves it. Open for sampled tier 2 output: owner test-engineer, M2 with redaction (ADR 0006; PRD section 5)`
  - **Row, evidence column:** `.github/workflows/ci.yaml job gitleaks; .gitleaks.toml; .gitleaksignore (four judged false positives); tools/secrets/control.sh. The release preflight (.claude/commands/release.md) requires the job green on the candidate commit`
  - **MCP04 summary line:** replace `secret scanner not in CI (open, release-engineer)` with `secret scanner not in CI (repository and fixtures mitigated, M1-42; sampled tier 2 output open, M2)`.
- **Network rules outside `tests/fixtures/`.** Docs, research briefs and `internal/redact/redactor_test.go` use non-FAKE illustrative values. Widening the rules means converting those examples first; it is a follow-up, not filed yet.
- **Your agent file** (`.claude/agents/security-reviewer.md` lines 44, 59, 83) still describes the M2 sampled-output canary. It is left as is, and is yours to adjust.

## Reproduce green

```sh
make secrets-control && make secrets-scan                    # full history
make secrets-scan GITLEAKS_LOG_OPTS="origin/main..HEAD"      # what a pull request runs
go test -count=1 ./internal/redact/ && make fixtures-check
make actionlint && make status-check && make licences-check
```

## Decisions made without an ADR

- No ADR for a CI tool. Precedent: golangci-lint (T0.20) and actionlint. No `go.mod` change; noted in the PR.
- The network-config rules run on `tests/fixtures/` only (not repo-wide), for the reason above.
- The fixture rename, instead of widening the allow-list regex to accept `FAKE` mid-value.

## Questions for the receiver

- Is the marker list (`$1$ $5$ $6$ $8$ $9$`, `-AQ==`, `0x`) narrow enough, or should each marker be tied to its vendor's fixture file?
- Should the `tests/integration/conftest.py` sha256 false positive (recurs on every eos-mcp bump) get an inline `gitleaks:allow` on that line instead of a fingerprint each time?
