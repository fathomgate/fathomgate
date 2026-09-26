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

## Round 2 (security review of PR #198: M1 to M3, L1, L2, N1, N3)

State: in review again. `internal/redact` is touched (test only), so please re-check. The round 1 commands above that use `GITLEAKS_LOG_OPTS` are superseded: use `make secrets-scan GITLEAKS_BASE=origin/main`.

- **M1, merge commits.** `tools/secrets/scan.py` passes `--diff-merges=first-parent <range>`. I tested `remerge` and the combined formats too: gitleaks 8.30.1 cannot parse combined diffs, and `remerge` hides a conflicted file behind its `remerge CONFLICT` header line, so a conflict-resolution secret was missed. A first-parent diff repeats what the merge brought in from its other parents. On the full history that was 13 findings, each already fingerprinted at its own commit. So `scan.py` drops a finding in a merge only when that exact line is already in the same file of one of the merge's other parents. A line no parent has (an evil merge, a conflict resolution) stays. Control cases: `evilCleanMerge` and `evilConflict` are found; `ignoredOnMain`, repeated by the merges, is not.
- **M2, bad range.** Both ends are checked with `git cat-file -e <sha>^{commit}`. The lower bound is `git merge-base`. `scan.py` exits 2 if gitleaks reports no "commits scanned" count, or reports 0 while `git rev-list --count --no-merges` is above 0. I used `--no-merges` because a range of clean merges has no diff to scan. Control cases: an unknown base, and a stub gitleaks that scans 0 commits and exits 0. The stub case runs on Linux and macOS only.
- **M3, fixture coverage.**
  - `TestFixtureCorpus` now requires every `exp.Secrets` entry to match `^(\$\d+\$|-AQ==|0x)?FAKE`. It also requires every token in the redacted output to be `r.Token(s)` of a listed secret, so every value the redactor replaced is listed; the test matches tokens because the redactor exposes no originals. Mutation-checked: dropping a listed secret from the expect file fails, and making one non-FAKE in both files fails.
  - gitleaks rules: the crypt rule gains `$4$` and `$14$`, and its value runs to white space or a quote. `type0-type7` gains type 3 and a 3-character minimum, and `;` no longer ends a secret. The allow-list marker is `\$[0-9]{1,2}\$`, the same as the Go test.
- **L1, self-silencing.** A second PR step scans with the base branch's `.gitleaks.toml` and `.gitleaksignore` from `git show "$BASE_SHA:..."`. It falls back to the PR's own files only when the base has no `.gitleaks.toml`, and uses an empty ignore file when the base has a config but no ignore file. There is no label gate. The design is recorded in `docs/maintainers.md`, "The secret scan and its config": config changes land first in their own PR.
- **L2.** `--ignore-gitleaks-allow` is set. Control line 11 carries `! gitleaks:allow` and must be found.
- **N1.** `control.sh` rejects any `.gitleaksignore` line that is not `^[0-9a-f]{40}:[^:]+:[a-z0-9-]+:[0-9]+$`.
- **N3.** The archive is kept. Before each use, `gitleaks-bin` re-hashes it against the pin and unpacks the binary afresh; a mismatch deletes the archive and fails.
- **Other items.**
  - The `awk -F,` comment is in `control.sh`, which now picks CSV columns by header name.
  - The `conftest.py` false positive keeps one fingerprint per eos-mcp bump (`docs/maintainers.md`, "Judging a finding").
  - `CLAUDE.md` Toolchain facts has the CI-only-tools line, with the same line in `AGENTS.md`.
- **Mutation checks of `control.sh`.** Removing `--diff-merges`, honouring inline allows, and dropping the inherited-line filter each fail it. Dropping the `cat-file` base check does not, because the `merge-base` check still exits 2. Dropping the zero-scan backstop is only caught on Linux or macOS.

### Threat-model rows to apply when PR #194 merges (replaces the round 1 wording)

- **"Secret scanner not in CI":**
  - Status: `Mitigated for the five rule shapes in tests/fixtures/, backed by the redactor-based fixture check (M1-42, PR #198): TestFixtureCorpus fails on a listed fixture secret that does not start with FAKE and on any redacted value the expect file does not list; CI job gitleaks scans each pull request's commits, merge diffs included, and the full history on main. Open, owner test-engineer: a value with FAKE in front of a real secret passes both by construction (review only); a secret in a shape the redactor does not know is outside both; sampled tier 2 output lands with M2 redaction (ADR 0006; PRD section 5)`.
  - Evidence: `internal/redact/redactor_test.go TestFixtureCorpus; .github/workflows/ci.yaml job gitleaks; tools/secrets/scan.py; .gitleaks.toml; .gitleaksignore; tools/secrets/control.sh`.
- **New row, "Secret-scan self-modification by PR"** (L1): `a pull request edits .gitleaks.toml or .gitleaksignore to silence its own finding` | MCP04 | `Mitigated (M1-42): a second scan uses the base branch's config and ignore file. Open, owner maintainer: a pull request can still edit ci.yaml, the Makefile or tools/secrets/, because pull_request workflows run the pull request's files; review those paths as security changes` | `docs/maintainers.md, "The secret scan and its config"`.
- **New row, "GitHub secret scanning and push protection disabled"**: `the repository settings do not run GitHub's own secret scanning or block a push that contains a known credential format` | MCP04 | `Mitigated: secret scanning and push protection enabled by the maintainer 2026-09-25 (checked through the API: secret_scanning and secret_scanning_push_protection enabled). Non-provider patterns still off (secret_scanning_non_provider_patterns disabled): open, owner maintainer` | repository settings (Settings, Code security); none in the repository.
- **New row, "gitleaks not a required status check"**: `the gitleaks job can fail and the pull request still merge` | MCP04 | `Open, owner maintainer: add gitleaks to the main ruleset's required checks` | `.github/workflows/ci.yaml job gitleaks`.
- **MCP04 summary line:** `secret scanner not in CI (fixture shapes mitigated, M1-42; sampled tier 2 output open, M2), secret-scan self-modification (mitigated for config, workflow edits open), GitHub secret scanning and push protection (mitigated 2026-09-25; non-provider patterns open, maintainer), gitleaks not required (open, maintainer)`.

### Reproduce green (round 2)

```sh
go test -count=1 ./internal/redact/
make secrets-control && make secrets-scan                 # full history
make secrets-scan GITLEAKS_BASE=origin/main               # the pull request range
make actionlint && make status-check && make licences-check
```

## Round 3 (re-review of PR #198: R2-M1 and lows)

- **R2-M1, multi-line findings in merges.** `inherited()` in `tools/secrets/scan.py` now drops a merge finding only when the whole matched block, lines `StartLine..EndLine` of the merge's file, appears as consecutive lines in the same file of a non-first parent. No value is compared or kept outside git.
  - New `control.sh` case: `main` adds a PEM block to `keys/control.pem`, ignored by fingerprint. A merge appends a different block to the same file, and it must be found at line 5 in both the full-history and PR-range scans. The key bodies are 96 random bytes made at run time, never committed.
  - Mutation check: going back to StartLine-only comparison fails the control (`private-key keys/control.pem 5` missing).
- **Low, values in test logs.** `TestFixtureCorpus` messages now name `<fixture>.expect.json secrets[i]` or `<fixture>.txt line n`, never the value or the line text.
- **Low, device transcripts.** The new `TestTranscriptSecretsAreFake` runs the redactor over every file under `tests/fixtures/device/transcripts/`. Every replaced value must be a word of the transcript that starts with `FAKE` (after an optional marker), or `<removed>`, the placeholder EOS prints for secrets in `show tech-support`. Mutation check: a non-FAKE SNMP community in `show_running_config.txt` fails it, at line 14 only.
- **Note, CRLF.** The `.gitleaksignore` format check strips `\r` first. Checked with a CRLF copy of the file.
- **A fifth `.gitleaksignore` entry, please check it.** The first round 3 commit (`a10ced9`) wrote the PEM armour lines literally in `control.sh`'s `pem()` helper, with shell code between them, so the private-key rule matched the script. The scan caught it before CI did. The next commit builds the armour lines at run time, and `a10ced9:tools/secrets/control.sh:private-key:136` is ignored with that reason. That commit contains no key.
- **Docs.** `docs/maintainers.md` now says the fallback applies to any base without `.gitleaks.toml`, and that the pull request's control of the scan files is accepted, with the reasons. `test-strategy.md`, the fixture README and `CHANGELOG.md` are updated.

### Threat-model rows, round 3 (replace the round 2 wording of these three rows; the others stand)

- **"Secret scanner not in CI"**, status: `Mitigated for the five rule shapes in tests/fixtures/, backed by the redactor-based fixture checks (TestFixtureCorpus; TestTranscriptSecretsAreFake for the device transcripts), including multi-line findings in merge commits (M1-42, PR #198): CI job gitleaks scans each pull request's commits, merge diffs included, and the full history on main. Open, owner test-engineer: a value with FAKE in front of a real secret passes both by construction (review only); a secret in a shape the redactor does not know is outside both; sampled tier 2 output lands with M2 redaction (ADR 0006; PRD section 5)`.
- **"Secret-scan self-modification by PR"** (L1), status: `Config route closed by the base-config scan (M1-42): a second scan uses the base branch's .gitleaks.toml and .gitleaksignore; the fallback to the pull request's own config applies to any base without .gitleaks.toml. The pull request still controls scan.py, the Makefile, control.sh and ci.yaml. Accepted: no outside code is accepted and push protection is on; a change to those files needs the maintainer's eye` | evidence `docs/maintainers.md, "The secret scan and its config"`.
- **"gitleaks not a required status check"**, status: `Open, owner maintainer, until gitleaks is added to the main ruleset's required checks after PR #198 merges`.
- **MCP04 summary line:** `secret scanner not in CI (fixture shapes mitigated, multi-line merge findings included, M1-42; sampled tier 2 output open, M2), secret-scan self-modification (config route closed; scan files accepted, maintainer review), GitHub secret scanning and push protection (mitigated 2026-09-25; non-provider patterns open, maintainer), gitleaks not required (open, maintainer, after merge)`.
