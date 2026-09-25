# M1-16: classifier downgrade and config-read cases, class_source, and the PR #150 multi-line injection fix; review the downgrade rule

- **Task:** M1-16 — Classifier - downgrade and config-read cases from classification sections 5 and 6, class_source on the result, whitespace variants
- **From → To:** policy-engineer → security-reviewer (go-reviewer is the second reviewer)
- **State now:** in review. M1-16 is on the board only on PR #125's branch; this PR does not edit `docs/milestones/`.
- **Branch / PR:** `feat/classify-downgrade-cases` · [PR #152](https://github.com/fathomgate/fathomgate/pull/152)
- **Date:** 2026-09-25

## Done

- `internal/classify/command.go`: the raw command is checked before whitespace is collapsed. Any control byte other than tab, and any non-ASCII byte (NEL, U+2028, U+2029, C1), is `EXEC_ARBITRARY`. This fixes the critical finding from the PR #150 review: `show clock\nconf t\nhostname pwned\nend` and the three other inputs were allowed as `READ_OPERATIONAL`. Leading-dash arguments fail. The blocklist has two parts: a start-anchored one (section 5.3 `bl-config-mode` plus the vendor rows) and an anywhere one that now includes the abbreviations (`conf t`, `wr`, `rel`, `relo`, `copy`, `tclsh`, ...). `monitor` is allowed only as `monitor interface` and `monitor traffic`, and `write-file` is blocked. Config reads are matched by stem (`show run`, `show conf`, `show start`, `show tech`), which is the high finding.
- `internal/classify/normalize.go`: `Result.ClassSource` (`profile`, `fallback`, `downgrade`, `reclassify`; `capability_table` and `annotation_raise` are declared but not emitted). `Reason` names the first failing command (`%q`, 80 bytes) and the check. The `never-downgrade` profile-notes token is honoured. `profiles/junos-mcp-server.yaml` `execute_junos_pfe_command` carries it; before this, `show jnh 0 exceptions` on the PFE shell was downgraded.
- Tests: `classify_test.go` covers every section 9 row except Meraki, exit criterion 3, and one positive and one negative per allow-list, blocklist and config-read entry, plus chaining and injection. `security_test.go` has the PR #150 inputs × 12 line-break variants through 5 free-form tools, plus the flattened forms.
- Docs: `docs/specs/classification.md` sections 2, 3, 4, 5, 6, 8, 9 and 10 now describe the code, and the vendor tables are marked planned. The `never-downgrade` row is in `profile-schema.md`, and CHANGELOG has Security and Added entries.

## Fix round 1 (security and Go reviews of PR #152)

- `never-downgrade` is matched case-insensitively (Go blocker). Test: `Never-Downgrade.` and `NEVER-DOWNGRADE` in `TestNeverDowngrade`.
- Config reads use a two-way prefix test (`isConfigRead`), so `show sys rol 1`, `show tec`, `show ru` and `show derived` are covered, and so are a bare `show`, `get` and `display`. `show system rollback` in full still hits the blocklist and stays `EXEC_ARBITRARY`. **Before test-matrix row 5 (or any Junos row that relies on this) is validated, check on vJunos that `show sys rol 1` is accepted through the `<command>` RPC that junos-mcp-server uses.**
- FortiOS `show` and other vendors' secret-printing operational commands are recorded as looser than the design (classification.md sections 2 and 9, threat model: accepted, open until the vendor reaches `Classify`). The mitigation depends on M2 redaction running for every class.
- `Normalize` trims commands of space and tab only and keeps empty elements. `shellMeta` also refuses `"`, `'`, backslash, `{`, `}` and `$`. Commands over 1024 bytes fail as `too-long`, and `monitor traffic` without `count` fails as `monitor-no-count`.
- `Reason` never quotes input: `command N failed the read allow-list (<check>)` and `tool not in profile`. This answers my earlier question.
- `Source` gains `String`, `ParseSource` and `Sources`, with a round-trip test, and audit-event-schema lists `annotation_raise`. There are four threat-model rows. classification.md lists the accepted false positives (`show debug`, `show system commit`).

## Look at this first

- `classifyCommand` in `internal/classify/command.go`, then `TestDowngradeNeverAccepts` and `security_test.go`.

## Deliberately unfinished

- The per-vendor allow-lists, output-filter pipes (`| json`, `| no-more`), the section 3 fallback classifier and section 7 dry-run are not implemented. The code is stricter in every case except one: FortiOS `show system interface` is `READ_CONFIG`, where the design says `EXEC_ARBITRARY`. The vendor is not known at classify time. Adding it is an interface change.
- The Meraki rows are M1-17 and annotations are M1-18 (ADR 0026). `Classify`'s signature is unchanged.
- There is no upa profile. The tests use a one-tool fixture.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check
go test ./internal/classify/ -run 'Security|MultiLine|Flattened|NeverAccepts|WorkedExamples|ExitCriterion3' -v
bin/fathomgate policy eval --policy policies/examples/read-only.yaml --inventory inventory.example.yaml \
  --profile profiles/netdev-ssh-mcp.yaml --tool run_show_command --arg host=lab-sw-01 \
  --arg command="$(printf 'show clock\nconf t\nhostname pwned\nend')"   # deny, no-exec, control-character
```

## Decisions made without an ADR

- Tab is whitespace. It is horizontal: on a CLI it at most completes the current word, and it cannot start a line. So `show<TAB>running-config` is `READ_CONFIG`. Every other control byte fails.
- Every non-ASCII byte fails the downgrade. This is stricter than listing separators. The cost: an IDN hostname in `ping` is `EXEC_ARBITRARY`.
- `never-downgrade` is a token in free-text `notes`, as section 8 already says. A typed field would be a profile-schema change that needs an ADR.
- `reclassify` also covers a `READ_OPERATIONAL` call that is raised to `EXEC_ARBITRARY` because its command fails.

## Questions for the receiver

- Are the anywhere-blocklist abbreviations (`rel`, `wr`, `copy`) too broad or too narrow now that multi-line input cannot reach them?
- Should `Reason` leave the command out entirely rather than quoting 80 bytes of it, since M1-18 may put `Reason` into agent-facing deny text?
