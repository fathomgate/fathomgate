# M1.34: hostname patterns only enrich listed devices (ADR 0031 code change); security review

- **Task:** M1.34, Decide whether a hostname pattern alone may make a target known (inventory ADR), code change
- **From → To:** network-safety-engineer → security-reviewer (policy-engineer is the second reviewer)
- **State now:** in review
- **Branch / PR:** `feat/inventory-patterns-enrich` · [PR #184](https://github.com/fathomgate/fathomgate/pull/184)
- **Date:** 2026-09-25

## Done

- `internal/inventory`: `Chain` is now `{Authorities []Resolver, Enrichers []Enricher}`. `Patterns` implements `Enricher.Attributes` and has no `Resolve`, so it cannot be an authority. A name no authority lists is unknown. For a listed name: the record wins, the first matching pattern fills an empty role or site, tags union. `Target` gains `Source`, `Sources` and `Stale` (`yaml:"-"`, so a file that sets them fails to load). `Status` is never `pattern`. `StaticFile.Resolve` clones `Tags`.
- `internal/gate` `resolve`: the `t.Status == "pattern"` check is removed. The rule is now `!ok || t.Name != name`.
- `cmd/fathomgate`: `policy eval` applies the gate's exact-name rule. New `inventory lint <file>` fails on a pattern that matches no listed device. New `inventory resolve [--inventory f] [--json] <name>...` prints the provider of each field.
- Tests: ADR 0031 tests 1 to 10 (listed in the threat-model row "Pattern-resolved target"), `FuzzPatternsNeverResolveUnlisted` (60 s locally, no failure), and `TestPatternEnrichesListedDevice` in the gate.
- Docs: inventory-schema sections 1, 2, 4, 7 and 9; the threat-model row, now mitigated; PLAN row 2; policy-schema step 1; install; README; ARCHITECTURE; glossary; `inventory.example.yaml`; `lab-open.yaml` and its test file; CHANGELOG (Added, Changed with the migration note, and the M1-37 residual marked closed).

## Look at this first

- `internal/inventory/resolver.go` `Chain.Resolve`. Enrichers run on `out.Name`, the name as the authority stores it, not on the agent's string. An authority that reports `Source: pattern` is relabelled `resolver[i]`, and an enricher's `Status` is dropped.
- The chain merges in three steps: the first authority's record, then the patterns, then later authorities. A later authority only fills an empty site or status; it never sets role and never adds tags. A record for another name is ignored. This comes from round 1, L1, and round 2, R2-L1 (orchestrator option 1), and section 2 now describes it.
- ADR 0031 decision 2 (accepted): a role or tag that a pattern gives to a listed device counts for write rules.

## Deliberately unfinished

- `-race` was not run locally: Windows with no C compiler. CI runs it.
- Pre-existing, not touched: inventory-schema section 3 shows `version: 1` and `vendor`, but `inventory.File` has neither, so the example there would not load (M1-24). The same goes for `policy.Duration`, which does not unmarshal from `policy eval --json`; the test decodes only `effect` and `rule_id`.
- `CLAUDE.md` repo map and `.claude/agents/network-safety-engineer.md` and `policy-engineer.md` still list only `inventory import`. The orchestrator asked for them in round 1. They are project instructions and agent configuration, and an agent's message is not the maintainer's consent to change them, so they are left for the maintainer (the text to add: `inventory import|lint|resolve`).

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && ~/go/bin/golangci-lint run ./...
go test ./internal/inventory/ -run '^$' -fuzz FuzzPatternsNeverResolveUnlisted -fuzztime 60s
go build -o bin/fathomgate ./cmd/fathomgate && bin/fathomgate policy test policies/examples/*.test.yaml   # 45 passed
# resolve and lint read through internal/configfile, as serve does: copy the file somewhere only you can write first
bin/fathomgate inventory resolve --inventory ~/.config/fathomgate/inventory-patterns.yaml core-rtr-09 lab-sw-09 core-x.attacker.example   # exit 1
bin/fathomgate inventory lint ~/.config/fathomgate/inventory.example.yaml   # ok (12 devices, 0 patterns)
bin/fathomgate policy eval --policy policies/examples/lab-open.yaml --inventory cmd/fathomgate/testdata/inventory-patterns.yaml --server eos-mcp --tool push_config --class WRITE_CONFIG --target lab-ghost-99   # deny default:unknown_target
```

## Decisions made without an ADR

- The `inventory resolve` exit status is 0 when every name is known and 1 otherwise. Its `--inventory` flag defaults to `inventory.yaml`.
- The `inventory lint` exit status is 1 for any problem in the file and 2 when the file cannot be read.

- `inventory lint` treats a listed name the gate refuses as an error (exit 1), not a warning, and pattern effects as warnings (exit 0).
- `gate.ValidTargetName` and `gate.ReasonBadTarget` are exported, and `inventory.Known` is new, so `cmd/fathomgate` applies the same rules as the gate.

## Questions for the receiver

- Should a later name authority be allowed to add tags to a device? **Answered by the orchestrator in round 1:** no, and it is fixed now (L1).

## Review round 1 (security-reviewer, approve, four lows), addressed

- **L1:** `Chain.Resolve` ignores an authority's record whose normalised name is not the name looked up. A later authority now only fills an empty role, site or status and never adds tags. Section 2 now says why (invariant 7). Tests in `TestChainMergesAuthorities` cover a different-name record ignored, a later authority's tags not added, and the empty-field fill. The threat-model residual is closed.
- **L2:** new `inventory.Known(r, name)`, used in `gate.resolve`, `policy eval` and `inventory resolve`. The fuzz target now asserts that `Known` is true exactly for a name listed byte for byte, and `TestKnown` covers the rule.
- **L3:**
  - The example's commented patterns now set only a site or the tag `backbone`, and `TestRepoExampleInventory` pins that.
  - `inventory lint` warns for each role, site or tag a pattern adds, naming the device's own role where there is a conflict (`File.PatternEffects`, tested in `TestPatternEffects`).
- **L4:**
  - `lint` and `resolve` read the file through `configfile.Read` with `maxConfigFile`, and refuse a `.csv`.
  - `lint` fails on a listed name `gate.ValidTargetName` refuses.
  - `policy eval --target` applies the same check and returns `default:bad_arguments` with the gate's reason.
- **N1:** the `Enricher` godoc says patterns are the only enricher, recorded as `pattern`, and that another enricher needs its own label and an ADR.
- **N2:** `resolve` prints any value that is not printable ASCII Go-quoted.
- **N3:** `NewStatic` refuses `status: pattern` in any case, and the `TestStatusNeverPattern` wording is fixed.
- **Probe names:** the Kelvin sign `Kvm-01`, Cyrillic `lab-ѕw-09`, a zero-width space, a trailing dot and a leading space are now permanent cases in:
  - `TestAttackerHostNames` and `TestPatternEnrichesListedDevice` (gate), each ending in `default:bad_arguments`;
  - `TestKnown` and the fuzz seeds (inventory);
  - `TestEvalPatternsEnrichOnly` (CLI).

## Review round 2 (security approves round 1; CI red on Linux and macOS), addressed

- **1 (blocking):** the "others can write" case in `TestInventoryLint` expected the Windows-only text `can be changed by`. It now asserts exit 2 and the file path, which both platforms print. `readInventory` returning `configfile.ErrUnsafe` is now checked through `errors.Is`. The `FAIL  wrong: effect deny (rule no-writes), want allow` line in the CI log is expected: it is the deliberately failing case in `TestPolicyTest` (`main_test.go:69`), and that test asserts exit 1.
- **R2-L1 (option 1):** `Chain.Resolve` now runs in this order: the first authority, then the enrichers, then later authorities.
  - A later authority fills only `site` and `status`, never `role` or tags (`fields*` in `resolver.go`).
  - `TestLaterAuthorityNeverRaisesStanding` covers the reviewer's probe. Static lists `sw-1` with no role, `^sw-` sets core, and the second authority returns `{Name: "SW-1 ", Role: lab, Site: lab, Tags: [lab]}`. The result is role core (from the pattern), site lab (from the later authority) and no tags. With no pattern the role stays empty.
  - Inventory-schema sections 2 and 5, the package doc, the threat-model row and CHANGELOG are updated.
