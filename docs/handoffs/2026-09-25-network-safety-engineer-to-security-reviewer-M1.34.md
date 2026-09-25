# M1.34: hostname patterns only enrich listed devices (ADR 0031 code change); security review

- **Task:** M1.34, Decide whether a hostname pattern alone may make a target known (inventory ADR), code change
- **From → To:** network-safety-engineer → security-reviewer (policy-engineer is the second reviewer)
- **State now:** in review
- **Branch / PR:** `feat/inventory-patterns-enrich` · PR linked from the board once opened
- **Date:** 2026-09-25

## Done

- `internal/inventory`: `Chain` is now `{Authorities []Resolver, Enrichers []Enricher}`. `Patterns` implements `Enricher.Attributes` and has no `Resolve`, so it cannot be an authority. A name no authority lists is unknown. For a listed name: the record wins, the first matching pattern fills an empty role or site, tags union. `Target` gains `Source`, `Sources` and `Stale` (`yaml:"-"`, so a file that sets them fails to load). `Status` is never `pattern`. `StaticFile.Resolve` clones `Tags`.
- `internal/gate` `resolve`: the `t.Status == "pattern"` check is removed. The rule is now `!ok || t.Name != name`.
- `cmd/fathomgate`: `policy eval` applies the gate's exact-name rule. New `inventory lint <file>` fails on a pattern that matches no listed device. New `inventory resolve [--inventory f] [--json] <name>...` prints the provider of each field.
- Tests: ADR 0031 tests 1 to 10 (listed in the threat-model row "Pattern-resolved target"), `FuzzPatternsNeverResolveUnlisted` (60 s locally, no failure), and `TestPatternEnrichesListedDevice` in the gate.
- Docs: inventory-schema sections 1, 2, 4, 7 and 9; the threat-model row, now mitigated; PLAN row 2; policy-schema step 1; install; README; ARCHITECTURE; glossary; `inventory.example.yaml`; `lab-open.yaml` and its test file; CHANGELOG (Added, Changed with the migration note, and the M1-37 residual marked closed).

## Look at this first

- `internal/inventory/resolver.go` `Chain.Resolve`. Enrichers run on `out.Name`, the name as the authority stores it, not on the agent's string. An authority that reports `Source: pattern` is relabelled `resolver[i]`, and an enricher's `Status` is dropped.
- A later authority may add tags to a listed device. Section 2 says so, and it is the merge the brief asked for. In M1 there is only one authority, so nothing changes today. Once M2 adds the upstream provider, an upstream (untrusted data, invariant 7) could add `lab` to a device the static file lists. The M2 upstream-provider ADR must decide whether that is allowed. The threat-model row records this as an open residual.
- ADR 0031 decision 2 (accepted): a role or tag that a pattern gives to a listed device counts for write rules.

## Deliberately unfinished

- `-race` was not run locally: Windows with no C compiler. CI runs it.
- Pre-existing, not touched: inventory-schema section 3 shows `version: 1` and `vendor`, but `inventory.File` has neither, so the example there would not load (M1-24). The same goes for `policy.Duration`, which does not unmarshal from `policy eval --json`; the test decodes only `effect` and `rule_id`.
- `CLAUDE.md` repo map and `.claude/agents/*.md` still list only `inventory import`. They were left for the maintainer.

## Reproduce green

```sh
go build ./... && go vet ./... && go test ./... && ~/go/bin/golangci-lint run ./...
go test ./internal/inventory/ -run '^$' -fuzz FuzzPatternsNeverResolveUnlisted -fuzztime 60s
go build -o bin/fathomgate ./cmd/fathomgate && bin/fathomgate policy test policies/examples/*.test.yaml   # 45 passed
bin/fathomgate inventory resolve --inventory cmd/fathomgate/testdata/inventory-patterns.yaml core-rtr-09 lab-sw-09 core-x.attacker.example   # exit 1
bin/fathomgate inventory lint inventory.example.yaml   # ok (12 devices, 0 patterns)
bin/fathomgate policy eval --policy policies/examples/lab-open.yaml --inventory cmd/fathomgate/testdata/inventory-patterns.yaml --server eos-mcp --tool push_config --class WRITE_CONFIG --target lab-ghost-99   # deny default:unknown_target
```

## Decisions made without an ADR

- The `inventory resolve` exit status is 0 when every name is known and 1 otherwise. Its `--inventory` flag defaults to `inventory.yaml`.
- The `inventory lint` exit status is 1 for any problem in the file and 2 when the file cannot be read.

## Questions for the receiver

- Should a later name authority be allowed to add tags to a device, or should it fill empty fields only? This matters from M2 on. As built, the section 2 merge lets it add tags.
