# Scaffold complete; M0 is yours and it starts with a toolchain bump

- **Task:** M0 — Pass-through proxy (board: `docs/milestones/M0.yaml`)
- **From → To:** joshscott13 (with Claude as lead) → netguard-orchestrator
- **State now:** M0 blocked on B1; all six tasks open, T0.1 unblocked
- **Branch / PR:** `main` at the commit that added `STATUS.md` · no PR
- **Date:** 2026-09-23

## Done

- Five Go packages with tests: `internal/policy`, `internal/classify`, `internal/redact`, `internal/audit`, `internal/inventory`. 25/25 policy cases, six-vendor redaction fixture corpus, hash chain verified.
- CLI: `policy test|eval`, `audit verify|keygen`, `redact`, `inventory import`; `serve` is a stub that exits 2.
- Docs: plan, PRD, architecture, roadmap, 10 ADRs, 8 specs (all reconciled to the code on 2026-09-23), test strategy and 22-case matrix, governance files.
- Agents: 11 specialists and 8 slash commands under `.claude/`; roster in `docs/agents/README.md`.
- Status tracking: this protocol, `docs/milestones/M0.yaml`, `STATUS.md`, `make status`, CI check.
- CI green on `main`: build/vet/test, golangci-lint v2, policy-lint smoke.

## Look at this first

- `docs/milestones/M0.yaml` — T0.1 is the only unblocked task and it is a one-purpose PR: `go 1.25` in `go.mod`, the CI `setup-go` version, the `Dockerfile` builder image, and `github.com/modelcontextprotocol/go-sdk v1.7.x`. Nothing else in that PR.
- `docs/specs/profile-schema.md` section 3 — the planned profile fields that `internal/proxy` will need (`dry_run_param`, `capability_table`); do not add them to `internal/classify` until T0.2 shows which are needed.

## Deliberately unfinished

- `internal/proxy`, `internal/approval`, `internal/safety` do not exist. Their specs do. Do not stub them; create each in its milestone's PR.
- `internal/inventory/netbox.go` is a `Resolver`-satisfying stub with a TODO for M2 (ADR 0007: NetBox is optional).
- `docs/specs/audit-event-schema.md` section 2.1 lists fields the Go struct does not yet carry; they arrive in M4 and the verifier rejects them until then.
- The name NetGuard is a placeholder. No brand assets.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check
golangci-lint run ./...          # v2.1.x; config in .golangci.yaml
python3 tools/status/render.py --check
```

## Decisions made without an ADR

- Strict first-match rule evaluation with no specificity ranking. `docs/PLAN.md` originally said "deny beats hold beats allow at equal specificity"; the code never did that and ADR 0003 plus the policy spec were corrected to match. If you want precedence, that is an ADR superseding 0003.
- `misspell` is configured for UK English with `neighbor` and `flavor` allow-listed because they are vendor CLI keywords and a Go identifier respectively.
- Public key file written 0644 with a `//nolint:gosec` annotation; private keys and audit logs are 0600.

## Questions for the receiver

- Does the Go 1.25 bump also move the GoReleaser builder and the nightly containerlab runner image, or do those follow in T0.6?
- Dependabot has opened a `goccy/go-yaml` 1.18→1.19 PR. Merge it before or after T0.1? (Either is fine; after keeps T0.1's diff minimal.)
