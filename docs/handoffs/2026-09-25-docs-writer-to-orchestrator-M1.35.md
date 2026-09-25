# Clarify the public preview and reporting routes

- **Task:** M1-35 — Clarify the public preview, reporting contacts and release guidance
- **From → To:** docs-writer → orchestrator
- **State now:** in review
- **Branch / PR:** `codex/public-facing-clarity` · [PR #163](https://github.com/fathomgate/fathomgate/pull/163)
- **Date:** 2026-09-25

## Done

- README leads with v0.1.0 pass-through limits, labels future behavior, leads with verified binary downloads and separates offline evaluation from live enforcement.
- Architecture, roadmap and contributor copy distinguish shipped tools from planned protections; broad claims about other projects removed.
- Security and conduct reporting use the maintainer-supplied address; governance matches M0 versioning, actual release assets and GitHub Releases announcements.
- GitHub description, topics and homepage updated. Private vulnerability reporting verified enabled.

## Look at this first

- README opening and quickstart: evaluation can return hold without creating a live approval.

## Deliberately unfinished

- The separate ten-minute lab walkthrough remains issue #103.

## Reproduce green

- Windows: `go build ./...`, `go vet ./...`, `golangci-lint run` (0 issues), `gofmt -l .` (empty).
- Ubuntu WSL with Go 1.26.8: `go test -race ./...`; `make policy-test fixtures-check licences-check PYTHON=python3`. All passed; 45 policy cases.
- `make status-check PYTHON=python3`, `git diff --check`, changed-document local link targets and contact-placeholder check.
- README policy evaluation returned the documented hold, rule, obligations and trace.
- Conformance not required: no proxy, serve or dependency changes.

## Decisions made without an ADR

- Documentation and repository metadata only; no CLI, schema, dependency or policy interface changes.

## Questions for the receiver

- Review public wording and merge after checks pass.
