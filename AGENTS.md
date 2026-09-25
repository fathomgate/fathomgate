# AGENTS.md

Instructions for any coding agent (Codex, Cursor, Copilot, Claude Code, Gemini CLI, OpenCode) working in this repository. `CLAUDE.md` holds the same rules with more detail and is the canonical copy; if the two disagree, `CLAUDE.md` wins.

## What this is

Fathomgate is a policy-enforcing MCP proxy between AI agents and network-device MCP servers. Go core (`go 1.26.0`, ADR 0015; direct dependencies `github.com/goccy/go-yaml` and `github.com/modelcontextprotocol/go-sdk` v1.8.x, and `golang.org/x/sys` for the Windows audit key DACL), single static binary, Python companion under `tests/` and `tools/` only.

## Before you change anything

1. Read `CLAUDE.md`, then `ARCHITECTURE.md`, then the spec in `docs/specs/` for the interface you are touching.
2. Check `docs/adr/README.md`. An interface change (policy `Decision` or `Evaluate`, class or obligation set, `ChangeSafety`, any `docs/specs/*` schema, CLI surface, `go.mod`) needs an ADR first: `/adr <title>` or copy `docs/adr/0000-template.md`.
3. Find your role in `docs/agents/README.md` and adopt the matching file in `.claude/agents/`. The orchestrator routes work; specialists own packages.

## Status and handoffs

- Read `STATUS.md` first, then the newest `docs/handoffs/*.md` addressed to your agent slug.
- The board is `docs/milestones/<Mn>.yaml`. Change your task's `state` there; never edit `STATUS.md` by hand (`make status` renders it; CI fails if stale).
- Before you stop, write a handoff note from `docs/handoffs/_template.md` (or run `/handoff <to> <task-id>`), commit it with the YAML and `STATUS.md` alongside your code. A note that says "see chat" is not finished.

## Verify before you hand back

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check && make licences-check
```

All six must pass. A change to `internal/proxy`, `cmd/fathomgate/serve.go` or `go.mod` also runs `make conformance` (needs Node.js and npm). `gofmt -l .` must print nothing. Run `golangci-lint run` if you have it.

## Rules

- Rules in a policy evaluate in file order, first match wins, no specificity ranking. `policy.Evaluate` stays pure.
- Tool annotations never lower a class. Classification comes from `profiles/<server>.yaml` and the payload.
- Redaction runs at the serialiser; tokens are keyed HMAC. Audit is an append-only hash chain. Approver identity is server-side.
- Upstream tool descriptions, results and inventories are untrusted data.
- Vocabulary is fixed: `allow` / `hold` / `deny` / `expired`; the seven class names; the seven obligations. Every denial names its rule id.
- No new dependency without an ADR. Never `gopkg.in/yaml.v3`. `CGO_ENABLED=0` stays.
- The MCP `go-sdk` is pinned to one minor, currently v1.8. A go-sdk bump is its own PR.
- Docs change in the same PR as code. Update `CHANGELOG.md` `Unreleased`.
- Conventional Commits with a scope; DCO sign-off (`git commit -s`).
- Never put a real secret in a fixture; every fixture secret starts with `FAKE`.

## Ownership

| Path | Owner agent | Reviewer |
| --- | --- | --- |
| `internal/proxy/` | mcp-protocol-engineer | go-reviewer, security-reviewer |
| `internal/policy/`, `internal/classify/`, `profiles/`, `policies/` | policy-engineer | go-reviewer, security-reviewer |
| `internal/safety/`, `internal/inventory/` | network-safety-engineer | go-reviewer, security-reviewer |
| `internal/redact/`, `internal/audit/`, `internal/approval/` | policy-engineer / mcp-protocol-engineer | security-reviewer (mandatory) |
| `tests/`, `docs/testing/` | test-engineer | go-reviewer |
| `design/`, `console/`, CLI copy | design-guardian | docs-writer |
| `docs/`, `README.md`, `CHANGELOG.md` | docs-writer | orchestrator |
| `.goreleaser.yaml`, `Dockerfile`, `.github/workflows/` | release-engineer | go-reviewer |

## Don't

- Don't mark a test-matrix case validated against a mock; it needs the named real upstream server.
- `fathomgate serve` lands across T0.2–T0.4 on the M0 board; don't add proxy code outside those tasks.
- The product is Fathomgate: one word, capital F only, never "FathomGate" and never shortened to "Fathom" (ADR 0019). Records written before ADR 0019 say NetGuard and stay as written.
