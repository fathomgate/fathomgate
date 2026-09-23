# NetGuard (working name)

A policy-enforcing MCP proxy that sits between AI agents and network-device MCP servers. It classifies every tool call by network semantics, resolves the target device's role from a static inventory, hostname patterns or NetBox/Nautobot, evaluates a YAML policy, and forwards, denies, or holds the call for human approval. Every result passes through a secret redactor and lands in a hash-chained audit log.

```jsonc
// mcp.json — the proxy in front of a real server (once M0 ships the transport)
{
  "mcpServers": {
    "netdev": {
      "command": "netguard",
      "args": ["serve", "--policy", "policies/examples/read-only.yaml",
               "--inventory", "inventory.yaml", "--upstream", "netdev-ssh-mcp"]
    }
  }
}
```

## Status

The building blocks are done and tested; the proxy transport is not. See [ROADMAP.md](ROADMAP.md).

| Piece | Package | Try it |
| --- | --- | --- |
| Policy DSL, `Evaluate`, trace, `*.test.yaml` runner | `internal/policy` | `netguard policy test policies/examples/prod-approval.test.yaml` |
| Tool classes, per-server profiles, argument normaliser, fallback command classifier | `internal/classify` | `netguard policy eval --policy … --profile profiles/eos-mcp.yaml --tool run_command --arg hostname=lab-leaf-01 --arg "command=show version"` |
| Vendor secret patterns, keyed HMAC tokens, fixture corpus | `internal/redact` | `netguard redact --key-file k tests/fixtures/configs/junos.txt` |
| Hash-chained JSONL, Ed25519 checkpoints, verify | `internal/audit` | `netguard audit keygen && netguard audit verify audit.jsonl --key audit.key.pub` |
| Resolver chain: static file, hostname patterns, CSV import, NetBox stub | `internal/inventory` | `netguard inventory import --csv devices.csv --out inventory.yaml` |
| Proxy transport (M0) | `internal/proxy` | `netguard serve` prints why it is not here yet: the official go-sdk v1.7 needs Go 1.25 |

## Build

```sh
make build        # bin/netguard
make test         # go test -race ./...
make policy-test  # every policies/**/*.test.yaml through netguard policy test
make fixtures-check
```

Go 1.25. Direct dependencies: `github.com/goccy/go-yaml` and the official MCP `github.com/modelcontextprotocol/go-sdk` (v1.7.x, pinned for the M0 proxy). The Python companion under `tests/` needs `uv` and is optional.

## How a call is decided

```
tools/call ──▶ Normalize (targets, commands, config payload from the server profile)
           ──▶ Classify  (profile class, downgraded/escalated by inspecting commands)
           ──▶ Resolve   (inventory.yaml → hostname patterns → NetBox; unknown stays unknown)
           ──▶ Evaluate  (defaults.unknown_target, session caps, rules in order, first match wins)
           ──▶ allow / hold / deny, each with a rule id and a full trace
```

```yaml
# policies/examples/prod-approval.yaml
rules:
  - id: reads-anywhere
    match: { class: [READ_OPERATIONAL, READ_CONFIG, INVENTORY_READ] }
    effect: allow
  - id: lab-writes-free
    match: { class: [WRITE_CONFIG], device_tags: [lab] }
    effect: allow
    obligations: [dry_run, diff]
  - id: prod-core-needs-approval
    match: { class: [WRITE_CONFIG], device_roles: [core, border] }
    effect: hold
    approval: { ttl: 15m, approver_must_differ: true }
```

Every denial names its rule. Policies are data; test them with `netguard policy test` and lint them with `tools/policy-lint/policy-lint` without a Go toolchain.

## Layout

```
cmd/netguard/          CLI: version, serve (stub), policy test|eval, audit verify|keygen, redact, inventory import
internal/classify/     Class enum, profiles, Normalize, ClassifyCommand
internal/policy/       Policy types, Load/Parse/Validate, Evaluate, RunTestFile
internal/redact/       Rules, Redactor, HMAC tokens
internal/audit/        Event, canonical JSON, Writer, Verify, keys
internal/inventory/    Resolver, StaticFile, Patterns, Chain, ImportCSV, NetBox stub
profiles/              one YAML per upstream server (tool → class, param mapping)
policies/examples/     read-only, lab-open, prod-approval and their *.test.yaml
tests/                 Python companion: policy_lint, tiered pytest, fixtures/configs
tools/policy-lint/     launcher for tests/policy_lint
design/                Fathom tokens + the NetGuard policy layer + console preview
docs/                  PLAN, PRD, adr/ (10 ADRs), specs/ (8 normative specs), testing/, agents/, research/
.claude/               11 specialist agents + 8 slash commands that run the build pipeline
STATUS.md              rendered board for the current milestone (docs/milestones/, docs/handoffs/)
```

## Reading order

| If you want to | Start at |
| --- | --- |
| Understand the design in five minutes | [ARCHITECTURE.md](ARCHITECTURE.md) |
| See what ships when | [ROADMAP.md](ROADMAP.md) |
| Know why a decision was made | [docs/adr/](docs/adr/README.md) |
| Implement or review an interface | [docs/specs/](docs/specs/) |
| Contribute a server profile, policy or redaction pattern without Go | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Work here as a coding agent | [CLAUDE.md](CLAUDE.md), [AGENTS.md](AGENTS.md), [docs/agents/](docs/agents/README.md) |
| See what is in flight and who has it | [STATUS.md](STATUS.md), then [docs/handoffs/](docs/handoffs/README.md) |
| See the console design | [design/DESIGN.md](design/DESIGN.md) and `design/preview.html` |
| Read the research this was built on | [docs/research/](docs/research/) |

## Status of the ecosystem this sits in

As of September 2026 no vendor-agnostic, network-aware guardrail proxy for MCP exists. Generic MCP gateways enforce policy on tool names and caller identity but cannot see arguments; safety features for network servers are being added to individual servers one pull request at a time. NetGuard is the layer in front of all of them. Details and citations are in [docs/research/01-mcp-proxy-prior-art.md](docs/research/01-mcp-proxy-prior-art.md).

## Licence

MIT. NetGuard is a placeholder name; it will change before the first release.
