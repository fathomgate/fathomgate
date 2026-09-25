<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="design/brand/fathomgate-horizontal-tagline-dark.svg">
    <img src="design/brand/fathomgate-horizontal-tagline-light.svg" alt="Fathomgate: safe passage for AI on your network." width="560">
  </picture>
</h1>

<p align="center">
  A safety checkpoint between your AI assistant and your network.<br>
  <a href="ROADMAP.md">Where it's headed</a> · <a href="CONTRIBUTING.md">How to help</a> · <a href="docs/install.md">Install</a>
</p>

AI assistants such as Claude Code and Cursor can now work on routers, switches and firewalls. They do it through small plug-in programs called **MCP servers**: one might log in over SSH and run commands, another might talk to Junos or Arista EOS directly.

That is useful, and it is also risky. The same connection that lets an assistant run `show interfaces` also lets it push a config change to a core router at 3 a.m. Most network MCP servers have few or no guardrails of their own, and the assistant decides for itself what to run.

Fathomgate sits in the middle. The assistant talks to Fathomgate instead of talking to the MCP server directly, and Fathomgate passes each request on only if your rules allow it.

```
  AI assistant              Fathomgate                     Network MCP server       Your devices
  (Claude Code, Cursor) ──▶  checks every request  ──────▶  (e.g. netdev-ssh-mcp) ──▶ routers, switches,
                            · what kind of action?                                     firewalls
                            · which device, and what role does it play?
                            · what do your rules say?
                    ◀────── results come back with passwords and keys masked ◀──────
```

For every request, Fathomgate does one of three things:

- **Allow** it: the request goes through as normal.
- **Hold** it: nothing happens until a person approves it. If no one approves in time, it expires.
- **Deny** it: the assistant gets a clear refusal that names the rule responsible, so it can try something else and you can find the rule.

Every decision is written to an audit log that shows if anyone has edited it.

## What that looks like

With the example policy [`prod-approval.yaml`](policies/examples/prod-approval.yaml):

| The assistant asks to… | Fathomgate sees | Result |
| --- | --- | --- |
| run `show version` on `lab-leaf-01` | a read-only command | **Allowed** by `reads-anywhere` |
| change the config on `lab-leaf-01` | a config change on a lab device | **Allowed** by `lab-writes-free`, with a dry run and a diff first |
| change the config on `core-rtr-01` | a config change on a core router | **Holding** under `prod-core-needs-approval` until someone other than the requester approves it, for up to 15 minutes |
| run a free-form `reload` on `core-rtr-01` | an arbitrary command | **Denied** by `no-exec` |

A few more things happen along the way:

- **Secrets are masked.** If a device replies with a config that contains passwords, SNMP communities or VPN keys, Fathomgate replaces them with tokens before the assistant sees them.
- **The action type comes from what the request actually does, not from the tool's label.** A tool called `run_command` that is sent `show version` counts as a read, and the same tool sent `reload` counts as an arbitrary command. A tool that calls itself "read-only" is not trusted on its word.
- **Unknown devices get a default.** If Fathomgate cannot tell what a device is, your policy's default for unknown targets applies. It never guesses.

## Where it is today

Fathomgate is early. The parts are built and tested on their own, but they are not yet wired together:

| Part | Status |
| --- | --- |
| The rules engine: policy files, decisions, and a trace of why | Done. You can try it today (below) |
| Working out what kind of action a request is (per-server profiles, command inspection) | Done |
| Secret masking for Cisco IOS and NX-OS, Junos, EOS, PAN-OS and FortiOS output | Done |
| Tamper-evident audit log | Done |
| Device lookup from an inventory file, a CSV import or hostname patterns | Done |
| **The checkpoint itself** (`fathomgate serve`) | **Passes every request through unchanged for now.** The rules are wired in during the next milestone, M1 |
| Approvals, dry runs, automatic rollback, a local web console for one operator | Later milestones |
| A team console: single sign-on, roles, many Fathomgate instances in one view | Part of the paid edition |
| Loading a NetBox or Nautobot CSV export | M2, free |
| Live NetBox and Nautobot connectors: lookup as requests arrive, auto-sync, freshness checks | Part of the paid edition |

The full plan is in [ROADMAP.md](ROADMAP.md).

## Try it

You need Go 1.26 or later.

```sh
make build        # builds bin/fathomgate
```

**Ask the rules engine what it would decide.** This needs no network and no devices:

```sh
bin/fathomgate policy eval --policy policies/examples/prod-approval.yaml \
  --inventory inventory.example.yaml --server junos --tool load_and_commit_config \
  --class WRITE_CONFIG --target core-rtr-01
```

```
decision:    hold
class:       WRITE_CONFIG
target:      core-rtr-01 (role core, site dfw1, tags prod,critical)
rule:        prod-core-needs-approval
obligations: dry_run, diff, timed_rollback
approval:    ttl 15m0s, approver must differ: true
trace:
  - default:session.max_devices      1 of 5 devices
  - reads-anywhere                   class WRITE_CONFIG not in [READ_OPERATIONAL READ_CONFIG INVENTORY_READ]
  - lab-writes-free                  target core-rtr-01 tags [prod critical] have none of [lab]
  * prod-core-needs-approval         matched
```

The trace lists every rule Fathomgate checked, top to bottom, and why each one did or did not apply. The first rule that matches decides.

**Put the checkpoint in front of a real MCP server.** In your assistant's MCP settings (`mcp.json`), point it at Fathomgate and tell Fathomgate which server to start behind it:

```jsonc
{
  "mcpServers": {
    "netdev": {
      "command": "/usr/local/bin/fathomgate",
      "args": ["serve", "--server", "netdev-ssh-mcp",
               "--upstream", "/usr/local/bin/netdev-ssh-mcp"]
    }
  }
}
```

The assistant then sees the server's tools with a prefix, such as `netdev-ssh-mcp.run_show_command`, so you can tell which server each tool comes from. Use full paths: desktop apps often start servers without your shell's `PATH`. Point `--upstream` at the server itself (its binary, or the Python interpreter in its virtual environment), not at a launcher such as `uvx`, `npx`, `uv run`, a shell script or `docker run -i`. A server that has not answered within 5 seconds is restarted on the older protocol, and although fathomgate stops the launcher's whole process tree, a server that escapes it (behind `docker run -i`, or detached by its launcher) keeps running when the launcher is stopped ([why](docs/install.md#point---upstream-at-the-server-not-at-a-launcher)). If you must use `uvx` or `npx`, run it once by hand first so it starts fast. For now every request passes straight through (see above).

**Or start it yourself and let assistants connect over HTTP.** Start Fathomgate with `--listen` and a token file that only you can read, one per client, and it serves on this computer only:

```sh
fathomgate serve --listen 127.0.0.1:8931 \
  --listen-token-file claude-code=$HOME/.config/fathomgate/claude-code.token \
  --server netdev-ssh-mcp --upstream /usr/local/bin/netdev-ssh-mcp
```

Copy the URL from the `listening` line it prints. In Claude Code, add the server with a header that names a variable, not the token:

```sh
claude mcp add --transport http netdev http://127.0.0.1:8931/mcp \
  --header 'Authorization: Bearer ${CLAUDE_FATHOMGATE_TOKEN}'
```

Then start Claude Code with the token set for it alone, in one command, so your shell never keeps it:

```sh
CLAUDE_FATHOMGATE_TOKEN="$(cat ~/.config/fathomgate/claude-code.token)" claude
```

Never put the token in a shell startup file or `setx`, where every program you run would inherit it. [docs/install.md](docs/install.md#remote-agents-over-http) shows how to make the token, the Windows commands and the `.mcp.json` form.

Step-by-step setup for Claude Code and Cursor, device credentials, and what to do if the client can't find fathomgate or the server, is in [docs/install.md](docs/install.md).

**Run a policy's test cases:**

```sh
bin/fathomgate policy test policies/examples/prod-approval.test.yaml
```

**Mask the secrets in a device config.** The sample configs contain only fake secrets:

```sh
FATHOMGATE_REDACT_KEY=demo-key bin/fathomgate redact -q tests/fixtures/configs/junos.txt
```

A line such as `encrypted-password "$9$…";` comes back as `encrypted-password "<redacted:hmac:7bc878b4ae5b>";`. The same secret always gives the same token under the same key, so you can still tell that two devices share a password without seeing it.

## Words you will see

| Word | Meaning |
| --- | --- |
| **MCP** | Model Context Protocol, the standard way AI assistants connect to outside tools. |
| **MCP server** or **upstream** | A program that gives an assistant tools, such as "run a show command on a device". Fathomgate runs it behind itself. |
| **Agent** | The AI assistant making requests. |
| **Tool call** | One request from the agent, such as "run `show bgp summary` on `core-rtr-01`". |
| **Class** | The kind of action: `READ_OPERATIONAL`, `READ_CONFIG`, `WRITE_CONFIG`, `EXEC_ARBITRARY`, `INVENTORY_READ`, `LAB_LIFECYCLE`, `LOCAL_ADMIN`. |
| **Policy** | A YAML file of rules. Rules are checked in order, and the first match wins. |
| **Obligation** | Something that must happen with an allowed change, such as `dry_run`, `diff` or `timed_rollback`. |
| **Profile** | A YAML file per MCP server that tells Fathomgate what each of its tools does. See [`profiles/`](profiles/). |
| **Inventory** | Where Fathomgate learns a device's role, site and tags, for example that `core-rtr-01` is a core router in production. |

The full glossary is in [docs/glossary.md](docs/glossary.md).

## Under the hood

The source is public so you can read, build and audit every line that decides what reaches a device.

### How a request is decided

```
tool call ──▶ Normalize  work out the targets, commands and config from the server's profile
          ──▶ Classify   the profile's class, raised or lowered by inspecting the commands
          ──▶ Resolve    the device's role: inventory.yaml (or a CSV import) → hostname patterns; unknown stays unknown
          ──▶ Evaluate   unknown-target default, session caps, then the rules in order; first match wins
          ──▶ allow / hold / deny, each with a rule id and a full trace
```

```yaml
# policies/examples/prod-approval.yaml (excerpt)
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

Policies are data. Test them with `fathomgate policy test`, or lint them with `tools/policy-lint/policy-lint`, which needs no Go toolchain.

### Build and test

```sh
make build        # bin/fathomgate
make test         # go test -race ./...
make policy-test  # every policies/**/*.test.yaml
make fixtures-check
make conformance  # the official MCP conformance suite against fathomgate serve (needs Node.js)
```

Go 1.26 ([ADR 0015](docs/adr/0015-raise-go-floor-to-1-26.md)). Fathomgate ships as a single static binary with three direct dependencies: `github.com/goccy/go-yaml`, the official MCP `github.com/modelcontextprotocol/go-sdk` (v1.8.x, pinned to one minor) and `golang.org/x/sys` (Windows file permissions for the audit key). See [ADR 0011](docs/adr/0011-accept-go-sdk-transitive-modules.md). The Python companion under `tests/` is optional and needs `uv`.

### Layout

```
cmd/fathomgate/        the CLI: version, serve, policy test|eval, audit verify|keygen, redact, inventory import
internal/proxy/        the checkpoint: talks MCP to the agent and to the upstream server, prefixes tool names
internal/classify/     classes, server profiles, working out what a request does
internal/policy/       policy files, Evaluate, test runner
internal/redact/       secret patterns per vendor, keyed tokens
internal/audit/        the tamper-evident log, signing keys, verify
internal/inventory/    device lookup: inventory file, hostname patterns, CSV import, NetBox stub (live connector: paid edition)
profiles/              one YAML per upstream server
policies/examples/     read-only, lab-open, prod-approval and their tests
tests/                 Python companion: policy lint, tiered tests, fixture configs, conformance harness
design/                console and CLI design system
docs/                  plan, ADRs, specs, testing, research
```

### Where to read next

| If you want to | Start at |
| --- | --- |
| Understand the design in five minutes | [ARCHITECTURE.md](ARCHITECTURE.md) |
| See what ships when | [ROADMAP.md](ROADMAP.md) |
| Know why a decision was made | [docs/adr/](docs/adr/README.md) |
| Implement or review an interface | [docs/specs/](docs/specs/) |
| Help through issues: profile requests, secret-masking reports, bugs, ideas | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Work here as a coding agent | [CLAUDE.md](CLAUDE.md), [AGENTS.md](AGENTS.md), [docs/agents/](docs/agents/README.md) |
| See what is in progress | [STATUS.md](STATUS.md) |
| See the console design | [design/DESIGN.md](design/DESIGN.md) |

## Why this exists

As of September 2026 there is no vendor-neutral guardrail for AI assistants that understands networks. General MCP gateways can allow or block a tool by its name or by who is calling, but they do not look inside the request. They cannot tell `show version` from `reload`, or a lab switch from a core router. Individual network MCP servers are adding their own safety features one at a time. Fathomgate is meant to be one checkpoint in front of all of them. Research and sources are in [docs/research/](docs/research/01-mcp-proxy-prior-art.md).

## Licence

Fathomgate is source-available under the [Functional Source License, Version 1.1, ALv2 Future License](LICENSE) (`FSL-1.1-ALv2`). You may read, build, run, modify and redistribute it for any purpose except a Competing Use: offering it, or a product or service with the same or substantially similar function, commercially to others. Running it in front of your own network, at any scale, is allowed. Each version becomes Apache-2.0 two years after it is made available; every commit pushed here counts as a version, and each release's notes give its conversion date. The decision is [ADR 0034](docs/adr/0034-source-available-under-fsl.md).

| Path or version | Licence |
| --- | --- |
| Everything in this repository not listed below | `FSL-1.1-ALv2` ([LICENSE](LICENSE)) |
| [`policies/examples/`](policies/examples/LICENSE) and [`profiles/`](profiles/LICENSE) | Apache-2.0, so you can copy and share policies and profiles freely |
| `v0.1.0`, and every commit before the relicensing | Apache-2.0, for good |

[NOTICE](NOTICE) carries the copyright line, the licence history and the attributions for every module linked into the binary, and [THIRD_PARTY_LICENSES/](THIRD_PARTY_LICENSES/README.md) their full licence texts; both ship in every release archive and image. Fathomgate does not accept code from outside contributors for now; ideas, bugs, profile requests and secret-masking gaps are welcome as issues ([CONTRIBUTING.md](CONTRIBUTING.md)). Neither licence covers the name: a fork must not ship as Fathomgate ([TRADEMARKS.md](TRADEMARKS.md)).

The product was called NetGuard, a placeholder, until [ADR 0019](docs/adr/0019-rename-to-fathomgate.md) renamed it Fathomgate; older ADRs and handoff notes keep the old name.
