<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="design/brand/fathomgate-horizontal-tagline-dark.svg">
    <img src="design/brand/fathomgate-horizontal-tagline-light.svg" alt="Fathomgate: safe passage for AI on your network." width="560">
  </picture>
</h1>

<p align="center">
  Building a network-aware policy checkpoint between AI assistants and network-device MCP servers.<br>
  <a href="ROADMAP.md">Where it's headed</a> · <a href="CONTRIBUTING.md">How to help</a> · <a href="docs/install.md">Install</a>
</p>

> **Current release: [v0.1.0](https://github.com/fathomgate/fathomgate/releases/tag/v0.1.0), a pass-through preview for lab evaluation.** Live tool calls are forwarded without policy enforcement, approvals, secret masking or decision audit logging. The standalone policy evaluator and redaction tools work today. Use read-only device credentials in your lab.

AI assistants such as Claude Code and Cursor can now work on routers, switches and firewalls. They do it through small plug-in programs called **MCP servers**: one might log in over SSH and run commands, another might talk to Junos or Arista EOS directly.

That is useful, and it is also risky. The same connection that lets an assistant run `show interfaces` also lets it push a config change to a core router at 3 a.m. The controls available depend on the MCP server and the device account's permissions. A shared policy layer can add network-specific decisions across those tools.

Fathomgate sits in the middle. Today it forwards tool calls; the planned enforcement pipeline below will check each call against your policy before forwarding it. See [the roadmap](ROADMAP.md) for when each stage arrives.

## Planned workflow

```
  AI assistant              Fathomgate                     Network MCP server       Your devices
  (Claude Code, Cursor) ──▶  checks every request  ──────▶  (e.g. netdev-ssh-mcp) ──▶ routers, switches,
                            · what kind of action?                                     firewalls
                            · which device, and what role does it play?
                            · what do your rules say?
                    ◀────── results come back with passwords and keys masked ◀──────
```

The planned pipeline will make one of three decisions for each request:

- **Allow** it: the request goes through as normal.
- **Hold** it: nothing happens until a person approves it. If no one approves in time, it expires.
- **Deny** it: the assistant gets a clear refusal that names the rule responsible, so it can try something else and you can find the rule.

Decision audit logging is planned for M4; it will make edits to the log detectable.

## Planned policy behavior

These examples describe the intended live workflow, including approvals and obligations from later milestones. The standalone evaluator can report the decision today, but does not execute a call or enforce its obligations. With the example policy [`prod-approval.yaml`](policies/examples/prod-approval.yaml):

| The assistant asks to… | Fathomgate sees | Result |
| --- | --- | --- |
| run `show version` on `lab-leaf-01` | a read-only command | **Allowed** by `reads-anywhere` |
| change the config on `lab-leaf-01` | a config change on a lab device | **Allowed** by `lab-writes-free`, with a dry run and a diff first |
| change the config on `core-rtr-01` | a config change on a core router | **Holding** under `prod-core-needs-approval` until someone other than the requester approves it, for up to 15 minutes |
| run a free-form `reload` on `core-rtr-01` | an arbitrary command | **Denied** by `no-exec` |

The planned pipeline also includes:

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
| Device lookup from an inventory file or hostname patterns (NetBox is optional and comes later) | Done |
| **The checkpoint itself** (`fathomgate serve`) | **Passes every request through unchanged for now.** The rules are wired in during the next milestone, M1 |
| Approvals, dry runs, automatic rollback, a local web console for one operator | Later milestones |
| A team console: single sign-on, roles, many Fathomgate instances in one view | Part of the paid edition |

The full plan is in [ROADMAP.md](ROADMAP.md).

## Try it

[Download v0.1.0 for Linux, macOS or Windows](https://github.com/fathomgate/fathomgate/releases/tag/v0.1.0) and follow the [signature and checksum verification steps](docs/install.md#what-you-need). Extract the full archive, which includes the example policies and inventory, and open a terminal in that directory. No Go toolchain is needed.

The commands below use `./fathomgate` (`.\fathomgate.exe` in PowerShell). To build from source instead, use Go 1.26 or later and `make build`, then substitute `bin/fathomgate`.

**Ask the rules engine what it would decide.** This needs no network and no devices:

```sh
./fathomgate policy eval --policy policies/examples/prod-approval.yaml \
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

The trace lists every rule Fathomgate checked, top to bottom, and why each one did or did not apply. The first rule that matches decides. Here, `hold` is an evaluation result: no device is contacted and no live approval is created.

## More standalone tools

From a source checkout, build with `make build` before trying the redaction fixture below; test fixtures are not included in the release archive.

**Run a policy's test cases** from the extracted release directory:

```sh
./fathomgate policy test policies/examples/prod-approval.test.yaml
```

**Mask the secrets in a device config.** The sample configs contain only fake secrets:

```sh
FATHOMGATE_REDACT_KEY=demo-key bin/fathomgate redact -q tests/fixtures/configs/junos.txt
```

A line such as `encrypted-password "$9$…";` comes back as `encrypted-password "<redacted:hmac:7bc878b4ae5b>";`. The same secret always gives the same token under the same key, so you can still tell that two devices share a password without seeing it.

## Connect a lab MCP server

These optional setups exercise the pass-through proxy. They do not add policy enforcement or secret masking.

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

## For contributors

### How a request is decided

```
tool call ──▶ Normalize  work out the targets, commands and config from the server's profile
          ──▶ Classify   the profile's class, raised or lowered by inspecting the commands
          ──▶ Resolve    the device's role: inventory.yaml → hostname patterns → NetBox; unknown stays unknown
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
internal/inventory/    device lookup: inventory file, hostname patterns, CSV import, NetBox stub
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
| Help without writing Go: profiles, policies, secret-masking reports, docs | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Work here as a coding agent | [CLAUDE.md](CLAUDE.md), [AGENTS.md](AGENTS.md), [docs/agents/](docs/agents/README.md) |
| See what is in progress | [STATUS.md](STATUS.md) |
| See the console design | [design/DESIGN.md](design/DESIGN.md) |

## Why this exists

Fathomgate focuses on network-specific policy: what command will run, which device it targets, and that device's operational role. The goal is a shared checkpoint across network MCP servers, complementing their own controls and the device account's permissions. General MCP gateways can provide authentication, routing and other controls alongside it. The project's research and sources are in [docs/research/](docs/research/01-mcp-proxy-prior-art.md).

## Licence

Apache License 2.0, see [LICENSE](LICENSE) and [ADR 0020](docs/adr/0020-open-core-apache-2.md). [NOTICE](NOTICE) carries the copyright line and the attributions for every module linked into the binary, and [THIRD_PARTY_LICENSES/](THIRD_PARTY_LICENSES/README.md) their full licence texts; both ship in every release archive and image. Contributions are accepted under Apache-2.0 by DCO sign-off, with no CLA ([CONTRIBUTING.md](CONTRIBUTING.md#licence-of-contributions)). The licence covers the code, not the name: a fork must not ship as Fathomgate ([TRADEMARKS.md](TRADEMARKS.md)).

The product was called NetGuard, a placeholder, until [ADR 0019](docs/adr/0019-rename-to-fathomgate.md) renamed it Fathomgate; older ADRs and handoff notes keep the old name.
