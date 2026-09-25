# Roadmap

**Safe passage for AI on your network.**

AI assistants can already log in to routers, read configs and push changes. That is going to be one of the most useful things to happen to network operations in years, and one of the riskiest. Today the only thing standing between an assistant and `reload` on a core router is whatever guardrails each MCP server's author thought to add, and most added none.

Fathomgate is the missing layer. It sits between the assistant and every network MCP server you run, reads each request before it reaches a device, and decides: **allow** it, **hold** it for a person to approve, or **deny** it with the rule that said no. It masks secrets on the way back and keeps a record of every decision that shows if anyone has edited it.

We want a future where connecting an AI assistant to a production network is as ordinary, and as safe, as giving a new engineer read-only access on their first day and change access once they've earned it.

## What we believe

- **Guardrails belong in one place, not in every tool.** You shouldn't have to wait for twenty MCP servers to each add a read-only mode. Put Fathomgate in front of them all and write your rules once.
- **Nothing reaches a device that your rules didn't allow.** When Fathomgate isn't sure what a request does, it treats it as risky, not safe.
- **People stay in the loop for the changes that matter.** Reads flow freely. Config changes on production gear wait for a human, show them the diff first, and can roll themselves back.
- **Every decision can be explained and proved.** Each refusal names its rule. The audit log is chained so an edited line gives itself away.
- **The parts that keep you safe are open, and stay open.** Everything that decides what's allowed, or proves what happened, is Apache-2.0 and always will be. You can read it, audit it and run it yourself.

## The journey

Each stage ships something you can use, and each is tested against real network MCP servers before the next one starts. Most of the building blocks for later stages (the policy language, command classification, secret masking, the audit chain, device inventory) already exist in the tree and are waiting to be wired in.

### 1. Pass-through (M0) — *nearly there*

Fathomgate sits between Claude Code, Cursor or any other MCP client and a network MCP server, and forwards everything faithfully. It speaks both generations of the MCP protocol, the older one where connections keep state and the 2026 one where they don't, and passes the official MCP conformance suite, with every known gap written down and tracked. Tested against [netdev-ssh-mcp](https://github.com/krisiasty/netdev-ssh-mcp) and [mcp-netmiko-server](https://github.com/upa/mcp-netmiko-server).

Left to do: an HTTP listener so remote agents can connect, and the first tagged release with binaries for Linux, macOS and Windows.

### 2. Say no (M1) — *next*

Your rules start to count. Fathomgate works out what each request really does (a read, a config change, an arbitrary command), which device it touches and what role that device plays, then allows or denies it. A denial tells the assistant which rule refused it, so the assistant can try something safer.

**This is the stage where Fathomgate becomes useful on its own:** a proxy that lets an assistant look at everything and stops `reload` from ever reaching a device. We'll announce it here.

### 3. Know your network (M2)

Fathomgate learns device roles from wherever you keep them: a spreadsheet, a naming convention, the MCP server's own inventory, or NetBox and Nautobot. Passwords, keys and SNMP communities are masked in everything that comes back. And if an MCP server quietly changes what its tools claim to do, Fathomgate notices and stops trusting it.

### 4. Ask first (M3)

The heart of it. A config change on a production device is held. For every held request, the command line shows the diff, the rule trace and the rule that held it, so the person deciding sees exactly what would change and why. They approve or deny it from the command line or a webhook, and the change runs once. If the device's config changed in the meantime, it doesn't run at all. Changes can be applied with a timer that rolls them back unless someone confirms. First for Junos and Arista EOS.

### 5. Prove it (M4)

Every decision lands in a tamper-evident audit log that you can verify and hand to an auditor. The log is standard JSON, one line per event, so any log shipper can forward it to your SIEM. Limits on how much an assistant can touch at once: no more than N devices per session, a canary device first, changes only in maintenance windows.

### 6. See it (M5)

A console in your browser, served by Fathomgate itself on your own machine. Watch what assistants are doing as it happens, open each held request to see its diff, its rule trace and the rule that held it, approve or deny it, and check that your audit log still verifies. It's off until you turn it on, it only listens on your own machine, and it needs no accounts. An approval there counts the same as one from your command line, so a rule that needs a second person still needs one.

Safe-change drivers with automatic rollback for Cisco IOS-XE and NX-OS, Palo Alto PAN-OS and Fortinet FortiOS. Where a platform can't roll a change back on its own timer, Fathomgate keeps the timer: if nobody confirms the change in time, it rolls it back. And if your team already writes policy in OPA, you can use it as the policy engine, with the same allow, hold and deny.

For teams, the paid edition will add a team console: single sign-on, roles, approvals that need more than one person, one view across many Fathomgate instances, central policy, long-term search of the audit log, and ready-made OCSF and CEF exporters for your SIEM.

## Beyond

- **Every network MCP server, profiled.** A shared library that tells Fathomgate what each tool of each server really does. Anyone can contribute one.
- **Policy packs you can drop in:** read-only everywhere, change freeze, lab-open and production-closed, follow-the-sun approvals.
- **More vendors and more ways to change safely**, starting with the platforms the community runs.
- **A standard shape for AI safety on networks** that MCP server authors can point to, instead of each building their own.

## Come build it with us

You don't need to know Go to make a real difference.

- **Profile an MCP server you use.** Tell Fathomgate what each of its tools does. There's an [issue template](.github/ISSUE_TEMPLATE/upstream_server_profile.yml) for it, and it's the single most valuable thing you can give the project.
- **Found a secret that wasn't masked?** Report it with the [redaction gap template](.github/ISSUE_TEMPLATE/redaction_gap.yml), with fake values please. Every vendor's config dialect has corners we haven't seen.
- **Write a policy for how your team actually works** and share it in `policies/examples/`.
- **Try it in your lab** (containerlab is perfect for this) and tell us what broke or what surprised you.
- **Improve the docs.** If something here confused you, it will confuse the next person too.

Start with [CONTRIBUTING.md](CONTRIBUTING.md). Contributions are under Apache-2.0 with a DCO sign-off (`git commit -s`), and everyone is expected to follow the [Code of Conduct](CODE_OF_CONDUCT.md).

## Open source, and how it's funded

The core of Fathomgate (the proxy, the policy engine, classification, secret masking, approvals from the command line and the local console, the safe-change drivers and the audit log) is open source under Apache-2.0. The paid edition that funds the work is for teams: the team console, with single sign-on, roles, approvals by more than one person, a view across many Fathomgate instances, central policy, long-term retention and search, and ready-made OCSF and CEF exporters for SIEMs. The team console shows nothing about a request that you can't get from the open command line and the local console. The rule we hold ourselves to: **anything that decides what's allowed, or proves what happened, stays open.** The reasoning is in [ADR 0020](docs/adr/0020-open-core-apache-2.md).

## For the details

- What's happening this week: [STATUS.md](STATUS.md)
- The full plan, with exit criteria for every stage and the real servers each is tested against: [docs/PLAN.md](docs/PLAN.md)
- Why things were decided the way they were: [docs/adr/](docs/adr/README.md)
- Questions we haven't answered yet: [docs/PLAN.md](docs/PLAN.md#open-questions-and-risks)
