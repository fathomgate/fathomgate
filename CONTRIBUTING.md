# Contributing to Fathomgate

Thanks for being here. Fathomgate keeps AI assistants safe on real networks, and the people who know those networks best are the ones running them. For now, the way to help is through issues: **Fathomgate does not accept code from outside contributors.** You tell us what you found or need, and the maintainer writes the code.

Why: Fathomgate is source-available under the [Functional Source License](LICENSE) and funded by a paid edition. Taking in outside code would need a contributor agreement first, and there isn't one yet. The decision and the path to accepting code later are in [ADR 0034](docs/adr/0034-source-available-under-fsl.md).

New to the project? Read the [roadmap](ROADMAP.md) for where it's going, then pick something below. If you're unsure about anything, open an issue and ask. Questions are contributions too.

## Ways to help

### Try it and tell us what happened

Put Fathomgate in front of an MCP server in your lab ([docs/install.md](docs/install.md) shows how) and open an issue about anything that broke, confused you or surprised you. A lab built with [containerlab](https://containerlab.dev) is perfect for this. Reports from real setups shape what gets built next.

### Tell us what an MCP server's tools do

Fathomgate needs to know, for each tool an MCP server offers, whether it only reads, changes config or runs anything it's given. We call that description a **profile**. There are profiles for a handful of servers so far in [`profiles/`](profiles/), and dozens of servers still need one.

1. Pick a server you use and open an [upstream server profile issue](https://github.com/fathomgate/fathomgate/issues/new?template=upstream_server_profile.yml).
2. List its tools. Take the names and parameters from the server's code, not its README; the two often disagree.
3. For each tool, say what it does: read state, read config, change config, or run arbitrary commands. If you're torn between two, pick the riskier one and say why.

The maintainer turns the issue into `profiles/<server>.yaml`. The format is in [docs/specs/profile-schema.md](docs/specs/profile-schema.md), if you want to see what your answers become. Profiles and example policies are Apache-2.0, so you can copy and share them freely.

### Report a secret that wasn't masked

Fathomgate hides passwords, keys and community strings in everything that comes back from a device. Every vendor writes secrets in its own way, and we won't have seen them all. If you find one that slips through, or a config format we don't handle yet, open a [redaction gap issue](https://github.com/fathomgate/fathomgate/issues/new?template=redaction_gap.yml) with a few example lines.

**Never paste a real secret anywhere**: not in an issue, a comment or a screenshot. Replace it with a made-up value of the same shape and length, starting with `FAKE`.

### Describe how your team works

A policy is a YAML file of rules: who can read what, which changes need approval, what's never allowed. Examples live in [`policies/examples/`](policies/examples/) ([policy format](docs/specs/policy-schema.md)). If none of them fits how your team works, open a [feature request](https://github.com/fathomgate/fathomgate/issues/new?template=feature_request.yml) that says who the policy is for and what it should allow, hold and deny. You can check a policy of your own with `tools/policy-lint/policy-lint <file>` (Python only, no Go needed).

### Point out what's confusing

If something in the docs confused you, it'll confuse the next person too. Open an issue that quotes the passage and says what you expected. The project's words for things are in [docs/glossary.md](docs/glossary.md): a request is **allowed**, **held** or **denied**.

### Bring your platform knowledge

Vendor drivers (safe config changes with rollback for Junos, EOS, IOS-XE and others) arrive in later stages of the [roadmap](ROADMAP.md). If you know a platform's commit and rollback commands well, read the command tables in [docs/specs/change-safety-drivers.md](docs/specs/change-safety-drivers.md) and open an issue where they're wrong or missing something.

## Pull requests

Pull requests from outside contributors are closed, with thanks and a pointer to open an issue instead. Please don't take it personally: the idea in your pull request is welcome, and the issue is where it gets picked up.

## Building it yourself

The source is public, so you can build, run and audit Fathomgate yourself:

```sh
git clone https://github.com/fathomgate/fathomgate
cd fathomgate
make build        # builds bin/fathomgate
make all          # builds, runs the Go tests and every policy test
```

- **Python only** (policy lint, test fixtures): install [uv](https://docs.astral.sh/uv/), then `cd tests && uv run --extra dev pytest unit -q`. [tests/README.md](tests/README.md) has more.
- **Tests against real MCP servers**: [tests/README.md](tests/README.md) explains how to run them.
- **The official MCP conformance suite**: `make conformance`, which needs Node.js.

`make help` lists everything else. [ARCHITECTURE.md](ARCHITECTURE.md) explains how the pieces fit, and the specs in [docs/specs/](docs/specs/) are the rules the code follows.

## Licence

Fathomgate is licensed under the [Functional Source License, Version 1.1, ALv2 Future License](LICENSE) (`FSL-1.1-ALv2`). You may use, copy, modify and redistribute it for any purpose except offering a competing commercial product or service. Each version becomes Apache-2.0 two years after it is published.

- `policies/examples/` and `profiles/` are under the [Apache License 2.0](profiles/LICENSE).
- `v0.1.0` and every commit before the relicensing stay Apache-2.0 ([NOTICE](NOTICE)).
- The name "Fathomgate" isn't covered by either licence: see [TRADEMARKS.md](TRADEMARKS.md).

## Security problems

If you find a way around a policy, an approval or the secret masking, **please don't open a public issue.** Follow [SECURITY.md](SECURITY.md) to report it privately.

## Be kind

Everyone here follows the [Code of Conduct](CODE_OF_CONDUCT.md). Assume good intent, and be patient with newcomers.
