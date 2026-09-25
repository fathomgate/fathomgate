# Contributing to Fathomgate

Thanks for being here. Fathomgate is building a policy checkpoint for AI assistants working on networks, and the people who know those networks best are the ones running them. You don't need to write Go to help, and most of the contributions we need most don't involve any code at all.

New to the project? Read the [roadmap](ROADMAP.md) for where it's going, then pick something below. Issues labelled [`good first issue`](https://github.com/fathomgate/fathomgate/labels/good%20first%20issue) are a good place to start. If you're unsure about anything, open an issue and ask. Questions are contributions too.

## Ways to help, easiest first

### Try it and tell us what happened

Put Fathomgate in front of an MCP server in your lab ([docs/install.md](docs/install.md) shows how) and open an issue about anything that broke, confused you or surprised you. A lab built with [containerlab](https://containerlab.dev) is perfect for this. Reports from real setups shape what gets built next.

### Tell Fathomgate what an MCP server's tools do

Fathomgate needs to know, for each tool an MCP server offers, whether it only reads, changes config or runs anything it's given. We call that description a **profile**. There are profiles for four servers so far in [`profiles/`](profiles/), and dozens of servers still need one.

1. Pick a server you use and open an [upstream server profile issue](https://github.com/fathomgate/fathomgate/issues/new?template=upstream_server_profile.yml).
2. List its tools. Take the names and parameters from the server's code, not its README; the two often disagree.
3. For each tool, say what it does: read state, read config, change config, or run arbitrary commands. If you're torn between two, pick the riskier one and say why.
4. If you're comfortable with YAML, turn it into `profiles/<server>.yaml` using an existing profile such as [`profiles/netdev-ssh-mcp.yaml`](profiles/netdev-ssh-mcp.yaml) as a guide. If not, the issue alone is a big help, and a maintainer will turn it into a profile.

The full format is in [docs/specs/profile-schema.md](docs/specs/profile-schema.md).

### Report a secret that wasn't masked

The standalone `fathomgate redact` command masks supported password, key and community-string patterns. Masking live proxy responses is planned; v0.1.0 forwards them unchanged. Every vendor writes secrets in its own way, and we won't have seen them all. If you find one that slips through, or a config format we don't handle yet, follow [SECURITY.md](SECURITY.md) privately for a documented pattern that is not masked. For a new, undocumented vendor format, open a [redaction gap issue](https://github.com/fathomgate/fathomgate/issues/new?template=redaction_gap.yml).

**Never paste a real secret anywhere**: not in an issue, a commit or a test file. Replace it with a made-up value of the same shape and length, starting with `FAKE`.

To go further, add the example lines to a file in [`tests/fixtures/configs/`](tests/fixtures/configs/). Each vendor has a `.txt` config excerpt with a `## rule:` note on each secret line, and a `.expect.json` listing the secrets that must disappear. `make fixtures-check` shows whether they're all caught. The masking rules themselves live in Go, in [`internal/redact/rules.go`](internal/redact/rules.go), and are described in [docs/specs/redaction-patterns.md](docs/specs/redaction-patterns.md).

### Share a policy for how your team works

A policy is a YAML file of rules: who can read what, which changes need approval, what's never allowed. Examples live in [`policies/examples/`](policies/examples/). To add one:

1. Write `policies/examples/<name>.yaml` ([policy format](docs/specs/policy-schema.md)).
2. Write `policies/examples/<name>.test.yaml` with at least three cases: one allowed, one denied, and one for the rule you think people are most likely to misread.
3. Check it with `tools/policy-lint/policy-lint policies/examples/<name>.yaml` (Python only, no Go needed) or `make policy-test`.
4. In the pull request, say in one sentence who the policy is for.

### Improve the docs

If something in the docs confused you, it'll confuse the next person too. Fixes to wording, missing steps and clearer examples are always welcome. Please use the project's words for things ([docs/glossary.md](docs/glossary.md)). For example, a request is **allowed**, **held** or **denied**, never "blocked" or "rejected".

### Write Go

Core changes, new features and vendor drivers are Go (1.26 or later). Before you start on anything bigger than a small fix, open an issue so we can agree on the approach. Some changes need a short design record first (see [docs/adr/](docs/adr/README.md)), and it's much nicer to find that out before you've written the code. [ARCHITECTURE.md](ARCHITECTURE.md) explains how the pieces fit, and the specs in [docs/specs/](docs/specs/) are the rules the code follows.

Vendor drivers (safe config changes with rollback for Junos, EOS, IOS-XE and others) arrive in later stages of the [roadmap](ROADMAP.md). If you know a platform's commit and rollback commands well, the command tables in [docs/specs/change-safety-drivers.md](docs/specs/change-safety-drivers.md) are where your knowledge helps most, even before any Go is written.

## Getting set up

```sh
git clone https://github.com/fathomgate/fathomgate
cd fathomgate
make build        # builds bin/fathomgate
make all          # builds, runs the Go tests and every policy test
```

- **Python only** (policies, profiles, test fixtures): install [uv](https://docs.astral.sh/uv/), then `cd tests && uv run --extra dev pytest unit -q`. [tests/README.md](tests/README.md) has more.
- **Tests against real MCP servers**: [tests/README.md](tests/README.md) explains how to run them.
- **The official MCP conformance suite**: `make conformance`, which needs Node.js.

`make help` lists everything else.

## Sending a pull request

- **One change per pull request.** A profile and a policy example are two pull requests.
- **Sign off your commits** with `git commit -s`. That adds a `Signed-off-by` line, which says you wrote the change and have the right to contribute it ([Developer Certificate of Origin](https://developercertificate.org/)). The `DCO` check fails a pull request if any commit's sign-off is missing or doesn't match its author. Forgot one? You don't need to rewrite your branch: the check's details page shows the exact commit to add. A consistent pseudonym is fine.
- **Commit messages** follow [Conventional Commits](https://www.conventionalcommits.org/): `type(scope): what changed`. For example, `feat(profiles): add scrapli-mcp profile` or `docs: fix the install steps for Windows`. Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`. The scope is the area you touched (`profiles`, `policies`, `redact`, `proxy`, `docs`, `tests` and so on).
- **Fill in the [pull request template](.github/PULL_REQUEST_TEMPLATE.md).** Its short checklist catches the usual things: tests, docs, and whether a design record is needed.
- **CI has to pass.** If it fails and you can't see why, say so in the pull request and we'll help.
- **A maintainer replies within a week.** How decisions are made is in [GOVERNANCE.md](GOVERNANCE.md).

Changing the build, the Go toolchain, dependencies or the CI workflows? [docs/maintainers.md](docs/maintainers.md) has the extra checks those need.

## Licence

Fathomgate is licensed under the [Apache License 2.0](LICENSE). When you sign off a commit, you agree to license it under Apache-2.0. There's no separate contributor agreement: the project gets no more rights to your code than that licence gives, so it can't relicense your work without your consent.

- New Go, Python and shell files start with an `SPDX-License-Identifier: Apache-2.0` comment. `python3 tools/licences/spdx.py --fix` adds it for you. Data files (policies, profiles, fixtures, Markdown) don't need one.
- Code copied from another project keeps its own licence notice. Say where it came from in the pull request; its licence must be compatible with Apache-2.0.
- If you add or remove a Go module dependency, run `make licences` and commit the result. CI checks this.
- The name "Fathomgate" isn't covered by the code licence: see [TRADEMARKS.md](TRADEMARKS.md).

## Security problems

If you find a way around a policy, an approval or the secret masking, **please don't open a public issue.** Follow [SECURITY.md](SECURITY.md) to report it privately.

## Be kind

Everyone here follows the [Code of Conduct](CODE_OF_CONDUCT.md). Assume good intent, be patient with newcomers, and remember that many people are contributing in their spare time.
