# Contributing

Most useful contributions to NetGuard are data, not Go: an upstream server profile, a policy example with tests, a redaction pattern with a fixture line. Those need no Go toolchain. Vendor drivers and core changes need Go 1.25 or later. Every commit is signed off under the DCO and follows Conventional Commits.

Read [ARCHITECTURE.md](ARCHITECTURE.md) first. The specs in [docs/specs/](docs/specs/) are normative; if code and spec disagree, file an issue rather than guessing.

## Setup

```sh
git clone https://github.com/joshscott13/netguard
cd netguard
make tools        # installs golangci-lint, goreleaser, uv; creates the Python venv under tests/
make test         # tier 1: go test, netguard policy test, pytest tests/unit
```

Tier 2 needs Docker: `make test-integration`. Tier 3 needs containerlab and images: see [docs/testing/test-strategy.md](docs/testing/test-strategy.md).

## Ways to contribute

### Add an upstream server profile

1. Read the upstream's source, not just its README. Tool names and parameter names must come from the code that registers them. Cite the file in `notes`.
2. Copy `profiles/_template.yaml` to `profiles/<server>.yaml` and fill it per [profile-schema.md](docs/specs/profile-schema.md).
3. Classify every tool. When unsure between two classes, choose the stricter one and explain in `notes`.
4. Run `netguard profile lint profiles/` (or `uv run policy-lint profiles/` from `tests/` without Go).
5. Add a tier 2 image build under `tests/images/<server>/` pinned to a commit, and one case to [docs/testing/test-matrix.md](docs/testing/test-matrix.md) that names the server.
6. Open the pull request with the [upstream server profile issue](.github/ISSUE_TEMPLATE/upstream_server_profile.yml) linked if one exists.

### Add a policy example

1. Put the policy in `policies/examples/<name>.yaml` per [policy-schema.md](docs/specs/policy-schema.md).
2. Add `policies/examples/<name>.test.yaml` with at least three cases: one allow, one deny, and one that exercises the rule you consider most likely to be misread.
3. Run `netguard policy test policies/` or `uv run policy-lint policies/`.
4. Describe in the pull request who the policy is for, in one sentence.

### Add a redaction pattern

1. Never paste a real secret anywhere: issue, commit, fixture, test name. Replace the secret characters with a made-up value of the same shape and length.
2. Add the pattern to the table in [redaction-patterns.md](docs/specs/redaction-patterns.md) and to `internal/redact/patterns.yaml` (the same file `policy-lint` reads).
3. Add an annotated line to `tests/fixtures/configs/<vendor>.cfg` with the `ng:<pattern-id>` comment.
4. Run `make test`. The fixture test must show the new line caught by exactly that pattern and no existing line changing hands.

### Add a vendor driver

1. Read [change-safety-drivers.md](docs/specs/change-safety-drivers.md). Fill in the per-platform command table row first, in a pull request to the spec, and get it reviewed before writing Go. Vendor command details are where reviewers add most value.
2. Implement `ChangeSafety` in `internal/safety/<vendor>/`. The driver talks to the device only through `Executor`; it never opens its own session.
3. Tier 1: a recording fake upstream asserts the exact command sequence for `Prepare`, `Apply`, `Confirm`, `Abort`, and the watchdog on a fake clock if the platform has no native timer.
4. Tier 2: add persona responses to `tests/fakedevice/responses/<vendor>/`.
5. Tier 3, if an image exists: a containerlab case and an `assert_device` helper.
6. An ADR is needed if the driver changes the interface.

### Python-only paths

Everything under `tests/` and `tools/` is Python (3.11 or later, managed with `uv`). You can contribute without Go to:

- `tests/fakedevice/`: vendor personas and canned responses.
- `tests/clab/`: topologies and scrapli assertion helpers.
- `tests/fixtures/configs/`: redaction corpus.
- `tools/policy-lint/`: the YAML schema validator and classifier-table checker, which must stay in step with the Go loader. If you change one, change the other or open an issue.
- `profiles/`, `policies/examples/`: data.

Run `cd tests && uv run pytest` for the Python suite.

### Core Go changes

- `gofmt`, `go vet` and `golangci-lint run` must pass; `make lint` runs them.
- Table tests over synthetic requests; no network in `go test`.
- A change to `Evaluate`, the classifier tables, the audit hash or the redaction token format needs a spec update in the same pull request, and usually an ADR.
- Do not add a dependency without saying why in the pull request. `gopkg.in/yaml.v3` is not permitted.

## Commit messages

Conventional Commits:

```
type(scope): summary in sentence case, under 72 characters

Body explaining why, wrapped at 80. Reference issues.

Signed-off-by: Your Name <you@example.com>
```

Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `chore`. Scopes are package or directory names: `proxy`, `normalize`, `classify`, `inventory`, `policy`, `approval`, `safety`, `redact`, `audit`, `profiles`, `policies`, `tests`, `tools`, `docs`, `design`, `console`.

## DCO sign-off

Every commit must carry a `Signed-off-by` line matching the author, certifying the [Developer Certificate of Origin 1.1](https://developercertificate.org/). Use `git commit -s`. The DCO check runs on every pull request. Anonymous or pseudonymous sign-offs are fine as long as they are consistent.

## Pull requests

- One change per pull request. A profile and a redaction pattern are two pull requests.
- Fill in the [template](.github/PULL_REQUEST_TEMPLATE.md). The checklist asks whether an ADR is needed, whether policy tests and redaction fixtures were updated, and whether docs changed.
- CI must be green: lint, tier 1, tier 2 (for changes touching `internal/proxy`, profiles or images), DCO.
- A maintainer reviews within a week. See [GOVERNANCE.md](GOVERNANCE.md).

## Vocabulary

Use the words in [docs/glossary.md](docs/glossary.md). Decisions are `allow`, `hold`, `deny`, `expired`; there is no "blocked" or "rejected". Classes are spelled in upper snake case. Every denial names its rule.

## Security issues

Do not open a public issue for a redaction bypass, a policy bypass or an approval bypass. Follow [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
