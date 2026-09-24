# Contributing

Most useful contributions to Fathomgate are data, not Go: an upstream server profile, a policy example with tests, a redaction pattern with a fixture line. Those need no Go toolchain. Vendor drivers and core changes need Go 1.26 or later. Every commit is signed off under the DCO and follows Conventional Commits.

Read [ARCHITECTURE.md](ARCHITECTURE.md) first. The specs in [docs/specs/](docs/specs/) are normative; if code and spec disagree, file an issue rather than guessing.

## Setup

```sh
git clone https://github.com/fathomgate/fathomgate
cd fathomgate
make tools        # installs golangci-lint, goreleaser, uv; creates the Python venv under tests/
make test         # tier 1: go test, fathomgate policy test, pytest tests/unit
```

`make conformance` runs the official MCP conformance suite against `fathomgate serve` for both protocol eras; it needs Node.js and npm as well as Go and `python3` ([tests/conformance/README.md](tests/conformance/README.md)). Tier 2 needs Docker: `make test-integration`. Tier 3 needs containerlab and images: see [docs/testing/test-strategy.md](docs/testing/test-strategy.md).

## Ways to contribute

### Add an upstream server profile

1. Read the upstream's source, not just its README. Tool names and parameter names must come from the code that registers them. Cite the file in `notes`.
2. Copy `profiles/_template.yaml` to `profiles/<server>.yaml` and fill it per [profile-schema.md](docs/specs/profile-schema.md).
3. Classify every tool. When unsure between two classes, choose the stricter one and explain in `notes`.
4. Run `fathomgate profile lint profiles/` (or `uv run policy-lint profiles/` from `tests/` without Go).
5. Add a tier 2 image build under `tests/images/<server>/` pinned to a commit, and one case to [docs/testing/test-matrix.md](docs/testing/test-matrix.md) that names the server.
6. Open the pull request with the [upstream server profile issue](.github/ISSUE_TEMPLATE/upstream_server_profile.yml) linked if one exists.

### Add a policy example

1. Put the policy in `policies/examples/<name>.yaml` per [policy-schema.md](docs/specs/policy-schema.md).
2. Add `policies/examples/<name>.test.yaml` with at least three cases: one allow, one deny, and one that exercises the rule you consider most likely to be misread.
3. Run `fathomgate policy test policies/` or `uv run policy-lint policies/`.
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
- The Go that CI and releases build with is the `toolchain` line in `go.mod`; the `go` line stays the floor (ADR 0013). With the default `GOTOOLCHAIN=auto`, a local Go older than the pin downloads it on first use; a newer local Go keeps building with itself. `make toolchain-check` reports whether the Go in use is the pinned one.
- `make vulncheck` (govulncheck, pinned in the `Makefile`) must report no vulnerability reachable from our code; CI runs it on every push, every pull request and weekly. It sets `GOTOOLCHAIN` to the `go.mod` toolchain, so it scans the standard library that ships, regardless of the Go you have installed. A fix is usually a toolchain bump (below) or a module bump, and a module bump follows ADR 0011.
- **Bumping the Go toolchain.** Dependabot does not update the `toolchain` line (dependabot/dependabot-core#13520), so a bump is manual, usually because the weekly govulncheck run failed on a new standard-library advisory or a new Go patch is out. Below, `go1.X.N` is the new release; the version is written only in `go.mod`, so no workflow, Makefile or doc line needs editing:
  1. Find the newest patch of the minor you are on: `curl -s 'https://go.dev/dl/?mode=json&include=all' | grep -o '"go1\.X\.[0-9]*"' | head -1` (`include=all` also lists releases that are out of support, which the default list omits).
  2. `go mod edit -toolchain=go1.X.N`; `go mod tidy -diff` must print nothing.
  3. `GOTOOLCHAIN=go1.X.N make toolchain-check`, `make vulncheck`, then the green gate. After `GOTOOLCHAIN=go1.X.N make build`, `go version -m bin/fathomgate` shows the new toolchain.
  4. Add a `### Security` entry under `[Unreleased]` in `CHANGELOG.md` naming the new toolchain and the advisory IDs it fixes (or "no advisory" for a routine patch).
  5. Open a `build(ci): bump Go toolchain to go1.X.N` pull request with the advisory IDs it fixes; go-reviewer and security-reviewer review it. Moving the toolchain to a new Go minor also needs `GOVULNCHECK_VERSION`, the golangci-lint version and the `Dockerfile` builder checked; raising the `go` floor needs a new ADR. golangci-lint refuses to run when it was built with an older Go minor than the toolchain, so pick a release whose `golangci-lint version` says `built with go1.X` or newer. The `Dockerfile` builder image (`golang:1.X-alpine`) must match the new minor, because it builds with its own Go. Dependabot does not propose a new `golang` minor for the builder: `.github/dependabot.yml` ignores `golang` semver-minor updates, so the builder minor changes only in this bump. The builder is pinned as `golang:1.X-alpine@sha256:<digest>`, so change the tag and the digest together (see base image pins, below).
- **Base image pins.** `Dockerfile` (builder and runtime) and `Dockerfile.goreleaser` (the base of every release image) pin each `FROM` as `tag@sha256:<digest>`, where the digest is the multi-arch image index, never a single-platform manifest (a platform digest would break the arm64 image). Dependabot's `docker` entry proposes digest updates for the same tag monthly; review them like any dependency bump. To re-pin by hand, run `docker buildx imagetools inspect <image>:<tag>` (or `crane digest <image>:<tag>`), check that `MediaType` is `application/vnd.oci.image.index.v1+json` and that it lists `linux/amd64` and `linux/arm64`, and use the top-level `Digest`. Keep the distroless digest identical in both files, and do not change a pin to a debug tag: `snapshot.yaml` fails an image that has a shell or does not run as `nonroot`.
- **golangci-lint.** `make lint` (and the CI `golangci-lint` job, which runs it) downloads the upstream release archive for `GOLANGCI_LINT_VERSION` into `bin/tools/`, checks it against the sha256 pinned in the `Makefile` before unpacking it, then runs `config verify` and `run ./...` under the `go.mod` toolchain once for each of `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64` and `windows/amd64`, because syscall field types differ per target and a `nolint` needed on one can be unused on another (`LINT_TARGETS` sets the list; `LINT_GOOS`/`LINT_GOARCH` lint a single target). Why this and not the alternatives (T0.20): golangci-lint-action v9.3.0 downloads the archive and extracts it without checking a hash or signature; `go run …@vX` would be verified by the checksum database but builds with whatever Go is local and is a build upstream does not support. A committed hash pins the exact bytes that upstream ships, and it is the same check locally and in CI. Supported hosts are linux and darwin on amd64 and arm64.
- **Bumping golangci-lint.** Dependabot cannot see the version, so a bump is manual: download the new release's `golangci-lint-X.Y.Z-checksums.txt` and the four `linux`/`darwin` `amd64`/`arm64` `.tar.gz` archives, run `gh attestation verify <archive> --repo golangci/golangci-lint` on each (the checksums file itself is not signed or attested), check that `shasum -a 256` matches the checksums file, then update `GOLANGCI_LINT_VERSION` and the four `GOLANGCI_LINT_SHA256_*` lines together. Pick a release built with at least the toolchain's Go minor (bullet above), and note it in `CHANGELOG.md`.
- A change under `.github/workflows/` must pass `make actionlint` (actionlint, pinned in the `Makefile`, config in `.github/actionlint.yaml`). CI runs it on every push and pull request; install `shellcheck` locally to get the same `run:` script checks.
- CI job `windows` (`ci.yaml`) runs `go vet ./...` and `go test -count=1 ./...` on an elevated `windows-latest` runner with `FATHOMGATE_REQUIRE_PRIVILEGED_TESTS=1`, then re-runs the `Windows` tests in `internal/audit` with `-v` and fails unless each one prints `--- PASS` and none prints `--- SKIP`. With that variable set, the symlink, dangling-symlink, junction and other-owner DACL tests fail instead of skipping when they cannot run. On an unelevated Windows host without Developer Mode, leave the variable unset and those tests skip; CI is where they must run. There is no `-race` on Windows; the Linux `go` job covers it.
- CI job `mcp-conformance` (`ci.yaml`) runs `make conformance` on every push to `main` and every pull request, Dependabot's included, with no path filter; it is meant to be a required status check on `main`. It drives the real `fathomgate serve` binary through the official MCP conformance suite (pinned in `tests/conformance/package-lock.json`) for `2025-11-25` and `2026-07-28`, with go-sdk's own conformance everything-server as the upstream. The run fails on a scored check that is not in `tests/conformance/baseline/`, and on a baseline entry that now passes, so a fix deletes its entry in the same pull request. A change to `internal/proxy` or `cmd/fathomgate/serve.go` runs it locally first. Keep the job's `name:` as `mcp-conformance`: branch protection matches it by name.
- **Bumping go-sdk.** A go-sdk bump, including a Dependabot `go-deps` group PR that moves it, must pass `mcp-conformance` before it merges. The bump rebuilds the fixture upstream from the new go-sdk and runs fathomgate built against it, so a behaviour change on either side shows up as an unexpected failure or a stale baseline entry. Re-check the connection wrapper in `internal/proxy` (`tracksConn`): run `grep -n 'mcpConn.(' mcp/*.go` in the new go-sdk module directory (`go list -m -f '{{.Dir}}' github.com/modelcontextprotocol/go-sdk`) and confirm that every type assertion listed in the `tracksConn` comment still fails, or still succeeds, on go-sdk's newline-delimited connection with and without the wrapper, and that there are no new ones. Reconcile `tests/conformance/baseline/` in the same pull request with a reason on each changed entry, and compare go-sdk's own `.github/workflows/conformance.yml` `CONFORMANCE_VERSION` with the pin in `tests/conformance/package.json` (a suite bump is its own pull request). A go-sdk minor bump is still its own pull request, and the modules it pulls follow ADR 0011.
- A change to `.goreleaser.yaml`, `Dockerfile`, `Dockerfile.goreleaser`, `go.mod`, `go.sum` or the release workflows also runs `snapshot.yaml` (a GoReleaser snapshot with no publishing or signing). Locally: `goreleaser release --snapshot --clean --skip=publish,sign` with GoReleaser v2.18.2.
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
- CI must be green: lint, tier 1, `mcp-conformance`, tier 2 (for changes touching `internal/proxy`, profiles or images), DCO.
- A maintainer reviews within a week. See [GOVERNANCE.md](GOVERNANCE.md).

## Vocabulary

Use the words in [docs/glossary.md](docs/glossary.md). Decisions are `allow`, `hold`, `deny`, `expired`; there is no "blocked" or "rejected". Classes are spelled in upper snake case. Every denial names its rule.

## Security issues

Do not open a public issue for a redaction bypass, a policy bypass or an approval bypass. Follow [SECURITY.md](SECURITY.md).

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
