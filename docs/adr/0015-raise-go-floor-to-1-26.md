# ADR 0015: Raise the go floor to 1.26.0 and let it follow the oldest supported Go release

- Status: accepted
- Date: 2026-09-23
- Deciders: Josh Scott (maintainer; accepted 2026-09-23)
- Supersedes: the "keep `go 1.25.0` as the floor" clause of [ADR 0013](0013-pin-go-toolchain-in-go-mod.md). The rest of ADR 0013 (the `toolchain` pin, `go-version-file`, `make toolchain-check`, manual toolchain bumps) stands.

## Context

ADR 0013 pinned the build toolchain in `go.mod` and kept `go 1.25.0` as the module floor, the minimum set by go-sdk (ADR 0011). Its guardrail 6 says a toolchain bump needs no new ADR "as long as the `go` floor does not change".

Dependabot PR #39 (`ef3b4cd`, merged 2026-09-24 UTC) moved `golang.org/x/sys` from v0.47.0 to v0.48.0. x/sys v0.48.0 declares `go 1.26.0`, so `go mod tidy` raised NetGuard's floor to `go 1.26.0`. No other module in the build list needs more than 1.25.0 (`go list -m -f '{{.GoVersion}}' all`). The floor changed without the ADR that ADR 0013 asks for, and six live documents still say 1.25.

Go 1.25 has been out of support since Go 1.27.0 shipped on 2026-08-19. CI and release builds already use `toolchain go1.26.8` (T0.14). NetGuard ships as a single binary; nobody imports the module, so the floor constrains only contributors who build with an older local Go.

## Decision

We will accept `go 1.26.0` as the floor, and from now on let the floor rise to the oldest supported Go release whenever a dependency requires it, without a new ADR.

- A dependency bump that raises the floor to a Go release that is still supported upstream is an ordinary pull request. It says so in its description and adds a `CHANGELOG.md` line, and it updates the version in `CLAUDE.md`, `AGENTS.md`, `ARCHITECTURE.md`, `CONTRIBUTING.md`, `README.md` and `ROADMAP.md` if they name it.
- Raising the floor past the oldest supported release (for example to 1.27 while 1.26 is still supported) needs a new ADR, because it drops a Go release that users can still be on.
- The `toolchain` line must be at or above the floor. ADR 0013's rules for bumping it are unchanged.
- We do not pin a dependency back to keep an old floor. The only reason to do so would be to keep an unsupported Go release building.

## Consequences

### Positive

- Security fixes in `golang.org/x/*` modules, which follow the Go support window, land through Dependabot without an ADR each time.
- The floor, the toolchain and the supported Go releases now agree. A contributor on an unsupported Go gets a clear `go.mod requires go >= 1.26.0` error instead of building against a standard library with known vulnerabilities.

### Negative

- Contributors must have Go 1.26 or later, or let `GOTOOLCHAIN=auto` download it. Mitigation: CONTRIBUTING.md names the version, and Go 1.21+ fetches the toolchain automatically by default.
- A Dependabot PR can change the floor quietly, as #39 did. Mitigation: the rule above makes the PR description and CHANGELOG line part of the merge, and go-reviewer checks the `go` line on every `go.mod` diff.

### Neutral

- CI, release and `make toolchain-check` are unchanged: they read the `toolchain` line, which was already `go1.26.8`.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Pin `golang.org/x/sys` back to v0.47.0 and keep `go 1.25.0` | Keeps a floor on an unsupported Go release, and blocks every later x/sys fix, including ones like GO-2026-5024 that the audit key code needed. |
| Keep an ADR for every floor change | The floor follows the Go support window, not a design choice. A new ADR every six months records nothing a contributor needs to decide. |
| Drop the floor rule and let `go mod tidy` decide | That already happened with #39 and left six documents stale. The rule keeps the change visible. |

## References

- [ADR 0011](0011-accept-go-sdk-transitive-modules.md), module table and the x/sys row
- [ADR 0013](0013-pin-go-toolchain-in-go-mod.md), toolchain pin; its floor clause is superseded here
- Dependabot PR #39, `golang.org/x/sys` v0.47.0 to v0.48.0 (`ef3b4cd`)
- Go release policy: each major release is supported until there are two newer major releases, https://go.dev/doc/devel/release#policy
