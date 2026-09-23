# ADR 0012: `netguard serve` flags and the `internal/proxy` API for M0

- Status: proposed
- Date: 2026-09-23
- Deciders: Josh Scott (maintainer); proposed by mcp-protocol-engineer in T0.2

## Context

T0.2 turns `netguard serve` from a stub into a pass-through proxy for one stdio upstream. The CLI surface and any new interface need a decision record ([CLAUDE.md](../../CLAUDE.md#how-work-moves)), and no spec defined the `serve` flags. The stub accepted `--policy`, `--inventory`, `--profiles`, `--audit` and `--upstream` and ignored them all; the README snippet and the skipped tier 2 fixture passed them.

Three constraints shape the flags. The tool prefix is the profile's `server` key and must not be guessed from the binary name ([profile-schema section 1](../specs/profile-schema.md#1-top-level-fields)). An operator who passes `--policy` to a proxy that enforces nothing would believe calls are being checked when M0 forwards every one. And the upstream is untrusted code running with whatever environment the proxy hands it: the proxy's own environment can hold unrelated credentials (cloud keys, SSH agent sockets, NetGuard's own settings) that an upstream has no business reading.

## Decision

We will ship `netguard serve --server <name> --upstream <path> [--upstream-env KEY=VALUE]... [-- <upstream args>...]` for M0, refuse `--policy`, `--inventory`, `--profiles` and `--audit` with exit 2 until the pipeline they configure is wired, give the upstream a minimal allow-listed environment, and keep the seam for that pipeline unexported inside `internal/proxy`.

- `--server` is required and is the prefix. It is validated before anything is spawned; an invalid name exits 2.
- `--upstream` is the executable, run with no shell. Its arguments are accepted only after `--`. Arguments left over without `--`, and any reserved flag name among the leftovers (with or without `--`), are refused, because Go's flag parser stops at the first positional argument.
- Environment: the upstream inherits only an allow-list from the proxy. Unix: `PATH`, `HOME`, `USER`, `LANG`, `TMPDIR` and the POSIX `LC_` categories by name (no wildcard). Windows (ASCII case-insensitive, no Unicode folding): `PATH`, `SystemRoot`, `SystemDrive`, `TEMP`, `TMP`, `USERPROFILE`, `APPDATA`, `LOCALAPPDATA`, `PATHEXT`, `COMSPEC`. Everything else, including `NETGUARD_*`, reaches the upstream only through `--upstream-env`, which is appended last and so overrides. `--upstream-env` keys must match `[A-Za-z_][A-Za-z0-9_]*`; an empty `--upstream` or `--upstream --` is refused.
- Upstream stderr goes to the proxy's stderr, each line prefixed `upstream <server>: ` with control characters escaped.
- `internal/proxy` exports `Upstream{Server, Transport}`, `Options{Version, Logger}`, `New(ctx, []Upstream, Options) (*Proxy, error)`, `(*Proxy).Run(ctx, mcp.Transport)`, `(*Proxy).Close()`, `Command{Path, Args, Env, Stderr, StderrPrefix}` with `Transport()`, `ValidateServerName(string) error`, and the constant `Name`. `New` takes a slice so multi-upstream support does not change the signature. If `New` fails after a `Command` process started, the process is killed.
- The M1 pipeline plugs in at the unexported `Proxy.dispatch`. Exporting a pipeline interface is left to the M1 record that defines it.
- Prefix and error rules are in [profile-schema section 8](../specs/profile-schema.md#8-proxy-config-m0).

## Consequences

### Positive

- Nothing guesses the prefix. A launcher config names it once, matching the profile and future policy `match.servers`.
- No shell parsing of the upstream command, so paths with spaces work and nothing is interpreted.
- A copied snippet that still passes `--policy` fails loudly instead of running unenforced, however the arguments are ordered.
- A compromised or careless upstream cannot read credentials the operator gave the proxy for something else.

### Negative

- The README snippet and the tier 2 fixture change shape. Both are updated in the same PR.
- A config file (`--config`, mentioned in agent briefs) is not part of this record. If M1 needs one, it supersedes the flag set here.
- An upstream that needs a variable outside the allow-list (a proxy setting such as `HTTPS_PROXY`, a vendor `*_CONFIG` path, its own credentials) needs it passed with `--upstream-env`. That is the point, but it is a migration step for anyone who relied on inheritance.
- An upstream with its own `--policy`, `--inventory`, `--profiles` or `--audit` flag cannot be given it after `--` in M0.

### Neutral

- The reserved flags keep their names, so M1 turns them on without renaming.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| `--upstream "<command line>"` split on spaces | Breaks Windows paths with spaces and invites shell-quoting bugs; `--` is unambiguous and maps one-to-one onto `mcp.json` `args`. |
| Derive the prefix from `--upstream` | Explicitly ruled out: the prefix is the profile key, and binary names differ from it (`netdev-ssh-mcp` vs a renamed or versioned binary). |
| Accept and ignore `--policy` in M0 | An operator would believe a policy is enforced. |
| Pass the proxy's whole environment to the upstream | Leaks unrelated credentials to untrusted code; the MCP security guidance treats token passthrough to upstreams as a confused-deputy risk. |
| Export `(*Proxy).Tools()` | Only tests and one log line used it; the tool count is now logged by `New` itself. |
| A YAML config file now | New schema and spec for one upstream with three settings; revisit when M1 adds policy and inventory. |

## References

- [ADR 0002, standalone proxy](0002-standalone-proxy-not-gateway-plugin.md)
- [ADR 0011, go-sdk v1.7.0](0011-accept-go-sdk-transitive-modules.md)
- [profile-schema section 8](../specs/profile-schema.md#8-proxy-config-m0)
- [M0 board](../milestones/M0.yaml), task T0.2
