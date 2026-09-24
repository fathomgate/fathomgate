# ADR 0017: Keep upstream secrets off the command line with `--upstream-env-pass`

- Status: proposed
- Date: 2026-09-23
- Deciders: Josh Scott (maintainer); proposed by mcp-protocol-engineer in T0.23
- Extends: [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md) (`netguard serve` flags). It adds one flag and tightens one error message. It does not change the default allow-list or any other part of ADR 0012.

## Context

T0.5 put netguard in front of the real `netdev-ssh-mcp` from Claude Code and Cursor. The only way to give that upstream a device password today is `--upstream-env DEVICE_PASSWORD=<value>` ([docs/install.md, Device credentials](../install.md#device-credentials)). The value then sits in netguard's argv, and so in the client's `mcp.json`. ssh-agent works, but `SSH_AUTH_SOCK` has to be written into the arguments as a literal path, and that path changes between logins on some systems.

How the environment reaches the upstream today (read in `cmd/netguard/serve.go` and `internal/proxy/command.go`, and checked with a stub upstream that prints its environment to stderr):

- An MCP client's `env` block (Claude Code `claude mcp add -e`, Cursor and Claude Desktop `"env": {...}`) sets variables in **netguard's** environment. They get that far.
- netguard does not pass them on. `proxy.Command.Transport` builds the child environment as `baseEnv(os.Environ(), runtime.GOOS)` followed by the `--upstream-env` entries. `baseEnv` keeps only the ADR 0012 allow-list (Unix `PATH`, `HOME`, `USER`, `LANG`, `TMPDIR`, the POSIX `LC_` categories; the Windows list in ADR 0012). Run as `DEVICE_PASSWORD=... SSH_AUTH_SOCK=... netguard serve ...`, the upstream saw `DEVICE_USERNAME` (given with `--upstream-env`), `HOME`, `PATH`, `TMPDIR` and `USER`, and neither `DEVICE_PASSWORD` nor `SSH_AUTH_SOCK`. So an `env` block never reaches the upstream today. This is deliberate: ADR 0012 withholds everything else so that untrusted upstream code cannot read credentials meant for something else.
- A malformed `--upstream-env` argument is echoed in full in the exit-2 error. `--upstream-env DEVICE-PASSWORD=FAKE-hunter2` prints `--upstream-env "DEVICE-PASSWORD=FAKE-hunter2" is not KEY=VALUE ...` to stderr, which the client writes to its MCP log. The same happens to a bare value passed by mistake.
- Nothing else in netguard formats the upstream environment. Startup errors from `exec` name the path, not the environment. The `slog` startup line logs the server name only. There is no audit writer in `serve` yet (M4).

### Threat model

The secret is a device credential that the upstream needs in its own environment. The upstream is untrusted code, but it must get this value, so it is out of scope as an adversary here. The proxy host is trusted ([SECURITY.md](../../SECURITY.md#threat-model-summary)). The question is where else the value ends up.

| Exposure | `--upstream-env` today | Notes |
| --- | --- | --- |
| Other local users (`ps`, `/proc/<pid>/cmdline`) | Exposed. On Linux, cmdline is world-readable unless `/proc` is mounted `hidepid`. macOS `ps` shows every user's arguments. | A process environment is readable only by the same user or root (`/proc/<pid>/environ` is mode 0400; macOS `ps -E` shows the environment only for the caller's own processes). |
| Process-creation logging | Exposed. Linux `auditd` execve records, Windows Security event 4688 with command-line auditing, Sysmon event 1 and most EDR agents record argv and ship it to a SIEM. | None of these record the environment by default. |
| Shell history | Exposed when the operator runs `claude mcp add ... --upstream-env DEVICE_PASSWORD=...`. | Same for `claude mcp add -e DEVICE_PASSWORD=...`. No option fixes this for the client's own CLI. Docs say to edit the config file instead, or use variable expansion where the client supports it. |
| Client config file (`~/.claude.json`, `.mcp.json`, `~/.cursor/mcp.json`, `claude_desktop_config.json`) | Exposed in `args`. A project `.mcp.json` gets committed. | An `env` block is in the same file. It is only better if the client expands `${VAR}` from its own environment. Claude Code documents this for `.mcp.json`. Other clients must be checked at implementation, not assumed. |
| Client MCP logs | Exposed if the client logs the spawn command line. Also exposed through netguard's own echo on a malformed argument (above). | |
| Crash dumps and core files | Exposed. Both argv and environment are in process memory, in netguard and in the upstream. | No option changes this. Mitigated by the platform's dump settings, not by netguard. |
| netguard's audit log (M4) | Must not happen. [CLAUDE.md invariant 5](../../CLAUDE.md#invariants-you-must-not-break) and SECURITY.md key handling. | An audit startup event must never record raw argv or the upstream environment. It may record variable **names**. |
| Upstream's own stderr | Out of netguard's control. An upstream that prints its environment leaks the value into netguard's stderr whichever way it arrived. | M0 escapes upstream stderr but does not redact it. |
| Same-user malware | Exposed in every option. It can read the upstream's environment. | Out of scope. The proxy host is trusted. |

So the concrete gap is argv: visible to other users on Unix and recorded by process auditing everywhere. It is also the only channel netguard offers today. With the status quo, no configuration keeps a password out of argv. Even a wrapper script that reads a keychain must end by putting the value on netguard's command line.

## Decision

We will add `--upstream-env-pass NAME`, a repeatable `netguard serve` flag. It copies the variable `NAME` from netguard's own environment into the upstream's environment, so no value appears on netguard's command line. We will also stop echoing values in `--upstream-env` errors. The default allow-list of ADR 0012 stays exactly as it is.

- **Syntax.** `--upstream-env-pass NAME`, repeatable. `NAME` must match `[A-Za-z_][A-Za-z0-9_]*`, the same rule as `--upstream-env` keys. There is no wildcard, prefix match or "pass everything" form.
- **Source.** netguard's own environment at startup (`os.LookupEnv`). This is where a client's `env` block, a launching shell, or a wrapper script (for example one that runs `security find-generic-password -w`, `pass` or `op read` and then `exec`s netguard) puts it.
- **Unset is an error.** If `NAME` is unset, `serve` exits 2 before spawning anything, with `--upstream-env-pass NAME: not set in netguard's environment`. A set but empty value is passed through as set: netguard does not judge values.
- **Conflicts are errors.** The same name in both `--upstream-env` and `--upstream-env-pass` exits 2 (names compared ASCII case-insensitively on Windows, exactly on Unix), so which one wins is never a question. Repeating a name in `--upstream-env-pass` is harmless and deduplicated. Naming an allow-listed variable (`PATH`) is allowed and has no effect beyond what the allow-list already passes.
- **`NETGUARD_*` is refused.** `--upstream-env-pass NETGUARD_REDACT_KEY` (any `NETGUARD_` prefix, ASCII case-insensitive on Windows) exits 2. netguard's own keys and settings must never be forwarded to untrusted code by a single flag. `--upstream-env NETGUARD_X=...` stays as it is, because it carries its value explicitly (see open questions).
- **Order.** The child environment is the allow-list, then the `--upstream-env-pass` entries, then the `--upstream-env` entries. Since conflicts between the two flags are refused, the order matters only for overriding allow-listed variables, as today.
- **Values never enter a formatted string.** netguard builds `NAME=` plus the value directly into `proxy.Command.Env`, which is already a plain `[]string` of `KEY=VALUE` entries, so `internal/proxy` needs no API change. No error, log line, `slog` attribute, usage text or (from M4) audit event contains a value. Errors and logs may name the variable. The `serve` startup log may list the names passed with `--upstream-env-pass`. Tests assert that a canary value (`FAKE-canary-...`) appears in none of netguard's stderr, error strings or log output, and does appear in the upstream's environment.
- **`--upstream-env` error text.** A malformed argument is reported as its key only, `--upstream-env "DEVICE-PASSWORD": key must match [A-Za-z_][A-Za-z0-9_]*`. An argument with no `=` is reported as `--upstream-env argument N is not KEY=VALUE`, without quoting it, because a bare argument may be the value itself.
- **Windows.** Environment names are case-insensitive, and Go's `os.LookupEnv` and `exec.Cmd` (which deduplicates `Env` case-insensitively, last entry wins) already behave that way. The name is copied as the operator wrote it, and the value is looked up case-insensitively. The Windows OpenSSH agent uses a named pipe rather than `SSH_AUTH_SOCK` by default, so `SSH_AUTH_SOCK` pass-through is mostly a Unix matter. On Windows the argv exposure is mainly process-creation logging (4688, Sysmon, EDR) rather than other users' `ps`. The flag closes it the same way.
- **CLI surface.** At implementation time these are updated in the same PR: the usage string in `serve.go` and `main.go`, [profile-schema section 8.3](../specs/profile-schema.md#83-netguard-serve-flags) (new flag row, the error texts, the ordering sentence), [SECURITY.md](../../SECURITY.md) (upstream environment line and operator hardening guidance) and `CHANGELOG.md`. `--upstream-env` is kept: it is the right channel for non-secrets (`DEVICE_USERNAME`, `SSH_KNOWN_HOSTS`, `PATH` for wrapper upstreams). It is not deprecated.

### Migration of docs/install.md

- "Device credentials" is rewritten around two channels. Non-secrets use `--upstream-env NAME=value`. Secrets are set in the client's `env` block and named with `--upstream-env-pass NAME`. The table gains a "pass with" column: `DEVICE_PASSWORD` and `SSH_AUTH_SOCK` use `--upstream-env-pass`, `DEVICE_USERNAME` and `SSH_KNOWN_HOSTS` use `--upstream-env`.
- The JSON example gains an `"env": { "DEVICE_PASSWORD": "..." }` block and `"--upstream-env-pass", "DEVICE_PASSWORD"` in `args`. The Claude Code example uses `claude mcp add -e DEVICE_PASSWORD=... -- netguard serve ... --upstream-env-pass DEVICE_PASSWORD`, and warns that `-e` puts the value in shell history and in the config file.
- The warning paragraph changes from "a password on netguard's command line is visible in `ps`" to what is left: the value is in the client config file, so keep that file out of git (a project `.mcp.json` is committed). Use `${VAR}` expansion where the client documents it, or a wrapper that reads a keychain. ssh-agent is still preferred.
- `SSH_AUTH_SOCK` becomes `--upstream-env-pass SSH_AUTH_SOCK`, with no literal socket path. The page says this works when the client inherited it: from a terminal, yes. From a GUI launcher it depends on the platform's session setup, which the implementer checks and records on the page.
- "Check it works" (fake device) keeps `--upstream-env DEVICE_PASSWORD=FAKE-device-pass`, because the value is a published fake. The page says so, so readers do not copy the pattern for a real password.
- Existing configs keep working unchanged. Nothing is removed, so the migration is opt-in.

## Consequences

### Positive

- A device password no longer has to appear in netguard's argv, `ps`, `auditd`/4688/Sysmon/EDR process records, or netguard's own error output.
- It composes with whatever secret handling the client or operator already has: the client's `env` block, `${VAR}` expansion, a keychain wrapper script. So keychain users get a path with no cgo and no new dependency.
- `SSH_AUTH_SOCK` can follow the session's real agent socket instead of a hard-coded path.
- ADR 0012's allow-list is untouched. Passing a variable is still an explicit, named, per-variable opt-in, and `NETGUARD_*` cannot be passed by name.
- Small and additive: no file parser, no filesystem trust decisions, no platform ACL code, no `internal/proxy` API change.

### Negative

- The value still sits in the client's config file (in the `env` block instead of `args`). This ADR does not protect secrets at rest. Mitigation: the docs above. A file-based channel (alternative (a)) remains available later, most naturally inside the M1 config file that ADR 0012 anticipates.
- Operators now have two flags that look alike. Mitigation: usage text and docs give each one a single job (`--upstream-env` for non-secrets, `--upstream-env-pass` for secrets).
- Clients differ in whether their `env` block merges with or replaces the inherited environment, and in whether it expands `${VAR}`. netguard cannot fix that. The docs state what each documented client does, as checked at implementation.
- An unset variable makes startup fail rather than start the upstream without its credential. That is intended, but it is a new way for a copied snippet to fail.

### Neutral

- The upstream receives the secret in its environment, as it does today. Same-user processes and crash dumps can still see it.
- The M4 audit writer inherits one more rule: record names, never values, never raw argv.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| (a) `--upstream-env-file <path>`: `KEY=VALUE` lines, refused unless a regular file, not a link, owned by the current user, with no group or other access (Unix) or an owner-only protected DACL (Windows), in the manner of `internal/audit`'s key file | Protects secrets at rest better than (b), and keeps the client config shareable. But it adds a parser (quoting, `export`, comments, CRLF, BOM; every dotenv dialect differs), a read-side ACL check on Windows that the audit code does not have today (T0.12 needed several review rounds for the write side), a file for operators to manage and rotate, and a relative-path trap under clients that launch with an odd working directory. The concrete T0.5 gap is argv, and (b) closes it at a fraction of the surface. Good fit later for the M1 config file, reusing `internal/audit`'s open-without-following machinery. |
| (b) `--upstream-env-pass NAME` | Chosen. |
| (c) OS keychain lookup inside netguard (`--upstream-env-keychain NAME=item`) | macOS Keychain needs the Security framework (cgo) or runs the `security` CLI (a runtime dependency on an external tool). Linux Secret Service needs a D-Bus client (a new module, ADR) and a session bus that headless hosts and many launchers do not have. Windows Credential Manager is reachable through `syscall`, but that is a third backend with its own unlock semantics. It breaks the single static binary or adds dependencies, and it gives three behaviours to test. (b) plus a wrapper script gives keychain users the same result. |
| (d) Status quo plus docs | Leaves no way at all to keep a password out of argv: even a keychain wrapper has to put the value on netguard's command line. The docs already say to prefer ssh-agent, and T0.5 found that not enough. |
| (e) Docker-style overload: `--upstream-env NAME` with no `=` means "pass from my environment" | One flag fewer. But it turns today's "not KEY=VALUE" typo error into silent lookup semantics. A mistaken bare value that happens to look like a name becomes a lookup whose "not set" error prints it. And it cannot be told apart in logs or `grep` from an explicit value. A separate flag is explicit and validated on its own. |
| (f) Add `SSH_AUTH_SOCK` (and similar) to the default allow-list | ADR 0012 withholds agent sockets deliberately: every upstream would then get the operator's SSH agent whether it needs it or not. Opt-in per variable keeps that decision with the operator. |
| (g) Read secrets from netguard's stdin | stdin is the MCP transport toward the agent. |

## Open questions for the maintainer

1. Should `--upstream-env` warn on stderr (naming the key only) when the key looks like a secret (`*PASSWORD*`, `*SECRET*`, `*TOKEN*`, `*_KEY`), pointing to `--upstream-env-pass`? It is cheap, but it is a heuristic, and it would fire on the fake-device example.
2. Should `--upstream-env NETGUARD_*=...` also be refused, for symmetry with the pass flag? Today it is allowed and carries its value explicitly.
3. Should netguard scrub the exact values it passed with `--upstream-env-pass` out of upstream stderr lines (replacing them with `[redacted:NAME]`)? This would catch an upstream that prints its environment. It means holding the values for the process lifetime, and it misses a value split across the 4096-byte line boundary. It could instead wait for M2 redaction.
4. Should an empty value count as unset (exit 2)? This ADR passes it through, as the environment defines it.

## References

- [ADR 0012, `netguard serve` flags and the `internal/proxy` API for M0](0012-serve-cli-and-proxy-api-for-m0.md)
- [ADR 0011, go-sdk and `golang.org/x/sys`](0011-accept-go-sdk-transitive-modules.md)
- [profile-schema section 8.3](../specs/profile-schema.md#83-netguard-serve-flags)
- [docs/install.md, Device credentials](../install.md#device-credentials)
- [SECURITY.md, threat model and hardening guidance](../../SECURITY.md)
- [M0 board](../milestones/M0.yaml), tasks T0.5 and T0.23
- MCP specification, security best practices: token passthrough and confused deputy in proxies
