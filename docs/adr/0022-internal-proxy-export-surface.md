# ADR 0022: The exported surface of `internal/proxy`, restated in one record

- Status: accepted
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer), accepted by the maintainer 2026-09-25; proposed by mcp-protocol-engineer for T0.52 (L3 in the post-merge security review of PR #109); reviewers security-reviewer, go-reviewer

## Context

The exported surface of `internal/proxy` is the seam between the proxy and `cmd/fathomgate`, and from M1 the pipeline stages. It was decided in [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md) and has grown since through [ADR 0016](0016-streamable-http-listener.md) (`HTTPHandler`, `HTTPOptions`, `HTTPPath`), [ADR 0017](0017-keep-upstream-secrets-off-the-command-line.md) (`Secret`, `Command.Secrets`, `Redactor`), [ADR 0018](0018-bound-server-discover-then-initialize-only.md) (`Upstream.NewTransport`) and amendment rows. Two of those rows added exports: `ErrMCPGODEBUG` (the K4 row of ADR 0016) and `(*Proxy).UpstreamExited` (the T0.31 rows of ADR 0012 and ADR 0016).

[GOVERNANCE.md](../../GOVERNANCE.md#architecture-decisions) allows an accepted record to be amended in place only for a factual correction that leaves the decision unchanged. A new exported method is a new decision, however small. The security review of PR #109 (L3) found that `UpstreamExited` came in that way, and that nothing lists the whole surface in one place: a reader has to put it together from five records and their amendment tables.

## Decision

We will treat the list below as the whole exported surface of `internal/proxy` as of go-sdk v1.8.0 and T0.52, and change it only through a new record that supersedes this one.

| Export | Kind | Purpose | First decided in |
| --- | --- | --- | --- |
| `Name` | const `"fathomgate"` | `serverInfo` and `clientInfo` name | ADR 0012 (renamed by ADR 0019) |
| `HTTPPath` | const `"/mcp"` | The only path the listener serves | ADR 0016 |
| `MinSecretLen` | const `4` | Shortest `Secret` value that is scrubbed | ADR 0017 |
| `ErrMCPGODEBUG` | var `error` | The one refusal text for `MCPGODEBUG`, shared by `HTTPHandler` and `serve`'s pre-flight | ADR 0016, K4 amendment row |
| `ValidateServerName(string) error` | func | Checks a tool prefix | ADR 0012 |
| `Upstream{Server string; NewTransport func() mcp.Transport}` | struct | One upstream: its prefix and a transport factory (a new process per call) | ADR 0012, changed by ADR 0018 |
| `Options{Version string; Logger *slog.Logger}` | struct | Proxy settings; the zero value works | ADR 0012 |
| `New(ctx, []Upstream, Options) (*Proxy, error)` | func | Connects every upstream, lists and registers its tools | ADR 0012 |
| `(*Proxy).Run(ctx, mcp.Transport) error` | method | Serves one local agent session (stdio) | ADR 0012 |
| `(*Proxy).HTTPHandler(HTTPOptions) (http.Handler, error)` | method | The Streamable HTTP handler for both eras, with its checks and caps | ADR 0016 |
| `(*Proxy).UpstreamExited() <-chan struct{}` | method | Closed when the first upstream session ends on its own; `serve --listen` stops and exits 1 on it | ADR 0012 and ADR 0016, T0.31 amendment rows (this record makes it a decision) |
| `(*Proxy).Close() error` | method | Cancels calls, closes agent sessions, then stops every upstream | ADR 0012 |
| `HTTPOptions{Tokens map[string][]byte; MaxInFlight, MaxInFlightPerPrincipal, MaxSessions, MaxSessionsPerPrincipal, MaxCallsPerSession, MaxCallsPerPrincipal int; SessionTimeout, OrphanTTL, WriteTimeout, BodyReadTimeout time.Duration}` | struct | Tokens by principal (required) and the listener's limits; zero means the default, negative is an error, no field turns a check off | ADR 0016, fields added by its amendment rows |
| `Command{Path string; Args, Env []string; Stderr io.Writer; StderrPrefix string; Secrets []Secret}` | struct | A stdio upstream process | ADR 0012; `Secrets` from ADR 0017 |
| `(Command).Transport() *mcp.CommandTransport` | method | The go-sdk transport for that process, with the allow-listed environment | ADR 0012 |
| `Secret` (opaque), `NewSecret(name, value string) Secret` | type, func | A value passed to the upstream (`--upstream-env-pass`) that never formats | ADR 0017 |
| `(Secret).Name`, `String`, `GoString`, `Format`, `LogValue`, `MarshalJSON` | methods | The name; every formatting path yields `[redacted:NAME]` | ADR 0017 |
| `Redactor` (opaque), `NewRedactor([]Secret) *Redactor`, `(*Redactor).Redact(string) string` | type, func, method | Scrubs secret values in raw and encoded forms; `serve` also uses it on its own stderr | ADR 0017 |

Rules that go with the list:

- Anything not in the table is unexported. The M1 pipeline plugs in at the unexported `Proxy.dispatch` (ADR 0012); exporting a pipeline interface is the M1 record's decision.
- A change to the table (a new export, a removed one, a changed signature or field, or a changed meaning such as when `UpstreamExited` closes) needs a new record that supersedes this one and restates the table. An amendment row may correct a fact about an entry (a stale line reference, a godoc wording) and nothing more.
- The limits `HTTPOptions` carries stay constants in `internal/proxy` with the defaults profile-schema 8.5 lists. ADR 0016's "one entry point" (`HTTPHandler`) stands.
- `go doc ./internal/proxy` is the check: at each review, its exported identifiers must match this table.

## Consequences

### Positive

- One place to read the seam `cmd/fathomgate` and M1 build on.
- `UpstreamExited` rests on a decision record instead of an amendment row.
- The next export cannot slip in as an amendment: the rule above says what an amendment may do here.

### Negative

- Every export change costs a short record. That is the point; the surface is small and should stay so.

### Neutral

- No code changes. The T0.31 amendment rows in ADR 0012 and ADR 0016 stay as written (records are not edited); this record is where the surface is now read.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Leave `UpstreamExited` recorded by amendment | GOVERNANCE.md reserves in-place amendment for factual corrections, and the review found it outside that. |
| Supersede ADR 0012 and ADR 0016 | They decide far more than the export list (flags, environment, listener security); restating all of it would bury the change. This record supersedes neither; it takes over only their export lists. |
| An `api.txt` checked by a tool (like Go's `api/` files) | Useful later, and it would make the `go doc` check mechanical. For a surface this size a table in a record is enough; revisit when M1 adds the pipeline interface. |

## References

- [ADR 0012](0012-serve-cli-and-proxy-api-for-m0.md), [ADR 0016](0016-streamable-http-listener.md), [ADR 0017](0017-keep-upstream-secrets-off-the-command-line.md), [ADR 0018](0018-bound-server-discover-then-initialize-only.md), [ADR 0019](0019-rename-to-fathomgate.md)
- [GOVERNANCE.md, architecture decisions](../../GOVERNANCE.md#architecture-decisions)
- `internal/proxy` godoc (`go doc -all ./internal/proxy`)
- Post-merge security review of PR #109, finding L3 (T0.52; [handoff](../handoffs/2026-09-25-mcp-protocol-engineer-to-security-reviewer-T0.52.md))
