# ADR 0024: A local console in the core: embedded in the binary, loopback only

- Status: accepted
- Date: 2026-09-25
- Deciders: Josh Scott (maintainer), accepted by the maintainer 2026-09-25 with the answers under *Decisions on the open questions*; proposed by docs-writer with the orchestrator; reviewers security-reviewer, design-guardian, release-engineer, go-reviewer
- Relates to: [ADR 0025](0025-split-the-console.md) (the console split: the local console in the core, the team console in the paid edition; accepted by the maintainer 2026-09-25, in pull request #120), which settles the console row that [ADR 0020](0020-open-core-apache-2.md) left contested. This record decides how the core's half is built and served
- Settles: the `design/` contested row of [ADR 0020](0020-open-core-apache-2.md) (dated row in its *Amendments*)
- Builds on: [ADR 0016](0016-streamable-http-listener.md) and [ADR 0023](0023-listener-binds-both-loopback-families.md) (the loopback listener and its browser defences), [ADR 0009](0009-fathom-design-system-policy-layer.md) (the design system), [ADR 0004](0004-approval-hold-state-machine.md) and [approval-protocol 6 and 8](../specs/approval-protocol.md#6-decision-channels) (decision channels and separation of duties)

## Context

On 2026-09-25 the maintainer split the console in two ([ADR 0025](0025-split-the-console.md)). The open core gets a **local console**: one operator, one machine, used to watch activity, approve or deny held requests, and read the audit chain. The paid edition gets the **team console**: SSO, RBAC, N-of-M approval, fleet views, retention and SIEM. This record decides how the local console is built, served and secured, so that M5 tasks can be written against it.

The maintainer supplied two AI-generated reference mockups ([design/reference/](../../design/reference/README.md)) and a proposed stack: Next.js (App Router, API routes), TypeScript, React, Tailwind with CSS variables, shadcn/ui, TanStack Query, TanStack Table, Recharts, Lucide, React Hook Form with Zod, SSE or WebSockets, Framer Motion used sparingly, the fonts Unbounded, Figtree and Martian Mono, and the architecture Browser, then a Next.js app and API layer, then the Fathomgate core.

Five constraints decide what of that the core can take:

| Constraint | Where it is fixed |
| --- | --- |
| One static binary, `CGO_ENABLED=0`, three direct Go dependencies; no new Go dependency without an ADR | `CLAUDE.md` *Toolchain facts*, [ADR 0001](0001-go-core-with-python-companion.md), [ADR 0011](0011-accept-go-sdk-transitive-modules.md) |
| A loopback socket is reachable by every local user and process and, through DNS rebinding, by any web page in a local browser. The listener refuses every `Origin`, checks `Host`, authenticates every request, and binds both loopback families | [ADR 0016](0016-streamable-http-listener.md) *Request handling*, [ADR 0023](0023-listener-binds-both-loopback-families.md) |
| An approval goes through one `Decide(id, verdict, approver, comment)` in the process that holds the pending store; the channel only establishes the approver's identity, server-side | [approval-protocol 6](../specs/approval-protocol.md#6-decision-channels), invariant 6 |
| Anything that decides or proves stays open; an extension that shows tool output sees redacted output only and reads the audit chain, never writes it | [ADR 0020](0020-open-core-apache-2.md) sections 2 and 3, invariants 4 and 5 |
| One vocabulary and one set of components across UI, CLI and audit log, built on `design/tokens.css` and `design/policy.css` | [ADR 0009](0009-fathom-design-system-policy-layer.md), [DESIGN.md](../../design/DESIGN.md) |

A Next.js server with API routes is a Node process in the path between the operator and the pending store. It would need its own authentication to the core, a way to reach the core's in-process `Decide`, and a Node runtime on every host that runs Fathomgate. None of that fits the constraints above.

## Decision

We will build the local console as static files, embed them in the `fathomgate` binary with `go:embed`, and serve them with a small JSON and SSE API from the `fathomgate serve` process on a separate loopback-only port, off by default, behind a one-time bootstrap token exchanged for a session cookie that no agent token can stand in for.

### 1. Serving and the CLI surface

- **Embedded, no Node at runtime.** The console is compiled once to HTML, CSS, JavaScript and fonts, and embedded in a new package `internal/console` with the standard library's `embed`. The Go side serves the page and a small API: JSON for reads and the one write (approve or deny), and `text/event-stream` for live updates, with `net/http` only. It does not use go-sdk: the console API is not MCP. The binary stays single and static with `CGO_ENABLED=0`, and `go.mod` does not change.
- **Off by default.** Without the flag below, no console socket is opened and none of the console's code serves anything.
- **CLI surface (a change, stated here as required).** Two additions:

  ```text
  fathomgate serve ... [--console <addr>:<port>]
  fathomgate console open [--print] [--port <port>]
  ```

  | Command or flag | Meaning |
  | --- | --- |
  | `serve --console <addr>:<port>` | Serve the console at `http://<addr>:<port>/console/`. `<addr>` takes exactly what `--listen` takes (`localhost`, bound as `127.0.0.1` and never resolved; `127.0.0.1`; `[::1]`), and the other loopback family is bound on the same port, with the same refusals, retries and warnings as [ADR 0023](0023-listener-binds-both-loopback-families.md) point 1. Port `0` asks the OS for a free port. Anything else exits 2. The same port as `--listen` exits 2. It works whether the agent side is stdio or `--listen`. `serve` logs `msg=console url=http://127.0.0.1:<port>/console/` per bound address, with no token in it |
  | `console open` | Reads the current bootstrap URL from its owner-only file (section 2) and opens it in the default browser; `--print` writes it to stdout instead, for a headless host or SSH port forwarding. `--port` picks the instance when several run. It talks to no socket and changes no state; the running `serve` is the only process that holds sessions |

- **Why a flag on `serve` and not a separate process.** The alternatives are compared in the table under *Alternatives considered*. The deciding facts:
  1. The pending store, the TTL sweeper, the drift guard and `Decide` live in the `serve` process from M3 ([approval-protocol 1 to 5](../specs/approval-protocol.md)). A console inside that process calls `Decide` directly, as the CLI's socket handler will. A separate `fathomgate console` process would need a second client of the local socket that also streams live activity and the audit tail, which is a larger protocol than approve, deny and list.
  2. The listener code already carries the loopback-only bind of both families, the connection cap, the `Host` check, the first-request header timeout and the shutdown rules. `--console` reuses that code for its own socket instead of re-implementing it in a second process.
  3. Most agents reach Fathomgate over stdio, launched by the MCP host. Serving the console on the `--listen` port would make HTTP to the agent a precondition for the console. A separate port works with both agent sides.
  4. On separate ports with separate handlers, "an agent token never authenticates the console, and a console cookie never authenticates `/mcp`" is structural: the console handler never reads `Authorization`, and the `/mcp` handler never reads cookies. Tests pin both directions.

### 2. Authentication and browser safety

Checks run in this order on every console request; the first failure answers and nothing later runs. Numbers not given here (caps, lifetimes) are fixed in `docs/specs/console.md` as constants, not flags, as ADR 0016 did for the listener.

1. **Connection cap and first-request header timeout**, from the listener code, with the console's own smaller cap.
2. **Host allow-list.** The host part of `Host` must be `127.0.0.1`, `[::1]` or `localhost`; anything else gets 403. The port is not compared, so SSH port forwarding to another local port works. This closes DNS rebinding: a rebinding page's requests carry its own host name.
3. **Origin and fetch metadata.** A request whose `Sec-Fetch-Site` is present and is neither `same-origin` nor, for a top-level page navigation, `none` gets 403. A request that carries `Origin` must carry exactly `http://` plus its `Host`. Every state-changing request (any method but GET and HEAD) must carry `Origin`. Comparing `Origin` with `Host` is safe here, where ADR 0016 ruled it out for `/mcp`, because step 2 has already refused every host a rebinding page could present. No CORS headers are ever sent, and OPTIONS gets 405.
4. **Bootstrap exchange** (`/console/login` only). At start, and again after each successful exchange, `serve` draws a bootstrap token (256 bits from `crypto/rand`), keeps only its SHA-256 in memory, and writes the URL `http://127.0.0.1:<port>/console/login?token=<token>` to an owner-only file in the per-user runtime directory (`$XDG_RUNTIME_DIR/fathomgate/` on Linux, the per-user temporary directory on macOS, `%LOCALAPPDATA%\fathomgate\` on Windows), named for the port, with the owner-only checks `internal/audit` applies to its key file. The token is never logged; stderr names the file, not its content. `GET /console/login?token=` compares in constant time, consumes the token, rotates the file, and answers 303 to `/console/` with the session cookie. The token is single-use and lives in memory only, so a copy in browser history or a stale file is worthless, and a restarted `serve` never honours a token from an earlier process.
5. **Session cookie.** `fathomgate_console_<port>`: 256 random bits, stored server-side as a SHA-256 digest in memory only, `HttpOnly`, `SameSite=Strict`, `Path=/console/`, no `Domain`. Sessions end when the process exits, and after an idle and an absolute lifetime set in the spec (recommended: 1 hour idle, 12 hours absolute). A request without a valid cookie gets 401 on the API and a page telling the operator to run `fathomgate console open`.
6. **CSRF.** A state-changing request needs all of: the cookie, the custom header `X-Fathomgate-Console: 1`, and the matching `Origin` from step 3. The custom header forces a CORS preflight from any other origin, and step 3 answers none.
7. **Response headers on everything.** `Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'` (no inline script, no `eval`, no remote origin), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, and `Cache-Control: no-store` on the API.

Everything the console shows from an upstream, an inventory or a diff is untrusted data (invariant 7). React escapes text by default; `dangerouslySetInnerHTML` is banned by a lint rule; the CSP is the second layer. The diff view and every technical value render control and bidirectional characters visibly, so a diff cannot hide a line from the approver.

### 3. Approver identity and the one decision path

- **Identity.** A console approval or denial calls `Decide` with approver `console:<os-user>`, where `<os-user>` is the OS user that started `fathomgate serve`, resolved once at start with `os/user` (on Windows, `DOMAIN\user`). `decision_channel` is `console`. The namespace is recorded with the identity, per ADR 0020 invariant 6, so a console identity is never taken for a `cli:` or `webhook:` one. The API body carries the verdict, a comment and the `diff_sha256` the operator was shown; a body that carries an approver, a requester or any other identity field gets 400. The browser never names who approved.
- **Strength.** The console identity is no stronger than the CLI on the local socket, and in one respect weaker: it names the process owner, not the person at the browser. Any process running as that OS user can read the bootstrap file, read the browser's cookie store, or drive the browser, and so can approve. That includes an agent, or a tool an agent runs, when the agent runs as the same OS user.
- **`approver_must_differ`.** A console approval never satisfies `approver_must_differ` in the core. Under [approval-protocol 8](../specs/approval-protocol.md#8-separation-of-duties) the comparison would reach the same answer in every M5 configuration: with a stdio agent the requester is the process owner, which is the console identity; with a listen-token requester the comparison cannot resolve a token principal to an OS user and fails closed. This record states the rule instead of leaving it to the comparison. A held card whose rule sets `approver_must_differ` shows "Approver must differ from requester" and names the channels that can satisfy it (`fathomgate approve` as a different OS user, or the signed webhook), and its Approve button is not offered. Deny is always offered: a denial needs no second person.
- **One path.** The console never evaluates policy, never classifies, and never reads the policy file. It calls `Decide` and reads what the core has already decided. `Decide` runs the drift guard as for every channel ([approval-protocol 5](../specs/approval-protocol.md#5-drift-guard)); in addition, an approval whose `diff_sha256` differs from the record's is refused with `invalid_transition`, so the operator approves the diff they saw.
- **Redacted output only (invariant 4).** The console's data comes from the records the core has already redacted: the audit event, the pending record, and the redacted `Prepare` output behind `prepare_ref`. It has no path to raw upstream output.
- **Read-only audit (invariant 5).** The Audit page opens the chain read-only, with its own file handle, never the `Writer`. Its verify status is `audit.Verify` run in the `serve` process and shown with the words `fathomgate audit verify` prints.

### 4. Frontend stack

| Proposed | Decision | Reason |
| --- | --- | --- |
| Next.js, App Router, API routes | **Vite + React + TypeScript**, compiled to static files | The core serves the API (section 1). Next.js is acceptable only as a static export with no API routes, no middleware and no server runtime, and then it brings file-based routing and little else, at the cost of a larger toolchain. Five pages need no framework router; a small hand-written route switch serves them, and `internal/console` returns `index.html` for every page path |
| TypeScript, React | Kept | |
| Tailwind + CSS variables | **Omitted** | `design/tokens.css` already is the variable layer. Utility classes are a second styling vocabulary that bypasses the semantic tokens unless every utility is remapped. Page layout is a short stylesheet in `console/` that uses the Fathom spacing and radius tokens |
| shadcn/ui | **Omitted** | React components wrap the existing `fg-*` classes in `design/policy.css` (`fg-decision`, `fg-class`, `fg-approval`, `fg-diff`, `fg-ttl`, `fg-blast`, `fg-timeline`, `fg-trace`, `fg-redacted`, `fg-btn`). Re-implementing them as shadcn components would make two sources of truth for one component. `design/` stays the only place a component's look is defined, and the console imports `tokens.css` and `policy.css` from there at build time |
| TanStack Query | Kept | Server state for the read views; an SSE event invalidates the cached list it affects, in one call |
| TanStack Table | Kept | Activity and Audit are dense, sortable tables |
| Lucide | Kept | Icons, imported per icon so only the ones used are bundled |
| Recharts | **Dropped** | No page needs a chart. The blast meter is four discrete bands (`fg-blast`), not a chart, and counts are numbers. A chart comes back only when a page proves it needs one, through the dependency rule in section 5 |
| React Hook Form + Zod | **Dropped** | There is one form: approve or deny with a comment |
| SSE or WebSockets | **SSE only** | Updates flow one way, server to browser. `EventSource` sends the cookie, reconnects on its own, and needs no upgrade handling in the core. Writes are ordinary POSTs |
| Framer Motion | **Dropped** | CSS transitions, as `policy.css` already uses for the hold pulse and the TTL bar, which stop under `prefers-reduced-motion` ([DESIGN.md](../../design/DESIGN.md#accessibility)) |
| Unbounded, Figtree, Martian Mono | Kept, **self-hosted inside the binary** | The font files (WOFF2) are embedded and served from `'self'`. The console never requests Google Fonts or any other origin: labs are often air-gapped, and a font request from an operator's browser tells a third party that a Fathomgate console is open. All three are under the SIL Open Font License 1.1, whose text and copyright lines go in `THIRD_PARTY_LICENSES/` and `NOTICE` |

### 5. npm supply chain and the build

- **Layout.** The frontend lives in `console/` at the repository root, as [PLAN.md](../PLAN.md) already lays out, with its own `package.json` and `package-lock.json`. TypeScript lives only there, as Python lives only in `tests/` and `tools/`. Its build writes into `internal/console/dist/`, which the Go package embeds.
- **Built assets are not committed.** `internal/console/dist/` holds one committed file, `placeholder.html`; everything else there is ignored by git. Plain `go build` without Node therefore compiles and serves the placeholder, a page that says the console was not built and names the command that builds it (`make console`). GoReleaser's clean-tree check passes because the built files are ignored. Committing the build would put minified code in review that no one reads, and make every pull request that touches `console/` carry a second, generated diff.
- **Dependencies.** Versions pinned exactly in `package.json`, `npm ci` from the lockfile everywhere, `--ignore-scripts` so no package's install script runs. The direct dependencies are an allow-list in this record's terms: runtime `react`, `react-dom`, `@tanstack/react-query`, `@tanstack/react-table`, `lucide-react`; build `vite`, `@vitejs/plugin-react`, `typescript`, and a test runner (`vitest`). A new direct npm dependency needs a named reviewer's sign-off (release-engineer and security-reviewer) in the pull request that adds it, with the reason; it needs no ADR per package. The Node version is pinned in `console/.nvmrc` and `engines`.
- **Checks.** `tools/licences` is extended to the npm packages that end up in the bundle (runtime dependencies and what they pull in): each must be under a licence on the existing allow-list (Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC), and their notices join `THIRD_PARTY_LICENSES/`. OFL-1.1 is added for font files only. `npm audit` and an OSV scan run in CI; Dependabot gets an `npm` entry for `console/`. The existing `tests/conformance/package-lock.json` is the precedent for a pinned npm tree in this repository.
- **Release and snapshot builds.** The Node build runs in the unprivileged job of `release.yaml` (the `test` job of the split in pull request #119: `contents: read`, no `id-token`), and the same in `snapshot.yaml`. It uploads `internal/console/dist/` as a workflow artifact with its SHA-256 in the job output; the `goreleaser` job, which alone holds `id-token: write`, downloads it, checks the digest, and never runs npm. A release fails if `dist/index.html` is missing, so no release ships the placeholder. CI builds the console on every pull request that touches `console/` or `design/`.

### 6. Scope in M5, "See it" (core)

| Page | Shows | Acts |
| --- | --- | --- |
| Activity | Live calls: decision badge, class chip, target, rule id, principal, time | None |
| Holding | Held requests: approval card with diff, rule trace, TTL bar, blast meter, requester, rule | Approve (when section 3 allows it) and Deny, each with a comment |
| Audit | Timeline, newest first, with the first 8 characters of each chain hash and the `fathomgate audit verify` result | None |
| Devices | Inventory and resolved roles, including `sot: stale` marking | None (read-only) |
| Drivers | `ChangeSafety` driver health per target (M5 drivers) | None |

Out of scope for the core console: editing settings, policy or inventory in the UI; accounts, sign-in pages or roles; anything that runs as a second process or on a non-loopback address. The team console features (SSO, RBAC, N-of-M approval, fleet, retention, SIEM) are the paid edition's ([ADR 0025](0025-split-the-console.md)).

### 7. Design rules the mockups bend to

The mockups in `design/reference/` are references; [DESIGN.md](../../design/DESIGN.md) wins. For design-guardian's review of the M5 screens:

| In the mockups | In the core console |
| --- | --- |
| "Pending", "Pending Approvals", "Waiting for approval", "Rolled Back", "Verified" as states | Allowed, Holding, Denied, Expired, then Approved, Cancelled, Executed, Failed, and no other state word. A rolled-back change is **Failed**, with the rollback (`error_class: rollback_fired`) in its detail. The chain check is shown as the `fathomgate audit verify` output, not as a per-row state |
| Hero "Watch. Decide. Approve.", the quote card, footer slogans | No marketing copy in the operational UI. The tagline, where one appears (the empty state, the placeholder page), is "Safe passage for AI on your network." |
| Several highlighted panels | One glow per screen, on the held approval card (`shadow-glow`) |
| The teal detailed mark beside decision views | The one-colour `-white` or `-ink` mark on every view that shows decisions; teal reads as allow |
| Deny as a filled red button | **Approve** primary, **Deny** danger outline, and no third action |
| "Josh Scott, Administrator" | The OS user `serve` runs as, set in mono. There are no accounts |
| "Risk Level: Medium" | The blast meter, four discrete bands |
| Sparkline and bar charts, "Top Agents" bars | Numbers and tables; see section 4 on charts |
| Search bar, notification bell, Settings page | Not in the core console's scope |

## Consequences

### Positive

- An operator can watch, approve and audit from a browser with the Apache-2.0 binary alone: no Node, no second process, no network access, no account.
- The single static binary with `CGO_ENABLED=0` and the three direct Go dependencies stay as they are.
- Approvals from the console go through the same `Decide`, drift guard and audit record as every other channel, under their own namespace. The console cannot become a second policy engine.
- The browser defences are the listener's, reviewed twice already (PR #109, PR #112), plus a cookie session and CSRF rules that ADR 0016 did not need.
- One component library: the console renders the same `fg-*` classes as `design/preview.html`, so design review of either covers both.
- Self-hosted fonts keep the console working in an air-gapped lab and make no third-party request.

### Negative

- A second web surface in the process that holds device access. Mitigated by off-by-default, loopback-only on both families, the bootstrap-to-cookie exchange, the Origin and Host rules, CSRF, a strict CSP and small caps. Residuals for the threat model (security-reviewer):
  - **Same OS user.** A process running as the user `serve` runs as, an agent or a tool it runs among them, can read the bootstrap file, read the browser's cookie store, or drive the browser, and approve. That is why a console approval never satisfies `approver_must_differ` (section 3). Accepted.
  - **Cookies are not isolated by port.** A browser sends the console cookie to any service on the same loopback host whose path matches, whatever its port. Another local user who runs a service on `127.0.0.1:<other port>` and gets the operator's browser to it from a same-site page receives the cookie. `SameSite=Strict`, `Path=/console/` and short session lifetimes narrow it. Open for the security review; `__Host-` cookies would close it but need `Secure`, whose handling on plain-HTTP loopback varies by browser and is to be tested for the spec.
  - **Browser extensions** with access to the loopback origin can read the page and act in it. Accepted; out of Fathomgate's reach.
  - **Port squatting while `serve` is down** (the ADR 0023 row) applies to the console port too: a squatter can show a fake console. It cannot use a stale bootstrap token, which lives only in the memory of the process that drew it.
- A JavaScript toolchain enters the repository: a lockfile, Dependabot traffic, licence checks over npm packages, and a Node step in CI and releases. Mitigated by the short allow-list of direct dependencies, `--ignore-scripts`, the review rule, and running npm only in the job without `id-token`.
- The binary grows by the bundle and three font families. The spec sets a size budget and CI checks it.
- A plain `go build` produces a binary whose console shows the placeholder. Mitigated by the placeholder naming the build command, and by the release check that refuses to ship it.
- The CLI surface grows by one `serve` flag and one subcommand.

### Neutral

- Stdio stays the default for agents, and `--listen` is unchanged.
- The core console is deliberately small. The team console ([ADR 0025](0025-split-the-console.md)) is built in the paid edition on the same open tokens and components, and on the exported approval-channel seam that ADR 0020 section 3 anticipates.
- The console lands in M5, after the pending store (M3) and the audit chain (M4) exist to show.

### Follow-ups

| What | Owner | When |
| --- | --- | --- |
| `docs/specs/console.md`: routes, API shapes, SSE event types, caps, session lifetimes, bootstrap file path per OS, size budget, test list | docs-writer with go-reviewer and security-reviewer | M5, before code |
| [approval-protocol](../specs/approval-protocol.md): section 6.5 *Console*; `decision_channel` gains `console`; section 8 lists `console:<os-user>` and the rule that it never satisfies `approver_must_differ` | docs-writer, policy owner | With the spec |
| Threat-model rows for the four residuals under *Negative*, and for XSS from untrusted upstream data | security-reviewer | With the spec |
| M5 board tasks: `internal/console` handler and embedding; `serve --console` and `console open` in `cmd/fathomgate`; `console/` scaffold on the `fg-*` components; the five pages; npm licence and audit checks, Dependabot `npm`, CI and release jobs; self-hosted fonts and their notices | orchestrator | When the M5 board is written |
| `design/DESIGN.md`: the console is the local console (core) and the team console (paid edition), both on these tokens; the mockup rules of section 7 | design-guardian | With [ADR 0025](0025-split-the-console.md) or the first console pull request |

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Next.js with API routes, as proposed (Browser, then a Next.js app and API layer, then the core) | A Node server in the approval path, with its own authentication to the core and a runtime on every host, and no in-process access to `Decide`. It breaks the single-binary property the project treats as a feature |
| Next.js as a static export | Acceptable, but with no API routes, middleware or server runtime it contributes file-based routing and little else, for a heavier toolchain and more dependencies than Vite |
| Console paths on the `--listen` port (`serve --listen ... --console`) | Makes HTTP to the agent a precondition, so stdio agents, the common case, get no console. Puts cookies and bearer tokens on one endpoint, where "neither authenticates the other" becomes a per-path rule instead of a separate handler. `/mcp` refuses every `Origin`, and the console needs a same-origin rule, so the two would need different Origin logic on one port |
| A separate `fathomgate console` process that attaches to a running `serve` over the local socket | Needs a socket protocol that streams activity and the audit tail as well as approve and deny, a second process to start and supervise, and the listener defences built again in that process. It would get a peer-credential identity from the socket, but the browser in front of it still adds nothing stronger than the process owner |
| Console in a separate binary or container | A second artefact to release, sign and keep in step with the core, for one operator on one machine |
| Bearer token in `localStorage` sent as a header instead of a cookie | Readable by any script that runs in the page, so one XSS gives the token away. An `HttpOnly` cookie is not readable by script, and the custom header gives the same CSRF property |
| Bootstrap URL printed on stderr (Jupyter-style) | With a stdio agent, `serve`'s stderr goes to the MCP host's log, which the agent's host owns. An owner-only file read by `fathomgate console open` keeps the token out of logs |
| WebSockets | Two-way transport for one-way updates, an upgrade path the core does not otherwise need, and no cookie handling advantage |
| Tailwind and shadcn/ui on top of the tokens | Two styling vocabularies and two definitions of each component; see section 4 |
| Commit the built assets | Unreviewable generated code in every console pull request, and a second diff to keep in step |
| No local console; CLI only in the core | The maintainer's decision of 2026-09-25 ([ADR 0025](0025-split-the-console.md)) puts a local console in the core. The CLI stays complete and needs no browser |

## Decisions on the open questions

Accepted by the maintainer, Josh Scott, on 2026-09-25, with these answers:

1. **CLI surface: accepted.** `fathomgate serve --console <addr>:<port>` on its own loopback port, plus `fathomgate console open [--print] [--port]`, with the login URL in an owner-only file, as in section 1.
2. **`approver_must_differ`: accepted as written.** A console approval never satisfies it (section 3). A later record may revisit this for a `serve` that runs as a dedicated OS user, with the console session started over the local socket by a different user.
3. **The console split and the milestone: resolved.** Pull request #120 records the split as [ADR 0025](0025-split-the-console.md) (accepted). The local console stays in M5, the roadmap stage "See it".
4. **Licence of `design/`: decided.** `design/` (`tokens.css`, `policy.css`, `preview.html`, `DESIGN.md` and the reference mockups in `design/reference/`) is under Apache-2.0 like the rest of the core. The fonts keep their own licence, the SIL Open Font License 1.1. The logo and the name stay governed by [TRADEMARKS.md](../../TRADEMARKS.md), not by the code licence. This settles the `design/` contested row of [ADR 0020](0020-open-core-apache-2.md), in a dated row of its *Amendments*.
5. **Session lifetimes, `Secure` or `__Host-` cookies on plain-HTTP loopback, and the bundle size budget: deferred** to the M5 console spec, `docs/specs/console.md`. The values in section 2 stay recommendations until then.
6. **OFL-1.1 on the licence allow-list for font files only: approved in principle**, applied in the pull request that adds the fonts, and specified in `docs/specs/console.md`.

The wording rules for the mockups in section 7 are accepted as written.

## Amendments

This section records factual corrections and pointers (GOVERNANCE.md). It does not change the decision.

| Date | What changed | Why |
| --- | --- | --- |
| 2026-09-25 | Pointer: the licence in answer 4 (`design/` under Apache-2.0) is superseded by [ADR 0034](0034-source-available-under-fsl.md) (accepted 2026-09-25). From the relicensing commit on, `design/` follows the repository licence, `FSL-1.1-ALv2`; what was published before it stays Apache-2.0. The fonts keep OFL-1.1, and the logo and name stay under [TRADEMARKS.md](../../TRADEMARKS.md). How the console is built and served is unchanged | Maintainer decision, Josh Scott, 2026-09-25 |

## References

- [ADR 0025](0025-split-the-console.md), the console split (pull request #120)
- [ADR 0016, the Streamable HTTP listener](0016-streamable-http-listener.md): *Request handling, in order*, steps 1 to 3, and why `http.CrossOriginProtection` was ruled out
- [ADR 0023, both loopback families](0023-listener-binds-both-loopback-families.md): point 1 and the port-squatting residual
- [ADR 0020, open core](0020-open-core-apache-2.md): the boundary rule, the contested console row, invariants 4 to 6
- [ADR 0009, Fathom design system](0009-fathom-design-system-policy-layer.md); [DESIGN.md](../../design/DESIGN.md); `design/tokens.css`; `design/policy.css`
- [approval-protocol](../specs/approval-protocol.md), sections 2 (pending record), 5 (drift guard), 6 (decision channels), 8 (separation of duties)
- [Threat model](../security/threat-model.md)
- [design/reference/](../../design/reference/README.md): the maintainer's reference mockups
- [PLAN.md](../PLAN.md): the planned `console/` directory
- Pull request #119: the `release.yaml` split into an unprivileged `test` job and a `goreleaser` job with `id-token`
- [MCP transports, security warning](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports#security-warning); [Fetch Metadata request headers](https://www.w3.org/TR/fetch-metadata/); [RFC 6265bis, SameSite and cookie prefixes](https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/); [Content Security Policy Level 3](https://www.w3.org/TR/CSP3/); [SIL Open Font License 1.1](https://openfontlicense.org/)
