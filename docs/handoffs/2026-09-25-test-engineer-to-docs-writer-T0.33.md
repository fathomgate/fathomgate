# T0.33: matrix row 23 runs the HTTP listener against the real netdev-ssh-mcp; Claude Code `"type": "http"` tested and documented

- **Task:** T0.33 — Matrix row 23 (tier 2 over HTTP, Claude Code type http), profile-schema 8.5 HTTP listener, SECURITY.md gap rows, README and install.md snippets
- **From → To:** test-engineer → docs-writer (security-reviewer also reviews)
- **State now:** in review. `docs/milestones/M0.yaml` is not edited here; the orchestrator syncs the board.
- **Branch / PR:** `test/tier2-over-http` · [PR #115](https://github.com/fathomgate/fathomgate/pull/115)
- **Date:** 2026-09-25

## Done

- **`tests/integration/test_http_listener.py`** (new, `tier2` and `netdev_ssh_mcp` markers, so it runs in the existing required job `tier2 client smoke (netdev-ssh-mcp)`; only that job's step name and comment changed in `ci.yaml`):
  - It starts `fathomgate serve --listen 127.0.0.1:0` in front of the pinned netdev-ssh-mcp v1.7.1 and the fake device. The token is FAKE and random, from an owner-only file (`0600`, or install.md's `icacls` on Windows) or from `FATHOMGATE_LISTEN_TOKEN`. The harness reads the URLs from the `msg=listening url=` lines.
  - `test_http_tools_list_and_show_version`, for each token source in both eras: python-sdk `mcp` 2.2.0 `Client` over `streamable_http_client` with the `Authorization` header, `mode="legacy"` (2025-11-25) and `mode="auto"` (`server/discover`, 2026-07-28). It checks the five prefixed tools exactly, `show version` unchanged and once on the device, and the principal name in the `listening` line.
  - `test_http_both_listening_urls`: the same in both eras on `127.0.0.1` and `[::1]` (same port, ADR 0023). In CI (`FATHOMGATE_TIER2_REQUIRED=1`) a missing `[::1]` fails; locally it skips.
  - `test_http_refusals`, both URLs, 2025 and 2026 request shapes: 200 with the token first, as a control. Then 401 plus `WWW-Authenticate: Bearer` for no token, a wrong token and `Basic`; 403 for `Origin` with and without the token, and for `Host: evil.example`. Each refusal has `Connection: close` and no CORS header, and no token in the body or headers. Nothing reaches the device, and an `authentication failed` log line is written.
  - Every test stops fathomgate with SIGINT, or `CTRL_BREAK_EVENT` on Windows, and checks exit 0, `shutting down`, an empty stdout, and no token (nor the wrong one) anywhere in stderr.
- **Real-server evidence:** Windows 11, v1.7.1 release binary, all 7 pass; the whole `netdev_ssh_mcp` set is 21 passed, 11 skipped, 1 xfailed. A mutant with `crossOrigin` disabled fails `test_http_refusals` (`200 == 403`). CI: [run 36099468294](https://github.com/fathomgate/fathomgate/actions/runs/36099468294) on PR #115, job `tier2 client smoke (netdev-ssh-mcp)`: all 7 passed on Linux, both URLs, 30 passed / 2 skipped / 1 xfailed overall. Row 23 is `passing`.
- **Claude Code 2.1.281, by hand:** `claude -p --mcp-config` with `{"type": "http", "url": ..., "headers": {"Authorization": "Bearer ${FATHOMGATE_TOKEN}"}}` connected on both URLs, listed the five tools and ran `show version` (one device line each). A wrong token gave `failed`/401. `claude mcp add --transport http ... --header` in an isolated `CLAUDE_CONFIG_DIR` gave `✔ Connected` with the token and with the `${FATHOMGATE_TOKEN}` reference; without the variable it failed with a `Missing environment variables` warning. `claude mcp get` prints a literal token in clear. Details are in the row 23 run note.
- **Docs:**
  - `docs/install.md` "Remote agents over HTTP": the `listening` sample now matches the real line (`time=`, `upstream_env_pass`). Step 3 has the tested Claude Code commands (sh and PowerShell), the `.mcp.json` / `--mcp-config` JSON, the 401 troubleshooting and the variable-name caveat, and says what was and was not tested.
  - `README.md`: a short "Or run it once and let assistants connect over HTTP" paragraph that links to it.
  - `docs/specs/profile-schema.md` 8.5: the T0.33 sentence is now present tense, and the `listening` line format is exact.
  - `SECURITY.md`:
    - *Hung upstream* and *Payload size* now describe the listener (2025 POST drop and the call caps; 4 MiB body, 64 KiB headers).
    - The listener row cites row 23.
    - New row: connection slots held without a token (the threat model's accepted residual, which had no SECURITY.md row).
    - New hardening bullet: a token per client, given as a `${VAR}` reference.
    - The T0.52 port-squatting row is left as it was.
  - `docs/testing/test-matrix.md`: row 23 and its run note. The coverage tables add 23 (and 22 under netdev-ssh-mcp, which was missing).
  - `tests/README.md` and `CHANGELOG.md` (Added). The CHANGELOG also loses a stale duplicate of the T0.31 entry that still said `127.0.0.0/8`, left by the PR #112 merge.

## Fix round (security and docs reviews of PR #115)

The security review asked for changes (three medium items, all docs). The docs review approves after changes. Where they conflict, security wins: docs item 5 (put the `export` in `~/.zshrc` or `$PROFILE` so it lasts) was rejected by the coordinator, and the docs now say the opposite.

- **M1, the client variable spreads the token.**
  - install.md step 3 and the README now add the server once with `'Authorization: Bearer ${CLAUDE_FATHOMGATE_TOKEN}'`. They start Claude Code with the variable set for that process alone: `CLAUDE_FATHOMGATE_TOKEN="$(cat ~/.config/fathomgate/claude-code.token)" claude` in sh, or in PowerShell a window used only to start Claude Code.
  - They say never to put it in a shell rc file, `$PROFILE` or `setx`, and why: Claude Code's Bash tool, hooks and stdio servers inherit it.
  - They say to read a project's `url` and `headers` before approving its MCP servers.
  - The variable is renamed from `FATHOMGATE_TOKEN` to `CLAUDE_FATHOMGATE_TOKEN`: outside the reserved `FATHOMGATE_*` prefix, and not `FG_*` (ADR 0019). The docs say Fathomgate never reads it.
  - Docs item 1 is covered with my own wording, because the reviewer's text was not available to me. Don't use `FATHOMGATE_LISTEN_TOKEN` (checked: `serve --listen-token-file` exits 2 with it set). Don't use a credential variable such as `ANTHROPIC_API_KEY` (checked: an empty `Bearer`, a 401, no warning).
- **M2, "safe to commit".** It now reads "It holds the variable's name, not the token". The docs also:
  - recommend `--scope local` or `user`;
  - forbid `--scope project` with a pasted token;
  - say that a committed entry sends each person's token to that port on their own machine (the port-squatting row).
- **M3, withdrawing a token.**
  - install.md step 2, SECURITY.md hardening and threat-model row 58 now say that token files are read once at startup, so a token is withdrawn by removing its entry or replacing the file, then restarting. Deleting the file changes nothing until the restart.
  - The examples use a per-client file and principal (`claude-code.token`, `claude-code`).
- **L1:** `claude mcp get` on a `${VAR}` entry prints `Authorization: Bearer ${CLAUDE_FATHOMGATE_TOKEN}`, the reference, whether the variable is set or not. This is recorded in the row 23 run note, and install.md matches it.
- **L2:** a new `non-loopback Host without token` case gets 403.
  - Mutation with `hostAllowed` returning true: that case fails (`401 == 403`).
  - The case with a token still passes, because go-sdk's own Host check answers 403 behind authentication. So only the tokenless case notices.
- **L3:** new `test_http_tool_call_needs_token` in both eras.
  - A `tools/call` of `run_show_command` with no token or a wrong one gets 401, and the device logs nothing. The 2025 call goes on a session the right token opened.
  - A control call with the token then runs `show version` once.
  - Mutation with a verifier that accepts any token: fails in both eras (`200 == 401`).
- **N2:** SECURITY.md payload row: "Results have no cap below the 16 MiB frame limit".
- **N3:** SECURITY.md port-squatting row: on Windows a wildcard bind (`0.0.0.0:P` or `[::]:P`) can wait for Fathomgate to stop.
- **Threat model:** row 38 now lists the client-side exposures: an exported or persisted variable, inheritance by tools and hooks, a project `.mcp.json` naming the variable, and `claude mcp get` printing a literal token. Their status is "client side open, documentation only (T0.33)". The OWASP MCP07 line says the same.
- **Docs 2:** install.md has a tested/untested paragraph, with my own wording, because the reviewer's text was not available to me.
  - Tested: Git Bash on Windows 11, Claude Code 2.1.281.
  - Not run: the PowerShell lines in Windows PowerShell 5.1 or 7 (this agent's sandbox refuses `powershell.exe`, and I did not work around it), macOS and Linux terminals, project `.mcp.json` approval, and Cursor or any other client over HTTP.
  - The row 23 run note has the matching evidence.
- **Docs 3:** "If you already added `netdev` over stdio earlier on this page, remove it first with `claude mcp remove netdev`, or use another name."
- **Docs 6:** README "Or start it yourself and let assistants connect over HTTP.", the scoped launch, and "docs/install.md shows how to make the token, the Windows commands and the `.mcp.json` form."
- **Docs 7:** "Fathomgate" in prose on the lines this PR touched: CHANGELOG, test-matrix row 23 and its run note, the SECURITY.md listener, port-squatting and slot rows and bullets, tests/README, and install.md step 3.
- **Docs 8:** the row 23 run note says ADR 0016 names `.mcp.json`, but the same JSON ran through `--mcp-config --strict-mcp-config`.
- **Minor:** "Here is the same entry as JSON, ...".

Locally after the round: `test_http_listener.py` 9 passed on Windows against v1.7.1.

## Look at this first

- The install.md step 3 text: it is the first user-facing HTTP client config, so it should be checked for tone and accuracy. Every command and key in it was run against Claude Code 2.1.281, except a project `.mcp.json` session (it needs the interactive approval). The text says so.

## Deliberately unfinished

- Cursor, Claude Desktop and other clients over HTTP: not run. install.md says so.
- The token scrubber (`[redacted:listen-token:<name>]`) is not exercised by tier 2, because nothing on this path tries to print the token. The tier 1 `TestServeListenProcess` and `TestServeListenRefusals` cover it. Tier 2 checks the outcome: no token in stderr.
- `docs/security/threat-model.md` is unchanged. Row 34 already holds the slot-exhaustion residual that the new SECURITY.md row points to.

## Reproduce green

```sh
go build ./... && go vet ./... && go test -race ./... && make policy-test && make fixtures-check && make status-check && make licences-check
make build
GOBIN=$PWD/.upstream go install github.com/krisiasty/netdev-ssh-mcp@v1.7.1   # or the release binary
cd tests && FATHOMGATE_UPSTREAM=$PWD/../.upstream/netdev-ssh-mcp \
  uv run --extra integration pytest integration -m "tier2 and netdev_ssh_mcp" -v
```

Locally on Windows (no `make`, no cgo): the Makefile gates by hand, `go test ./...` without `-race`, `uv run --extra dev pytest unit -q` (53 passed), actionlint v1.7.12 clean, `render.py --check`.

## Decisions made without an ADR

- The variable name `FATHOMGATE_TOKEN` for the client side, deliberately not `FATHOMGATE_LISTEN_TOKEN`: exporting that one in a shell and then starting `fathomgate serve --listen-token-file` there exits 2 (both sources set). fathomgate never reads `FATHOMGATE_TOKEN`.
- Row 23's Expected cell adds "the token never appears in fathomgate's stderr" and the `[::1]` URL to ADR 0016's wording, as the task asked.

## Questions for the receiver

- install.md now shows the Claude Code commands in both sh and PowerShell. Should the Cursor section get an HTTP form once someone can run it, or should it stay out until then?
