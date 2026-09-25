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
