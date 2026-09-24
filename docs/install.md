# Install and connect a client

This page gets an AI client (Claude Code or Cursor) talking to your network
devices through fathomgate. It assumes you know SSH and your devices, and have
not set up MCP before.

## How the pieces fit

MCP (Model Context Protocol) is how an AI client calls tools. An *MCP server*
is a small program that offers tools, for example "run a show command on a
device". The client starts the server as a child process and talks to it
over its stdin and stdout.

fathomgate sits in the middle. The client starts fathomgate, and fathomgate starts
the real MCP server (the *upstream*):

```
Claude Code / Cursor  ->  fathomgate serve  ->  netdev-ssh-mcp  ->  SSH  ->  device
```

The client sees the upstream's tools with the upstream's name in front:
`netdev-ssh-mcp.run_show_command`, `netdev-ssh-mcp.get_config` and so on.

In M0, fathomgate forwards every call without checking it. No policy, no
redaction and no audit log yet; those come in M1 to M4 (see
[ROADMAP.md](../ROADMAP.md)). Use M0 against lab devices only.

## What you need

1. **fathomgate.** Build it with `make build` (the binary is `bin/fathomgate`)
   and copy it somewhere permanent, such as `/usr/local/bin/fathomgate`.
2. **An upstream MCP server.** This guide uses
   [netdev-ssh-mcp](https://github.com/krisiasty/netdev-ssh-mcp) v1.6.6, the
   version fathomgate is tested against. Download
   `netdev-ssh-mcp_1.6.6_<os>_<arch>` from its
   [v1.6.6 release](https://github.com/krisiasty/netdev-ssh-mcp/releases/tag/v1.6.6),
   check it against that release's `checksums.txt`, and make it executable.
   Or build it:

   ```sh
   go install github.com/krisiasty/netdev-ssh-mcp@v1.6.6   # lands in $(go env GOPATH)/bin
   ```

3. **Full paths to both programs.** Run `command -v fathomgate` and
   `command -v netdev-ssh-mcp` and write down what they print (for example
   `/usr/local/bin/fathomgate` and `/Users/you/go/bin/netdev-ssh-mcp`). Use
   these full paths in every config below. The last section explains why.
4. **A `known_hosts` entry for each device.** netdev-ssh-mcp checks SSH host
   keys. SSH to the device once by hand, or use its `trust_host_key` tool.

### Device credentials

fathomgate does not pass its own environment on to the upstream, apart from a
short list (`PATH`, `HOME`, `USER`, `LANG`, `TMPDIR`, the `LC_*` locale
settings). So anything netdev-ssh-mcp needs must be handed over by name.
There are two flags, one for each kind of setting:

- **Not secret:** `--upstream-env NAME=value`. The value is written in
  fathomgate's arguments.
- **Secret:** `--upstream-env-pass NAME`. The value is not in the arguments.
  You set `NAME` in fathomgate's own environment, normally through the
  client's `env` block (shown below), and fathomgate copies it to the
  upstream.

| netdev-ssh-mcp setting | What it is | Pass with |
| --- | --- | --- |
| `DEVICE_USERNAME` | SSH username, if the tool call does not give one | `--upstream-env DEVICE_USERNAME=netops` |
| `DEVICE_PASSWORD` | SSH password | `--upstream-env-pass DEVICE_PASSWORD` |
| `SSH_AUTH_SOCK` | Your ssh-agent socket, to log in with keys instead of a password | `--upstream-env-pass SSH_AUTH_SOCK` |
| `SSH_KNOWN_HOSTS` | Path to a `known_hosts` file, if not `~/.ssh/known_hosts` | `--upstream-env SSH_KNOWN_HOSTS=/Users/you/.ssh/known_hosts` |

Why two flags: a value in fathomgate's arguments can be seen by other users
on the machine (`ps`) and is recorded by process-auditing tools (Linux
`auditd`, Windows event 4688, Sysmon, most EDR agents). A value in the
environment is not. Arguments are fine for a user name or a path, not for a
password.

What `--upstream-env-pass` checks before it starts anything (each failure
exits with status 2 and names the variable, never its value):

- `NAME` must be set in fathomgate's environment and not empty. If the client
  did not pass it, fathomgate says
  `--upstream-env-pass DEVICE_PASSWORD: not set in fathomgate's environment`.
- The same name cannot be given to both `--upstream-env` and
  `--upstream-env-pass`.
- Names starting with `FATHOMGATE_` are refused by both flags: fathomgate's own
  settings are never passed to an upstream.

fathomgate also removes the value from what the upstream prints on stderr:
if the upstream logs the password, the line shows
`[redacted:DEVICE_PASSWORD]` instead. The same goes for an error message
the upstream sends back to the client. This covers the exact value and the
common ways a log writes it (quoted as in Go or JSON, percent-encoded,
Python escapes). A value shorter than 4 bytes is not removed, because it
would match too much ordinary text. Do not rely on this for anything else:
a tool result that contains the password still reaches the client.

The password is still in the client's config file, in the `env` block
instead of the arguments. So:

- Keep that file out of git. A project `.mcp.json` gets committed; use
  `${DEVICE_PASSWORD}` there so it holds no value (Claude Code expands it
  from its own environment; see the Claude Code section).
- Or start fathomgate from a small wrapper script that reads the password from
  your keychain and then runs fathomgate, for example
  `DEVICE_PASSWORD="$(security find-generic-password -s netdev -w)" exec /usr/local/bin/fathomgate "$@"`
  on macOS (or `pass`, `op read`, `secret-tool lookup` elsewhere), and
  point the client's `command` at the script.
- ssh-agent is still better than a password, and use a lab account either
  way.

`SSH_AUTH_SOCK` with `--upstream-env-pass` follows your real agent socket,
so no path is written into the config. It works only if the client itself
has `SSH_AUTH_SOCK` and passes it on to fathomgate. From a terminal it does.
From an app started from the Dock or a desktop menu it depends on the
platform. On macOS, launchd gives every app the system ssh-agent socket
(`launchctl getenv SSH_AUTH_SOCK` shows it), but an agent started from your
shell profile (1Password, Secretive, a plain `ssh-agent`) is not seen. On
Linux it depends on the desktop session. If it is missing, fathomgate stops at
once with the "not set" message above; nothing hangs.

### Leave netdev-ssh-mcp's obfuscation on

fathomgate M0 does not redact anything. Device output reaches the agent
exactly as the upstream sends it, and fathomgate's own redaction arrives in
M2. Until then, do not start netdev-ssh-mcp with `--no-obfuscate`. Its
default obfuscation replaces many secrets in `get_config` and
`run_show_command` output with tokens like `[h:efa1f375d761]`, which is
better than nothing.

It is not a security control. Treat everything the agent sees as if it
contained your secrets:

- The token is a plain, unkeyed SHA-256. Anyone who has the output can hash
  a word list and match it. `[h:efa1f375d761]` is `public`.
- Some lines keep the secret in clear next to a token. For example, in
  `key-string 7 <key>` it is the `7` that gets hashed. Other lines, such as
  `snmp-server host ... <community>`, are not touched at all.

Details, checked against the v1.6.6 source, are in
[docs/research/02-network-mcp-servers.md](research/02-network-mcp-servers.md#update-2026-09-23-the-obfuscation-is-an-unkeyed-hash-with-gaps-t029).
Use lab devices and lab credentials only.

## Claude Code

Add fathomgate with `claude mcp add`. Everything after `--` is the command
Claude Code runs. With ssh-agent, nothing secret is written anywhere:

```sh
claude mcp add netdev -- /usr/local/bin/fathomgate serve \
  --server netdev-ssh-mcp \
  --upstream /Users/you/go/bin/netdev-ssh-mcp \
  --upstream-env DEVICE_USERNAME=netops \
  --upstream-env-pass SSH_AUTH_SOCK
```

With a password, set it in the server's environment with `-e`, and name it
with `--upstream-env-pass`:

```sh
claude mcp add netdev -e DEVICE_PASSWORD=your-lab-password -- /usr/local/bin/fathomgate serve \
  --server netdev-ssh-mcp \
  --upstream /Users/you/go/bin/netdev-ssh-mcp \
  --upstream-env DEVICE_USERNAME=netops \
  --upstream-env-pass DEVICE_PASSWORD
```

`-e` keeps the password out of fathomgate's arguments, but this command line
goes into your shell history, and Claude Code saves the value in its config
file. To avoid the history, edit the config file instead (below).

This saves the server for you only, in this project. Use `--scope project`
to write a `.mcp.json` file that the whole team shares. That file gets
committed, so never put a password in it: write `"${DEVICE_PASSWORD}"` in
its `env` block, and Claude Code fills it in from its own environment when
it starts. The same entry as JSON:

```json
{
  "mcpServers": {
    "netdev": {
      "command": "/usr/local/bin/fathomgate",
      "args": [
        "serve",
        "--server", "netdev-ssh-mcp",
        "--upstream", "/Users/you/go/bin/netdev-ssh-mcp",
        "--upstream-env", "DEVICE_USERNAME=netops",
        "--upstream-env-pass", "DEVICE_PASSWORD"
      ],
      "env": {
        "DEVICE_PASSWORD": "${DEVICE_PASSWORD}"
      }
    }
  }
}
```

In a file that is not shared (`~/.claude.json`, or Cursor's
`~/.cursor/mcp.json`), `"DEVICE_PASSWORD"` may hold the password itself.
For ssh-agent, replace `DEVICE_PASSWORD` with `SSH_AUTH_SOCK` in `args` and
drop the `env` block: the client passes its own `SSH_AUTH_SOCK` to fathomgate.

Run `claude mcp list` (or `/mcp` inside Claude Code) and check that `netdev`
shows as connected. Claude Code shows the tools as
`mcp__netdev__netdev-ssh-mcp_run_show_command` and so on. It swaps the `.`
for `_`, and that is expected.

## Cursor

Cursor reads the same `mcpServers` format from `~/.cursor/mcp.json` (all
projects) or `.cursor/mcp.json` (one project). Use the JSON block from the
Claude Code section, `env` block included. Cursor's MCP documentation
writes environment references as `${env:DEVICE_PASSWORD}` rather than
`${DEVICE_PASSWORD}`; fathomgate's tests do not run Cursor, so check what
your Cursor version expands, or put the value in `~/.cursor/mcp.json`,
which is not shared. Then open Cursor Settings, go to MCP, check that
`netdev` has a green dot, and confirm it lists five tools.

## If the client can't find fathomgate or the upstream

When you start Cursor or Claude Desktop from the Dock or Finder, it does not
read your shell profile. The programs it starts get a very short `PATH`
(often just `/usr/bin:/bin`) or none at all. A config that works from a
terminal can then fail in the app. The fix is always the same: use full
paths.

What goes wrong, and how it looks:

| You wrote | What happens | Message (in the client's MCP log) |
| --- | --- | --- |
| `"command": "fathomgate"` | The client cannot start fathomgate | Depends on the client, often `spawn fathomgate ENOENT` |
| `--upstream netdev-ssh-mcp` (no path) | fathomgate stops at once, exit 1 | `fathomgate: proxy: upstream netdev-ssh-mcp: connect: exec: "netdev-ssh-mcp": executable file not found in $PATH` |
| `--upstream /path/to/a-wrapper` that runs another program by name (as `npx` and `uvx` do) | fathomgate stops at once, exit 1 | a line starting `upstream netdev-ssh-mcp:` that says `not found`, then `fathomgate: proxy: upstream netdev-ssh-mcp: connect: connection closed: calling "initialize": client is closing: EOF` |
| Client started with no `HOME` | netdev-ssh-mcp cannot find `~/.ssh/known_hosts` and stops, exit 1 | `upstream netdev-ssh-mcp: configure ssh client: resolve home directory for known_hosts: $HOME is not defined` |

None of these hang. fathomgate gives up within a second and prints the reason
on stderr.

The fixes:

- Give `command` and `--upstream` as full paths. This works however short
  `PATH` is.
- If the upstream is a wrapper that needs `PATH` (anything started through
  `npx`, `uvx` or a shell script), give it one:
  `--upstream-env PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin`. This
  replaces the `PATH` the upstream would otherwise inherit from fathomgate.
- If the client runs without `HOME`, add
  `--upstream-env SSH_KNOWN_HOSTS=/Users/you/.ssh/known_hosts`.

These cases run as automated tests with an empty `PATH` and with a fully
empty environment (`env -i`): `tests/integration/test_launcher_path.py`.

When the upstream process exits by itself during startup, fathomgate's error
ends with its exit status, for example `; upstream process ended: exit
status 1`. The upstream's own last stderr line, just above, usually says why.

## Point `--upstream` at the server, not at a launcher

Give `--upstream` the program that is the MCP server: the server's own
binary, or for a Python server the interpreter inside its virtual
environment, with the script after `--`: `/path/to/venv/bin/python` on
macOS and Linux, `C:\path\to\venv\Scripts\python.exe` on Windows. Avoid
launchers that start the server as a child of their own: `uvx`, `npx`,
`uv run`, a shell script, `docker run -i`. Two reasons:

- **A slow first start costs you the newer protocol.** fathomgate gives an
  upstream 5 seconds to answer its first `server/discover` probe. An
  upstream that has not answered by then is stopped, started again and
  connected with the older `initialize` handshake (2025-11-25), and it stays
  on that protocol until fathomgate restarts (ADR 0018). A launcher that is
  still downloading or resolving packages on its first run, as `uvx` and
  `npx` do, can take longer than 5 seconds. If you must use one, run it once
  by hand first so its cache is warm.
- **A stopped launcher can leave the server running.** fathomgate stops only
  the process it started. If that process is a launcher, the real server
  underneath can keep running, holding the same credentials you passed with
  `--upstream-env-pass`, next to the copy fathomgate starts for the restart.
  This is an open issue in [the threat model](security/threat-model.md).
  Pointing `--upstream` at the server itself avoids it.

On Windows a virtual environment's `Scripts\python.exe` is itself a small
redirector: it starts the base interpreter as a child process. That child
does not outlive it. Checked on 2026-09-24 with Python 3.13.15, for a venv
made by `python -m venv` and one made by `uv venv`: when the redirector was
terminated the way fathomgate kills an upstream (`TerminateProcess` on the
parent only), the child ended with it. So on Windows the venv's
`Scripts\python.exe` is safe to use as `--upstream`.

## Check it works

Ask the client, in plain words: "Using the netdev tools, run `show version`
on `<a lab device>`, port 22, device type `eos`." The client should call
`netdev-ssh-mcp.run_show_command` (shown as
`mcp__netdev__netdev-ssh-mcp_run_show_command` in Claude Code) and print the
device's output. If you get an error, the client's MCP log shows fathomgate's
stderr, and every line from the upstream starts with
`upstream netdev-ssh-mcp:`.

To try this without a real device, use the fake device that the tests use:

```sh
cd tests
uv run --extra integration python fixtures/device/fake_ssh.py --state-dir /tmp/fakedev --port 22022
# prints READY 22022; writes /tmp/fakedev/known_hosts
```

Then set `--upstream-env DEVICE_USERNAME=admin`,
`--upstream-env DEVICE_PASSWORD=FAKE-device-pass` and
`--upstream-env SSH_KNOWN_HOSTS=/tmp/fakedev/known_hosts`, and ask for
`show version` on host `127.0.0.1`, port `22022`, device type `eos`. The
answer includes `Serial number: FAKE0000SN01`, and `/tmp/fakedev/commands.log`
records the command.

Here the password goes in the arguments with `--upstream-env` only because
`FAKE-device-pass` is a published fake. Do not copy this for a real
password; use `--upstream-env-pass` as in
[Device credentials](#device-credentials).
