# Install and connect a client

This page gets an AI client (Claude Code or Cursor) talking to your network
devices through netguard. It assumes you know SSH and your devices, and have
not set up MCP before.

## How the pieces fit

MCP (Model Context Protocol) is how an AI client calls tools. An *MCP server*
is a small program that offers tools, for example "run a show command on a
device". The client starts the server as a child process and talks to it
over its stdin and stdout.

netguard sits in the middle. The client starts netguard, and netguard starts
the real MCP server (the *upstream*):

```
Claude Code / Cursor  ->  netguard serve  ->  netdev-ssh-mcp  ->  SSH  ->  device
```

The client sees the upstream's tools with the upstream's name in front:
`netdev-ssh-mcp.run_show_command`, `netdev-ssh-mcp.get_config` and so on.

In M0, netguard forwards every call without checking it. No policy, no
redaction and no audit log yet; those come in M1 to M4 (see
[ROADMAP.md](../ROADMAP.md)). Use M0 against lab devices only.

## What you need

1. **netguard.** Build it with `make build` (the binary is `bin/netguard`)
   and copy it somewhere permanent, such as `/usr/local/bin/netguard`.
2. **An upstream MCP server.** This guide uses
   [netdev-ssh-mcp](https://github.com/krisiasty/netdev-ssh-mcp) v1.6.6, the
   version netguard is tested against. Download
   `netdev-ssh-mcp_1.6.6_<os>_<arch>` from its
   [v1.6.6 release](https://github.com/krisiasty/netdev-ssh-mcp/releases/tag/v1.6.6),
   check it against that release's `checksums.txt`, and make it executable.
   Or build it:

   ```sh
   go install github.com/krisiasty/netdev-ssh-mcp@v1.6.6   # lands in $(go env GOPATH)/bin
   ```

3. **Full paths to both programs.** Run `command -v netguard` and
   `command -v netdev-ssh-mcp` and write down what they print (for example
   `/usr/local/bin/netguard` and `/Users/you/go/bin/netdev-ssh-mcp`). Use
   these full paths in every config below. The last section explains why.
4. **A `known_hosts` entry for each device.** netdev-ssh-mcp checks SSH host
   keys. SSH to the device once by hand, or use its `trust_host_key` tool.

### Device credentials

netguard does not pass its own environment on to the upstream, apart from a
short list (`PATH`, `HOME`, `USER`, `LANG`, `TMPDIR`, the `LC_*` locale
settings). So anything netdev-ssh-mcp needs must be handed over with
`--upstream-env NAME=value`:

| netdev-ssh-mcp setting | What it is |
| --- | --- |
| `DEVICE_USERNAME` | SSH username, if the tool call does not give one |
| `DEVICE_PASSWORD` | SSH password |
| `SSH_AUTH_SOCK` | Path to your ssh-agent socket, to log in with keys instead of a password |
| `SSH_KNOWN_HOSTS` | Path to a `known_hosts` file, if not `~/.ssh/known_hosts` |

A password passed this way sits on netguard's command line, where other
users on the machine can see it with `ps`, and in the client's config file.
Prefer ssh-agent. If you must use a password, keep the config out of git
and use a lab account.

## Claude Code

Add netguard with `claude mcp add`. Everything after `--` is the command
Claude Code runs:

```sh
claude mcp add netdev -- /usr/local/bin/netguard serve \
  --server netdev-ssh-mcp \
  --upstream /Users/you/go/bin/netdev-ssh-mcp \
  --upstream-env DEVICE_USERNAME=netops \
  --upstream-env SSH_AUTH_SOCK=/path/to/agent.sock
```

This saves the server for you only, in this project. Use `--scope project`
to write a `.mcp.json` file that the whole team shares. Leave passwords out
of that file, because it gets committed. The same entry as JSON:

```json
{
  "mcpServers": {
    "netdev": {
      "command": "/usr/local/bin/netguard",
      "args": [
        "serve",
        "--server", "netdev-ssh-mcp",
        "--upstream", "/Users/you/go/bin/netdev-ssh-mcp",
        "--upstream-env", "DEVICE_USERNAME=netops",
        "--upstream-env", "SSH_AUTH_SOCK=/path/to/agent.sock"
      ]
    }
  }
}
```

Run `claude mcp list` (or `/mcp` inside Claude Code) and check that `netdev`
shows as connected. Claude Code shows the tools as
`mcp__netdev__netdev-ssh-mcp_run_show_command` and so on. It swaps the `.`
for `_`, and that is expected.

## Cursor

Cursor reads the same `mcpServers` format from `~/.cursor/mcp.json` (all
projects) or `.cursor/mcp.json` (one project). Use the JSON block from the
Claude Code section. Then open Cursor Settings, go to MCP, check that
`netdev` has a green dot, and confirm it lists five tools.

## If the client can't find netguard or the upstream

When you start Cursor or Claude Desktop from the Dock or Finder, it does not
read your shell profile. The programs it starts get a very short `PATH`
(often just `/usr/bin:/bin`) or none at all. A config that works from a
terminal can then fail in the app. The fix is always the same: use full
paths.

What goes wrong, and how it looks:

| You wrote | What happens | Message (in the client's MCP log) |
| --- | --- | --- |
| `"command": "netguard"` | The client cannot start netguard | Depends on the client, often `spawn netguard ENOENT` |
| `--upstream netdev-ssh-mcp` (no path) | netguard stops at once, exit 1 | `netguard: proxy: upstream netdev-ssh-mcp: connect: exec: "netdev-ssh-mcp": executable file not found in $PATH` |
| `--upstream /path/to/a-wrapper` that runs another program by name (as `npx` and `uvx` do) | netguard stops at once, exit 1 | a line starting `upstream netdev-ssh-mcp:` that says `not found`, then `netguard: proxy: upstream netdev-ssh-mcp: connect: connection closed: calling "initialize": client is closing: EOF` |
| Client started with no `HOME` | netdev-ssh-mcp cannot find `~/.ssh/known_hosts` and stops, exit 1 | `upstream netdev-ssh-mcp: configure ssh client: resolve home directory for known_hosts: $HOME is not defined` |

None of these hang. netguard gives up within a second and prints the reason
on stderr.

The fixes:

- Give `command` and `--upstream` as full paths. This works however short
  `PATH` is.
- If the upstream is a wrapper that needs `PATH` (anything started through
  `npx`, `uvx` or a shell script), give it one:
  `--upstream-env PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin`. This
  replaces the `PATH` the upstream would otherwise inherit from netguard.
- If the client runs without `HOME`, add
  `--upstream-env SSH_KNOWN_HOSTS=/Users/you/.ssh/known_hosts`.

These cases run as automated tests with an empty `PATH` and with a fully
empty environment (`env -i`): `tests/integration/test_launcher_path.py`.

## Check it works

Ask the client, in plain words: "Using the netdev tools, run `show version`
on `<a lab device>`, port 22, device type `eos`." The client should call
`netdev-ssh-mcp.run_show_command` (shown as
`mcp__netdev__netdev-ssh-mcp_run_show_command` in Claude Code) and print the
device's output. If you get an error, the client's MCP log shows netguard's
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
