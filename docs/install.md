# Install and connect a client

This page gets an AI client (Claude Code or Cursor) talking to your network
devices through Fathomgate. It assumes you know SSH and your devices, and have
not set up MCP before.

## How the pieces fit

MCP (Model Context Protocol) is how an AI client calls tools. An *MCP server*
is a small program that offers tools, for example "run a show command on a
device". The client starts the server as a child process and talks to it
over its stdin and stdout.

Fathomgate sits in the middle. The client starts Fathomgate, and Fathomgate starts
the real MCP server (the *upstream*):

```
Claude Code / Cursor  ->  fathomgate serve  ->  netdev-ssh-mcp  ->  SSH  ->  device
```

The client sees the upstream's tools with the upstream's name in front:
`netdev-ssh-mcp.run_show_command`, `netdev-ssh-mcp.get_config` and so on.

Fathomgate checks every call against your policy file (`--policy`) before
the upstream sees it: it works out what the call does (a show command, a
configuration change, a free-form command), which devices it names, and what
your policy says about that. A call the policy does not allow never reaches
the upstream, and the agent gets a tool error naming the rule. Redaction of
device output and a signed audit log are not there yet; they come in M2 and
M4 (see [ROADMAP.md](../ROADMAP.md)). Until then, use lab devices.

Upgrading from v0.1.0? It forwarded every call, and `serve` now refuses to
start without `--policy` or `--no-policy`. See
[Upgrading from v0.1.0](#upgrading-from-v010).

## What you need

1. **Fathomgate.** Download it from a
   [release](https://github.com/fathomgate/fathomgate/releases), or build it
   with `make build` (the binary is `bin/fathomgate`). Either way, copy it
   somewhere permanent, such as `/usr/local/bin/fathomgate`.

   A release has one archive per platform
   (`fathomgate_<version>_<os>_<arch>.tar.gz`, `.zip` on Windows), plus
   `checksums.txt` and `checksums.txt.sigstore.json`. Before you unpack
   anything, check the signature on `checksums.txt` with
   [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) v3.
   Then check your archive against `checksums.txt`. For v0.1.0 on
   linux/amd64:

   ```sh
   v=0.1.0
   base=https://github.com/fathomgate/fathomgate/releases/download/v$v
   curl -LO $base/fathomgate_${v}_linux_amd64.tar.gz
   curl -LO $base/checksums.txt
   curl -LO $base/checksums.txt.sigstore.json
   cosign verify-blob --bundle checksums.txt.sigstore.json \
     --certificate-identity https://github.com/fathomgate/fathomgate/.github/workflows/release.yaml@refs/tags/v$v \
     --certificate-oidc-issuer https://token.actions.githubusercontent.com \
     --certificate-github-workflow-trigger push \
     checksums.txt                                  # must print: Verified OK
   sha256sum -c checksums.txt --ignore-missing      # macOS: shasum -a 256 -c checksums.txt --ignore-missing
   tar -xzf fathomgate_${v}_linux_amd64.tar.gz fathomgate
   ```

   The certificate identity pins the signature to this repository's release
   workflow at that exact tag, and the trigger flag to a run started by the
   tag push. For another version, change `v` in both
   places. If cosign prints anything but `Verified OK`, do not use the
   download. On Windows, `Get-FileHash -Algorithm SHA256` gives the hash to
   compare with the zip's line in `checksums.txt`.
2. **An upstream MCP server.** This guide uses
   [netdev-ssh-mcp](https://github.com/krisiasty/netdev-ssh-mcp) v1.7.1, the
   version Fathomgate is tested against. Download
   `netdev-ssh-mcp_1.7.1_<os>_<arch>` from its
   [v1.7.1 release](https://github.com/krisiasty/netdev-ssh-mcp/releases/tag/v1.7.1),
   check it against that release's `checksums.txt`, and make it executable.
   Or build it:

   ```sh
   go install github.com/krisiasty/netdev-ssh-mcp@v1.7.1   # lands in $(go env GOPATH)/bin
   ```

   Do not use an older version:

   - v1.6.6 and earlier leave some secrets in clear, and hide others with a
     hash that a word list reverses
     ([GHSA-8g43-jrf3-q9vq](https://github.com/krisiasty/netdev-ssh-mcp/security/advisories/GHSA-8g43-jrf3-q9vq),
     fixed in v1.7.0).
   - v1.7.0 and earlier let a `run_show_command`, `run_ping` or
     `run_traceroute` call make the device run further commands, which could
     change its configuration or write files on it
     ([GHSA-h47r-329w-6p9h](https://github.com/krisiasty/netdev-ssh-mcp/security/advisories/GHSA-h47r-329w-6p9h),
     fixed in v1.7.1).

   Fathomgate's policy is one layer; keep the upstream's own checks as
   another. Log in to devices with a read-only account as well, so that no
   command sent through the server can change a device.

3. **A policy file and an inventory of your devices.** A release archive
   has the example policies in `policies/examples/` and an example
   inventory, `inventory.example.yaml`; with `make build` they are in the
   repository. Copy one policy and the inventory somewhere permanent:

   ```sh
   mkdir -p ~/.config/fathomgate
   cp policies/examples/read-only.yaml ~/.config/fathomgate/policy.yaml
   cp inventory.example.yaml ~/.config/fathomgate/inventory.yaml
   ```

   `read-only.yaml` allows show commands, configuration reads and inventory
   listings on devices it knows, and denies configuration changes,
   free-form commands, lab and local admin actions. Edit `inventory.yaml` so
   it lists your devices by name, exactly as the agent will name them. A
   device that is not listed is unknown, and every example policy denies
   every call to an unknown device. `fathomgate inventory import --csv
   devices.csv --out inventory.yaml` builds the file from a spreadsheet or
   IPAM export; `--inventory` takes the YAML file, not the CSV. Ask the
   policy what it would decide with `fathomgate policy eval` (see the
   README) before an agent does.

   Fathomgate also needs a *profile* for the upstream: which of its tools
   read, which write, and which arguments name a device. The profiles for
   the servers it has been checked against are built into the binary, and
   `fathomgate version` lists their server keys. Pass one of those keys as
   `--server` (`netdev-ssh-mcp` here). With a `--server` that has no
   profile, Fathomgate denies every call that carries arguments (rule
   `default:bad_arguments`) and warns at start; use a key that `fathomgate
   version` lists, or add a profile with `--profiles <dir>`.

   Fathomgate refuses to start if another user can change the policy, the
   inventory or a `--profiles` file: they decide what reaches your devices.
   Keep them in a directory only you (and the administrators) can write,
   because a user who can write the directory can replace a file in it
   even when the file itself is protected.

   On macOS and Linux:

   ```sh
   chmod 700 ~/.config/fathomgate
   chmod go-w ~/.config/fathomgate/*.yaml
   ```

   Debian and Ubuntu give users a umask of 002, so files you create there
   are group-writable and Fathomgate refuses them until you run the
   `chmod go-w` above (or set `umask 022` first). A Linux ACL entry that
   lets another user write the file shows as the group write bit and is
   refused the same way.

   On Windows, only you, SYSTEM and Administrators may be able to write
   the files. Keep them in `%USERPROFILE%\.config\fathomgate`, or for a
   service in `C:\ProgramData\fathomgate` writable only by Administrators
   and SYSTEM. If other accounts can write a file, Fathomgate names every
   one of them and prints the commands that fix it, one per line, for
   example:

   ```text
   icacls "C:\Users\you\.config\fathomgate\policy.yaml" /inheritance:r /grant:r "*S-1-5-21-...-1001:F" "*S-1-5-18:F" "*S-1-5-32-544:F"
   icacls "C:\Users\you\.config\fathomgate\policy.yaml" /remove:g "*S-1-5-11"
   ```

   The accounts are named by SID, so the lines work in Command Prompt and
   in PowerShell; run them one at a time. The second line appears only
   when an account was given access to the file itself rather than
   through its folder. If the path holds a character outside letters,
   digits, spaces and `\ / : . _ - ( ) [ ] { } + , = @ # ~ ' & ^` (for
   example `%`, `!`, `$` or a curly quote), Fathomgate describes the fix
   instead of printing a command.

4. **Full paths to all of these.** Run `command -v fathomgate` and
   `command -v netdev-ssh-mcp` and write down what they print (for example
   `/usr/local/bin/fathomgate` and `/Users/you/go/bin/netdev-ssh-mcp`). Use
   these full paths in every config below. The last section explains why.
5. **A `known_hosts` entry for each device.** netdev-ssh-mcp checks SSH host
   keys. SSH to the device once by hand, or use its `trust_host_key` tool.

### Device credentials

Fathomgate does not pass its own environment on to the upstream, apart from a
short list (`PATH`, `HOME`, `USER`, `LANG`, `TMPDIR`, the `LC_*` locale
settings). So anything netdev-ssh-mcp needs must be handed over by name.
There are two flags, one for each kind of setting:

- **Not secret:** `--upstream-env NAME=value`. The value is written in
  Fathomgate's arguments.
- **Secret:** `--upstream-env-pass NAME`. The value is not in the arguments.
  You set `NAME` in Fathomgate's own environment, normally through the
  client's `env` block (shown below), and Fathomgate copies it to the
  upstream.

| netdev-ssh-mcp setting | What it is | Pass with |
| --- | --- | --- |
| `DEVICE_USERNAME` | SSH username, if the tool call does not give one | `--upstream-env DEVICE_USERNAME=netops` |
| `DEVICE_PASSWORD` | SSH password | `--upstream-env-pass DEVICE_PASSWORD` |
| `SSH_AUTH_SOCK` | Your ssh-agent socket, to log in with keys instead of a password | `--upstream-env-pass SSH_AUTH_SOCK` |
| `SSH_KNOWN_HOSTS` | Path to a `known_hosts` file, if not `~/.ssh/known_hosts` | `--upstream-env SSH_KNOWN_HOSTS=/Users/you/.ssh/known_hosts` |
| `OBFUSCATION_KEY_FILE` | Optional. Path to a key file, only if netdev-ssh-mcp's secret tokens must match across runs; keep the file where the agent's tools cannot read it (see [below](#leave-netdev-ssh-mcps-obfuscation-on)) | `--upstream-env OBFUSCATION_KEY_FILE=/Users/you/.config/netdev-ssh-mcp.key` |
| `OBFUSCATION_KEY` | Optional. The same key as a value. Never put it in a client's `env` block; set it from a wrapper script that reads your keychain | `--upstream-env-pass OBFUSCATION_KEY` |

Why two flags: a value in Fathomgate's arguments can be seen by other users
on the machine (`ps`) and is recorded by process-auditing tools (Linux
`auditd`, Windows event 4688, Sysmon, most EDR agents). A value in the
environment is not. Arguments are fine for a user name or a path, not for a
password.

What `--upstream-env-pass` checks before it starts anything (each failure
exits with status 2 and names the variable, never its value):

- `NAME` must be set in Fathomgate's environment and not empty. If the client
  did not pass it, Fathomgate says
  `--upstream-env-pass DEVICE_PASSWORD: not set in fathomgate's environment`.
- The same name cannot be given to both `--upstream-env` and
  `--upstream-env-pass`.
- Names starting with `FATHOMGATE_` are refused by both flags: Fathomgate's own
  settings are never passed to an upstream.

Fathomgate also removes the value from what the upstream prints on stderr:
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
- Or start Fathomgate from a small wrapper script that reads the password from
  your keychain and then runs Fathomgate, for example
  `DEVICE_PASSWORD="$(security find-generic-password -s netdev -w)" exec /usr/local/bin/fathomgate "$@"`
  on macOS (or `pass`, `op read`, `secret-tool lookup` elsewhere), and
  point the client's `command` at the script.
- ssh-agent is still better than a password, and use a lab account either
  way.

`SSH_AUTH_SOCK` with `--upstream-env-pass` follows your real agent socket,
so no path is written into the config. It works only if the client itself
has `SSH_AUTH_SOCK` and passes it on to Fathomgate. From a terminal it does.
From an app started from the Dock or a desktop menu it depends on the
platform. On macOS, launchd gives every app the system ssh-agent socket
(`launchctl getenv SSH_AUTH_SOCK` shows it), but an agent started from your
shell profile (1Password, Secretive, a plain `ssh-agent`) is not seen. On
Linux it depends on the desktop session. If it is missing, Fathomgate stops at
once with the "not set" message above; nothing hangs.

### Leave netdev-ssh-mcp's obfuscation on

Fathomgate does not redact anything yet. Device output reaches the agent
exactly as the upstream sends it, and Fathomgate's own redaction arrives in
M2. Until then, do not start netdev-ssh-mcp with `--no-obfuscate`. Its
default obfuscation replaces secrets in `get_config` and `run_show_command`
output with tokens like `[h:3c91e0a47b2d]`. Since v1.7.0 each token is a
keyed hash (HMAC-SHA256), so it cannot be matched against guessed values
without the key.

Leave the key at its default unless you need tokens to match across runs.
By default netdev-ssh-mcp picks a random key each time it starts and keeps
it only in its own memory. Nothing, the agent included, can read it, so this
is the safest setting. Tokens match within one run, not across runs. Every
result that holds a token ends with a note from netdev-ssh-mcp saying so and
suggesting a key. The note is harmless; the agent may pass the suggestion on,
and you can ignore it.

A key file makes tokens stable across runs and machines, and it makes the key
something that can be stolen. Anyone who has the key and a transcript can
check guessed values against the tokens offline, which is the weakness
GHSA-8g43-jrf3-q9vq fixed. If you need one anyway:

- Keep it where the agent's tools cannot read it: outside every project and
  workspace the agent works in, covered by your client's deny rules for file
  reads, and ideally owned by a separate OS user that Fathomgate runs as.
- Pass its path with `--upstream-env OBFUSCATION_KEY_FILE=<full path>`
  (clients do not expand `~`). The path is not secret; the file is.
- Never put the key itself in a client config's `env` block. If you pass it
  as a value with `--upstream-env-pass OBFUSCATION_KEY`, set it from a
  wrapper script that reads your keychain (see
  [Device credentials](#device-credentials)). Use a file or a value, not
  both: netdev-ssh-mcp exits at startup if both are set, or if the key is
  shorter than 16 bytes.

To make a key file (then add the file to your client's deny rules for reads):

```sh
mkdir -p ~/.config
# only you can read it
(umask 077 && openssl rand -hex 32 > ~/.config/netdev-ssh-mcp.key)
```

The examples below use the default per-run key. If you need stable tokens,
add `--upstream-env OBFUSCATION_KEY_FILE=<full path>` to Fathomgate's
arguments in them.

Obfuscation is still not Fathomgate's redaction. Treat everything the agent
sees as if it contained your secrets:

- It replaces only the secrets on lines its patterns know. A secret on any
  other line reaches the agent in clear.
- Output collected with v1.6.6 or earlier may hold secrets in clear, or as
  tokens that a word list reverses. The advisory
  ([GHSA-8g43-jrf3-q9vq](https://github.com/krisiasty/netdev-ssh-mcp/security/advisories/GHSA-8g43-jrf3-q9vq))
  says to treat it as sensitive and to consider rotating secrets whose output
  left your control.

The v1.6.6 findings and what v1.7.1 changed, checked against the source and
run against Fathomgate's redaction fixtures, are in
[profiles/netdev-ssh-mcp.yaml](../profiles/netdev-ssh-mcp.yaml) and
[docs/research/02-network-mcp-servers.md](research/02-network-mcp-servers.md#update-2026-09-25-v171-keys-the-hash-and-closes-the-gaps-t051).
Use lab devices and lab credentials only.

## Claude Code

Add Fathomgate with `claude mcp add`. Everything after `--` is the command
Claude Code runs. With ssh-agent, nothing secret is written anywhere:

```sh
claude mcp add netdev -- /usr/local/bin/fathomgate serve \
  --server netdev-ssh-mcp \
  --upstream /Users/you/go/bin/netdev-ssh-mcp \
  --policy /Users/you/.config/fathomgate/policy.yaml \
  --inventory /Users/you/.config/fathomgate/inventory.yaml \
  --upstream-env DEVICE_USERNAME=netops \
  --upstream-env-pass SSH_AUTH_SOCK
```

With a password, set it in the server's environment with `-e`, and name it
with `--upstream-env-pass`:

```sh
claude mcp add netdev -e DEVICE_PASSWORD=your-lab-password -- /usr/local/bin/fathomgate serve \
  --server netdev-ssh-mcp \
  --upstream /Users/you/go/bin/netdev-ssh-mcp \
  --policy /Users/you/.config/fathomgate/policy.yaml \
  --inventory /Users/you/.config/fathomgate/inventory.yaml \
  --upstream-env DEVICE_USERNAME=netops \
  --upstream-env-pass DEVICE_PASSWORD
```

`-e` keeps the password out of Fathomgate's arguments, but this command line
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
        "--policy", "/Users/you/.config/fathomgate/policy.yaml",
        "--inventory", "/Users/you/.config/fathomgate/inventory.yaml",
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
drop the `env` block: the client passes its own `SSH_AUTH_SOCK` to Fathomgate.

Run `claude mcp list` (or `/mcp` inside Claude Code) and check that `netdev`
shows as connected. Claude Code shows the tools as
`mcp__netdev__netdev-ssh-mcp_run_show_command` and so on. It swaps the `.`
for `_`, and that is expected.

Ask the agent to run `show version` on a device in your inventory, then on
one that is not. The first comes back from the device. The second comes back
as a tool error, `fathomgate denied netdev-ssh-mcp.run_show_command: rule
default:unknown_target (class READ_OPERATIONAL): target not in inventory`,
and never reaches the upstream. Fathomgate writes one `msg=decision` line to
its stderr for every call; Claude Code keeps a
server's stderr in its MCP logs (`claude --debug`).

## Claude Desktop

Claude Desktop reads the same `mcpServers` block from
`claude_desktop_config.json` (Settings, Developer, Edit Config). Use the JSON
block from the Claude Code section with full paths for every file, since
Claude Desktop does not start Fathomgate from your shell. Fathomgate's tests
do not run Claude Desktop, so check whether your version expands
`${DEVICE_PASSWORD}` in `env`; if not, use ssh-agent (`SSH_AUTH_SOCK`), or
put the value in the file, which is yours alone. Restart Claude Desktop
after editing the file.

## Cursor

Cursor reads the same `mcpServers` format from `~/.cursor/mcp.json` (all
projects) or `.cursor/mcp.json` (one project). Use the JSON block from the
Claude Code section, `env` block included. Cursor's MCP documentation
writes environment references as `${env:DEVICE_PASSWORD}` rather than
`${DEVICE_PASSWORD}`; Fathomgate's tests do not run Cursor, so check what
your Cursor version expands, or put the value in `~/.cursor/mcp.json`,
which is not shared. Then open Cursor Settings, go to MCP, check that
`netdev` has a green dot, and confirm it lists five tools.

## Remote agents over HTTP

Instead of letting the client start Fathomgate, you can start Fathomgate
yourself and have clients connect to it over HTTP. That helps when an app
cannot start programs, or when several clients should share one Fathomgate.

This has three limits, on purpose:

- Fathomgate listens on this computer only (`127.0.0.1`, `localhost` or
  `[::1]`, and no other address, not even another `127.x.x.x`). Other
  machines cannot connect, and it refuses any other address. Listening on a network waits for M2, when
  Fathomgate gains built-in TLS. Whichever of the three you give, Fathomgate
  takes the port on both `127.0.0.1` and `[::1]`, so that no other user of this
  computer can take the other one and collect tokens from clients that try
  it first.
- Every request must carry a token, a long random password that you make.
  Anyone who has the token can use your devices through Fathomgate, so
  treat it like a device password.
- It needs `--policy` (or `--no-policy`) like every `serve`. Use it
  against lab devices until redaction arrives (M2).

**1. Make a token file for each client, that only you can read.** Name
the file after the client that will use it. Here that is Claude Code. On
macOS or Linux:

```sh
mkdir -p ~/.config/fathomgate
(umask 077; openssl rand -hex 32 > ~/.config/fathomgate/claude-code.token)
```

On Windows, in PowerShell (not as administrator, because a file an
administrator shell creates can belong to the Administrators group, and
Fathomgate refuses a token file that does not belong to you):

```powershell
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
$token = -join ($bytes | ForEach-Object { $_.ToString('x2') })
Set-Content -NoNewline -Path "$HOME\fathomgate-claude-code.token" -Value $token
icacls "$HOME\fathomgate-claude-code.token" /inheritance:r /grant:r "${env:USERNAME}:F"
```

Fathomgate refuses to start if other users could read or change the file,
and tells you which command fixes it (`chmod 600`, `chmod -N` for a macOS
access control list, or `icacls`).

**2. Start Fathomgate with `--listen`.** Use the same `serve` flags as in
the sections above, plus `--listen` and the token file:

```sh
fathomgate serve --listen 127.0.0.1:8931 \
  --listen-token-file claude-code=$HOME/.config/fathomgate/claude-code.token \
  --server netdev-ssh-mcp \
  --upstream /Users/you/go/bin/netdev-ssh-mcp \
  --policy ~/.config/fathomgate/policy.yaml \
  --inventory ~/.config/fathomgate/inventory.yaml \
  --upstream-env DEVICE_USERNAME=netops \
  --upstream-env-pass SSH_AUTH_SOCK
```

It prints one `listening` line for each address it listens on:

```text
time=... level=INFO msg=listening url=http://127.0.0.1:8931/mcp server=netdev-ssh-mcp principals=claude-code upstream_env_pass=SSH_AUTH_SOCK policy=/Users/you/.config/fathomgate/policy.yaml rules=4 inventory=/Users/you/.config/fathomgate/inventory.yaml devices=12 profiles=embedded profile=netdev-ssh-mcp.yaml
time=... level=INFO msg=listening url=http://[::1]:8931/mcp server=netdev-ssh-mcp principals=claude-code upstream_env_pass=SSH_AUTH_SOCK policy=/Users/you/.config/fathomgate/policy.yaml rules=4 inventory=/Users/you/.config/fathomgate/inventory.yaml devices=12 profiles=embedded profile=netdev-ssh-mcp.yaml
```

Port `0` picks a free port, and the lines then show which one. If another
program already holds the port on either address, Fathomgate stops with
status 1 and names the address: stop that program or pick another port. On
a computer without IPv6 it prints a warning and one `listening` line.

`claude-code` is a name for the token. It appears in Fathomgate's log so
that you can tell clients apart. Give each client its own token file and
name by repeating `--listen-token-file`, for example
`--listen-token-file cursor=$HOME/.config/fathomgate/cursor.token`. The
name is only a label. It does not prove which person is using it.

Fathomgate reads the token files once, when it starts. To take a token
away from a client, remove its `--listen-token-file` entry (or put a new
token in its file) and restart Fathomgate. Deleting the file while
Fathomgate runs changes nothing: the old token keeps working until the
restart. That is one more reason to give each client its own file.

Clients that share a token can also push each other out. Each token has
4 sessions. When a client connects and all 4 are taken, Fathomgate ends
that token's session that has been idle longest, so an agent that
crashed or restarted can connect again at once. With a shared token, that
idle session can belong to another client, which then has to reconnect. If
the server behind Fathomgate asks the human questions (elicitation),
Fathomgate refuses those questions to the reconnected client for up to 5
minutes. It does this because it cannot tell whether a question belongs to
a call the old session had already ended. One token per client avoids
all of this.

If your system hands secrets to programs in environment variables instead
of files, put the token in `FATHOMGATE_LISTEN_TOKEN` and leave out
`--listen-token-file`. Its name in the log is `env`. Never put the token on
the command line: Fathomgate has no flag for it.

**3. Point the client at the URL.** Paste the exact URL from a `listening`
line into the client config, for example `http://127.0.0.1:8931/mcp`,
rather than typing `localhost`: an address written out means the client
connects where Fathomgate listens and nowhere else. The client connects to
it as a Streamable HTTP (sometimes just "HTTP") MCP server, and sends the
header `Authorization: Bearer <token>` with every request. Browser-based
clients cannot connect: Fathomgate refuses every request that comes from a
web page.

For Claude Code, add the server once, with the URL from your `listening`
line. If you already added `netdev` over stdio earlier on this page, remove
it first with `claude mcp remove netdev`, or use another name.

```sh
claude mcp add --transport http netdev http://127.0.0.1:8931/mcp \
  --header 'Authorization: Bearer ${CLAUDE_FATHOMGATE_TOKEN}'
```

Keep the single quotes. They stop your shell from filling in the variable,
so Claude Code saves the text `${CLAUDE_FATHOMGATE_TOKEN}`, not the token,
and fills in the value from its own environment each time it connects.
`claude mcp get netdev` then shows `Authorization: Bearer
${CLAUDE_FATHOMGATE_TOKEN}`, not the token.

Then start Claude Code with the token in its environment, and in nothing
else's:

```sh
CLAUDE_FATHOMGATE_TOKEN="$(cat ~/.config/fathomgate/claude-code.token)" claude
```

That sets the variable for that one `claude` process. Your shell does not
keep it. On Windows, open a PowerShell window that you use only to start
Claude Code, and run:

```powershell
$env:CLAUDE_FATHOMGATE_TOKEN = Get-Content "$HOME\fathomgate-claude-code.token"
claude
```

Close that window when you are done with Claude Code.

Keep the token out of everywhere else:

- Never put the variable in `~/.zshrc`, `~/.bashrc`, your PowerShell
  `$PROFILE` or `setx`, and never `export` it in a shell you use for other
  work. A variable set there reaches every program you start, and
  everything Claude Code starts inherits it: its Bash tool, hooks and
  stdio MCP servers.
- Claude Code fills `${CLAUDE_FATHOMGATE_TOKEN}` into any server entry that
  names it. A project's `.mcp.json` that names it would send your token to
  whatever `url` that file gives. Approve a project's MCP servers only after
  you have read their `url` and `headers`.
- Pick the variable name with care. `CLAUDE_FATHOMGATE_TOKEN` is only a
  name; Fathomgate never reads it. Any name of your own works, with two
  exceptions:
  - Don't use `FATHOMGATE_LISTEN_TOKEN`. That is the variable Fathomgate
    reads its own token from. If it is set where you start
    `fathomgate serve --listen-token-file ...`, Fathomgate exits with
    status 2 and says both are set.
  - Don't use a credential variable that Claude Code never sends to a
    remote server, such as `ANTHROPIC_API_KEY`. Claude Code sends an empty
    `Bearer` instead, Fathomgate answers 401, and Claude Code gives no
    warning about the variable
    ([Claude Code's MCP docs](https://code.claude.com/docs/en/mcp#credential-variables-that-read-as-empty)).
- Use `--scope local` (the default) or `--scope user` for your own setup.
  Never use `--scope project` with the token pasted into the header: that
  writes the token itself into `.mcp.json`. If you paste the token into
  `claude mcp add` at all, it lands in your shell history and in
  `~/.claude.json`, and `claude mcp get netdev` prints it.

Here is the same entry as JSON, for a project's `.mcp.json`
(`--scope project`) or a file you pass with `claude --mcp-config`. It holds
the variable's name, not the token:

```json
{
  "mcpServers": {
    "netdev": {
      "type": "http",
      "url": "http://127.0.0.1:8931/mcp",
      "headers": {
        "Authorization": "Bearer ${CLAUDE_FATHOMGATE_TOKEN}"
      }
    }
  }
}
```

A committed entry like this still sends each person's own token to that
port on their own computer. If Fathomgate is not running there and another
user of that computer holds the port, that program receives the token (see
the port-squatting row in [SECURITY.md](../SECURITY.md#proxy-transport-m0-gaps)).
Share it only with people who run Fathomgate on that port.

To check it, run `/mcp` inside Claude Code, or in another terminal
`CLAUDE_FATHOMGATE_TOKEN="$(cat ~/.config/fathomgate/claude-code.token)" claude mcp list`.
`netdev` should show `✔ Connected`. If it shows `Failed to connect — Server
rejected the configured Authorization header (HTTP 401)`, the token did not
arrive. Check that Claude Code was started with `CLAUDE_FATHOMGATE_TOKEN`
set (without it, `claude mcp list` also warns `Missing environment
variables: CLAUDE_FATHOMGATE_TOKEN`) and that the token matches the file
Fathomgate read when it started. The tools show up as
`mcp__netdev__netdev-ssh-mcp_run_show_command` and so on, as over stdio.

What we tested, with Claude Code 2.1.281 on Windows 11, in Git Bash: the
`claude mcp add` command above, and `claude mcp list` and `claude mcp get`
started with the variable as shown. We also ran a headless session with
the JSON file through `claude --mcp-config` on both `listening` URLs. It
listed the five tools and ran `show version` on the test device. We have
not run the PowerShell lines in Windows PowerShell 5.1 or PowerShell 7. We
have not tested a macOS or Linux terminal, approving a project's
`.mcp.json`, or Cursor or any other client over HTTP. Any client that can
send a header with each request should work the same way.

**4. Stop it** with Ctrl+C (or SIGTERM). Fathomgate gives calls in progress
up to 5 seconds to finish, then stops. Press Ctrl+C a second time to stop
it at once; the upstream server may then be left running. If the upstream
server exits, Fathomgate stops too and exits with status 1, so run it under
something that restarts it (systemd, launchd, a Windows service wrapper) if
clients depend on it.

Have that supervisor restart Fathomgate straight away, with no delay or
back-off. While Fathomgate is not running, another user of this computer
can take its port, and a client that keeps retrying will send that program
its token: the client has no way to tell it is not Fathomgate. Fathomgate
refuses to start if it finds its port taken, so the log shows it when this
happens. M2 closes the gap with TLS and a pinned certificate, or a socket
file that only you can open.

## If the client can't find Fathomgate or the upstream

When you start Cursor or Claude Desktop from the Dock or Finder, it does not
read your shell profile. The programs it starts get a very short `PATH`
(often just `/usr/bin:/bin`) or none at all. A config that works from a
terminal can then fail in the app. The fix is always the same: use full
paths.

What goes wrong, and how it looks:

| You wrote | What happens | Message (in the client's MCP log) |
| --- | --- | --- |
| `"command": "fathomgate"` | The client cannot start Fathomgate | Depends on the client, often `spawn fathomgate ENOENT` |
| `--upstream netdev-ssh-mcp` (no path) | Fathomgate stops at once, exit 1 | `fathomgate: proxy: upstream netdev-ssh-mcp: connect: exec: "netdev-ssh-mcp": executable file not found in $PATH` |
| `--upstream /path/to/a-wrapper` that runs another program by name (as `npx` and `uvx` do) | Fathomgate stops at once, exit 1 | a line starting `upstream netdev-ssh-mcp:` that says `not found`, then `fathomgate: proxy: upstream netdev-ssh-mcp: connect: connection closed: calling "initialize": client is closing: EOF` |
| Client started with no `HOME` | netdev-ssh-mcp cannot find `~/.ssh/known_hosts` and stops, exit 1 | `upstream netdev-ssh-mcp: configure ssh client: resolve home directory for known_hosts: $HOME is not defined` |

None of these hang. Fathomgate gives up within a second and prints the reason
on stderr.

The fixes:

- Give `command` and `--upstream` as full paths. This works however short
  `PATH` is.
- If the upstream is a wrapper that needs `PATH` (anything started through
  `npx`, `uvx` or a shell script), give it one:
  `--upstream-env PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin`. This
  replaces the `PATH` the upstream would otherwise inherit from Fathomgate.
- If the client runs without `HOME`, add
  `--upstream-env SSH_KNOWN_HOSTS=/Users/you/.ssh/known_hosts`.

These cases run as automated tests with an empty `PATH` and with a fully
empty environment (`env -i`): `tests/integration/test_launcher_path.py`.

When the upstream process exits by itself during startup, Fathomgate's error
ends with its exit status, for example `; upstream process ended: exit
status 1`. The upstream's own last stderr line, just above, usually says why.

## Point `--upstream` at the server, not at a launcher

Give `--upstream` the program that is the MCP server: the server's own
binary, or for a Python server the interpreter inside its virtual
environment, with the script after `--`: `/path/to/venv/bin/python` on
macOS and Linux, `C:\path\to\venv\Scripts\python.exe` on Windows. Avoid
launchers that start the server as a child of their own: `uvx`, `npx`,
`uv run`, a shell script, `docker run -i`. Two reasons:

- **A slow first start costs you the newer protocol.** Fathomgate gives an
  upstream 5 seconds to answer its first `server/discover` probe. An
  upstream that has not answered by then is stopped, started again and
  connected with the older `initialize` handshake (2025-11-25), and it stays
  on that protocol until Fathomgate restarts (ADR 0018). A launcher that is
  still downloading or resolving packages on its first run, as `uvx` and
  `npx` do, can take longer than 5 seconds. If you must use one, run it once
  by hand first so its cache is warm.
- **A stopped launcher can leave the server running.** Fathomgate starts the
  upstream in a process group of its own (Linux, macOS) or a Job Object of
  its own (Windows), and stops that whole tree on a restart, a failed start
  and shutdown ([ADR 0021](adr/0021-kill-the-upstream-process-tree.md)). A
  server that stays in the tree is stopped with its launcher. That has not
  yet been checked for `uvx`, `npx` and `uv run` on each system, and it
  never covers `docker run -i` (the container belongs to Docker, not to the
  `docker` command) or a launcher that detaches its server (`setsid`, a
  daemon). A server that escapes can keep running, holding the same
  credentials you passed with `--upstream-env-pass`, next to the copy
  Fathomgate starts for the restart. On Linux and macOS, if Fathomgate
  itself is killed, the tree is left running; run Fathomgate under systemd,
  which stops everything the service started. Pointing `--upstream` at the
  server itself avoids all of this.

On Windows a virtual environment's `Scripts\python.exe` is itself a small
redirector: it starts the base interpreter as a child process. That child
does not outlive it. Checked on 2026-09-24 with Python 3.13.15, for a venv
made by `python -m venv` and one made by `uv venv`: when the redirector was
terminated with `TerminateProcess` on the parent only (how Fathomgate
killed an upstream before ADR 0021), the child ended with it. Since ADR
0021 the child is also in the upstream's job. So on Windows the venv's
`Scripts\python.exe` is safe to use as `--upstream`.

## Upgrading from v0.1.0

v0.1.0 forwarded every call with no policy, and refused `--policy`. Since
v0.2.0, `fathomgate serve` needs one of two flags and exits with status 2,
before it starts the upstream, if it has neither:

- Add `--policy <file> --inventory <file>`, and check that `--server` is a
  server key that `fathomgate version` lists (for example
  `netdev-ssh-mcp`). A `--server` name with no profile denies every call
  that carries arguments. This is what the snippets above do.
- Or add `--no-policy` to keep v0.1.0's pass-through: every call is
  forwarded unchecked. Fathomgate logs a warning saying so at every start.
  Use it for protocol testing, not in front of devices you care about.

`fathomgate version` now prints more lines: the built-in profiles follow the
version line. The policy and inventory files must not be writable by other
users (see step 3 of [What you need](#what-you-need)).

`--inventory` and `--profiles` work only with `--policy`, and `--policy`
with `--no-policy` is an error. `--audit` is still refused: the signed
audit log arrives in M4, and until then every decision is one
`msg=decision` line on Fathomgate's stderr. Nothing else in the command line
changes.

At start, Fathomgate logs a warning for anything in your files that will not
do what it seems to: no `--inventory` (every device is unknown), a server
with no profile (calls with arguments are denied), `unknown_target: allow`
in the policy, a hostname pattern in the inventory that matches no listed
device, an obligation that is not enforced yet, and a `hold` rule, whose
calls are not run until approvals arrive (M3). A `roles:` pattern only
adds a role, site or tags to a device you list by name; it never makes a
name known ([ADR 0031](adr/0031-hostname-patterns-never-make-a-target-known.md)).
`fathomgate inventory lint inventory.yaml` fails on a pattern that matches
no listed device, and `fathomgate inventory resolve <name>` shows where
each of a device's fields came from.

## Running Fathomgate in a container

If you run Fathomgate itself in a container (the distroless image), start
it with an init process: `docker run --init`, or `init: true` in Compose.
Without one, Fathomgate is PID 1 and nothing reaps the processes its
upstream's tree leaves behind when they exit. They stay as zombies, and
while they are there Fathomgate cannot tell that the tree has emptied, so
stopping an upstream takes up to 2 seconds longer
([ADR 0021](adr/0021-kill-the-upstream-process-tree.md)).

## Check it works

Ask the client, in plain words: "Using the netdev tools, run `show version`
on `<a lab device>`, port 22, device type `eos`." The client should call
`netdev-ssh-mcp.run_show_command` (shown as
`mcp__netdev__netdev-ssh-mcp_run_show_command` in Claude Code) and print the
device's output. If you get an error, the client's MCP log shows Fathomgate's
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
`--upstream-env SSH_KNOWN_HOSTS=/tmp/fakedev/known_hosts`, add the fake
device to your inventory by the name the agent will use:

```yaml
devices:
  - name: 127.0.0.1
    role: lab
    tags: [lab]
```

and ask for `show version` on host `127.0.0.1`, port `22022`, device type
`eos`. The answer includes `Serial number: FAKE0000SN01`, and
`/tmp/fakedev/commands.log` records the command. Then ask for `reload` on the
same host: with `read-only.yaml` the agent gets `fathomgate denied
netdev-ssh-mcp.run_show_command: rule no-exec (class EXEC_ARBITRARY):
EXEC_ARBITRARY is denied: the call runs commands outside the read allow-list
or outside configuration mode`, and `commands.log` has no new line.

Here the password goes in the arguments with `--upstream-env` only because
`FAKE-device-pass` is a published fake. Do not copy this for a real
password; use `--upstream-env-pass` as in
[Device credentials](#device-credentials).
