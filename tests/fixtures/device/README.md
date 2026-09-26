# Fake device

`fake_ssh.py` is an asyncssh server that stands in for a network device in
tier 2, so a real upstream MCP server can run a real SSH session without a
real device. See the module docstring for its command line.

What it does today (T0.5, T0.34):

- The SSH exec channel, which is what netdev-ssh-mcp v1.6.6 and v1.7.1 use.
- An interactive shell (a PTY and the prompt `fake-eos#`, set with
  `--hostname`), which is what netmiko uses for upa/mcp-netmiko-server with
  `device_type = "arista_eos"`. Input is echoed and each line is one
  command. `terminal width <n>` answers `Width set to <n> columns.` and
  `terminal length 0` answers `Pagination disabled.`, the words netmiko's
  EOS session preparation waits for. `exit` or `quit` ends the session.
  Every other line is looked up in the transcripts as below.
- Password auth; the username defaults to `admin`, the password comes from
  `FAKE_DEVICE_PASSWORD` (default `FAKE-device-pass`).
- Answers a command from `transcripts/<vendor>/<name>.txt`
  (`show version` -> `show_version.txt`), `% Invalid input` otherwise. A
  trailing `| no-more` is dropped before the lookup, because it only turns
  paging off; netdev-ssh-mcp's `get_config` sends
  `show running-config | no-more`.
- Logs every exec request, and every non-empty shell line (netmiko's
  session setup and `exit` included), to `<state-dir>/commands.log`.

What it does not do yet: enable mode, config mode, and the
change-safety sequences (`commit confirmed`, `configure session`,
`checkpoint`, ...). Those land with the M3 drivers.

## Fake eAPI device (`fake_eapi.py`, M1-22)

The eAPI counterpart, for shigechika/eos-mcp, which talks to EOS over
pyeapi and HTTPS rather than SSH. See the module docstring for its command
line.

- `POST /command-api`, JSON-RPC method `runCmds`, HTTP Basic auth: username
  `admin`, password from `FAKE_EAPI_PASSWORD` (default `FAKE-eapi-pass`).
  A wrong pair gets 401 and runs nothing.
- The server is the standard library (`http.server`, `ssl`, `json`). The
  throwaway self-signed certificate and key are generated at start with
  `cryptography`, already in the `integration` extra through asyncssh,
  into the state directory. No key is ever committed.
- `--host` accepts loopback address literals only and refuses any other
  address or a name. The tier 2 fixture passes `--also-ipv6-loopback`, so
  the device also listens on `[::1]:443` where the host has it, and
  `localhost` reaches it whichever address resolves first. Where another
  program holds `[::1]:443` (seen on one Windows host), the `localhost`
  control case skips, or fails under `FATHOMGATE_TIER2_REQUIRED=1`.
- It listens on `127.0.0.1:443`. eos-mcp 1.3.0 passes no port to
  `pyeapi.connect`, so pyeapi 1.0.4 uses 443 for HTTPS. On Linux the
  runner user needs `sysctl net.ipv4.ip_unprivileged_port_start=443` (the
  CI job `tier2-eos-mcp` sets it); Windows and macOS let any user bind it.
  If the bind fails, it prints `BIND-FAILED` and exits 3, and the tier 2
  fixture skips, or fails under `FATHOMGATE_TIER2_REQUIRED=1`.
- `format: text` answers from `transcripts/eos/<name>.txt` (the same
  lookup as `fake_ssh.py`); `format: json` from
  `transcripts/eos/eapi/<name>.json`. An unknown command stops the request
  with eAPI's error shape (code 1002, `CLI command <i> of <n> '<cmd>'
  failed: invalid command`); the rest of the list does not run.
- Logs, in the state directory: `connections.log` (one line per TCP
  accept, before TLS and authentication, then the TLS SNI), `requests.log`
  (one JSON object per `runCmds` request: the whole `cmds` list, the
  format), and `commands.log` (`<user>\t<command>`, as `fake_ssh.py`
  writes it). No new line in `connections.log` means eos-mcp never
  connected.

### What the fake eAPI device cannot prove

It speaks eAPI's envelope and nothing of EOS's CLI. Its configure sessions
are a sketch so that eos-mcp's session tools get well-formed answers:
lines after `configure session <name>` are recorded and answered `{}`,
`show session-config diffs` echoes them with `+`, and `abort`, `commit`,
`commit timer`, `end` leave the session. None of this is evidence for
how EOS behaves. These need cEOS (M1-28 and M3, tier 3). As of M1-28
(2026-09-25) they are **blocked**, not run: cEOS-lab is downloaded from
arista.com with an account and cannot be redistributed, so no public CI job
can pull it; the repository is public, so only the scheduled
`nightly-clab.yaml` may use a self-hosted runner, and it stays off until
`FATHOMGATE_CLAB_ENABLED` is `true`
(docs/ci-runners.md); and `tests/clab/` does not exist yet. Moved to M3 by the
maintainer 2026-09-25, alongside the change-safety drivers, which need real
devices anyway (test-matrix.md run notes, M1-28 entry). Rows 3, 4, 5 and 6 do not
depend on them: fathomgate denies these calls before they leave.

- Whether config lines after `end` in one `runCmds` call run outside the
  session, so that push_config's `["end", "reload now"]` would reload the
  switch even with `dry_run=True`. The tier 2 case shows only that eos-mcp
  sends those lines in one call with `configure session mcp-push` before
  `abort`, and that fathomgate denies the call before it leaves. That
  `reload now` is refused by the fake is not EOS behaviour.
- `clock set`, `watch` and `terminal` from configuration mode, and an
  alias (`alias hn reload now`, then `hn`) inside a session.
- How eAPI treats a newline inside one `cmds` element.
- Configure-session semantics: that `commit timer` reverts an unconfirmed
  session at the deadline (matrix row 20), that `configure session <name>
  commit` confirms it, that `abort` discards it, that `show session-config
  diffs` matches what is applied, and session-name collisions.
- Real output: every transcript here is synthetic or a sanitised public
  sample, so a parser that works on them may still fail on a real EOS.
- Authentication and TLS as EOS does them (AAA, enable passwords, EOS's
  own certificate and cipher list).

## Transcripts

| File | Status |
| --- | --- |
| `transcripts/eos/show_version.txt` | Synthetic, shaped like EOS 4.32 `show version`; serial and build are `FAKE`. Stays synthetic until a real, publishable capture turns up (T0.26). |
| `transcripts/eos/show_running_config.txt` | Real public sample with the credentials swapped for FAKE values (T0.26). Provenance below. |
| `transcripts/eos/show_ip_bgp_summary.txt` | Synthetic (M1-22): documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`), private ASNs, `FAKE-` peer descriptions. |
| `transcripts/eos/show_tech_support.txt` | Synthetic (M1-22), a few sections shaped like EOS `show tech-support`, with a sanitised running-config section and no secret. For eos-mcp `collect_tech_support`. M2 must add a FAKE secret line to it (annotated with its pattern id in the matching redaction fixture), so the `collect_tech_support` tier 2 case also proves redaction; today it proves only the class. |
| `transcripts/eos/eapi/show_version.json`, `show_hostname.json` | Synthetic (M1-22), the key names eos-mcp reads from EOS's JSON (`modelName`, `version`, `serialNumber`, `hostname`, ...); serial and build are `FAKE`. For eAPI `format: json`. |

Transcripts follow the fixture rule: every credential, serial or other
identifier that could be real carries `FAKE`. Only public documentation
samples are used, never a capture from a real network.

### `show_running_config.txt` provenance

- Source: the Arista vEOS `show running-config` sample in HPE's public
  documentation. The maintainer supplied it on 2026-09-23. Device `Arista-1`,
  vEOS `EOS-4.16.6M` (MLAG pair member, `management api http-commands` on).
- Kept as published: hostname, `Arista-1`..`Arista-4` peer names, every
  address (`10.101.0.0/24` management, `10.0.0.0/30` and `10.0.1.0/30`
  MLAG, `8.8.8.8` resolver), VLANs, interface layout. These are
  documentation examples, not a real network. The unindented
  `description MLAG_LEFT_to_Arista-3` under `interface Ethernet2` is also
  kept as published.
- Replaced. The originals were never committed; the published sample used
  the vendor-default communities and two real-looking MD5-crypt hashes:

  | Line | Published | Now |
  | --- | --- | --- |
  | `snmp-server community ... rw` | `private` | `FAKE-private` |
  | `snmp-server community ... ro` | `public` | `FAKE-public` |
  | `enable secret 5 ...` | type-5 `$1$<salt>$<hash>` | `$1$FAKEsalt$FAKEenableMd5Hash0000.` |
  | `username admin ... secret 5 ...` | type-5 `$1$<salt>$<hash>` | `$1$FAKEsalt$FAKEadminMd5Hash00000/` |

  The replacements keep the shape: an 8-character salt and a 22-character
  hash in the crypt alphabet. They are not valid hashes of anything.
- The same text, with a header and `! <rule-id>` annotations, is the
  redaction fixture `tests/fixtures/configs/eos-4.16.txt`. The tier 1 test
  `tests/unit/test_device_transcripts.py` fails if the two copies differ.
