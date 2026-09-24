# Fake device

`fake_ssh.py` is an asyncssh server that stands in for a network device in
tier 2, so a real upstream MCP server can run a real SSH session without a
real device. See the module docstring for its command line.

What it does today (T0.5):

- The SSH exec channel only, which is what netdev-ssh-mcp v1.6.6 uses.
- Password auth; the username defaults to `admin`, the password comes from
  `FAKE_DEVICE_PASSWORD` (default `FAKE-device-pass`).
- Answers a command from `transcripts/<vendor>/<name>.txt`
  (`show version` -> `show_version.txt`), `% Invalid input` otherwise. A
  trailing `| no-more` is dropped before the lookup, because it only turns
  paging off; netdev-ssh-mcp's `get_config` sends
  `show running-config | no-more`.
- Logs every exec request to `<state-dir>/commands.log`.

What it does not do yet: interactive prompts, config mode, and the
change-safety sequences (`commit confirmed`, `configure session`,
`checkpoint`, ...). Those land with the M3 drivers.

## Transcripts

| File | Status |
| --- | --- |
| `transcripts/eos/show_version.txt` | Synthetic, shaped like EOS 4.32 `show version`; serial and build are `FAKE`. Stays synthetic until a real, publishable capture turns up (T0.26). |
| `transcripts/eos/show_running_config.txt` | Real public sample with the credentials swapped for FAKE values (T0.26). Provenance below. |

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
