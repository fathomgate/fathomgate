# Fake device

`fake_ssh.py` is an asyncssh server that stands in for a network device in
tier 2, so a real upstream MCP server can run a real SSH session without a
real device. See the module docstring for its command line.

What it does today (T0.5):

- The SSH exec channel only, which is what netdev-ssh-mcp v1.6.6 uses.
- Password auth; the username defaults to `admin`, the password comes from
  `FAKE_DEVICE_PASSWORD` (default `FAKE-device-pass`).
- Answers a command from `transcripts/<vendor>/<name>.txt`
  (`show version` -> `show_version.txt`), `% Invalid input` otherwise.
- Logs every exec request to `<state-dir>/commands.log`.

What it does not do yet: interactive prompts, config mode, and the
change-safety sequences (`commit confirmed`, `configure session`,
`checkpoint`, ...). Those land with the M3 drivers.

## Transcripts

| File | Status |
| --- | --- |
| `transcripts/eos/show_version.txt` | Synthetic, shaped like EOS 4.32 `show version`; serial and build are `FAKE`. To be replaced by a sanitised capture from the Network Safety Engineer, shared with `internal/safety/eos/testdata/`. |

Transcripts follow the fixture rule: nothing here was ever real, and every
identifier that could be real carries `FAKE`.
