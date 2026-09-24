"""Fake network device: an asyncssh server that answers `show` commands from
canned transcripts, so tier 2 can run a real upstream MCP server without a
real device.

Scope today (T0.5): the SSH *exec* channel only, which is what
krisiasty/netdev-ssh-mcp v1.6.6 uses (one non-PTY `session.Output(cmd)` per
call, see internal/sshclient/client.go at that tag). There is no interactive
prompt, no config mode and no commit/rollback state yet; those arrive with
the change-safety drivers (M3) and their transcripts from the Network Safety
Engineer.

    python fake_ssh.py --vendor eos --state-dir DIR

It generates an ed25519 host key in DIR, listens on 127.0.0.1 (port 0 means
pick one), writes DIR/known_hosts with the key for `[127.0.0.1]:<port>`, and
prints one line `READY <port>` on stdout once it accepts connections. Every
exec request is appended to DIR/commands.log as `<user>\t<command>`, so a
test can prove what reached the device (or that nothing did).

Auth is password only: the username and password come from --username and
the FAKE_DEVICE_PASSWORD environment variable (default `FAKE-device-pass`).
Both are fixtures; never point this at anything real.

A command maps to transcripts/<vendor>/<name>.txt where <name> is the
command lower-cased with runs of non-alphanumerics replaced by `_`
(`show version` -> `show_version.txt`); a trailing `| no-more` is dropped
first (`show running-config | no-more` -> `show_running_config.txt`). An
unknown command writes an EOS-style `% Invalid input` to stderr and exits 1.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import sys
from pathlib import Path

import asyncssh

HERE = Path(__file__).resolve().parent
DEFAULT_PASSWORD = "FAKE-device-pass"


# `| no-more` only turns paging off; the device prints the same text. The
# upstream's get_config appends it (`show running-config | no-more` for EOS),
# so it is dropped before the lookup. Other pipes (`| include`, `| json`)
# change the output and stay part of the name. commands.log keeps the
# command exactly as sent.
_NO_MORE = re.compile(r"\s*\|\s*no-more\s*$", re.I)


def transcript_name(command: str) -> str:
    command = _NO_MORE.sub("", command.strip())
    return re.sub(r"[^a-z0-9]+", "_", command.lower()).strip("_")


class _Server(asyncssh.SSHServer):
    def __init__(self, username: str, password: str) -> None:
        self._username = username
        self._password = password

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        return username == self._username and password == self._password


def _make_handler(transcripts: Path, log: Path):
    async def handle(process: asyncssh.SSHServerProcess) -> None:
        command = process.command or ""
        user = process.get_extra_info("username") or ""
        with log.open("a", encoding="utf-8") as f:
            f.write(f"{user}\t{command}\n")
        if not command:
            process.stderr.write("fake device: interactive shell not supported\n")
            process.exit(1)
            return
        path = transcripts / f"{transcript_name(command)}.txt"
        if path.is_file():
            process.stdout.write(path.read_text(encoding="utf-8"))
            process.exit(0)
        else:
            process.stderr.write("% Invalid input\n")
            process.exit(1)

    return handle


async def serve(vendor: str, state_dir: Path, port: int, username: str, password: str) -> None:
    transcripts = HERE / "transcripts" / vendor
    if not transcripts.is_dir():
        raise SystemExit(f"fake device: no transcripts for vendor {vendor!r} in {transcripts}")
    state_dir.mkdir(parents=True, exist_ok=True)
    key = asyncssh.generate_private_key("ssh-ed25519")
    key_path = state_dir / "host_key"
    key.write_private_key(str(key_path))
    log = state_dir / "commands.log"
    log.touch()

    acceptor = await asyncssh.create_server(
        lambda: _Server(username, password),
        "127.0.0.1",
        port,
        server_host_keys=[str(key_path)],
        process_factory=_make_handler(transcripts, log),
        encoding="utf-8",
    )
    bound = acceptor.sockets[0].getsockname()[1]
    pub = key.export_public_key("openssh").decode().strip()
    (state_dir / "known_hosts").write_text(f"[127.0.0.1]:{bound} {pub}\n", encoding="utf-8")
    print(f"READY {bound}", flush=True)
    await acceptor.wait_closed()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--vendor", default="eos")
    ap.add_argument("--state-dir", type=Path, required=True)
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--username", default="admin")
    args = ap.parse_args(argv)
    password = os.environ.get("FAKE_DEVICE_PASSWORD", DEFAULT_PASSWORD)
    try:
        asyncio.run(serve(args.vendor, args.state_dir, args.port, args.username, password))
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
