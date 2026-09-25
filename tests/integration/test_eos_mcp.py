# SPDX-License-Identifier: FSL-1.1-ALv2
"""Tier 2: `fathomgate serve` over stdio in front of the real
shigechika/eos-mcp v1.3.0 (FastMCP, pyeapi over HTTPS), pinned by wheel hash
and by the sha256 of every module at commit bffb893 (conftest), which reaches
the fake eAPI device (tests/fixtures/device/fake_eapi.py) on 127.0.0.1:443
(M1-22).

Two modes:

- `--no-policy`, the pass-through smoke: the 17 tools listed as
  `eos-mcp.<tool>`, `show version` through `run_command` reaching the device,
  and two facts about the upstream that the gate cases rest on: push_config
  with `dry_run` left at true still sends every config line to the device,
  in the same eAPI call as `configure session` (profile hazard 3), and
  `verify = true` in its config.ini does not make it check the device's
  certificate (profile hazard 1).
- `--policy policies/examples/read-only.yaml` with the embedded profile and
  an inventory listing only 127.0.0.1 (role lab): `show version` via
  run_command allowed and run once on the device; `reload` via run_command
  denied by `no-exec`; a host not in the inventory denied by
  `default:unknown_target`; any `config_path` denied by
  `default:bad_arguments`; push_config with ["end", "reload now"] denied as
  EXEC_ARBITRARY; collect_tech_support classified READ_CONFIG. Every denial
  is asserted as the exact tool error (the decision word and rule id, ADR
  0026) and as the decision line on fathomgate's stderr; the device's
  connections.log proves a denied call opened no TCP connection to it, so
  eos-mcp never connected, and its commands.log that nothing ran.

This is the eos-mcp half of matrix row 4 in CI; M1-28 runs the run_command
case under read-only.yaml and prod-approval.yaml, and the upa half in
test_upa_netmiko.py, and records the run ids in docs/testing/test-matrix.md.
What the fake device cannot prove (EOS's own configure-session semantics) is
listed in tests/fixtures/device/README.md.

Everything the upstream returns is data: compared, never acted on.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

import pytest

from .conftest import (
    EOS_SERVER,
    REPO,
    FakeEapi,
    eos_mcp_config,
    owner_only_file,
    tier2_absent,
)

pytestmark = [pytest.mark.tier2, pytest.mark.eos_mcp]

TRANSCRIPTS = REPO / "tests/fixtures/device/transcripts/eos"
SHOW_VERSION = (TRANSCRIPTS / "show_version.txt").read_text(encoding="utf-8")
SHOW_BGP = (TRANSCRIPTS / "show_ip_bgp_summary.txt").read_text(encoding="utf-8")
TECH_SUPPORT = (TRANSCRIPTS / "show_tech_support.txt").read_text(encoding="utf-8")

# server.py at bffb893 registers exactly these (profiles/eos-mcp.yaml).
UPSTREAM_TOOLS = {
    "health_check",
    "get_router_list",
    "get_device_facts",
    "get_device_facts_batch",
    "get_version",
    "get_config_diff",
    "list_config_sessions",
    "run_command",
    "run_commands",
    "run_command_batch",
    "run_commands_batch",
    "get_config",
    "push_config",
    "confirm_config_session",
    "abort_config_session",
    "collect_tech_support",
    "daily_brief",
}

DEVICE = "127.0.0.1"
INVENTORY = f"devices:\n  - name: {DEVICE}\n    role: lab\n    tags: [lab]\n"

# The example policies' reasons (policies/examples/read-only.yaml).
NO_EXEC = "EXEC_ARBITRARY is denied: the call runs commands outside the read allow-list or outside configuration mode"
NO_WRITES = "this proxy is read-only; configuration changes are denied"
# internal/gate/text.go, ADR 0033 section 3.
UNNAMED_ARG = "an argument is not named in the server profile for this tool"
UNKNOWN_TARGET = "target not in inventory"

READY = re.compile(r'msg="upstream ready" server=(\S+) tools=(\d+) protocol=(\S+) era=(\S+)')
DECISION = re.compile(r"\bmsg=decision\b")


def _text(result) -> str:
    return "\n".join(getattr(c, "text", "") or "" for c in result.content)


@dataclass
class Serve:
    argv: list[str]
    stderr: Path

    def lines(self) -> list[str]:
        return self.stderr.read_text(encoding="utf-8", errors="replace").splitlines()

    def decisions(self) -> list[dict[str, str]]:
        """fathomgate's `decision` lines (slog text), as key=value maps."""
        out = []
        for line in self.lines():
            if DECISION.search(line):
                fields = {}
                for tok in shlex.split(line, posix=True):
                    k, sep, v = tok.partition("=")
                    if sep:
                        fields[k] = v
                out.append(fields)
        return out


def _serve(fathomgate: Path, eos_mcp: Path, config: Path, tmp_path: Path, *policy: str) -> Serve:
    argv = [
        str(fathomgate),
        "serve",
        "--server",
        EOS_SERVER,
        "--upstream",
        str(eos_mcp),
        "--upstream-env",
        f"EOS_MCP_CONFIG={config}",
        *(policy or ("--no-policy",)),
    ]
    return Serve(argv=argv, stderr=tmp_path / "fathomgate.stderr")


def _policy_args(tmp_path: Path, policy: str = "read-only.yaml", text: str | None = None) -> tuple[str, ...]:
    body = text if text is not None else (REPO / "policies/examples" / policy).read_text(encoding="utf-8")
    p = owner_only_file(tmp_path / "policy.yaml", body)
    inv = owner_only_file(tmp_path / "inventory.yaml", INVENTORY)
    return ("--policy", str(p), "--inventory", str(inv))


class _Session:
    """An initialised python-sdk client session through fathomgate, with
    fathomgate's stderr (and the upstream's, relayed) going to serve.stderr."""

    def __init__(self, serve: Serve) -> None:
        self.serve = serve

    async def __aenter__(self):
        from contextlib import AsyncExitStack

        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client

        self._stack = AsyncExitStack()
        errlog = self._stack.enter_context(open(self.serve.stderr, "w", encoding="utf-8"))
        params = StdioServerParameters(command=self.serve.argv[0], args=self.serve.argv[1:])
        read, write = await self._stack.enter_async_context(stdio_client(params, errlog=errlog))
        session = await self._stack.enter_async_context(ClientSession(read, write))
        await session.initialize()
        return session

    async def __aexit__(self, *exc):
        await self._stack.aclose()


def _denied(tool: str, rule: str, cls: str, reason: str) -> str:
    return f"fathomgate denied {EOS_SERVER}.{tool}: rule {rule} (class {cls}): {reason}"


def _decision(serve: Serve, tool: str, index: int = -1) -> dict[str, str]:
    lines = [d for d in serve.decisions() if d.get("tool") == tool]
    assert lines, f"no decision line for {tool}:\n" + "\n".join(serve.lines()[-20:])
    return lines[index]


# --- pass-through smoke (--no-policy) ----------------------------------------


@pytest.mark.asyncio
async def test_passthrough_lists_tools_and_runs_show_version(
    fathomgate_binary: Path, eos_mcp_install: Path, fake_eapi: FakeEapi, tmp_path: Path
) -> None:
    """M0 behaviour, green before the gate: the 17 tools as `eos-mcp.<tool>`,
    and `show version` through run_command reaching the device once, in one
    eAPI call, with the transcript returned unchanged."""
    serve = _serve(fathomgate_binary, eos_mcp_install, eos_mcp_config(tmp_path), tmp_path)
    async with _Session(serve) as session:
        names = sorted(t.name for t in (await session.list_tools()).tools)
        result = await session.call_tool(f"{EOS_SERVER}.run_command", {"hostname": DEVICE, "command": "show version"})

    assert names == sorted(f"{EOS_SERVER}.{t}" for t in UPSTREAM_TOOLS)
    assert not result.is_error, _text(result)
    assert _text(result) == SHOW_VERSION
    assert fake_eapi.commands() == ["show version"]
    assert fake_eapi.requests() == [{"user": "admin", "cmds": ["show version"], "format": "text", "version": 1}]
    ready = [m.groups() for line in serve.lines() if (m := READY.search(line))]
    assert ready == [(EOS_SERVER, str(len(UPSTREAM_TOOLS)), "2025-11-25", "stateful")], serve.lines()[-20:]
    assert serve.decisions() == []  # --no-policy decides nothing


@pytest.mark.asyncio
async def test_passthrough_push_config_dry_run_still_sends_lines(
    fathomgate_binary: Path, eos_mcp_install: Path, fake_eapi: FakeEapi, tmp_path: Path
) -> None:
    """The negative control for the push_config deny below, and profile
    hazard 3 on the real upstream: with dry_run left at its default (true),
    eos-mcp sends `end` and `reload now` to the device, in the same runCmds
    call as `configure session mcp-push`, ahead of the final `abort`. Whether
    EOS then runs `reload now` outside the session is M1-28's cEOS check;
    here the fake answers it as an unknown exec command."""
    serve = _serve(fathomgate_binary, eos_mcp_install, eos_mcp_config(tmp_path), tmp_path)
    async with _Session(serve) as session:
        result = await session.call_tool(f"{EOS_SERVER}.push_config", {"hostname": DEVICE, "config_lines": ["end", "reload now"]})

    assert [r["cmds"] for r in fake_eapi.requests()] == [
        ["configure session mcp-push", "end", "reload now", "show session-config diffs", "abort"]
    ]
    # The upstream reports the device's error as text, not as isError.
    assert not result.is_error
    assert _text(result).startswith(f"Error ({DEVICE}): "), _text(result)
    assert "'reload now' failed: invalid command" in _text(result), _text(result)


@pytest.mark.asyncio
async def test_passthrough_verify_true_is_not_enforced(
    fathomgate_binary: Path, eos_mcp_install: Path, fake_eapi: FakeEapi, tmp_path: Path
) -> None:
    """Profile hazard 1 on the real upstream: with `verify = true` in
    config.ini, eos-mcp still completes a call to a device whose certificate
    is self-signed and not for this name. eos_mcp.eapi.get_node passes
    `verify=` to pyeapi.connect, which pyeapi 1.0.4 does not use; its HTTPS
    transport builds an unverified context unless given one. So the
    profile's advice to set `verify = true` does not make the eAPI
    credentials safe from an impostor; only fathomgate's unknown-target
    deny keeps them from a host the agent names."""
    serve = _serve(fathomgate_binary, eos_mcp_install, eos_mcp_config(tmp_path, verify="true"), tmp_path)
    async with _Session(serve) as session:
        result = await session.call_tool(f"{EOS_SERVER}.run_command", {"hostname": DEVICE, "command": "show version"})

    assert not result.is_error, _text(result)
    assert _text(result) == SHOW_VERSION
    assert fake_eapi.commands() == ["show version"]


@pytest.mark.asyncio
async def test_passthrough_unlisted_localhost_reaches_device(
    fathomgate_binary: Path, eos_mcp_install: Path, fake_eapi: FakeEapi, tmp_path: Path
) -> None:
    """The control for the unknown-target deny below: without the gate,
    `localhost` (not a section in eos-mcp's config.ini, not in fathomgate's
    inventory) reaches the fake device, which listens on 127.0.0.1 and, where
    the host has it, ::1, so whichever address `localhost` resolves to first
    is the device. eos-mcp logs in with the [DEFAULT] FAKE credentials
    (profile hazard 1) and sends SNI `localhost`. So when the gated test sees
    no new connection for `localhost`, the gate stopped a call that would
    have arrived.

    If `localhost` resolves to an address the fake could not bind (on a
    host where another program holds [::1]:443, http.client would reach
    that program first), the control cannot run: it skips, or fails under
    FATHOMGATE_TIER2_REQUIRED=1, rather than send the FAKE credentials to
    something else and call it the device."""
    import socket

    first = socket.getaddrinfo("localhost", 443, type=socket.SOCK_STREAM)[0][4][0]
    if first not in fake_eapi.addresses:
        tier2_absent(
            f"localhost resolves first to {first}, where the fake eAPI device is not listening "
            f"(it has {', '.join(fake_eapi.addresses)}; another program may hold [{first}]:443)"
        )
    serve = _serve(fathomgate_binary, eos_mcp_install, eos_mcp_config(tmp_path), tmp_path)
    async with _Session(serve) as session:
        result = await session.call_tool(f"{EOS_SERVER}.run_command", {"hostname": "localhost", "command": "show version"})

    assert not result.is_error, _text(result)
    assert _text(result) == SHOW_VERSION
    assert fake_eapi.accepts() == 1
    assert "tls localhost" in fake_eapi.connections()
    assert fake_eapi.commands() == ["show version"]


# --- through the gate (--policy read-only.yaml) ------------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize("policy", ["read-only.yaml", "prod-approval.yaml"])
async def test_policy_read_only_run_command(
    fathomgate_binary: Path, eos_mcp_install: Path, fake_eapi: FakeEapi, tmp_path: Path, policy: str
) -> None:
    """Row 4 (eos-mcp half) and the unknown-target default, over stdio,
    under read-only.yaml and prod-approval.yaml (M1-28).

    `show version` and `show ip bgp summary` via run_command: allow, rule
    reads-anywhere, downgraded from EXEC_ARBITRARY to READ_OPERATIONAL by
    the command, and each run once on the device. `reload`: deny, rule
    no-exec, class EXEC_ARBITRARY, and no new connection to the device.
    `localhost` and 10.99.99.99: deny, rule default:unknown_target.

    What the device's logs can prove differs between the two unknown hosts.
    `localhost` reaches this fake device when forwarded
    (test_passthrough_unlisted_localhost_reaches_device), so no new
    connection here means eos-mcp never connected. 10.99.99.99 would not
    reach the fake at all (it listens on loopback only), so for it the
    evidence is the exact tool error and the decision line with
    forwarded=false, not the device log."""
    serve = _serve(fathomgate_binary, eos_mcp_install, eos_mcp_config(tmp_path), tmp_path, *_policy_args(tmp_path, policy))
    tool = "run_command"
    async with _Session(serve) as session:
        allowed = await session.call_tool(f"{EOS_SERVER}.{tool}", {"hostname": DEVICE, "command": "show version"})
        assert not allowed.is_error, _text(allowed)
        assert _text(allowed) == SHOW_VERSION
        bgp = await session.call_tool(f"{EOS_SERVER}.{tool}", {"hostname": DEVICE, "command": "show ip bgp summary"})
        assert not bgp.is_error, _text(bgp)
        assert _text(bgp) == SHOW_BGP
        assert fake_eapi.commands() == ["show version", "show ip bgp summary"]
        accepts = fake_eapi.accepts()
        assert accepts == 2

        reload = await session.call_tool(f"{EOS_SERVER}.{tool}", {"hostname": DEVICE, "command": "reload"})
        assert reload.is_error
        assert _text(reload) == _denied(tool, "no-exec", "EXEC_ARBITRARY", NO_EXEC)

        for host in ("localhost", "10.99.99.99"):
            unknown = await session.call_tool(f"{EOS_SERVER}.{tool}", {"hostname": host, "command": "show version"})
            assert unknown.is_error
            assert _text(unknown) == _denied(tool, "default:unknown_target", "READ_OPERATIONAL", UNKNOWN_TARGET)

    # Nothing the policy denied reached the device: no new TCP connection
    # (which `reload` and `localhost` would have made, see the control
    # above) and no command. 10.99.99.99 rests on the decision lines below.
    assert fake_eapi.accepts() == accepts
    assert fake_eapi.commands() == ["show version", "show ip bgp summary"]

    d = serve.decisions()
    assert [(x["tool"], x["decision"], x["rule_id"], x["class"], x["forwarded"]) for x in d] == [
        (tool, "allow", "reads-anywhere", "READ_OPERATIONAL", "true"),
        (tool, "allow", "reads-anywhere", "READ_OPERATIONAL", "true"),
        (tool, "deny", "no-exec", "EXEC_ARBITRARY", "false"),
        (tool, "deny", "default:unknown_target", "READ_OPERATIONAL", "false"),
        (tool, "deny", "default:unknown_target", "READ_OPERATIONAL", "false"),
    ]
    assert [x["class_source"] for x in d[:2]] == ["downgrade", "downgrade"]
    assert [x["unknown_target"] for x in d] == ["false", "false", "false", "true", "true"]


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["", "config.ini", "/proc/self/environ"])
async def test_policy_config_path_refused(
    fathomgate_binary: Path, eos_mcp_install: Path, fake_eapi: FakeEapi, tmp_path: Path, value: str
) -> None:
    """Profile hazard 2: `config_path` is a local file read and a credential
    swap. The profile lists it under refused_args for every tool, so any
    value, the empty string included, is deny with default:bad_arguments
    (ADR 0033), on a tool that would otherwise be allowed (get_version, a
    READ_OPERATIONAL on a known device) and on health_check, which never
    touches a device. Nothing reaches the device."""
    serve = _serve(fathomgate_binary, eos_mcp_install, eos_mcp_config(tmp_path), tmp_path, *_policy_args(tmp_path))
    async with _Session(serve) as session:
        for tool, cls, args in (("get_version", "READ_OPERATIONAL", {"hostname": DEVICE}), ("health_check", "LOCAL_ADMIN", {})):
            r = await session.call_tool(f"{EOS_SERVER}.{tool}", {**args, "config_path": value})
            assert r.is_error, _text(r)
            # Exact: the value and the argument name are never echoed.
            assert _text(r) == _denied(tool, "default:bad_arguments", cls, UNNAMED_ARG)
            dec = _decision(serve, tool)
            assert (dec["decision"], dec["rule_id"], dec["class"], dec["forwarded"]) == ("deny", "default:bad_arguments", cls, "false")
            # The operator's log names the refused argument.
            assert dec["unnamed_args"] == "[config_path]"

    assert fake_eapi.accepts() == 0
    assert fake_eapi.commands() == []


@pytest.mark.asyncio
async def test_policy_push_config_leaving_session_is_exec(
    fathomgate_binary: Path, eos_mcp_install: Path, fake_eapi: FakeEapi, tmp_path: Path
) -> None:
    """push_config with ["end", "reload now"] (dry_run left at true): the
    line `end` leaves the configure session, so the call is EXEC_ARBITRARY
    (M1-36, classification.md section 11), not WRITE_CONFIG, and read-only
    denies it with no-exec. The pass-through test above shows what the
    device would have received. A plain config line is WRITE_CONFIG and is
    denied by no-writes. Neither opens a connection."""
    serve = _serve(fathomgate_binary, eos_mcp_install, eos_mcp_config(tmp_path), tmp_path, *_policy_args(tmp_path))
    tool = "push_config"
    async with _Session(serve) as session:
        exec_ = await session.call_tool(f"{EOS_SERVER}.{tool}", {"hostname": DEVICE, "config_lines": ["end", "reload now"]})
        assert exec_.is_error
        assert _text(exec_) == _denied(tool, "no-exec", "EXEC_ARBITRARY", NO_EXEC)

        write = await session.call_tool(f"{EOS_SERVER}.{tool}", {"hostname": DEVICE, "config_lines": ["hostname FAKE-lab-01"]})
        assert write.is_error
        assert _text(write) == _denied(tool, "no-writes", "WRITE_CONFIG", NO_WRITES)

    assert fake_eapi.accepts() == 0
    assert fake_eapi.requests() == []
    assert [(x["decision"], x["rule_id"], x["class"]) for x in serve.decisions()] == [
        ("deny", "no-exec", "EXEC_ARBITRARY"),
        ("deny", "no-writes", "WRITE_CONFIG"),
    ]


@pytest.mark.asyncio
async def test_policy_collect_tech_support_is_read_config(
    fathomgate_binary: Path, eos_mcp_install: Path, fake_eapi: FakeEapi, tmp_path: Path
) -> None:
    """collect_tech_support is READ_CONFIG (the M1-14 correction): read-only
    allows it by reads-anywhere with class READ_CONFIG, and the device gets
    one `show tech-support`.

    Not yet a redaction case: show_tech_support.txt carries no secret, and
    the transcript comes back unchanged. When M2 wires redaction, add a FAKE
    secret line (with its pattern id) to show_tech_support.txt and assert
    here that it comes back as a `<redacted:hmac:...>` token, since the
    `redact` obligation of reads-anywhere covers this tool too."""
    serve = _serve(fathomgate_binary, eos_mcp_install, eos_mcp_config(tmp_path), tmp_path, *_policy_args(tmp_path))
    async with _Session(serve) as session:
        r = await session.call_tool(f"{EOS_SERVER}.collect_tech_support", {"hostname": DEVICE})

    assert not r.is_error, _text(r)
    assert _text(r) == TECH_SUPPORT
    assert fake_eapi.commands() == ["show tech-support"]
    dec = _decision(serve, "collect_tech_support")
    assert (dec["decision"], dec["rule_id"], dec["class"], dec["forwarded"]) == ("allow", "reads-anywhere", "READ_CONFIG", "true")


# A policy that tells READ_CONFIG from READ_OPERATIONAL, so the class shows in
# the decision word as well as in the log line.
OPS_ONLY = """version: 1
defaults:
  unknown_target: deny
rules:
  - id: ops-reads
    match: { class: [READ_OPERATIONAL] }
    effect: allow
  - id: no-config-reads
    match: { class: [READ_CONFIG] }
    effect: deny
    reason: "configuration reads are denied in this test policy"
  - id: no-exec
    match: { class: [EXEC_ARBITRARY] }
    effect: deny
    reason: "EXEC_ARBITRARY is denied"
"""


@pytest.mark.asyncio
async def test_policy_tech_support_denied_as_read_config_both_ways(
    fathomgate_binary: Path, eos_mcp_install: Path, fake_eapi: FakeEapi, tmp_path: Path
) -> None:
    """Under a policy that denies READ_CONFIG only, collect_tech_support and
    the same command through run_command are both denied by no-config-reads
    with class READ_CONFIG: the typed tool is not looser than the free-form
    one. `show version` through run_command is still allowed by ops-reads."""
    serve = _serve(fathomgate_binary, eos_mcp_install, eos_mcp_config(tmp_path), tmp_path, *_policy_args(tmp_path, text=OPS_ONLY))
    reason = "configuration reads are denied in this test policy"
    async with _Session(serve) as session:
        typed = await session.call_tool(f"{EOS_SERVER}.collect_tech_support", {"hostname": DEVICE})
        free = await session.call_tool(f"{EOS_SERVER}.run_command", {"hostname": DEVICE, "command": "show tech-support"})
        ok = await session.call_tool(f"{EOS_SERVER}.run_command", {"hostname": DEVICE, "command": "show version"})

    assert typed.is_error and _text(typed) == _denied("collect_tech_support", "no-config-reads", "READ_CONFIG", reason)
    assert free.is_error and _text(free) == _denied("run_command", "no-config-reads", "READ_CONFIG", reason)
    assert not ok.is_error and _text(ok) == SHOW_VERSION
    assert fake_eapi.commands() == ["show version"]
    assert fake_eapi.accepts() == 1


# Row 5 (M1 half): a config dump through run_command, the words separated by
# any run of spaces and tabs (the tier 1 variants in internal/classify).
CONFIG_DUMPS = ["show running-config", "show  running-config", "show\trunning-config", "\tshow\t\trunning-config\t"]
SHOW_RUN = (TRANSCRIPTS / "show_running_config.txt").read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_row5_config_dump_reclassified_read_config(
    fathomgate_binary: Path, eos_mcp_install: Path, fake_eapi: FakeEapi, tmp_path: Path
) -> None:
    """Row 5, M1 half, on eos-mcp: `show running-config` through run_command
    in each whitespace variant is READ_CONFIG with class_source reclassify.
    Under read-only it is allow by reads-anywhere, and eAPI carries each
    variant to the device exactly as sent (tabs included). The output is
    not redacted in M1 (the row's M2 half)."""
    serve = _serve(fathomgate_binary, eos_mcp_install, eos_mcp_config(tmp_path), tmp_path, *_policy_args(tmp_path))
    async with _Session(serve) as session:
        for cmd in CONFIG_DUMPS:
            r = await session.call_tool(f"{EOS_SERVER}.run_command", {"hostname": DEVICE, "command": cmd})
            assert not r.is_error, (cmd, _text(r))
            assert _text(r) == SHOW_RUN, cmd

    assert fake_eapi.commands() == CONFIG_DUMPS
    assert [(x["decision"], x["rule_id"], x["class"], x["class_source"], x["forwarded"]) for x in serve.decisions()] == [
        ("allow", "reads-anywhere", "READ_CONFIG", "reclassify", "true") for _ in CONFIG_DUMPS
    ]


@pytest.mark.asyncio
async def test_row5_config_dump_denied_where_config_reads_are(
    fathomgate_binary: Path, eos_mcp_install: Path, fake_eapi: FakeEapi, tmp_path: Path
) -> None:
    """Row 5, M1 half, on eos-mcp: under a policy that denies READ_CONFIG
    only, every variant through run_command is deny by no-config-reads with
    class READ_CONFIG, and no connection reaches the device."""
    serve = _serve(fathomgate_binary, eos_mcp_install, eos_mcp_config(tmp_path), tmp_path, *_policy_args(tmp_path, text=OPS_ONLY))
    reason = "configuration reads are denied in this test policy"
    async with _Session(serve) as session:
        for cmd in CONFIG_DUMPS:
            r = await session.call_tool(f"{EOS_SERVER}.run_command", {"hostname": DEVICE, "command": cmd})
            assert r.is_error, cmd
            assert _text(r) == _denied("run_command", "no-config-reads", "READ_CONFIG", reason)

    assert fake_eapi.accepts() == 0
    assert fake_eapi.commands() == []
    assert [(x["decision"], x["rule_id"], x["class"], x["class_source"], x["forwarded"]) for x in serve.decisions()] == [
        ("deny", "no-config-reads", "READ_CONFIG", "reclassify", "false") for _ in CONFIG_DUMPS
    ]
