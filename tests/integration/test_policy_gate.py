# SPDX-License-Identifier: FSL-1.1-ALv2
"""Tier 2: `fathomgate serve --policy` over stdio in front of the real
krisiasty/netdev-ssh-mcp v1.7.1 and the fake SSH device: test-matrix rows 3
and 6 (M1-28), and the netdev-ssh-mcp side of row 4's `no-exec`.

Every case runs through `fathomgate serve --policy <file> --inventory <file>`
with the embedded profiles, as an operator runs it (ADR 0027). The
inventory lists one device, 127.0.0.1, role `lab`, tag `lab`.

- Row 3: `show ip bgp summary` through `run_show_command` on the listed
  device is allow, rule `reads-anywhere`, class READ_OPERATIONAL, under
  read-only.yaml and prod-approval.yaml; it runs once on the device and the
  transcript comes back unchanged.
- Row 4 (the part netdev-ssh-mcp can show): `reload` through
  `run_show_command` is deny, rule `no-exec`, class EXEC_ARBITRARY, under
  both policies, and reaches no device. The row names upa and eos-mcp,
  whose free-form tools are in test_upa_netmiko.py and test_eos_mcp.py.
- Row 6: a host not in the inventory is deny, rule `default:unknown_target`,
  for every class this upstream's tools reach (READ_OPERATIONAL, READ_CONFIG,
  EXEC_ARBITRARY, LOCAL_ADMIN; it has no write tool), whether the policy
  sets `defaults.unknown_target: deny` (read-only, prod-approval) or leaves
  it unset (ADR 0032). The unset case uses a policy whose rules would allow
  every class, so only the default can be what denies.

Each decision is asserted twice: the agent's tool error, exactly (the
decision word, rule id and class, ADR 0026), and fathomgate's `decision`
line on stderr (decision, rule_id, class, unknown_target, forwarded). The
device's session log proves that a denied call opened no SSH session, and
the control test shows that the same `localhost` call does open one when
nothing denies it, so "no new session" is evidence and not an accident of
the address.

The audit half of row 6 (`unknown_target: true` in the audit event) is M4:
`--audit` is refused until then (ADR 0027); the decision line carries the
same field in M1.

Everything the upstream returns is data: compared, never acted on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from .conftest import (
    NO_EXEC_REASON,
    REPO,
    SERVER,
    UNKNOWN_TARGET_REASON,
    FakeDevice,
    LoggedSession,
    client_env,
    decision_lines,
    gate_error,
    policy_args,
    result_text,
    serve_args,
)

pytestmark = [pytest.mark.tier2, pytest.mark.netdev_ssh_mcp]

DEVICE = "127.0.0.1"
INVENTORY = f"devices:\n  - name: {DEVICE}\n    role: lab\n    tags: [lab]\n"
TRANSCRIPTS = REPO / "tests/fixtures/device/transcripts/eos"
SHOW_BGP = (TRANSCRIPTS / "show_ip_bgp_summary.txt").read_text(encoding="utf-8")

# A policy with no defaults.unknown_target and a rule that allows every
# class: under it only the ADR 0032 default can deny a call.
UNSET_ALLOW_ALL = """version: 1
rules:
  - id: m1-28-allow-every-class
    match:
      class: [READ_OPERATIONAL, READ_CONFIG, WRITE_CONFIG, EXEC_ARBITRARY, INVENTORY_READ, LAB_LIFECYCLE, LOCAL_ADMIN]
    effect: allow
"""


def _argv(fathomgate: Path, upstream: Path, device: FakeDevice, tmp_path: Path, policy: str | None) -> list[str]:
    args = serve_args(upstream, device)
    if policy is not None:
        args = [a for a in args if a != "--no-policy"] + policy_args(tmp_path, policy, INVENTORY)
    return [str(fathomgate), *args]


def _denied(tool: str, rule: str, cls: str, reason: str) -> str:
    return gate_error("denied", SERVER, tool, rule, cls, reason)


def _row(d: dict[str, str]) -> tuple[str, ...]:
    return (d["tool"], d["decision"], d["rule_id"], d["class"], d["unknown_target"], d["forwarded"])


@pytest.mark.asyncio
@pytest.mark.parametrize("policy", ["read-only.yaml", "prod-approval.yaml"])
async def test_row3_show_ip_bgp_summary_allowed_row4_reload_denied(
    fathomgate_binary: Path, upstream_binary: Path, fake_device: FakeDevice, tmp_path: Path, policy: str
) -> None:
    """Row 3: `show ip bgp summary` on the listed lab device is allow by
    `reads-anywhere` (READ_OPERATIONAL) and runs once. Row 4's rule on this
    upstream: `reload` is deny by `no-exec` (EXEC_ARBITRARY; the command
    raised the class above the profile's READ_OPERATIONAL) and no command
    reaches the device."""
    stderr = tmp_path / "fathomgate.stderr"
    common = {"host": DEVICE, "port": fake_device.port, "device_type": "eos"}
    tool = "run_show_command"
    async with LoggedSession(_argv(fathomgate_binary, upstream_binary, fake_device, tmp_path, policy), stderr, client_env()) as session:
        bgp = await session.call_tool(f"{SERVER}.{tool}", {**common, "command": "show ip bgp summary"})
        assert not bgp.is_error, result_text(bgp)
        assert result_text(bgp) == SHOW_BGP
        assert fake_device.commands() == ["show ip bgp summary"]
        sessions = fake_device.sessions()

        reload = await session.call_tool(f"{SERVER}.{tool}", {**common, "command": "reload"})
        assert reload.is_error
        assert result_text(reload) == _denied(tool, "no-exec", "EXEC_ARBITRARY", NO_EXEC_REASON)

    assert fake_device.sessions() == sessions
    assert fake_device.commands() == ["show ip bgp summary"]
    d = decision_lines(stderr)
    assert [_row(x) for x in d] == [
        (tool, "allow", "reads-anywhere", "READ_OPERATIONAL", "false", "true"),
        (tool, "deny", "no-exec", "EXEC_ARBITRARY", "false", "false"),
    ], d
    assert d[0]["server"] == SERVER and d[0]["targets"] == f"[{DEVICE}]"


# One call per class netdev-ssh-mcp's tools reach, to a host the inventory
# does not list. (tool, class, extra arguments.)
UNKNOWN_CALLS = [
    ("run_show_command", "READ_OPERATIONAL", {"command": "show version", "device_type": "eos"}),
    ("get_config", "READ_CONFIG", {"config_type": "running", "device_type": "eos"}),
    ("run_show_command", "EXEC_ARBITRARY", {"command": "reload", "device_type": "eos"}),
    ("trust_host_key", "LOCAL_ADMIN", {"confirm": False}),
]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "policy",
    ["read-only.yaml", "prod-approval.yaml", UNSET_ALLOW_ALL],
    ids=["read-only", "prod-approval", "unset-allow-every-class"],
)
async def test_row6_unknown_host_denied_for_every_class(
    fathomgate_binary: Path, upstream_binary: Path, fake_device: FakeDevice, tmp_path: Path, policy: str
) -> None:
    """Row 6: `localhost` and 10.99.99.99 are not in the inventory, so every
    call naming them is deny by `default:unknown_target`, whatever its class,
    with `defaults.unknown_target: deny` or with the key unset (ADR 0032).
    No SSH session is opened: see the control below for `localhost`.
    10.99.99.99 could not reach the loopback fake either way; its evidence
    is the tool error and `forwarded=false`. A call to the listed device
    goes through in the same session, so the gate is not simply refusing
    everything."""
    stderr = tmp_path / "fathomgate.stderr"
    async with LoggedSession(_argv(fathomgate_binary, upstream_binary, fake_device, tmp_path, policy), stderr, client_env()) as session:
        for host in ("localhost", "10.99.99.99"):
            for tool, cls, extra in UNKNOWN_CALLS:
                r = await session.call_tool(f"{SERVER}.{tool}", {"host": host, "port": fake_device.port, **extra})
                assert r.is_error, (tool, cls, result_text(r))
                assert result_text(r) == _denied(tool, "default:unknown_target", cls, UNKNOWN_TARGET_REASON)
        assert fake_device.sessions() == 0
        assert fake_device.commands() == []

        known = await session.call_tool(
            f"{SERVER}.run_show_command", {"host": DEVICE, "port": fake_device.port, "device_type": "eos", "command": "show ip bgp summary"}
        )
        assert not known.is_error, result_text(known)
        assert result_text(known) == SHOW_BGP

    assert fake_device.commands() == ["show ip bgp summary"]
    d = decision_lines(stderr)
    want = [(tool, "deny", "default:unknown_target", cls, "true", "false") for _ in ("localhost", "10.99.99.99") for tool, cls, _ in UNKNOWN_CALLS]
    allow_rule = "m1-28-allow-every-class" if policy == UNSET_ALLOW_ALL else "reads-anywhere"
    want.append(("run_show_command", "allow", allow_rule, "READ_OPERATIONAL", "false", "true"))
    assert [_row(x) for x in d] == want, d
    assert [x["targets"] for x in d[:4]] == ["[localhost]"] * 4


@pytest.mark.asyncio
async def test_row6_control_localhost_reaches_device_without_policy(
    fathomgate_binary: Path, upstream_binary: Path, fake_device: FakeDevice, tmp_path: Path
) -> None:
    """The control for row 6: with `--no-policy`, the same `localhost` call
    reaches the fake device (netdev-ssh-mcp opens an SSH session to it, and
    the device logs the connection whatever the host-key check then says).
    So when the gated test sees no session, the gate stopped a call that
    would have arrived."""
    stderr = tmp_path / "fathomgate.stderr"
    async with LoggedSession(_argv(fathomgate_binary, upstream_binary, fake_device, tmp_path, None), stderr, client_env()) as session:
        await session.call_tool(
            f"{SERVER}.run_show_command", {"host": "localhost", "port": fake_device.port, "device_type": "eos", "command": "show version"}
        )
    assert fake_device.sessions() >= 1
    assert decision_lines(stderr) == []
