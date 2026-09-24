#!/usr/bin/env python3
"""Upstream prompts through fathomgate serve from a 2025-11-25 upstream (T0.19).

The conformance suite reaches the "2025 agent x 2025 upstream" elicitation
path (tools-call-elicitation on the fathomgate-up2025 leg), but no 2026-07-28
scenario calls a stateful elicitation tool, so the ADR 0014 refusal
("2026 agent x 2025 upstream") is never exercised by the suite. This script
drives both cells over stdio against the real upstream that leg uses: go-sdk
v1.6.1's conformance everything-server (tests/conformance/upstream-2025), a
release with no 2026-07-28 support.

  era_pairs.py --fathomgate bin/fathomgate --upstream bin/conformance/everything-server-2025

Each pair checks, word for word:

  agent 2025-11-25 x upstream 2025-11-25
      fathomgate negotiated 2025-11-25 (stateful) with the upstream; the
      upstream's elicitation/create reaches the agent with "[from conf] "
      in front of the message and of the field title; the agent's accept goes
      back and the tool completes with it.
  agent 2026-07-28 x upstream 2025-11-25
      same upstream era; no server-initiated request reaches the agent; the
      call ends with isError and fathomgate's ADR 0014 refusal text; the
      upstream's prompt text appears nowhere in the result.

Standard library only; exits 1 on the first failed check, printing
fathomgate's stderr. Talks stdio to fathomgate directly (no relay), so it does
not change when the suite moves onto the HTTP listener (T0.32).
"""

from __future__ import annotations

import argparse
import json
import queue
import subprocess
import sys
import threading

SERVER = "conf"
TOOL = "test_elicitation"
PROMPT = "FAKE-era-pairs: choose a username"
ANSWER = "FAKE-alice"
V2025 = "2025-11-25"
V2026 = "2026-07-28"
TIMEOUT = 20.0

UPSTREAM_READY = f"protocol={V2025} era=stateful"
REFUSAL = (
    f"fathomgate refused an input request (elicitation) from upstream {SERVER} during {TOOL}: "
    f"this client speaks the stateless era ({V2026}) and cannot receive a server-initiated "
    "prompt; see ADR 0014"
)


class Failure(Exception):
    pass


class Fathomgate:
    """fathomgate serve over stdio, one JSON-RPC message per line."""

    def __init__(self, fathomgate: str, upstream: str) -> None:
        self.proc = subprocess.Popen(
            [fathomgate, "serve", "--server", SERVER, "--upstream", upstream],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.stderr: list[str] = []
        threading.Thread(target=self._pump_out, daemon=True).start()
        threading.Thread(target=self._pump_err, daemon=True).start()

    def _pump_out(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def _pump_err(self) -> None:
        assert self.proc.stderr is not None
        for line in self.proc.stderr:
            self.stderr.append(line)

    def send(self, msg: dict) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.write(json.dumps({"jsonrpc": "2.0", **msg}) + "\n")
        self.proc.stdin.flush()

    def read(self) -> dict:
        try:
            line = self.lines.get(timeout=TIMEOUT)
        except queue.Empty:
            raise Failure(f"no message from fathomgate within {TIMEOUT:.0f}s") from None
        if line is None:
            raise Failure("fathomgate closed stdout")
        return json.loads(line)

    def close(self) -> None:
        if self.proc.stdin:
            self.proc.stdin.close()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()


def texts(result: dict) -> list[str]:
    return [c.get("text", "") for c in result.get("content", []) if c.get("type") == "text"]


def check_upstream_era(ng: Fathomgate) -> None:
    if not any("upstream ready" in l and UPSTREAM_READY in l for l in ng.stderr):
        raise Failure(f"fathomgate did not log {UPSTREAM_READY!r} for the upstream")


def stateful_agent(ng: Fathomgate) -> str:
    ng.send(
        {
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": V2025,
                "capabilities": {"elicitation": {"form": {}}},
                "clientInfo": {"name": "era-pairs", "version": "0"},
            },
        }
    )
    init = ng.read()
    got = init.get("result", {}).get("protocolVersion")
    if got != V2025:
        raise Failure(f"agent negotiated {got!r}, want {V2025}")
    ng.send({"method": "notifications/initialized"})
    ng.send({"id": 2, "method": "tools/call", "params": {"name": f"{SERVER}.{TOOL}", "arguments": {"message": PROMPT}}})

    prompts = 0
    while True:
        msg = ng.read()
        if msg.get("method") == "elicitation/create":
            prompts += 1
            params = msg["params"]
            want = f"[from {SERVER}] {PROMPT}"
            if params.get("message") != want:
                raise Failure(f"prompt message {params.get('message')!r}, want {want!r}")
            prop = params.get("requestedSchema", {}).get("properties", {}).get("username", {})
            if not str(prop.get("title", "")).startswith(f"[from {SERVER}] "):
                raise Failure(f"field title {prop.get('title')!r} lacks the [from {SERVER}] label")
            ng.send({"id": msg["id"], "result": {"action": "accept", "content": {"username": ANSWER}}})
            continue
        if "method" in msg:
            continue  # notifications (progress, list changes) are not under test here
        if msg.get("id") != 2:
            raise Failure(f"unexpected response {msg}")
        break
    if prompts != 1:
        raise Failure(f"agent saw {prompts} prompts, want 1")
    result = msg.get("result")
    if result is None or result.get("isError"):
        raise Failure(f"tool call failed: {msg}")
    body = " ".join(texts(result))
    if "action=accept" not in body or ANSWER not in body:
        raise Failure(f"tool result {body!r} does not carry the accepted answer")
    check_upstream_era(ng)
    return "prompt relabelled [from conf], answer returned, tool completed"


def stateless_agent(ng: Fathomgate) -> str:
    meta = {
        "io.modelcontextprotocol/protocolVersion": V2026,
        "io.modelcontextprotocol/clientInfo": {"name": "era-pairs", "version": "0"},
        "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}},
    }
    ng.send({"id": 1, "method": "server/discover", "params": {"_meta": meta}})
    disc = ng.read()
    if V2026 not in disc.get("result", {}).get("supportedVersions", []):
        raise Failure(f"server/discover does not offer {V2026}: {disc}")
    ng.send(
        {
            "id": 2,
            "method": "tools/call",
            "params": {"_meta": meta, "name": f"{SERVER}.{TOOL}", "arguments": {"message": PROMPT}},
        }
    )
    while True:
        msg = ng.read()
        if "id" in msg and "method" in msg:
            raise Failure(f"a server-initiated request reached a stateless agent: {msg['method']}")
        if "method" in msg:
            continue
        break
    if msg.get("id") != 2 or "result" not in msg:
        raise Failure(f"unexpected response {msg}")
    result = msg["result"]
    if result.get("isError") is not True:
        raise Failure(f"want isError true, got {result}")
    body = texts(result)
    if REFUSAL not in body:
        raise Failure(f"no content item is the ADR 0014 refusal; got {body!r}")
    if any(PROMPT in t for t in body):
        raise Failure("the upstream's prompt text reached the agent")
    check_upstream_era(ng)
    return "refused per ADR 0014, prompt not shown"


PAIRS = [
    (f"agent {V2025} x upstream {V2025}", stateful_agent),
    (f"agent {V2026} x upstream {V2025}", stateless_agent),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fathomgate", required=True)
    ap.add_argument("--upstream", required=True, help="a 2025-11-25-only MCP server (stdio)")
    args = ap.parse_args()

    failed = False
    for name, run in PAIRS:
        ng = Fathomgate(args.fathomgate, args.upstream)
        try:
            print(f"ok    {name}: {run(ng)}")
        except Failure as e:
            failed = True
            print(f"FAIL  {name}: {e}")
            ng.close()
            sys.stdout.write("".join(ng.stderr))
            continue
        ng.close()
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
