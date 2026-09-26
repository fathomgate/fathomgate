#!/usr/bin/env python3
# SPDX-License-Identifier: FSL-1.1-ALv2
"""Tie the fathomgate-policy leg's MRTR baseline entries to their cause (M1-28).

baseline/fathomgate-policy-2026-07-28.yml lists seven checks that fail
because, with a policy loaded, fathomgate does not relay an upstream prompt
during a call to a tool whose server has a profile (profile-schema section
8.2, last row). The suite's results do not always carry the tool result, and
fathomgate's own refusal log line is throttled per reason (once per 10 s,
not per tool), so neither can show that each of those tools met that
refusal. This script does, over stdio, as a 2026-07-28 agent that declares
every input capability:

  policy_prompts.py --fathomgate bin/fathomgate --upstream bin/conformance/everything-server \\
      --policy <dir>/policy.yaml --profiles <dir>/profiles

For each tool behind a baseline entry it calls `conf.<tool>` on a fresh
fathomgate and requires, word for word, an isError result whose one text
block is

  fathomgate refused an input request (input_required) from upstream conf during <tool>:
  a policy is enforced and fathomgate cannot check an answer against the server profile,
  so upstream prompts are not relayed

and a decision line allowing the call by conf-reads (so the call was
forwarded and the refusal came after the upstream asked). Standard library
only; exits 1 on any miss, printing fathomgate's stderr.
"""

from __future__ import annotations

import argparse
import json
import queue
import subprocess
import sys
import threading

SERVER = "conf"
V2026 = "2026-07-28"
REASON = "a policy is enforced and fathomgate cannot check an answer against the server profile, so upstream prompts are not relayed"
# The fixture tool behind each of the seven baseline entries (the suite's
# scenario sources): basic-elicitation, result-type, missing-input-response
# and validate-input call test_input_required_result_elicitation;
# request-state, multi-round and tampered-state call their own tools.
TOOLS = [
    "test_input_required_result_elicitation",
    "test_input_required_result_request_state",
    "test_input_required_result_multi_round",
    "test_input_required_result_tampered_state",
]
META = {
    "io.modelcontextprotocol/protocolVersion": V2026,
    "io.modelcontextprotocol/clientInfo": {"name": "fathomgate-policy-prompts", "version": "0"},
    "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"form": {}}, "sampling": {}, "roots": {}},
}


def call(argv: list[str], tool: str) -> tuple[dict | None, str]:
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    lines: queue.Queue[str | None] = queue.Queue()
    err: list[str] = []

    def pump_out() -> None:
        for line in proc.stdout:
            lines.put(line)
        lines.put(None)

    def pump_err() -> None:
        for line in proc.stderr:
            err.append(line)

    threading.Thread(target=pump_out, daemon=True).start()
    t_err = threading.Thread(target=pump_err, daemon=True)
    t_err.start()

    def request(id_: int, method: str, params: dict) -> dict | None:
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": id_, "method": method, "params": params}) + "\n")
        proc.stdin.flush()
        while True:
            try:
                line = lines.get(timeout=30)
            except queue.Empty:
                return None
            if line is None:
                return None
            msg = json.loads(line)
            if "method" in msg and "id" in msg:
                raise SystemExit(f"{tool}: server-initiated request reached the agent: {msg['method']}")
            if msg.get("id") == id_:
                return msg

    result = None
    try:
        if request(1, "server/discover", {"_meta": META}) is not None:
            resp = request(2, "tools/call", {"_meta": META, "name": f"{SERVER}.{tool}", "arguments": {}})
            result = None if resp is None else resp.get("result")
    finally:
        proc.stdin.close()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
        t_err.join(timeout=5)
    return result, "".join(err)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--fathomgate", required=True)
    ap.add_argument("--upstream", required=True)
    ap.add_argument("--policy", required=True)
    ap.add_argument("--profiles", required=True)
    a = ap.parse_args()
    argv = [a.fathomgate, "serve", "--server", SERVER, "--upstream", a.upstream, "--policy", a.policy, "--profiles", a.profiles]
    failed = 0
    for tool in TOOLS:
        result, stderr = call(argv, tool)
        want = f"fathomgate refused an input request (input_required) from upstream {SERVER} during {tool}: {REASON}"
        texts = [c.get("text") for c in (result or {}).get("content", []) if c.get("type") == "text"]
        allowed = any(
            "msg=decision " in line and f" tool={tool} " in line and " decision=allow rule_id=conf-reads " in line and " forwarded=true " in line
            for line in stderr.splitlines()
        )
        if result is not None and result.get("isError") is True and texts == [want] and allowed:
            print(f"ok   {tool}: allowed by conf-reads, upstream prompt refused under the policy")
            continue
        failed += 1
        print(f"FAIL {tool}: result={json.dumps(result)[:600]} allowed_line={allowed}", file=sys.stderr)
        print(stderr[-3000:], file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
