#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
# Run the official MCP conformance suite against one leg and one spec
# revision over Streamable HTTP. `make conformance` calls this for every leg
# and revision.
#
#   tests/conformance/run.sh <leg> <revision>
#
# A leg is a chain (with or without fathomgate) and an upstream fixture. The
# suite always reaches the chain through shim.py (T0.32, ADR 0016): on a
# fathomgate leg it adds the bearer token and the `conf.` tool prefix, on a
# control leg it changes nothing.
#
#   leg                chain                                                 upstream
#   control            shim -> everything-server -http                       current
#   fathomgate         shim -> fathomgate serve --listen -> upstream (stdio)  current
#   control-up2025     shim -> everything-server -http                       2025
#   fathomgate-up2025  shim -> fathomgate serve --listen -> upstream (stdio)  2025
#
#   upstream  current  go-sdk conformance/everything-server at the go.mod
#                      version; negotiates 2026-07-28 with fathomgate. On a
#                      control leg it serves HTTP itself, -stateless=false for
#                      2025-11-25 and -stateless=true for 2026-07-28, as
#                      go-sdk's own conformance workflow does
#             2025     the same server at go-sdk v1.6.1, the last release
#                      before 2026-07-28 support (upstream-2025/go.mod);
#                      speaks 2025-11-25 and older only (its -http handler
#                      is always stateful)
#   revision  2025-11-25 (stateful, initialize) or 2026-07-28 (stateless)
#
# A control leg proves the shim transparent and gives the upstream's own HTTP
# result, so a failure only on the matching fathomgate leg belongs to
# fathomgate. control-up2025 has no 2026-07-28 run (a 2025-only server cannot
# speak it with nothing in between): that pair prints "skipped" and exits 0;
# it is never scored.
#
# fathomgate gets a fresh FAKE-prefixed token through FATHOMGATE_LISTEN_TOKEN
# (principal `env`), and the shim the same value through
# CONFORMANCE_SHIM_TOKEN. Neither is ever on a command line or printed; a
# token found in any result or log file fails the run.
#
# The suite exits non-zero on any scored failure that is not listed in
# baseline/<leg>-<revision>.yml, and on any listed entry that now passes
# (a stale baseline). On a 2025-11-25 fathomgate leg a few scenarios then
# run again, each alone on a fresh fathomgate, and must pass outright
# (README, "One process"): server-session-lifecycle, and on
# fathomgate-up2025 tools-call-elicitation and elicitation-sep1034-defaults. Results go to $CONFORMANCE_OUT/<leg>-<revision>/, with
# chain.log (fathomgate's and the upstream's stderr, or the control
# upstream's) and shim.log beside them, and isolated-<scenario>/ for each
# fresh-process run.
#
# Environment (all optional):
#   FATHOMGATE_BIN           fathomgate binary         (bin/fathomgate)
#   CONFORMANCE_SERVER       current upstream          (bin/conformance/everything-server)
#   CONFORMANCE_SERVER_2025  2025 upstream             (bin/conformance/everything-server-2025)
#   CONFORMANCE_OUT          results root              (tests/conformance/results)
#   PYTHON                   interpreter for shim.py   (python3; stdlib only)
set -euo pipefail

usage() {
  echo "usage: $0 <control|fathomgate|control-up2025|fathomgate-up2025> <2025-11-25|2026-07-28>" >&2
  exit 2
}
[ $# -eq 2 ] || usage
leg=$1
rev=$2
case "$rev" in 2025-11-25 | 2026-07-28) ;; *) usage ;; esac

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

# Leg: which chain, which upstream.
case "$leg" in
  control) chain=direct upstream=current ;;
  fathomgate) chain=fathomgate upstream=current ;;
  control-up2025) chain=direct upstream=2025 ;;
  fathomgate-up2025) chain=fathomgate upstream=2025 ;;
  *) usage ;;
esac
if [ "$chain" = direct ] && [ "$upstream" = 2025 ] && [ "$rev" = 2026-07-28 ]; then
  echo "== conformance $leg $rev: skipped (a 2025-only upstream has no 2026-07-28 run without fathomgate in front)"
  exit 0
fi

# Upstream selection.
case "$upstream" in
  current) fixture=${CONFORMANCE_SERVER:-$root/bin/conformance/everything-server} ;;
  2025) fixture=${CONFORMANCE_SERVER_2025:-$root/bin/conformance/everything-server-2025} ;;
esac

fathomgate=${FATHOMGATE_BIN:-$root/bin/fathomgate}
out=${CONFORMANCE_OUT:-$here/results}/$leg-$rev
python=${PYTHON:-python3}
suite=$here/node_modules/.bin/conformance
baseline=$here/baseline/$leg-$rev.yml

for f in "$fixture" "$suite" "$baseline"; do
  if [ ! -e "$f" ]; then
    echo "conformance: missing $f (run \`make conformance\`, which builds and installs it)" >&2
    exit 2
  fi
done
if [ "$chain" = fathomgate ] && [ ! -x "$fathomgate" ]; then
  echo "conformance: missing $fathomgate (run \`make build\`)" >&2
  exit 2
fi

# Fresh results for this leg: the suite writes one timestamped directory per
# scenario, and old runs would otherwise pile up next to the new one.
case "$out" in */conformance/results/*-20??-??-?? | "${CONFORMANCE_OUT:-}"/*-20??-??-??) rm -rf "$out" ;; esac
mkdir -p "$out"

# A listen token from the caller's shell must never reach the harness.
unset FATHOMGATE_LISTEN_TOKEN CONFORMANCE_SHIM_TOKEN
token=
if [ "$chain" = fathomgate ]; then
  # Printable ASCII, at least 32 bytes (cmd/fathomgate checkListenToken).
  token=$("$python" -c 'import secrets; print("FAKE-conformance-" + secrets.token_hex(16))')
fi

chain_pid=
shim_pid=
# stop_pid PID: SIGTERM, up to 10 s for it to exit, then SIGKILL.
stop_pid() {
  local pid=$1
  [ -n "$pid" ] || return 0
  kill "$pid" 2>/dev/null || return 0
  for _ in $(seq 1 100); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -9 "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}
# shellcheck disable=SC2329 # also invoked by the EXIT trap
stop_chain() {
  stop_pid "$shim_pid"
  stop_pid "$chain_pid"
  shim_pid=
  chain_pid=
}
trap stop_chain EXIT

# wait_line FILE PATTERN PID: print the first `<key>=<value>` match of
# PATTERN in FILE once it appears; fail if PID exits or 15 s pass.
wait_line() {
  local file=$1 pattern=$2 pid=$3 line
  for _ in $(seq 1 75); do
    line=$(grep -o -m 1 -- "$pattern" "$file" 2>/dev/null || true)
    if [ -n "$line" ]; then
      echo "${line#*=}"
      return 0
    fi
    kill -0 "$pid" 2>/dev/null || return 1
    sleep 0.2
  done
  return 1
}

fail_start() {
  echo "conformance: $1 did not start; logs follow" >&2
  cat "$chain_log" "$shim_log" >&2 2>/dev/null || true
  exit 1
}

# start_chain DIR: start the chain and the shim in front of it, logging to
# DIR/chain.log and DIR/shim.log; sets chain_pid, shim_pid, target and url.
start_chain() {
  chain_log=$1/chain.log
  shim_log=$1/shim.log
  local prefix=()
  if [ "$chain" = fathomgate ]; then
    # The server name "conf" is the tool prefix fathomgate applies; the shim
    # puts it on the suite's unprefixed tools/call names (and nowhere else).
    # --no-policy: the suite checks the protocol, through the pass-through
    # (ADR 0027), so the baselines do not change with the policy.
    FATHOMGATE_LISTEN_TOKEN=$token "$fathomgate" serve --listen 127.0.0.1:0 \
      --server conf --upstream "$fixture" --no-policy </dev/null >"$chain_log" 2>&1 &
    chain_pid=$!
    # One `listening url=` line per loopback family, the address asked for
    # first (ADR 0023); the shim targets that one.
    target=$(wait_line "$chain_log" 'listening url=[^ ]*' "$chain_pid") || fail_start "fathomgate serve --listen"
    prefix=(--tool-prefix conf)
  else
    # everything-server -http takes a fixed address: let the OS pick a free
    # loopback port, then hand it over (a small race, as in go-sdk's workflow).
    local port args ready=0
    port=$("$python" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
    args=(-http "127.0.0.1:$port")
    if [ "$upstream" = current ]; then
      if [ "$rev" = 2025-11-25 ]; then args+=(-stateless=false); else args+=(-stateless=true); fi
    fi
    "$fixture" "${args[@]}" </dev/null >"$chain_log" 2>&1 &
    chain_pid=$!
    target="http://127.0.0.1:$port/mcp"
    # Ready when the server answers anything over HTTP.
    for _ in $(seq 1 75); do
      if "$python" -c 'import sys, urllib.request, urllib.error
try:
    urllib.request.urlopen(sys.argv[1], timeout=1)
except urllib.error.HTTPError:
    pass
except Exception:
    sys.exit(1)' "$target"; then
        ready=1
        break
      fi
      kill -0 "$chain_pid" 2>/dev/null || break
      sleep 0.2
    done
    [ "$ready" = 1 ] || fail_start "everything-server -http"
  fi
  # The shim in front. It reads the token from its environment only.
  # ${prefix[@]+...}: an empty array under `set -u` on bash < 4.4 (macOS).
  CONFORMANCE_SHIM_TOKEN=$token "$python" "$here/shim.py" --target "$target" ${prefix[@]+"${prefix[@]}"} \
    </dev/null >"$shim_log" 2>&1 &
  shim_pid=$!
  url=$(wait_line "$shim_log" 'shim listening url=[^ ]*' "$shim_pid") || fail_start "shim.py"
}

start_chain "$out"
echo "== conformance $leg $rev ($url -> $target)"
status=0
(cd "$out" && "$suite" server --url "$url" --requirements "$rev" \
  --expected-failures "$baseline" --output-dir "$out") || status=$?
if [ "$status" -ne 0 ]; then
  echo "conformance: $leg $rev failed (exit $status); chain stderr in $chain_log, shim log in $shim_log" >&2
fi
# Stop the chain before reading its log, so every line is flushed.
stop_chain

# Fresh-process scenarios (2025-11-25 fathomgate legs). In the run above one
# fathomgate serves every scenario, so the session cap and the orphan rule
# (README, "One process") hide these; here each runs alone against a
# fathomgate of its own and must pass outright, scored by the suite's exit
# code. The --requirements run cannot take --scenario, hence --spec-version.
isolated=()
if [ "$chain" = fathomgate ] && [ "$rev" = 2025-11-25 ]; then
  isolated=(server-session-lifecycle)
  if [ "$upstream" = 2025 ]; then
    isolated+=(tools-call-elicitation elicitation-sep1034-defaults)
  fi
fi
for scenario in ${isolated[@]+"${isolated[@]}"}; do
  dir=$out/isolated-$scenario
  mkdir -p "$dir"
  start_chain "$dir"
  echo "== conformance $leg $rev, $scenario alone on a fresh fathomgate ($url -> $target)"
  scenario_status=0
  (cd "$dir" && "$suite" server --url "$url" --scenario "$scenario" --spec-version "$rev" \
    --output-dir "$dir") >"$dir/suite.log" 2>&1 || scenario_status=$?
  stop_chain
  if [ "$scenario_status" -ne 0 ]; then
    cat "$dir/suite.log"
    echo "conformance: $leg $rev: $scenario failed on a fresh fathomgate (exit $scenario_status); logs in $dir" >&2
    status=1
  else
    grep -E '^(Passed|Test Results)' "$dir/suite.log" | tail -1 || true
  fi
done

# The token must not appear in any result or log. It is given to grep on
# stdin (-f -), never on its command line.
if [ -n "$token" ] && printf '%s\n' "$token" | grep -rqF -f - "$out"; then
  echo "conformance: $leg $rev: the listen token appears in $out (value not shown)" >&2
  status=1
fi
exit "$status"
