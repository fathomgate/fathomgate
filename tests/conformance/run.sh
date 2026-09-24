#!/usr/bin/env bash
# Run the official MCP conformance suite against one leg and one spec
# revision. `make conformance` calls this for every leg and revision.
#
#   tests/conformance/run.sh <leg> <revision>
#
#   leg       netguard  relay -> netguard serve (stdio) -> everything-server
#             control   relay -> everything-server, no netguard: proves the
#                       relay is transparent, so a failure only on the
#                       netguard leg belongs to netguard
#   revision  2025-11-25 (stateful, initialize) or 2026-07-28 (stateless)
#
# The suite exits non-zero on any scored failure that is not listed in
# baseline/<leg>-<revision>.yml, and on any listed entry that now passes
# (a stale baseline). Results go to $CONFORMANCE_OUT/<leg>-<revision>/.
#
# Environment (all optional):
#   NETGUARD_BIN        netguard binary          (bin/netguard)
#   CONFORMANCE_SERVER  go-sdk everything-server (bin/conformance/everything-server)
#   CONFORMANCE_OUT     results root             (tests/conformance/results)
#   PYTHON              interpreter for relay.py (python3; stdlib only)
set -euo pipefail

usage() {
  echo "usage: $0 <netguard|control> <2025-11-25|2026-07-28>" >&2
  exit 2
}
[ $# -eq 2 ] || usage
leg=$1
rev=$2
case "$leg" in netguard | control) ;; *) usage ;; esac
case "$rev" in 2025-11-25 | 2026-07-28) ;; *) usage ;; esac

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
netguard=${NETGUARD_BIN:-$root/bin/netguard}
fixture=${CONFORMANCE_SERVER:-$root/bin/conformance/everything-server}
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
if [ "$leg" = netguard ] && [ ! -x "$netguard" ]; then
  echo "conformance: missing $netguard (run \`make build\`)" >&2
  exit 2
fi

# The server name "conf" is the tool prefix netguard applies; relay.py puts
# it on the suite's unprefixed tools/call names (and nowhere else).
if [ "$leg" = netguard ]; then
  cmd=(--tool-prefix conf -- "$netguard" serve --server conf --upstream "$fixture")
else
  cmd=(-- "$fixture")
fi

# Let the OS pick a free loopback port.
port=$("$python" -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
url="http://127.0.0.1:$port/mcp"

# Fresh results for this leg: the suite writes one timestamped directory per
# scenario, and old runs would otherwise pile up next to the new one.
case "$out" in */conformance/results/*-20??-??-?? | "${CONFORMANCE_OUT:-}"/*-20??-??-??) rm -rf "$out" ;; esac
mkdir -p "$out"
relay_log=$out/relay.log
"$python" "$here/relay.py" --port "$port" "${cmd[@]}" >"$relay_log" 2>&1 &
relay_pid=$!
# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
  kill "$relay_pid" 2>/dev/null || true
  wait "$relay_pid" 2>/dev/null || true
}
trap cleanup EXIT

# Ready when the listener answers (GET is 405 by design).
ready=0
for _ in $(seq 1 50); do
  if "$python" -c 'import sys, urllib.request, urllib.error
try:
    urllib.request.urlopen(sys.argv[1], timeout=1)
except urllib.error.HTTPError:
    pass
except Exception:
    sys.exit(1)' "$url"; then
    ready=1
    break
  fi
  if ! kill -0 "$relay_pid" 2>/dev/null; then
    break
  fi
  sleep 0.2
done
if [ "$ready" != 1 ]; then
  echo "conformance: relay did not start; log follows" >&2
  cat "$relay_log" >&2
  exit 1
fi

echo "== conformance $leg $rev ($url)"
status=0
(cd "$out" && "$suite" server --url "$url" --requirements "$rev" \
  --expected-failures "$baseline" --output-dir "$out") || status=$?
if [ "$status" -ne 0 ]; then
  echo "conformance: $leg $rev failed (exit $status); relay and child stderr in $relay_log" >&2
fi
exit "$status"
