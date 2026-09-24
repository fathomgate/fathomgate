#!/usr/bin/env bash
# One-time setup of the WSL CI runners (docs/ci-runners.md). Run in the WSL
# Ubuntu shell as the user who registered them: it asks for your sudo password.
# Idempotent: re-running it only restarts the services.
set -euo pipefail

sudo apt-get install -y shellcheck

for i in 1 2 3; do
  d="$HOME/actions-runner-$i"
  if [ ! -f "$d/.runner" ]; then
    echo "skip ng-wsl-$i: $d is not registered (see docs/ci-runners.md)" >&2
    continue
  fi
  cd "$d"
  if [ ! -f .service ]; then
    sudo ./svc.sh install "$USER"
  fi
  sudo ./svc.sh start
done

echo "done; check with: gh api repos/joshscott13/netguard/actions/runners -q '.runners[]|.name+\" \"+.status'"
