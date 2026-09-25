#!/bin/sh
# SPDX-License-Identifier: FSL-1.1-ALv2
# Install upa/mcp-netmiko-server, pinned, for the tier 2 tests (T0.34).
#
#   tests/integration/upstreams/upa-mcp-netmiko-server/install.sh DEST
#
# DEST/src           the upstream at UPA_COMMIT (git checks the commit id;
#                    the tests also check main.py's sha256)
# DEST/venv-current  Python 3.13 with requirements.txt (mcp 1.30.0, every
#                    wheel hash-checked): negotiates 2025-11-25
# DEST/venv-locked   Python 3.13 from the upstream's own uv.lock (uv sync
#                    --locked checks its hashes): mcp 1.6.0, 2024-11-05 only
#
# Prints the three FATHOMGATE_UPA_* variables the tests read, one per line,
# for `>> "$GITHUB_ENV"` or `export`. Needs git and uv; uv fetches Python
# 3.13 if it is missing. Bump UPA_COMMIT here and in
# tests/integration/conftest.py together.
set -eu

UPA_REPO=https://github.com/upa/mcp-netmiko-server
UPA_COMMIT=96e8ff321cc839eeb525474736439ddc2ebc795c

dest=${1:?usage: install.sh DEST}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$dest"
dest=$(cd "$dest" && pwd)

if [ ! -d "$dest/src/.git" ]; then
  git init -q "$dest/src"
fi
git -C "$dest/src" fetch -q --depth 1 "$UPA_REPO" "$UPA_COMMIT"
git -C "$dest/src" checkout -q --detach FETCH_HEAD
got=$(git -C "$dest/src" rev-parse HEAD)
if [ "$got" != "$UPA_COMMIT" ]; then
  echo "install.sh: fetched $got, want $UPA_COMMIT" >&2
  exit 1
fi

# The upstream as its authors lock it. The project has no build system, so
# there is nothing of its own to install; --locked fails if uv.lock does not
# match pyproject.toml.
(cd "$dest/src" && UV_PROJECT_ENVIRONMENT="$dest/venv-locked" uv sync -q --locked --no-install-project --python 3.13)

uv venv -q --allow-existing --python 3.13 "$dest/venv-current"
VIRTUAL_ENV="$dest/venv-current" uv pip install -q --require-hashes -r "$here/requirements.txt"

echo "FATHOMGATE_UPA_DIR=$dest/src"
echo "FATHOMGATE_UPA_PYTHON=$dest/venv-current/bin/python"
echo "FATHOMGATE_UPA_LOCKED_PYTHON=$dest/venv-locked/bin/python"
