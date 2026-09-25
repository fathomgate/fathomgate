#!/bin/sh
# SPDX-License-Identifier: FSL-1.1-ALv2
# Install shigechika/eos-mcp v1.3.0, pinned, for the tier 2 tests (M1-22).
#
#   tests/integration/upstreams/eos-mcp/install.sh DEST
#
# DEST/venv  Python 3.13 with requirements.txt: eos-mcp 1.3.0 from PyPI and
#            its dependencies, every artifact hash-checked (--require-hashes).
#            All are wheels except pyeapi 1.0.4, which PyPI has only as an
#            sdist (its hash is checked too); uv builds it with the setuptools
#            pinned and hash-checked in build-constraints.txt, and without
#            --build-constraints it would take whatever setuptools the index
#            serves, unhashed. check-build-constraints.sh proves the uv in use
#            enforces those hashes (CI runs it first). The tests also check
#            each installed eos_mcp/*.py against the sha256 of the same file
#            at commit bffb893 (the tag v1.3.0, which profiles/eos-mcp.yaml
#            was read at).
#
# Prints FATHOMGATE_EOS_MCP (the venv's `eos-mcp` entry point, the command
# the upstream's README configures), for `>> "$GITHUB_ENV"` or `export`.
# Needs uv; uv fetches Python 3.13 if it is missing. Bump the pin here, in
# requirements.in/.txt, build-constraints.in/.txt and in
# tests/integration/conftest.py together.
set -eu

dest=${1:?usage: install.sh DEST}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$dest"
dest=$(cd "$dest" && pwd)

uv venv -q --allow-existing --python 3.13 "$dest/venv"
VIRTUAL_ENV="$dest/venv" uv pip install -q --require-hashes -r "$here/requirements.txt"   --build-constraints "$here/build-constraints.txt"

# uv lays a venv out as bin/ on Unix and Scripts/ on Windows (Git Bash).
if [ -e "$dest/venv/bin/eos-mcp" ]; then
  echo "FATHOMGATE_EOS_MCP=$dest/venv/bin/eos-mcp"
else
  # Git Bash: print a path Windows programs read (C:/...).
  echo "FATHOMGATE_EOS_MCP=$(cygpath -m "$dest/venv/Scripts/eos-mcp.exe")"
fi
