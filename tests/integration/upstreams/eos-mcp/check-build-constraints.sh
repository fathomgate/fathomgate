#!/bin/sh
# SPDX-License-Identifier: FSL-1.1-ALv2
# Negative control for install.sh: prove that the uv in use checks the hashes
# in --build-constraints, so the setuptools that builds the pyeapi 1.0.4 sdist
# is the hashed one in build-constraints.txt and nothing else.
#
#   tests/integration/upstreams/eos-mcp/check-build-constraints.sh SCRATCH
#
# It builds pyeapi alone (no dependencies, no cache) twice in throwaway venvs
# under SCRATCH: with build-constraints.txt, which must succeed, and with the
# same file with its hashes replaced, which must fail with a hash mismatch.
# Exit 0 only if both happen. uv without --build-constraints would build the
# sdist with whatever setuptools the index serves, hashes or not.
set -eu

scratch=${1:?usage: check-build-constraints.sh SCRATCH}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$scratch"
scratch=$(cd "$scratch" && pwd)

# The pyeapi requirement with its hash, exactly as requirements.txt has it.
awk '/^pyeapi==/{p=1} p&&/^    #/{exit} p{print}' "$here/requirements.txt" > "$scratch/pyeapi.txt"
grep -q -- '--hash=sha256:' "$scratch/pyeapi.txt"
sed -E 's/sha256:[0-9a-f]{64}/sha256:0000000000000000000000000000000000000000000000000000000000000000/' \
  "$here/build-constraints.txt" > "$scratch/build-constraints-bad.txt"

build() {
  rm -rf "$scratch/venv-$1"
  uv venv -q --python 3.13 "$scratch/venv-$1"
  VIRTUAL_ENV="$scratch/venv-$1" uv pip install -q --no-cache --no-deps --require-hashes \
    -r "$scratch/pyeapi.txt" --build-constraints "$2" > "$scratch/$1.log" 2>&1
}

if ! build good "$here/build-constraints.txt"; then
  cat "$scratch/good.log" >&2
  echo "check-build-constraints: pyeapi did not build with the hashed build constraints" >&2
  exit 1
fi
if build bad "$scratch/build-constraints-bad.txt"; then
  echo "check-build-constraints: uv built pyeapi with a setuptools whose hash is not in the constraints; build hashes are not enforced" >&2
  exit 1
fi
if ! grep -qi "hash" "$scratch/bad.log"; then
  cat "$scratch/bad.log" >&2
  echo "check-build-constraints: the bad-hash build failed, but not on a hash mismatch" >&2
  exit 1
fi
echo "check-build-constraints: $(uv --version) enforces build-constraint hashes (setuptools for pyeapi 1.0.4)"
