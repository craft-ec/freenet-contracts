#!/usr/bin/env bash
# Build every contract to build/*.wasm, reproducibly.
# The list is DERIVED from the tree, so a new contract is built by existing.
set -euo pipefail
cd "$(dirname "$0")"
n=0
for b in */build.sh; do "./$b" "$@"; n=$((n + 1)); done
[ "$n" -gt 0 ] || { echo "build: no contracts found (*/build.sh matched nothing)" >&2; exit 1; }
