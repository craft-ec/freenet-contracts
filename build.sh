#!/usr/bin/env bash
# Build every contract to build/*.wasm, reproducibly.
set -euo pipefail
cd "$(dirname "$0")"
for c in block register bag; do "./$c/build.sh" "$@"; done
