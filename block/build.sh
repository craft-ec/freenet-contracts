#!/usr/bin/env bash
# Reproducible build of block.wasm. The flags are in ../contract-build.sh, one
# copy for every contract: a hash is a network key, and three contracts built
# with three slightly different flag sets is the failure this prevents.
set -euo pipefail
exec "$(dirname "$0")/../contract-build.sh" block craftec-block-contract "$@"
