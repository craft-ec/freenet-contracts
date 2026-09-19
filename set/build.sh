#!/usr/bin/env bash
# Reproducible build of set.wasm. The flags are in ../contract-build.sh, one
# copy for every contract: a hash is a network key, and four contracts built
# with four slightly different flag sets is the failure this prevents.
set -euo pipefail
exec "$(dirname "$0")/../contract-build.sh" set craftec-set-contract "$@"
