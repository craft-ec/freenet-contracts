#!/usr/bin/env bash
# Reproducible build of block.wasm: paths are remapped so two clean checkouts
# produce identical bytes (the wasm hash is part of every block's network key).
set -euo pipefail
cd "$(dirname "$0")"
export RUSTFLAGS="--remap-path-prefix=$PWD=/block --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup"
cargo build --release --target wasm32-unknown-unknown "$@"
mkdir -p ../build
cp target/wasm32-unknown-unknown/release/craftec_block_contract.wasm ../build/block.wasm
echo "build/block.wasm $(wc -c < ../build/block.wasm | tr -d ' ') bytes blake3=$(b3sum ../build/block.wasm 2>/dev/null | cut -c1-16 || echo '?')"
