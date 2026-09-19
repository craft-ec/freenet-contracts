#!/usr/bin/env bash
# Reproducible build of register.wasm: paths are remapped so two clean checkouts
# produce identical bytes (the wasm hash is part of every register's network key).
set -euo pipefail
cd "$(dirname "$0")"
export RUSTFLAGS="--remap-path-prefix=$PWD=/register --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup"
# --locked: build the dependency versions this repo recorded, never a
# freshly resolved set — the wasm hash is part of the contract's network key.
cargo build --locked --release --target wasm32-unknown-unknown "$@"
mkdir -p ../build
cp target/wasm32-unknown-unknown/release/craftec_register_contract.wasm ../build/register.wasm
echo "build/register.wasm $(wc -c < ../build/register.wasm | tr -d ' ') bytes blake3=$(b3sum ../build/register.wasm 2>/dev/null | cut -c1-16 || echo '?')"
