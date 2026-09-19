#!/usr/bin/env bash
# Reproducible build of bag.wasm: paths are remapped so two clean checkouts
# produce identical bytes (the wasm hash is part of every bag's network key).
set -euo pipefail
cd "$(dirname "$0")"

# Every git dependency is unpacked into a directory cargo names after the
# REVISION, and that name reaches the binary through panic locations — so two
# revisions with identical code produced different wasm, and a contract's hash
# is its network key. Remap each checkout to the package's name alone: the hash
# commits to the compiled code, not to the name of the revision it came from.
# Derived, never hard-coded: a rev bump must not need an edit here.
dep_remaps() {
  local d name pkg
  for d in "$HOME/.cargo/git/checkouts"/*/*/; do
    [ -d "$d" ] || continue
    name=$(basename "$(dirname "$d")")   # freenet-prolly-e710ec000d97f4d5
    pkg=${name%-*}                       # freenet-prolly
    printf ' --remap-path-prefix=%s=/dep/%s' "${d%/}" "$pkg"
  done
}

export RUSTFLAGS="--remap-path-prefix=$PWD=/bag --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME/.rustup=/rustup$(dep_remaps)"
# --locked: build the dependency versions this repo recorded, never a
# freshly resolved set — the wasm hash is part of the contract's network key.
cargo build --locked --release --target wasm32-unknown-unknown "$@"
mkdir -p ../build
cp target/wasm32-unknown-unknown/release/craftec_bag_contract.wasm ../build/bag.wasm
echo "build/bag.wasm $(wc -c < ../build/bag.wasm | tr -d ' ') bytes blake3=$(b3sum ../build/bag.wasm 2>/dev/null | cut -c1-16 || echo '?')"
