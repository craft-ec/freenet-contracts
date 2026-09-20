#!/usr/bin/env bash
# The accept/refuse differential: does wasm-opt change what a contract KEEPS?
#
# Run it before adopting wasm-opt, before changing its flags, and before
# bumping binaryen. It answers one question and refuses to answer it vacuously:
# the corpus is generated from the contracts' own code, every base case is
# DECLARED accepted (a declaration the contract refuses is a hard failure), and
# the runner exits non-zero if any contract has no accepted case — because two
# builds that both refuse everything agree perfectly.
#
#   ./wasmopt-check.sh              differential over -O2/-Os/-Oz
#   ./wasmopt-check.sh --self-test  ALSO builds a mis-optimised contract and
#                                   requires the differential to CATCH it
set -euo pipefail
cd "$(dirname "$0")"

# Pinned, and asserted. wasm-opt's output is reproducible for a given binaryen
# but NOT across versions, so an unpinned tool would move every contract hash
# on an upgrade with nothing to notice it.
WANT_BINARYEN="${WASMOPT_VERSION:-125}"
FLAGS=(--enable-bulk-memory-opt --enable-bulk-memory)
LEVELS=(O2 Os Oz)

command -v wasm-opt >/dev/null || { echo "wasmopt-check: wasm-opt not installed" >&2; exit 1; }
command -v node >/dev/null || { echo "wasmopt-check: node not installed" >&2; exit 1; }
got=$(wasm-opt --version | awk '{print $NF}')
[ "$got" = "$WANT_BINARYEN" ] || {
  echo "wasmopt-check: binaryen $got, expected $WANT_BINARYEN — a different" >&2
  echo "  binaryen produces different bytes, so a result from it is about another tool." >&2
  exit 1; }

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
mkdir -p "$work/builds" "$work/corpus"

[ -f build/block.wasm ] || { echo "wasmopt-check: build/*.wasm missing — run ./build.sh first" >&2; exit 1; }
for c in bag block register set; do
  cp "build/$c.wasm" "$work/builds/$c.as-built.wasm"
  for lvl in "${LEVELS[@]}"; do
    wasm-opt "-$lvl" "${FLAGS[@]}" "build/$c.wasm" -o "$work/builds/$c.$lvl.wasm"
    # wasm-opt FAILS SILENTLY on flags it does not accept: no error, no exit
    # status, and NO OUTPUT FILE. A check that cannot tell that apart from
    # success is a check that passes by producing nothing.
    [ -s "$work/builds/$c.$lvl.wasm" ] || { echo "wasmopt-check: -$lvl produced no output for $c" >&2; exit 1; }
    a=$(wc -c < "build/$c.wasm"); b=$(wc -c < "$work/builds/$c.$lvl.wasm")
    [ "$b" -lt "$a" ] || { echo "wasmopt-check: -$lvl did not shrink $c ($a -> $b)" >&2; exit 1; }
  done
done

( cd vectors && cargo run --quiet --release -- "$work/corpus" )
node wasmopt/diff.js "$work/builds" "$work/corpus/cases.jsonl"

[ "${1:-}" = "--self-test" ] || exit 0

# THE CONTROL. A differential that has never been shown to fail is a differential
# nobody has tested. Delete a real rule from the contract, rebuild, optimise, and
# require the run to catch it.
echo
echo "== self-test: a mis-optimised contract must be CAUGHT =="
rule='        && state.len() <= 1 + max_body(state[0])'
n=$(grep -cF "$rule" block/src/lib.rs || true)
[ "$n" = 1 ] || { echo "self-test: the rule to remove matched $n times, expected 1" >&2; exit 1; }
cp block/src/lib.rs "$work/lib.rs.orig"; cp build/block.wasm "$work/block.wasm.orig"
restore() { cp "$work/lib.rs.orig" block/src/lib.rs; cp "$work/block.wasm.orig" build/block.wasm; }
trap 'restore; rm -rf "$work"' EXIT
grep -vF "$rule" block/src/lib.rs > "$work/lib.rs.mut" && cp "$work/lib.rs.mut" block/src/lib.rs
cmp -s "$work/lib.rs.orig" block/src/lib.rs && { echo "self-test: the mutation did not land" >&2; exit 1; }
env -u CARGO_TARGET_DIR ./block/build.sh >/dev/null
wasm-opt -Oz "${FLAGS[@]}" build/block.wasm -o "$work/builds/block.Oz.wasm"
restore
if node wasmopt/diff.js "$work/builds" "$work/corpus/cases.jsonl" > "$work/out" 2>&1; then
  echo "SELF-TEST FAILED: the differential did not catch a contract with a rule removed" >&2
  cat "$work/out" >&2; exit 1
fi
grep -c '^DISAGREE' "$work/out" | xargs -I{} echo "  caught it: {} case(s) disagreed"
cmp -s "$work/block.wasm.orig" build/block.wasm && echo "  build/block.wasm restored byte-identical"
echo "self-test: PASS"
