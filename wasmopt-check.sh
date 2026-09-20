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

work=$(mktemp -d)
mkdir -p "$work/builds" "$work/corpus"

[ -f build/block.wasm ] || { echo "wasmopt-check: build/*.wasm missing — run ./build.sh first" >&2; exit 1; }
# The reference is the SAME compile with the optimiser skipped — not the
# shipped artefact, which is now -Os. Comparing -Os against itself would be a
# gate that passes by construction.
for c in bag block register set; do cp "build/$c.wasm" "$work/shipped-$c.wasm"; done
trap 'for c in bag block register set; do [ -f "$work/shipped-$c.wasm" ] && cp "$work/shipped-$c.wasm" "build/$c.wasm"; done; rm -rf "$work"' EXIT
CONTRACT_BUILD_NO_WASM_OPT=1 ./build.sh >/dev/null
for c in bag block register set; do
  cp "build/$c.wasm" "$work/builds/$c.as-built.wasm"
  a=$(wc -c < "$work/builds/$c.as-built.wasm"); b=$(wc -c < "$work/shipped-$c.wasm")
  [ "$a" -gt "$b" ] || { echo "wasmopt-check: the reference build of $c is not larger than the shipped one ($a vs $b) — the skip switch did nothing" >&2; exit 1; }
  for lvl in "${LEVELS[@]}"; do
    wasm-opt "-$lvl" "${FLAGS[@]}" "$work/builds/$c.as-built.wasm" -o "$work/builds/$c.$lvl.wasm"
    # wasm-opt FAILS SILENTLY on flags it does not accept: no error, no exit
    # status, and NO OUTPUT FILE. A check that cannot tell that apart from
    # success is a check that passes by producing nothing.
    [ -s "$work/builds/$c.$lvl.wasm" ] || { echo "wasmopt-check: -$lvl produced no output for $c" >&2; exit 1; }
    a=$(wc -c < "$work/builds/$c.as-built.wasm"); b=$(wc -c < "$work/builds/$c.$lvl.wasm")
    [ "$b" -lt "$a" ] || { echo "wasmopt-check: -$lvl did not shrink $c ($a -> $b)" >&2; exit 1; }
  done
done

( cd vectors && cargo run --quiet --release -- "$work/corpus" )
node wasmopt/diff.js "$work/builds" "$work/corpus/cases.jsonl"

[ "${1:-}" = "--self-test" ] || exit 0

# THE CONTROL. A differential that has never been shown to fail is a
# differential nobody has tested. Delete a real rule from the contract,
# rebuild, optimise, and require the run to catch it.
#
# The mutation happens in a COPY of the crate, never in this checkout. Editing
# `block/src/lib.rs` in place and restoring it from a trap is fine until the
# trap does not run — a SIGKILL, a power cut, a second session in the same
# worktree — and what it leaves behind is a contract with a validation rule
# deleted, one `git add` away from being committed. No gate is worth that.
echo
echo "== self-test: a mis-optimised contract must be CAUGHT =="
rule='        && state.len() <= 1 + max_body(state[0])'
n=$(grep -cF "$rule" block/src/lib.rs || true)
[ "$n" = 1 ] || { echo "self-test: the rule to remove matched $n times, expected 1" >&2; exit 1; }

repo=$work/repo
mkdir -p "$repo"
cp contract-build.sh "$repo/"
cp -R block "$repo/block"
rm -rf "$repo/block/target"
# The contracts have no path dependency on each other, so a copy builds to the
# same bytes from anywhere (#37 measured exactly this). Only the MUTANT's bytes
# matter here anyway.
grep -vF "$rule" block/src/lib.rs > "$repo/block/src/lib.rs"
cmp -s block/src/lib.rs "$repo/block/src/lib.rs" &&
  { echo "self-test: the mutation did not land" >&2; exit 1; }

( cd "$repo" && env -u CARGO_TARGET_DIR CONTRACT_BUILD_NO_WASM_OPT=1 ./block/build.sh ) >/dev/null
[ -s "$repo/build/block.wasm" ] ||
  { echo "self-test: the mutated crate did not build" >&2; exit 1; }
wasm-opt -Oz "${FLAGS[@]}" "$repo/build/block.wasm" -o "$work/builds/block.Oz.wasm"

if node wasmopt/diff.js "$work/builds" "$work/corpus/cases.jsonl" > "$work/out" 2>&1; then
  echo "SELF-TEST FAILED: the differential did not catch a contract with a rule removed" >&2
  cat "$work/out" >&2; exit 1
fi
echo "  caught it: $(grep -c '^DISAGREE' "$work/out") case(s) disagreed"
# Nothing in this checkout was touched, so there is nothing to restore — which
# is the point. Say so, and prove it.
if git rev-parse --git-dir >/dev/null 2>&1; then
  dirty=$(git status --porcelain -- block build 2>/dev/null | wc -l | tr -d ' ')
  [ "$dirty" = 0 ] ||
    { echo "self-test: the checkout was modified ($dirty path(s)) — it must not be" >&2
      git status --porcelain -- block build >&2; exit 1; }
  echo "  the checkout is untouched: git reports no change under block/ or build/"
fi
echo "self-test: PASS"
