#!/usr/bin/env bash
# What a contract's wasm hash must NOT depend on.
#
# The hash is part of the contract's network key, so anything it moves with is
# something that re-keys every instance in existence. This gate asserts
# PROPERTIES rather than a constant: a pinned expected hash would go red on
# every legitimate code change, and the person who then bumps it has silently
# declared an epoch. The released hashes live in `released.toml` and are never
# compared against here.
#
#   a   two clean builds of the same tree, at the same path, are equal
#   b1  a build from a different absolute repo directory is equal
#   b2  a build with a different absolute cargo home is equal
#   c   a build with a blank line inserted at the top of every source file of
#       the crate is equal — i.e. a comment edit does not re-key the contract
#   d   build/hashes.toml agrees with the wasm on disk (hashes-check.sh)
#
# and then, on a build made with the remaps and NO location strip — the only
# build in which the remaps are visible at all — that no cargo index-hash
# directory, no revision-named git checkout and no `$HOME` reached the binary,
# with floors of at least one `/registry/` path and, where the contract has a
# git dependency, at least one `/dep/`.
#
# Each property is run twice: once as built (must hold) and once with the
# hardening switched off through `CONTRACT_BUILD_UNHARDENED=1` (the control).
# A control that does not fail means the property is holding for some other
# reason and the mechanism is untested, so the gate refuses it — except for b1,
# where the axis provably does not reach the binary either way (cargo passes
# the local crate's files relative to its package directory) and the control is
# recorded as equal.
#
# Eleven clean wasm builds per contract. Each build's target directory is
# freed as soon as its wasm has been hashed, because holding them all costs
# tens of gigabytes at four contracts.
set -euo pipefail
cd "$(dirname "$0")"
root=$PWD

command -v rsync >/dev/null || { echo "hash-gate: rsync is required" >&2; exit 1; }
command -v shasum >/dev/null || { echo "hash-gate: shasum is required" >&2; exit 1; }
command -v strings >/dev/null || { echo "hash-gate: strings is required" >&2; exit 1; }

kinds=()
for b in */build.sh; do kinds+=("$(dirname "$b")"); done
[ ${#kinds[@]} -gt 0 ] || { echo "hash-gate: no contracts found (*/build.sh matched nothing)" >&2; exit 1; }

base=$(mktemp -d "${TMPDIR:-/tmp}/hash-gate.XXXXXX")
trap 'rm -rf "$base"' EXIT
alt_cargo="$base/a-cargo-home-reached-by-another-path"
ln -s "${CARGO_HOME:-$HOME/.cargo}" "$alt_cargo"

copy() { mkdir -p "$1"; rsync -a --exclude .git --exclude target --exclude build "$root"/ "$1"/; }

# One blank line at the top of every source file of one crate: the smallest
# edit that moves every line number in it without changing a single statement.
perturb() {
  local f n=0
  while IFS= read -r f; do
    { printf '\n'; cat "$f"; } > "$f.pert" && mv "$f.pert" "$f"
    n=$((n + 1))
  done < <(find "$1/$2/src" -name '*.rs')
  [ "$n" -gt 0 ] || { echo "hash-gate: perturbed 0 source files in $2 — nothing was tested" >&2; exit 1; }
  printf '%s' "$n"
}

# Every ABSOLUTE source path in the binary, whole — std, dependencies and the
# registry. Whole, and anchored where it is matched, because
# `/cargo/registry/src/index.crates.io-…` CONTAINS the substring `/registry/`:
# a grep for that substring passes while the registry remap does nothing at all.
abs_paths() {
  strings -a "$1" | { grep -oE '/[A-Za-z0-9_][A-Za-z0-9_/.-]*\.rs' || true; } | sort -u
}

# Source paths of the crate ITSELF. Cargo passes the local crate's files
# RELATIVE to its package directory, so those are the only `.rs` strings in the
# wasm that are not absolute.
#
# This is what decides whether property c's control CAN fail: a crate none of
# whose own panic locations reach the binary keeps its hash through a comment
# edit whatever the build flags are, and a control that cannot fail must say
# which of the two reasons it is.
own_locations() {
  # `|| true`: finding none is the expected answer, not a broken pipeline.
  strings -a "$1" | { grep -oE '(^|[^A-Za-z0-9_/.-])src/[A-Za-z0-9_/-]+\.rs' || true; } |
    sed -E 's#^[^A-Za-z0-9_/.-]##' | sort -u
}

# A clean build, returning the first 16 hex of the wasm's sha256.
build() {
  local d=$1 k=$2 out=$2 log="$base/build.log"; shift 2
  case " $* " in
    *CONTRACT_BUILD_UNHARDENED=*) out="$k.unhardened" ;;
    *CONTRACT_BUILD_REMAPS_ONLY=*) out="$k.remaps-only" ;;
  esac
  rm -rf "$d/$k/target"
  # The log is kept and shown on failure: a gate that reports "build failed"
  # and nothing else cannot be acted on.
  if [ $# -gt 0 ]; then env "$@" "$d/$k/build.sh" >"$log" 2>&1
  else "$d/$k/build.sh" >"$log" 2>&1; fi ||
    { echo "hash-gate: build failed ($k $*)" >&2; tail -20 "$log" >&2; exit 1; }
  local w="$d/build/$out.wasm"
  [ -s "$w" ] || { echo "hash-gate: $w missing or empty" >&2; exit 1; }
  local hash
  hash=$(shasum -a 256 "$w" | cut -c1-16)
  # Freed as soon as its wasm has been read. The gate makes four checkouts per
  # contract and builds each of them several times; holding every target
  # directory at once costs tens of gigabytes once there are four contracts,
  # and the failure is a build error in the middle of a run rather than
  # anything the gate reports about hashes.
  rm -rf "$d/$k/target"
  printf '%s' "$hash"
}

checks=0 failures=0
row() { # row <id> <text> <lhs> <op> <rhs>   op: = (must be equal) | ! (must differ) | ? (recorded)
  local want=$4 ok
  case $want in
    '=') [ "$3" = "$5" ] && ok=PASS || ok=FAIL ;;
    '!') [ "$3" != "$5" ] && ok="CONTROL OK" || ok="CONTROL VACUOUS" ;;
    '?') ok="(recorded)" ;;
  esac
  [ "$want" = '?' ] || checks=$((checks + 1))
  case $ok in FAIL|"CONTROL VACUOUS") failures=$((failures + 1));; esac
  printf '  %-3s %-52s %s %s %s   %s\n' "$1" "$2" "$3" \
    "$([ "$3" = "$5" ] && echo '=' || echo '≠')" "$5" "$ok"
}

for k in "${kinds[@]}"; do
  echo "$k"
  p="$base/$k/p"                                     # the fixed path: a, b2, c
  q="$base/$k/a-second-checkout-at-another-depth/x"  # b1
  s="$base/$k/controls"                              # the unhardened controls
  t="$base/$k/controls-at-another-depth/x"
  copy "$p"; copy "$q"; copy "$s"; copy "$t"

  h1=$(build "$p" "$k")
  hard_locs=$(own_locations "$p/build/$k.wasm")
  h2=$(build "$p" "$k")
  row a "two clean builds, same path" "$h1" '=' "$h2"

  hq=$(build "$q" "$k")
  row b1 "a different absolute repo directory" "$h1" '=' "$hq"

  hc=$(build "$p" "$k" "CARGO_HOME=$alt_cargo")
  row b2 "a different absolute cargo home" "$h1" '=' "$hc"

  n=$(perturb "$p" "$k")
  hp=$(build "$p" "$k")
  row c "a blank line atop each of $n source files" "$h1" '=' "$hp"

  echo "  controls — hardening off; each must DIFFER, or the property above is vacuous"
  u1=$(build "$s" "$k" CONTRACT_BUILD_UNHARDENED=1)
  soft_locs=$(own_locations "$s/build/$k.unhardened.wasm")
  ut=$(build "$t" "$k" CONTRACT_BUILD_UNHARDENED=1)
  row b1 "different repo directory, unhardened" "$u1" '?' "$ut"
  echo "      this axis reaches neither build: cargo passes the local crate's files relative"
  uc=$(build "$s" "$k" CONTRACT_BUILD_UNHARDENED=1 "CARGO_HOME=$alt_cargo")
  row b2 "different cargo home, unhardened" "$u1" '!' "$uc"
  perturb "$s" "$k" >/dev/null
  up=$(build "$s" "$k" CONTRACT_BUILD_UNHARDENED=1)
  # Whether this control CAN fail is a measured property of the crate, not an
  # assumption: it can only move the hash if one of the crate's own panic
  # locations is in the binary to begin with.
  if [ -n "$soft_locs" ]; then
    row c "blank line atop each source file, unhardened" "$u1" '!' "$up"
    echo "      moves: $(echo "$soft_locs" | tr '\n' ' ')"
  else
    row c "blank line atop each source file, unhardened" "$u1" '?' "$up"
    echo "      no control possible: no panic location of $k's own sources reaches the"
    echo "      binary even unhardened, so a comment edit cannot re-key it either way."
    echo "      The moment $k's code gains one, this control starts failing as it should."
  fi
  # The mechanism's own signature, asserted directly rather than inferred from
  # the hashes: after the build, none of the crate's source paths are in it.
  row loc "no source path of $k in the built wasm" \
    "$(printf '%s' "${hard_locs:-none}" | tr '\n' ',')" '=' none

  # The remaps, gated on their own. In the shipping build `-Zlocation-detail`
  # has already removed every path a broken remap would show, so the remaps are
  # only observable here — and `file!()`/`module_path!()` in a dependency are
  # NOT covered by that flag, so a broken remap is a live exposure and not a
  # cosmetic one.
  echo "  the remaps alone — a build with the remaps and no location strip"
  build "$s" "$k" CONTRACT_BUILD_REMAPS_ONLY=1 >/dev/null
  rp=$(abs_paths "$s/build/$k.remaps-only.wasm")
  n_idx=$(printf '%s\n' "$rp" | grep -c 'index\.crates\.io-' || true)
  n_ck=$(printf '%s\n' "$rp" | grep -c '/git/checkouts/' || true)
  n_home=$(printf '%s\n' "$rp" | grep -cF "$HOME" || true)
  n_reg=$(printf '%s\n' "$rp" | grep -c '^/registry/' || true)
  n_dep=$(printf '%s\n' "$rp" | grep -c '^/dep/' || true)
  row idx "no cargo index-hash directory in the path" "$n_idx" '=' 0
  row ck  "no revision-named git checkout in the path" "$n_ck" '=' 0
  row hom "no \$HOME in the path" "$n_home" '=' 0
  # A floor, not just an absence: an empty binary would satisfy every check
  # above. Every contract pulls registry crates, so /registry/ must be present.
  row reg "registry sources remapped to /registry (≥1)" "$([ "$n_reg" -ge 1 ] && echo ok || echo "none of ${n_reg}")" '=' ok
  # Only contracts that HAVE a git dependency can show /dep/, so the floor is
  # derived from the unremapped build rather than hard-coded per contract.
  #
  # `grep -c`, never `grep -q`: under `pipefail` a `-q` exits on the first
  # match and SIGPIPEs the producer, so the pipeline reports failure exactly
  # when the match SUCCEEDED — which silently skipped this floor for the one
  # contract that has a git dependency.
  n_gitdep=$(printf '%s\n' "$(abs_paths "$s/build/$k.unhardened.wasm")" |
    { grep -c '/git/checkouts/' || true; })
  if [ "$n_gitdep" -gt 0 ]; then
    row dep "git dependencies remapped to /dep/<pkg> (≥1)" "$([ "$n_dep" -ge 1 ] && echo ok || echo none)" '=' ok
  else
    row dep "git dependencies remapped to /dep/<pkg>" "n/a" '?' "n/a"
    echo "      $k has no git dependency path in the binary; nothing to remap"
  fi
  # This contract is finished with; its four checkouts go now rather than at
  # the end of the run, so peak disk is one contract's worth and not all of
  # them together.
  rm -rf "$base/$k"
done

# And that build/hashes.toml says what is actually on disk.
#
# This does not gate ON the table. Nothing here reads a hash out of it and
# believes it; `hashes-check.sh` regenerates the artefacts and compares the
# table against them, so an edited table can only turn this RED. That is the
# distinction #32 draws and released.toml's header draws before it: a gate a
# hash table can satisfy is a gate anyone can edit green.
#
# What it therefore catches is a build that writes digests which are not what
# it produced — a changed digest algorithm, a wasm copied from somewhere else,
# a contract silently missing from the table. It does NOT catch a stale
# `hashes.toml`, because it overwrites one; staleness is not reachable when the
# file is regenerated by the same command that builds.
echo
echo "== build/hashes.toml =="
checks=$((checks + 1))
if ./hashes-check.sh; then
  printf '\n  %-64s %s\n' "hashes-check.sh (its own checks, counted as one here)" ok
else
  printf '\n  %-64s %s\n' "hashes-check.sh (its own checks, counted as one here)" FAILED
  failures=$((failures + 1))
fi

echo
[ "$checks" -gt 0 ] || { echo "hash-gate: 0 checks ran" >&2; exit 1; }
if [ "$failures" -gt 0 ]; then
  echo "hash-gate: $failures of $checks checks FAILED"
  exit 1
fi
echo "hash-gate: $checks checks passed over ${#kinds[@]} contract(s): ${kinds[*]}"
