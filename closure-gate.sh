#!/usr/bin/env bash
# Is the instrumentation crate ABSENT from every contract's wasm closure?
#
# A dependency's IDENTITY reaches a contract's wasm hash even when nothing calls
# it: changing only the `version` field of a dependency whose source was
# byte-identical took block.wasm from 551 functions and 124,020 B to 543 and
# 123,393 B (F37, freenet-contracts#37). So merely DEPENDING on `instrument`
# would re-key every contract — an epoch bought by an import nobody used.
#
# NEVER PROVE THIS BY COMPARING HASHES. The input→hash map is not one-to-one:
# sixteen builds of one source produced six distinct hashes, two of which
# collided. A hash that happens to match after adding a dependency proves
# nothing about the closure, and that is precisely the case this gate exists
# for. Ask cargo what the closure IS.
#
# Native tests MAY use it: `probe`/`instrument` as a DEV-dependency is present
# in `cargo test` and absent from the wasm build, which is the pattern the
# contracts' own `testing` feature already follows.
#
#   ./closure-gate.sh              gate this checkout
#   ./closure-gate.sh --self-test  put the defect back and watch the gate fire
set -euo pipefail
cd "$(dirname "$0")"
root=$PWD

# The crates that must never appear. Both names: the crate was `probe` in its
# interim home and is `instrument` in its own repository, and a gate that knows
# only the new name would pass on an old checkout.
FORBIDDEN=(instrument probe)

# A tree this small means cargo answered with something that is not a closure.
# Every contract pulls freenet-stdlib, blake3 and their dependencies; single
# digits means the command failed in a way that still exited 0.
MIN_PACKAGES=5

gate() {
command -v cargo >/dev/null || { echo "closure-gate: cargo is required" >&2; exit 1; }

kinds=()
for b in */build.sh; do kinds+=("$(dirname "$b")"); done
[ ${#kinds[@]} -gt 0 ] || { echo "closure-gate: no contracts found" >&2; exit 1; }

checks=0
failures=0
row() { # row <what> <verdict> <note>
  checks=$((checks + 1))
  case $2 in FAILED) failures=$((failures + 1));; esac
  printf '  %-34s %-7s %s\n' "$1" "$2" "${3:-}"
}

# The closure for one contract, or nothing at all.
#
# `-e normal` excludes dev- and build-dependencies, which is the whole
# distinction: a dev-dependency is in the test build and not in the wasm.
tree_of() { # tree_of <dir>
  ( cd "$1" && cargo tree -e normal --target wasm32-unknown-unknown --prefix none 2>/dev/null )
}

echo "closure-gate: ${FORBIDDEN[*]} must not be in any contract's wasm closure"
for k in "${kinds[@]}"; do
  tree=$(tree_of "$k" || true)
  # "Could not produce the tree" is a FAILURE, not a skip. A gate with three
  # outcomes that reports two is a gate that passes when it cannot look.
  if [ -z "$tree" ]; then
    row "$k" FAILED "cargo tree produced nothing — the closure was not examined"
    continue
  fi
  n=$(printf '%s\n' "$tree" | grep -c . || true)
  if [ "$n" -lt "$MIN_PACKAGES" ]; then
    row "$k" FAILED "only $n package(s) in the tree; that is not a closure"
    continue
  fi
  hit=""
  for bad in "${FORBIDDEN[@]}"; do
    # Anchored on the package NAME at the start of a line, so a crate merely
    # mentioning the word in a path or a version does not trip it, and a
    # dependency OF the forbidden crate is caught by its own line.
    if printf '%s\n' "$tree" | grep -qE "^${bad} v"; then
      hit="$hit $bad"
    fi
  done
  if [ -n "$hit" ]; then
    row "$k" FAILED "closure contains:$hit — that is an epoch (F37)"
  else
    # The count is printed on SUCCESS: a selective scan that does not say what
    # it covered degrades silently into a gate that checks nothing.
    row "$k" ok "$n packages examined, none forbidden"
  fi
done

echo
[ "$checks" -gt 0 ] || { echo "closure-gate: 0 checks ran" >&2; exit 1; }
if [ "$failures" -gt 0 ]; then
  echo "closure-gate: $failures of $checks contract(s) FAILED"
  exit 1
fi
echo "closure-gate: $checks contract(s) clean: ${kinds[*]}"
}

# ---------------------------------------------------------------- control ----
#
# A gate that has never been shown to fail is a gate nobody has tested. So the
# control RUNS rather than being described: a scratch copy of this repository
# gets `instrument` as a NORMAL dependency of `block`, and the gate must fail
# naming `block`. Then the same copy gets it as a DEV-dependency, and the gate
# must PASS — because that is the pattern the contracts actually use, and a
# gate that refused it would forbid the native tests their probe.
self_test() {
  local inst=${INSTRUMENT_PATH:-$root/../craftworks-instrument}
  [ -f "$inst/Cargo.toml" ] || {
    echo "self-test: no instrument crate at $inst (set INSTRUMENT_PATH)" >&2
    exit 1
  }
  local work
  work=$(mktemp -d "${TMPDIR:-/tmp}/closure-gate.XXXXXX")
  trap 'rm -rf "$work"' RETURN
  # The crate is copied in, so the scratch copy does not depend on a path
  # outside itself — a relative path dep would resolve differently there.
  cp -R "$root" "$work/repo"
  cp -R "$inst" "$work/instrument"
  rm -rf "$work/repo/.git" "$work"/repo/*/target "$work/repo/build"
  local c=0 f=0

  echo "== control 1: a NORMAL dependency must make the gate FAIL =="
  # INTO [dependencies], not onto the end of the file. Appending put the line
  # inside [profile.release], cargo ignored it, and the gate reported block
  # clean — a mutation that did not land and a gate that cannot see the defect
  # print the same green.
  python3 - "$work/repo/block/Cargo.toml" <<'EOF'
import sys
p = sys.argv[1]
s = open(p).read()
assert s.count("\n[dependencies]\n") == 1, "no single [dependencies] section to edit"
s = s.replace("\n[dependencies]\n", "\n[dependencies]\ninstrument = { path = \"../../instrument\" }\n", 1)
open(p, "w").write(s)
EOF
  ( cd "$work/repo/block" && cargo generate-lockfile >/dev/null 2>&1 || true )
  # And PROVE it landed before judging the gate: if cargo does not see the
  # dependency, this control is testing nothing.
  if ! ( cd "$work/repo/block" && cargo tree -e normal --target wasm32-unknown-unknown --prefix none 2>/dev/null ) | grep -qE "^instrument v"; then
    echo "  FAILED  the control did not land — cargo does not see the dependency,"
    echo "          so this proves nothing about the gate"
    exit 1
  fi
  local out rc
  out=$( cd "$work/repo" && ./closure-gate.sh 2>&1 ) && rc=0 || rc=$?
  c=$((c + 1))
  if [ "$rc" -ne 0 ] && printf '%s' "$out" | grep -q "block .*FAILED"; then
    echo "  ok      the gate failed and named block"
  else
    f=$((f + 1))
    echo "  FAILED  the gate did not fire (rc=$rc). It would pass with the defect in:"
    printf '%s\n' "$out" | sed 's/^/          /'
  fi

  echo "== control 2: a DEV-dependency must still PASS =="
  # Undo control 1 and add it the way the contracts really would.
  git -C "$root" show HEAD:block/Cargo.toml > "$work/repo/block/Cargo.toml"
  printf '\n[dev-dependencies]\ninstrument = { path = "../../instrument" }\n' >> "$work/repo/block/Cargo.toml"
  ( cd "$work/repo/block" && cargo generate-lockfile >/dev/null 2>&1 || true )
  out=$( cd "$work/repo" && ./closure-gate.sh 2>&1 ) && rc=0 || rc=$?
  c=$((c + 1))
  if [ "$rc" -eq 0 ]; then
    echo "  ok      a dev-dependency is in the test build and not in the wasm"
  else
    f=$((f + 1))
    echo "  FAILED  the gate refused a dev-dependency, which would forbid the"
    echo "          native tests their probe:"
    printf '%s\n' "$out" | sed 's/^/          /'
  fi

  echo
  if [ "$f" -gt 0 ]; then
    echo "self-test: $f of $c controls FAILED"
    exit 1
  fi
  echo "self-test: $c controls passed — the gate fires on a normal dependency and"
  echo "           permits a dev-dependency"
}

if [ "${1:-}" = --self-test ]; then
  self_test
  exit 0
fi

gate
