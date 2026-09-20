#!/usr/bin/env bash
# Does build/hashes.toml say what the files on disk actually are?
#
# The table exists to be READ by consumers — the builder's versions panel, the
# harness's `--expect-sha`. Nothing here gates on its contents: a check a hash
# table can satisfy is a check anyone can edit green. This asks the opposite
# question, the only one worth asking of a generated file: does it agree with
# what was generated? So editing the table can only turn this red.
#
# It regenerates rather than reads, because a table that agrees with a wasm
# nobody built this year agrees with nothing.
set -euo pipefail
cd "$(dirname "$0")"
root=$PWD
command -v shasum >/dev/null || { echo "hashes-check: shasum is required" >&2; exit 1; }

checks=0
failures=0
row() { # row <id> <what> <got> <want>
  checks=$((checks + 1))
  if [ "$3" = "$4" ]; then
    printf '  %-8s %-58s %s\n' "$1" "$2" ok
  else
    printf '  %-8s %-58s FAILED (got %s, want %s)\n' "$1" "$2" "$3" "$4"
    failures=$((failures + 1))
  fi
}

# The comparison itself, over a directory of artefacts and its table. Used
# once on the real build and once on a deliberately corrupted copy of it, so
# the negative control exercises this code and not a description of it.
#
# Prints one line per disagreement and returns non-zero if there were any.
compare() { # compare <dir> <expected contract names...>
  local dir=$1; shift
  local want_names="$*" got_names="" bad=0 name digest fresh
  [ -f "$dir/hashes.toml" ] || { echo "    no $dir/hashes.toml"; return 1; }
  while read -r name _ digest; do
    digest=${digest%\"}; digest=${digest#\"}
    got_names="$got_names $name"
    case $digest in
      sha256:*) ;;
      *) echo "    $name: digest is not sha256-prefixed: $digest"; bad=1; continue ;;
    esac
    if [ ! -f "$dir/$name.wasm" ]; then
      echo "    $name: a row with no $dir/$name.wasm behind it"; bad=1; continue
    fi
    fresh="sha256:$(shasum -a 256 "$dir/$name.wasm" | cut -d' ' -f1)"
    # 64 hex, not the 16 the build line prints: a consumer pinning an artefact
    # needs the whole digest.
    if [ ${#digest} -ne 71 ]; then
      echo "    $name: digest is ${#digest} characters, want 71 (sha256: + 64 hex)"; bad=1
    fi
    if [ "$digest" != "$fresh" ]; then
      echo "    $name: table says $digest, the file is $fresh"; bad=1
    fi
  done < <(sed -n '/^\[code\]/,$p' "$dir/hashes.toml" | grep -E '^[A-Za-z0-9_-]+ = "' || true)
  # Both directions. A row with no wasm is caught above; a wasm with no row is
  # a contract silently missing from the table, which is the failure the
  # derived list exists to prevent.
  local a b
  a=$(printf '%s\n' $want_names | sort | tr '\n' ' ')
  b=$(printf '%s\n' $got_names | sort | tr '\n' ' ')
  if [ "$a" != "$b" ]; then
    echo "    rows are [$b], contracts are [$a]"; bad=1
  fi
  [ -n "$got_names" ] || { echo "    the table has no rows at all"; bad=1; }
  return $bad
}

kinds=()
for b in */build.sh; do kinds+=("$(dirname "$b")"); done
[ ${#kinds[@]} -gt 0 ] || { echo "hashes-check: no contracts found" >&2; exit 1; }

echo "regenerating build/hashes.toml (${#kinds[@]} contracts)"
./build.sh >/dev/null

echo
echo "the table against the files it describes"
compare build "${kinds[@]}" && agree=ok || agree=disagrees
row fresh "every digest equals a fresh shasum of build/<name>.wasm" "$agree" ok
n_rows=$(sed -n '/^\[code\]/,$p' build/hashes.toml | grep -cE '^[A-Za-z0-9_-]+ = "' || true)
row rows "one row per contract built" "$n_rows" "${#kinds[@]}"

# The rev must name the tree that compiled. Running this with a modified tree
# is the normal case, so the assertion is the implication, not a constant.
rev=$(sed -n 's/^rev   = "\(.*\)"$/\1/p' build/hashes.toml)
marked=clean
case $rev in *-dirty) marked=dirty ;; esac
if [ -n "$(git status --porcelain 2>/dev/null)" ]; then
  row dirty "a modified tree is marked -dirty" "$marked" dirty
else
  row dirty "an unmodified tree is not marked -dirty" "$marked" clean
fi

# NEGATIVE CONTROL. One byte of one wasm, after the table was written. If this
# does not come back red, everything above is agreeing for some other reason
# and this script is checking nothing.
echo
echo "negative control: one corrupted byte"
ctl=$(mktemp -d "${TMPDIR:-/tmp}/hashes-check.XXXXXX")
trap 'rm -rf "$ctl"' EXIT
mkdir -p "$ctl/build"
cp build/hashes.toml "$ctl/build/"
for k in "${kinds[@]}"; do cp "build/$k.wasm" "$ctl/build/"; done
victim=${kinds[0]}
printf '\xff' | dd of="$ctl/build/$victim.wasm" bs=1 seek=64 conv=notrunc status=none
compare "$ctl/build" "${kinds[@]}" >/dev/null 2>&1 && ctl_says=passed || ctl_says=caught
row corrupt "a flipped byte in $victim.wasm is caught" "$ctl_says" caught
# And the second direction: a row nobody built.
cp -f build/hashes.toml "$ctl/build/hashes.toml"
rm -f "$ctl/build/$victim.wasm"
compare "$ctl/build" "${kinds[@]}" >/dev/null 2>&1 && ctl_says=passed || ctl_says=caught
row missing "a row with no wasm behind it is caught" "$ctl_says" caught

# DERIVATION. The list must come from the tree, so that a new contract appears
# by existing. Proven on a tree of stand-in contracts rather than by reading
# the loop: each stub does what a real contract's build.sh does at the end —
# leave build/<name>.wasm — which is the only part this derivation depends on.
echo
echo "the list is derived from the tree, not from a list"
stub=$(mktemp -d "${TMPDIR:-/tmp}/hashes-derive.XXXXXX")
cp "$root/build.sh" "$stub/"
mkstub() {
  mkdir -p "$stub/$1"
  printf '#!/usr/bin/env bash\nset -eu\ncd "$(dirname "$0")"\nmkdir -p ../build\nprintf %%s "%s" > ../build/%s.wasm\n' "$2" "$1" > "$stub/$1/build.sh"
  chmod +x "$stub/$1/build.sh"
}
mkstub alpha one
mkstub beta two
(cd "$stub" && ./build.sh >/dev/null)
(cd "$stub" && compare build alpha beta) && two=ok || two=disagrees
row derive2 "two contracts in the tree give two correct rows" "$two" ok
mkstub gamma three
(cd "$stub" && ./build.sh >/dev/null)
(cd "$stub" && compare build alpha beta gamma) && three=ok || three=disagrees
row derive3 "a third appears without anyone editing a list" "$three" ok

# A contract whose build.sh leaves no wasm must STOP the build. Otherwise the
# table quietly describes a subset and reads as complete.
mkdir -p "$stub/delta"
printf '#!/usr/bin/env bash\nexit 0\n' > "$stub/delta/build.sh"
chmod +x "$stub/delta/build.sh"
(cd "$stub" && ./build.sh >/dev/null 2>&1) && silent=wrote || silent=refused
row nowasm "a contract that produces no wasm stops the build" "$silent" refused
rm -rf "$stub/delta"

# A control build writes wrong-flag wasm on purpose. Its hashes must not
# become the table.
(cd "$stub" && ./build.sh >/dev/null)
before=$(shasum -a 256 "$stub/build/hashes.toml" | cut -d' ' -f1)
(cd "$stub" && CONTRACT_BUILD_UNHARDENED=1 ./build.sh >/dev/null 2>&1)
after=$(shasum -a 256 "$stub/build/hashes.toml" | cut -d' ' -f1)
row control "a control build leaves the table alone" "$([ "$before" = "$after" ] && echo ok || echo overwritten)" ok
rm -rf "$stub"

echo
[ "$checks" -gt 0 ] || { echo "hashes-check: 0 checks ran" >&2; exit 1; }
if [ "$failures" -gt 0 ]; then
  echo "hashes-check: $failures of $checks checks FAILED"
  exit 1
fi
echo "hashes-check: $checks checks passed; build/hashes.toml describes ${#kinds[@]} contract(s) at $rev"
