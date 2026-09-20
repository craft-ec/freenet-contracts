#!/usr/bin/env bash
# Rebuild a released epoch from the row that describes it.
#
# A contract's wasm hash is part of its network key, and the map from inputs to
# hash is NOT injective: #36 produced six distinct hashes over sixteen builds of
# the same source, two of which collided. So a hash can never stand in for a
# record of what produced it. A row carries the inputs; this script performs the
# build they describe, at a DIFFERENT absolute path, and compares the result.
#
# It does not gate ON the table. Every value here is used as an INPUT to a
# rebuild or as an assertion about the environment — nothing is believed because
# the table says it. Editing a row can only turn this red.
#
# A check has three outcomes and "could not check" is a FAILURE. A missing
# field, a toolchain that is not the recorded one, a commit that does not exist:
# each stops the run with the field named. The SDK's pin gate printed SKIPPED
# for weeks from a worktree because a sibling was not where it looked, and
# nobody reads the stdout of a green test.
#
#   ./release-check.sh <epoch>                 verify that epoch
#   ./release-check.sh --write <epoch> --tag T  build and EMIT the row
#   ./release-check.sh --self-test             write a row, verify it, then put
#                                              each field back wrong
#
# `--file F` reads and writes F instead of released.toml.
set -euo pipefail
cd "$(dirname "$0")"
root=$PWD

for t in python3 shasum git; do
  command -v "$t" >/dev/null || { echo "release-check: $t is required" >&2; exit 1; }
done

file=released.toml
mode=verify
epoch=
tag=
while [ $# -gt 0 ]; do
  case $1 in
    --write) mode=write; epoch=${2:-}; shift 2 ;;
    --self-test) mode=selftest; shift ;;
    --tag) tag=${2:-}; shift 2 ;;
    --file) file=${2:-}; shift 2 ;;
    -h|--help) sed -n '2,28p' "$0"; exit 0 ;;
    -*) echo "release-check: unknown option $1" >&2; exit 1 ;;
    *) epoch=$1; shift ;;
  esac
done

work=$(mktemp -d "${TMPDIR:-/tmp}/release-check.XXXXXX")
trap 'rm -rf "$work"; [ -n "${wt:-}" ] && git -C "$root" worktree remove --force "$wt" 2>/dev/null || true' EXIT

# ---------------------------------------------------------------- reading ----
# One python call per document, flattened to `key<TAB>value` lines, because a
# call per field is a call per field. `field` then reads that file: this bash is
# 3.2 on macOS and has no associative arrays.
flatten_row() { # flatten_row <toml> <epoch-number> > key<TAB>value
  python3 - "$1" "$2" <<'PY'
import sys, tomllib
doc = tomllib.load(open(sys.argv[1], "rb"))
want = int(sys.argv[2])
rows = [e for e in doc.get("epoch", []) if e.get("number") == want]
if len(rows) != 1:
    print("ERROR\tepoch %s appears %d times in %s" % (want, len(rows), sys.argv[1]))
    sys.exit(0)
def emit(prefix, v):
    if isinstance(v, dict):
        if prefix == "contract":
            print("contracts\t" + " ".join(v.keys()))
        for k, x in v.items():
            emit(prefix + "." + k if prefix else k, x)
    elif isinstance(v, list):
        print(prefix + ".len\t%d" % len(v))
        for i, x in enumerate(v):
            print("%s.%d\t%s" % (prefix, i, x))
    elif isinstance(v, bool):
        print("%s\t%s" % (prefix, "true" if v else "false"))
    else:
        print("%s\t%s" % (prefix, v))
emit("", rows[0])
PY
}

flatten_profile() { # flatten_profile <Cargo.toml> > key<TAB>value, row spelling
  python3 - "$1" <<'PY'
import sys, tomllib
p = tomllib.load(open(sys.argv[1], "rb")).get("profile", {}).get("release", {})
names = {"opt-level": "opt_level", "lto": "lto", "codegen-units": "codegen_units",
         "panic": "panic", "strip": "strip", "debug": "debug"}
for k, out in names.items():
    if k in p:
        v = p[k]
        print("%s\t%s" % (out, "true" if v is True else "false" if v is False else v))
PY
}

lock_git_deps() { # lock_git_deps <Cargo.lock> > name<TAB>rev
  python3 - "$1" <<'PY'
import sys, tomllib
for pkg in tomllib.load(open(sys.argv[1], "rb")).get("package", []):
    src = pkg.get("source", "")
    if src.startswith("git+") and "#" in src:
        print("%s\t%s" % (pkg["name"], src.rsplit("#", 1)[1]))
PY
}

field() { # field <key> — empty if absent
  awk -F'\t' -v k="$1" '$1==k {print $2; found=1} END {if (!found) print ""}' "$work/row" | head -1
}

# ------------------------------------------------------------- reporting ----
checks=0; failures=0
row() { # row <field> <got> <want>
  checks=$((checks + 1))
  if [ "$2" = "$3" ]; then
    printf '  %-34s %s\n' "$1" ok
  else
    printf '  %-34s FAILED  row says %s, build says %s\n' "$1" "$3" "$2"
    failures=$((failures + 1))
  fi
}
fail() { printf '  %-34s FAILED  %s\n' "$1" "$2"; failures=$((failures + 1)); checks=$((checks + 1)); }

REQUIRED="number released tag builder
source.repo source.commit source.dirty
toolchain.channel toolchain.rustc toolchain.llvm toolchain.cargo toolchain.target toolchain.bootstrap
profile.opt_level profile.lto profile.codegen_units profile.panic profile.strip profile.debug
flags.location_detail flags.remap.len flags.remap_expanded
postprocess.tools.len
contracts"

# --------------------------------------------------------------- verify -----
verify() { # verify <toml> <epoch>
  local f=$1 n=$2 k
  echo "release-check: epoch $n of $f"
  flatten_row "$f" "$n" > "$work/row"
  if [ -n "$(field ERROR)" ]; then
    echo "release-check: $(field ERROR)" >&2; return 1
  fi

  echo "  -- the row is complete"
  local missing=""
  for key in $REQUIRED; do
    [ -n "$(field "$key")" ] || missing="$missing $key"
  done
  for k in $(field contracts); do
    for key in lock_sha256 sha256 bytes; do
      [ -n "$(field "contract.$k.$key")" ] || missing="$missing contract.$k.$key"
    done
  done
  if [ -n "$missing" ]; then
    fail "row is complete" "missing:$missing"
    echo; echo "release-check: $failures of $checks checks FAILED"; return 1
  fi
  row "row is complete" complete complete

  # A released build is never made from a dirty tree, so a row that says it was
  # is refused rather than rebuilt.
  [ "$(field source.dirty)" = "false" ] || fail source.dirty "the row records a DIRTY tree; that is not a release"

  echo "  -- the toolchain is the recorded one"
  row toolchain.rustc "$(rustc -vV | sed -n '1p')" "$(field toolchain.rustc)"
  row toolchain.cargo "$(cargo -vV | sed -n '1p')" "$(field toolchain.cargo)"
  row toolchain.llvm  "$(rustc -vV | sed -n 's/^LLVM version: //p')" "$(field toolchain.llvm)"
  row toolchain.channel "$(python3 -c 'import tomllib;print(tomllib.load(open("rust-toolchain.toml","rb"))["toolchain"]["channel"])')" "$(field toolchain.channel)"
  if [ "$failures" -gt 0 ]; then
    echo; echo "release-check: the toolchain is not the one that made this epoch — install $(field toolchain.channel) and run again"
    echo "release-check: $failures of $checks checks FAILED"; return 1
  fi

  echo "  -- a fresh checkout of $(field source.commit | cut -c1-12), at a different path"
  git -C "$root" rev-parse --verify --quiet "$(field source.commit)^{commit}" >/dev/null || {
    fail source.commit "commit $(field source.commit) is not in this repository"
    echo; echo "release-check: $failures of $checks checks FAILED"; return 1
  }
  wt="$work/at-another-path/x"
  git -C "$root" worktree add --detach --quiet "$wt" "$(field source.commit)"

  echo "  -- each contract's inputs"
  for k in $(field contracts); do
    row "contract.$k.lock_sha256" "sha256:$(shasum -a 256 "$wt/$k/Cargo.lock" | cut -d' ' -f1)" "$(field "contract.$k.lock_sha256")"
    flatten_profile "$wt/$k/Cargo.toml" > "$work/profile"
    for p in opt_level lto codegen_units panic strip debug; do
      row "$k profile.$p" "$(awk -F'\t' -v key="$p" '$1==key{print $2}' "$work/profile")" "$(field "profile.$p")"
    done
    lock_git_deps "$wt/$k/Cargo.lock" > "$work/gitdeps"
    while IFS=$'\t' read -r name rev; do
      [ -n "$name" ] || continue
      row "$k git dep $name" "$rev" "$(field "contract.$k.git_deps.$name")"
    done < "$work/gitdeps"
  done

  # Everything above is cheap and fails at the door. The build is last.
  if [ "$failures" -gt 0 ]; then
    # Worded without the word "rebuilding": a message that differs from the
    # build's own banner only by a negation is one no substring test can tell
    # apart, and the self-test read this line as proof that the build HAD run.
    echo; echo "release-check: the inputs disagree with the row; the build was not run"
    echo "release-check: $failures of $checks checks FAILED"; return 1
  fi

  echo "  -- rebuilding (this is a cold build of every contract)"
  ( cd "$wt" && env -u CARGO_TARGET_DIR ./build.sh ) > "$work/build.log" 2>&1 || {
    fail build "build.sh failed; last lines follow"; tail -20 "$work/build.log" >&2
    echo; echo "release-check: $failures of $checks checks FAILED"; return 1
  }

  echo "  -- the artefacts"
  for k in $(field contracts); do
    local w="$wt/build/$k.wasm"
    row "contract.$k.sha256" "sha256:$(shasum -a 256 "$w" | cut -d' ' -f1)" "$(field "contract.$k.sha256")"
    row "contract.$k.bytes" "$(wc -c < "$w" | tr -d ' ')" "$(field "contract.$k.bytes")"
    # Nothing may touch the wasm after cargo. This is what makes an empty
    # postprocess.tools a CHECKED claim rather than an asserted one.
    local crate cargo_out
    crate=$(python3 -c 'import sys,tomllib;print(tomllib.load(open(sys.argv[1],"rb"))["package"]["name"].replace("-","_"))' "$wt/$k/Cargo.toml")
    cargo_out="$wt/$k/target/wasm32-unknown-unknown/release/$crate.wasm"
    if cmp -s "$w" "$cargo_out"; then
      row "$k untouched after cargo" same same
    else
      row "$k untouched after cargo" "differs from $crate.wasm" same
    fi
  done
  if [ "$(field postprocess.tools.len)" = "0" ]; then
    row "postprocess.tools" 0 0
  else
    local i=0
    while [ "$i" -lt "$(field postprocess.tools.len)" ]; do
      local spec name
      spec=$(field "postprocess.tools.$i"); name=${spec%% *}
      row "postprocess.tools.$i" "$($name --version 2>&1 | head -1)" "$spec"
      i=$((i + 1))
    done
  fi

  echo
  if [ "$failures" -gt 0 ]; then
    echo "release-check: $failures of $checks checks FAILED"; return 1
  fi
  echo "release-check: $checks checks passed — epoch $n rebuilds to the bytes its row records"
}

# ---------------------------------------------------------------- write -----
write_row() { # write_row <epoch> <tag> > the row
  local n=$1 t=$2 commit k crate
  [ -n "$t" ] || { echo "release-check: --write needs --tag" >&2; exit 1; }
  [ -z "$(git -C "$root" status --porcelain)" ] ||
    { echo "release-check: the tree is dirty; a release is built from a commit" >&2; exit 1; }
  git -C "$root" rev-parse --verify --quiet "$t^{commit}" >/dev/null ||
    { echo "release-check: tag $t does not exist" >&2; exit 1; }
  commit=$(git -C "$root" rev-parse "$t^{commit}")
  [ "$commit" = "$(git -C "$root" rev-parse HEAD)" ] ||
    { echo "release-check: tag $t is not at HEAD" >&2; exit 1; }
  ( cd "$root" && env -u CARGO_TARGET_DIR ./build.sh ) >/dev/null 2>&1 ||
    { echo "release-check: build.sh failed" >&2; exit 1; }

  local kinds=""
  for b in "$root"/*/build.sh; do kinds="$kinds $(basename "$(dirname "$b")")"; done
  local first; first=$(echo $kinds | cut -d' ' -f1)
  {
    echo "[[epoch]]"
    echo "number   = $n"
    echo "released = \"$(date -u +%Y-%m-%d)\""
    echo "tag      = \"$t\""
    echo "builder  = \"${RELEASE_BUILDER:-$(git -C "$root" config user.name)}\""
    echo
    echo "[epoch.source]"
    echo "repo   = \"$(git -C "$root" remote get-url origin)\""
    echo "commit = \"$commit\""
    echo "dirty  = false"
    echo
    echo "[epoch.toolchain]"
    echo "channel   = \"$(python3 -c 'import tomllib;print(tomllib.load(open("rust-toolchain.toml","rb"))["toolchain"]["channel"])')\""
    echo "rustc     = \"$(rustc -vV | sed -n '1p')\""
    echo "llvm      = \"$(rustc -vV | sed -n 's/^LLVM version: //p')\""
    echo "cargo     = \"$(cargo -vV | sed -n '1p')\""
    echo "target    = \"wasm32-unknown-unknown\""
    echo "bootstrap = true"
    echo
    echo "[epoch.profile]"
    flatten_profile "$root/$first/Cargo.toml" |
      awk -F'\t' '{ v=$2; if (v ~ /^[0-9]+$/ || v=="true" || v=="false") printf "%-14s= %s\n", $1, v; else printf "%-14s= \"%s\"\n", $1, v }'
    echo
    echo "[epoch.flags]"
    echo "location_detail = \"none\""
    echo "remap = ["
    echo "  \"\$RUSTUP_HOME=/rustup\","
    echo "  \"\$CARGO_HOME=/cargo\","
    echo "  \"\$REPO=/contracts\","
    echo "  \"\$REPO/<contract>=/<contract>\","
    echo "  \"\$CARGO_HOME/registry/src/<index>=/registry\","
    echo "  \"\$CARGO_HOME/git/checkouts/<pkg>-<hash>/<rev>=/dep/<pkg>\","
    echo "]"
    echo "remap_expanded = $("$root/contract-build.sh" --flags "$first" | tr ' ' '\n' | grep -c remap-path-prefix)"
    echo
    echo "[epoch.postprocess]"
    echo "tools = []"
    for k in $kinds; do
      echo
      echo "[epoch.contract.$k]"
      echo "lock_sha256 = \"sha256:$(shasum -a 256 "$root/$k/Cargo.lock" | cut -d' ' -f1)\""
      echo "sha256      = \"sha256:$(shasum -a 256 "$root/build/$k.wasm" | cut -d' ' -f1)\""
      echo "bytes       = $(wc -c < "$root/build/$k.wasm" | tr -d ' ')"
      lock_git_deps "$root/$k/Cargo.lock" | while IFS=$'\t' read -r name rev; do
        [ -n "$name" ] || continue
        echo
        echo "[epoch.contract.$k.git_deps]"
        echo "\"$name\" = \"$rev\""
      done
    done
  }
}

case $mode in
  verify)
    [ -n "$epoch" ] || { echo "release-check: which epoch? see --help" >&2; exit 1; }
    [ -f "$file" ] || { echo "release-check: $file does not exist" >&2; exit 1; }
    verify "$file" "$epoch"
    ;;
  write)
    [ -n "$epoch" ] || { echo "release-check: --write needs an epoch number" >&2; exit 1; }
    write_row "$epoch" "$tag"
    ;;
  selftest)
    "$root/release-check-selftest.sh"
    ;;
esac
