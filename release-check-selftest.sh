#!/usr/bin/env bash
# Put each field of a row back WRONG, and check `release-check.sh` says so.
#
# A gate that has never been shown to fail is a gate nobody has tested. Each
# mutant below is proved to have LANDED — the pattern must match exactly once
# and the file's checksum must change — because a patch that silently did not
# apply and a gate that cannot see the defect print the same green.
#
# Most mutants must also be caught BEFORE the rebuild: the cheap assertions
# exist so that a wrong row costs seconds rather than a cold build of every
# contract, and a mutant that reaches the build has bypassed them.
#
# Two cold builds: one for the row that must verify, one for the mutant that
# only a rebuild can catch.
set -euo pipefail
cd "$(dirname "$0")"
root=$PWD
work=$(mktemp -d "${TMPDIR:-/tmp}/release-selftest.XXXXXX")
tagname=release-check-selftest
trap 'rm -rf "$work"; git -C "$root" tag -d "$tagname" >/dev/null 2>&1 || true' EXIT

[ -z "$(git -C "$root" status --porcelain)" ] ||
  { echo "self-test: the tree is dirty; --write refuses that and so does this" >&2; exit 1; }
git -C "$root" tag -f "$tagname" HEAD >/dev/null

checks=0; failures=0
verdict() { # verdict <name> <ok|FAILED> <note>
  checks=$((checks + 1))
  [ "$2" = ok ] || failures=$((failures + 1))
  printf '  %-46s %-7s %s\n' "$1" "$2" "${3:-}"
}

echo "== a row written by the gate, for HEAD =="
./release-check.sh --write 1 --tag "$tagname" > "$work/base.toml"
grep -c . "$work/base.toml" >/dev/null
echo "  $(grep -cE '^\[epoch\.contract\.[a-z0-9-]+\]$' "$work/base.toml") contract(s), $(wc -l < "$work/base.toml" | tr -d ' ') lines"

echo
echo "== and it verifies =="
if ./release-check.sh 1 --file "$work/base.toml" > "$work/pass.log" 2>&1; then
  verdict "the written row rebuilds to its own bytes" ok "$(tail -1 "$work/pass.log")"
else
  verdict "the written row rebuilds to its own bytes" FAILED "see below"
  sed 's/^/    /' "$work/pass.log"
fi

# mutate <label> <old> <new> <must-say> <before-the-build?>
mutate() {
  local label=$1 old=$2 new=$3 must=$4 cheap=$5 out rc
  python3 - "$work/base.toml" "$work/m.toml" "$old" "$new" <<'PY'
import hashlib, sys
src, dst, old, new = sys.argv[1:5]
text = open(src).read()
n = text.count(old)
if n != 1:
    sys.exit("MUTANT REFUSED: %r matched %d times, not once" % (old, n))
out = text.replace(old, new, 1)
if hashlib.sha256(out.encode()).hexdigest() == hashlib.sha256(text.encode()).hexdigest():
    sys.exit("MUTANT REFUSED: the file did not change")
open(dst, "w").write(out)
PY
  out=$("$root/release-check.sh" 1 --file "$work/m.toml" 2>&1) && rc=0 || rc=$?
  if [ "$rc" -eq 0 ]; then
    verdict "$label" FAILED "SURVIVES — the gate passed with it in"
    return
  fi
  case $out in
    *"$must"*) ;;
    *) verdict "$label" FAILED "caught, but never said $must"; return ;;
  esac
  if [ "$cheap" = cheap ]; then
    # Anchored on the build's own banner, not on the word: the early-exit
    # message used to contain "rebuilding" too ("not rebuilding"), and this
    # test then reported two mutants as reaching the build when neither did.
    case $out in
      *"-- rebuilding"*) verdict "$label" FAILED "caught only AFTER a cold rebuild"; return ;;
    esac
  fi
  verdict "$label" ok "$([ "$cheap" = cheap ] && echo 'before the build' || echo 'after the rebuild')"
}

echo
echo "== each field, put back wrong =="
mutate "a missing field is a FAILURE, not a skip" \
  "$(grep -m1 '^bytes' "$work/base.toml")" "" "row is complete" cheap
mutate "a row that admits a dirty tree is refused" \
  "dirty  = false" "dirty  = true" "source.dirty" cheap
mutate "a toolchain that is not the recorded one" \
  "$(grep -m1 '^rustc  ' "$work/base.toml")" 'rustc     = "rustc 9.9.9 (deadbeef 2000-01-01)"' "toolchain.rustc" cheap
mutate "a commit this repository does not have" \
  "$(grep -m1 '^commit' "$work/base.toml")" 'commit = "0000000000000000000000000000000000000000"' "source.commit" cheap
mutate "a lockfile digest that is not the lockfile's" \
  "$(grep -m1 '^lock_sha256' "$work/base.toml")" 'lock_sha256 = "sha256:0000000000000000000000000000000000000000000000000000000000000000"' "lock_sha256" cheap
mutate "a profile field the Cargo.toml does not say" \
  'opt_level     = "z"' 'opt_level     = "s"' "profile.opt_level" cheap
mutate "a wasm hash the build does not produce" \
  "$(grep -m1 '^sha256 ' "$work/base.toml")" 'sha256      = "sha256:0000000000000000000000000000000000000000000000000000000000000000"' "sha256" rebuild

echo
[ "$checks" -gt 0 ] || { echo "self-test: 0 checks ran" >&2; exit 1; }
if [ "$failures" -gt 0 ]; then
  echo "self-test: $failures of $checks FAILED"
  exit 1
fi
echo "self-test: $checks checks passed — every field of a row is load-bearing"
