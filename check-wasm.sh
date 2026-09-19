#!/usr/bin/env bash
# Time each contract's validation inside wasm32, on the worst case a host can
# be handed. A missing tool fails; it never skips.
#
# The harness is built with the SAME flags a contract ships with, taken from
# `contract-build.sh --flags` rather than copied: a timing run over code built
# differently from the code that runs on the network is a number about nothing.
# `CHECK_WASM_UNHARDENED=1` builds it without them, which is how the cost of
# the hardening itself is measured.
set -euo pipefail
cd "$(dirname "$0")"
command -v node >/dev/null || { echo "check-wasm: node is required" >&2; exit 1; }
rustup target list --installed | grep -qx wasm32-unknown-unknown ||
  { echo "check-wasm: rust target wasm32-unknown-unknown is required" >&2; exit 1; }
if [ -n "${CHECK_WASM_UNHARDENED:-}" ]; then
  echo "check-wasm: harness built UNHARDENED — not the code that ships" >&2
  export RUSTFLAGS=""
else
  export RUSTC_BOOTSTRAP=1
  RUSTFLAGS=$(./contract-build.sh --flags wasm-check); export RUSTFLAGS
fi
cargo build --quiet --release --target wasm32-unknown-unknown --manifest-path wasm-check/Cargo.toml
harness=wasm-check/target/wasm32-unknown-unknown/release/wasm_check.wasm
# WHICH binary was timed, printed rather than assumed: a timing run over a
# stale or differently-built artefact reads exactly like a fast one. The size
# is the observable that separates the two modes — 113,759 B hardened against
# 118,899 B not, at the time of writing — because this profile sets
# `strip = true`, so the source paths that distinguish a contract's two builds
# are gone from the harness either way.
echo "harness: $(wc -c < "$harness" | tr -d ' ') B sha256=$(shasum -a 256 "$harness" | cut -c1-16)$([ -n "${CHECK_WASM_UNHARDENED:-}" ] && echo ' UNHARDENED' || echo ' (contract flags)')"
node - <<'JS'
const fs = require('fs');
const path = 'wasm-check/target/wasm32-unknown-unknown/release/wasm_check.wasm';
const bytes = fs.readFileSync(path);
const mod = new WebAssembly.Module(bytes);
// Stub whatever the module imports, so a host-side dependency shows up as a
// named failure instead of a silent one.
const imports = {};
for (const { module, name } of WebAssembly.Module.imports(mod)) {
  (imports[module] ??= {})[name] = () => {
    throw new Error(`wasm called host import ${module}.${name}`);
  };
}
const { exports: w } = new WebAssembly.Instance(mod, imports);
const h = w.prepare();
const entries = w.entries(h), len = w.state_len(h);
// A timing run over a node that was never built would print a very good number.
if (entries < 500) throw new Error(`worst case has only ${entries} entries`);
if (w.accepts_good_refuses_corrupt(h) !== 1)
  throw new Error('wasm32: the check does not separate a good node from a corrupt one');
const time = (fn, runs) => {
  fn(h, Math.min(runs, 50));                       // warm up
  const t = process.hrtime.bigint();
  const ok = fn(h, runs);
  const ns = Number(process.hrtime.bigint() - t) / runs;
  if (ok !== runs) throw new Error(`only ${ok}/${runs} passed`);
  return ns;
};
const runs = 2000;
console.log(`block, worst case: ${entries} entries, ${len} B state (wasm32, opt-level z + lto)`);
console.log(`  parse + check_node   ${(time(w.well_formed_n, runs) / 1000).toFixed(1)} us`);
console.log(`  check() (with hash)  ${(time(w.check_n, runs) / 1000).toFixed(1)} us`);

// Register: mode 1, n = 16, k = 16 — sixteen signatures per validation.
const rh = w.prepare_register();
const rlen = w.register_state_len(rh);
if (w.register_accepts_good_refuses_corrupt(rh) !== 1)
  throw new Error('wasm32: register validation does not separate a good state from a corrupt one');
const rtime = (() => {
  w.register_validate_n(rh, 5);
  const t = process.hrtime.bigint();
  const ok = w.register_validate_n(rh, 200);
  const ns = Number(process.hrtime.bigint() - t) / 200;
  if (ok !== 200) throw new Error(`only ${ok}/200 validated`);
  return ns;
})();
const rep = (fn, runs) => {
  fn(rh, 5);
  const t = process.hrtime.bigint();
  const ok = fn(rh, runs);
  const ns = Number(process.hrtime.bigint() - t) / runs;
  if (ok !== runs) throw new Error(`only ${ok}/${runs} succeeded`);
  return ns;
};
console.log(`register, worst case (mode 1, n=16 k=16): ${rlen} B state`);
console.log(`  validate_state             ${(rtime / 1000).toFixed(0)} us`);
console.log(`  stale replay, verify late  ${(rep(w.register_stale_replay_n, 200) / 1000).toFixed(0)} us`);
console.log(`  stale replay, eager        ${(rep(w.register_stale_replay_eager_n, 200) / 1000).toFixed(0)} us`);
JS
node - <<'JS'
const fs = require('fs');
const path = 'wasm-check/target/wasm32-unknown-unknown/release/wasm_check.wasm';
const mod = new WebAssembly.Module(fs.readFileSync(path));
const imports = {};
for (const { module, name } of WebAssembly.Module.imports(mod)) {
  (imports[module] ??= {})[name] = () => { throw new Error(`host import ${module}.${name}`); };
}
const { exports: w } = new WebAssembly.Instance(mod, imports);
const time = (fn, h, runs) => {
  fn(h, Math.min(runs, 20));
  const t = process.hrtime.bigint();
  const ok = fn(h, runs);
  const ns = Number(process.hrtime.bigint() - t) / runs;
  if (ok !== runs) throw new Error(`only ${ok}/${runs} passed`);
  return ns / 1000;
};
console.log('');
console.log('bag, worst case (M pointers at the 256 B payload cap), wasm32:');
console.log('  M     payload    state      summary   validate_state   one no-op delta (update + F23 validate)');
for (const [m, pay] of [[256, 256], [1024, 256], [256, 48], [1024, 48]]) {
  const h = w.bag_prepare_with(m, pay);
  if (w.bag_count(h) !== m) throw new Error(`bag_prepare(${m}) built ${w.bag_count(h)}`);
  if (w.bag_accepts_good_refuses_corrupt(h) !== 1)
    throw new Error('wasm32: validation does not separate a good bag from a corrupt one');
  const runs = m === 256 ? 400 : 100;
  const v = time(w.bag_validate_n, h, runs);
  const d = time(w.bag_noop_delta_n, h, runs);
  console.log(
    `  ${String(m).padEnd(5)} ${String(pay).padStart(5)} B  ${String(w.bag_state_len(h)).padStart(8)} B  ` +
    `${String(w.bag_summary_len(h)).padStart(6)} B   ${v.toFixed(0).padStart(8)} us   ${d.toFixed(0).padStart(10)} us`
  );
}
console.log('  (on the PEER-BROADCAST path a byte-identical replay is dropped before any wasm — F24b — so it costs 0 there;');
console.log('   through the client API in local mode an identical payload was measured running FULL validation, so it costs a validate_state)');

console.log('set, worst case (both tiers full, 256 B payloads, every cap-holder item carrying its grant), wasm32:');
console.log('  M     items    state      summary   validate_state   one no-op update (absorb + F23 validate)');
for (const m of [16, 64]) {
  const h = w.set_prepare(m);
  if (w.set_items(h) !== 2 * m) throw new Error(`set_prepare(${m}) built ${w.set_items(h)} items, wanted ${2 * m}`);
  if (w.set_accepts_good_refuses_corrupt(h) !== 1)
    throw new Error('wasm32: validation does not separate a good set from a corrupt one');
  const runs = m === 16 ? 200 : 60;
  const v = time(w.set_validate_n, h, runs);
  const d = time(w.set_noop_delta_n, h, runs);
  console.log(
    `  ${String(m).padEnd(5)} ${String(w.set_items(h)).padStart(5)}  ${String(w.set_state_len(h)).padStart(8)} B  ` +
    `${String(w.set_summary_len(h)).padStart(6)} B   ${v.toFixed(0).padStart(8)} us   ${d.toFixed(0).padStart(10)} us`
  );
}
JS
