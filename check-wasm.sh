#!/usr/bin/env bash
# Time the block contract's validation inside wasm32, on the worst case a host
# can be handed. A missing tool fails; it never skips.
set -euo pipefail
cd "$(dirname "$0")"
command -v node >/dev/null || { echo "check-wasm: node is required" >&2; exit 1; }
rustup target list --installed | grep -qx wasm32-unknown-unknown ||
  { echo "check-wasm: rust target wasm32-unknown-unknown is required" >&2; exit 1; }
cargo build --quiet --release --target wasm32-unknown-unknown --manifest-path wasm-check/Cargo.toml
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
