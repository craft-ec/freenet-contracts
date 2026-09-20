'use strict';
// Validation time with the module compile taken OUT: instantiate once, then
// call validate_state many times on the same instance.
//
// Two different numbers are wanted and they must not be mixed. A node COMPILES
// a contract and then validates with it many times, so a smaller module that
// compiles faster is a real saving — but it is not a cheaper validation, and a
// table that reports one as the other flatters whichever build happens to be
// smaller.
//
// The buffers this ABI allocates are never freed (the stdlib leaks them by
// design; the host drops the instance instead), so memory grows with the
// iteration count and the count is kept modest for the large states.
const fs = require('fs');

// bincode writes a HashMap's length as a u64, so an empty RelatedContracts is
// eight zero bytes — NOT an empty payload. (Framed, that is [8,0,0,0] then the
// eight zeros; the header is the streaming length, not the value.)
const EMPTY_RELATED = Buffer.alloc(8);
function instantiate(path) {
  const mod = new WebAssembly.Module(fs.readFileSync(path));
  const im = {};
  for (const { module, name } of WebAssembly.Module.imports(mod)) (im[module] ??= {})[name] = () => 0;
  return new WebAssembly.Instance(mod, im).exports;
}
function put(w, data) {
  const framed = Buffer.alloc(4 + data.length);
  framed.writeUInt32LE(data.length, 0);
  Buffer.from(data).copy(framed, 4);
  const ptr = Number(w.__frnt__initiate_buffer(framed.length));
  let dv = new DataView(w.memory.buffer);
  const start = Number(dv.getBigInt64(ptr, true));
  const lw = Number(dv.getBigInt64(ptr + 24, true));
  new Uint8Array(w.memory.buffer).set(framed, start);
  new DataView(w.memory.buffer).setUint32(lw, framed.length, true);
  return ptr;
}
function verdict(w, res) {
  const dv = new DataView(w.memory.buffer);
  const ptr = Number(dv.getBigInt64(res, true)), kind = dv.getInt32(res + 8, true), size = dv.getUint32(res + 12, true);
  if (kind !== 0) return `kind${kind}`;
  const b = Buffer.from(new Uint8Array(w.memory.buffer).slice(ptr, ptr + size));
  return b.readUInt32LE(0) !== 0 ? 'contract-error' : ['accept', 'refuse', 'related'][b.readUInt32LE(4)];
}

const corpus = fs.readFileSync('corpus/cases.jsonl', 'utf8').trim().split('\n').map(JSON.parse);
const pick = n => { const c = corpus.find(x => x.name === n); return { name: n, contract: c.contract, p: Buffer.from(c.params, 'hex'), s: Buffer.from(c.state, 'hex'), expect: c.expect }; };
const CASES = [['tree-node-worst-case', 400], ['raw-at-bound', 60], ['bag-full', 400], ['set-two', 400], ['register-1', 400]]
  .map(([n, iters]) => ({ ...pick(n), iters }));
const LEVELS = ['as-built', 'O2', 'Os', 'Oz'];

const med = a => { const b = [...a].sort((x, y) => x - y); return b[Math.floor(b.length / 2)]; };
const out = {};
// Interleaved by ROUND across levels, so drift in machine load moves all arms.
for (let round = 0; round < 5; round++) {
  for (const c of CASES) for (const l of LEVELS) {
    const w = instantiate(`builds/${c.contract}.${l}.wasm`);
    const per = [];
    for (let i = 0; i < c.iters; i++) {
      const pp = put(w, c.p), ss = put(w, c.s), rr = put(w, EMPTY_RELATED);
      const t0 = process.hrtime.bigint();
      const res = Number(w.validate_state(BigInt(pp), BigInt(ss), BigInt(rr)));
      const t1 = process.hrtime.bigint();
      if (verdict(w, res) !== c.expect) throw new Error(`${c.name} ${l} wrong verdict`);
      per.push(Number(t1 - t0) / 1e3);       // microseconds
    }
    (out[`${c.name}|${l}`] ??= []).push(med(per));
  }
}
console.log('median microseconds per validate_state call, module compile EXCLUDED');
console.log('(5 interleaved rounds; each round is the median of the per-call times in that round)');
console.log();
console.log('case                      state B  ' + LEVELS.map(l => (l + ' us').padStart(12)).join('') + '     Os vs as-built');
for (const c of CASES) {
  const v = LEVELS.map(l => med(out[`${c.name}|${l}`]));
  const d = ((v[2] - v[0]) / v[0]) * 100;
  console.log(c.name.padEnd(24) + String(c.s.length).padStart(8) + '  ' +
    v.map(x => x.toFixed(1).padStart(12)).join('') + `     ${d >= 0 ? '+' : ''}${d.toFixed(1)}%`);
}
console.log();
console.log('compile+instantiate alone, median ms of 20:');
for (const contract of ['block', 'bag', 'register', 'set']) {
  const t = LEVELS.map(l => {
    const a = [];
    for (let i = 0; i < 20; i++) { const t0 = process.hrtime.bigint(); instantiate(`builds/${contract}.${l}.wasm`); a.push(Number(process.hrtime.bigint() - t0) / 1e6); }
    return med(a);
  });
  console.log('  ' + contract.padEnd(10) + t.map(x => x.toFixed(2).padStart(10)).join('') +
    `     Oz vs as-built ${(((t[3] - t[0]) / t[0]) * 100).toFixed(1)}%`);
}
