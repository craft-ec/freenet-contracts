'use strict';
// Replays the frozen corpus through every build of a contract and requires the
// verdicts to be IDENTICAL. Two oracles, catching different failures:
//   build-vs-build : the optimiser changed what the network will keep.
//   build-vs-native: the wasm boundary is being driven wrong by this harness.
const fs = require('fs');
const { validate } = require('./host.js');

const dir = process.argv[2] || 'builds';
const corpus = process.argv[3] || 'corpus/cases.jsonl';
const only = process.argv[4];           // one contract, or all
const LEVELS = ['as-built', 'O2', 'Os', 'Oz'];

const cases = fs.readFileSync(corpus, 'utf8').trim().split('\n').map(JSON.parse)
  .filter(c => !only || c.contract === only);
const contracts = [...new Set(cases.map(c => c.contract))]
  .filter(c => fs.existsSync(`${dir}/${c}.as-built.wasm`));

let disagreements = 0, nativeMismatch = 0, total = 0;
const rows = [];
for (const contract of contracts) {
  const mine = cases.filter(c => c.contract === contract);
  const counts = Object.fromEntries(LEVELS.map(l => [l, { accept: 0, refuse: 0, other: 0 }]));
  let disagree = 0, mismatch = 0;
  for (const c of mine) {
    total++;
    const p = Buffer.from(c.params, 'hex'), s = Buffer.from(c.state, 'hex');
    const got = LEVELS.map(l => validate(`${dir}/${contract}.${l}.wasm`, p, s));
    for (let i = 0; i < LEVELS.length; i++) {
      const k = got[i] === 'accept' ? 'accept' : got[i] === 'refuse' ? 'refuse' : 'other';
      counts[LEVELS[i]][k]++;
    }
    if (new Set(got).size !== 1) {
      disagree++; disagreements++;
      console.log(`DISAGREE ${contract} ${c.name}`);
      LEVELS.forEach((l, i) => console.log(`    ${l.padEnd(9)} ${got[i]}`));
    } else if (got[0] !== c.expect) {
      mismatch++; nativeMismatch++;
      if (mismatch <= 5)
        console.log(`NATIVE-MISMATCH ${contract} ${c.name}: wasm ${got[0]}, native says ${c.expect}`);
    }
  }
  rows.push({ contract, n: mine.length, disagree, mismatch, counts });
}

console.log();
console.log('contract    cases  disagree  vs-native   ' + LEVELS.map(l => (l + ' a/r').padStart(16)).join(''));
for (const r of rows) {
  console.log(
    r.contract.padEnd(10) + String(r.n).padStart(7) + String(r.disagree).padStart(10) +
    String(r.mismatch).padStart(11) + '   ' +
    LEVELS.map(l => `${r.counts[l].accept}/${r.counts[l].refuse}${r.counts[l].other ? '+' + r.counts[l].other : ''}`.padStart(16)).join(''));
}
console.log();
// A corpus that never accepts anything compares two builds that both refuse
// everything, which is a green run about nothing.
for (const r of rows) {
  const acc = r.counts['as-built'].accept;
  if (acc === 0) { console.log(`FAIL ${r.contract}: no case was ACCEPTED by the as-built module`); process.exit(2); }
}
console.log(`${total} cases over ${contracts.length} contract(s) x ${LEVELS.length} builds`);
console.log(disagreements === 0
  ? 'DIFFERENTIAL PASS: every build gave the same verdict on every case'
  : `DIFFERENTIAL FAIL: ${disagreements} case(s) where builds disagreed`);
if (nativeMismatch) console.log(`NOTE: ${nativeMismatch} case(s) where wasm and native disagreed`);
process.exit(disagreements === 0 ? 0 : 1);
