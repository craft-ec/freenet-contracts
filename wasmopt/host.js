'use strict';
// A host for a freenet contract's validate_state, enough to ask ONE question:
// does this module ACCEPT or REFUSE these bytes? It is deliberately not a node
// — nothing here decides anything a node decides, it only carries bytes across
// the ABI and reads the verdict back.
//
// ABI, from freenet-stdlib 0.1.40:
//   __frnt__initiate_buffer(capacity: u32) -> i64   ptr to a BufferBuilder
//   BufferBuilder, #[repr(C)] on wasm32:
//     start: i64 @0, capacity: u32 @8, (pad), last_read: i64 @16, last_write: i64 @24
//   Each argument is a STREAMING buffer: the data is [total_len: u32 LE][payload],
//   the contract reads from offset 4, and `last_write` holds 4 + payload.len().
//   Getting this wrong is silent — every call returns a bincode "unexpected end
//   of file" whatever the payload is, because the length header is read as the
//   payload's first four bytes.
//   validate_state(params, state, related) -> i64   ptr to ContractInterfaceResult
//   ContractInterfaceResult, #[repr(C)]: ptr: i64 @0, kind: i32 @8, size: u32 @12
//   payload at `ptr`, `size` bytes: bincode Result<ValidateResult, ContractError>
//   bincode here is fixint LE with a u32 enum discriminant, so
//     Ok(Valid) = 00000000 00000000, Ok(Invalid) = 00000000 01000000, Err = 01......
const fs = require('fs');

// RelatedContracts { map: HashMap<..> } — bincode writes the length as a u64.
const EMPTY_RELATED = Buffer.alloc(8);

function load(path) {
  const mod = new WebAssembly.Module(fs.readFileSync(path));
  const imports = {};
  const refills = { n: 0 };
  for (const { module, name } of WebAssembly.Module.imports(mod)) {
    // The contract refills a buffer it has drained. Everything here fits in
    // one buffer, so a refill means the host got the framing wrong — return 0
    // (EOF), exactly as the stdlib's own native stub does, and COUNT it, so a
    // silently truncated argument shows up instead of looking like a refusal.
    (imports[module] ??= {})[name] = () => {
      refills.n += 1;
      return 0;
    };
  }
  const inst = new WebAssembly.Instance(mod, imports);
  return { w: inst.exports, refills,
           mem: () => new DataView(inst.exports.memory.buffer),
           bytes: () => new Uint8Array(inst.exports.memory.buffer) };
}

function putBuf(m, data) {
  const framed = Buffer.alloc(4 + data.length);
  framed.writeUInt32LE(data.length, 0);
  Buffer.from(data).copy(framed, 4);
  const ptr = Number(m.w.__frnt__initiate_buffer(framed.length));
  const dv = m.mem();
  const start = Number(dv.getBigInt64(ptr + 0, true));
  const cap = dv.getUint32(ptr + 8, true);
  if (framed.length > cap) throw new Error(`buffer too small: ${framed.length} > ${cap}`);
  m.bytes().set(framed, start);
  const lastWrite = Number(dv.getBigInt64(ptr + 24, true));
  m.mem().setUint32(lastWrite, framed.length, true);
  return ptr;
}

// Returns 'accept' | 'refuse' | 'error:<detail>' | 'trap:<detail>'.
// A trap is its OWN outcome, never folded into refuse: "the module rejected
// this" and "the module died on this" are different answers and a differential
// that merges them cannot see an optimiser turning one into the other.
function validate(path, params, state) {
  let m;
  try { m = load(path); } catch (e) { return `loadfail:${e.message}`; }
  try {
    const p = putBuf(m, params), s = putBuf(m, state), r = putBuf(m, EMPTY_RELATED);
    const res = Number(m.w.validate_state(BigInt(p), BigInt(s), BigInt(r)));
    const dv = m.mem();
    const ptr = Number(dv.getBigInt64(res + 0, true));
    const kind = dv.getInt32(res + 8, true);
    const size = dv.getUint32(res + 12, true);
    if (kind !== 0) return `error:kind=${kind}`;
    const buf = Buffer.from(m.bytes().slice(ptr, ptr + size));
    if (buf.length < 8) return `error:short=${buf.length}`;
    const outer = buf.readUInt32LE(0);
    if (outer === 1) return `error:contract`;
    if (outer !== 0) return `error:outer=${outer}`;
    if (m.refills.n > 0) return `error:refilled=${m.refills.n}`;
    const v = buf.readUInt32LE(4);
    if (v === 0) return 'accept';
    if (v === 1) return 'refuse';
    if (v === 2) return 'related';
    return `error:verdict=${v}`;
  } catch (e) {
    return `trap:${String(e.message).slice(0, 60)}`;
  }
}

module.exports = { validate, EMPTY_RELATED };
