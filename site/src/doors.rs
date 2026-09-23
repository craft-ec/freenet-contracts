//! The contract's four entry points as BYTES in, BYTES out -- what the node's contract ABI carries -- with no
//! freenet-stdlib. The rules are this crate's own ([`crate::check`], [`crate::merge`]); this module only states
//! the answers in the wire form the node reads: bincode 1 as freenet-stdlib's host decodes it (fixint,
//! little-endian, u32 enum tags, u64 lengths), of `Result<_, ContractError>`. A copy of `webapp/src/doors.rs`
//! (see lib.rs for why not shared), over this crate's rules. Behaviour, door for door:
//! - validate: an empty state, or one [`crate::check`] accepts, is `Valid`; anything else `Invalid`;
//! - update: every valid candidate (a `State`, a `Delta`, or either half of a `StateAndDelta`, in order; the
//!   `Related*` shapes are skipped) is MERGED into the held state ([`crate::merge`]); an invalid one is ignored;
//! - summarize: blake3 of the state (nothing for an empty one);
//! - delta: nothing when the summary is this state's, else the whole state.

use crate::{check, merge, params, parse};

/// Result kinds, as the node's `ContractInterfaceResult` names them.
pub const KIND_VALIDATE: i32 = 0;
pub const KIND_UPDATE: i32 = 2;
pub const KIND_SUMMARIZE: i32 = 3;
pub const KIND_DELTA: i32 = 4;

/// `Ok(ValidateResult::Valid)`.
pub const OK_VALID: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];
/// `Ok(ValidateResult::Invalid)`.
pub const OK_INVALID: [u8; 8] = [0, 0, 0, 0, 1, 0, 0, 0];

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u64).to_le_bytes());
    out.extend_from_slice(b);
}

/// `Ok(UpdateModification::valid(state))`: Ok, `new_state: Some(state)`, `related: []`.
fn ok_update(state: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 1 + 8 + state.len() + 8);
    v.extend_from_slice(&[0, 0, 0, 0, 1]);
    put_bytes(&mut v, state);
    v.extend_from_slice(&0u64.to_le_bytes());
    v
}

/// `Ok(bytes)` for a `StateSummary` or a `StateDelta`: both are a byte string.
fn ok_bytes(b: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + 8 + b.len());
    v.extend_from_slice(&[0, 0, 0, 0]);
    put_bytes(&mut v, b);
    v
}

/// `Err(ContractError::Deser(msg))`.
fn err_deser(msg: &str) -> Vec<u8> {
    let mut v = vec![1, 0, 0, 0, 0, 0, 0, 0];
    put_bytes(&mut v, msg.as_bytes());
    v
}

pub fn validate(params: &[u8], state: &[u8]) -> &'static [u8] {
    if state.is_empty() || check(params, state) {
        &OK_VALID
    } else {
        &OK_INVALID
    }
}

/// A cursor over bincode bytes that never reads past the end.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (a, b) = self.0.split_at_checked(n)?;
        self.0 = b;
        Some(a)
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Option<u64> {
        let b = self.take(8)?;
        Some(u64::from_le_bytes(b.try_into().ok()?))
    }
    fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = usize::try_from(self.u64()?).ok()?;
        self.take(n)
    }
}

/// `Vec<UpdateData>` as the candidate states each item offers, in order; `None` when it does not decode. The
/// count is not trusted for an allocation: every item costs at least its 4-byte tag, so a lying count runs out of
/// bytes, not memory. Trailing bytes are allowed, as `bincode::deserialize` allows them.
fn candidates(updates: &[u8]) -> Option<Vec<[Option<&[u8]>; 2]>> {
    let mut r = Reader(updates);
    let n = r.u64()?;
    let mut out = Vec::new();
    for _ in 0..n {
        let item = match r.u32()? {
            0 | 1 => [Some(r.bytes()?), None], // State, Delta
            2 => {
                let state = r.bytes()?;
                let delta = r.bytes()?;
                [Some(state), Some(delta)] // StateAndDelta
            }
            3 | 4 => {
                r.take(32)?; // RelatedState, RelatedDelta: another contract's; skipped
                r.bytes()?;
                [None, None]
            }
            5 => {
                r.take(32)?; // RelatedStateAndDelta
                r.bytes()?;
                r.bytes()?;
                [None, None]
            }
            _ => return None,
        };
        out.push(item);
    }
    Some(out)
}

pub fn update(params_bytes: &[u8], held: &[u8], updates: &[u8]) -> Vec<u8> {
    // Decoded FIRST, as the stdlib entry did: data that does not decode is an error even for a held state.
    let Some(items) = candidates(updates) else {
        return err_deser("update data does not decode as Vec<UpdateData>");
    };
    // Params this contract refuses make every state invalid: nothing is adopted.
    let Some(p) = params(params_bytes) else {
        return ok_update(held);
    };
    let mut cur: Vec<u8> = held.to_vec();
    for c in items.into_iter().flatten().flatten() {
        let Some(cand) = parse(&p, c) else { continue };
        cur = match parse(&p, &cur) {
            Some(h) => merge(&p, &h, &cand),
            // Empty (or, never on a host, invalid) held state: the candidate is adopted as it is.
            None => c.to_vec(),
        };
    }
    ok_update(&cur)
}

pub fn summarize(state: &[u8]) -> Vec<u8> {
    if state.is_empty() {
        return ok_bytes(&[]);
    }
    ok_bytes(blake3::hash(state).as_bytes())
}

pub fn delta(state: &[u8], summary: &[u8]) -> Vec<u8> {
    if state.is_empty() || summary == blake3::hash(state).as_bytes() {
        ok_bytes(&[])
    } else {
        ok_bytes(state)
    }
}
