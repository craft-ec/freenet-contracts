//! The contract's four entry points as BYTES in, BYTES out -- what the node's contract ABI carries -- with no
//! freenet-stdlib. The rules are this crate's own ([`crate::check`]); this module only states the answers in the
//! wire form the node reads: bincode 1 as freenet-stdlib's host decodes it (fixint, little-endian, u32 enum tags,
//! u64 lengths), of `Result<_, ContractError>`.
//!
//! WHY by hand: freenet-stdlib's `#[contract]` interface (serde, bincode, formatting) was ~76 KB of the ~101 KB
//! contract every client PUT carries (measured, freenet-contracts `measure-min-block`). The encodings here are pinned
//! against freenet-stdlib's OWN serializer by the tests below, so a drift in either is a red test, not a silent
//! mis-decode on the node.
//!
//! A copy of `block/src/doors.rs` (see lib.rs for why not shared), over this
//! crate's `check`. Behaviour, door for door:
//! - validate: an empty state, or one [`crate::check`] accepts, is `Valid`; anything else `Invalid`;
//! - update: a held state never changes; an empty one adopts the first candidate that `check`s (a `State`, a
//!   `Delta`, or either half of a `StateAndDelta`, in order; the `Related*` shapes are skipped);
//! - summarize: one byte, `1` if a state is held;
//! - delta: nothing for a summary of `[1]` or an empty state, else the whole state.
//!
//! Two answers differ from the stdlib build only in an error's TEXT, never its kind: update data that does not
//! decode is `Err(Deser(..))` as before, with this module's message rather than bincode's; and validate ignores its
//! `related` argument where the stdlib decoded it first (a node always sends a well-formed empty map).

use crate::check;

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

pub fn update(params: &[u8], held: &[u8], updates: &[u8]) -> Vec<u8> {
    // Decoded FIRST, as the stdlib entry did: data that does not decode is an error even for a held state.
    let Some(items) = candidates(updates) else {
        return err_deser("update data does not decode as Vec<UpdateData>");
    };
    if !held.is_empty() {
        return ok_update(held);
    }
    for c in items.into_iter().flatten().flatten() {
        if check(params, c) {
            return ok_update(c);
        }
    }
    ok_update(held)
}

pub fn summarize(state: &[u8]) -> Vec<u8> {
    ok_bytes(&[u8::from(!state.is_empty())])
}

pub fn delta(state: &[u8], summary: &[u8]) -> Vec<u8> {
    if summary == [1] || state.is_empty() {
        ok_bytes(&[])
    } else {
        ok_bytes(state)
    }
}

