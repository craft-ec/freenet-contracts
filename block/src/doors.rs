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
//! Behaviour is `block/`'s as it shipped through `#[contract]`, door for door:
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

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_stdlib::prelude::*;

    fn raw(body: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let s = crate::encode(crate::kind::RAW, body);
        (blake3::hash(&s).as_bytes().to_vec(), s)
    }
    fn new_state(bytes: &[u8]) -> Option<Vec<u8>> {
        let r: Result<UpdateModification<'_>, ContractError> = bincode::deserialize(bytes).unwrap();
        r.unwrap().new_state.map(|s| s.as_ref().to_vec())
    }

    /// Every `UpdateData` shape, encoded by stdlib: only `State`, `Delta` and either half of `StateAndDelta` are
    /// candidates, in order; the `Related*` ones -- another contract's bytes -- are skipped, even when they would
    /// check.
    #[test]
    fn update_takes_its_candidates_from_every_shape_in_order() {
        let (p, good) = raw(b"the one");
        let id = ContractInstanceId::new([9; 32]);
        let junk = State::from(b"junk".to_vec());
        let data = vec![
            UpdateData::RelatedState {
                related_to: id,
                state: State::from(good.clone()),
            },
            UpdateData::RelatedDelta {
                related_to: id,
                delta: StateDelta::from(good.clone()),
            },
            UpdateData::RelatedStateAndDelta {
                related_to: id,
                state: State::from(good.clone()),
                delta: StateDelta::from(good.clone()),
            },
            UpdateData::StateAndDelta {
                state: junk.clone(),
                delta: StateDelta::from(good.clone()),
            },
        ];
        let wire = bincode::serialize(&data).unwrap();
        assert_eq!(
            new_state(&update(&p, &[], &wire)),
            Some(good.clone()),
            "the delta half was not adopted"
        );
        // Only Related* offered: nothing is adopted, and the empty state stays empty.
        let wire = bincode::serialize(&data[..3]).unwrap();
        assert_eq!(new_state(&update(&p, &[], &wire)), Some(vec![]));
        // A held state never changes, whatever is offered.
        let (_, other) = raw(b"held");
        let wire = bincode::serialize(&vec![UpdateData::State(State::from(good))]).unwrap();
        assert_eq!(new_state(&update(&p, &other, &wire)), Some(other));
    }

    /// Update data that does not decode is `Err(Deser)`, a held state included (stdlib decoded before deciding);
    /// trailing bytes after the items are allowed, as `bincode::deserialize` allows them.
    #[test]
    fn update_data_that_does_not_decode_is_an_error_and_trailing_bytes_are_not() {
        let (p, good) = raw(b"x");
        for bad in [vec![], vec![1, 0, 0, 0, 0, 0, 0, 0], {
            let mut v = 1u64.to_le_bytes().to_vec();
            v.extend_from_slice(&9u32.to_le_bytes()); // no such UpdateData variant
            v
        }] {
            for held in [&[][..], &good[..]] {
                let answer = update(&p, held, &bad);
                let r: Result<UpdateModification<'_>, ContractError> =
                    bincode::deserialize(&answer).unwrap();
                assert!(matches!(r, Err(ContractError::Deser(_))), "{bad:?} decoded");
            }
        }
        let mut wire =
            bincode::serialize(&vec![UpdateData::State(State::from(good.clone()))]).unwrap();
        wire.extend_from_slice(b"trailing");
        assert_eq!(new_state(&update(&p, &[], &wire)), Some(good));
    }

    /// A count that lies is refused by running out of bytes, not by allocating for it.
    #[test]
    fn a_lying_update_count_costs_nothing() {
        let (p, _) = raw(b"x");
        let answer = update(&p, &[], &u64::MAX.to_le_bytes());
        let r: Result<UpdateModification<'_>, ContractError> =
            bincode::deserialize(&answer).unwrap();
        assert!(matches!(r, Err(ContractError::Deser(_))));
    }
}
