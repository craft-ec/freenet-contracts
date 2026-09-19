//! Set contract: a bounded union of signed items (ARCHITECTURE.md §1).
//!
//! Params = `"ST01" ‖ owner ‖ admission ‖ limits ‖ bucket ‖ label`, so the
//!          contract key commits to who may write it and to how big it gets.
//! State  = `"ST01" ‖ deny count ‖ deny* ‖ item count ‖ item*`, in rank order.
//! Valid  = every signature in it verifies under the params, every encoding is
//!          the canonical one, and the limits hold.
//! Merge  = union the slots, keep the best DECISION in each, cut to capacity,
//!          then drop the denied — a semilattice on decisions (`crate::merge`).
//!
//! **The one thing a Set asserts is that every item in it was signed by its
//! slot's key.** Validation therefore verifies every signature, every time. It
//! is not an optimisation waiting to happen: a node that stores a Set FETCHED
//! from a peer runs `validate_state` and nothing else (F23), so a state whose
//! top ranks were forged would poison an honest replica and no honest update
//! would ever heal it. Verify-on-contest was considered for exactly this and
//! rejected.
//!
//! **What that costs, and why `M` is 64.** The host re-validates the whole
//! state after every accepted update, and a no-op update still validates
//! (F24) — so one replayed message costs every host a full validation. With
//! one signature per item an accepted item costs O(M) and filling a Set costs
//! O(M²). Volume comes from sharding: a Set's shards are listed in the owner's
//! own tree, and the counts there are the owner's claims.
//!
//! **Nothing here binds the contract's code.** Slot names, stamps, signatures
//! and capabilities bind `BLAKE3(params)` only. A contract's key moves when its
//! code is upgraded, and every item must stay valid and re-publishable across
//! that — so nothing in the format may know which build is hosting it.

use freenet_stdlib::prelude::*;

pub mod merge;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod wire;

use merge::{delta, join, summarize};
use wire::{
    Held, Item, Params, SetState, CAP_LEN, KEY_LEN, MAX_DENY, MAX_ITEM_KEY, MAX_M, SIG_LEN,
};

/// The largest state the format can express, derived rather than guessed:
/// two tiers of `MAX_M` items at their maximum encoded size, plus a full deny
/// list and the headers.
///
/// Checked BEFORE anything is parsed. A stranger can send any number of bytes,
/// and a state that is refused after being walked has still been walked.
pub const MAX_STATE: usize = {
    let item = KEY_LEN + 1 + MAX_ITEM_KEY + 8 + 1 + 2 + 256 + CAP_LEN + 8 + SIG_LEN;
    4 + 2 + (MAX_DENY as usize) * (KEY_LEN + SIG_LEN) + 2 + 2 * (MAX_M as usize) * item
};

/// Parse and fully verify a state against its params: what `validate_state`
/// does.
pub fn read(params: &[u8], state: &[u8]) -> Option<(Params, SetState)> {
    if state.len() > MAX_STATE {
        return None;
    }
    let p = Params::parse(params)?;
    let s = SetState::parse(state, &p)?;
    Some((p, s))
}

/// Structure only, for the state a host ALREADY HOLDS.
///
/// Its signatures were checked by `validate_state` before it was ever stored,
/// and re-checking 128 of them on every summary and delta would cost a great
/// deal for an answer that cannot have changed. Candidates arriving from the
/// network are a different matter and are verified in [`absorb`].
pub fn read_unverified(params: &[u8], state: &[u8]) -> Option<(Params, SetState)> {
    if state.len() > MAX_STATE {
        return None;
    }
    let p = Params::parse(params)?;
    let s = SetState::parse_unverified(state, &p)?;
    Some((p, s))
}

/// Merge a parsed-but-unverified candidate into `held`, verifying only what
/// could change the state.
///
/// A replayed item is the cheapest thing anyone can send, and with `M = 64` a
/// full verification is 64 signature checks. So each candidate item is placed
/// against the slot it claims first: an item whose decision cannot beat the one
/// already held is dropped for the price of a parse, and only an item that
/// would actually enter or replace buys a signature check.
///
/// Skipping those checks is safe precisely because they could not matter — a
/// candidate that loses the decision order is discarded whether its signature
/// holds or not. It is also not a weakening of the guarantee: the host
/// re-validates the whole resulting state afterwards, and that path verifies
/// everything.
pub fn absorb(held: &SetState, cand: SetState, p: &Params) -> SetState {
    let ph = p.hash();
    let mut useful = SetState {
        // A denial is owner-signed and grow-only; one this state already holds
        // is dropped before its signature is looked at.
        deny: cand
            .deny
            .into_iter()
            .filter(|d| {
                held.deny
                    .binary_search_by_key(&d.signer, |x| x.signer)
                    .is_err()
                    && d.verify(p, &ph)
            })
            .collect(),
        held: Vec::new(),
    };
    for h in cand.held {
        let beats = match held.held.iter().find(|x| x.slot == h.slot) {
            Some(x) => h.item.decision().rank() > x.item.decision().rank(),
            // A slot nothing is held for could still lose the cut, but the cut
            // is cheap and the signature is not, so the order is: could it win
            // the slot, then is it real.
            None => true,
        };
        if beats && h.item.verify(p, &ph) {
            useful.held.push(h);
        }
    }
    useful.held.sort_by_key(|h| h.rank());
    join(held, &useful, p)
}

pub struct Set;

#[contract]
impl ContractInterface for Set {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        // Never RequestRelated: the host would validate this contract twice
        // for one update (F24), and a Set needs nothing from anyone else.
        Ok(match read(parameters.as_ref(), state.as_ref()) {
            Some(_) => ValidateResult::Valid,
            None => ValidateResult::Invalid,
        })
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let Some((p, mut held)) = read_unverified(parameters.as_ref(), state.as_ref()) else {
            return Err(ContractError::InvalidState);
        };
        for item in data {
            let candidates: [Option<&[u8]>; 2] = match &item {
                UpdateData::State(s) => [Some(s.as_ref()), None],
                UpdateData::Delta(d) => [Some(d.as_ref()), None],
                UpdateData::StateAndDelta { state, delta } => {
                    [Some(state.as_ref()), Some(delta.as_ref())]
                }
                _ => [None, None],
            };
            for bytes in candidates.into_iter().flatten() {
                // An unreadable candidate is ignored, never fatal: one bad
                // sender must not cost a good one its update in the same batch.
                if bytes.len() <= MAX_STATE {
                    if let Some(c) = SetState::parse_unverified(bytes, &p) {
                        held = absorb(&held, c, &p);
                    }
                }
            }
        }
        Ok(UpdateModification::valid(State::from(held.encode())))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let Some((p, s)) = read_unverified(parameters.as_ref(), state.as_ref()) else {
            return Err(ContractError::InvalidState);
        };
        Ok(StateSummary::from(summarize(&s, &p)))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let Some((p, s)) = read_unverified(parameters.as_ref(), state.as_ref()) else {
            return Err(ContractError::InvalidState);
        };
        // A summary this host cannot read gets the whole state: refusing would
        // strand a peer whose summary was corrupted in flight, and the state is
        // bounded anyway.
        let d = delta(&s, summary.as_ref(), &p).unwrap_or_else(|| s.clone());
        if d.held.is_empty() && d.deny.is_empty() {
            return Ok(StateDelta::from(Vec::new()));
        }
        Ok(StateDelta::from(d.encode()))
    }
}

/// Build the state a set would hold given these items — for callers assembling
/// one, and for the fixtures.
pub fn collect(items: impl IntoIterator<Item = Item>, p: &Params) -> SetState {
    let ph = p.hash();
    let held: Vec<Held> = items.into_iter().map(|i| Held::of(i, p, &ph)).collect();
    let mut s = SetState {
        deny: Vec::new(),
        held: merge::cut(held, p),
    };
    s.held.sort_by_key(|h| h.rank());
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{world, world_with};
    use crate::wire::{verifications, Admission};

    fn update_with(p: &[u8], held: &[u8], data: Vec<Vec<u8>>) -> Vec<u8> {
        let data = data
            .into_iter()
            .map(|d| UpdateData::State(State::from(d)))
            .collect();
        Set::update_state(
            Parameters::from(p.to_vec()),
            State::from(held.to_vec()),
            data,
        )
        .unwrap()
        .new_state
        .map(|s| s.as_ref().to_vec())
        .unwrap_or_default()
    }

    #[test]
    fn a_first_write_is_adopted_and_an_older_version_never_displaces_it() {
        let w = world();
        let newer = w.encode(&w.state(vec![w.item(1, b"k", 9, b"new")]));
        assert_eq!(
            update_with(
                &w.params_bytes,
                &w.encode(&SetState::default()),
                vec![newer.clone()]
            ),
            newer
        );
        let older = w.encode(&w.state(vec![w.item(1, b"k", 2, b"old")]));
        assert_eq!(
            update_with(&w.params_bytes, &newer, vec![older]),
            newer,
            "an older version displaced a newer one"
        );
    }

    #[test]
    fn garbage_cannot_displace_a_held_state_and_one_bad_candidate_does_not_block_a_good_one() {
        let w = world();
        let held = w.encode(&w.state(vec![w.item(0, b"k", 6, b"held")]));
        let junk = vec![
            Vec::new(),
            b"garbage".to_vec(),
            vec![0u8; 3],
            vec![0xff; 5000],
            vec![0u8; MAX_STATE + 1],
        ];
        assert_eq!(update_with(&w.params_bytes, &held, junk.clone()), held);

        let good = w.encode(&w.state(vec![w.item(1, b"other", 1, b"good")]));
        let mut mixed = junk;
        mixed.insert(2, good);
        let after = update_with(&w.params_bytes, &held, mixed);
        let (_, s) = read(&w.params_bytes, &after).expect("the result must be valid");
        assert_eq!(s.held.len(), 2, "the good candidate was lost");
    }

    /// An item that cannot win its slot must not buy a signature check.
    /// Replaying what a host already holds is the cheapest thing anyone can
    /// send, and with `M = 64` a full verification is sixty-four of them.
    #[test]
    fn only_a_candidate_that_could_win_costs_signature_checks() {
        let w = world();
        let held = w.encode(&w.state(vec![w.item(1, b"k", 5, b"held")]));
        let cost = |cand: Vec<u8>| {
            verifications::reset();
            update_with(&w.params_bytes, &held, vec![cand]);
            verifications::count()
        };
        assert_eq!(
            cost(w.encode(&w.state(vec![w.item(1, b"k", 2, b"stale")]))),
            0,
            "a replayed older version bought signature checks"
        );
        assert_eq!(
            cost(w.encode(&w.state(vec![w.item_full(1, b"k", 5, b"held", false, false, 42)]))),
            0,
            "another witness of the held decision bought signature checks"
        );
        // A newer version costs exactly two: the item and its capability.
        assert_eq!(
            cost(w.encode(&w.state(vec![w.item(1, b"k", 9, b"newer")]))),
            2
        );
        // And validation itself still checks everything, every time.
        verifications::reset();
        assert!(read(&w.params_bytes, &held).is_some());
        assert_eq!(verifications::count(), 2);
    }

    /// A second witness of the decision already held must leave the state byte
    /// for byte unchanged. Anything less and a key holder can make every host
    /// rewrite its state and wake every subscriber, for free, for ever.
    #[test]
    fn a_second_witness_of_the_held_decision_is_a_no_op() {
        let w = world();
        let held = w.encode(&w.state(vec![w.item_full(1, b"k", 5, b"v", false, false, 0)]));
        let other = w.encode(&w.state(vec![w.item_full(1, b"k", 5, b"v", false, false, 91)]));
        assert_ne!(other, held, "the fixture must be a different encoding");
        assert!(read(&w.params_bytes, &other).is_some(), "and a valid one");
        assert_eq!(update_with(&w.params_bytes, &held, vec![other]), held);
    }

    /// An unsigned item offered through `update_state` must never enter the
    /// state. This is the path a stranger actually reaches, and a state the
    /// host then re-validates would be rejected wholesale — so a miss here
    /// costs the honest writers their update too.
    #[test]
    fn a_forged_item_cannot_enter_through_update() {
        let w = world();
        let held = w.encode(&w.state(vec![w.item(0, b"k", 1, b"held")]));
        let mut forged = w.item(1, b"new", 9, b"forged");
        forged.sig = [0u8; 64];
        let bytes = SetState {
            deny: Vec::new(),
            held: vec![Held::of(forged, &w.params, &w.params.hash())],
        }
        .encode();
        let after = update_with(&w.params_bytes, &held, vec![bytes]);
        assert_eq!(after, held, "a forged item entered the state");
        assert!(read(&w.params_bytes, &after).is_some());
    }

    /// A denial offered by a stranger must not drop anyone's items, and the
    /// owner's must.
    #[test]
    fn only_the_owner_can_deny() {
        let w = world();
        let held = w.encode(&w.state(vec![w.item(1, b"k", 1, b"v")]));
        let forged = SetState {
            deny: vec![crate::testing::elsewhere().deny_of(1)],
            held: Vec::new(),
        }
        .encode();
        assert_eq!(
            update_with(&w.params_bytes, &held, vec![forged]),
            held,
            "a stranger's denial changed the state"
        );
        let real = SetState {
            deny: vec![w.deny_of(1)],
            held: Vec::new(),
        }
        .encode();
        let after = update_with(&w.params_bytes, &held, vec![real]);
        let (_, s) = read(&w.params_bytes, &after).unwrap();
        assert!(
            s.held.is_empty(),
            "the owner's denial did not drop the item"
        );
        assert_eq!(s.deny.len(), 1);
    }

    #[test]
    fn a_no_op_delta_is_empty_and_a_peer_with_nothing_gets_everything() {
        let w = world_with(8, 4, Admission::Cap, 8, 4, 0);
        let s = w.encode(&w.state(vec![w.item(0, b"a", 1, b"v"), w.item(1, b"b", 2, b"w")]));
        let sum = |bytes: &[u8]| {
            Set::summarize_state(
                Parameters::from(w.params_bytes.clone()),
                State::from(bytes.to_vec()),
            )
            .unwrap()
            .as_ref()
            .to_vec()
        };
        let d = |bytes: &[u8], summary: Vec<u8>| {
            Set::get_state_delta(
                Parameters::from(w.params_bytes.clone()),
                State::from(bytes.to_vec()),
                StateSummary::from(summary),
            )
            .unwrap()
            .as_ref()
            .to_vec()
        };
        assert!(d(&s, sum(&s)).is_empty(), "a level peer was sent something");
        let empty = w.encode(&SetState::default());
        let all = d(&s, sum(&empty));
        assert!(!all.is_empty());
        // What comes back is a state in its own right, checked identically.
        let (_, parsed) = read(&w.params_bytes, &all).expect("a delta IS a set");
        assert_eq!(parsed.held.len(), 2);
    }
}
