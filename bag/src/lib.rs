//! Bag contract: unsigned immutable pointers, top-M by work (ARCHITECTURE §8).
//!
//! Params = `"BG01" ‖ owner ‖ work_bits ‖ M ‖ payload cap ‖ bucket ‖ label`,
//!          so the contract key commits to the price and the size.
//! State  = `"BG01" ‖ count ‖ pointers`, in rank order — one canonical spelling.
//! Valid  = every name meets the price, every payload is within the cap, the
//!          order is strict, and the count is at most M.
//! Merge  = union, keep the top M by (work desc, name asc) — a join.
//!
//! # What a bag asserts
//!
//! **Only that these names met the price.** Nothing else. There is no signer,
//! no signature, no timestamp and no tombstone; a pointer is bytes the contract
//! never interprets plus a nonce, and its identity is its name. This is what an
//! inbox, a comment thread, a reaction list or a listing index physically IS: a
//! transient mailbox. The durable thread is the owner's own tree.
//!
//! So `count` and `full` are **claims a stranger can buy**, not facts about the
//! world — anyone willing to mine names can fill a bag to M. A reader that
//! shows "412 replies" is showing what 412 names paid for, and the SDK labels a
//! bag's count as claimed for that reason. Moderation and promotion live in the
//! owner's tree, where they are signed; a DENY needs a signature and belongs to
//! the Set, not here.
//!
//! # The name binds the PARAMS — never the key, never the code
//!
//! A contract's key moves when its code is upgraded, and anyone must be able to
//! re-publish an entry under the new code. So the work preimage contains the
//! params and nothing derived from the key or the wasm: mining for a bag needs
//! no knowledge of which build is hosting it, and an upgrade invalidates no
//! pointer anyone paid for. Validation takes the params and the bytes, so two
//! hosts on different builds cannot disagree about a bag.
//!
//! # Why work, and why the name binds the params
//!
//! A name is `BLAKE3(domain ‖ params hash ‖ len ‖ payload ‖ nonce)` and must
//! have `work_bits` leading zeros. The params hash is in the preimage, so work
//! mined for one bag is worthless in another: a pointer cannot be moved between
//! bags, and the price is paid per bag. Two pointers with the same payload and
//! different nonces are two pointers — **a consumer dedupes by what the
//! payload refers to**, after resolving it, because the contract never
//! interprets a payload and so cannot tell two names for one thing from two
//! things.
//!
//! # Sync, and what a summary gives away
//!
//! A summary is `count ‖ full ‖ lowest kept (work ‖ full 32-byte name) ‖ 16-byte
//! truncations`. Sixteen bytes because "you already have it" is an assertion a
//! stranger can aim at: making a peer miss a chosen pointer costs a 2^128
//! search (2^128/M against any of M targets), where 8 bytes would cost 2^64/M.
//!
//! Two consequences of a summary being a stranger's claim, both bounded:
//! under-reporting ("I am empty") pulls at most M pointers, about 300 KB at
//! M = 1,024 with a 256-byte cap; over-reporting the lowest kept starves only
//! the reporter, which is the usual self-harm bar.
//!
//! At M = 1,024 a summary is ~16 KB, and the host calls `get_state_delta` once
//! per subscriber up to 32 per fan-out (F23). That is the real price of the
//! ceiling, and it is why the ceiling is frozen in the format rather than left
//! to a caller.
//!
//! # What a replay costs
//!
//! A delta whose merge changes nothing still runs `update_state` and then a
//! full `validate_state` (F24c) — measured at 1.5 ms for M = 1,024 pointers at
//! the payload cap, 0.9 ms at a realistic 48-byte payload. Every host that
//! processes the message pays it, so k distinct already-known pointers are k
//! full validations.
//!
//! A byte-identical replay is cheaper, but only on ONE path: the
//! peer-broadcast path drops it before any wasm runs (F24b). Through the client
//! API in local mode an identical payload has been measured running full
//! validation. So "identical bytes are free" is true of gossip between peers
//! and NOT of a client resubmitting — worth knowing before building a retry on
//! the assumption.
//!
//! # Validation stands alone
//!
//! A node that stores a bag fetched from a peer runs `validate_state` and
//! nothing else (F23), so every check lives in the parser: there is no
//! "unchecked read" in this crate. `update_state` parses candidates with the
//! same function a host uses on the whole state.

use freenet_stdlib::prelude::*;

pub mod merge;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod wire;

use merge::{delta, join, summarize};
use wire::{BagState, Params, MAX_M, MAX_PAYLOAD};

/// Largest state: M pointers at the payload cap, plus the header.
///
/// A cost-to-refuse guard, and it earns its place: without it a state claiming
/// a plausible count and carrying megabytes behind it is parsed — every name
/// hashed — before the trailing bytes are noticed at the very end. With it the
/// length decides first and nothing is hashed at all. Measured in
/// `tests::an_oversized_state_is_refused_before_any_name_is_hashed`.
pub const MAX_STATE: usize =
    4 + 2 + (MAX_M as usize) * (2 + MAX_PAYLOAD as usize + wire::NONCE_LEN);

/// Parse and fully check a state against its params.
///
/// The empty byte string is NOT a valid bag, unlike a Block, whose empty state
/// is the legitimate "this block holds nothing yet". A bag's smallest state is
/// `"BG01" ‖ 0` — six bytes saying a bag exists and is empty — so accepting
/// zero bytes as a second spelling of that would give one logical state two
/// hashes, and the merge breaks ties on hashes.
///
/// The only reader. `validate_state` and `update_state` both go through it, so
/// a candidate cannot carry anything a stored state could not.
pub fn read(params: &[u8], state: &[u8]) -> Option<(Params, BagState)> {
    if state.len() > MAX_STATE {
        return None;
    }
    let p = Params::parse(params)?;
    let s = BagState::parse(state, &p)?;
    Some((p, s))
}

pub struct Bag;

#[contract]
impl ContractInterface for Bag {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        // Never RequestRelated: a bag is checkable on its own, and asking for a
        // related contract would make hosting one depend on fetching another.
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
        let Some((p, mut held)) = read(parameters.as_ref(), state.as_ref()) else {
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
                // sender must not stop a good one in the same batch. A garbage
                // or empty candidate therefore cannot displace what is held —
                // the join with nothing is what is held.
                if let Some(c) = BagState::parse(bytes, &p) {
                    held = join(&held, &c, p.m);
                }
            }
        }
        Ok(UpdateModification::valid(State::from(held.encode())))
    }

    fn summarize_state(
        parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        let Some((p, s)) = read(parameters.as_ref(), state.as_ref()) else {
            return Err(ContractError::InvalidState);
        };
        Ok(StateSummary::from(summarize(&s, p.m)))
    }

    fn get_state_delta(
        parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let Some((p, s)) = read(parameters.as_ref(), state.as_ref()) else {
            return Err(ContractError::InvalidState);
        };
        // An unreadable summary — malformed, or longer than a bag of this size
        // could ever produce — is treated as an empty peer: the whole state is
        // at most M pointers, so the cost is bounded, and refusing outright
        // would let a malformed summary stop a sync.
        let d = delta(&s, summary.as_ref(), p.m).unwrap_or_else(|| s.clone());
        Ok(StateDelta::from(d.encode()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merge::{collect, delta, join, summarize};
    use crate::testing::{many, params};
    use crate::wire::{BagState, Held, HASHED, HASH_LEN};
    use std::sync::atomic::Ordering;

    /// The length check refuses a huge state before a single name is hashed.
    ///
    /// Without it the parser reads `count` pointers — hashing each — and only
    /// then notices the megabytes trailing behind them. The check looks
    /// redundant because `parse` refuses the same input; what it changes is the
    /// PRICE of refusing, which no correctness test can see.
    #[test]
    fn an_oversized_state_is_refused_before_any_name_is_hashed() {
        let p = params(0, 64);
        let s = collect(many(&p, 64, 5), &p);
        let good = s.encode();
        let ps = p.encode();

        HASHED.store(0, Ordering::Relaxed);
        assert!(read(&ps, &good).is_some());
        let honest = HASHED.load(Ordering::Relaxed);
        assert_eq!(honest, 64, "an honest read hashes one name per pointer");

        // A valid bag with megabytes stapled to the end.
        let mut hostile = good.clone();
        hostile.extend(std::iter::repeat_n(0u8, MAX_STATE + 1_000_000));
        assert!(hostile.len() > MAX_STATE);

        HASHED.store(0, Ordering::Relaxed);
        assert!(
            read(&ps, &hostile).is_none(),
            "trailing bytes must be refused"
        );
        assert_eq!(
            HASHED.load(Ordering::Relaxed),
            0,
            "{} B of padding cost {} names hashed; the length check should have \
             decided first",
            hostile.len(),
            HASHED.load(Ordering::Relaxed)
        );

        // And the control: with the length check bypassed, the same input costs
        // a full parse. This is what the guard is worth.
        HASHED.store(0, Ordering::Relaxed);
        let p2 = Params::parse(&ps).expect("params");
        assert!(BagState::parse(&hostile, &p2).is_none());
        assert_eq!(
            HASHED.load(Ordering::Relaxed),
            honest,
            "without the length check the parser hashes every name before \
             noticing the padding"
        );
    }

    /// A summary longer than a bag of this size could produce is refused
    /// BEFORE it is copied or sorted.
    ///
    /// A summary arrives from a stranger and `get_state_delta` sorts it, on
    /// every host that serves the bag — so its length is work an attacker
    /// chooses. The bound is `m`, which is in the params and therefore the same
    /// for both sides. Asserted on truncations copied, because the defect here
    /// is a price and not an answer.
    #[test]
    fn an_oversized_summary_is_refused_before_it_is_sorted() {
        use crate::merge::SUMMARY_ENTRIES;
        let p = params(0, 64);
        let mine = collect(many(&p, 64, 23), &p);
        let honest = summarize(&mine, p.m);

        SUMMARY_ENTRIES.store(0, Ordering::Relaxed);
        assert!(delta(&mine, &honest, p.m).is_some());
        assert_eq!(
            SUMMARY_ENTRIES.load(Ordering::Relaxed),
            64,
            "an honest summary copies one truncation per pointer"
        );

        // A megabyte of truncations, with the count field AGREEING — otherwise
        // the count check refuses it first and the length bound is never
        // reached, which is how a mutant on the bound survived a whole suite.
        let entries = 65_535usize;
        let mut hostile = honest[..4 + HASH_LEN].to_vec();
        hostile[0..2].copy_from_slice(&(entries as u16).to_le_bytes());
        for i in 0..entries as u32 {
            let mut t = [0u8; 16];
            t[..4].copy_from_slice(&i.to_le_bytes());
            hostile.extend_from_slice(&t);
        }
        assert!(hostile.len() > 1_000_000, "{} B", hostile.len());
        SUMMARY_ENTRIES.store(0, Ordering::Relaxed);
        assert!(
            delta(&mine, &hostile, p.m).is_none(),
            "a summary of more than m truncations is not a summary of this bag"
        );
        assert_eq!(
            SUMMARY_ENTRIES.load(Ordering::Relaxed),
            0,
            "{} B of summary was copied before being refused",
            hostile.len()
        );

        // The count field must agree with what follows: one spelling.
        let mut lying = honest.clone();
        lying[0] = 5;
        assert!(
            delta(&mine, &lying, p.m).is_none(),
            "a lying count was accepted"
        );

        // And the honest one still works after all that.
        assert!(delta(&mine, &honest, p.m).is_some());
    }

    /// A peer that is NOT full gets everything it lacks — the sender does not
    /// try to work out which of them will survive the peer's own merge.
    ///
    /// Its own test: this rule was being killed only incidentally, by a test
    /// about 8-byte collisions, which is not evidence about the rule.
    #[test]
    fn a_peer_with_room_is_sent_everything_it_lacks() {
        let p = params(0, 32);
        let pool = many(&p, 40, 17);
        let mine = collect(pool.clone(), &p);
        assert_eq!(mine.held.len(), 32, "the sender is full");

        for have in [0usize, 1, 5, 20, 31] {
            let theirs = BagState {
                held: mine.held[..have].to_vec(),
            };
            assert!((theirs.held.len() as u16) < p.m, "the peer must have room");
            let d = delta(&mine, &summarize(&theirs, p.m), p.m).expect("a summary");

            // Everything the sender holds and the peer lacks — no filtering by
            // rank, because a peer with room can use any of it.
            let want: Vec<[u8; 32]> = mine
                .held
                .iter()
                .filter(|h| !theirs.held.iter().any(|x| x.name == h.name))
                .map(|h| h.name)
                .collect();
            let got: Vec<[u8; 32]> = d.held.iter().map(|h| h.name).collect();
            assert_eq!(got, want, "peer holding {have} of {}", p.m);
            assert_eq!(d.held.len(), 32 - have);

            // One round is enough.
            assert_eq!(join(&theirs, &d, p.m), mine);
        }

        // The lowest-ranked pointer is sent too, even though a FULL peer would
        // have refused it — that is the whole difference the flag makes.
        let empty = BagState::default();
        let d = delta(&mine, &summarize(&empty, p.m), p.m).expect("a summary");
        let lowest = mine.held.last().expect("full");
        assert!(
            d.held.iter().any(|h| h.name == lowest.name),
            "a peer with room was not sent the cheapest pointer"
        );
        let _ = Held::of(pool[0].clone(), &p.hash());
    }
}
