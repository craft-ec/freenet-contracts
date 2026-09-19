//! `PACK`: a commit's blocks in one PUT.
//!
//! A relay forwards the full contract container — the wasm included — at every
//! hop, so a 4 KiB tree node costs 4 KiB plus about 118 KiB per hop and the
//! number of PUTs on the commit path is the lever. A pack is one PUT carrying
//! several blocks, unpacked off the commit path by anyone who holds it.
//!
//! **A pack is not a layout.** No pointer anywhere names `(pack, index)`. Root
//! hashes, dedup, proofs and parity are untouched: a pack is a transport, and
//! the blocks inside it are the same blocks with the same ids.
//!
//! ```text
//! body = "PK01" ‖ count:u16 ‖ member*        member = kind:u8 ‖ len:u32 ‖ bytes
//! ```
//!
//! Members are strictly ascending **by their own block id**, which states "a
//! set of blocks" directly: the id IS a block's identity, so ordering by it
//! forbids duplicates and gives one encoding per set. Two writers packing the
//! same commit therefore produce the same pack, with the same id.
//!
//! **A member is valid exactly when it would be valid as its own Block.** That
//! is not a restatement of the rules — it is a call to the same
//! [`crate::well_formed`] the contract runs on a standalone block, so a host
//! that unpacks can never produce a block the Block contract would refuse, and
//! a later change to what a `TREE_NODE` may be (the parity rule) reaches packs
//! without touching this format. What that does NOT cover is which kinds may be
//! members: adding one is a format change here.

use crate::kind;

/// Magic for the pack body.
pub const MAGIC: &[u8; 4] = b"PK01";

/// The ceiling on a pack's body. A ceiling, not a target: the engine packs to
/// ≤ 256 KiB by default until PUT latency above that is measured, and that is
/// policy which can move without an epoch. This is the format's limit.
pub const MAX_PACK: usize = 1024 * 1024;

/// The smallest a member can be: a kind byte, a length, and an empty body.
/// Every early refusal is measured against this.
pub const MIN_MEMBER: usize = 1 + 4;

const HEADER: usize = 4 + 2;

/// May this kind ride in a pack?
///
/// `RAW` and `TREE_NODE` only — no pack in a pack, and nothing whose format has
/// not landed. Checked from the kind BYTE, before the member is hashed or
/// parsed, because it is the cheapest thing that can refuse a whole pack.
fn packable(k: u8) -> bool {
    k == kind::RAW || k == kind::TREE_NODE
}

/// Is `body` a well-formed pack?
///
/// The order of the checks is the point. Everything decidable from lengths and
/// kind bytes runs first, so a hostile pack is refused for the price of reading
/// its header — a stranger can send a megabyte and must not be able to buy a
/// megabyte of hashing with it. Only then does each member cost a BLAKE3 for
/// its id and a well-formedness pass, which an honest pack pays anyway.
pub fn well_formed(body: &[u8]) -> bool {
    let Some((head, mut rest)) = body.split_at_checked(HEADER) else {
        return false;
    };
    if &head[..4] != MAGIC {
        return false;
    }
    let count = u16::from_le_bytes([head[4], head[5]]) as usize;
    // A pack of nothing is not a pack, and the empty body has one spelling.
    if count == 0 {
        return false;
    }
    // The declared count must fit in what follows, at the smallest a member can
    // be. This is what stops `count = 65535` buying 65,535 iterations of
    // anything: it is decided from two lengths, before a single byte is hashed.
    if count
        .checked_mul(MIN_MEMBER)
        .is_none_or(|need| need > rest.len())
    {
        return false;
    }

    let mut prev: Option<[u8; 32]> = None;
    for _ in 0..count {
        let Some((h, tail)) = rest.split_at_checked(MIN_MEMBER) else {
            return false;
        };
        let k = h[0];
        // Refused from the kind byte alone: an unknown or unpackable kind
        // costs nothing, however large the pack claiming it is.
        if !packable(k) {
            return false;
        }
        let len = u32::from_le_bytes([h[1], h[2], h[3], h[4]]) as usize;
        // A member is a Block, so it is bounded by what a Block of that kind
        // may be — checked against the length FIELD before anything is read.
        if len > crate::max_body(k) {
            return false;
        }
        let Some((bytes, tail)) = tail.split_at_checked(len) else {
            return false;
        };
        rest = tail;

        // From here the member costs real work, and an honest pack pays the
        // same. The id comes first because it is one hash, where a body check
        // can be a full node parse.
        #[cfg(any(test, feature = "testing"))]
        crate::work::tick_id();
        let id = freenet_prolly::block_id(k, bytes);
        // Strictly ascending: no duplicates, and one encoding per set.
        if prev.is_some_and(|p| p >= id) {
            return false;
        }
        prev = Some(id);

        #[cfg(any(test, feature = "testing"))]
        crate::work::tick_body();
        // THE SAME check the contract runs on a standalone block. Not a copy of
        // its rules: a call to it.
        if !crate::well_formed(k, bytes) {
            return false;
        }
    }
    // The lengths must tile the body exactly; trailing bytes are a second
    // encoding of the same set.
    rest.is_empty()
}

/// Build a pack body from members, ordering them as the format requires.
///
/// A pack is a SET, so the same block offered twice is one member: sorting
/// without de-duplicating would hand the caller bytes the contract refuses.
/// De-duplication is by block id, which is what the order is over and what
/// "the same block" means here — two members with the same id ARE the same
/// bytes.
///
/// It does not otherwise check the members: `well_formed` decides, and a
/// builder that refused early would hide the cases the tests exist to reach.
pub fn build(members: &[(u8, Vec<u8>)]) -> Result<Vec<u8>, BuildError> {
    let mut ordered: Vec<&(u8, Vec<u8>)> = members.iter().collect();
    ordered.sort_by_key(|(k, b)| freenet_prolly::block_id(*k, b));
    ordered.dedup_by_key(|(k, b)| freenet_prolly::block_id(*k, b));
    if ordered.is_empty() {
        return Err(BuildError::Empty);
    }
    // `count` is a u16 on the wire, so more members than that cannot be
    // expressed — and casting would have written a small count in front of a
    // long body, which the contract refuses for a reason the caller could not
    // see from its own input.
    if ordered.len() > u16::MAX as usize {
        return Err(BuildError::TooManyMembers(ordered.len()));
    }
    let mut out = Vec::from(&MAGIC[..]);
    out.extend_from_slice(&(ordered.len() as u16).to_le_bytes());
    for (k, b) in ordered {
        out.push(*k);
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }
    // Checked at the end rather than accumulated, because the members are not
    // known to be within their own kinds' caps either; `well_formed` decides
    // that, and this only promises that what comes back is a pack the contract
    // could accept on size.
    if out.len() > MAX_PACK {
        return Err(BuildError::TooLarge(out.len()));
    }
    Ok(out)
}

/// Why a set of members cannot be made into a pack.
///
/// The engine calls `build`, so the ways it can fail are part of its contract
/// with the engine rather than something a caller discovers from a refusal
/// three layers away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// A pack of nothing is not a pack.
    Empty,
    /// More members than the u16 count can express.
    TooManyMembers(usize),
    /// The body would exceed [`MAX_PACK`].
    TooLarge(usize),
}
