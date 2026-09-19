//! Encodings, and the checks that make each one canonical.
//!
//! Every integer is little-endian. Every structure here has exactly one valid
//! encoding: two spellings of one logical state would hash two ways, and a
//! merge whose ties break on hashes would stop being a function of the state.

use blake3::Hasher;
use ed25519_dalek::{Signature, VerifyingKey};

pub const MAGIC: &[u8; 4] = b"ST01";
/// Domain separator for the signed message.
pub const SIG_DOMAIN: &[u8; 8] = b"ST01-sig";
/// Domain separator for a slot's name — what ranks it.
pub const SLOT_DOMAIN: &[u8; 9] = b"ST01-slot";
/// Domain separator for the per-decision stamp — what rate-limits updates.
pub const STAMP_DOMAIN: &[u8; 10] = b"ST01-stamp";
/// Domain separator for a capability.
pub const CAP_DOMAIN: &[u8; 8] = b"ST01-cap";
/// Domain separator for a denial.
pub const DENY_DOMAIN: &[u8; 9] = b"ST01-deny";

/// The frozen ceiling on items. Not a judgement call: the host re-validates the
/// WHOLE state after every accepted update (F23) and every item carries a
/// signature, so an accepted item costs O(M) verifications and filling a set
/// costs O(M²). At 64 that is 4,096 verifications per fill; volume comes from
/// sharding, with the shards listed in the owner's own tree.
pub const MAX_M: u16 = 64;
/// The frozen ceiling on denials. A denial is for a misbehaving cap-holder, and
/// an owner issued at most `M` slots' worth of caps in a bucket, so a list
/// longer than the set it protects would be a strange shape.
pub const MAX_DENY: u16 = 64;
pub const MAX_PAYLOAD: u16 = 256;
pub const MAX_ITEM_KEY: usize = 64;
pub const MAX_LABEL: usize = 64;
pub const KEY_LEN: usize = 32;
pub const SIG_LEN: usize = 64;
pub const HASH_LEN: usize = 32;
pub const NONCE_LEN: usize = 8;
/// Bytes of a decision hash a summary carries. 16, not 8: "you already have it"
/// is an assertion a stranger can aim at, and at 8 bytes aiming it at one of M
/// held decisions costs ≈ 2^64/M hashes.
pub const TRUNC: usize = 16;

/// Signature verifications performed.
///
/// Verification is the expensive thing in this contract and anyone can ask a
/// host for it: the host re-validates the WHOLE state after every accepted
/// update (F23), and a no-op update still validates (F24). So what a candidate
/// COSTS is a property in its own right, separate from whether it is accepted,
/// and a test that only checks verdicts cannot see it. Counted here so the cost
/// can be asserted rather than argued.
/// **Thread-local, deliberately.** The test harness runs the tests in one
/// binary on many threads, so a process-global counter reports whatever every
/// other test happened to be doing at the same moment: a cost assertion over
/// it is a race that usually passes. Per-thread, each test sees its own work
/// and nobody else's.
#[cfg(any(test, feature = "testing"))]
pub mod verifications {
    use core::cell::Cell;
    thread_local! { static N: Cell<usize> = const { Cell::new(0) }; }
    pub fn reset() {
        N.with(|n| n.set(0));
    }
    pub fn count() -> usize {
        N.with(|n| n.get())
    }
    pub(crate) fn tick() {
        N.with(|n| n.set(n.get() + 1));
    }
}

/// One Ed25519 check, counted. Strict: `verify_strict` rejects the small-order
/// and non-canonical cases a plain `verify` accepts, and every host must agree
/// on validity or they disagree about what the state IS.
fn verify_one(key: &VerifyingKey, msg: &[u8], sig: &[u8; SIG_LEN]) -> bool {
    #[cfg(any(test, feature = "testing"))]
    verifications::tick();
    key.verify_strict(msg, &Signature::from_bytes(sig)).is_ok()
}

/// Field modulus p = 2²⁵⁵ − 19, little-endian.
const P_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Is this the canonical encoding of a point, i.e. is y < p? `VerifyingKey`
/// accepts a handful of y ≥ p encodings, which decompress to points that also
/// have a canonical spelling — two names for one signer.
fn key_is_canonical(b: &[u8; KEY_LEN]) -> bool {
    let mut y = *b;
    y[31] &= 0x7f;
    for i in (0..KEY_LEN).rev() {
        match y[i].cmp(&P_LE[i]) {
            core::cmp::Ordering::Less => return true,
            core::cmp::Ordering::Greater => return false,
            core::cmp::Ordering::Equal => {}
        }
    }
    false
}

pub(crate) fn usable_key(b: &[u8]) -> Option<VerifyingKey> {
    let b: [u8; KEY_LEN] = b.try_into().ok()?;
    if !key_is_canonical(&b) {
        return None;
    }
    let k = VerifyingKey::from_bytes(&b).ok()?;
    (!k.is_weak()).then_some(k)
}

/// Who may write. There is no open tier: an open many-writer collection is a
/// Bag, whose items are unsigned pointers and whose price is work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admission {
    /// Only the owner writes.
    OwnerOnly,
    /// The owner, and anyone holding a capability it signed.
    Cap,
}

/// The only `mode` this build accepts.
///
/// The byte is RESERVED, not decorative: a later epoch wants a Set whose rank
/// is `BLAKE3("dir-rank" ‖ key)` rather than slot work, with work demoted to an
/// admission threshold, so that an implicit trie of Sets can act as a directory
/// with no writer (#19). Reserving it now makes that a parameterisation of this
/// contract instead of a fifth contract kind. Anything other than `0` is
/// refused at parse, so a state written for a mode this build does not
/// implement can never be mistaken for one it does.
pub const MODE_CURRENT: u8 = 0;

/// What a set is, fixed in its contract key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub owner: VerifyingKey,
    pub admission: Admission,
    /// Slots kept per tier.
    pub m: u16,
    /// Slots one signer may hold.
    pub quota: u16,
    /// Leading zero bits a decision's stamp must have: the price of an UPDATE,
    /// paid per version rather than per slot.
    pub decision_bits: u8,
    pub payload_cap: u16,
    /// Which shard this is. A capability names a RANGE of these.
    pub bucket: u32,
    pub label: Vec<u8>,
}

const PARAMS_FIXED: usize = 4 + 1 + KEY_LEN + 1 + 2 + 2 + 1 + 2 + 4;

impl Params {
    pub fn parse(b: &[u8]) -> Option<Params> {
        let (head, label) = b.split_at_checked(PARAMS_FIXED)?;
        if &head[..4] != MAGIC || label.len() > MAX_LABEL {
            return None;
        }
        // Reserved: one accepted value, so there is nothing to carry in the
        // struct and nothing two encodings could disagree about.
        if head[4] != MODE_CURRENT {
            return None;
        }
        let owner = usable_key(&head[5..5 + KEY_LEN])?;
        let at = 5 + KEY_LEN;
        let admission = match head[at] {
            0 => Admission::OwnerOnly,
            1 => Admission::Cap,
            _ => return None,
        };
        let p = Params {
            owner,
            admission,
            m: u16::from_le_bytes([head[at + 1], head[at + 2]]),
            quota: u16::from_le_bytes([head[at + 3], head[at + 4]]),
            decision_bits: head[at + 5],
            payload_cap: u16::from_le_bytes([head[at + 6], head[at + 7]]),
            bucket: u32::from_le_bytes([head[at + 8], head[at + 9], head[at + 10], head[at + 11]]),
            label: label.to_vec(),
        };
        // The ceilings are part of the format, not a caller's judgement.
        (p.m >= 1
            && p.m <= MAX_M
            && p.quota >= 1
            && p.quota <= p.m
            && p.payload_cap >= 1
            && p.payload_cap <= MAX_PAYLOAD
            // 64 bits of stamp is already unmineable; more would be a set
            // nobody can update.
            && p.decision_bits <= 64)
            .then_some(p)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::from(&MAGIC[..]);
        out.push(MODE_CURRENT);
        out.extend_from_slice(self.owner.as_bytes());
        out.push(match self.admission {
            Admission::OwnerOnly => 0,
            Admission::Cap => 1,
        });
        out.extend_from_slice(&self.m.to_le_bytes());
        out.extend_from_slice(&self.quota.to_le_bytes());
        out.push(self.decision_bits);
        out.extend_from_slice(&self.payload_cap.to_le_bytes());
        out.extend_from_slice(&self.bucket.to_le_bytes());
        out.extend_from_slice(&self.label);
        out
    }

    /// What every signed message binds, so nothing replays into another set or
    /// another bucket.
    ///
    /// The params and nothing else — not the contract key, not the code hash. A
    /// contract's key moves when its code is upgraded and every item must stay
    /// valid and re-publishable, so nothing here may know which build is
    /// hosting the set.
    pub fn hash(&self) -> [u8; HASH_LEN] {
        *blake3::hash(&self.encode()).as_bytes()
    }

    /// What a CAPABILITY binds: the params with the bucket field zeroed.
    ///
    /// A cap names a range of buckets, so it cannot bind the bucket it was
    /// written in — but it must still bind everything else, or a cap for label
    /// `L` would carry into a differently-configured set with the same label.
    pub fn hash_sans_bucket(&self) -> [u8; HASH_LEN] {
        let mut b = self.encode();
        let at = PARAMS_FIXED - 4;
        b[at..at + 4].copy_from_slice(&[0; 4]);
        *blake3::hash(&b).as_bytes()
    }
}

/// An owner's grant: this key may write these buckets of this set.
///
/// Carried by every item its holder writes, because a node that stores a set
/// fetched from a peer runs validation and nothing else — the grant has to be
/// checkable from the state alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cap {
    pub grantee: VerifyingKey,
    pub params_sans_bucket: [u8; HASH_LEN],
    pub from: u32,
    pub to: u32,
    pub sig: [u8; SIG_LEN],
}

pub const CAP_LEN: usize = KEY_LEN + HASH_LEN + 4 + 4 + SIG_LEN;

impl Cap {
    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = Vec::from(&CAP_DOMAIN[..]);
        out.extend_from_slice(self.grantee.as_bytes());
        out.extend_from_slice(&self.params_sans_bucket);
        out.extend_from_slice(&self.from.to_le_bytes());
        out.extend_from_slice(&self.to.to_le_bytes());
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(CAP_LEN);
        out.extend_from_slice(self.grantee.as_bytes());
        out.extend_from_slice(&self.params_sans_bucket);
        out.extend_from_slice(&self.from.to_le_bytes());
        out.extend_from_slice(&self.to.to_le_bytes());
        out.extend_from_slice(&self.sig);
        out
    }

    fn parse(b: &[u8]) -> Option<Cap> {
        if b.len() != CAP_LEN {
            return None;
        }
        Some(Cap {
            grantee: usable_key(&b[..KEY_LEN])?,
            params_sans_bucket: b[KEY_LEN..KEY_LEN + HASH_LEN].try_into().ok()?,
            from: u32::from_le_bytes(
                b[KEY_LEN + HASH_LEN..KEY_LEN + HASH_LEN + 4]
                    .try_into()
                    .ok()?,
            ),
            to: u32::from_le_bytes(
                b[KEY_LEN + HASH_LEN + 4..KEY_LEN + HASH_LEN + 8]
                    .try_into()
                    .ok()?,
            ),
            sig: b[CAP_LEN - SIG_LEN..].try_into().ok()?,
        })
    }

    /// Does this grant let `signer` write this bucket of this set?
    ///
    /// A bucket RANGE bounds WHERE a grantee may write, not when: the contract
    /// has no clock (F13), and calling it expiry would be a lie a reader might
    /// rely on.
    pub fn admits(&self, signer: &VerifyingKey, p: &Params) -> bool {
        self.grantee == *signer
            && self.params_sans_bucket == p.hash_sans_bucket()
            && self.from <= p.bucket
            && p.bucket <= self.to
            && verify_one(&p.owner, &self.signed_bytes(), &self.sig)
    }
}

/// What a writer decided about a slot: when, and what it holds.
///
/// The DECISION is what is ordered and what syncs. A signature, a capability
/// and a stamp are witnesses of a decision — another witness of the same
/// decision changes nothing, which is why the summary hashes decisions rather
/// than encodings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    pub ts: u64,
    pub tombstone: bool,
    pub sealed: bool,
    pub payload_hash: [u8; HASH_LEN],
}

impl Decision {
    fn flags(&self) -> u8 {
        u8::from(self.tombstone) | (u8::from(self.sealed) << 1)
    }

    fn write(&self, h: &mut Hasher) {
        h.update(&self.ts.to_le_bytes());
        h.update(&[self.flags()]);
        h.update(&self.payload_hash);
    }

    /// **Sealed first, then newer, then the lower payload hash.**
    ///
    /// `ts` is the WRITER's claim — the contract has no clock — so this orders
    /// one writer's own versions of its own slot and nothing else. A writer
    /// that lies about its own `ts` reorders only itself.
    ///
    /// Sealing is ONE-WAY: no decision this order can express unseals a slot,
    /// because a sealed decision outranks every unsealed one whatever its `ts`.
    ///
    /// `sealed` leads because it has to MEAN something. A flag that is parsed,
    /// signed and hashed but decides nothing is a claim the contract invites a
    /// reader to rely on and never enforces. Sealed means exactly this: **no
    /// unsealed decision ever supersedes it, whatever `ts` it claims.** It does
    /// not mean immutable — a later SEALED decision by the same writer still
    /// wins on `ts`, so the promise is "no ordinary edit", not "no edit". That
    /// is the strongest reading that keeps the order total, which is what makes
    /// the per-slot max a join.
    ///
    /// A tombstone is an ordinary decision here, so deleting a sealed slot
    /// takes a sealed tombstone. That follows from sealing meaning anything at
    /// all, and it is the writer's own slot either way.
    /// **Total on decisions**, which the laws depend on: every field of a
    /// `Decision` appears here, so equal rank means equal decision. It did not
    /// always — `tombstone` was missing, and since a tombstone carries an empty
    /// payload and a live item may carry one too, a delete and a live-empty
    /// item at one `ts` had equal rank and different meanings. The incumbent
    /// wins a tie, so the two orders of one merge disagreed about whether the
    /// slot was deleted, for ever, with summaries that differed and therefore
    /// re-sent on every exchange without either side changing.
    ///
    /// A delete beats a live item at the same `ts`: a slot deleted stays
    /// deleted, which is the same reason a tombstone keeps its slot.
    pub fn rank(&self) -> (bool, u64, bool, core::cmp::Reverse<[u8; HASH_LEN]>) {
        (
            self.sealed,
            self.ts,
            self.tombstone,
            core::cmp::Reverse(self.payload_hash),
        )
    }

    /// What the summary carries, and what the stamp is bought for.
    pub fn hash(&self, ph: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
        let mut h = Hasher::new();
        h.update(ph);
        self.write(&mut h);
        *h.finalize().as_bytes()
    }
}

/// One item: a decision about a slot, with the witnesses that admit it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Item {
    pub signer: VerifyingKey,
    /// `base ‖ nonce`. Two nonces for one base are two slots.
    pub item_key: Vec<u8>,
    pub ts: u64,
    pub tombstone: bool,
    pub sealed: bool,
    /// Empty for a tombstone. The contract never interprets it.
    pub payload: Vec<u8>,
    pub cap: Option<Cap>,
    pub stamp_nonce: [u8; NONCE_LEN],
    pub sig: [u8; SIG_LEN],
}

impl Item {
    pub fn decision(&self) -> Decision {
        Decision {
            ts: self.ts,
            tombstone: self.tombstone,
            sealed: self.sealed,
            payload_hash: *blake3::hash(&self.payload).as_bytes(),
        }
    }

    /// The slot this item is about: `BLAKE3(domain ‖ params ‖ signer ‖ key)`.
    ///
    /// The name is the same for every version of the slot, so a slot's rank
    /// cannot be improved by writing to it and cannot be changed by anyone but
    /// the signer choosing its key in the first place.
    pub fn slot_hash(&self, ph: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
        let mut h = Hasher::new();
        h.update(SLOT_DOMAIN);
        h.update(ph);
        h.update(self.signer.as_bytes());
        h.update(&(self.item_key.len() as u16).to_le_bytes());
        h.update(&self.item_key);
        *h.finalize().as_bytes()
    }

    /// Public so a fixture can sign one; the contract only ever verifies.
    pub fn signed_bytes(&self, ph: &[u8; HASH_LEN]) -> Vec<u8> {
        let mut out = Vec::from(&SIG_DOMAIN[..]);
        out.extend_from_slice(ph);
        out.extend_from_slice(self.signer.as_bytes());
        out.extend_from_slice(&(self.item_key.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.item_key);
        let d = self.decision();
        out.extend_from_slice(&d.ts.to_le_bytes());
        out.push(d.flags());
        out.extend_from_slice(&d.payload_hash);
        out.extend_from_slice(&self.stamp_nonce);
        out
    }

    /// Leading zero bits of `BLAKE3(domain ‖ params ‖ decision ‖ nonce)`: what
    /// a writer paid for THIS version.
    pub fn stamp_work(&self, ph: &[u8; HASH_LEN]) -> u32 {
        let mut h = Hasher::new();
        h.update(STAMP_DOMAIN);
        h.update(ph);
        self.decision().write(&mut h);
        h.update(&self.stamp_nonce);
        leading_zeros(h.finalize().as_bytes())
    }

    /// Everything decidable without an Ed25519 check: shape, caps, and the
    /// proof-of-work stamp.
    ///
    /// Split from the signature checks because signatures are the expensive
    /// part and the two have different audiences. A host merging candidates
    /// needs this on every item it parses; it needs the signatures only on an
    /// item that could actually enter the state.
    pub fn well_formed(&self, p: &Params, ph: &[u8; HASH_LEN]) -> bool {
        if self.item_key.is_empty() || self.item_key.len() > MAX_ITEM_KEY {
            return false;
        }
        if self.payload.len() > p.payload_cap as usize {
            return false;
        }
        // A tombstone carries nothing: one encoding per decision.
        if self.tombstone && !self.payload.is_empty() {
            return false;
        }
        if self.stamp_work(ph) < p.decision_bits as u32 {
            return false;
        }
        // The owner needs no grant, and carrying one would be a second
        // encoding of the same item; a non-owner without one is not admitted
        // at all. Neither question needs a signature.
        match (&self.cap, self.signer == p.owner) {
            (Some(_), true) => return false,
            (None, true) => {}
            (None, false) => return false,
            (Some(_), false) => {
                if p.admission == Admission::OwnerOnly {
                    return false;
                }
            }
        }
        true
    }

    /// `well_formed`, and then every signature: the grant's and the item's.
    ///
    /// This is what `validate_state` runs, on every item, every time. A node
    /// that stores a set fetched from a peer runs validation and nothing else,
    /// so a Set asserts exactly one thing — every item in it was signed by its
    /// slot's key — and that assertion has to be decided here or not at all.
    pub fn verify(&self, p: &Params, ph: &[u8; HASH_LEN]) -> bool {
        if !self.well_formed(p, ph) {
            return false;
        }
        if let Some(c) = &self.cap {
            if !c.admits(&self.signer, p) {
                return false;
            }
        }
        verify_one(&self.signer, &self.signed_bytes(ph), &self.sig)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(self.signer.as_bytes());
        out.push(self.item_key.len() as u8);
        out.extend_from_slice(&self.item_key);
        out.extend_from_slice(&self.ts.to_le_bytes());
        out.push(self.decision().flags() | (u8::from(self.cap.is_some()) << 2));
        out.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.payload);
        if let Some(c) = &self.cap {
            out.extend_from_slice(&c.encode());
        }
        out.extend_from_slice(&self.stamp_nonce);
        out.extend_from_slice(&self.sig);
        out
    }

    fn parse(b: &[u8]) -> Option<(Item, &[u8])> {
        let (signer, rest) = b.split_at_checked(KEY_LEN)?;
        let signer = usable_key(signer)?;
        let (&klen, rest) = rest.split_first()?;
        if klen == 0 || klen as usize > MAX_ITEM_KEY {
            return None;
        }
        let (item_key, rest) = rest.split_at_checked(klen as usize)?;
        let (ts, rest) = rest.split_at_checked(8)?;
        let (&flags, rest) = rest.split_first()?;
        // Only the three defined bits: an unknown bit is a second spelling.
        if flags & !0b111 != 0 {
            return None;
        }
        let (plen, rest) = rest.split_at_checked(2)?;
        let plen = u16::from_le_bytes([plen[0], plen[1]]);
        let (payload, rest) = rest.split_at_checked(plen as usize)?;
        let (cap, rest) = if flags & 0b100 != 0 {
            let (c, rest) = rest.split_at_checked(CAP_LEN)?;
            (Some(Cap::parse(c)?), rest)
        } else {
            (None, rest)
        };
        let (nonce, rest) = rest.split_at_checked(NONCE_LEN)?;
        let (sig, rest) = rest.split_at_checked(SIG_LEN)?;
        Some((
            Item {
                signer,
                item_key: item_key.to_vec(),
                ts: u64::from_le_bytes(ts.try_into().ok()?),
                tombstone: flags & 1 != 0,
                sealed: flags & 0b10 != 0,
                payload: payload.to_vec(),
                cap,
                stamp_nonce: nonce.try_into().ok()?,
                sig: sig.try_into().ok()?,
            },
            rest,
        ))
    }
}

/// Leading zero bits of a hash — the work that bought it.
pub fn leading_zeros(h: &[u8; HASH_LEN]) -> u32 {
    let mut n = 0;
    for b in h {
        n += b.leading_zeros();
        if *b != 0 {
            break;
        }
    }
    n
}

/// Which tier a signer writes in. Capacity is per tier, so a flood in one
/// cannot touch the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Tier {
    Owner = 0,
    CapHolder = 1,
}

/// An owner's refusal of a signer, signed. Grow-only within a bucket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Deny {
    pub signer: [u8; KEY_LEN],
    pub sig: [u8; SIG_LEN],
}

pub const DENY_LEN: usize = KEY_LEN + SIG_LEN;

impl Deny {
    fn signed_bytes(&self, ph: &[u8; HASH_LEN]) -> Vec<u8> {
        let mut out = Vec::from(&DENY_DOMAIN[..]);
        out.extend_from_slice(ph);
        out.extend_from_slice(&self.signer);
        out
    }

    /// The denial is identified by WHO is denied; the signature is a witness,
    /// so re-signing the same denial changes nothing.
    pub fn verify(&self, p: &Params, ph: &[u8; HASH_LEN]) -> bool {
        verify_one(&p.owner, &self.signed_bytes(ph), &self.sig)
    }
}

/// One item per slot — the surviving decision — plus what the contract derived.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    pub item: Item,
    pub slot: [u8; HASH_LEN],
    pub tier: Tier,
}

impl Held {
    pub fn of(item: Item, p: &Params, ph: &[u8; HASH_LEN]) -> Held {
        let slot = item.slot_hash(ph);
        let tier = if item.signer == p.owner {
            Tier::Owner
        } else {
            Tier::CapHolder
        };
        Held { item, slot, tier }
    }

    /// The order a set keeps: **tier, then slot work descending, then slot hash
    /// ascending**.
    ///
    /// Rank belongs to the SLOT and never to a version, which is what makes the
    /// merge associative: a slot in the global top M is in the top M of every
    /// subset containing it, whatever versions anyone holds.
    ///
    /// The work term is written out because it says what the order is FOR, but
    /// it decides nothing on its own: work IS the leading zeros of the slot
    /// hash, so a hash with more of them is numerically smaller and the two
    /// comparisons cannot disagree. Pinned by a test.
    pub fn rank(&self) -> (Tier, core::cmp::Reverse<u32>, [u8; HASH_LEN]) {
        (
            self.tier,
            core::cmp::Reverse(leading_zeros(&self.slot)),
            self.slot,
        )
    }
}

/// What a state SAYS, with every witness dropped: the denied keys, and one
/// decision per held slot in slot order.
pub type Facts = (Vec<[u8; KEY_LEN]>, Vec<([u8; HASH_LEN], Decision)>);

/// `"ST01" ‖ deny count ‖ deny* ‖ item count ‖ item*`.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct SetState {
    /// Sorted by key, no repeats.
    pub deny: Vec<Deny>,
    /// In rank order.
    pub held: Vec<Held>,
}

impl SetState {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::from(&MAGIC[..]);
        out.extend_from_slice(&(self.deny.len() as u16).to_le_bytes());
        for d in &self.deny {
            out.extend_from_slice(&d.signer);
            out.extend_from_slice(&d.sig);
        }
        out.extend_from_slice(&(self.held.len() as u16).to_le_bytes());
        for h in &self.held {
            out.extend_from_slice(&h.item.encode());
        }
        out
    }

    /// Parse AND verify every signature. This is what `validate_state` does.
    pub fn parse(b: &[u8], p: &Params) -> Option<SetState> {
        let s = Self::parse_unverified(b, p)?;
        let ph = p.hash();
        for d in &s.deny {
            if !d.verify(p, &ph) {
                return None;
            }
        }
        for h in &s.held {
            if !h.item.verify(p, &ph) {
                return None;
            }
        }
        Some(s)
    }

    /// Structure, canonical order and the limits — no Ed25519.
    ///
    /// For the state a host ALREADY HOLDS: its signatures were checked by
    /// `validate_state` before it was stored, and re-checking 128 of them on
    /// every summary and delta would buy an answer that cannot have changed.
    /// Anything arriving from the network goes through `parse` or through the
    /// verify-on-entry path in `absorb`, never through this.
    pub fn parse_unverified(b: &[u8], p: &Params) -> Option<SetState> {
        let ph = p.hash();
        let (head, mut rest) = b.split_at_checked(6)?;
        if &head[..4] != MAGIC {
            return None;
        }
        let dcount = u16::from_le_bytes([head[4], head[5]]);
        if dcount > MAX_DENY {
            return None;
        }
        let mut deny: Vec<Deny> = Vec::with_capacity(dcount as usize);
        for _ in 0..dcount {
            let (d, tail) = rest.split_at_checked(DENY_LEN)?;
            rest = tail;
            let entry = Deny {
                signer: d[..KEY_LEN].try_into().ok()?,
                sig: d[KEY_LEN..].try_into().ok()?,
            };
            // The owner cannot deny ITSELF. Hiding its own tier is never what
            // an owner means, it is a second way to empty a Set, and — unlike
            // every other denial — nothing else in the format would stop it:
            // the owner signs denials, so it can always produce a valid one
            // naming its own key. Refused here, where a fetched state is the
            // only thing a host checks.
            if entry.signer == *p.owner.as_bytes() {
                return None;
            }
            // Canonical: strictly increasing by the denied key.
            if let Some(prev) = deny.last() {
                if prev.signer >= entry.signer {
                    return None;
                }
            }
            deny.push(entry);
        }

        let (head, mut rest2) = rest.split_at_checked(2)?;
        let count = u16::from_le_bytes([head[0], head[1]]);
        // Two tiers, each capped at M.
        if count > p.m.saturating_mul(2) {
            return None;
        }
        let mut held: Vec<Held> = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (item, tail) = Item::parse(rest2)?;
            rest2 = tail;
            if !item.well_formed(p, &ph) {
                return None;
            }
            let h = Held::of(item, p, &ph);
            if let Some(prev) = held.last() {
                if prev.rank() >= h.rank() {
                    return None;
                }
            }
            held.push(h);
        }
        if !rest2.is_empty() {
            return None;
        }
        let s = SetState { deny, held };
        s.within_limits(p).then_some(s)
    }

    /// **The only way to read a Set's contents.** A denied signer's slots are
    /// RETAINED in the state and hidden here; listing `held` directly shows
    /// items the owner has denied.
    ///
    /// They are retained rather than removed because the merge has to be a
    /// merge. A denial arrives later than the items it denies, and the capacity
    /// cut discards the losers irrecoverably — so if the stored state omitted a
    /// denied slot, that slot would stop consuming its place on a replica that
    /// learned the denial early while still consuming it on one that learned it
    /// late, and the two would disagree. Retained, the cut is a pure function of
    /// the slot union everywhere, and the denial is a filter on the VIEW.
    ///
    /// The cost is that a denied signer's slots hold their places for the life
    /// of the bucket. Bounded: at most `quota` of them, in the cap-holder tier
    /// only, and their payloads are capped like any other. The owner's tier is
    /// untouched. That is the price of a merge whose result does not depend on
    /// the order the merges happened in.
    pub fn visible(&self) -> impl Iterator<Item = &Held> {
        self.held.iter().filter(|h| !self.is_denied(h))
    }

    /// Is this slot's signer denied? A denial is identified by WHO is denied,
    /// and the list is sorted, so this is a binary search.
    pub fn is_denied(&self, h: &Held) -> bool {
        self.deny
            .binary_search_by_key(h.item.signer.as_bytes(), |d| d.signer)
            .is_ok()
    }

    /// The state as a set of FACTS, with every witness dropped: one
    /// `(slot, decision)` per held slot, plus the denied keys.
    ///
    /// This is what the merge laws are stated over. Two replicas can hold
    /// different witnesses of one decision — a second signature, another stamp
    /// nonce, a different capability — and comparing encodings would call that
    /// a disagreement when the two states say exactly the same thing.
    pub fn decisions(&self) -> Facts {
        let mut d: Vec<([u8; HASH_LEN], Decision)> = self
            .held
            .iter()
            .map(|h| (h.slot, h.item.decision()))
            .collect();
        d.sort_by_key(|(slot, _)| *slot);
        (self.deny.iter().map(|x| x.signer).collect(), d)
    }

    /// Per-tier capacity and the per-signer quota.
    pub fn within_limits(&self, p: &Params) -> bool {
        for tier in [Tier::Owner, Tier::CapHolder] {
            if self.held.iter().filter(|h| h.tier == tier).count() > p.m as usize {
                return false;
            }
        }
        let mut signers: Vec<&[u8; KEY_LEN]> =
            self.held.iter().map(|h| h.item.signer.as_bytes()).collect();
        signers.sort_unstable();
        let mut run = 0;
        for w in signers.windows(2) {
            run = if w[0] == w[1] { run + 1 } else { 0 };
            if run + 1 > p.quota as usize {
                return false;
            }
        }
        true
    }
}
