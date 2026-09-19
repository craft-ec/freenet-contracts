//! Encodings, and the checks that make each one canonical.
//!
//! Every integer is little-endian. Every structure here has exactly one valid
//! encoding: two spellings of one logical state would hash two ways, and a
//! merge that breaks ties on names would stop being a function of the contents.

use blake3::Hasher;

pub const MAGIC: &[u8; 4] = b"BG01";
/// Domain separator for a pointer's name. Distinct from [`MAGIC`] so a state
/// can never be read as a name preimage or the reverse.
pub const NAME_DOMAIN: &[u8; 8] = b"BG01-ptr";
pub const MAX_LABEL: usize = 64;
/// The frozen ceiling on `M`. A bag's summary is 16 bytes per pointer, so this
/// bounds a summary at ~16 KB — see the module doc in `lib.rs`.
pub const MAX_M: u16 = 1024;
/// The frozen ceiling on a payload. A pointer is a NAME, not a document.
pub const MAX_PAYLOAD: u16 = 256;
pub const KEY_LEN: usize = 32;
pub const HASH_LEN: usize = 32;
pub const NONCE_LEN: usize = 8;
/// Bytes of a name a summary carries. 16, not 8: "you already have it" is an
/// assertion a stranger can aim at, and at 8 bytes aiming it costs 2^64/M.
pub const TRUNC: usize = 16;
/// The most work a bag may demand. Not 255: a `u8` can never reach the 256 bits
/// of a name, so "work_bits < 256" is a check that cannot fail — it looked like
/// a ceiling and enforced nothing. Sixty-four leading zeros is already beyond
/// anyone's reach, so a bag asking for more is one nobody can ever write to,
/// and refusing it at parse beats hosting it empty forever.
pub const MAX_WORK_BITS: u8 = 64;

/// What a bag is, fixed in its contract key.
///
/// `"BG01" ‖ owner(32) ‖ work_bits(1) ‖ M(2) ‖ payload_cap(2) ‖ bucket(4) ‖
/// label(≤64)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    /// Who the bag belongs to. The contract never checks a signature — this is
    /// here so the key commits to it and the owner's own tree can refer to it.
    pub owner: [u8; KEY_LEN],
    /// Leading zero bits a pointer's name must have. The price of a name.
    pub work_bits: u8,
    /// How many pointers the bag keeps.
    pub m: u16,
    pub payload_cap: u16,
    /// Lets one owner have many bags of the same shape.
    pub bucket: u32,
    pub label: Vec<u8>,
}

impl Params {
    pub fn parse(b: &[u8]) -> Option<Params> {
        let (head, label) = b.split_at_checked(4 + KEY_LEN + 1 + 2 + 2 + 4)?;
        if &head[..4] != MAGIC {
            return None;
        }
        if label.len() > MAX_LABEL {
            return None;
        }
        let mut owner = [0u8; KEY_LEN];
        owner.copy_from_slice(&head[4..4 + KEY_LEN]);
        let at = 4 + KEY_LEN;
        let p = Params {
            owner,
            work_bits: head[at],
            m: u16::from_le_bytes([head[at + 1], head[at + 2]]),
            payload_cap: u16::from_le_bytes([head[at + 3], head[at + 4]]),
            bucket: u32::from_le_bytes([head[at + 5], head[at + 6], head[at + 7], head[at + 8]]),
            label: label.to_vec(),
        };
        // The ceilings are part of the format, not of a caller's judgement: a
        // bag whose params exceed them is not a bag this code will host.
        (p.m >= 1
            && p.m <= MAX_M
            && p.payload_cap >= 1
            && p.payload_cap <= MAX_PAYLOAD
            && p.work_bits <= MAX_WORK_BITS)
            .then_some(p)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::from(&MAGIC[..]);
        out.extend_from_slice(&self.owner);
        out.push(self.work_bits);
        out.extend_from_slice(&self.m.to_le_bytes());
        out.extend_from_slice(&self.payload_cap.to_le_bytes());
        out.extend_from_slice(&self.bucket.to_le_bytes());
        out.extend_from_slice(&self.label);
        out
    }

    /// What a pointer's name is bound to.
    ///
    /// Hashing the whole params means work mined for one bag is worthless in
    /// another: a pointer cannot be moved, and the price is per bag.
    pub fn hash(&self) -> [u8; HASH_LEN] {
        *blake3::hash(&self.encode()).as_bytes()
    }
}

/// One pointer: bytes this contract never interprets, and a nonce.
///
/// No signer, no signature, no timestamp, no tombstone. A bag asserts only that
/// these names met the price.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pointer {
    pub payload: Vec<u8>,
    pub nonce: [u8; NONCE_LEN],
}

impl Pointer {
    /// `BLAKE3(NAME_DOMAIN ‖ params hash ‖ len(payload) ‖ payload ‖ nonce)`.
    ///
    /// The length is hashed because a payload is variable-length: without it,
    /// `("ab", "c" ‖ nonce)` and `("abc", nonce)` could be made to agree, and a
    /// name must have one preimage shape.
    pub fn name(&self, ph: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
        let mut h = Hasher::new();
        h.update(NAME_DOMAIN);
        h.update(ph);
        h.update(&(self.payload.len() as u16).to_le_bytes());
        h.update(&self.payload);
        h.update(&self.nonce);
        *h.finalize().as_bytes()
    }

    /// Leading zero bits of the name: the work that bought it.
    pub fn work(name: &[u8; HASH_LEN]) -> u32 {
        let mut n = 0;
        for b in name {
            n += b.leading_zeros();
            if *b != 0 {
                break;
            }
        }
        n
    }

    fn encoded_len(&self) -> usize {
        2 + self.payload.len() + NONCE_LEN
    }

    fn write(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.payload);
        out.extend_from_slice(&self.nonce);
    }

    fn read(b: &[u8], cap: u16) -> Option<(Pointer, &[u8])> {
        let (len, rest) = b.split_at_checked(2)?;
        let len = u16::from_le_bytes([len[0], len[1]]);
        if len > cap {
            return None;
        }
        let (payload, rest) = rest.split_at_checked(len as usize)?;
        let (nonce, rest) = rest.split_at_checked(NONCE_LEN)?;
        Some((
            Pointer {
                payload: payload.to_vec(),
                nonce: nonce.try_into().ok()?,
            },
            rest,
        ))
    }
}

/// A pointer with what the contract derived from it. Derived, never carried:
/// a state that carried a name would be asserting it, and the assertion would
/// have to be checked anyway.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    pub ptr: Pointer,
    pub name: [u8; HASH_LEN],
    pub work: u32,
}

/// Names hashed. A pointer's name costs a BLAKE3 over its payload, and that is
/// the work a hostile state can impose — counted so a test can assert on it
/// rather than on a clock.
///
/// **Thread-local, and that is the whole point of the module.** The harness
/// runs a binary's tests in parallel threads, so a process-global counter
/// reports whatever every other test happened to be doing at the moment it was
/// read. Every cost assertion over one is a race that usually passes, and a
/// green run looks identical either way. Per-thread, a test sees its own work
/// and nobody else's.
#[cfg(any(test, feature = "testing"))]
pub mod hashed {
    use core::cell::Cell;
    thread_local! { static N: Cell<usize> = const { Cell::new(0) }; }
    /// Names hashed on this thread since the last [`reset`].
    pub fn count() -> usize {
        N.with(|n| n.get())
    }
    pub fn reset() {
        N.with(|n| n.set(0));
    }
    pub(crate) fn tick() {
        N.with(|n| n.set(n.get() + 1));
    }
}

impl Held {
    pub fn of(ptr: Pointer, ph: &[u8; HASH_LEN]) -> Held {
        #[cfg(any(test, feature = "testing"))]
        hashed::tick();
        let name = ptr.name(ph);
        Held {
            work: Pointer::work(&name),
            name,
            ptr,
        }
    }

    /// The total order the bag keeps: **work descending, then name ascending**.
    /// Total (names are unique), so top-M under it is a function of the set.
    pub fn rank(&self) -> (core::cmp::Reverse<u32>, [u8; HASH_LEN]) {
        (core::cmp::Reverse(self.work), self.name)
    }
}

/// `"BG01" ‖ count(2) ‖ pointer*`, pointers in rank order.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BagState {
    pub held: Vec<Held>,
}

impl BagState {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::from(&MAGIC[..]);
        out.extend_from_slice(&(self.held.len() as u16).to_le_bytes());
        for h in &self.held {
            h.ptr.write(&mut out);
        }
        out
    }

    pub fn encoded_len(&self) -> usize {
        4 + 2 + self.held.iter().map(|h| h.ptr.encoded_len()).sum::<usize>()
    }

    /// Parse AND check. There is no unchecked read: a bag fetched from a peer
    /// is validated and nothing else (F23), so everything the contract asserts
    /// has to be decided here.
    ///
    /// Checked: the magic; the count matching what follows; no trailing bytes;
    /// every payload within the cap; every name at or above `work_bits`; strict
    /// rank order (which also forbids a repeated name); and `count ≤ M`.
    pub fn parse(b: &[u8], p: &Params) -> Option<BagState> {
        let ph = p.hash();
        let (head, mut rest) = b.split_at_checked(6)?;
        if &head[..4] != MAGIC {
            return None;
        }
        let count = u16::from_le_bytes([head[4], head[5]]);
        if count > p.m {
            return None;
        }
        let mut held: Vec<Held> = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let (ptr, tail) = Pointer::read(rest, p.payload_cap)?;
            rest = tail;
            let h = Held::of(ptr, &ph);
            if h.work < p.work_bits as u32 {
                return None;
            }
            // STRICTLY increasing: equal ranks would mean a repeated name, and
            // one order per set is what makes the state canonical.
            if let Some(prev) = held.last() {
                if prev.rank() >= h.rank() {
                    return None;
                }
            }
            held.push(h);
        }
        rest.is_empty().then_some(BagState { held })
    }
}
