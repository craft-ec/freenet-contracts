//! Fixtures. Off by default, so none of this is in the contract's wasm.
//!
//! Everything here is deterministic: keys come from seeds, `ts` is supplied by
//! the caller, and stamps are mined by counting. A fixture that needed entropy
//! would make a failing test a story about the run rather than about the code.

use crate::merge::{cut, join};
use crate::wire::{
    Admission, Cap, Deny, Held, Item, Params, SetState, CAP_DOMAIN, DENY_DOMAIN, HASH_LEN,
    NONCE_LEN,
};
use ed25519_dalek::{Signer, SigningKey};

pub struct World {
    pub params: Params,
    pub params_bytes: Vec<u8>,
    /// `keys[0]` is the owner.
    pub keys: Vec<SigningKey>,
}

/// A set with `n` keys, the first of which owns it.
pub fn world_with(
    seed: u8,
    n: usize,
    admission: Admission,
    m: u16,
    quota: u16,
    decision_bits: u8,
) -> World {
    let keys: Vec<SigningKey> = (0..n)
        .map(|i| {
            let mut b = [0u8; 32];
            b[0] = seed;
            b[1] = i as u8 + 1;
            SigningKey::from_bytes(&b)
        })
        .collect();
    let params = Params {
        owner: keys[0].verifying_key(),
        admission,
        m,
        quota,
        decision_bits,
        payload_cap: 256,
        bucket: 7,
        label: b"notes".to_vec(),
    };
    let params_bytes = params.encode();
    World {
        params,
        params_bytes,
        keys,
    }
}

/// The default: capability admission, four keys, room for eight slots a tier,
/// four per signer, no stamp required.
pub fn world() -> World {
    world_with(1, 4, Admission::Cap, 8, 4, 0)
}

impl World {
    pub fn ph(&self) -> [u8; HASH_LEN] {
        self.params.hash()
    }

    /// An owner-signed grant for `who`, covering buckets `from..=to`.
    pub fn cap_for(&self, who: usize, from: u32, to: u32) -> Cap {
        let grantee = self.keys[who].verifying_key();
        let psb = self.params.hash_sans_bucket();
        let mut msg = Vec::from(&CAP_DOMAIN[..]);
        msg.extend_from_slice(grantee.as_bytes());
        msg.extend_from_slice(&psb);
        msg.extend_from_slice(&from.to_le_bytes());
        msg.extend_from_slice(&to.to_le_bytes());
        Cap {
            grantee,
            params_sans_bucket: psb,
            from,
            to,
            sig: self.keys[0].sign(&msg).to_bytes(),
        }
    }

    /// An owner-signed denial of `who`.
    pub fn deny_of(&self, who: usize) -> Deny {
        let signer = self.keys[who].verifying_key().to_bytes();
        let mut msg = Vec::from(&DENY_DOMAIN[..]);
        msg.extend_from_slice(&self.ph());
        msg.extend_from_slice(&signer);
        Deny {
            signer,
            sig: self.keys[0].sign(&msg).to_bytes(),
        }
    }

    /// A signed item. `who = 0` is the owner and carries no capability; anyone
    /// else carries one for this bucket.
    pub fn item(&self, who: usize, key: &[u8], ts: u64, payload: &[u8]) -> Item {
        self.item_full(who, key, ts, payload, false, false, 0)
    }

    pub fn tombstone(&self, who: usize, key: &[u8], ts: u64) -> Item {
        self.item_full(who, key, ts, b"", true, false, 0)
    }

    pub fn sealed(&self, who: usize, key: &[u8], ts: u64, payload: &[u8]) -> Item {
        self.item_full(who, key, ts, payload, false, true, 0)
    }

    /// `salt` picks a different stamp nonce among the ones that satisfy the
    /// work requirement, which is how a SECOND witness of one decision is
    /// built: same decision, different nonce, different signature.
    #[allow(clippy::too_many_arguments)]
    pub fn item_full(
        &self,
        who: usize,
        key: &[u8],
        ts: u64,
        payload: &[u8],
        tombstone: bool,
        sealed: bool,
        salt: u64,
    ) -> Item {
        let mut it = Item {
            signer: self.keys[who].verifying_key(),
            item_key: key.to_vec(),
            ts,
            tombstone,
            sealed,
            payload: payload.to_vec(),
            cap: (who != 0).then(|| self.cap_for(who, 0, u32::MAX)),
            stamp_nonce: [0u8; NONCE_LEN],
            sig: [0u8; 64],
        };
        let ph = self.ph();
        // Mine the stamp by counting. At the default of zero required bits the
        // first nonce tried is already good, so the ordinary fixture pays
        // nothing for this.
        let mut n = salt;
        loop {
            it.stamp_nonce = n.to_le_bytes();
            if it.stamp_work(&ph) >= self.params.decision_bits as u32 {
                break;
            }
            n += 1;
        }
        it.sig = self.keys[who].sign(&it.signed_bytes(&ph)).to_bytes();
        it
    }

    /// Re-sign an item after a test has changed a field. Without this a
    /// "tampered" fixture would be refused for the signature alone, and the
    /// rule it was built to exercise would never be reached.
    pub fn resign(&self, it: &mut Item, who: usize) {
        it.sig = self.keys[who].sign(&it.signed_bytes(&self.ph())).to_bytes();
    }

    /// The state holding exactly these items, cut and ordered as the contract
    /// would leave it.
    pub fn state(&self, items: Vec<Item>) -> SetState {
        self.state_with(items, Vec::new())
    }

    pub fn state_with(&self, items: Vec<Item>, deny: Vec<Deny>) -> SetState {
        let empty = SetState::default();
        let ph = self.ph();
        let held: Vec<Held> = items
            .into_iter()
            .map(|i| Held::of(i, &self.params, &ph))
            .collect();
        let mut s = SetState {
            deny,
            held: cut(held, &self.params),
        };
        s.held.sort_by_key(|h| h.rank());
        // Through the join once, so a fixture can never hand a test a state the
        // contract itself would not produce.
        join(&s, &empty, &self.params)
    }

    pub fn encode(&self, s: &SetState) -> Vec<u8> {
        s.encode()
    }
}

/// Two independent sets that happen to have the same shape — for showing that a
/// signature, a capability or a denial from one is refused by the other.
pub fn elsewhere() -> World {
    world_with(9, 4, Admission::Cap, 8, 4, 0)
}
