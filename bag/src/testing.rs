//! Fixtures. Mining a name is the only slow part, so everything here is built
//! from a nonce search and kept deterministic.

use crate::wire::{Held, Params, Pointer, NONCE_LEN};

pub fn params(work_bits: u8, m: u16) -> Params {
    Params {
        owner: [7u8; 32],
        work_bits,
        m,
        payload_cap: 256,
        bucket: 0,
        label: b"inbox".to_vec(),
    }
}

/// Mine a pointer for `payload` that meets the price. Deterministic in `seed`,
/// so a test that needs two different pointers asks for two seeds.
pub fn mine(p: &Params, payload: &[u8], seed: u64) -> Pointer {
    let ph = p.hash();
    let mut n = seed;
    loop {
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&n.to_le_bytes());
        let ptr = Pointer {
            payload: payload.to_vec(),
            nonce,
        };
        if Held::of(ptr.clone(), &ph).work >= p.work_bits as u32 {
            return ptr;
        }
        n = n.wrapping_add(1);
    }
}

/// `n` pointers, each with its own payload.
pub fn many(p: &Params, n: usize, seed: u64) -> Vec<Pointer> {
    (0..n)
        .map(|i| mine(p, format!("craftec://ref/{i:06}").as_bytes(), seed + i as u64 * 7919))
        .collect()
}
