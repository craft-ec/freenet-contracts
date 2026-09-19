//! Building registers to test and to measure against.
//!
//! Behind the off-by-default `testing` feature, so none of it reaches the
//! contract's wasm, and shared with `wasm-check/` so the case that is timed is
//! the same one the tests assert on.

use crate::merge::update;
use crate::wire::{Authority, Evidence, Params, Record, RegState, Signed, MAGIC, SIG_LEN};
use ed25519_dalek::{Signer, SigningKey};

/// Deterministic, so a failing case is the same case tomorrow.
pub fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed | 1;
    move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    }
}

/// A register and the keys that may write it.
pub struct World {
    pub params_bytes: Vec<u8>,
    pub params: Params,
    pub auth: Authority,
    /// Sorted to match the keyset order, so index `i` here is bit `i`.
    pub signers: Vec<SigningKey>,
    pub k: usize,
}

/// A k-of-n register. `n = 1, k = 1` with `mode0 = true` gives the single-key
/// form instead. `seed` picks the keys, so two worlds can hold genuinely
/// different keysets — a fixture whose "other" keys are the same keys proves
/// nothing about a wrong-key refusal.
pub fn keyset_seeded(seed: u8, k: usize, n: usize, mode0: bool) -> World {
    let mut signers: Vec<SigningKey> = (0..n)
        .map(|i| SigningKey::from_bytes(&[i as u8 + 1 + seed * 64; 32]))
        .collect();
    // The keyset is sorted by public key, and the bitmap indexes that order.
    signers.sort_by_key(|s| s.verifying_key().to_bytes());
    let mut params_bytes = Vec::from(*MAGIC);
    if mode0 {
        assert_eq!((k, n), (1, 1), "mode 0 is one key");
        params_bytes.push(0);
        params_bytes.extend_from_slice(&signers[0].verifying_key().to_bytes());
    } else {
        params_bytes.push(1);
        params_bytes.push(k as u8);
        params_bytes.push(n as u8);
        for s in &signers {
            params_bytes.extend_from_slice(&s.verifying_key().to_bytes());
        }
    }
    params_bytes.extend_from_slice(b"head");
    let params = Params::parse(&params_bytes).expect("built params must parse");
    let auth = params.authority.clone();
    World {
        params_bytes,
        params,
        auth,
        signers,
        k,
    }
}

pub fn keyset(k: usize, n: usize, mode0: bool) -> World {
    keyset_seeded(0, k, n, mode0)
}

/// The default world for the unit tests: 2-of-4.
pub fn world() -> World {
    keyset(2, 4, false)
}

impl World {
    /// A record signed by the given signer indices, which must be sorted.
    pub fn record_signed_by(
        &self,
        terminal: bool,
        seq: u64,
        value: &[u8],
        who: &[usize],
    ) -> Record {
        let value_hash = *blake3::hash(value).as_bytes();
        let msg = self.params.signed_message(terminal, seq, &value_hash);
        let mut bitmap = 0u16;
        let mut sigs: Vec<[u8; SIG_LEN]> = Vec::new();
        for &i in who {
            bitmap |= 1 << i;
            sigs.push(self.signers[i].sign(&msg).to_bytes());
        }
        if matches!(self.auth, Authority::One(_)) {
            bitmap = 0; // mode 0 has nothing to choose, so it stores no bitmap
        }
        Record {
            signed: Signed {
                terminal,
                seq,
                value_hash,
                bitmap,
                sigs,
            },
            value: value.to_vec(),
        }
    }

    /// A record signed by the first `k` signers.
    pub fn record(&self, terminal: bool, seq: u64, value: &[u8]) -> Record {
        let who: Vec<usize> = (0..self.k).collect();
        self.record_signed_by(terminal, seq, value, &who)
    }

    /// A different quorum of the same size — the same decision, spelled by
    /// other signers. Only exists when there is a spare key (`k < n`); with no
    /// spare there is only one way to sign a decision.
    pub fn alternate(&self, terminal: bool, seq: u64, value: &[u8]) -> Option<Record> {
        let n = match &self.auth {
            Authority::One(_) => 1,
            Authority::Quorum { keys, .. } => keys.len(),
        };
        (self.k < n).then(|| {
            let who: Vec<usize> = (1..=self.k).collect();
            self.record_signed_by(terminal, seq, value, &who)
        })
    }

    /// Every way to choose `k` of the `n` signers, in index order.
    pub fn subsets(&self) -> Vec<Vec<usize>> {
        let n = match &self.auth {
            Authority::One(_) => 1,
            Authority::Quorum { keys, .. } => keys.len(),
        };
        let mut out = Vec::new();
        for mask in 0u32..(1 << n) {
            if mask.count_ones() as usize == self.k {
                out.push((0..n).filter(|i| mask & (1 << i) != 0).collect());
            }
        }
        out
    }

    /// Every encoding of one decision: the same `(terminal, seq, value)` signed
    /// by each possible quorum.
    pub fn all_encodings(&self, terminal: bool, seq: u64, value: &[u8]) -> Vec<Record> {
        self.subsets()
            .into_iter()
            .map(|who| self.record_signed_by(terminal, seq, value, &who))
            .collect()
    }

    pub fn state(&self, r: Record) -> RegState {
        RegState {
            record: Some(r),
            evidence: None,
        }
    }

    pub fn evidence_of(&self, x: &Record, y: &Record) -> Evidence {
        Evidence::new(&x.signed, &y.signed, &self.auth).expect("these two must conflict")
    }

    pub fn encode(&self, s: &RegState) -> Vec<u8> {
        s.encode(&self.auth)
    }

    /// States covering every shape the merge has to handle: empty, record only,
    /// evidence only (third-party proof), both, equivocating pairs, terminals.
    pub fn sample_states(&self) -> Vec<RegState> {
        let a = self.record(false, 7, b"one");
        let b = self.record(false, 7, b"two"); // same seq, other value: a fork
        let c = self.record(false, 9, b"later");
        let t = self.record(true, 1, b"moved-to");
        let t2 = self.record(true, 4, b"elsewhere"); // two terminals: also a fork
        let e1 = self.evidence_of(&a, &b);
        let e2 = self.evidence_of(&t, &t2);
        let mut out = vec![
            RegState::default(),
            self.state(a.clone()),
            self.state(b.clone()),
            self.state(c.clone()),
            self.state(t.clone()),
            self.state(t2.clone()),
            RegState {
                record: None,
                evidence: Some(e1.clone()),
            },
            RegState {
                record: None,
                evidence: Some(e2.clone()),
            },
            RegState {
                record: Some(a),
                evidence: Some(e1.clone()),
            },
            RegState {
                record: Some(c),
                evidence: Some(e2.clone()),
            },
            RegState {
                record: Some(t),
                evidence: Some(e1),
            },
            RegState {
                record: Some(t2),
                evidence: Some(e2),
            },
        ];
        // The same decision spelled by another quorum, where one exists.
        out.extend(self.alternate(false, 7, b"one").map(|r| self.state(r)));
        out
    }

    /// Hand the sample records to replicas in a seed-dependent order, then let
    /// every pair exchange until nothing changes. Returns the final states and
    /// how many rounds it took.
    pub fn gossip(
        &self,
        seed: u64,
        with_terminal: bool,
        merge: impl Fn(&RegState, &RegState, &Authority) -> RegState,
    ) -> (Vec<RegState>, usize) {
        let mut r = rng(seed);
        // The HIGHEST seq is the equivocating pair, deliberately: if the top of
        // the order were decided by seq alone, every merge would agree for
        // reasons that have nothing to do with the tie-breaks, and a merge that
        // got the tie-breaks wrong would still converge.
        let mut records = vec![
            self.record(false, 9, b"one"),
            self.record(false, 9, b"two"),
            self.record(false, 5, b"mid"),
            self.record(false, 3, b"early"),
        ];
        // The same decision spelled by a second quorum, so the record-hash
        // tie-break is exercised too.
        records.extend(self.alternate(false, 5, b"mid"));
        if with_terminal {
            records.push(self.record(true, 2, b"moved-to"));
        }
        const REPLICAS: usize = 5;
        let mut reps = vec![RegState::default(); REPLICAS];
        // Each record reaches a random subset of replicas, in a random order.
        let mut order: Vec<usize> = (0..records.len()).collect();
        for i in (1..order.len()).rev() {
            order.swap(i, (r() % (i as u64 + 1)) as usize);
        }
        for &i in &order {
            let who = (r() % REPLICAS as u64) as usize;
            reps[who] = merge(&reps[who], &self.state(records[i].clone()), &self.auth);
        }
        // Gossip to a fixpoint.
        let mut rounds = 0;
        loop {
            let before: Vec<Vec<u8>> = reps.iter().map(|s| self.encode(s)).collect();
            for i in 0..REPLICAS {
                for j in 0..REPLICAS {
                    if i != j {
                        let merged = merge(&reps[i], &reps[j], &self.auth);
                        reps[i] = merged;
                    }
                }
            }
            rounds += 1;
            let after: Vec<Vec<u8>> = reps.iter().map(|s| self.encode(s)).collect();
            if before == after || rounds > 20 {
                break;
            }
        }
        (reps, rounds)
    }
}

/// The worst case a host can be handed: mode 1 with `n = 16, k = 16`, so every
/// validation verifies sixteen signatures, over a full-size value.
pub fn worst_case() -> (Vec<u8>, Vec<u8>) {
    let w = keyset(16, 16, false);
    let value = vec![0xa5u8; crate::wire::MAX_VALUE];
    let value_hash = *blake3::hash(&value).as_bytes();
    // The rival must LOSE, or the state that gets validated holds its short
    // value instead of the full-size one. The lower value hash wins, so pick a
    // rival whose hash is above the big value's.
    let rival = (0..1000)
        .map(|i| format!("rival-{i}").into_bytes())
        .find(|v| *blake3::hash(v).as_bytes() > value_hash)
        .expect("some rival hashes higher");
    let held = w.state(w.record(false, 1, &value));
    // A second record at the same seq, so the state also carries evidence — the
    // most signatures a single validation can be made to verify: k for the
    // record and k for each side of the proof.
    let full = update(&held, &w.state(w.record(false, 1, &rival)), &w.auth);
    assert!(full.forked(), "the worst case includes carrying evidence");
    assert_eq!(
        full.record.as_ref().map(|r| r.value.len()),
        Some(crate::wire::MAX_VALUE),
        "the full-size value must be the one held"
    );
    (w.params_bytes.clone(), w.encode(&full))
}
