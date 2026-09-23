//! The site contract's rules, through its doors, with the Register's own
//! signing fixtures (`testing`) and stdlib's serializer pinning every answer.

use super::*;
use craftec_register_contract::testing::keyset_seeded;
use craftec_register_contract::wire::{Evidence, Record, Signed, SIG_LEN};
use ed25519_dalek::Signer;
use freenet_stdlib::prelude::*;
use std::collections::BTreeSet;

/// An identity (one key, or k of n) publishing app `app`.
struct Id {
    params_bytes: Vec<u8>,
    params: Params,
    signers: Vec<ed25519_dalek::SigningKey>,
    k: usize,
}

fn id_with_label(seed: u8, k: usize, n: usize, label: &[u8]) -> Id {
    let w = keyset_seeded(seed, k, n, k == 1 && n == 1);
    let mut params_bytes = w.params_bytes[..w.params_bytes.len() - b"head".len()].to_vec();
    params_bytes.extend_from_slice(label);
    let params = Params::parse(&params_bytes).expect("the Register parses it");
    Id { params_bytes, params, signers: w.signers, k }
}

fn id(seed: u8, k: usize, n: usize) -> Id {
    id_with_label(seed, k, n, b"site:notes")
}

impl Id {
    /// A record for `version` naming `web`, signed by signers `who`.
    fn record_by(&self, version: u64, web: &[u8], who: &[usize], terminal: bool) -> Record {
        let value = blake3::hash(web).as_bytes().to_vec();
        let value_hash = *blake3::hash(&value).as_bytes();
        let msg = self.params.signed_message(terminal, version, &value_hash);
        let mut bitmap = 0u16;
        let mut sigs: Vec<[u8; SIG_LEN]> = Vec::new();
        for &i in who {
            bitmap |= 1 << i;
            sigs.push(self.signers[i].sign(&msg).to_bytes());
        }
        if matches!(self.params.authority, Authority::One(_)) {
            bitmap = 0;
        }
        Record { signed: Signed { terminal, seq: version, value_hash, bitmap, sigs }, value }
    }
    fn record(&self, version: u64, web: &[u8]) -> Record {
        self.record_by(version, web, &(0..self.k).collect::<Vec<_>>(), false)
    }
    fn state_of(&self, reg: &RegState, web: &[u8]) -> Vec<u8> {
        encode(&reg.encode(&self.params.authority), web)
    }
    fn publish(&self, version: u64, web: &[u8]) -> Vec<u8> {
        self.state_of(&RegState { record: Some(self.record(version, web)), evidence: None }, web)
    }
}

fn web(tag: &str) -> Vec<u8> {
    format!("xz-tar of the app, version {tag}").into_bytes()
}

/// Decode a door's answer, and require it to be the stdlib's own encoding of what it decodes to.
fn read<'a, T: serde::Deserialize<'a> + serde::Serialize>(bytes: &'a [u8]) -> T {
    let v: T = bincode::deserialize(bytes).expect("a door's bytes decode as the stdlib type");
    assert_eq!(bincode::serialize(&v).expect("re-encodes"), bytes, "a door's bytes are not the stdlib encoding of what they decode to");
    v
}

fn valid(params: &[u8], state: &[u8]) -> bool {
    let r: Result<ValidateResult, ContractError> = read(doors::validate(params, state));
    r.expect("validate answers Ok") == ValidateResult::Valid
}

/// The node's update door with `cands` as full-state updates.
fn update(params: &[u8], held: &[u8], cands: &[&[u8]]) -> Vec<u8> {
    let data: Vec<UpdateData<'static>> = cands.iter().map(|c| UpdateData::State(State::from(c.to_vec()))).collect();
    let bytes = doors::update(params, held, &bincode::serialize(&data).unwrap());
    let r: Result<UpdateModification<'_>, ContractError> = read(&bytes);
    r.expect("update answers Ok").new_state.expect("a state").as_ref().to_vec()
}

#[test]
fn a_published_version_is_valid_under_its_publishers_params() {
    for i in [id(1, 1, 1), id(2, 2, 3), id(3, 4, 5)] {
        let s = i.publish(1, &web("1"));
        assert!(valid(&i.params_bytes, &s), "k={} site not valid", i.k);
        assert!(check(&i.params_bytes, &s));
    }
}

#[test]
fn a_label_that_is_not_site_and_an_app_id_is_refused() {
    let good = id(1, 1, 1);
    assert!(params(&good.params_bytes).is_some(), "THE CONTROL: the good label is accepted");
    for label in [&b"head"[..], b"site:", b"site:Notes", b"site:a.b", b"site:has space", b"x:notes", b"site:notes/", &[b's', b'i', b't', b'e', b':', 0xff]] {
        let i = id_with_label(1, 1, 1, label);
        let s = i.publish(1, &web("1"));
        assert!(!valid(&i.params_bytes, &s), "label {:?} accepted", String::from_utf8_lossy(label));
    }
    let long = [b"site:".to_vec(), vec![b'a'; 33]].concat();
    let i = id_with_label(1, 1, 1, &long);
    assert!(!valid(&i.params_bytes, &i.publish(1, &web("1"))), "a 33-char app id accepted");
    let edge = [b"site:".to_vec(), vec![b'a'; 32]].concat();
    let i = id_with_label(1, 1, 1, &edge);
    assert!(valid(&i.params_bytes, &i.publish(1, &web("1"))), "THE CONTROL: a 32-char app id refused");
}

#[test]
fn a_record_that_does_not_name_its_web_part_is_refused() {
    let i = id(1, 1, 1);
    let reg = RegState { record: Some(i.record(1, &web("1"))), evidence: None };
    assert!(valid(&i.params_bytes, &i.state_of(&reg, &web("1"))), "THE CONTROL");
    assert!(!valid(&i.params_bytes, &i.state_of(&reg, &web("2"))), "a web part its record does not name was accepted");
}

#[test]
fn a_terminal_record_a_forged_signature_and_another_identitys_record_are_refused() {
    let i = id(1, 1, 1);
    let w = web("1");
    let term = RegState { record: Some(i.record_by(1, &w, &[0], true)), evidence: None };
    // A terminal record's value must be 32 bytes, which a bundle hash is: so it
    // would parse, and only this contract's own rule refuses it.
    assert!(!valid(&i.params_bytes, &i.state_of(&term, &w)), "a terminal record was accepted");
    let mut forged = i.record(1, &w);
    forged.signed.sigs[0][5] ^= 1;
    assert!(!valid(&i.params_bytes, &i.state_of(&RegState { record: Some(forged), evidence: None }, &w)));
    let other = id(9, 1, 1);
    assert!(!valid(&i.params_bytes, &other.publish(1, &w)), "another identity's site was accepted under these params");
    // k of n: fewer signers than k.
    let q = id(2, 2, 3);
    let short = q.record_by(1, &w, &[0], false);
    assert!(!valid(&q.params_bytes, &q.state_of(&RegState { record: Some(short), evidence: None }, &w)));
}

#[test]
fn every_framing_defect_is_refused() {
    let i = id(1, 1, 1);
    let good = i.publish(1, &web("1"));
    assert!(valid(&i.params_bytes, &good));
    let mut trailing = good.clone();
    trailing.push(0);
    let mut short_len = good.clone();
    short_len[7] = short_len[7].wrapping_sub(1);
    let meta_len = u64::from_be_bytes(good[..8].try_into().unwrap()) as usize;
    let no_web = good[..8 + meta_len + 8].to_vec();
    for (what, s) in [("trailing byte", trailing), ("metadata length off by one", short_len), ("empty web part", no_web)] {
        assert!(!valid(&i.params_bytes, &s), "{what} accepted");
    }
}

/// The bound is the WORST case (record + fork evidence), checked against the
/// Register's real encodings: `worst_metadata` must equal what a forked state
/// actually encodes to, for one key and every k-of-n that fits.
#[test]
fn the_metadata_bound_is_the_real_worst_case_and_refuses_k_above_4() {
    let mut checked = 0;
    for (k, n) in [(1, 1), (1, 2), (2, 3), (3, 4), (4, 5), (4, 16)] {
        let i = id(k as u8 + n as u8, k, n);
        let a = i.record(3, &web("a"));
        let b = i.record(3, &web("b"));
        let e = Evidence::new(&a.signed, &b.signed, &i.params.authority).expect("a same-version fork");
        let forked = RegState { record: Some(a), evidence: Some(e) };
        let actual = forked.encode(&i.params.authority).len();
        assert_eq!(worst_metadata(&i.params.authority), actual, "k={k} n={n}: the bound is not the real worst case");
        assert!(actual <= MAX_METADATA, "k={k} n={n}: {actual} B does not fit");
        assert!(valid(&i.params_bytes, &i.state_of(&forked, &web("a"))), "k={k} n={n}: a forked site does not validate");
        checked += 1;
    }
    assert_eq!(checked, 6);
    for (k, n) in [(5, 5), (5, 16)] {
        let i = id(40 + k as u8, k, n);
        assert!(worst_metadata(&i.params.authority) > MAX_METADATA, "THE CONTROL: k={k} would fit");
        assert!(params(&i.params_bytes).is_none(), "k={k} accepted though its forked state can never fit");
        assert!(!valid(&i.params_bytes, &i.publish(1, &web("1"))), "k={k}: a site whose fork cannot fit was accepted");
    }
}

#[test]
fn a_higher_version_replaces_and_carries_its_own_web() {
    let i = id(1, 1, 1);
    let (w1, w2) = (web("1"), web("2"));
    let s1 = i.publish(1, &w1);
    let s2 = i.publish(2, &w2);
    assert_eq!(update(&i.params_bytes, &s1, &[&s2]), s2, "version 2 did not replace version 1");
    assert_eq!(update(&i.params_bytes, &s2, &[&s1]), s2, "version 1 replaced version 2");
    assert_eq!(update(&i.params_bytes, &[], &[&s1]), s1, "an empty contract did not adopt version 1");
    // An invalid candidate changes nothing.
    let other = id(9, 1, 1).publish(3, &web("3"));
    assert_eq!(update(&i.params_bytes, &s1, &[&other]), s1, "another identity's version 3 was merged");
}

/// Two devices publish the SAME version with different bundles: the lower
/// bundle hash wins on every replica, the web part is the winner's, and the
/// fork is kept as evidence (F56).
#[test]
fn a_same_version_fork_converges_on_the_lower_bundle_hash_with_evidence() {
    let i = id(2, 2, 3);
    let (wa, wb) = (web("a"), web("b"));
    let (sa, sb) = (i.publish(5, &wa), i.publish(5, &wb));
    let ab = update(&i.params_bytes, &sa, &[&sb]);
    let ba = update(&i.params_bytes, &sb, &[&sa]);
    let lower = if blake3::hash(blake3::hash(&wa).as_bytes()).as_bytes() < blake3::hash(blake3::hash(&wb).as_bytes()).as_bytes() { &wa } else { &wb };
    for m in [&ab, &ba] {
        let s = parse(&i.params, m).expect("the merge is valid");
        assert_eq!(s.web, lower.as_slice(), "the fork did not settle on the lower bundle hash");
        assert!(s.reg.forked(), "the fork left no evidence");
    }
    assert_eq!(view(&i, &ab), view(&i, &ba), "the two replicas disagree");
}

/// What a state DECIDES, as a reader sees it: the record's decision, the
/// evidence's, and the web part. Signatures are not part of it — on equal
/// decisions the held bytes stay, so two replicas may hold different
/// witnesses of one decision.
fn view(i: &Id, s: &[u8]) -> (Option<(u64, [u8; 32])>, Option<(bool, u64, u64, [u8; 32], [u8; 32])>, Vec<u8>) {
    if s.is_empty() {
        return (None, None, Vec::new());
    }
    let p = parse(&i.params, s).expect("every state in the sweep is valid");
    (p.reg.record.as_ref().map(|r| (r.signed.seq, r.signed.value_hash)), p.reg.evidence.as_ref().map(Evidence::key), p.web.to_vec())
}

/// THE MERGE LAW, by a generated sweep (CLAUDE.md: never a hand-picked
/// triple). A shared pool: versions 1–3 × three bundles, each signed by
/// DIFFERENT signer sets (the same decision, other witnesses), plus every
/// pairwise merge (so forks with evidence are in it); competitors sit on
/// opposite sides of every merge. Commutative, associative and idempotent on
/// what a state decides, every result valid — with floors on how many cases
/// actually changed something and how many straddled a fork.
#[test]
fn the_merge_is_a_semilattice_over_a_generated_pool() {
    for i in [id(1, 1, 1), id(2, 2, 3)] {
        let p = &i.params_bytes;
        let n_sets: Vec<Vec<usize>> = if i.k == 1 { vec![vec![0]] } else { vec![vec![0, 1], vec![0, 2], vec![1, 2]] };
        let mut pool: Vec<Vec<u8>> = vec![Vec::new()];
        for v in 1..=3u64 {
            for b in ["a", "b", "c"] {
                let w = web(b);
                for who in &n_sets {
                    let reg = RegState { record: Some(i.record_by(v, &w, who, false)), evidence: None };
                    pool.push(i.state_of(&reg, &w));
                }
            }
        }
        let base = pool.len();
        for x in 0..base {
            for y in 0..base {
                let m = update(p, &pool[x], &[&pool[y]]);
                if !pool.contains(&m) {
                    pool.push(m);
                }
            }
        }
        let (mut changed, mut forks, mut cases) = (0, 0, 0);
        let j = |a: &[u8], b: &[u8]| update(p, a, &[b]);
        for a in &pool {
            assert_eq!(view(&i, &j(a, a)), view(&i, a), "not idempotent");
            for b in &pool {
                let ab = j(a, b);
                assert!(ab.is_empty() || check(p, &ab), "a merge produced an invalid state");
                assert_eq!(view(&i, &ab), view(&i, &j(b, a)), "not commutative");
                if view(&i, &ab) != view(&i, a) {
                    changed += 1;
                }
                if !ab.is_empty() && parse(&i.params, &ab).unwrap().reg.forked() {
                    forks += 1;
                }
            }
        }
        // Associativity: the full cube for a small pool, every other state for a larger one.
        let pick: Vec<&Vec<u8>> = pool.iter().step_by(if pool.len() > 30 { 2 } else { 1 }).collect();
        for a in &pick {
            for b in &pick {
                for c in &pick {
                    // What synced replicas DECIDE (record + web) is associative;
                    // whether a fork was NOTICED depends on delivery order, as in
                    // the Register (register/src/merge.rs:1-9, :114: detection is
                    // deliberately not part of the join).
                    let (l, r) = (view(&i, &j(&j(a, b), c)), view(&i, &j(a, &j(b, c))));
                    assert_eq!((&l.0, &l.2), (&r.0, &r.2), "not associative on what it decides");
                    cases += 1;
                }
            }
        }
        println!("k={}: pool {}, pairs changed {changed}, pairs forked {forks}, triples {cases}", i.k, pool.len());
        assert!(changed >= 100, "the sweep barely merged anything ({changed})");
        assert!(forks >= 50, "the sweep barely straddled a fork ({forks})");
        assert!(cases >= 1000, "too few triples ({cases})");
    }
}

/// A fork, once ANY replica noticed it, reaches every replica it syncs with:
/// evidence is sticky in the join, so the proof spreads whatever else is held.
#[test]
fn fork_evidence_spreads_to_every_replica_that_syncs() {
    let i = id(1, 1, 1);
    let p = &i.params_bytes;
    let forked = update(p, &i.publish(1, &web("a")), &[&i.publish(1, &web("b"))]);
    assert!(parse(&i.params, &forked).unwrap().reg.forked(), "THE CONTROL: the pair forked");
    for other in [i.publish(2, &web("c")), i.publish(1, &web("a")), i.publish(3, &web("d"))] {
        for m in [update(p, &other, &[&forked]), update(p, &forked, &[&other])] {
            assert!(parse(&i.params, &m).unwrap().reg.forked(), "a replica that synced with the forked one lost the proof");
        }
    }
}

/// A re-signed duplicate of the held decision changes NOTHING (the held bytes
/// stay): otherwise one keyholder could churn every replica forever.
#[test]
fn another_witness_of_the_held_version_changes_nothing() {
    let i = id(2, 2, 3);
    let w = web("1");
    let held = i.state_of(&RegState { record: Some(i.record_by(1, &w, &[0, 1], false)), evidence: None }, &w);
    let witness = i.state_of(&RegState { record: Some(i.record_by(1, &w, &[1, 2], false)), evidence: None }, &w);
    assert_ne!(held, witness, "THE CONTROL: two different encodings");
    assert_eq!(update(&i.params_bytes, &held, &[&witness]), held, "a second witness replaced the held bytes");
}

#[test]
fn summary_and_delta_send_nothing_to_a_replica_that_holds_this_state() {
    let i = id(1, 1, 1);
    let s = i.publish(1, &web("1"));
    let b = doors::summarize(&s);
    let sum: Result<StateSummary<'_>, ContractError> = read(&b);
    let sum = sum.unwrap().as_ref().to_vec();
    let b = doors::delta(&s, &sum);
    let d: Result<StateDelta<'_>, ContractError> = read(&b);
    assert!(d.unwrap().as_ref().is_empty(), "a replica holding this state was sent it again");
    let b = doors::delta(&s, b"other");
    let d: Result<StateDelta<'_>, ContractError> = read(&b);
    assert_eq!(d.unwrap().as_ref(), s.as_slice(), "a replica holding another state was not sent this one");
    let b = doors::summarize(&[]);
    let e: Result<StateSummary<'_>, ContractError> = read(&b);
    assert!(e.unwrap().as_ref().is_empty());
}

#[test]
fn update_data_that_does_not_decode_is_an_error_even_for_a_held_state() {
    let i = id(1, 1, 1);
    let s = i.publish(1, &web("1"));
    let b = doors::update(&i.params_bytes, &s, &[1, 2, 3]);
    let r: Result<UpdateModification<'_>, ContractError> = read(&b);
    assert!(matches!(r, Err(ContractError::Deser(_))));
}

#[test]
fn the_pool_has_distinct_bundles_and_versions() {
    // The sweep's discriminating power: its pool must really hold competing
    // decisions, or its floors are measuring nothing.
    let i = id(1, 1, 1);
    let seen: BTreeSet<[u8; 32]> = ["a", "b", "c"].iter().map(|b| *blake3::hash(&web(b)).as_bytes()).collect();
    assert_eq!(seen.len(), 3);
    assert_ne!(i.publish(1, &web("a")), i.publish(2, &web("a")));
}
