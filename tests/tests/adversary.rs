//! The ckb-adversary engine on mldsa-lock. Shape of the engine's multisig seed: Alice's cells under
//! the ML-DSA lock (reviewed, signed, not the builder's) and Carol's cell (the builder, no signature
//! to make again) in one payment. Every mutation Carol makes changes what Alice signed, so the lock
//! must refuse it; a byte the signature does not cover would show as accepted. A finding fails.
//!
//! Seeds: each level (44, 65, 87) under hash type data2 and under type, with one input of Alice's,
//! and level 65 with two inputs in the group. Control: with MLDSA_ENGINE_CONTROL set and MLDSA_BIN
//! pointing at a build whose signature check is off, the engine must come back with findings; a run
//! that finds nothing there would prove nothing here.
use ckb_adversary::{attack, summary, Seed, Verdict};
use ckb_testtool::builtin::ALWAYS_SUCCESS;
use ckb_testtool::ckb_hash::new_blake2b;
use ckb_testtool::ckb_types::{
    bytes::Bytes,
    core::{ScriptHashType, TransactionBuilder, TransactionView},
    packed::{CellDep, CellInput, CellOutput, Script, WitnessArgs},
    prelude::*,
};
use ckb_testtool::context::Context;
use fips204::traits::{KeyGen, SerDes, Signer};

const CKB: u64 = 100_000_000;
const FEE: u64 = 100_000;
const CONTEXT: &[u8] = b"CKB-MLDSA-LOCK";

fn bin() -> Bytes {
    let dir = std::env::var("MLDSA_BIN").unwrap_or_else(|_| "/root/mldsa/target/riscv64imac-unknown-none-elf/release".into());
    std::fs::read(format!("{dir}/mldsa-lock")).expect("binary").into()
}
fn blake(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = new_blake2b();
    for p in parts {
        h.update(p);
    }
    let mut o = [0u8; 32];
    h.finalize(&mut o);
    o
}

/// The lock's message for the group made of the first `group` inputs: script hash, then sighash_all.
fn sighash(tx: &TransactionView, script_hash: &[u8], group: usize, lock_len: usize) -> [u8; 32] {
    let mut h = new_blake2b();
    h.update(script_hash);
    h.update(tx.hash().as_slice());
    let w0 = WitnessArgs::new_unchecked(tx.witnesses().get(0).unwrap().raw_data());
    let zeroed = w0.as_builder().lock(Some(Bytes::from(vec![0u8; lock_len])).pack()).build();
    h.update(&(zeroed.as_slice().len() as u64).to_le_bytes());
    h.update(zeroed.as_slice());
    for i in (1..group).chain(tx.inputs().len()..tx.witnesses().len()) {
        let w = tx.witnesses().get(i).unwrap();
        h.update(&(w.raw_data().len() as u64).to_le_bytes());
        h.update(&w.raw_data());
    }
    let mut o = [0u8; 32];
    h.finalize(&mut o);
    o
}

/// A key of `level`: its public key bytes, its signature length, and a signer over a message.
fn key(level: u8) -> (Vec<u8>, usize, Box<dyn Fn(&[u8]) -> Vec<u8>>) {
    match level {
        0x02 => {
            let (pk, sk) = fips204::ml_dsa_44::KG::try_keygen().unwrap();
            (pk.into_bytes().to_vec(), fips204::ml_dsa_44::SIG_LEN, Box::new(move |m| sk.try_sign(m, CONTEXT).unwrap().to_vec()))
        }
        0x03 => {
            let (pk, sk) = fips204::ml_dsa_65::KG::try_keygen().unwrap();
            (pk.into_bytes().to_vec(), fips204::ml_dsa_65::SIG_LEN, Box::new(move |m| sk.try_sign(m, CONTEXT).unwrap().to_vec()))
        }
        _ => {
            let (pk, sk) = fips204::ml_dsa_87::KG::try_keygen().unwrap();
            (pk.into_bytes().to_vec(), fips204::ml_dsa_87::SIG_LEN, Box::new(move |m| sk.try_sign(m, CONTEXT).unwrap().to_vec()))
        }
    }
}

/// Alice pays Dave 500 CKB from `group` cells of hers under the lock at `level` and `hash_type`;
/// Carol builds the transaction and pays the fee from a cell of her own.
fn payment(level: u8, hash_type: ScriptHashType, group: usize) -> Seed {
    let mut ctx = Context::new_with_deterministic_rng();
    let code = ctx.deploy_cell(bin());
    let always = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let carol = ctx.build_script(&always, Bytes::from_static(b"carol")).unwrap();
    let dave = ctx.build_script(&always, Bytes::from_static(b"dave")).unwrap();
    let (pk, sig_len, sign) = key(level);
    let lock_len = pk.len() + sig_len;
    let args = [&[level][..], &blake(&[&pk])[..]].concat();
    let alice: Script = ctx.build_script_with_hash_type(&code, hash_type, Bytes::from(args)).unwrap();
    let plain = |cap: u64, lock: &Script| CellOutput::new_builder().capacity(cap).lock(lock.clone()).build();
    let each = 2_000 * CKB;
    let mut b = TransactionBuilder::default()
        .cell_dep(CellDep::new_builder().out_point(code).build())
        .cell_dep(CellDep::new_builder().out_point(always).build());
    for _ in 0..group {
        let cell = ctx.create_cell(plain(each, &alice), Bytes::new());
        b = b.input(CellInput::new_builder().previous_output(cell).build());
    }
    let ccell = ctx.create_cell(plain(300 * CKB, &carol), Bytes::new());
    let mut b = b
        .input(CellInput::new_builder().previous_output(ccell).build())
        .output(plain(500 * CKB, &dave))
        .output_data(Bytes::new().pack())
        .output(plain(each * group as u64 - 500 * CKB, &alice))
        .output_data(Bytes::new().pack())
        .output(plain(300 * CKB - FEE, &carol))
        .output_data(Bytes::new().pack())
        .witness(WitnessArgs::new_builder().lock(Some(Bytes::from(vec![0u8; lock_len])).pack()).build().as_bytes().pack());
    for _ in 0..group {
        b = b.witness(Bytes::new().pack());
    }
    let tx = b.build();
    let sig = sign(&sighash(&tx, alice.calc_script_hash().as_slice(), group, lock_len));
    let w0 = WitnessArgs::new_builder().lock(Some(Bytes::from([&pk[..], &sig[..]].concat())).pack()).build();
    let mut witnesses = vec![w0.as_bytes().pack()];
    witnesses.extend((0..group).map(|_| Bytes::new().pack()));
    let tx = tx.as_advanced_builder().set_witnesses(witnesses).build();
    let kind = if hash_type == ScriptHashType::Type { "type" } else { "data2" };
    Seed {
        name: format!("mldsa level {level:#04x}, {kind}, {group} input(s) in the group"),
        ctx,
        tx,
        builder: vec![carol],
        open: vec![],
        reviewed: vec![alice.code_hash()],
        since_tight: false,
        xudt: None,
        permissionless: false,
        identity: vec![],
        singleton: false,
    }
}

#[test]
fn the_engine_finds_nothing_on_the_mldsa_lock() {
    let control = std::env::var("MLDSA_ENGINE_CONTROL").is_ok();
    let mut seeds = vec![];
    for level in [0x02u8, 0x03, 0x05] {
        for hash_type in [ScriptHashType::Data2, ScriptHashType::Type] {
            seeds.push(payment(level, hash_type, 1));
        }
    }
    seeds.push(payment(0x03, ScriptHashType::Data2, 2));
    seeds.push(payment(0x03, ScriptHashType::Type, 2));
    let (mut total, mut findings) = (0, 0);
    for seed in &seeds {
        let rows = attack(seed);
        let refused: std::collections::BTreeMap<String, usize> = rows.iter().fold(Default::default(), |mut m, r| {
            if let Verdict::Refused { code, .. } = &r.verdict {
                *m.entry(format!("{code}")).or_default() += 1;
            }
            m
        });
        let found = rows.iter().filter(|r| matches!(r.verdict, Verdict::Finding(_))).count();
        println!("SEED {}: {} rows, {} findings, refusals by code {:?}", seed.name, rows.len(), found, refused);
        if !control {
            println!("{}", summary(&rows));
            for r in &rows {
                match &r.verdict {
                    Verdict::Finding(_) => println!("FINDING {:<22} {:<90} {:?}", r.family, r.what, r.verdict),
                    Verdict::Review(_) => println!("REVIEW  {:<22} {:<90} {:?}", r.family, r.what, r.verdict),
                    _ => {}
                }
            }
        }
        total += rows.len();
        findings += found;
    }
    println!("TOTAL {} seeds, {} rows, {} findings", seeds.len(), total, findings);
    if control {
        assert!(findings > 0, "the control build has no signature check: the engine must find it");
    } else {
        assert_eq!(findings, 0, "the engine found something");
    }
}
