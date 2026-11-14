//! The ckb-adversary engine on mldsa-lock. Shape of the engine's multisig seed: Alice's cell under
//! the ML-DSA lock (reviewed, signed, not the builder's) and Carol's cell (the builder, no signature
//! to make again) in one payment. Every mutation Carol makes changes what Alice signed, so the lock
//! must refuse it; a byte the signature does not cover would show as accepted. A finding fails.
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

/// The lock's message for the group made of input 0 alone: script hash, then sighash_all.
fn sighash(tx: &TransactionView, script_hash: &[u8], lock_len: usize) -> [u8; 32] {
    let mut h = new_blake2b();
    h.update(script_hash);
    h.update(tx.hash().as_slice());
    let w0 = WitnessArgs::new_unchecked(tx.witnesses().get(0).unwrap().raw_data());
    let zeroed = w0.as_builder().lock(Some(Bytes::from(vec![0u8; lock_len])).pack()).build();
    h.update(&(zeroed.as_slice().len() as u64).to_le_bytes());
    h.update(zeroed.as_slice());
    for i in tx.inputs().len()..tx.witnesses().len() {
        let w = tx.witnesses().get(i).unwrap();
        h.update(&(w.raw_data().len() as u64).to_le_bytes());
        h.update(&w.raw_data());
    }
    let mut o = [0u8; 32];
    h.finalize(&mut o);
    o
}

fn payment() -> Seed {
    let mut ctx = Context::new_with_deterministic_rng();
    let code = ctx.deploy_cell(bin());
    let always = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let carol = ctx.build_script(&always, Bytes::from_static(b"carol")).unwrap();
    let dave = ctx.build_script(&always, Bytes::from_static(b"dave")).unwrap();
    let (pk, sk) = fips204::ml_dsa_65::KG::try_keygen().unwrap();
    let pk = pk.into_bytes().to_vec();
    let lock_len = pk.len() + fips204::ml_dsa_65::SIG_LEN;
    let args = [&[0x03u8][..], &blake(&[&pk])[..]].concat();
    let alice: Script = ctx.build_script_with_hash_type(&code, ScriptHashType::Data2, Bytes::from(args)).unwrap();
    let plain = |cap: u64, lock: &Script| CellOutput::new_builder().capacity(cap).lock(lock.clone()).build();
    let acell = ctx.create_cell(plain(2_000 * CKB, &alice), Bytes::new());
    let ccell = ctx.create_cell(plain(300 * CKB, &carol), Bytes::new());
    let tx = TransactionBuilder::default()
        .cell_dep(CellDep::new_builder().out_point(code).build())
        .cell_dep(CellDep::new_builder().out_point(always).build())
        .input(CellInput::new_builder().previous_output(acell).build())
        .input(CellInput::new_builder().previous_output(ccell).build())
        .output(plain(500 * CKB, &dave))
        .output_data(Bytes::new().pack())
        .output(plain(1_500 * CKB, &alice))
        .output_data(Bytes::new().pack())
        .output(plain(300 * CKB - FEE, &carol))
        .output_data(Bytes::new().pack())
        .witness(WitnessArgs::new_builder().lock(Some(Bytes::from(vec![0u8; lock_len])).pack()).build().as_bytes().pack())
        .witness(Bytes::new().pack())
        .build();
    let msg = sighash(&tx, alice.calc_script_hash().as_slice(), lock_len);
    let sig = sk.try_sign(&msg, CONTEXT).unwrap();
    let w0 = WitnessArgs::new_builder().lock(Some(Bytes::from([&pk[..], &sig[..]].concat())).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![w0.as_bytes().pack(), Bytes::new().pack()]).build();
    Seed {
        name: "mldsa-65 payment".into(),
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
    let seed = payment();
    let rows = attack(&seed);
    println!("{}", summary(&rows));
    let refused: std::collections::BTreeMap<String, usize> = rows.iter().fold(Default::default(), |mut m, r| {
        if let Verdict::Refused { code, .. } = &r.verdict {
            *m.entry(format!("{code}")).or_default() += 1;
        }
        m
    });
    println!("{} rows, refusals by code {:?}", rows.len(), refused);
    let mut findings = 0;
    for r in &rows {
        match &r.verdict {
            Verdict::Finding(_) => {
                findings += 1;
                println!("FINDING {:<22} {:<90} {:?}", r.family, r.what, r.verdict);
            }
            Verdict::Review(_) => println!("REVIEW  {:<22} {:<90} {:?}", r.family, r.what, r.verdict),
            _ => {}
        }
    }
    for r in rows.iter().filter(|r| r.family == "E4 ignored byte" || r.family.starts_with("S1")) {
        println!("{:<22} {:<90} {:?}", r.family, r.what, r.verdict);
    }
    assert_eq!(findings, 0, "the engine found something");
}
