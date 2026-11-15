//! Common envelope for the bench locks. Every binary differs only in `verify`.
//! args = blake2b-256(pk) (CKB personalization); witness 0 of the group: WitnessArgs.lock = pk || sig;
//! message = blake2b(tx_hash || len || witness0 with lock zeroed || other group witnesses), like sighash_all.
#![no_std]
extern crate alloc;

// Legacy __sync_* libcalls for bytes::Bytes refcounts (copied from the Wicket vault lock).
mod atomics;

use alloc::vec;
use blake2b_ref::{Blake2b, Blake2bBuilder};
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{bytes::Bytes, packed::{BytesOpt, WitnessArgs}, prelude::*},
    error::SysError,
    high_level::{load_script, load_tx_hash, load_witness, load_witness_args},
};

pub const ERR_ARGS: i8 = 5;
pub const ERR_WITNESS: i8 = 6;
pub const ERR_PUBKEY_HASH: i8 = 7;
pub const ERR_SIGNATURE: i8 = 8;
pub const ERR_SYSCALL: i8 = 9;

pub type Verify = fn(&[u8], &[u8; 32], &[u8]) -> bool;

pub fn blake2b() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"ckb-default-hash").build()
}

pub fn run(pk_len: usize, verify: Verify) -> i8 {
    match inner(pk_len, verify) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

fn inner(pk_len: usize, verify: Verify) -> Result<(), i8> {
    let script = load_script().map_err(|_| ERR_SYSCALL)?;
    let args = script.args().raw_data();
    if args.len() != 32 {
        return Err(ERR_ARGS);
    }
    let wa = load_witness_args(0, Source::GroupInput).map_err(|_| ERR_WITNESS)?;
    let lock = wa.lock().to_opt().ok_or(ERR_WITNESS)?.raw_data();
    if lock.len() <= pk_len {
        return Err(ERR_WITNESS);
    }
    let (pk, sig) = lock.split_at(pk_len);
    let mut pkh = [0u8; 32];
    let mut h = blake2b();
    h.update(pk);
    h.finalize(&mut pkh);
    if pkh[..] != args[..] {
        return Err(ERR_PUBKEY_HASH);
    }
    let msg = sighash_all(&wa, lock.len())?;
    if !verify(pk, &msg, sig) {
        return Err(ERR_SIGNATURE);
    }
    Ok(())
}

fn sighash_all(wa: &WitnessArgs, lock_len: usize) -> Result<[u8; 32], i8> {
    let tx_hash = load_tx_hash().map_err(|_| ERR_SYSCALL)?;
    let zeroed = wa
        .clone()
        .as_builder()
        .lock(BytesOpt::new_builder().set(Some(Bytes::from(vec![0u8; lock_len]).pack())).build())
        .build();
    let mut h = blake2b();
    h.update(&tx_hash);
    let z = zeroed.as_slice();
    h.update(&(z.len() as u64).to_le_bytes());
    h.update(z);
    let mut i = 1;
    loop {
        match load_witness(i, Source::GroupInput) {
            Ok(w) => {
                h.update(&(w.len() as u64).to_le_bytes());
                h.update(&w);
            }
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(ERR_SYSCALL),
        }
        i += 1;
    }
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    Ok(out)
}
