//! `mldsa-lock`: a CKB lock that opens with an ML-DSA (FIPS 204) signature over the transaction.
//!
//! args    = level (1 byte: 0x02 ML-DSA-44, 0x03 ML-DSA-65, 0x05 ML-DSA-87, the NIST categories)
//!           || blake2b-256(public key) (32 bytes, CKB personalization)
//! witness = the group's first WitnessArgs, `lock` = public key || signature, each of exactly the
//!           level's size
//! message = CKB sighash_all, as the secp256k1 lock computes it: blake2b(tx hash, then the group's
//!           first witness with its lock bytes zeroed, then the group's other witnesses, then every
//!           witness past the inputs, each preceded by its length as u64 little-endian)
//! context = "CKB-MLDSA-LOCK" (FIPS 204 domain separation: a signature made here means nothing
//!           to another protocol, and one made elsewhere means nothing here)
//!
//! One signature opens every input of the group. Error codes: 1 syscall, 2 args, 3 witness,
//! 4 public key hash, 5 signature.
#![no_std]
#![no_main]

mod atomics;

use alloc::vec::Vec;
use blake2b_ref::{Blake2b, Blake2bBuilder};
use ckb_std::{
    ckb_constants::Source,
    ckb_types::{packed::WitnessArgs, prelude::*},
    error::SysError,
    high_level::{load_input_since, load_script, load_tx_hash, load_witness},
    syscalls,
};
use fips204::traits::{SerDes, Verifier};

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

const ERR_SYSCALL: i8 = 1;
const ERR_ARGS: i8 = 2;
const ERR_WITNESS: i8 = 3;
const ERR_PUBKEY_HASH: i8 = 4;
const ERR_SIGNATURE: i8 = 5;

pub const CONTEXT: &[u8] = b"CKB-MLDSA-LOCK";

fn blake2b() -> Blake2b {
    Blake2bBuilder::new(32).personal(b"ckb-default-hash").build()
}

fn program_entry() -> i8 {
    match run() {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// (public key length, signature length) of a level.
fn sizes(level: u8) -> Result<(usize, usize), i8> {
    match level {
        0x02 => Ok((fips204::ml_dsa_44::PK_LEN, fips204::ml_dsa_44::SIG_LEN)),
        0x03 => Ok((fips204::ml_dsa_65::PK_LEN, fips204::ml_dsa_65::SIG_LEN)),
        0x05 => Ok((fips204::ml_dsa_87::PK_LEN, fips204::ml_dsa_87::SIG_LEN)),
        _ => Err(ERR_ARGS),
    }
}

macro_rules! verify_level {
    ($m:ident, $pk:expr, $msg:expr, $sig:expr) => {{
        let (Ok(pk), Ok(sig)) = (<[u8; fips204::$m::PK_LEN]>::try_from($pk), <[u8; fips204::$m::SIG_LEN]>::try_from($sig)) else {
            return false;
        };
        match fips204::$m::PublicKey::try_from_bytes(pk) {
            Ok(pk) => pk.verify($msg, &sig, CONTEXT),
            Err(_) => false,
        }
    }};
}

fn verify(level: u8, pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
    match level {
        0x02 => verify_level!(ml_dsa_44, pk, msg, sig),
        0x03 => verify_level!(ml_dsa_65, pk, msg, sig),
        0x05 => verify_level!(ml_dsa_87, pk, msg, sig),
        _ => false,
    }
}

fn run() -> Result<(), i8> {
    let script = load_script().map_err(|_| ERR_SYSCALL)?;
    let args = script.args().raw_data();
    if args.len() != 33 {
        return Err(ERR_ARGS);
    }
    let level = args[0];
    let (pk_len, sig_len) = sizes(level)?;

    let first: Vec<u8> = load_witness(0, Source::GroupInput).map_err(|_| ERR_WITNESS)?;
    let wa = WitnessArgs::from_slice(&first).map_err(|_| ERR_WITNESS)?;
    let lock = wa.lock().to_opt().ok_or(ERR_WITNESS)?.raw_data();
    if lock.len() != pk_len + sig_len {
        return Err(ERR_WITNESS);
    }
    let (pk, sig) = lock.split_at(pk_len);

    let mut pkh = [0u8; 32];
    let mut h = blake2b();
    h.update(pk);
    h.finalize(&mut pkh);
    if pkh[..] != args[1..] {
        return Err(ERR_PUBKEY_HASH);
    }

    let msg = sighash_all(&first, lock.len())?;
    if !verify(level, pk, &msg, sig) {
        return Err(ERR_SIGNATURE);
    }
    Ok(())
}

/// The group's first witness with the bytes of its `lock` field set to zero (same length), as the
/// signer saw it. WitnessArgs is a molecule table: total size, then one u32 offset per field; `lock`
/// is a BytesOpt whose content is a u32 length then the bytes.
fn zero_lock(witness: &[u8], lock_len: usize) -> Result<Vec<u8>, i8> {
    let rd = |o: usize| -> Result<usize, i8> {
        let b = witness.get(o..o + 4).ok_or(ERR_WITNESS)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
    };
    let lock_start = rd(4)?;
    let lock_end = rd(8)?;
    // A present lock field: 4 length bytes then exactly lock_len bytes.
    if lock_end != lock_start + 4 + lock_len || rd(lock_start)? != lock_len {
        return Err(ERR_WITNESS);
    }
    let mut z = witness.to_vec();
    for b in &mut z[lock_start + 4..lock_end] {
        *b = 0;
    }
    Ok(z)
}

const CHUNK: usize = 4096;

/// Hashes `len (u64 LE) || witness` for a witness read in 4 KB pieces, so a large witness never has
/// to sit in the heap whole. IndexOutOfBound when the witness does not exist.
fn hash_witness(h: &mut Blake2b, index: usize, source: Source) -> Result<(), SysError> {
    let mut buf = [0u8; CHUNK];
    let total = match syscalls::load_witness(&mut buf, 0, index, source) {
        Ok(n) => n,
        Err(SysError::LengthNotEnough(n)) => n,
        Err(e) => return Err(e),
    };
    h.update(&(total as u64).to_le_bytes());
    let mut off = 0;
    while off < total {
        let n = core::cmp::min(CHUNK, total - off);
        match syscalls::load_witness(&mut buf, off, index, source) {
            Ok(_) | Err(SysError::LengthNotEnough(_)) => {}
            Err(e) => return Err(e),
        }
        h.update(&buf[..n]);
        off += n;
    }
    Ok(())
}

fn sighash_all(first: &[u8], lock_len: usize) -> Result<[u8; 32], i8> {
    let tx_hash = load_tx_hash().map_err(|_| ERR_SYSCALL)?;
    let zeroed = zero_lock(first, lock_len)?;
    let mut h = blake2b();
    h.update(&tx_hash);
    h.update(&(zeroed.len() as u64).to_le_bytes());
    h.update(&zeroed);
    // The group's other witnesses.
    let mut i = 1;
    loop {
        match hash_witness(&mut h, i, Source::GroupInput) {
            Ok(()) => i += 1,
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(ERR_SYSCALL),
        }
    }
    // Every witness past the inputs.
    let mut inputs = 0;
    while load_input_since(inputs, Source::Input).is_ok() {
        inputs += 1;
    }
    let mut i = inputs;
    loop {
        match hash_witness(&mut h, i, Source::Input) {
            Ok(()) => i += 1,
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(ERR_SYSCALL),
        }
    }
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    Ok(out)
}
