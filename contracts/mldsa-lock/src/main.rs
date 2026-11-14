//! `mldsa-lock`: a CKB lock that opens with an ML-DSA (FIPS 204) signature over the transaction.
//!
//! args    = level (1 byte: 0x02 ML-DSA-44, 0x03 ML-DSA-65, 0x05 ML-DSA-87, the NIST categories)
//!           || blake2b-256(public key) (32 bytes, CKB personalization)
//! witness = the group's first WitnessArgs, `lock` = public key || signature, each of exactly the
//!           level's size
//! message = blake2b(this lock script's hash, then CKB sighash_all as the secp256k1 lock computes
//!           it: the tx hash, the group's first witness with its lock bytes zeroed, the group's other
//!           witnesses, every witness past the inputs, each preceded by its length as u64 LE). The
//!           script hash in front ties a signature to this exact lock (code, hash type, args), so it
//!           cannot open a cell of the same key under another hash type or another deployment.
//! context = "CKB-MLDSA-LOCK" (FIPS 204 domain separation)
//!
//! Every witness is read in 4 KB pieces, the first one too (its lock bytes zeroed on the way), so a
//! large witness never has to fit in the heap. One signature opens every input of the group.
//! Error codes: 1 syscall, 2 args, 3 witness, 4 public key hash, 5 signature.
//! Reference the code with hash type data1, data2 or type. Under data (VM0) it never opens: the VM
//! stops it before the script runs (measured 2026-11-14: MemWriteOnExecutablePage).
#![no_std]
#![no_main]

mod atomics;

use alloc::vec;
use blake2b_ref::{Blake2b, Blake2bBuilder};
use ckb_std::{
    ckb_constants::Source,
    error::SysError,
    high_level::{load_input_since, load_script, load_script_hash, load_tx_hash},
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
const CHUNK: usize = 4096;

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

/// Total length of witness `index`, or the error (IndexOutOfBound when it does not exist).
fn witness_len(index: usize, source: Source) -> Result<usize, SysError> {
    let mut probe = [0u8; 0];
    match syscalls::load_witness(&mut probe, 0, index, source) {
        Ok(n) => Ok(n),
        Err(SysError::LengthNotEnough(n)) => Ok(n),
        Err(e) => Err(e),
    }
}

/// Exactly `buf.len()` bytes of witness `index` from `offset`.
fn read_at(buf: &mut [u8], offset: usize, index: usize, source: Source) -> Result<(), i8> {
    match syscalls::load_witness(buf, offset, index, source) {
        Ok(n) if n == buf.len() => Ok(()),
        Err(SysError::LengthNotEnough(n)) if n >= buf.len() => Ok(()),
        _ => Err(ERR_WITNESS),
    }
}

fn u32_at(index: usize, offset: usize) -> Result<usize, i8> {
    let mut b = [0u8; 4];
    read_at(&mut b, offset, index, Source::GroupInput)?;
    Ok(u32::from_le_bytes(b) as usize)
}

/// The group's first witness as a WitnessArgs, checked as strictly as molecule does, without loading
/// it whole: total size, three field offsets (the first at 16, in order, within the total), a present
/// lock (a u32 length then exactly that many bytes), and input_type/output_type empty or a u32 length
/// then exactly that many bytes. Returns (total length, start and end of the lock bytes).
fn first_witness_layout() -> Result<(usize, usize, usize), i8> {
    let total = witness_len(0, Source::GroupInput).map_err(|_| ERR_WITNESS)?;
    if total < 16 {
        return Err(ERR_WITNESS);
    }
    let (size, o_lock, o_in, o_out) = (u32_at(0, 0)?, u32_at(0, 4)?, u32_at(0, 8)?, u32_at(0, 12)?);
    if size != total || o_lock != 16 || o_lock > o_in || o_in > o_out || o_out > total {
        return Err(ERR_WITNESS);
    }
    // lock: must be present
    if o_in - o_lock < 4 || u32_at(0, o_lock)? != o_in - o_lock - 4 {
        return Err(ERR_WITNESS);
    }
    // input_type and output_type: absent, or a well-formed Bytes
    for (start, end) in [(o_in, o_out), (o_out, total)] {
        if end > start && (end - start < 4 || u32_at(0, start)? != end - start - 4) {
            return Err(ERR_WITNESS);
        }
    }
    Ok((total, o_lock + 4, o_in))
}

/// `len (u64 LE) || witness` for witness `index`, read in pieces; bytes in [zero_from, zero_to) hashed
/// as zeros. IndexOutOfBound when the witness does not exist.
fn hash_witness(h: &mut Blake2b, index: usize, source: Source, zero_from: usize, zero_to: usize) -> Result<(), SysError> {
    let total = witness_len(index, source)?;
    h.update(&(total as u64).to_le_bytes());
    let mut buf = [0u8; CHUNK];
    let mut off = 0;
    while off < total {
        let n = core::cmp::min(CHUNK, total - off);
        match syscalls::load_witness(&mut buf, off, index, source) {
            Ok(_) | Err(SysError::LengthNotEnough(_)) => {}
            Err(e) => return Err(e),
        }
        for (k, b) in buf[..n].iter_mut().enumerate() {
            let p = off + k;
            if p >= zero_from && p < zero_to {
                *b = 0;
            }
        }
        h.update(&buf[..n]);
        off += n;
    }
    Ok(())
}

fn run() -> Result<(), i8> {
    let script = load_script().map_err(|_| ERR_SYSCALL)?;
    let args = script.args().raw_data();
    if args.len() != 33 {
        return Err(ERR_ARGS);
    }
    let level = args[0];
    let (pk_len, sig_len) = sizes(level)?;

    let (_, lock_from, lock_to) = first_witness_layout()?;
    if lock_to - lock_from != pk_len + sig_len {
        return Err(ERR_WITNESS);
    }
    let mut lock = vec![0u8; pk_len + sig_len];
    read_at(&mut lock, lock_from, 0, Source::GroupInput)?;
    let (pk, sig) = lock.split_at(pk_len);

    let mut pkh = [0u8; 32];
    let mut h = blake2b();
    h.update(pk);
    h.finalize(&mut pkh);
    if pkh[..] != args[1..] {
        return Err(ERR_PUBKEY_HASH);
    }

    let msg = message(lock_from, lock_to)?;
    if !verify(level, pk, &msg, sig) {
        return Err(ERR_SIGNATURE);
    }
    Ok(())
}

fn message(lock_from: usize, lock_to: usize) -> Result<[u8; 32], i8> {
    let mut h = blake2b();
    h.update(&load_script_hash().map_err(|_| ERR_SYSCALL)?);
    h.update(&load_tx_hash().map_err(|_| ERR_SYSCALL)?);
    hash_witness(&mut h, 0, Source::GroupInput, lock_from, lock_to).map_err(|_| ERR_WITNESS)?;
    // The group's other witnesses.
    let mut i = 1;
    loop {
        match hash_witness(&mut h, i, Source::GroupInput, 0, 0) {
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
        match hash_witness(&mut h, i, Source::Input, 0, 0) {
            Ok(()) => i += 1,
            Err(SysError::IndexOutOfBound) => break,
            Err(_) => return Err(ERR_SYSCALL),
        }
    }
    let mut out = [0u8; 32];
    h.finalize(&mut out);
    Ok(out)
}
