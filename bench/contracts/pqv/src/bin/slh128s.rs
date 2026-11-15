#![no_std]
#![no_main]
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

use fips205::{slh_dsa_sha2_128s, traits::{SerDes, Verifier}};

// Control: the same FIPS 205 code the official Rust lock uses (their table: sha2 128s Rust 21.9M).
fn verify(pk: &[u8], msg: &[u8; 32], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (<[u8; slh_dsa_sha2_128s::PK_LEN]>::try_from(pk), <[u8; slh_dsa_sha2_128s::SIG_LEN]>::try_from(sig)) else {
        return false;
    };
    match slh_dsa_sha2_128s::PublicKey::try_from_bytes(pk) {
        Ok(pk) => pk.verify(msg, &sig, b""),
        Err(_) => false,
    }
}

fn program_entry() -> i8 {
    pqv::run(slh_dsa_sha2_128s::PK_LEN, verify)
}
