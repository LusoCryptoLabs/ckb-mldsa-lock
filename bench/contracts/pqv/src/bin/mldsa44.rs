#![no_std]
#![no_main]
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

use fips204::{ml_dsa_44, traits::{SerDes, Verifier}};

fn verify(pk: &[u8], msg: &[u8; 32], sig: &[u8]) -> bool {
    let (Ok(pk), Ok(sig)) = (<[u8; ml_dsa_44::PK_LEN]>::try_from(pk), <[u8; ml_dsa_44::SIG_LEN]>::try_from(sig)) else {
        return false;
    };
    match ml_dsa_44::PublicKey::try_from_bytes(pk) {
        Ok(pk) => pk.verify(msg, &sig, b""),
        Err(_) => false,
    }
}

fn program_entry() -> i8 {
    pqv::run(ml_dsa_44::PK_LEN, verify)
}
