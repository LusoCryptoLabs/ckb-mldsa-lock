#![no_std]
#![no_main]
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

use fn_dsa_vrfy::{VerifyingKey, VerifyingKey1024, DOMAIN_NONE, HASH_ID_RAW};

fn verify(pk: &[u8], msg: &[u8; 32], sig: &[u8]) -> bool {
    match VerifyingKey1024::decode(pk) {
        Some(vk) => vk.verify(sig, &DOMAIN_NONE, &HASH_ID_RAW, msg),
        None => false,
    }
}

fn program_entry() -> i8 {
    pqv::run(1793, verify)
}
