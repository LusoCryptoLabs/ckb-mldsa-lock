//! Test only, never deployed: the same fips204 verification the lock runs, built the same way for
//! CKB-VM, with the context and message taken from witness 0 instead of the transaction:
//! level (1) || context length (1) || context || public key || signature || message.
//! Exit 0 when the signature verifies, 5 when it does not, 3 on a malformed witness.
#![no_std]
#![no_main]

mod atomics;

use ckb_std::{ckb_constants::Source, high_level::load_witness};
use fips204::traits::{SerDes, Verifier};

ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

macro_rules! verify_level {
    ($m:ident, $w:expr, $ctx:expr) => {{
        let w: &[u8] = $w;
        if w.len() < fips204::$m::PK_LEN + fips204::$m::SIG_LEN {
            return 3;
        }
        let (pk, rest) = w.split_at(fips204::$m::PK_LEN);
        let (sig, msg) = rest.split_at(fips204::$m::SIG_LEN);
        let (Ok(pk), Ok(sig)) = (<[u8; fips204::$m::PK_LEN]>::try_from(pk), <[u8; fips204::$m::SIG_LEN]>::try_from(sig)) else {
            return 3;
        };
        match fips204::$m::PublicKey::try_from_bytes(pk) {
            Ok(pk) if pk.verify(msg, &sig, $ctx) => 0,
            _ => 5,
        }
    }};
}

fn program_entry() -> i8 {
    let Ok(w) = load_witness(0, Source::Input) else { return 3 };
    if w.len() < 2 || w.len() < 2 + w[1] as usize {
        return 3;
    }
    let (level, n) = (w[0], w[1] as usize);
    let ctx = &w[2..2 + n];
    let rest = &w[2 + n..];
    match level {
        0x02 => verify_level!(ml_dsa_44, rest, ctx),
        0x03 => verify_level!(ml_dsa_65, rest, ctx),
        0x05 => verify_level!(ml_dsa_87, rest, ctx),
        _ => 3,
    }
}
