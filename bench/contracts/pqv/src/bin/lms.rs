#![no_std]
#![no_main]
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

use hbs_lms::Sha256_256;

// LMS/HSS (RFC 8554, NIST SP 800-208), one level. pk = L(4) || LMS pk(56).
fn verify(pk: &[u8], msg: &[u8; 32], sig: &[u8]) -> bool {
    hbs_lms::verify::<Sha256_256>(msg, sig, pk).is_ok()
}

fn program_entry() -> i8 {
    pqv::run(60, verify)
}
