#![no_std]
#![no_main]
ckb_std::entry!(program_entry);
ckb_std::default_alloc!();

// Envelope only (load, pk hash, sighash): the floor every lock pays.
fn program_entry() -> i8 {
    pqv::run(32, |_pk, _msg, _sig| true)
}
