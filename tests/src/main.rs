//! ckb-testtool rows for mldsa-lock: one honest spend per level, then each attack, refused with the
//! code that names its reason. Signing with the Rust fips204 crate here; the devnet run signs with
//! the wallet's JavaScript library.
use ckb_testtool::{
    builtin::ALWAYS_SUCCESS,
    ckb_hash::new_blake2b,
    ckb_types::{
        bytes::Bytes,
        core::{ScriptHashType, TransactionBuilder, TransactionView},
        packed::*,
        prelude::*,
    },
    context::Context,
};
use fips204::traits::{KeyGen, SerDes, Signer};

const MAX_CYCLES: u64 = 70_000_000;
const CKB: u64 = 100_000_000;
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
fn code(e: &str) -> String {
    match e.split("error code ").nth(1) {
        Some(s) => s.chars().take_while(|c| c.is_ascii_digit() || *c == '-').collect(),
        None => e.chars().take(200).collect(),
    }
}

/// A key of one level: public key bytes and a signing function (message, context).
struct Key {
    level: u8,
    pk: Vec<u8>,
    sign: Box<dyn Fn(&[u8], &[u8]) -> Vec<u8>>,
}
macro_rules! key {
    ($m:ident, $lv:expr) => {{
        let (pk, sk) = fips204::$m::KG::try_keygen().unwrap();
        Key { level: $lv, pk: pk.into_bytes().to_vec(), sign: Box::new(move |m: &[u8], c: &[u8]| sk.try_sign(m, c).unwrap().to_vec()) }
    }};
}
fn key(level: u8) -> Key {
    match level {
        0x02 => key!(ml_dsa_44, 0x02),
        0x03 => key!(ml_dsa_65, 0x03),
        _ => key!(ml_dsa_87, 0x05),
    }
}
fn sig_len(level: u8) -> usize {
    match level {
        0x02 => fips204::ml_dsa_44::SIG_LEN,
        0x03 => fips204::ml_dsa_65::SIG_LEN,
        _ => fips204::ml_dsa_87::SIG_LEN,
    }
}

/// The lock's message: blake2b(script hash, tx hash, the group's first witness with its lock bytes
/// zeroed, the group's other witnesses, every witness past the inputs; each witness length-prefixed).
fn message(tx: &TransactionView, script_hash: &[u8], group: &[usize], lock_len: usize) -> [u8; 32] {
    // Controls: a build that leaves a part out is matched by a signer that leaves it out too.
    let no_group = std::env::var("MLDSA_CONTROL_NO_GROUP").is_ok();
    let no_past = std::env::var("MLDSA_CONTROL_NO_PAST").is_ok();
    let no_script = std::env::var("MLDSA_CONTROL_NO_SCRIPT").is_ok();
    let mut h = new_blake2b();
    if !no_script {
        h.update(script_hash);
    }
    h.update(tx.hash().as_slice());
    let w0 = WitnessArgs::new_unchecked(tx.witnesses().get(group[0]).unwrap().raw_data());
    let zeroed = w0.as_builder().lock(Some(Bytes::from(vec![0u8; lock_len])).pack()).build();
    h.update(&(zeroed.as_slice().len() as u64).to_le_bytes());
    h.update(zeroed.as_slice());
    for &i in group[1..].iter().filter(|_| !no_group) {
        if let Some(w) = tx.witnesses().get(i) {
            h.update(&(w.raw_data().len() as u64).to_le_bytes());
            h.update(&w.raw_data());
        }
    }
    let n = tx.inputs().len();
    for i in (n..tx.witnesses().len()).filter(|_| !no_past) {
        let w = tx.witnesses().get(i).unwrap();
        h.update(&(w.raw_data().len() as u64).to_le_bytes());
        h.update(&w.raw_data());
    }
    let mut o = [0u8; 32];
    h.finalize(&mut o);
    o
}

struct Env {
    ctx: Context,
    code: OutPoint,
    always: OutPoint,
    other: Script,
}

impl Env {
    fn new() -> Self {
        let mut ctx = Context::default();
        let code = ctx.deploy_cell(bin());
        let always = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
        let other = ctx.build_script(&always, Bytes::from_static(b"payee")).unwrap();
        Env { ctx, code, always, other }
    }
    fn lock_ht(&mut self, level: u8, pk: &[u8], ht: ScriptHashType) -> Script {
        let args = [&[level][..], &blake(&[pk])[..]].concat();
        self.ctx.build_script_with_hash_type(&self.code, ht, Bytes::from(args)).unwrap()
    }
    fn lock(&mut self, level: u8, pk: &[u8]) -> Script {
        self.lock_ht(level, pk, ScriptHashType::Data2)
    }
    fn cell(&mut self, lock: &Script) -> CellInput {
        let c = self.ctx.create_cell(CellOutput::new_builder().capacity(1_000 * CKB).lock(lock.clone()).build(), Bytes::new());
        CellInput::new_builder().previous_output(c).build()
    }
    /// The given inputs (one empty witness each) to the payee, an extra witness past the inputs when `extra`.
    fn tx_of(&mut self, ins: Vec<CellInput>, extra: bool) -> TransactionView {
        let n = ins.len() as u64;
        let mut b = TransactionBuilder::default();
        for i in ins {
            b = b.input(i).witness(Bytes::new().pack());
        }
        b = b.output(CellOutput::new_builder().capacity(n * 1_000 * CKB - 100_000).lock(self.other.clone()).build()).output_data(Bytes::new().pack());
        if extra {
            b = b.witness(Bytes::from_static(b"a witness past the inputs").pack());
        }
        let tx = b.build();
        self.ctx.complete_tx(tx)
    }
    fn tx(&mut self, lock: &Script, n: usize, extra: bool) -> TransactionView {
        let ins = (0..n).map(|_| self.cell(lock)).collect();
        self.tx_of(ins, extra)
    }
    /// Signs the group `group` (input indices sharing `lock`): placeholder in its first witness (keeping
    /// any input_type/output_type there), message, signature.
    fn sign_group(&self, tx: &TransactionView, k: &Key, lock: &Script, group: &[usize], ctx: &[u8]) -> TransactionView {
        let lock_len = k.pk.len() + sig_len(k.level);
        let mut wits: Vec<Bytes> = tx.witnesses().into_iter().map(|w| w.raw_data()).collect();
        let w0 = if wits[group[0]].is_empty() { WitnessArgs::default() } else { WitnessArgs::new_unchecked(wits[group[0]].clone()) };
        wits[group[0]] = w0.clone().as_builder().lock(Some(Bytes::from(vec![0u8; lock_len])).pack()).build().as_bytes();
        let placeholder = tx.as_advanced_builder().set_witnesses(wits.iter().map(|w| w.pack()).collect()).build();
        let msg = message(&placeholder, lock.calc_script_hash().as_slice(), group, lock_len);
        let sig = (k.sign)(&msg, ctx);
        wits[group[0]] = w0.as_builder().lock(Some(Bytes::from([&k.pk[..], &sig[..]].concat())).pack()).build().as_bytes();
        tx.as_advanced_builder().set_witnesses(wits.iter().map(|w| w.pack()).collect()).build()
    }
    fn sign(&self, tx: &TransactionView, k: &Key, lock: &Script, ctx: &[u8]) -> TransactionView {
        let group: Vec<usize> = (0..tx.inputs().len()).collect();
        self.sign_group(tx, k, lock, &group, ctx)
    }
    fn verify(&self, tx: &TransactionView) -> Result<u64, String> {
        self.ctx.verify_tx(tx, MAX_CYCLES).map_err(|e| e.to_string())
    }
}

fn set_witness(tx: &TransactionView, i: usize, w: Bytes) -> TransactionView {
    let mut wits: Vec<Bytes> = tx.witnesses().into_iter().map(|w| w.raw_data()).collect();
    wits[i] = w;
    tx.as_advanced_builder().set_witnesses(wits.iter().map(|w| w.pack()).collect()).build()
}
fn with_lock(tx: &TransactionView, lock: Bytes) -> TransactionView {
    set_witness(tx, 0, WitnessArgs::new_builder().lock(Some(lock).pack()).build().as_bytes())
}
fn lock_bytes(tx: &TransactionView) -> Vec<u8> {
    WitnessArgs::new_unchecked(tx.witnesses().get(0).unwrap().raw_data()).lock().to_opt().unwrap().raw_data().to_vec()
}

fn expect(name: &str, r: Result<u64, String>, want: &str) -> bool {
    let ok = match (&r, want) {
        (Ok(_), "ok") => true,
        (Err(e), w) if w.starts_with('~') => e.contains(&w[1..]),
        (Err(e), w) if w != "ok" => code(e) == w,
        _ => false,
    };
    let got = match &r {
        Ok(c) => format!("passed, {c} cycles"),
        Err(e) if want.starts_with('~') => format!("refused, {}", e.chars().filter(|c| !c.is_control()).take(140).collect::<String>()),
        Err(e) => format!("refused, code {}", code(e)),
    };
    println!("{} {name:<66} {got}  (want {want})", if ok { "PASS" } else { "FAIL" });
    ok
}

fn main() {
    let mut all = true;
    let mut e = Env::new();
    println!("binary {} bytes", bin().len());

    // One honest spend per level.
    for level in [0x02u8, 0x03, 0x05] {
        let k = key(level);
        let lock = e.lock(level, &k.pk);
        let tx = e.tx(&lock, 1, false);
        let tx = e.sign(&tx, &k, &lock, CONTEXT);
        let wit = tx.witnesses().get(0).unwrap().raw_data().len();
        all &= expect(&format!("level 0x{level:02x}: honest spend, witness {wit} bytes, tx {} bytes", tx.data().as_slice().len()), e.verify(&tx), "ok");
    }

    // Attacks, on ML-DSA-65.
    let k = key(0x03);
    let lock = e.lock(0x03, &k.pk);
    let tx = e.tx(&lock, 1, true);
    let good = e.sign(&tx, &k, &lock, CONTEXT);
    all &= expect("honest spend with a witness past the inputs", e.verify(&good), "ok");

    let mut l = lock_bytes(&good);
    l[k.pk.len() + 100] ^= 1;
    all &= expect("one signature bit flipped", e.verify(&with_lock(&good, Bytes::from(l))), "5");
    let k2 = key(0x03);
    all &= expect("another key's valid signature", e.verify(&e.sign(&tx, &k2, &lock, CONTEXT)), "4");
    all &= expect("signed with no context", e.verify(&e.sign(&tx, &k, &lock, b"")), "5");
    all &= expect("signed with another context", e.verify(&e.sign(&tx, &k, &lock, b"CKB-MLDSA-LOCK2")), "5");
    all &= expect("a witness past the inputs changed after signing", e.verify(&set_witness(&good, 1, Bytes::from_static(b"changed"))), "5");
    let out = good.as_advanced_builder().set_outputs(vec![CellOutput::new_builder().capacity(999 * CKB).lock(e.other.clone()).build()]).build();
    all &= expect("an output changed after signing", e.verify(&out), "5");

    let mut longer = lock_bytes(&good);
    longer.push(0);
    all &= expect("one byte appended to the lock field", e.verify(&with_lock(&good, Bytes::from(longer))), "3");
    let mut shorter = lock_bytes(&good);
    shorter.pop();
    all &= expect("one byte cut from the lock field", e.verify(&with_lock(&good, Bytes::from(shorter))), "3");
    let k44 = key(0x02);
    let as65 = e.lock(0x03, &k44.pk);
    let t44 = e.tx(&as65, 1, false);
    all &= expect("an ML-DSA-44 key and signature under a level 65 address", e.verify(&e.sign(&t44, &k44, &as65, CONTEXT)), "3");
    for (name, args, want) in [("args with an unknown level 0x04", [&[0x04u8][..], &blake(&[&k.pk])[..]].concat(), "2"), ("args one byte short", blake(&[&k.pk]).to_vec(), "2")] {
        let s = e.ctx.build_script_with_hash_type(&e.code, ScriptHashType::Data2, Bytes::from(args)).unwrap();
        let t = e.tx(&s, 1, false);
        all &= expect(name, e.verify(&e.sign(&t, &k, &s, CONTEXT)), want);
    }
    let none = with_lock(&e.tx(&lock, 1, false), Bytes::new());
    all &= expect("an empty lock field", e.verify(&none), "3");

    // Groups.
    let t2 = e.tx(&lock, 2, false);
    let s2 = e.sign(&t2, &k, &lock, CONTEXT);
    all &= expect("two cells of the same lock, one signature", e.verify(&s2), "ok");
    all &= expect("the group's second witness changed after signing", e.verify(&set_witness(&s2, 1, Bytes::from_static(b"x"))), "5");

    // Review of 2026-11-14: the gaps it listed.
    let wa = WitnessArgs::new_unchecked(good.witnesses().get(0).unwrap().raw_data());
    let it = wa.as_builder().input_type(Some(Bytes::from_static(b"added")).pack()).build();
    all &= expect("R: the first witness's input_type changed after signing", e.verify(&set_witness(&good, 0, it.as_bytes())), "5");
    {
        let other_in = {
            let s = e.ctx.build_script(&e.always, Bytes::from_static(b"someone")).unwrap();
            e.cell(&s)
        };
        let mine = e.cell(&lock);
        let t = e.tx_of(vec![other_in, mine], false);
        all &= expect("R: the group starting at input 1", e.verify(&e.sign_group(&t, &k, &lock, &[1], CONTEXT)), "ok");
    }
    {
        let mine = e.cell(&lock);
        let t = e.tx_of(vec![mine], false).as_advanced_builder().set_witnesses(vec![]).build();
        all &= expect("R: no witness at all for the group's first input", e.verify(&t), "3");
    }
    {
        // A WitnessArgs with a fourth field: header 20 bytes, four offsets.
        let l = lock_bytes(&good);
        let mut w = Vec::new();
        let lock_field = [&(l.len() as u32).to_le_bytes()[..], &l[..]].concat();
        let total = 20 + lock_field.len();
        w.extend_from_slice(&(total as u32).to_le_bytes());
        w.extend_from_slice(&20u32.to_le_bytes());
        for _ in 0..3 {
            w.extend_from_slice(&(total as u32).to_le_bytes());
        }
        w.extend_from_slice(&lock_field);
        all &= expect("R: a WitnessArgs with a fourth field", e.verify(&set_witness(&good, 0, Bytes::from(w))), "3");
    }
    {
        let kb = key(0x03);
        let lb = e.lock(0x03, &kb.pk);
        let a = e.cell(&lock);
        let b = e.cell(&lb);
        let t = e.tx_of(vec![a, b], false);
        let t = e.sign_group(&t, &k, &lock, &[0], CONTEXT);
        let t = e.sign_group(&t, &kb, &lb, &[1], CONTEXT);
        all &= expect("R: two ML-DSA groups of two keys in one transaction", e.verify(&t), "ok");
    }
    {
        let l1 = e.lock_ht(0x03, &k.pk, ScriptHashType::Data1);
        let t = e.tx(&l1, 1, false);
        all &= expect("R: the lock referenced as data1", e.verify(&e.sign(&t, &k, &l1, CONTEXT)), "ok");
        let l0 = e.lock_ht(0x03, &k.pk, ScriptHashType::Data);
        let t = e.tx(&l0, 1, false);
        all &= expect("R: the lock referenced as data (VM0, no B extension)", e.verify(&e.sign(&t, &k, &l0, CONTEXT)), "~VM Internal Error");
    }
    {
        // One cell under data2, one under data1, same code and args: group {0} signed, its witness copied to 1.
        let l1 = e.lock_ht(0x03, &k.pk, ScriptHashType::Data1);
        let a = e.cell(&lock);
        let b = e.cell(&l1);
        let t = e.tx_of(vec![a, b], false);
        let t = e.sign_group(&t, &k, &lock, &[0], CONTEXT);
        let t = set_witness(&t, 1, t.witnesses().get(0).unwrap().raw_data());
        all &= expect("R: one signature copied onto the same key under data1", e.verify(&t), "5");
    }
    for kib in [120usize, 200] {
        let mine = e.cell(&lock);
        let t = e.tx_of(vec![mine], false);
        let big = WitnessArgs::new_builder().input_type(Some(Bytes::from(vec![7u8; kib * 1024])).pack()).build();
        let t = set_witness(&t, 0, big.as_bytes());
        all &= expect(&format!("R: a {kib} KiB input_type in the first witness, honest"), e.verify(&e.sign(&t, &k, &lock, CONTEXT)), "ok");
    }

    println!("{}", if all { "ALL AS EXPECTED" } else { "SOMETHING DID NOT BEHAVE" });
}
