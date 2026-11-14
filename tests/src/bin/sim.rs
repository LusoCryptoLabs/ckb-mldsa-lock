//! Simulations for mldsa-lock, on ckb-testtool's CKB-VM.
//!   sim kat <vectors.json>     NIST ACVP ML-DSA sigVer, external pure: the verifier must agree with NIST
//!   sim cross <corpus.jsonl>   signatures from the wallet's JS library and changed copies: must agree with it
//!   sim txs <n>                random transactions under the real lock: each honest one passes, each
//!                              with one random change fails
//!   sim junk <n>               random signatures and witnesses: none passes, every refusal is 3, 4 or 5
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
use rand::{seq::SliceRandom, Rng};

const MAX_CYCLES: u64 = 70_000_000;
const CKB: u64 = 100_000_000;
const CONTEXT: &[u8] = b"CKB-MLDSA-LOCK";

fn dir() -> String {
    std::env::var("MLDSA_BIN").unwrap_or_else(|_| "/root/mldsa/target/riscv64imac-unknown-none-elf/release".into())
}
fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
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
/// Ok(cycles), or Err(script exit code), or Err(i64::MIN) for anything that is not a script exit code.
fn outcome(ctx: &Context, tx: &TransactionView) -> Result<u64, i64> {
    ctx.verify_tx(tx, MAX_CYCLES).map_err(|e| {
        let s = e.to_string();
        s.split("error code ").nth(1).and_then(|x| x.split(|c: char| !c.is_ascii_digit() && c != '-').next()).and_then(|x| x.parse().ok()).unwrap_or(i64::MIN)
    })
}

/// Runs one (level, ctx, pk, sig, msg) through the test-only verifier on CKB-VM: true when it verifies.
struct Kat {
    ctx: Context,
    lock: Script,
}
impl Kat {
    fn new() -> Self {
        let mut ctx = Context::default();
        let code = ctx.deploy_cell(std::fs::read(format!("{}/mldsa-kat", dir())).unwrap().into());
        let lock = ctx.build_script_with_hash_type(&code, ScriptHashType::Data2, Bytes::new()).unwrap();
        Kat { ctx, lock }
    }
    fn verify(&mut self, level: u8, ctx: &[u8], pk: &[u8], sig: &[u8], msg: &[u8]) -> Result<bool, String> {
        let w = [&[level, ctx.len() as u8][..], ctx, pk, sig, msg].concat();
        let c = self.ctx.create_cell(CellOutput::new_builder().capacity(1_000 * CKB).lock(self.lock.clone()).build(), Bytes::new());
        let tx = TransactionBuilder::default()
            .input(CellInput::new_builder().previous_output(c).build())
            .output(CellOutput::new_builder().capacity(999 * CKB).build())
            .output_data(Bytes::new().pack())
            .witness(Bytes::from(w).pack())
            .build();
        let tx = self.ctx.complete_tx(tx);
        match outcome(&self.ctx, &tx) {
            Ok(_) => Ok(true),
            Err(5) => Ok(false),
            Err(c) => Err(format!("exit {c}")),
        }
    }
}

fn kat(path: &str) {
    let v: Vec<serde_json::Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut k = Kat::new();
    let (mut agree, mut disagree) = (0, 0);
    for t in &v {
        let level = t["level"].as_u64().unwrap() as u8;
        let got = k.verify(level, &unhex(t["ctx"].as_str().unwrap()), &unhex(t["pk"].as_str().unwrap()), &unhex(t["sig"].as_str().unwrap()), &unhex(t["msg"].as_str().unwrap()));
        let want = t["pass"].as_bool().unwrap();
        if got == Ok(want) {
            agree += 1;
        } else {
            disagree += 1;
            println!("DISAGREE level {level} want {want} got {got:?} ({})", t["reason"]);
        }
    }
    println!("NIST vectors: {} run, {agree} agree with NIST, {disagree} disagree", v.len());
}

fn cross(path: &str) {
    let text = std::fs::read_to_string(path).unwrap();
    let mut k = Kat::new();
    let (mut n, mut agree, mut valid) = (0, 0, 0);
    let mut bad = Vec::new();
    for line in text.lines().filter(|l| !l.is_empty()) {
        let t: serde_json::Value = serde_json::from_str(line).unwrap();
        let level = t["level"].as_u64().unwrap() as u8;
        let want = t["expect"].as_bool().unwrap();
        let got = k.verify(level, &unhex(t["ctx"].as_str().unwrap()), &unhex(t["pk"].as_str().unwrap()), &unhex(t["sig"].as_str().unwrap()), &unhex(t["msg"].as_str().unwrap()));
        n += 1;
        if got == Ok(want) {
            agree += 1;
            valid += want as usize;
        } else {
            bad.push(format!("line {n}: level {level} js says {want}, lock says {got:?}"));
        }
    }
    for b in bad.iter().take(10) {
        println!("DISAGREE {b}");
    }
    println!("cross check: {n} lines, {agree} agree with the JS library ({valid} valid), {} disagree", bad.len());
}

/// A key of a random level for the real lock.
struct Key {
    level: u8,
    pk: Vec<u8>,
    sig_len: usize,
    sign: Box<dyn Fn(&[u8]) -> Vec<u8>>,
}
macro_rules! key {
    ($m:ident, $lv:expr) => {{
        let (pk, sk) = fips204::$m::KG::try_keygen().unwrap();
        Key { level: $lv, pk: pk.into_bytes().to_vec(), sig_len: fips204::$m::SIG_LEN, sign: Box::new(move |m: &[u8]| sk.try_sign(m, CONTEXT).unwrap().to_vec()) }
    }};
}
fn random_key(r: &mut impl Rng) -> Key {
    match r.gen_range(0..3) {
        0 => key!(ml_dsa_44, 0x02),
        1 => key!(ml_dsa_65, 0x03),
        _ => key!(ml_dsa_87, 0x05),
    }
}
fn rand_bytes(r: &mut impl Rng, n: usize) -> Bytes {
    let mut v = vec![0u8; n];
    r.fill(&mut v[..]);
    Bytes::from(v)
}

fn message(tx: &TransactionView, script_hash: &[u8], group: &[usize], lock_len: usize) -> [u8; 32] {
    let mut h = new_blake2b();
    h.update(script_hash);
    h.update(tx.hash().as_slice());
    let w0 = WitnessArgs::new_unchecked(tx.witnesses().get(group[0]).unwrap().raw_data());
    let zeroed = w0.as_builder().lock(Some(Bytes::from(vec![0u8; lock_len])).pack()).build();
    h.update(&(zeroed.as_slice().len() as u64).to_le_bytes());
    h.update(zeroed.as_slice());
    for &i in &group[1..] {
        if let Some(w) = tx.witnesses().get(i) {
            h.update(&(w.raw_data().len() as u64).to_le_bytes());
            h.update(&w.raw_data());
        }
    }
    for i in tx.inputs().len()..tx.witnesses().len() {
        let w = tx.witnesses().get(i).unwrap();
        h.update(&(w.raw_data().len() as u64).to_le_bytes());
        h.update(&w.raw_data());
    }
    let mut o = [0u8; 32];
    h.finalize(&mut o);
    o
}

fn txs(n: usize) {
    let mut r = rand::thread_rng();
    let mut ctx = Context::default();
    let code = ctx.deploy_cell(std::fs::read(format!("{}/mldsa-lock", dir())).unwrap().into());
    let always = ctx.deploy_cell(ALWAYS_SUCCESS.clone());
    let (mut honest_ok, mut changed_refused, mut max_cycles) = (0usize, 0usize, 0u64);
    let mut problems = Vec::new();
    let mut kinds = std::collections::BTreeMap::<&str, usize>::new();
    for it in 0..n {
        let k = random_key(&mut r);
        let ht = if r.gen_bool(0.5) { ScriptHashType::Data2 } else { ScriptHashType::Data1 };
        let lock = ctx.build_script_with_hash_type(&code, ht, Bytes::from([&[k.level][..], &blake(&[&k.pk])[..]].concat())).unwrap();
        let other = ctx.build_script(&always, rand_bytes(&mut r, 8)).unwrap();
        // inputs: g cells of the lock and o others, shuffled
        let (g, o) = (r.gen_range(1..=4), r.gen_range(0..=2));
        let mut kinds_in: Vec<bool> = (0..g).map(|_| true).chain((0..o).map(|_| false)).collect();
        kinds_in.shuffle(&mut r);
        let mut b = TransactionBuilder::default();
        let mut total = 0u64;
        let mut group = Vec::new();
        for (i, mine) in kinds_in.iter().enumerate() {
            let cap = r.gen_range(200..2_000) * CKB;
            total += cap;
            let c = ctx.create_cell(CellOutput::new_builder().capacity(cap).lock(if *mine { lock.clone() } else { other.clone() }).build(), Bytes::new());
            b = b.input(CellInput::new_builder().previous_output(c).since(if r.gen_bool(0.2) { r.gen::<u32>() as u64 } else { 0 }).build());
            if *mine {
                group.push(i);
            }
        }
        // outputs
        let outs = r.gen_range(1..=3);
        let mut left = total - 100_000;
        for j in 0..outs {
            let cap = if j + 1 == outs { left } else { left / 2 };
            left -= cap;
            let dn = if r.gen_bool(0.3) { r.gen_range(0..512) } else { 0 };
            let data = rand_bytes(&mut r, dn);
            b = b.output(CellOutput::new_builder().capacity(cap).lock(other.clone()).build()).output_data(data.pack());
        }
        // witnesses: one per input; the group's first may carry input_type / output_type; some past the inputs
        let lock_len = k.pk.len() + k.sig_len;
        let mut wits: Vec<Bytes> = Vec::new();
        for (i, mine) in kinds_in.iter().enumerate() {
            if *mine && i == group[0] {
                let mut wa = WitnessArgs::new_builder().lock(Some(Bytes::from(vec![0u8; lock_len])).pack());
                if r.gen_bool(0.3) {
                    let sz = if r.gen_bool(0.1) { 64 * 1024 } else { r.gen_range(0..2048) };
                    wa = wa.input_type(Some(rand_bytes(&mut r, sz)).pack());
                }
                if r.gen_bool(0.2) {
                    let n = r.gen_range(0..512);
                    wa = wa.output_type(Some(rand_bytes(&mut r, n)).pack());
                }
                wits.push(wa.build().as_bytes());
            } else {
                let sz = if r.gen_bool(0.5) { 0 } else { r.gen_range(0..256) };
                wits.push(rand_bytes(&mut r, sz));
            }
        }
        for _ in 0..r.gen_range(0..=3) {
            let sz = r.gen_range(0..4096);
            wits.push(rand_bytes(&mut r, sz));
        }
        let tx = ctx.complete_tx(b.witnesses(wits.iter().map(|w| w.pack()).collect::<Vec<_>>()).build());
        let msg = message(&tx, lock.calc_script_hash().as_slice(), &group, lock_len);
        let sig = (k.sign)(&msg);
        let w0 = WitnessArgs::new_unchecked(wits[group[0]].clone()).as_builder().lock(Some(Bytes::from([&k.pk[..], &sig[..]].concat())).pack()).build();
        wits[group[0]] = w0.as_bytes();
        let tx = tx.as_advanced_builder().set_witnesses(wits.iter().map(|w| w.pack()).collect()).build();
        match outcome(&ctx, &tx) {
            Ok(c) => {
                honest_ok += 1;
                max_cycles = max_cycles.max(c);
            }
            Err(c) => problems.push(format!("tx {it}: honest refused with {c}")),
        }
        // one random change, in something the signature covers
        let n_in = kinds_in.len();
        let covered_wits: Vec<usize> = (0..wits.len()).filter(|&i| i >= n_in || group.contains(&i)).collect();
        let (kind, changed): (&str, TransactionView) = match r.gen_range(0..7) {
            0 => {
                let i = *covered_wits.choose(&mut r).unwrap();
                let mut w = wits.clone();
                let mut v = w[i].to_vec();
                if v.is_empty() {
                    v.push(1)
                } else {
                    let p = r.gen_range(0..v.len());
                    v[p] ^= 1 << r.gen_range(0..8)
                }
                w[i] = Bytes::from(v);
                ("a bit of a covered witness", tx.as_advanced_builder().set_witnesses(w.iter().map(|x| x.pack()).collect()).build())
            }
            1 => {
                let mut o: Vec<CellOutput> = tx.outputs().into_iter().collect();
                let i = r.gen_range(0..o.len());
                let c: u64 = o[i].capacity().unpack();
                o[i] = o[i].clone().as_builder().capacity(c - 1).build();
                ("an output 1 shannon smaller", tx.as_advanced_builder().set_outputs(o).build())
            }
            2 => {
                let mut d: Vec<Bytes> = tx.outputs_data().into_iter().map(|x| x.raw_data()).collect();
                let i = r.gen_range(0..d.len());
                let mut v = d[i].to_vec();
                v.push(7);
                d[i] = Bytes::from(v);
                ("output data one byte longer", tx.as_advanced_builder().set_outputs_data(d.iter().map(|x| x.pack()).collect()).build())
            }
            3 => ("one more output", tx.as_advanced_builder().output(CellOutput::new_builder().capacity(61 * CKB).lock(other.clone()).build()).output_data(Bytes::new().pack()).build()),
            4 => {
                let mut ins: Vec<CellInput> = tx.inputs().into_iter().collect();
                let i = r.gen_range(0..ins.len());
                let s: u64 = ins[i].since().unpack();
                ins[i] = ins[i].clone().as_builder().since(s ^ 1).build();
                ("an input's since", tx.as_advanced_builder().set_inputs(ins).build())
            }
            5 => {
                let mut w = wits.clone();
                w.push(Bytes::from_static(b"x"));
                ("one more witness past the inputs", tx.as_advanced_builder().set_witnesses(w.iter().map(|x| x.pack()).collect()).build())
            }
            _ => ("a header dep added", {
                let h = ckb_testtool::ckb_types::core::HeaderBuilder::default().number(Pack::<Uint64>::pack(&(it as u64 + 1))).build();
                ctx.insert_header(h.clone());
                tx.as_advanced_builder().header_dep(h.hash()).build()
            }),
        };
        *kinds.entry(kind).or_default() += 1;
        match outcome(&ctx, &changed) {
            Ok(_) => problems.push(format!("tx {it}: {kind} was ACCEPTED")),
            Err(3) | Err(4) | Err(5) => changed_refused += 1,
            Err(c) => problems.push(format!("tx {it}: {kind} refused with an unexpected {c}")),
        }
    }
    for p in problems.iter().take(20) {
        println!("PROBLEM {p}");
    }
    println!("random transactions: {n} honest, {honest_ok} passed (max {max_cycles} cycles); {n} changed, {changed_refused} refused; changes {kinds:?}; {} problems", problems.len());
}

fn junk(n: usize) {
    let mut r = rand::thread_rng();
    let mut ctx = Context::default();
    let code = ctx.deploy_cell(std::fs::read(format!("{}/mldsa-lock", dir())).unwrap().into());
    let mut codes = std::collections::BTreeMap::<i64, usize>::new();
    let mut accepted = 0;
    let keys: Vec<Key> = (0..3).map(|_| random_key(&mut r)).collect();
    for _ in 0..n {
        let k = &keys[r.gen_range(0..keys.len())];
        let lock = ctx.build_script_with_hash_type(&code, ScriptHashType::Data2, Bytes::from([&[k.level][..], &blake(&[&k.pk])[..]].concat())).unwrap();
        let c = ctx.create_cell(CellOutput::new_builder().capacity(1_000 * CKB).lock(lock.clone()).build(), Bytes::new());
        let field = match r.gen_range(0..4) {
            // the right public key and a random signature of the right size: the verifier itself must say no
            0 | 1 => Bytes::from([&k.pk[..], &rand_bytes(&mut r, k.sig_len)[..]].concat()),
            // random bytes of a random size
            2 => {
                let n = r.gen_range(0..9000);
                rand_bytes(&mut r, n)
            }
            // the right key, a signature one byte off in length
            _ => {
                let n = if r.gen_bool(0.5) { k.sig_len + 1 } else { k.sig_len - 1 };
                Bytes::from([&k.pk[..], &rand_bytes(&mut r, n)[..]].concat())
            }
        };
        let witness = if r.gen_bool(0.85) {
            WitnessArgs::new_builder().lock(Some(field).pack()).build().as_bytes()
        } else {
            {
                let n = r.gen_range(0..200);
                rand_bytes(&mut r, n) // not a WitnessArgs at all
            }
        };
        let tx = TransactionBuilder::default()
            .input(CellInput::new_builder().previous_output(c).build())
            .output(CellOutput::new_builder().capacity(999 * CKB).build())
            .output_data(Bytes::new().pack())
            .witness(witness.pack())
            .build();
        let tx = ctx.complete_tx(tx);
        match outcome(&ctx, &tx) {
            Ok(_) => accepted += 1,
            Err(c) => *codes.entry(c).or_default() += 1,
        }
    }
    println!("junk: {n} tried, {accepted} accepted, refusals by code {codes:?}");
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(String::as_str) {
        Some("kat") => kat(&a[2]),
        Some("cross") => cross(&a[2]),
        Some("txs") => txs(a[2].parse().unwrap()),
        Some("junk") => junk(a[2].parse().unwrap()),
        _ => eprintln!("sim kat|cross|txs|junk ..."),
    }
}
