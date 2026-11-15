//! Runs each bench lock in ckb-testtool's CKB-VM and prints cycles and sizes, with three controls
//! per lock that must fail for the stated reason: a flipped signature bit (code 8), another key's
//! valid signature (code 7, key hash), and the right key signing another message (code 8).
use ckb_testtool::{
    ckb_hash::new_blake2b,
    ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*},
    context::Context,
};
use rand_core::{OsRng, RngCore};

const MAX_CYCLES: u64 = 3_500_000_000;
/// Where the bench locks were built: BENCH_BIN, or the workspace's own target folder.
fn bin_dir() -> String {
    std::env::var("BENCH_BIN").unwrap_or_else(|_| "../target/riscv64imac-unknown-none-elf/release".into())
}

trait Key {
    fn pk(&self) -> Vec<u8>;
    fn sign(&mut self, msg: &[u8; 32]) -> Vec<u8>;
}

struct Null(Vec<u8>);
impl Key for Null {
    fn pk(&self) -> Vec<u8> {
        self.0.clone()
    }
    fn sign(&mut self, _m: &[u8; 32]) -> Vec<u8> {
        vec![1]
    }
}

macro_rules! fips204_key {
    ($t:ident, $m:ident) => {
        struct $t(fips204::$m::PublicKey, fips204::$m::PrivateKey);
        impl $t {
            fn new() -> Self {
                let (p, s) = fips204::$m::try_keygen().unwrap();
                $t(p, s)
            }
        }
        impl Key for $t {
            fn pk(&self) -> Vec<u8> {
                use fips204::traits::SerDes;
                self.0.clone().into_bytes().to_vec()
            }
            fn sign(&mut self, m: &[u8; 32]) -> Vec<u8> {
                use fips204::traits::Signer;
                self.1.try_sign(m, b"").unwrap().to_vec()
            }
        }
    };
}
fips204_key!(MlDsa44, ml_dsa_44);
fips204_key!(MlDsa65, ml_dsa_65);

struct Slh(fips205::slh_dsa_sha2_128s::PublicKey, fips205::slh_dsa_sha2_128s::PrivateKey);
impl Slh {
    fn new() -> Self {
        let (p, s) = fips205::slh_dsa_sha2_128s::try_keygen().unwrap();
        Slh(p, s)
    }
}
impl Key for Slh {
    fn pk(&self) -> Vec<u8> {
        use fips205::traits::SerDes;
        self.0.clone().into_bytes().to_vec()
    }
    fn sign(&mut self, m: &[u8; 32]) -> Vec<u8> {
        use fips205::traits::Signer;
        self.1.try_sign(m, b"", true).unwrap().to_vec()
    }
}

struct Falcon {
    sk: Vec<u8>,
    vk: Vec<u8>,
}
impl Falcon {
    fn new(logn: u32) -> Self {
        use fn_dsa::{sign_key_size, vrfy_key_size, KeyPairGenerator, KeyPairGeneratorStandard};
        let mut sk = vec![0u8; sign_key_size(logn)];
        let mut vk = vec![0u8; vrfy_key_size(logn)];
        KeyPairGeneratorStandard::default().keygen(logn, &mut OsRng, &mut sk, &mut vk);
        Falcon { sk, vk }
    }
}
impl Key for Falcon {
    fn pk(&self) -> Vec<u8> {
        self.vk.clone()
    }
    fn sign(&mut self, m: &[u8; 32]) -> Vec<u8> {
        use fn_dsa::{signature_size, SigningKey, SigningKeyStandard, DOMAIN_NONE, HASH_ID_RAW};
        let mut sk = SigningKeyStandard::decode(&self.sk).unwrap();
        let mut sig = vec![0u8; signature_size(sk.get_logn())];
        sk.sign(&mut OsRng, &DOMAIN_NONE, &HASH_ID_RAW, m, &mut sig);
        sig
    }
}

struct Lms {
    sk: hbs_lms::SigningKey<hbs_lms::Sha256_256>,
    vk: Vec<u8>,
}
impl Lms {
    fn new(w: hbs_lms::LmotsAlgorithm, h: hbs_lms::LmsAlgorithm) -> Self {
        use hbs_lms::{HssParameter, Seed, Sha256_256};
        let params = [HssParameter::<Sha256_256>::new(w, h)];
        let mut seed = Seed::default();
        OsRng.fill_bytes(seed.as_mut_slice());
        let (sk, vk) = hbs_lms::keygen::<Sha256_256>(&params, &seed, None).unwrap();
        Lms { sk, vk: vk.as_slice().to_vec() }
    }
}
impl Key for Lms {
    fn pk(&self) -> Vec<u8> {
        self.vk.clone()
    }
    fn sign(&mut self, m: &[u8; 32]) -> Vec<u8> {
        use hbs_lms::signature::SignerMut;
        self.sk.try_sign(m).unwrap().as_ref().to_vec()
    }
}

struct Secp(ckb_testtool::ckb_crypto::secp::Privkey);
impl Secp {
    fn new() -> Self {
        let mut b = [0u8; 32];
        OsRng.fill_bytes(&mut b);
        Secp(ckb_testtool::ckb_crypto::secp::Privkey::from_slice(&b))
    }
}
impl Key for Secp {
    // The system script takes args = blake160(pubkey) and only the 65-byte signature in the witness.
    fn pk(&self) -> Vec<u8> {
        self.0.pubkey().unwrap().serialize()
    }
    fn sign(&mut self, m: &[u8; 32]) -> Vec<u8> {
        self.0.sign_recoverable(&ckb_testtool::ckb_types::H256::from(*m)).unwrap().serialize()
    }
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

fn code_of(e: &str) -> String {
    match e.split("error code ").nth(1) {
        Some(s) => s.chars().take_while(|c| c.is_ascii_digit() || *c == '-').collect(),
        None => e.chars().take(160).collect(),
    }
}

struct Run {
    cycles: Result<u64, String>,
    wit_lock: usize,
}

// One-input tx locked by `bin` with args = blake2b(pk_args); `signer` signs the sighash (or another
// message), the witness carries pk_shown || sig. `salt` makes each tx (and its message) different.
#[allow(clippy::too_many_arguments)]
fn run(bin: &Bytes, pk_args: &[u8], pk_shown: &[u8], signer: &mut dyn Key, sig_len: usize, salt: u8, other_msg: bool, flip: bool) -> Run {
    let mut ctx = Context::default();
    let op = ctx.deploy_cell(bin.clone());
    let secp = SECP.with(|c| *c.borrow());
    let args = if secp { Bytes::copy_from_slice(&blake(&[pk_args])[..20]) } else { Bytes::copy_from_slice(&blake(&[pk_args])) };
    let pk_shown: &[u8] = if secp { &[] } else { pk_shown };
    let lock = ctx.build_script_with_hash_type(&op, ckb_testtool::ckb_types::core::ScriptHashType::Data2, args).unwrap();
    let input_op = ctx.create_cell(
        CellOutput::new_builder().capacity(Pack::<Uint64>::pack(&1000_0000_0000u64)).lock(lock.clone()).build(),
        Bytes::new(),
    );
    let tx = TransactionBuilder::default()
        .input(CellInput::new_builder().previous_output(input_op).build())
        .output(CellOutput::new_builder().capacity(Pack::<Uint64>::pack(&999_0000_0000u64)).lock(lock).build())
        .output_data(Bytes::from(vec![salt]).pack())
        .build();
    let tx = if secp {
        let data_op = ctx.deploy_cell(system_script("secp256k1_data"));
        tx.as_advanced_builder().cell_dep(CellDep::new_builder().out_point(data_op).build()).build()
    } else {
        tx
    };
    let tx = ctx.complete_tx(tx);
    let lock_len = pk_shown.len() + sig_len;
    let zero = WitnessArgs::new_builder().lock(Some(Bytes::from(vec![0u8; lock_len])).pack()).build();
    let msg = blake(&[tx.hash().raw_data().as_ref(), &(zero.as_slice().len() as u64).to_le_bytes(), zero.as_slice()]);
    let signed = if other_msg { blake(&[&msg, b"other"]) } else { msg };
    let mut sig = signer.sign(&signed);
    assert_eq!(sig.len(), sig_len, "signature length changed");
    if flip {
        let i = sig.len() / 2;
        sig[i] ^= 0x01;
    }
    let w = WitnessArgs::new_builder().lock(Some(Bytes::from([pk_shown, &sig].concat())).pack()).build();
    let tx = tx.as_advanced_builder().set_witnesses(vec![w.as_bytes().pack()]).build();
    Run { cycles: ctx.verify_tx(&tx, MAX_CYCLES).map_err(|e| e.to_string()), wit_lock: lock_len }
}

thread_local!(static SECP: std::cell::RefCell<bool> = const { std::cell::RefCell::new(false) });

fn system_script(name: &str) -> Bytes {
    Bytes::from(ckb_system_scripts::BUNDLED_CELL.get(&format!("specs/cells/{name}")).expect("bundled system script").to_vec())
}

fn fmt(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

fn bench(name: &str, file: &str, mut key: Box<dyn Key>, mut other: Box<dyn Key>) {
    let secp = file == "secp256k1_blake160_sighash_all";
    SECP.with(|c| *c.borrow_mut() = secp);
    let bin: Bytes = if secp { system_script(file) } else { std::fs::read(format!("{}/{file}", bin_dir())).expect("binary").into() };
    let pk = key.pk();
    let sig_len = key.sign(&[7u8; 32]).len();
    let ok = run(&bin, &pk, &pk, key.as_mut(), sig_len, 1, false, false);
    let mut all: Vec<u64> = Vec::new();
    for salt in 10..14u8 {
        if let Ok(c) = run(&bin, &pk, &pk, key.as_mut(), sig_len, salt, false, false).cycles {
            all.push(c);
        }
    }
    let flip = run(&bin, &pk, &pk, key.as_mut(), sig_len, 2, false, true);
    let opk = other.pk();
    let wrong_key = run(&bin, &pk, &opk, other.as_mut(), sig_len, 3, false, false);
    let other_msg = run(&bin, &pk, &pk, key.as_mut(), sig_len, 4, true, false);
    let c = |r: &Run| match &r.cycles {
        Ok(_) => "PASSED(!)".to_string(),
        Err(e) => code_of(e),
    };
    match &ok.cycles {
        Ok(cy) => println!(
            "{name:<22} cycles {:>11} (5 sigs {}..{})  pk {:>5} B  sig {:>5} B  witness lock {:>5} B  binary {:>6} B  controls flip={} wrongkey={} othermsg={}",
            fmt(*cy),
            fmt(all.iter().copied().chain([*cy]).min().unwrap()),
            fmt(all.iter().copied().chain([*cy]).max().unwrap()),
            pk.len(),
            sig_len,
            ok.wit_lock,
            bin.len(),
            c(&flip),
            c(&wrong_key),
            c(&other_msg)
        ),
        Err(e) => println!("{name:<22} FAILED on the valid signature: {}", e.chars().take(400).collect::<String>()),
    }
}

fn main() {
    use hbs_lms::{LmotsAlgorithm as W, LmsAlgorithm as H};
    let only: Vec<String> = std::env::args().skip(1).collect();
    let want = |n: &str| only.is_empty() || only.iter().any(|o| n.contains(o.as_str()));
    let rnd = || {
        let mut b = vec![0u8; 32];
        OsRng.fill_bytes(&mut b);
        b
    };
    if want("secp") {
        bench("secp256k1 (CKB default)", "secp256k1_blake160_sighash_all", Box::new(Secp::new()), Box::new(Secp::new()));
    }
    if want("null") {
        bench("null (envelope only)", "null", Box::new(Null(rnd())), Box::new(Null(rnd())));
    }
    if want("slh") {
        bench("SLH-DSA-SHA2-128s", "slh128s", Box::new(Slh::new()), Box::new(Slh::new()));
    }
    if want("mldsa44") {
        bench("ML-DSA-44", "mldsa44", Box::new(MlDsa44::new()), Box::new(MlDsa44::new()));
    }
    if want("mldsa65") {
        bench("ML-DSA-65", "mldsa65", Box::new(MlDsa65::new()), Box::new(MlDsa65::new()));
    }
    if want("falcon") {
        bench("FN-DSA-512 (Falcon)", "fndsa512", Box::new(Falcon::new(9)), Box::new(Falcon::new(9)));
        bench("FN-DSA-1024 (Falcon)", "fndsa1024", Box::new(Falcon::new(10)), Box::new(Falcon::new(10)));
    }
    if want("lms") {
        bench("LMS H10 W4", "lms", Box::new(Lms::new(W::LmotsW4, H::LmsH10)), Box::new(Lms::new(W::LmotsW4, H::LmsH10)));
        bench("LMS H10 W8", "lms", Box::new(Lms::new(W::LmotsW8, H::LmsH10)), Box::new(Lms::new(W::LmotsW8, H::LmsH10)));
        bench("LMS H15 W4", "lms", Box::new(Lms::new(W::LmotsW4, H::LmsH15)), Box::new(Lms::new(W::LmotsW4, H::LmsH15)));
    }
}
