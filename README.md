# ckb-mldsa-lock

Prototype. Testnet only. Not for value.

A CKB lock that opens with an ML-DSA (FIPS 204) signature over the transaction. Three levels behind
one code hash, chosen by the address.

- args: level (`0x02` ML-DSA-44, `0x03` ML-DSA-65, `0x05` ML-DSA-87) followed by blake2b-256 of
  the public key (32 bytes, CKB personalization).
- witness: the group's first WitnessArgs, `lock` = public key || signature, exact sizes.
- message: blake2b of this lock script's hash, then CKB sighash_all (tx hash, the group's first
  witness with its lock bytes zeroed, the group's other witnesses, every witness past the inputs,
  each length-prefixed). The script hash ties a signature to this exact lock.
- context: `CKB-MLDSA-LOCK` (FIPS 204 domain separation).
- every witness is read in 4 KB pieces; a 200 KiB first witness is spent like any other.
- reference the code with hash type data1, data2 or type. Under data (VM0) it never opens.

Error codes: 1 syscall, 2 args, 3 witness, 4 public key hash, 5 signature.

## Measured (2026-11-14)

| level | witness | cycles on a dev node |
| --- | --- | --- |
| ML-DSA-44 | 3,752 bytes | 3,334,647 |
| ML-DSA-65 | 5,281 bytes | 5,112,986 |
| ML-DSA-87 | 7,239 bytes | 7,808,335 |

Binary: 97,280 bytes. Signing in Node with @noble/post-quantum 0.7.1 on the build PC, median of 200
(`bench/sign-times.mjs`, 2026-11-15): 1.9, 3.4 and 3.9 ms.

## Checks

- `tests/src/main.rs`: ckb-testtool rows, each attack refused with the code of its reason. Three
  controls (a build without the group's other witnesses, without the witnesses past the inputs,
  without the script hash) each accept the row about that part.
- A second internal review (2026-11-15, no finding): its missing rows are in (`R2`): the attacks at levels 44 and
  87, the lock referenced by type, a group with fewer witnesses than cells, each guard of the first
  witness's layout, and eight level 87 addresses in one transaction (62.5M cycles). Controls: without
  the public key hash check another key's signature passes; without the layout check a wrong size
  header is refused by the signature instead (5, not 3).
- `engine/tests/adversary.rs`: the ckb-adversary engine on eight payments (each level, hash types
  data2 and type, one and two inputs in the group), 2,726 mutants, all refused. Control: on a build
  with the signature check off the same run reports 188 findings. The engine is not public, so
  this crate is apart from `tests/` and needs a checkout of it beside this repository.
- `devnet/mldsa-dev.mjs`: on a dev chain, a key and signature from the wallet's JavaScript library
  at each level, verified by this lock; a signature without the context is refused.
- An internal adversarial review (2026-11-14): no way found to spend, reshape or replay. Its availability limit (a first
  witness over 128 KiB ran out of heap) is fixed by streaming; its hardening (the script hash in the
  message) is in; its missing rows are in.

## Simulations (2026-11-14, `tests/src/bin/sim.rs`)

| run | result |
| --- | --- |
| NIST ACVP ML-DSA sigVer, external pure (`tests/vectors`), on the CKB-VM build of the verifier | 45 of 45 agree with NIST (9 valid, 36 invalid) |
| 3,600 signatures from the wallet's library (`tests/gen-cross.mjs`) and changed copies | 3,600 of 3,600 agree with it (603 valid) |
| 3,000 random signed transactions (1 to 4 inputs of the lock among others, data1 and data2, witnesses up to 64 KiB, witnesses past the inputs, since values, output data) | all pass, at most 10.5M cycles |
| the same 3,000, each with one change the signature covers (a witness bit, an output, its data, one more output, a since, one more witness, a header dep) | all refused |
| 10,000 random signatures and witnesses | none accepted, every refusal 3 or 5 |
| control: the lock with its signature check turned off | 298 of 300 changed transactions accepted, so the run sees a broken lock |

Devnet soak (`devnet/mldsa-soak.mjs`, 45 minutes, six accounts, signed in JavaScript), run of
2026-11-15, record in `devnet/soak-45min.json`: 160 actions (payments, mixed secp and ML-DSA
transactions, large witnesses, bursts, RBF), 172 transactions sent, 160 committed, 12 replaced by
RBF, 148 attacker copies refused by the script, none accepted, and every account's balance on the node
equal to the books. A run of 2026-11-14 gave 171 committed and 163 copies refused; its record was not
kept. A run of only large witnesses (up to 100 KB, `devnet/soak-4min-big.json`): 10 of 10 committed,
10 copies refused.

Testnet (2026-11-14): the pinned copy (data2) and an upgradable copy (type id, its code cell under an
ML-DSA-87 key), a spend at each level, an upgrade refused with another key and accepted with the key,
spends before and after it. The wallet half (cellula-wallet branch feat/mldsa-account) signed 56
testnet transactions in a real browser with a virtual passkey (PRF), all committed.

`contracts/mldsa-kat` is a test-only build of the same verification, fed by the witness; it is never deployed.

## Benchmark (`bench/`)

Verification of other schemes in the same envelope (args = blake2b-256 of the public key, witness
lock = public key || signature, a sighash_all message), in ckb-testtool 1.1.1 on VM data2. It
measures verification only, so a full lock costs slightly more. Each lock has three controls that
must fail for the stated reason. Measured 2026-11-15, cycles over 5 signatures:

| scheme | cycles | public key + signature |
| --- | --- | --- |
| secp256k1 (the system script) | 1.61M to 1.65M | 65 B (signature only) |
| FN-DSA-512 (Falcon), fn-dsa 0.4 | 0.74M to 0.75M | 1,563 B |
| FN-DSA-1024 | 1.49M | 3,073 B |
| ML-DSA-44, fips204 0.5 | 3.25M | 3,732 B |
| ML-DSA-65 | 5.00M | 5,261 B |
| LMS H10 W4, hbs-lms 0.1.1 | 2.3M to 2.8M | 2,572 B |
| SLH-DSA-SHA2-128s, fips205 0.5 | 17.1M to 18.0M | 7,888 B |

FN-DSA is not a published standard yet and its encodings may change. Build the workspace for
`riscv64imac-unknown-none-elf`, then `cargo run --release` in `bench/tests`. `bench/sign-times.mjs`
times signing with @noble/post-quantum.

## Wallet rules

1. Sign with this key and context only a message the wallet computed itself from the transaction it
   shows. Login or message signing uses another context.
2. Show every input of the transaction, not only those under this exact script.
3. Witnesses of inputs under other locks are covered only by the tx hash of their own lock's
   signature, as with secp256k1.
4. Finalize every witness past the inputs before signing.
5. Do not collect cells at the address that carry a type script or data without meaning to.

## Build

`Cargo.lock` is committed: the reviewed build uses fips204 0.5.0, ckb-std 1.1.0, molecule 0.9.2.
The toolchain is pinned in `rust-toolchain.toml` (rustc 1.99.1); with it the build is 97,280 bytes
with data hash `0x92c18e85fc1d8cb0510f99ec7d7071bdcd5ac62d0fa3b627380e406d3343dc11`, the pinned
copy on testnet.
Contracts build for `riscv64imac-unknown-none-elf` with the flags in `.cargo/config.toml`. The
build needs clang and a RISC-V gcc for ckb-std's shim; the published bytes were built on Ubuntu
24.04 with its clang (18.1.3) and `gcc-riscv64-unknown-elf` (13.2.0).

```sh
sudo apt-get install -y clang gcc-riscv64-unknown-elf
cargo build --release --locked --target riscv64imac-unknown-none-elf
sha256sum target/riscv64imac-unknown-none-elf/release/mldsa-lock   # 5a7bec78... is the testnet copy
cd tests
cargo run --release --locked --bin mldsa-lock-tests                # the rows; ends "ALL AS EXPECTED"
cargo run --release --locked --bin sim -- kat vectors/kat-external-pure.json
cargo run --release --locked --bin sim -- txs 3000
cargo run --release --locked --bin sim -- junk 10000
```

The cross-check corpus comes from Node: `npm install`, then `node tests/gen-cross.mjs cross.jsonl`
and `cargo run --release --bin sim -- cross ../cross.jsonl` in `tests`. To point the tests at
another build of the lock, set `MLDSA_BIN` to its folder; that is how the controls run.

`devnet/` holds the scripts that ran on our dev chain and on testnet, as the record of what ran.
They import our chain helper and read key files by paths on our machine, so they do not run as they
are elsewhere.

## Reporting a problem

A way to spend, replay or reshape under this lock is what we most want to hear. Use GitHub's
private vulnerability reporting on this repository, or hello@lusocryptolabs.com.

## Licence

MIT.
