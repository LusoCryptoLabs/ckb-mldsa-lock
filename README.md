# ckb-mldsa-lock

Prototype. Devnet only. Not for value.

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

Binary: 97,280 bytes. Signing in Node with @noble/post-quantum 0.7.1 on the build PC: 2.2, 3.5 and
4.1 ms.

## Checks

- `tests/src/main.rs`: ckb-testtool rows, each attack refused with the code of its reason. Three
  controls (a build without the group's other witnesses, without the witnesses past the inputs,
  without the script hash) each accept the row about that part.
- `tests/tests/adversary.rs`: the ckb-adversary engine, 289 mutants of a payment, all refused.
- `devnet/mldsa-dev.mjs`: on a dev chain, a key and signature from the wallet's JavaScript library
  at each level, verified by this lock; a signature without the context is refused.
- One independent review: no way found to spend, reshape or replay. Its availability limit (a first
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

Devnet soak (`devnet/mldsa-soak.mjs`, 45 minutes, six accounts, signed in JavaScript): 155 actions
(payments, mixed secp and ML-DSA transactions, large witnesses, bursts, RBF), 171 transactions
committed, 163 attacker copies refused by the script, none accepted, 8 RBF replacements won, and every
account's balance on the node equal to the books. A second run of only large witnesses (up to 100 KB):
10 of 10 committed, 10 copies refused.

Testnet (2026-11-14): the pinned copy (data2) and an upgradable copy (type id, its code cell under an
ML-DSA-87 key), a spend at each level, an upgrade refused with another key and accepted with the key,
spends before and after it. The wallet half (cellula-wallet branch feat/mldsa-account) signed 56
testnet transactions in a real browser with a virtual passkey (PRF), all committed.

`contracts/mldsa-kat` is a test-only build of the same verification, fed by the witness; it is never deployed.

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
Contracts build for `riscv64imac-unknown-none-elf` with the flags in `.cargo/config.toml`.
