// mldsa-lock on the local dev chain, signed by the wallet's library (@noble/post-quantum), verified by
// the Rust lock: for each level, a key from a seed, a deposit to its address, a spend signed with
// the wrong context (the node must refuse it, code 5), then the honest spend. Devnet coins only.
//   MLDSA_BIN=<folder with mldsa-lock> node mldsa-dev.mjs
import { readFileSync } from 'node:fs'
import { ccc, devClient, deployerKey, committed, rpc } from 'file:///D:/DevData/scale/dev.mjs'
import { JsonRpcTransformers } from 'file:///D:/Repos/LCL.cells/sdk/node_modules/@ckb-ccc/core/dist/advanced.mjs'
import { ml_dsa44, ml_dsa65, ml_dsa87 } from 'file:///D:/Repos/LCL.cells/sdk/node_modules/@noble/post-quantum/ml-dsa.js'

const BIN = process.env.MLDSA_BIN ?? 'D:/Repos/ckb-mldsa-lock/build'
const CKB = 100_000_000n
const CONTEXT = new TextEncoder().encode('CKB-MLDSA-LOCK')
const LEVELS = [
  [0x02, 'ML-DSA-44', ml_dsa44],
  [0x03, 'ML-DSA-65', ml_dsa65],
  [0x05, 'ML-DSA-87', ml_dsa87],
]
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a)
const u64 = (n) => ccc.numLeToBytes(n, 8)

const client = await devClient()
const deployer = new ccc.SignerCkbPrivateKey(client, deployerKey())
const me = (await deployer.getRecommendedAddressObj()).script

const data = ccc.hexFrom(readFileSync(`${BIN}/mldsa-lock`))
const dtx = ccc.Transaction.from({ outputs: [{ lock: ccc.Script.from({ codeHash: me.codeHash, hashType: me.hashType, args: '0x' + '00'.repeat(20) }) }], outputsData: [data] })
await dtx.completeInputsByCapacity(deployer)
await dtx.completeFeeBy(deployer, 1000)
const codeTx = await deployer.sendTransaction(dtx)
await committed(codeTx)
const codeHash = ccc.hashCkb(data)
const dep = { outPoint: { txHash: codeTx, index: 0 }, depType: 'code' }
log(`deployed mldsa-lock (${(data.length - 2) / 2} bytes) in ${codeTx.slice(0, 12)}`)

// The lock's message: blake2b(script hash, tx hash, the group's first witness with its lock bytes
// zeroed, the group's other witnesses, every witness past the inputs; each witness length-prefixed).
// `group` lists the input indices under this lock, the first one carrying the signature.
function sighash(tx, lockLen, script, group = [0]) {
  const w0 = ccc.WitnessArgs.fromBytes(tx.witnesses[group[0]])
  const zeroed = ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(lockLen)), inputType: w0.inputType, outputType: w0.outputType }).toBytes()
  const parts = [ccc.bytesFrom(ccc.Script.from(script).hash()), ccc.bytesFrom(tx.hash()), u64(zeroed.length), zeroed]
  for (const i of group.slice(1)) {
    const w = ccc.bytesFrom(tx.witnesses[i] ?? '0x')
    if (tx.witnesses[i] !== undefined) parts.push(u64(w.length), w)
  }
  for (let i = tx.inputs.length; i < tx.witnesses.length; i++) {
    const w = ccc.bytesFrom(tx.witnesses[i])
    parts.push(u64(w.length), w)
  }
  return ccc.bytesFrom(ccc.hashCkb(ccc.bytesConcat(...parts)))
}

async function trySend(name, tx, want) {
  try {
    const h = await client.sendTransaction(tx, 'passthrough')
    await committed(h)
    log(want === 'ok' ? 'PASS' : 'FAIL', name, '-> committed', h.slice(0, 12))
    return want === 'ok'
  } catch (e) {
    const m = String(e.message || e).replace(/\s+/g, ' ')
    const ok = want !== 'ok' && m.includes(want)
    log(ok ? 'PASS' : 'FAIL', name, '-> refused:', m.match(/error code \d+/)?.[0] ?? m.slice(0, 200))
    return ok
  }
}

let all = true
for (const [level, name, dsa] of LEVELS) {
  const { publicKey, secretKey } = dsa.keygen(crypto.getRandomValues(new Uint8Array(32)))
  const args = ccc.hexFrom(ccc.bytesConcat(new Uint8Array([level]), ccc.bytesFrom(ccc.hashCkb(publicKey))))
  const lock = ccc.Script.from({ codeHash, hashType: 'data2', args })
  const fund = ccc.Transaction.from({ outputs: [{ capacity: 1_000n * CKB, lock }], outputsData: ['0x'] })
  await fund.completeInputsByCapacity(deployer)
  await fund.completeFeeBy(deployer, 1000)
  const fh = await deployer.sendTransaction(fund)
  await committed(fh)
  const lockLen = publicKey.length + (level === 0x02 ? 2420 : level === 0x03 ? 3309 : 4627)
  const build = (ctxBytes) => {
    const tx = ccc.Transaction.from({
      cellDeps: [dep],
      inputs: [{ previousOutput: { txHash: fh, index: 0 } }],
      outputs: [{ capacity: 1_000n * CKB - 100_000n, lock: me }],
      outputsData: ['0x'],
    })
    tx.witnesses = [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(lockLen)) }).toBytes())]
    const sig = dsa.sign(sighash(tx, lockLen, lock), secretKey, ctxBytes === null ? {} : { context: ctxBytes })
    tx.witnesses = [ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(ccc.bytesConcat(publicKey, sig)) }).toBytes())]
    return tx
  }
  all &= await trySend(`${name}: signed with no context`, build(null), 'error code 5')
  const honest = build(CONTEXT)
  const cycles = BigInt((await rpc('estimate_cycles', [JsonRpcTransformers.transactionFrom(honest)])).cycles)
  log(`${name}: ${honest.toBytes().length} bytes, ${cycles.toLocaleString('en')} cycles on the node`)
  all &= await trySend(`${name}: honest spend signed in JavaScript`, honest, 'ok')
}
log(all ? 'ALL AS EXPECTED' : 'SOMETHING DID NOT BEHAVE')
