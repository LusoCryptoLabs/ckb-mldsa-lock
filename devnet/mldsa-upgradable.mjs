// An upgradable copy of mldsa-lock on the public testnet. The code cell carries a type id, so
// addresses that reference it by type (hash type "type") follow an upgrade. Its lock is the fixed
// copy of mldsa-lock (data2) with an ML-DSA-87 key: only that post-quantum key can replace the code.
//   1. deploy the copy (once, in STATE)
//   2. a spend through a "type" address
//   3. an upgrade signed with another ML-DSA-87 key: refused
//   4. the upgrade signed with the upgrade key (same bytes, so a no-op): accepted, new out point
//   5. a spend through the same "type" address after the upgrade
// The upgrade key's seed is kept in DIR, never printed. Faucet coins only.
import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { ccc } from 'file:///D:/Repos/LCL.cells/sdk/node_modules/@ckb-ccc/core/dist/index.mjs'
import { ml_dsa65, ml_dsa87 } from 'file:///D:/Repos/LCL.cells/sdk/node_modules/@noble/post-quantum/ml-dsa.js'

const DIR = 'D:/DevData/mldsa-testnet'
mkdirSync(DIR, { recursive: true })
const STATE = `${DIR}/upgradable.json`
const fixed = JSON.parse(readFileSync(`${DIR}/state.json`, 'utf8')) // the fixed copy (data2)
const state = existsSync(STATE) ? JSON.parse(readFileSync(STATE, 'utf8')) : {}
const save = () => writeFileSync(STATE, JSON.stringify(state, null, 2))
const BIN = process.env.MLDSA_BIN ?? 'D:/Repos/ckb-mldsa-lock/build'
const CKB = 100_000_000n
const CONTEXT = new TextEncoder().encode('CKB-MLDSA-LOCK')
const TYPE_ID = '0x00000000000000000000000000000000000000000000000000545950455f4944'
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a)
const u64 = (n) => ccc.numLeToBytes(n, 8)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const client = new ccc.ClientPublicTestnet()
const funder = new ccc.SignerCkbPrivateKey(client, readFileSync('D:/DevData/hcv-testnet/deployer.key', 'utf8').trim())
const me = (await funder.getRecommendedAddressObj()).script
async function committed(hash, ms = 600_000) {
  const end = Date.now() + ms
  while (Date.now() < end) {
    const t = await client.getTransaction(hash)
    if (t?.status === 'committed') return t
    if (t?.status === 'rejected') throw new Error(`${hash} rejected: ${t.reason}`)
    await sleep(3000)
  }
  throw new Error(`${hash} not committed`)
}

// The upgrade key.
if (!existsSync(`${DIR}/upgrade.seed`)) writeFileSync(`${DIR}/upgrade.seed`, randomBytes(32).toString('hex'))
const up = ml_dsa87.keygen(Uint8Array.from(Buffer.from(readFileSync(`${DIR}/upgrade.seed`, 'utf8').trim(), 'hex')))
const fixedDep = { outPoint: { txHash: fixed.codeTx, index: 0 }, depType: 'code' }
const mlLock = (codeHash, hashType, level, pk) => ccc.Script.from({ codeHash, hashType, args: ccc.hexFrom(ccc.bytesConcat(new Uint8Array([level]), ccc.bytesFrom(ccc.hashCkb(pk)))) })
const upgradeLock = mlLock(fixed.codeHash, 'data2', 0x05, up.publicKey)

// The lock's message: script hash, tx hash, the group's first witness with its lock zeroed, the group's
// other witnesses, the witnesses past the inputs.
function message(tx, lock, group, lockLen) {
  const w0 = ccc.WitnessArgs.fromBytes(tx.witnesses[group[0]])
  const zeroed = ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(lockLen)), inputType: w0.inputType, outputType: w0.outputType }).toBytes()
  const parts = [ccc.bytesFrom(lock.hash()), ccc.bytesFrom(tx.hash()), u64(zeroed.length), zeroed]
  for (const i of group.slice(1)) {
    const w = ccc.bytesFrom(tx.witnesses[i] ?? '0x')
    parts.push(u64(w.length), w)
  }
  for (let i = tx.inputs.length; i < tx.witnesses.length; i++) {
    const w = ccc.bytesFrom(tx.witnesses[i])
    parts.push(u64(w.length), w)
  }
  return ccc.bytesFrom(ccc.hashCkb(ccc.bytesConcat(...parts)))
}
function sign(tx, dsa, key, lock, group, sigLen) {
  const lockLen = key.publicKey.length + sigLen
  tx.witnesses[group[0]] = ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(lockLen)) }).toBytes())
  const sig = dsa.sign(message(tx, lock, group, lockLen), key.secretKey, { context: CONTEXT })
  tx.witnesses[group[0]] = ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(ccc.bytesConcat(key.publicKey, sig)) }).toBytes())
}

// 1. The upgradable copy.
const data = ccc.hexFrom(readFileSync(`${BIN}/mldsa-lock`))
if (!state.typeScript) {
  const tx = ccc.Transaction.from({ outputs: [{ lock: upgradeLock }], outputsData: [data] })
  await tx.completeInputsByCapacity(funder, 200n * CKB)
  const typeId = ccc.Script.from({ codeHash: TYPE_ID, hashType: 'type', args: ccc.hashTypeId(tx.inputs[0], 0) })
  tx.outputs[0] = ccc.CellOutput.from({ lock: upgradeLock, type: typeId }, data)
  tx.outputs[0].capacity += 200n * CKB // room for the fees of later upgrades
  await tx.completeFeeBy(funder, 1000)
  const h = await funder.sendTransaction(tx)
  await committed(h)
  state.typeScript = { codeHash: typeId.codeHash, hashType: 'type', args: typeId.args }
  state.typeHash = typeId.hash()
  state.codeCell = { txHash: h, index: 0 }
  state.deployTx = h
  save()
  log(`upgradable copy deployed in ${h}; addresses use code hash ${state.typeHash} with hash type type`)
}
const dep = () => ({ outPoint: state.codeCell, depType: 'code' })

let all = true
// 2 and 5. A spend through a "type" address.
async function spendThroughType(label) {
  const k = ml_dsa65.keygen(randomBytes(32))
  const lock = mlLock(state.typeHash, 'type', 0x03, k.publicKey)
  const f = ccc.Transaction.from({ outputs: [{ capacity: 300n * CKB, lock }], outputsData: ['0x'] })
  await f.completeInputsByCapacity(funder)
  await f.completeFeeBy(funder, 1000)
  const fh = await funder.sendTransaction(f)
  await committed(fh)
  const tx = ccc.Transaction.from({ cellDeps: [dep()], inputs: [{ previousOutput: { txHash: fh, index: 0 } }], outputs: [{ capacity: 300n * CKB - 100_000n, lock: me }], outputsData: ['0x'] })
  sign(tx, ml_dsa65, k, lock, [0], 3309)
  try {
    const h = await client.sendTransaction(tx, 'passthrough')
    await committed(h)
    log(`PASS ${label}: spend through a "type" address committed ${h}`)
    return h
  } catch (e) {
    all = false
    log(`FAIL ${label}: ${String(e.message || e).slice(0, 200)}`)
    return null
  }
}
state.spendBefore = await spendThroughType('before the upgrade')
save()

// 3 and 4. The upgrade: the code cell spent and rewritten, same type id, same lock.
async function upgrade(key, label, want) {
  const cell = await client.getCell(state.codeCell)
  const tx = ccc.Transaction.from({
    cellDeps: [fixedDep],
    inputs: [{ previousOutput: state.codeCell }],
    outputs: [{ capacity: cell.cellOutput.capacity - 2_000_000n, lock: upgradeLock, type: ccc.Script.from(state.typeScript) }],
    outputsData: [data],
  })
  sign(tx, ml_dsa87, key, upgradeLock, [0], 4627)
  try {
    const h = await client.sendTransaction(tx, 'passthrough')
    await committed(h)
    const ok = want === 'ok'
    all &&= ok
    log(`${ok ? 'PASS' : 'FAIL'} ${label}: committed ${h}`)
    if (ok) {
      state.codeCell = { txHash: h, index: 0 }
      state.upgradeTx = h
      save()
    }
  } catch (e) {
    const m = String(e.message || e)
    const ok = want !== 'ok' && m.includes(want)
    all &&= ok
    log(`${ok ? 'PASS' : 'FAIL'} ${label}: refused, ${m.match(/error code -?\d+/)?.[0] ?? m.slice(0, 200)}`)
  }
}
await upgrade(ml_dsa87.keygen(randomBytes(32)), 'an upgrade signed with another ML-DSA-87 key', 'error code 4')
await upgrade(up, 'the upgrade signed with the upgrade key', 'ok')
state.spendAfter = await spendThroughType('after the upgrade')
save()
log(all ? 'ALL AS EXPECTED' : 'SOMETHING DID NOT BEHAVE')
process.exit(0)
