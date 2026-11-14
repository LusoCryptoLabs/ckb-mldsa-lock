// A long run of mldsa-lock on the local dev chain, signed by the wallet's library. Six ML-DSA accounts
// (two per level) make random actions for SOAK_MINUTES:
//   pay      one account pays another from 1 to 3 of its cells, change back to itself
//   mixed    a secp256k1 input (the funder) and an ML-DSA input in one transaction, two signatures
//   big      a payment whose first witness carries up to 100 KB of input_type
//   burst    several accounts pay at once, in the same block
//   rbf      a payment sent, then the same inputs sent again with a higher fee (the second must win)
// After every honest send, an attacker copy (one covered byte changed) is sent too and must be refused.
// The run keeps every account's expected balance; at the end it must equal what the node reports.
//   MLDSA_BIN=<folder> SOAK_MINUTES=30 node mldsa-soak.mjs
import { readFileSync, writeFileSync } from 'node:fs'
import { ccc, devClient, deployerKey, committed, rpc } from 'file:///D:/DevData/scale/dev.mjs'
import { ml_dsa44, ml_dsa65, ml_dsa87 } from 'file:///D:/Repos/LCL.cells/sdk/node_modules/@noble/post-quantum/ml-dsa.js'

const BIN = process.env.MLDSA_BIN ?? 'D:/Repos/ckb-mldsa-lock/build'
const MINUTES = Number(process.env.SOAK_MINUTES ?? 30)
const CKB = 100_000_000n
const CONTEXT = new TextEncoder().encode('CKB-MLDSA-LOCK')
const SIG = { 2: 2420, 3: 3309, 5: 4627 }
const DSA = { 2: ml_dsa44, 3: ml_dsa65, 5: ml_dsa87 }
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a)
const u64 = (n) => ccc.numLeToBytes(n, 8)
const int = (n) => Math.floor(Math.random() * n)
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

const client = await devClient()
const funder = new ccc.SignerCkbPrivateKey(client, deployerKey())
const funderLock = (await funder.getRecommendedAddressObj()).script

// The code, under a lock nobody can spend.
const data = ccc.hexFrom(readFileSync(`${BIN}/mldsa-lock`))
const nobody = ccc.Script.from({ codeHash: funderLock.codeHash, hashType: funderLock.hashType, args: '0x' + '00'.repeat(20) })
const dtx = ccc.Transaction.from({ outputs: [{ lock: nobody }], outputsData: [data] })
await dtx.completeInputsByCapacity(funder)
await dtx.completeFeeBy(funder, 1000)
const codeTx = await funder.sendTransaction(dtx)
await committed(codeTx)
const codeHash = ccc.hashCkb(data)
const dep = ccc.CellDep.from({ outPoint: { txHash: codeTx, index: 0 }, depType: 'code' })

// Accounts.
const accounts = []
for (const level of [2, 2, 3, 3, 5, 5]) {
  const { publicKey, secretKey } = DSA[level].keygen(crypto.getRandomValues(new Uint8Array(32)))
  const ht = Math.random() < 0.5 ? 'data2' : 'data1'
  const lock = ccc.Script.from({ codeHash, hashType: ht, args: ccc.hexFrom(ccc.bytesConcat(new Uint8Array([level]), ccc.bytesFrom(ccc.hashCkb(publicKey)))) })
  accounts.push({ level, publicKey, secretKey, lock, expected: 0n, name: `acct${accounts.length}(L${level},${ht})` })
}
// Funding: three cells of 3,000 CKB each.
const fund = ccc.Transaction.from({ outputs: accounts.flatMap((a) => [0, 1, 2].map(() => ({ capacity: 3_000n * CKB, lock: a.lock }))), outputsData: accounts.flatMap(() => ['0x', '0x', '0x']) })
await fund.completeInputsByCapacity(funder)
await fund.completeFeeBy(funder, 1000)
const fundTx = await funder.sendTransaction(fund)
await committed(fundTx)
for (const a of accounts) a.expected = 9_000n * CKB
log(`deployed and funded ${accounts.length} accounts: ${accounts.map((a) => a.name).join(', ')}`)

const spent = new Set() // out points in pending transactions
const key = (op) => `${op.txHash}:${op.index}`
// Straight from the node's indexer: CCC's client cache also lists outputs of transactions it sent,
// a replaced RBF copy's included (the first trial counted those as money).
const scriptJson = (s) => ({ code_hash: s.codeHash, hash_type: s.hashType, args: s.args })
async function cellsOf(a, max) {
  const r = await rpc('get_cells', [{ script: scriptJson(a.lock), script_type: 'lock' }, 'asc', '0x64'])
  const out = []
  for (const o of r.objects) {
    const op = { txHash: o.out_point.tx_hash, index: Number(o.out_point.index) }
    if (spent.has(key(op))) continue
    out.push({ outPoint: op, cellOutput: { capacity: BigInt(o.output.capacity) } })
    if (out.length >= max) break
  }
  return out
}
async function balanceOf(a) {
  return BigInt((await rpc('get_cells_capacity', [{ script: scriptJson(a.lock), script_type: 'lock' }])).capacity)
}

// The lock's message: script hash, tx hash, the group's first witness with its lock zeroed, the group's
// other witnesses, the witnesses past the inputs.
function message(tx, lock, group, lockLen) {
  const w0 = ccc.WitnessArgs.fromBytes(tx.witnesses[group[0]])
  const zeroed = ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(lockLen)), inputType: w0.inputType, outputType: w0.outputType }).toBytes()
  const parts = [ccc.bytesFrom(lock.hash()), ccc.bytesFrom(tx.hash()), u64(zeroed.length), zeroed]
  for (const i of group.slice(1)) {
    if (tx.witnesses[i] === undefined) continue
    const w = ccc.bytesFrom(tx.witnesses[i])
    parts.push(u64(w.length), w)
  }
  for (let i = tx.inputs.length; i < tx.witnesses.length; i++) {
    const w = ccc.bytesFrom(tx.witnesses[i])
    parts.push(u64(w.length), w)
  }
  return ccc.bytesFrom(ccc.hashCkb(ccc.bytesConcat(...parts)))
}
function signMldsa(tx, a, group, inputType) {
  const lockLen = a.publicKey.length + SIG[a.level]
  tx.witnesses[group[0]] = ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(new Uint8Array(lockLen)), inputType }).toBytes())
  for (const i of group.slice(1)) tx.witnesses[i] = '0x'
  const sig = DSA[a.level].sign(message(tx, a.lock, group, lockLen), a.secretKey, { context: CONTEXT })
  tx.witnesses[group[0]] = ccc.hexFrom(ccc.WitnessArgs.from({ lock: ccc.hexFrom(ccc.bytesConcat(a.publicKey, sig)), inputType }).toBytes())
}
const feeFor = (tx) => BigInt(Math.max(100_000, (tx.toBytes().length + 200) * 2))

const stats = { sent: 0, committed: 0, attackRefused: 0, attackAccepted: 0, rbfWon: 0, rbfOther: 0, problems: [] }
const actions = {}
const pending = [] // { hash, effects: [[account, delta]], what }

async function attackCopy(tx) {
  // An attacker copy: one byte the signature covers, changed.
  const t = ccc.Transaction.from(tx).clone()
  const pick = int(3)
  if (pick === 0) t.outputs[0] = ccc.CellOutput.from({ ...t.outputs[0], capacity: t.outputs[0].capacity - 1n })
  else if (pick === 1) t.witnesses.push('0x01')
  else t.outputsData[0] = '0x00'
  try {
    await client.sendTransaction(t, 'passthrough')
    stats.attackAccepted++
    stats.problems.push(`attacker copy ACCEPTED (${pick})`)
  } catch (e) {
    const m = String(e.message || e)
    // Sent before the honest one, so nothing conflicts: the refusal must come from a script.
    if (/error code -?\d+/.test(m)) stats.attackRefused++
    else stats.problems.push(`attacker copy refused for another reason: ${m.slice(0, 160)}`)
  }
}

async function send(tx, effects, what, attack = true) {
  if (attack) await attackCopy(tx)
  const h = await client.sendTransaction(tx, 'passthrough')
  stats.sent++
  for (const i of tx.inputs) spent.add(key(i.previousOutput))
  pending.push({ hash: h, effects, what, inputs: tx.inputs.map((i) => key(i.previousOutput)) })
  return h
}

async function pay(a, b, nIn, inputType) {
  const cells = await cellsOf(a, nIn)
  if (cells.length === 0) return false
  const total = cells.reduce((s, c) => s + c.cellOutput.capacity, 0n)
  const amount = (BigInt(100 + int(800)) * CKB < total - 200n * CKB) ? BigInt(100 + int(800)) * CKB : total - 200n * CKB
  if (amount < 100n * CKB) return false
  const tx = ccc.Transaction.from({ cellDeps: [dep], inputs: cells.map((c) => ({ previousOutput: c.outPoint })), outputs: [{ capacity: amount, lock: b.lock }, { capacity: 0n, lock: a.lock }], outputsData: ['0x', '0x'] })
  const group = cells.map((_, i) => i)
  signMldsa(tx, a, group, inputType)
  const fee = feeFor(tx)
  tx.outputs[1] = ccc.CellOutput.from({ capacity: total - amount - fee, lock: a.lock })
  signMldsa(tx, a, group, inputType)
  await send(tx, [[a, -(amount + fee)], [b, amount]], `pay ${a.name}->${b.name}`)
  return true
}

async function mixed(a, b) {
  const cells = await cellsOf(a, 1)
  if (cells.length === 0) return false
  const mine = cells[0]
  const tx = ccc.Transaction.from({ cellDeps: [dep], inputs: [{ previousOutput: mine.outPoint }], outputs: [{ capacity: mine.cellOutput.capacity + 500n * CKB, lock: b.lock }], outputsData: ['0x'] })
  await tx.completeInputsByCapacity(funder, 600n * CKB)
  await funder.prepareTransaction(tx)
  // ML-DSA group: input 0. Its witness is set first; the funder signs last over its own group.
  signMldsa(tx, a, [0], undefined)
  await tx.completeFeeBy(funder, 2000)
  signMldsa(tx, a, [0], undefined)
  const signed = await funder.signOnlyTransaction(tx)
  // the ML-DSA message covers the tx hash only through what was fixed before the funder signed
  await send(signed, [[a, -mine.cellOutput.capacity], [b, mine.cellOutput.capacity + 500n * CKB]], `mixed ${a.name}+funder->${b.name}`)
  return true
}

async function rbf(a, b) {
  const cells = await cellsOf(a, 1)
  if (cells.length === 0) return false
  const c = cells[0]
  const build = (fee) => {
    const tx = ccc.Transaction.from({ cellDeps: [dep], inputs: [{ previousOutput: c.outPoint }], outputs: [{ capacity: 100n * CKB, lock: b.lock }, { capacity: c.cellOutput.capacity - 100n * CKB - fee, lock: a.lock }], outputsData: ['0x', '0x'] })
    signMldsa(tx, a, [0], undefined)
    return tx
  }
  const low = build(200_000n)
  const high = build(2_000_000n)
  await client.sendTransaction(low, 'passthrough')
  stats.sent++
  let hh
  try {
    hh = await client.sendTransaction(high, 'passthrough')
    stats.sent++
  } catch (e) {
    stats.rbfOther++
    stats.problems.push(`rbf replacement refused: ${String(e.message || e).slice(0, 160)}`)
    spent.add(key(c.outPoint))
    pending.push({ hash: low.hash(), effects: [[a, -(100n * CKB + 200_000n)], [b, 100n * CKB]], what: 'rbf low', inputs: [key(c.outPoint)] })
    return true
  }
  spent.add(key(c.outPoint))
  pending.push({ hash: hh, effects: [[a, -(100n * CKB + 2_000_000n)], [b, 100n * CKB]], what: 'rbf high', inputs: [key(c.outPoint)], rbf: low.hash() })
  return true
}

async function settle() {
  for (const p of pending.splice(0)) {
    try {
      await committed(p.hash, 180_000)
      stats.committed++
      for (const [acct, d] of p.effects) acct.expected += d
      if (p.rbf) {
        const old = await rpc('get_transaction', [p.rbf])
        if (old?.tx_status?.status !== 'committed') stats.rbfWon++
        else stats.problems.push('rbf: the low-fee copy committed')
      }
    } catch (e) {
      stats.problems.push(`${p.what} did not commit: ${String(e.message || e).slice(0, 160)}`)
    }
    for (const k of p.inputs) spent.delete(k)
  }
}

const end = Date.now() + MINUTES * 60_000
let round = 0
while (Date.now() < end) {
  round++
  const a = accounts[int(accounts.length)]
  let b = accounts[int(accounts.length)]
  if (b === a) b = accounts[(accounts.indexOf(a) + 1) % accounts.length]
  const r = Math.random()
  const what = r < 0.35 ? 'pay' : r < 0.5 ? 'mixed' : r < 0.6 ? 'big' : r < 0.85 ? 'burst' : 'rbf'
  actions[what] = (actions[what] ?? 0) + 1
  try {
    if (what === 'pay') await pay(a, b, 1 + int(3))
    else if (what === 'mixed') await mixed(a, b)
    else if (what === 'big') await pay(a, b, 1, ccc.hexFrom(crypto.getRandomValues(new Uint8Array(1 + int(100_000)))))
    else if (what === 'burst') for (const x of accounts) await pay(x, accounts[(accounts.indexOf(x) + 1 + int(5)) % accounts.length], 1)
    else await rbf(a, b)
  } catch (e) {
    stats.problems.push(`${what} build/send: ${String(e.message || e).slice(0, 200)}`)
  }
  await settle()
  await sleep(1500) // let the indexer catch up with the block that settled
  if (round % 20 === 0) log(`round ${round}: ${JSON.stringify({ ...stats, problems: stats.problems.length })}`)
}
await settle()
// The books: every account's expected balance against the node.
let books = true
for (const a of accounts) {
  const have = await balanceOf(a)
  if (have !== a.expected) {
    books = false
    stats.problems.push(`${a.name}: node says ${have}, expected ${a.expected}`)
  }
}
log('actions', JSON.stringify(actions))
log('result', JSON.stringify({ ...stats, problems: stats.problems.length, books }))
for (const p of stats.problems.slice(0, 20)) log('PROBLEM', p)
log(stats.problems.length === 0 && books ? 'ALL AS EXPECTED' : 'SOMETHING DID NOT BEHAVE')
writeFileSync('D:/Repos/ckb-mldsa-lock/devnet/soak-result.json', JSON.stringify({ when: new Date().toISOString(), minutes: MINUTES, actions, ...stats, books }, (k, v) => (typeof v === 'bigint' ? v.toString() : v), 2))
