// Time to sign a 32-byte message, median and range of N runs after a warm-up, same library for all.
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import * as slh from '@noble/post-quantum/slh-dsa.js'
import { randomBytes } from 'node:crypto'

const msg = randomBytes(32)
function time(name, alg, n) {
  const k = alg.keygen(randomBytes(alg.lengths?.seed ?? 32))
  let sig = alg.sign(msg, k.secretKey) // warm-up
  const ts = []
  for (let i = 0; i < n; i++) {
    const t = performance.now()
    sig = alg.sign(msg, k.secretKey)
    ts.push(performance.now() - t)
  }
  ts.sort((a, b) => a - b)
  const ok = alg.verify(sig, msg, k.publicKey)
  console.log(`${name.padEnd(22)} median ${ts[Math.floor(n / 2)].toFixed(2)} ms, min ${ts[0].toFixed(2)}, max ${ts[n - 1].toFixed(2)} (${n} runs), sig ${sig.length} B, pk ${k.publicKey.length} B, verifies ${ok}`)
}
console.log('slh exports:', Object.keys(slh).filter((k) => /128/.test(k)).join(' '))
time('ML-DSA-44', ml_dsa44, 200)
time('ML-DSA-65', ml_dsa65, 200)
time('ML-DSA-87', ml_dsa87, 200)
time('SLH-DSA-SHA2-128s', slh.slh_dsa_sha2_128s, 7)
time('SLH-DSA-SHA2-128f', slh.slh_dsa_sha2_128f, 7)
