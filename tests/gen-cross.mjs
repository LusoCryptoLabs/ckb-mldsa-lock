// Cross-check corpus from the wallet's library (@noble/post-quantum): for each level, N keys, each
// signing a random message under a random context, plus five changed copies (a bit flipped in the
// signature, the message, the public key or the context, or a byte of the signature replaced), each
// with noble's own verdict. The lock's verifier must give the same verdict on every line.
//   node gen-cross.mjs <out.jsonl> [N per level]
import { writeFileSync } from 'node:fs'
import { ml_dsa44, ml_dsa65, ml_dsa87 } from 'file:///D:/Repos/LCL.cells/sdk/node_modules/@noble/post-quantum/ml-dsa.js'

const out = process.argv[2]
const N = Number(process.argv[3] ?? 200)
const rnd = (n) => crypto.getRandomValues(new Uint8Array(n))
const int = (n) => Math.floor(Math.random() * n)
const hex = (b) => Buffer.from(b).toString('hex')
const flip = (b) => {
  const c = Uint8Array.from(b)
  if (c.length === 0) return Uint8Array.of(1)
  const i = int(c.length * 8)
  c[i >> 3] ^= 1 << (i & 7)
  return c
}
const lines = []
let total = 0
for (const [level, dsa] of [[2, ml_dsa44], [3, ml_dsa65], [5, ml_dsa87]]) {
  for (let k = 0; k < N; k++) {
    const { publicKey, secretKey } = dsa.keygen(rnd(32))
    const msg = rnd(int(1025))
    const pick = int(3)
    const ctx = pick === 0 ? new Uint8Array(0) : pick === 1 ? new TextEncoder().encode('CKB-MLDSA-LOCK') : rnd(1 + int(255))
    const sig = dsa.sign(msg, secretKey, { context: ctx })
    const v = (pk, m, c, s) => {
      let ok = false
      try { ok = dsa.verify(s, m, pk, { context: c }) } catch { ok = false }
      lines.push(JSON.stringify({ level, pk: hex(pk), msg: hex(m), ctx: hex(c), sig: hex(s), expect: ok }))
      total++
    }
    v(publicKey, msg, ctx, sig)
    v(publicKey, msg, ctx, flip(sig))
    v(publicKey, flip(msg), ctx, sig)
    v(flip(publicKey), msg, ctx, sig)
    v(publicKey, msg, ctx.length < 255 ? flip(ctx) : ctx.slice(1), sig)
    const s2 = Uint8Array.from(sig)
    s2[int(s2.length)] = int(256)
    v(publicKey, msg, ctx, s2)
  }
}
writeFileSync(out, lines.join('\n') + '\n')
console.log(`${total} lines, ${lines.filter((l) => l.endsWith('true}')).length} expected valid`)
