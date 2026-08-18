// Per-algorithm latency and memory benchmark.
//
// Deliberately shaped to a published external methodology: a fixed iteration
// count per algorithm, tail latency rather than a mean, and a memory figure.
// A mean hides the tail, and the tail is what a request budget has to absorb,
// so min/median/p95/p99/max are all reported and the mean is secondary.
//
// Every parameter set the package can reach is measured, not just the three it
// wraps in its own helpers. Figures are for the raw primitives; the package
// wrappers add one HKDF derivation on the keygen path, which is measured
// separately as `wrapper keypairFromMaster`.
//
// Run:  node bench/primitives.mjs [--iterations N] [--json PATH]
//
// SLH-DSA slow variants sign in seconds, so they take a smaller sample. The
// count actually used is recorded per row: a row is never presented as if it
// ran the full sample when it did not.

import { writeFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'

import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import * as slh from '@noble/post-quantum/slh-dsa.js'

const args = process.argv.slice(2)
const N = args.includes('--iterations') ? Number(args[args.indexOf('--iterations') + 1]) : 100
const jsonOut = args.includes('--json') ? args[args.indexOf('--json') + 1] : null

const MSG = new TextEncoder().encode('kxco benchmark payload')

function percentile(sorted, p) {
  if (sorted.length === 0) return 0
  const idx = Math.min(sorted.length - 1, Math.ceil((p / 100) * sorted.length) - 1)
  return sorted[Math.max(0, idx)]
}

// Measure one operation n times. Returns latency percentiles in milliseconds and
// the heap growth across the batch.
function measure(label, n, fn) {
  // Warm up so JIT compilation is not attributed to the first samples.
  for (let i = 0; i < Math.min(5, n); i++) fn()

  if (global.gc) global.gc()
  const heapBefore = process.memoryUsage().heapUsed

  const samples = new Array(n)
  for (let i = 0; i < n; i++) {
    const t0 = process.hrtime.bigint()
    fn()
    samples[i] = Number(process.hrtime.bigint() - t0) / 1e6
  }

  const heapAfter = process.memoryUsage().heapUsed
  samples.sort((a, b) => a - b)

  return {
    op: label,
    iterations: n,
    ms: {
      min: +samples[0].toFixed(4),
      median: +percentile(samples, 50).toFixed(4),
      p95: +percentile(samples, 95).toFixed(4),
      p99: +percentile(samples, 99).toFixed(4),
      max: +samples[samples.length - 1].toFixed(4),
      mean: +(samples.reduce((a, b) => a + b, 0) / n).toFixed(4),
    },
    opsPerSec: Math.round(1000 / (samples.reduce((a, b) => a + b, 0) / n)),
    // Heap growth over the batch, divided by iterations. GC can run mid-batch,
    // so treat this as an order of magnitude rather than an exact allocation
    // figure. Run with --expose-gc for a cleaner baseline.
    heapPerOpBytes: Math.round((heapAfter - heapBefore) / n),
  }
}

const rows = []

// ---------------------------------------------------------------- ML-KEM
for (const [name, alg] of [['ML-KEM-512', ml_kem512], ['ML-KEM-768', ml_kem768], ['ML-KEM-1024', ml_kem1024]]) {
  const seed = new Uint8Array(alg.lengths.seed).fill(7)
  const { publicKey, secretKey } = alg.keygen(seed)
  const { cipherText } = alg.encapsulate(publicKey)

  rows.push({ alg: name, ...measure('keygen', N, () => alg.keygen(seed)) })
  rows.push({ alg: name, ...measure('encapsulate', N, () => alg.encapsulate(publicKey)) })
  rows.push({ alg: name, ...measure('decapsulate', N, () => alg.decapsulate(cipherText, secretKey)) })
}

// ---------------------------------------------------------------- ML-DSA
for (const [name, alg] of [['ML-DSA-44', ml_dsa44], ['ML-DSA-65', ml_dsa65], ['ML-DSA-87', ml_dsa87]]) {
  const seed = new Uint8Array(alg.lengths.seed).fill(9)
  const { publicKey, secretKey } = alg.keygen(seed)
  const sig = alg.sign(MSG, secretKey)

  rows.push({ alg: name, ...measure('keygen', N, () => alg.keygen(seed)) })
  rows.push({ alg: name, ...measure('sign (hedged)', N, () => alg.sign(MSG, secretKey)) })
  rows.push({ alg: name, ...measure('verify', N, () => alg.verify(sig, MSG, publicKey)) })
}

// ---------------------------------------------------------------- SLH-DSA
// The `s` variants sign in seconds. Sampling them 100 times would take hours, so
// they are sampled less and the row says so.
const SLH_SETS = [
  ['SLH-DSA-SHA2-128f', slh.slh_dsa_sha2_128f, Math.min(N, 20)],
  ['SLH-DSA-SHA2-192s', slh.slh_dsa_sha2_192s, Math.min(N, 3)],
  ['SLH-DSA-SHAKE-256f', slh.slh_dsa_shake_256f, Math.min(N, 5)],
]
for (const [name, alg, n] of SLH_SETS) {
  const seed = new Uint8Array(alg.lengths.seed).fill(3)
  const { publicKey, secretKey } = alg.keygen(seed)
  const sig = alg.sign(MSG, secretKey)

  rows.push({ alg: name, ...measure('keygen', n, () => alg.keygen(seed)) })
  rows.push({ alg: name, ...measure('sign', n, () => alg.sign(MSG, secretKey)) })
  rows.push({ alg: name, ...measure('verify', Math.max(n, 10), () => alg.verify(sig, MSG, publicKey)) })
}

// ------------------------------------------------- wrapper derivation overhead
const { mlDsa, mlKem } = await import('../src/index.js')
const master = new Uint8Array(32).fill(11)
rows.push({ alg: 'ML-DSA-65', ...measure('wrapper keypairFromMaster', N, () => mlDsa.keypairFromMaster(master)) })
rows.push({ alg: 'ML-KEM-768', ...measure('wrapper keypairFromMaster', N, () => mlKem.keypairFromMaster(master)) })

// ------------------------------------------------------------------- output
const report = {
  subject: { package: 'kxco-post-quantum' },
  runtime: {
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
    cpus: (await import('node:os')).cpus()[0]?.model ?? 'unknown',
    gcExposed: Boolean(global.gc),
  },
  requestedIterations: N,
  rows,
}

const w = (s, n) => String(s).padEnd(n)
const r = (s, n) => String(s).padStart(n)
console.log(`kxco-post-quantum per-algorithm latency, ${N} iterations requested`)
console.log(`${report.runtime.node} on ${report.runtime.platform}`)
console.log(`${report.runtime.cpus}\n`)
console.log(`${w('algorithm', 20)}${w('operation', 27)}${r('n', 4)}${r('median', 11)}${r('p95', 11)}${r('p99', 11)}${r('ops/s', 10)}`)
console.log('-'.repeat(94))
for (const x of rows) {
  console.log(
    w(x.alg, 20) + w(x.op, 27) + r(x.iterations, 4) +
    r(x.ms.median.toFixed(3), 11) + r(x.ms.p95.toFixed(3), 11) +
    r(x.ms.p99.toFixed(3), 11) + r(x.opsPerSec, 10)
  )
}

if (jsonOut) {
  mkdirSync(dirname(jsonOut), { recursive: true })
  writeFileSync(jsonOut, `${JSON.stringify(report, null, 2)}\n`)
  console.log(`\nreport written to ${jsonOut}`)
}
