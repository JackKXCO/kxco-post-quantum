// Statistical timing measurement, dudect-style.
//
// THREAT-MODEL.md says this package makes no constant-time claim about the
// algorithm implementations, and lists published timing measurements as one of
// the things that would turn "no claim" into a measured bound. This is that
// measurement. It does not turn into a claim on its own, and the output says so.
//
// Method. Two classes of input are interleaved: a fixed secret key, and a
// secret key redrawn every iteration. If execution time is independent of the
// secret then the two populations are drawn from the same distribution.
// Welch's t-test on the two sets of timings gives a t-statistic; dudect's
// convention is that |t| > 10 is a detected leak and |t| < 10 over a large
// sample is evidence of absence of a *detectable* one.
//
// Interleaving matters and is not cosmetic: measuring all of class A and then
// all of class B attributes any drift over the run (thermal, JIT warm-up, other
// load) to the class rather than to time, which manufactures a t-statistic out
// of nothing.
//
// The lowest decile of samples is used rather than all of them. Timing tails
// here are dominated by scheduling and garbage collection, neither of which is
// secret-dependent, and including them buries the signal being looked for.
//
// What this cannot establish:
//
//   * It measures wall-clock at JavaScript resolution. It cannot see a leak
//     smaller than the timer's noise floor, and it says nothing about cache
//     occupancy, branch prediction, power draw or electromagnetic emission.
//   * A t-statistic below the threshold is not proof of constant-time
//     execution. It is the absence of a leak this test could detect, at this
//     sample size, on this machine, in this runtime. That is a weaker
//     statement and it is the only one available.
//   * On Node 24+ this measures OpenSSL; on Node 20 and 22 it measures the
//     JavaScript backend. They are different implementations and the report
//     records which one it measured.
//
// Run:  node --expose-gc bench/timing.mjs [--iterations N] [--json PATH]

import { writeFileSync, mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { randomBytes } from 'node:crypto'

import * as mlDsa from '../src/ml-dsa.js'
import * as mlKem from '../src/ml-kem.js'
import { native } from '#native'

const args = process.argv.slice(2)
const N = args.includes('--iterations') ? Number(args[args.indexOf('--iterations') + 1]) : 20000
const jsonOut = args.includes('--json') ? args[args.indexOf('--json') + 1] : null

const THRESHOLD = 10 // dudect convention
const MSG = new TextEncoder().encode('kxco timing measurement')

function welch(a, b) {
  const mean = (x) => x.reduce((s, v) => s + v, 0) / x.length
  const varr = (x, m) => x.reduce((s, v) => s + (v - m) * (v - m), 0) / (x.length - 1)
  const ma = mean(a)
  const mb = mean(b)
  const va = varr(a, ma)
  const vb = varr(b, mb)
  const t = (ma - mb) / Math.sqrt(va / a.length + vb / b.length)
  return { t, meanA: ma, meanB: mb, n: a.length + b.length }
}

// Keep the fastest decile: the tail is scheduler and GC, not secret-dependent.
function lowestDecile(xs) {
  const sorted = Float64Array.from(xs).sort()
  return Array.from(sorted.subarray(0, Math.max(2, Math.floor(sorted.length / 10))))
}

function study(label, makeFixed, makeRandom, run) {
  const fixed = []
  const random = []
  const fixedInput = makeFixed()

  // warm up so JIT compilation lands in neither class
  for (let i = 0; i < 200; i++) run(fixedInput)

  for (let i = 0; i < N; i++) {
    // interleave, and alternate which class goes first so that any pairwise
    // ordering effect cancels rather than accumulating into one class
    const order = i % 2 === 0
    const randomInput = makeRandom()

    const first = order ? fixedInput : randomInput
    const second = order ? randomInput : fixedInput

    let t0 = process.hrtime.bigint()
    run(first)
    const d1 = Number(process.hrtime.bigint() - t0)

    t0 = process.hrtime.bigint()
    run(second)
    const d2 = Number(process.hrtime.bigint() - t0)

    if (order) {
      fixed.push(d1)
      random.push(d2)
    } else {
      random.push(d1)
      fixed.push(d2)
    }
  }

  const r = welch(lowestDecile(fixed), lowestDecile(random))
  return {
    study: label,
    iterations: N,
    samplesCompared: r.n,
    tStatistic: Number(r.t.toFixed(3)),
    threshold: THRESHOLD,
    detected: Math.abs(r.t) > THRESHOLD,
    meanFixedNs: Math.round(r.meanA),
    meanRandomNs: Math.round(r.meanB),
  }
}

const studies = []

// ML-DSA-65 signing, fixed secret key against a freshly derived one each time.
{
  const fixedKey = mlDsa.keypairFromMaster(new Uint8Array(32).fill(1)).secretKey
  studies.push(
    study(
      'ML-DSA-65 sign, fixed vs random secret key',
      () => fixedKey,
      () => mlDsa.keypairFromMaster(randomBytes(32)).secretKey,
      (sk) => mlDsa.sign(sk, MSG)
    )
  )
}

// ML-KEM-768 decapsulation, fixed decapsulation key against a fresh one.
{
  const fixed = mlKem.keypairFromMaster(new Uint8Array(32).fill(2))
  const fixedCt = mlKem.encapsulate(fixed.publicKey).cipherText
  studies.push(
    study(
      'ML-KEM-768 decapsulate, fixed vs random secret key',
      () => fixed.secretKey,
      () => mlKem.keypairFromMaster(randomBytes(32)).secretKey,
      (sk) => mlKem.decapsulate(fixedCt, sk)
    )
  )
}

const report = {
  subject: { package: 'kxco-post-quantum' },
  backend: native === null
    ? { kind: 'javascript' }
    : { kind: 'openssl', openssl: native.openssl },
  runtime: {
    node: process.version,
    platform: `${process.platform}-${process.arch}`,
  },
  method: 'Welch t-test on interleaved fixed-vs-random secret key timings, lowest decile',
  threshold: THRESHOLD,
  interpretation:
    'A |t| below the threshold is the absence of a leak THIS test could detect, ' +
    'at this sample size, on this machine. It is not a constant-time claim. ' +
    'Cache, branch prediction, power and electromagnetic channels are not measured.',
  studies,
}

const w = (s, n) => String(s).padEnd(n)
console.log(`timing measurement, ${N} iterations per class, backend: ${report.backend.kind}`)
console.log(w('study', 52) + w('t', 10) + w('detected', 10))
for (const s of studies) {
  console.log(w(s.study, 52) + w(s.tStatistic, 10) + w(s.detected ? 'YES' : 'no', 10))
}
console.log('\n' + report.interpretation)

if (jsonOut) {
  mkdirSync(dirname(jsonOut), { recursive: true })
  writeFileSync(jsonOut, JSON.stringify(report, null, 2) + '\n')
  console.log(`\nreport written to ${jsonOut}`)
}

// A detected leak is a finding, not a build failure: this measurement is
// reported, not gated on, because the package makes no constant-time claim to
// regress against.
process.exit(0)
