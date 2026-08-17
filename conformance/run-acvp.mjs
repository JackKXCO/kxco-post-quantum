// Run the NIST ACVP vectors for FIPS 203, 204 and 205 against this package.
//
// Every parameter set NIST publishes vectors for is exercised, not just the
// three this package wraps in its own helpers, because the underlying
// primitives are the artefact under test. Groups the backend cannot express are
// recorded as skipped with a reason rather than silently dropped: a skipped
// group is a gap in the claim, and the report says so.
//
// Usage:  node conformance/run-acvp.mjs [--set NAME[,NAME...]] [--json PATH] [--quiet]
//                                      [--max-per-group N]
//
// --max-per-group caps how many test cases are taken from each ACVP group. The
// SLH-DSA slow variants sign in seconds per operation, so a full pass takes
// tens of minutes; CI subsamples and the published report records the cap it
// ran under. A report generated with a cap is not a full-suite claim.
//
// Exit code is non-zero if any test fails.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import * as slh from '@noble/post-quantum/slh-dsa.js'
import { sha224, sha256, sha384, sha512, sha512_224, sha512_256 } from '@noble/hashes/sha2.js'
import { sha3_224, sha3_256, sha3_384, sha3_512, shake128_32, shake256_64 } from '@noble/hashes/sha3.js'

import { vectorPath, acvpSource } from './fetch-vectors.mjs'

const HERE = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(readFileSync(join(HERE, '..', 'package.json'), 'utf8'))

const args = process.argv.slice(2)
// --set takes one name or a comma-separated list, so a caller can run a group of
// sets into a single report. The SLH-DSA signature sets cost roughly two orders
// of magnitude more than the rest, which is why they are worth running apart.
const only = args.includes('--set')
  ? args[args.indexOf('--set') + 1].split(',').map((s) => s.trim()).filter(Boolean)
  : null
const jsonOut = args.includes('--json') ? args[args.indexOf('--json') + 1] : null
const quiet = args.includes('--quiet')
const maxPerGroup = args.includes('--max-per-group')
  ? Number(args[args.indexOf('--max-per-group') + 1])
  : Infinity

// ---------------------------------------------------------------- primitives

const KEM = {
  'ML-KEM-512': ml_kem512,
  'ML-KEM-768': ml_kem768,
  'ML-KEM-1024': ml_kem1024,
}

const DSA = {
  'ML-DSA-44': ml_dsa44,
  'ML-DSA-65': ml_dsa65,
  'ML-DSA-87': ml_dsa87,
}

const SLH = {
  'SLH-DSA-SHA2-128s': slh.slh_dsa_sha2_128s,
  'SLH-DSA-SHA2-128f': slh.slh_dsa_sha2_128f,
  'SLH-DSA-SHA2-192s': slh.slh_dsa_sha2_192s,
  'SLH-DSA-SHA2-192f': slh.slh_dsa_sha2_192f,
  'SLH-DSA-SHA2-256s': slh.slh_dsa_sha2_256s,
  'SLH-DSA-SHA2-256f': slh.slh_dsa_sha2_256f,
  'SLH-DSA-SHAKE-128s': slh.slh_dsa_shake_128s,
  'SLH-DSA-SHAKE-128f': slh.slh_dsa_shake_128f,
  'SLH-DSA-SHAKE-192s': slh.slh_dsa_shake_192s,
  'SLH-DSA-SHAKE-192f': slh.slh_dsa_shake_192f,
  'SLH-DSA-SHAKE-256s': slh.slh_dsa_shake_256s,
  'SLH-DSA-SHAKE-256f': slh.slh_dsa_shake_256f,
}

// ACVP names the pre-hash function; the HashML-DSA (FIPS 204 §5.4) and
// pre-hash SLH-DSA variants fix the OID from that name, and the backend derives
// the OID from the hash object.
const HASHES = {
  'SHA2-224': sha224,
  'SHA2-256': sha256,
  'SHA2-384': sha384,
  'SHA2-512': sha512,
  'SHA2-512/224': sha512_224,
  'SHA2-512/256': sha512_256,
  'SHA3-224': sha3_224,
  'SHA3-256': sha3_256,
  'SHA3-384': sha3_384,
  'SHA3-512': sha3_512,
  // HashML-DSA and HashSLH-DSA fix the XOF output length rather than using the
  // bare 128/256-bit defaults: SHAKE128 at 256 bits, SHAKE256 at 512 bits.
  'SHAKE-128': shake128_32,
  'SHAKE-256': shake256_64,
}

// -------------------------------------------------------------------- helpers

const hex = (u8) => Buffer.from(u8).toString('hex').toUpperCase()
const bytes = (h) => Uint8Array.from(Buffer.from(h ?? '', 'hex'))

function loadSet(name) {
  const prompt = JSON.parse(readFileSync(vectorPath(name, 'prompt'), 'utf8'))
  const expected = JSON.parse(readFileSync(vectorPath(name, 'expectedResults'), 'utf8'))
  const byId = new Map()
  for (const g of expected.testGroups) {
    for (const t of g.tests) byId.set(`${g.tgId}:${t.tcId}`, t)
  }
  if (Number.isFinite(maxPerGroup)) {
    for (const g of prompt.testGroups) g.tests = g.tests.slice(0, maxPerGroup)
  }
  return { prompt, expectedById: byId }
}

class Tally {
  constructor(set) {
    this.set = set
    this.passed = 0
    this.failed = 0
    this.skipped = 0
    this.byParameterSet = {}
    this.failures = []
    this.skips = new Map()
  }

  #bucket(ps) {
    return (this.byParameterSet[ps] ??= { passed: 0, failed: 0, skipped: 0 })
  }

  pass(ps) {
    this.passed++
    this.#bucket(ps).passed++
  }

  fail(ps, tgId, tcId, detail) {
    this.failed++
    this.#bucket(ps).failed++
    if (this.failures.length < 20) this.failures.push({ parameterSet: ps, tgId, tcId, detail })
  }

  skip(ps, n, reason) {
    this.skipped += n
    this.#bucket(ps).skipped += n
    this.skips.set(reason, (this.skips.get(reason) ?? 0) + n)
  }

  toJSON() {
    return {
      set: this.set,
      total: this.passed + this.failed + this.skipped,
      passed: this.passed,
      failed: this.failed,
      skipped: this.skipped,
      byParameterSet: this.byParameterSet,
      skipReasons: Object.fromEntries(this.skips),
      failures: this.failures,
    }
  }
}

// ------------------------------------------------------------------- runners

function runMlKemKeyGen(tally, { prompt, expectedById }) {
  for (const g of prompt.testGroups) {
    const alg = KEM[g.parameterSet]
    if (!alg) {
      tally.skip(g.parameterSet, g.tests.length, `no backend for ${g.parameterSet}`)
      continue
    }
    for (const t of g.tests) {
      const exp = expectedById.get(`${g.tgId}:${t.tcId}`)
      // FIPS 203 §7.1 ML-KEM.KeyGen takes (d, z); the backend seed is d || z.
      const seed = Uint8Array.from([...bytes(t.d), ...bytes(t.z)])
      const k = alg.keygen(seed)
      if (hex(k.publicKey) !== exp.ek) {
        tally.fail(g.parameterSet, g.tgId, t.tcId, 'ek mismatch')
      } else if (hex(k.secretKey) !== exp.dk) {
        tally.fail(g.parameterSet, g.tgId, t.tcId, 'dk mismatch')
      } else {
        tally.pass(g.parameterSet)
      }
    }
  }
}

function runMlKemEncapDecap(tally, { prompt, expectedById }) {
  for (const g of prompt.testGroups) {
    const alg = KEM[g.parameterSet]
    if (!alg) {
      tally.skip(g.parameterSet, g.tests.length, `no backend for ${g.parameterSet}`)
      continue
    }

    for (const t of g.tests) {
      const exp = expectedById.get(`${g.tgId}:${t.tcId}`)
      try {
        if (g.function === 'encapsulation') {
          const r = alg.encapsulate(bytes(t.ek), bytes(t.m))
          const ct = r.cipherText ?? r.ciphertext
          if (hex(ct) !== exp.c) tally.fail(g.parameterSet, g.tgId, t.tcId, 'ciphertext mismatch')
          else if (hex(r.sharedSecret) !== exp.k) tally.fail(g.parameterSet, g.tgId, t.tcId, 'shared secret mismatch')
          else tally.pass(g.parameterSet)
        } else if (g.function === 'decapsulation') {
          const ss = alg.decapsulate(bytes(t.c), bytes(t.dk))
          if (hex(ss) !== exp.k) tally.fail(g.parameterSet, g.tgId, t.tcId, 'implicit-reject secret mismatch')
          else tally.pass(g.parameterSet)
        } else if (g.function === 'encapsulationKeyCheck' || g.function === 'decapsulationKeyCheck') {
          // §7.2/§7.3 input checks: a malformed key must be rejected, a
          // well-formed one accepted. testPassed says which is expected.
          let accepted = true
          try {
            if (g.function === 'encapsulationKeyCheck') alg.encapsulate(bytes(t.ek))
            else alg.decapsulate(new Uint8Array(alg.lengths.cipherText), bytes(t.dk))
          } catch {
            accepted = false
          }
          if (accepted === exp.testPassed) tally.pass(g.parameterSet)
          else tally.fail(g.parameterSet, g.tgId, t.tcId, `key check accepted=${accepted}, expected ${exp.testPassed}`)
        } else {
          tally.skip(g.parameterSet, 1, `unknown function ${g.function}`)
        }
      } catch (err) {
        tally.fail(g.parameterSet, g.tgId, t.tcId, `threw: ${err.message}`)
      }
    }
  }
}

function runMlDsaKeyGen(tally, { prompt, expectedById }) {
  for (const g of prompt.testGroups) {
    const alg = DSA[g.parameterSet]
    if (!alg) {
      tally.skip(g.parameterSet, g.tests.length, `no backend for ${g.parameterSet}`)
      continue
    }
    for (const t of g.tests) {
      const exp = expectedById.get(`${g.tgId}:${t.tcId}`)
      const k = alg.keygen(bytes(t.seed))
      if (hex(k.publicKey) !== exp.pk) tally.fail(g.parameterSet, g.tgId, t.tcId, 'pk mismatch')
      else if (hex(k.secretKey) !== exp.sk) tally.fail(g.parameterSet, g.tgId, t.tcId, 'sk mismatch')
      else tally.pass(g.parameterSet)
    }
  }
}

// Resolve the signer surface and options for one ACVP signature group.
// Returns null with a reason when the backend cannot express the group.
function signerFor(alg, g, t) {
  if (g.signatureInterface === 'internal') {
    if (!alg.internal) return { reason: 'backend exposes no internal interface' }
    return { signer: alg.internal, extraOpts: { externalMu: g.externalMu === true } }
  }
  if (g.preHash === 'preHash') {
    const hashName = g.hashAlg ?? t.hashAlg
    const hash = HASHES[hashName]
    if (!hash) return { reason: `unsupported pre-hash ${hashName}` }
    try {
      return { signer: alg.prehash(hash), extraOpts: {} }
    } catch (err) {
      // The backend refuses a pre-hash weaker than the parameter set's
      // collision-strength floor. NIST's sample vectors pair every approved
      // hash with every parameter set, including combinations below that floor,
      // so these are reported as skipped rather than treated as failures.
      return { reason: `${hashName} refused for ${g.parameterSet}: ${err.message}` }
    }
  }
  return { signer: alg, extraOpts: {} }
}

function runSigGen(tally, { prompt, expectedById }, table, rndField) {
  for (const g of prompt.testGroups) {
    const alg = table[g.parameterSet]
    if (!alg) {
      tally.skip(g.parameterSet, g.tests.length, `no backend for ${g.parameterSet}`)
      continue
    }

    for (const t of g.tests) {
      const exp = expectedById.get(`${g.tgId}:${t.tcId}`)
      const { signer, extraOpts, reason } = signerFor(alg, g, t)
      if (!signer) {
        tally.skip(g.parameterSet, 1, reason)
        continue
      }

      const opts = { ...extraOpts }
      if (g.signatureInterface !== 'internal' && t.context !== undefined) {
        opts.context = bytes(t.context)
      }
      // Deterministic groups fix the per-signature randomness to zero
      // (extraEntropy: false); randomized groups supply it as rnd /
      // additionalRandomness so the output is reproducible.
      opts.extraEntropy = g.deterministic === false ? bytes(t[rndField]) : false

      const msg = g.externalMu === true ? bytes(t.mu) : bytes(t.message)

      try {
        const sig = signer.sign(msg, bytes(t.sk), opts)
        if (hex(sig) !== exp.signature) tally.fail(g.parameterSet, g.tgId, t.tcId, 'signature mismatch')
        else tally.pass(g.parameterSet)
      } catch (err) {
        tally.fail(g.parameterSet, g.tgId, t.tcId, `threw: ${err.message}`)
      }
    }
  }
}

function runSigVer(tally, { prompt, expectedById }, table) {
  for (const g of prompt.testGroups) {
    const alg = table[g.parameterSet]
    if (!alg) {
      tally.skip(g.parameterSet, g.tests.length, `no backend for ${g.parameterSet}`)
      continue
    }

    for (const t of g.tests) {
      const exp = expectedById.get(`${g.tgId}:${t.tcId}`)
      const { signer, extraOpts, reason } = signerFor(alg, g, t)
      if (!signer) {
        tally.skip(g.parameterSet, 1, reason)
        continue
      }

      const opts = { ...extraOpts }
      if (g.signatureInterface !== 'internal' && t.context !== undefined) {
        opts.context = bytes(t.context)
      }
      const msg = g.externalMu === true ? bytes(t.mu) : bytes(t.message)

      // A negative vector may be malformed enough to throw. A throw and a
      // false return are the same verdict here: the signature was rejected.
      let ok
      try {
        ok = signer.verify(bytes(t.signature), msg, bytes(t.pk), opts)
      } catch {
        ok = false
      }

      if (ok === exp.testPassed) tally.pass(g.parameterSet)
      else tally.fail(g.parameterSet, g.tgId, t.tcId, `verify returned ${ok}, expected ${exp.testPassed}`)
    }
  }
}

function runSlhKeyGen(tally, { prompt, expectedById }) {
  for (const g of prompt.testGroups) {
    const alg = SLH[g.parameterSet]
    if (!alg) {
      tally.skip(g.parameterSet, g.tests.length, `no backend for ${g.parameterSet}`)
      continue
    }
    for (const t of g.tests) {
      const exp = expectedById.get(`${g.tgId}:${t.tcId}`)
      // FIPS 205 key generation takes (SK.seed, SK.prf, PK.seed) in that order;
      // the backend seed is their concatenation.
      const seed = Uint8Array.from([...bytes(t.skSeed), ...bytes(t.skPrf), ...bytes(t.pkSeed)])
      const k = alg.keygen(seed)
      if (hex(k.publicKey) !== exp.pk) tally.fail(g.parameterSet, g.tgId, t.tcId, 'pk mismatch')
      else if (hex(k.secretKey) !== exp.sk) tally.fail(g.parameterSet, g.tgId, t.tcId, 'sk mismatch')
      else tally.pass(g.parameterSet)
    }
  }
}

const RUNNERS = {
  'ML-KEM-keyGen-FIPS203': runMlKemKeyGen,
  'ML-KEM-encapDecap-FIPS203': runMlKemEncapDecap,
  'ML-DSA-keyGen-FIPS204': runMlDsaKeyGen,
  'ML-DSA-sigGen-FIPS204': (tally, v) => runSigGen(tally, v, DSA, 'rnd'),
  'ML-DSA-sigVer-FIPS204': (tally, v) => runSigVer(tally, v, DSA),
  'SLH-DSA-keyGen-FIPS205': runSlhKeyGen,
  'SLH-DSA-sigGen-FIPS205': (tally, v) => runSigGen(tally, v, SLH, 'additionalRandomness'),
  'SLH-DSA-sigVer-FIPS205': (tally, v) => runSigVer(tally, v, SLH),
}

// ----------------------------------------------------------------------- main

const source = acvpSource()
const sets = only ?? Object.keys(RUNNERS)
const report = {
  subject: { package: pkg.name, version: pkg.version },
  backend: pkg.dependencies,
  runtime: { node: process.version, platform: `${process.platform}-${process.arch}` },
  acvp: source,
  sampling: Number.isFinite(maxPerGroup)
    ? { full: false, maxPerGroup }
    : { full: true },
  sets: [],
}

let exitCode = 0

for (const set of sets) {
  const runner = RUNNERS[set]
  if (!runner) throw new Error(`unknown vector set: ${set}`)

  const tally = new Tally(set)
  const started = process.hrtime.bigint()
  runner(tally, loadSet(set))
  const ms = Number((process.hrtime.bigint() - started) / 1_000_000n)

  const json = { ...tally.toJSON(), durationMs: ms }
  report.sets.push(json)
  if (json.failed > 0) exitCode = 1

  if (!quiet) {
    const verdict = json.failed === 0 ? 'PASS' : 'FAIL'
    console.log(
      `${verdict}  ${set.padEnd(28)} ${String(json.passed).padStart(5)} passed  ` +
        `${String(json.failed).padStart(4)} failed  ${String(json.skipped).padStart(4)} skipped  (${ms} ms)`
    )
    for (const [reason, n] of tally.skips) console.log(`        skipped ${n}: ${reason}`)
    for (const f of json.failures) console.log(`        tg${f.tgId}/tc${f.tcId} ${f.parameterSet}: ${f.detail}`)
  }
}

report.totals = report.sets.reduce(
  (acc, s) => ({
    total: acc.total + s.total,
    passed: acc.passed + s.passed,
    failed: acc.failed + s.failed,
    skipped: acc.skipped + s.skipped,
  }),
  { total: 0, passed: 0, failed: 0, skipped: 0 }
)

if (!quiet) {
  const t = report.totals
  console.log(
    `\n${t.passed}/${t.total} ACVP tests passed, ${t.failed} failed, ${t.skipped} skipped ` +
      `(${pkg.name}@${pkg.version}, ACVP-Server@${source.commit.slice(0, 12)})`
  )
}

if (jsonOut) {
  mkdirSync(dirname(jsonOut), { recursive: true })
  writeFileSync(jsonOut, `${JSON.stringify(report, null, 2)}\n`)
  if (!quiet) console.log(`report written to ${jsonOut}`)
}

process.exit(exitCode)
