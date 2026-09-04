// Fuzz the surfaces that accept bytes from somewhere else.
//
// The cryptography is not the interesting attack surface here: ML-DSA and
// ML-KEM come from a reviewed implementation and are covered by 2,103 ACVP
// vectors. What is interesting is everything that PARSES: a JWS token from an
// untrusted caller, a JWK or a PKCS#8 blob from a key store, a signature from
// a peer. Those are the places where a malformed input reaches our code first.
//
// The property under test is narrow and absolute:
//
//   A parser given arbitrary bytes must return, or throw a typed error.
//   It must never throw something unrecognisable, never hang, and never
//   report a forgery as valid.
//
// Verification functions must additionally FAIL CLOSED: `verify` returns false
// on rubbish, it does not throw and it does not return true. A verifier that
// throws on malformed input pushes the decision to a caller's catch block,
// which is where "treat an exception as invalid" quietly becomes "treat an
// exception as valid" one refactor later.
//
//   node fuzz/fuzz.mjs [iterations]
//
// Deterministic by default so a failure is reproducible: pass FUZZ_SEED to
// change the corpus. A failing input is printed as hex, which is the whole
// point of writing it down rather than eyeballing it.

import { createHash } from 'node:crypto'
import { seed as seedmod, jws, mlDsa } from '../src/index.js'

const ITERATIONS = Number(process.argv[2] ?? process.env.FUZZ_ITERATIONS ?? 2000)
const SEED = process.env.FUZZ_SEED ?? 'kxco-pq-fuzz-v1'

// A counter-mode PRNG over SHA-256: no dependency, and the same seed gives the
// same corpus on every machine and every run.
let counter = 0
function rand(n) {
  const out = Buffer.alloc(n)
  let off = 0
  while (off < n) {
    const block = createHash('sha256').update(`${SEED}:${counter++}`).digest()
    block.copy(out, off)
    off += block.length
  }
  return out
}
const randInt = (max) => rand(4).readUInt32BE(0) % max

const failures = []
function check(name, input, fn) {
  try {
    fn()
  } catch (e) {
    // A typed, deliberate error is a pass: the parser recognised bad input.
    const named = e instanceof TypeError || e instanceof RangeError ||
                  e instanceof SyntaxError || typeof e?.code === 'string' ||
                  /^Kxco/.test(e?.constructor?.name ?? '')
    if (!named) {
      failures.push({ name, why: `${e?.constructor?.name}: ${e?.message}`.slice(0, 120), input: input.toString('hex').slice(0, 96) })
    }
  }
}

const CORPUS = [
  () => rand(randInt(4096)),                       // arbitrary bytes
  () => Buffer.alloc(randInt(64)),                 // zeros
  () => Buffer.alloc(randInt(64), 0xff),           // ones
  () => Buffer.from(rand(32).toString('base64url')),
  () => Buffer.from('.'.repeat(randInt(8)) + rand(8).toString('hex')),
  () => Buffer.from(JSON.stringify({ alg: rand(4).toString('hex'), pub: rand(8).toString('base64url') })),
]

// A real keypair, so verification is fuzzed on the path where a caller holds a
// genuine key and a forged signature, which is the case that actually matters.
const kp = mlDsa.keypairFromMaster(Buffer.alloc(32, 3))
const message = Buffer.from('fuzz')
const goodSig = mlDsa.sign(kp.secretKey, message)

let verifyTrueOnGarbage = 0

for (let i = 0; i < ITERATIONS; i++) {
  const input = CORPUS[i % CORPUS.length]()
  const text = input.toString('latin1')

  check('jws.decodeJwsHeader', input, () => jws.decodeJwsHeader(text))
  check('jws.verifyJws', input, () => jws.verifyJws(text, kp.publicKey))
  check('seed.importJwk', input, () => seedmod.importJwk('ML-DSA-65', JSON.parse(safeJson(text))))
  check('seed.importSeedPkcs8', input, () => seedmod.importSeedPkcs8('ML-DSA-65', input))
  check('seed.keypairFromSeed', input, () => seedmod.keypairFromSeed('ML-DSA-65', input))

  // Fail closed. verify() must answer false, not throw and not answer true.
  try {
    if (mlDsa.verify(kp.publicKey, message, input.toString('hex')) === true) verifyTrueOnGarbage++
    if (mlDsa.verify(input, message, goodSig) === true) verifyTrueOnGarbage++
    if (mlDsa.verify(kp.publicKey, input, goodSig) === true) verifyTrueOnGarbage++
  } catch (e) {
    failures.push({ name: 'mlDsa.verify threw instead of returning false', why: String(e?.message).slice(0, 120), input: input.toString('hex').slice(0, 96) })
  }
}

function safeJson(t) { return t.trimStart().startsWith('{') ? t : '{}' }

// The control: the harness must be able to see a real failure. If a genuine
// signature stops verifying, the corpus above proves nothing about anything.
const controlOk = mlDsa.verify(kp.publicKey, message, goodSig) === true
if (!controlOk) failures.push({ name: 'CONTROL', why: 'a valid signature did not verify; the harness is not measuring what it claims', input: '' })

console.log(`fuzz: ${ITERATIONS} iterations, seed "${SEED}"`)
console.log(`  positive control (a real signature verifies): ${controlOk}`)
console.log(`  forgeries accepted: ${verifyTrueOnGarbage}`)
console.log(`  untyped throws:     ${failures.length}`)

if (verifyTrueOnGarbage > 0) {
  console.error('\nA forged or malformed input verified as valid. This is a security failure.')
  process.exit(1)
}
if (failures.length) {
  console.error('\nInputs that produced an untyped error:')
  for (const f of failures.slice(0, 10)) {
    console.error(`  ${f.name}\n    ${f.why}\n    input: ${f.input}`)
  }
  process.exit(1)
}
console.log('  ok')
