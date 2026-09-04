// Seed-form keys and compact JWS.
//
// The interesting assertions here are not the round trips. They are the
// cross-backend ones: that a seed this package expands produces the same key
// OpenSSL expands from the same bytes, and that the DER this package writes is
// the DER OpenSSL writes. Those run only where the native backend exists, and
// they are skipped with a reason rather than silently passing where it does
// not — a green suite on a runtime without OpenSSL must not read as evidence
// about OpenSSL.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'

import {
  SEED_ALGORITHMS, keypairFromSeed, seedFromMaster,
  exportJwk, importJwk, exportSeedPkcs8, importSeedPkcs8,
} from '../src/seed.js'
import { signJws, verifyJws, decodeJwsHeader } from '../src/jws.js'
import { mlDsa, mlDsa87, mlKem, mlKem1024, fingerprint, backend, isNative } from '../src/index.js'

const MASTER = Buffer.alloc(32, 0x2b)

// Node names its parameter sets in lower case; ours are the FIPS spellings.
const nodeName = (alg) => alg.toLowerCase()

function nativeKeypair(alg) {
  const { privateKey } = crypto.generateKeyPairSync(nodeName(alg))
  const jwk = privateKey.export({ format: 'jwk' })
  return {
    seed: Buffer.from(jwk.priv, 'base64url'),
    publicKey: Buffer.from(jwk.pub, 'base64url'),
    pkcs8: privateKey.export({ format: 'der', type: 'pkcs8' }),
  }
}

// ── seeds and expansion ─────────────────────────────────────────────────────

test('every parameter set expands its seed to the documented lengths', () => {
  const expected = {
    'ML-DSA-65':   { seed: 32, pub: 1952, sec: 4032 },
    'ML-DSA-87':   { seed: 32, pub: 2592, sec: 4896 },
    'ML-KEM-768':  { seed: 64, pub: 1184, sec: 2400 },
    'ML-KEM-1024': { seed: 64, pub: 1568, sec: 3168 },
  }
  assert.deepEqual(SEED_ALGORITHMS.sort(), Object.keys(expected).sort())
  for (const alg of SEED_ALGORITHMS) {
    const kp = keypairFromSeed(alg, new Uint8Array(expected[alg].seed).fill(7))
    assert.equal(kp.seed.length, expected[alg].seed, alg)
    assert.equal(kp.publicKey.length, expected[alg].pub, alg)
    assert.equal(kp.secretKey.length, expected[alg].sec, alg)
  }
})

test('a wrong-length seed is rejected rather than padded', () => {
  assert.throws(() => keypairFromSeed('ML-DSA-65', new Uint8Array(31)), RangeError)
  assert.throws(() => keypairFromSeed('ML-KEM-768', new Uint8Array(32)), RangeError)
})

test('an unknown parameter set names the ones that exist', () => {
  assert.throws(
    () => keypairFromSeed('SLH-DSA-SHA2-192s', new Uint8Array(32)),
    /seed form is defined for ML-DSA-65/,
  )
})

// This is the property that makes seed export usable on keys already in
// production: the seed a caller can now derive is the same seed
// keypairFromMaster has been deriving all along.
test('seedFromMaster reproduces exactly the key keypairFromMaster produces', () => {
  const cases = [
    ['ML-DSA-65', mlDsa], ['ML-DSA-87', mlDsa87],
    ['ML-KEM-768', mlKem], ['ML-KEM-1024', mlKem1024],
  ]
  for (const [alg, mod] of cases) {
    const legacy = mod.keypairFromMaster(MASTER)
    const fromSeed = keypairFromSeed(alg, seedFromMaster(alg, MASTER))
    assert.deepEqual(Buffer.from(fromSeed.publicKey), Buffer.from(legacy.publicKey), alg)
    assert.deepEqual(Buffer.from(fromSeed.secretKey), Buffer.from(legacy.secretKey), alg)
    // And keypairFromMaster now hands back that seed directly.
    assert.deepEqual(Buffer.from(legacy.seed), Buffer.from(fromSeed.seed), alg)
  }
})

test('keypairFromMaster still satisfies callers that only destructure the pair', () => {
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(MASTER)
  const sig = mlDsa.sign(secretKey, 'unchanged')
  assert.equal(mlDsa.verify(publicKey, 'unchanged', sig), true)
})

// ── JWK, RFC 9964 ───────────────────────────────────────────────────────────

test('AKP JWKs round-trip and carry the seed, not the expanded key', () => {
  for (const alg of SEED_ALGORITHMS) {
    const kp = keypairFromSeed(alg, seedFromMaster(alg, MASTER))
    const jwk = exportJwk(alg, kp, { kid: fingerprint(kp.publicKey) })
    assert.equal(jwk.kty, 'AKP', alg)
    assert.equal(jwk.alg, alg)
    assert.equal(Buffer.from(jwk.priv, 'base64url').length, kp.seed.length, alg)

    const back = importJwk(jwk)
    assert.deepEqual(Buffer.from(back.publicKey), Buffer.from(kp.publicKey), alg)
    assert.deepEqual(Buffer.from(back.secretKey), Buffer.from(kp.secretKey), alg)
  }
})

test('a public JWK has no priv and imports without a secret key', () => {
  const kp = keypairFromSeed('ML-DSA-65', seedFromMaster('ML-DSA-65', MASTER))
  const jwk = exportJwk('ML-DSA-65', { publicKey: kp.publicKey })
  assert.equal(jwk.priv, undefined)
  const back = importJwk(jwk)
  assert.equal(back.secretKey, undefined)
  assert.deepEqual(Buffer.from(back.publicKey), Buffer.from(kp.publicKey))
})

// The expanded key is the shape a caller is most likely to have to hand, and
// its first 32 bytes are not the seed. Accepting it would mint a JWK naming a
// key it does not contain.
test('an expanded secret key is refused where a seed belongs, and says why', () => {
  const kp = keypairFromSeed('ML-DSA-65', new Uint8Array(32).fill(1))
  assert.throws(
    () => exportJwk('ML-DSA-65', { publicKey: kp.publicKey, seed: kp.secretKey }),
    /which is the expanded secret key/,
  )
})

test('a JWK whose seed and public key disagree is rejected', () => {
  const kp = keypairFromSeed('ML-DSA-65', new Uint8Array(32).fill(1))
  const other = keypairFromSeed('ML-DSA-65', new Uint8Array(32).fill(2))
  // One key's public half, another key's seed.
  const jwk = { ...exportJwk('ML-DSA-65', kp), priv: exportJwk('ML-DSA-65', other).priv }
  assert.throws(() => importJwk(jwk), /inconsistent/)
})

test('a non-AKP JWK is rejected by kty', () => {
  assert.throws(() => importJwk({ kty: 'OKP', alg: 'ML-DSA-65', pub: 'AA' }), /expected 'AKP'/)
})

// ── PKCS#8 seed form ────────────────────────────────────────────────────────

test('seed-form PKCS#8 round-trips for every parameter set', () => {
  for (const alg of SEED_ALGORITHMS) {
    const seed = seedFromMaster(alg, MASTER)
    const der = exportSeedPkcs8(alg, seed)
    const back = importSeedPkcs8(der)
    assert.equal(back.alg, alg)
    assert.deepEqual(Buffer.from(back.seed), Buffer.from(seed), alg)
  }
})

// An expanded-form PKCS#8 key is structurally valid and parses right up to the
// private key, where the CHOICE tag differs. Returning its first 32 bytes as a
// seed would hand back a completely different keypair.
test('an expanded-form PKCS#8 key is refused, not truncated into a seed', () => {
  const alg = 'ML-DSA-65'
  const kp = keypairFromSeed(alg, seedFromMaster(alg, MASTER))
  const seedDer = Buffer.from(exportSeedPkcs8(alg, kp.seed))
  // Same prefix, but the private key OCTET STRING wraps a bare OCTET STRING
  // (expanded form, tag 0x04) instead of the [0] seed CHOICE (tag 0x80).
  const algId = seedDer.subarray(5, 5 + 13) // 0x30 0x34 | version(3) | AlgorithmIdentifier(13)
  const expanded = Buffer.from(kp.secretKey)
  const inner = Buffer.concat([Buffer.from([0x04, 0x82, expanded.length >> 8, expanded.length & 0xff]), expanded])
  const body = Buffer.concat([
    Buffer.from('020100', 'hex'), algId,
    Buffer.from([0x04, 0x82, inner.length >> 8, inner.length & 0xff]), inner,
  ])
  const der = Buffer.concat([Buffer.from([0x30, 0x82, body.length >> 8, body.length & 0xff]), body])
  assert.throws(() => importSeedPkcs8(der), /expanded form, not seed form/)
})

test('an unrecognised algorithm OID is refused', () => {
  const der = Buffer.from(exportSeedPkcs8('ML-DSA-65', seedFromMaster('ML-DSA-65', MASTER)))
  der[der.indexOf(0x12, 3)] = 0x7f // corrupt the last OID arc
  assert.throws(() => importSeedPkcs8(der), /unrecognised algorithm OID/)
})

// ── cross-backend: the encodings are OpenSSL's, not our reading of the spec ──

// FIPS 204 allows a private key to be carried as the seed or as the expanded
// key, and OpenSSL changed which one it writes by default between 3.5.6 and
// 3.5.7: 3.5.6 emits the 54-byte seed form, 3.5.7 the 4098-byte expanded form.
// Ours is unchanged and remains the seed form.
//
// So a flat byte comparison against whatever OpenSSL happens to emit tests the
// installed OpenSSL's preference, not our encoding. Where OpenSSL writes the
// seed form we still hold the strong claim, byte for byte. Where it writes the
// expanded form we assert the claim that actually matters and is true on both:
// OpenSSL parses our seed form and arrives at the same key.
test('seed-form PKCS#8 is what OpenSSL reads, and what it writes when it writes seeds', (t) => {
  if (!isNative('ML-DSA-65')) {
    return t.skip(`no native backend on this runtime (${backend().reason})`)
  }
  for (const alg of SEED_ALGORITHMS) {
    const theirs = nativeKeypair(alg)
    const ours = Buffer.from(exportSeedPkcs8(alg, theirs.seed))

    if (theirs.pkcs8.length === ours.length) {
      assert.deepEqual(ours, Buffer.from(theirs.pkcs8), `${alg} seed-form PKCS#8`)
      continue
    }

    // OpenSSL emitted the expanded form. Hand it our seed form and require it
    // to land on the same key it generated.
    const reread = crypto.createPrivateKey({ key: ours, format: 'der', type: 'pkcs8' })
    const rejwk = reread.export({ format: 'jwk' })
    assert.deepEqual(
      Buffer.from(rejwk.pub, 'base64url'),
      theirs.publicKey,
      `${alg} seed-form PKCS#8 must reload to the same public key`,
    )
    assert.deepEqual(
      Buffer.from(rejwk.priv, 'base64url'),
      theirs.seed,
      `${alg} seed-form PKCS#8 must reload to the same seed`,
    )
  }
})

test('a seed expands to the same public key under both backends', (t) => {
  if (!isNative('ML-DSA-65')) return t.skip('no native backend on this runtime')
  for (const alg of SEED_ALGORITHMS) {
    const theirs = nativeKeypair(alg)
    const ours = keypairFromSeed(alg, theirs.seed)
    assert.deepEqual(Buffer.from(ours.publicKey), theirs.publicKey, alg)
  }
})

test('OpenSSL accepts the JWKs and the DER this package writes', (t) => {
  if (!isNative('ML-DSA-65')) return t.skip('no native backend on this runtime')
  for (const alg of SEED_ALGORITHMS) {
    const kp = keypairFromSeed(alg, seedFromMaster(alg, MASTER))
    assert.doesNotThrow(
      () => crypto.createPrivateKey({ key: exportJwk(alg, kp), format: 'jwk' }),
      `${alg} JWK`,
    )
    assert.doesNotThrow(
      () => crypto.createPrivateKey({
        key: Buffer.from(exportSeedPkcs8(alg, kp.seed)), format: 'der', type: 'pkcs8',
      }),
      `${alg} seed PKCS#8`,
    )
  }
})

test('a signature made by OpenSSL from a seed verifies under this package', (t) => {
  if (!isNative('ML-DSA-65')) return t.skip('no native backend on this runtime')
  const alg = 'ML-DSA-65'
  const seed = seedFromMaster(alg, MASTER)
  const kp = keypairFromSeed(alg, seed)
  const key = crypto.createPrivateKey({ key: exportJwk(alg, kp), format: 'jwk' })
  const message = Buffer.from('signed by openssl from a seed')
  const sig = crypto.sign(null, message, key)
  assert.equal(mlDsa.verify(kp.publicKey, message, sig.toString('hex')), true)
})

// ── JWS ─────────────────────────────────────────────────────────────────────

test('a compact JWS round-trips and carries the header it was given', () => {
  const kp = mlDsa.keypairFromMaster(MASTER)
  const kid = fingerprint(kp.publicKey)
  const token = signJws({ sub: 'org_test', amount: 100 }, kp.secretKey, { kid, typ: 'JWT' })

  assert.equal(token.split('.').length, 3)
  const result = verifyJws(token, kp.publicKey, { kid })
  assert.equal(result.valid, true)
  assert.deepEqual(JSON.parse(result.text), { sub: 'org_test', amount: 100 })
  assert.deepEqual(result.header, { alg: 'ML-DSA-65', typ: 'JWT', kid })
})

test('JWS verification needs no network and no configuration', () => {
  // The whole point of keeping this in the free package: a holder of the
  // public key can check a token with nothing else present.
  const kp = mlDsa.keypairFromMaster(MASTER)
  const token = signJws('offline', kp.secretKey)
  assert.equal(verifyJws(token, kp.publicKey).valid, true)
})

test('ML-DSA-87 signs and verifies under its own alg name', () => {
  const kp = mlDsa87.keypairFromMaster(MASTER)
  const token = signJws({ n: 1 }, kp.secretKey, { alg: 'ML-DSA-87' })
  assert.equal(verifyJws(token, kp.publicKey).valid, true)
  assert.match(verifyJws(token, kp.publicKey, { alg: 'ML-DSA-65' }).error, /alg mismatch/)
})

test('a tampered payload fails', () => {
  const kp = mlDsa.keypairFromMaster(MASTER)
  const [h, , s] = signJws({ amount: 100 }, kp.secretKey).split('.')
  const forged = [h, Buffer.from(JSON.stringify({ amount: 999 })).toString('base64url'), s].join('.')
  assert.equal(verifyJws(forged, kp.publicKey).valid, false)
})

// The classic JWT failure: the token names the algorithm and a naive verifier
// obeys it. The allowlist is the only thing that resolves an implementation.
test('a token cannot name its own verification routine', () => {
  const kp = mlDsa.keypairFromMaster(MASTER)
  const [, p, s] = signJws({ a: 1 }, kp.secretKey).split('.')
  for (const alg of ['none', 'HS256', 'ML-DSA-44']) {
    const header = Buffer.from(JSON.stringify({ alg })).toString('base64url')
    const result = verifyJws([header, p, s].join('.'), kp.publicKey)
    assert.equal(result.valid, false, alg)
    assert.match(result.error, /unsupported JWS alg/, alg)
  }
})

test('crit and b64 headers are refused rather than ignored', () => {
  const kp = mlDsa.keypairFromMaster(MASTER)
  const [, p, s] = signJws({ a: 1 }, kp.secretKey).split('.')
  for (const [name, header] of [['crit', { alg: 'ML-DSA-65', crit: ['exp'] }], ['b64', { alg: 'ML-DSA-65', b64: false }]]) {
    const h = Buffer.from(JSON.stringify(header)).toString('base64url')
    const result = verifyJws([h, p, s].join('.'), kp.publicKey)
    assert.equal(result.valid, false, name)
    assert.match(result.error, /does not implement/, name)
  }
})

test('a public key of the wrong size is reported as such, not as a bad signature', () => {
  const kp = mlDsa.keypairFromMaster(MASTER)
  const kp87 = mlDsa87.keypairFromMaster(MASTER)
  assert.match(verifyJws(signJws({}, kp.secretKey), kp87.publicKey).error, /but ML-DSA-65 public keys are 1952/)
})

test('malformed tokens fail closed without throwing', () => {
  const kp = mlDsa.keypairFromMaster(MASTER)
  for (const bad of ['', 'a.b', 'a.b.c.d', 'a.b.c', '...', 'not a token']) {
    const result = verifyJws(bad, kp.publicKey)
    assert.equal(result.valid, false, JSON.stringify(bad))
    assert.equal(typeof result.error, 'string')
  }
})

test('a header member may not restate what the options own', () => {
  const kp = mlDsa.keypairFromMaster(MASTER)
  assert.throws(() => signJws({}, kp.secretKey, { header: { alg: 'ML-DSA-87' } }), /opts\.alg/)
})

test('decodeJwsHeader reads a header without verifying it', () => {
  const kp = mlDsa.keypairFromMaster(MASTER)
  const token = signJws({ a: 1 }, kp.secretKey, { kid: 'abc123' })
  assert.equal(decodeJwsHeader(token).kid, 'abc123')
  assert.equal(decodeJwsHeader('rubbish'), null)
})

// ── backend reporting ───────────────────────────────────────────────────────

test('the backend reports itself, and says which one it is', () => {
  const b = backend()
  assert.ok(['openssl', 'javascript'].includes(b.kind))
  if (b.kind === 'openssl') {
    assert.equal(typeof b.openssl, 'string')
    assert.ok(Array.isArray(b.parameterSets))
    assert.ok(b.parameterSets.includes('ML-DSA-65'))
  } else {
    assert.equal(typeof b.reason, 'string')
  }
})
