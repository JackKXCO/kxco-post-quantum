// Browser-environment smoke test.
//
// Runs the public API in a context where `Buffer` is undefined to confirm
// the package works without Node-only globals. Verifies that key outputs are
// plain Uint8Array (not Buffer), and that signing + verification round-trip
// correctly under the same code paths a browser would hit.
//
// Run alongside the Node-flavoured basic.test.js — together they prove the
// same source works in both runtimes.

import { test } from 'node:test'
import assert from 'node:assert/strict'

// Stash and remove Buffer so import-time HAS_BUFFER detection sees a browser.
const realBuffer = globalThis.Buffer
delete globalThis.Buffer

const { mlDsa, mlKem, slhDsa, deriveSeed, fingerprint, webhook } = await import('../src/index.js?nobuf')

test('deriveSeed returns Uint8Array (not Buffer) when Buffer is absent', () => {
  const master = new Uint8Array(32)
  for (let i = 0; i < 32; i++) master[i] = i
  const seed = deriveSeed(master, 'browser-test', 32)
  assert.ok(seed instanceof Uint8Array, 'must be Uint8Array')
  assert.equal(seed.constructor.name, 'Uint8Array', 'must NOT be Buffer subclass')
  assert.equal(seed.length, 32)
})

test('ML-DSA keypair returns plain Uint8Array in browser-mode', () => {
  const master = new Uint8Array(32)
  for (let i = 0; i < 32; i++) master[i] = 0xAB
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(master)
  assert.equal(publicKey.constructor.name, 'Uint8Array')
  assert.equal(secretKey.constructor.name, 'Uint8Array')
  assert.equal(publicKey.length, 1952)
  assert.equal(secretKey.length, 4032)
})

test('ML-DSA sign + verify round-trip in browser-mode', () => {
  const master = new Uint8Array(32).fill(7)
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(master)
  const sig = mlDsa.sign(secretKey, 'browser-payload')
  assert.equal(typeof sig, 'string')
  assert.equal(sig.length, 6618)
  assert.ok(mlDsa.verify(publicKey, 'browser-payload', sig))
  assert.ok(!mlDsa.verify(publicKey, 'tampered', sig))
})

test('SLH-DSA sign + verify round-trip in browser-mode', () => {
  const master = new Uint8Array(32).fill(0x5a)
  const { publicKey, secretKey } = slhDsa.keypairFromMaster(master)
  assert.equal(publicKey.constructor.name, 'Uint8Array')
  assert.equal(secretKey.constructor.name, 'Uint8Array')
  const sig = slhDsa.sign(secretKey, 'browser-payload')
  assert.equal(typeof sig, 'string')
  assert.equal(sig.length, 32448)
  assert.ok(slhDsa.verify(publicKey, 'browser-payload', sig))
  assert.ok(!slhDsa.verify(publicKey, 'tampered', sig))
})

test('ML-KEM encapsulate/decapsulate in browser-mode', () => {
  const master = new Uint8Array(32).fill(9)
  const { publicKey, secretKey } = mlKem.keypairFromMaster(master)
  const { ciphertext, sharedSecret } = mlKem.encapsulate(publicKey)
  const recovered = mlKem.decapsulate(ciphertext, secretKey)
  assert.equal(ciphertext.constructor.name, 'Uint8Array')
  assert.equal(sharedSecret.constructor.name, 'Uint8Array')
  assert.deepEqual(sharedSecret, recovered)
})

test('fingerprint works without Buffer', () => {
  const master = new Uint8Array(32).fill(3)
  const { publicKey } = mlDsa.keypairFromMaster(master)
  const kid = fingerprint(publicKey)
  assert.equal(kid.length, 16)
  assert.match(kid, /^[0-9a-f]{16}$/)
})

test('hybrid webhook sign + verify in browser-mode', () => {
  const master = new Uint8Array(32).fill(5)
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(master)
  const kid = fingerprint(publicKey)
  const rawBody = JSON.stringify({ event: 'browser.test', n: 42 })
  const headers = webhook.signDelivery({
    rawBody, hmacSecret: 'browser-shared', pqSecretKey: secretKey, pqKid: kid,
  })
  const lowered = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])
  )
  const result = webhook.verifyDelivery({
    headers: lowered, rawBody, hmacSecret: 'browser-shared',
    pqPublicKey: publicKey, pinnedKid: kid,
  })
  assert.ok(result.hmacOk, 'hmac must verify')
  assert.ok(result.pqOk,   'pq must verify')
  assert.ok(result.kidOk)
  assert.ok(result.timestampOk)
})

// Restore Buffer so any downstream tests aren't affected.
test.after(() => {
  if (realBuffer) globalThis.Buffer = realBuffer
})

// ── seed form and JWS without Buffer ────────────────────────────────────────
//
// Both new modules do their own base64url, because Buffer is the fast path and
// btoa/atob is the only one a browser has. A bug in the fallback would be
// invisible on Node, so it is exercised here rather than assumed.

const { seed: seedApi, jws } = await import('../src/index.js?nobuf') // same cached module: HAS_BUFFER was false at its import

test('seed-form JWKs round-trip without Buffer', () => {
  for (const alg of seedApi.SEED_ALGORITHMS) {
    const master = new Uint8Array(32).fill(0x5c)
    const kp = seedApi.keypairFromSeed(alg, seedApi.seedFromMaster(alg, master))
    assert.equal(kp.seed.constructor.name, 'Uint8Array', alg)

    const jwk = seedApi.exportJwk(alg, kp)
    const back = seedApi.importJwk(jwk)
    assert.deepEqual(back.publicKey, kp.publicKey, `${alg} pub`)
    assert.deepEqual(back.secretKey, kp.secretKey, `${alg} sec`)
  }
})

test('seed-form PKCS#8 round-trips without Buffer', () => {
  const alg = 'ML-DSA-65'
  const s = seedApi.seedFromMaster(alg, new Uint8Array(32).fill(0x5c))
  const der = seedApi.exportSeedPkcs8(alg, s)
  assert.equal(der.constructor.name, 'Uint8Array')
  assert.deepEqual(seedApi.importSeedPkcs8(der).seed, s)
})

test('compact JWS signs and verifies without Buffer', () => {
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(new Uint8Array(32).fill(0x11))
  const token = jws.signJws({ browser: true }, secretKey, { kid: fingerprint(publicKey) })
  const result = jws.verifyJws(token, publicKey)
  assert.equal(result.valid, true)
  assert.deepEqual(JSON.parse(result.text), { browser: true })
})
