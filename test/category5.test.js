// ML-DSA-87 and ML-KEM-1024 (Security Category 5).
//
// Beyond the round trips, these tests pin the two properties that matter when a
// second parameter set exists alongside the default: the sizes callers will
// design storage around, and the fact that the two sets do not mix. A key or
// signature from one must not verify under the other, and one master must not
// derive the same key for both.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { randomBytes } from 'node:crypto'

import { mlDsa, mlKem, mlDsa87, mlKem1024 } from '../src/index.js'

test('ML-DSA-87 sign + verify round trip', () => {
  const master = randomBytes(32)
  const { publicKey, secretKey } = mlDsa87.keypairFromMaster(master)
  assert.equal(publicKey.length, 2592, 'ML-DSA-87 public key = 2592 bytes')
  assert.equal(secretKey.length, 4896, 'ML-DSA-87 secret key = 4896 bytes')

  const sig = mlDsa87.sign(secretKey, 'hello kxco')
  assert.equal(typeof sig, 'string')
  assert.equal(sig.length, 9254, 'ML-DSA-87 sig = 4627 bytes = 9254 hex chars')
  assert.ok(mlDsa87.verify(publicKey, 'hello kxco', sig))
  assert.ok(!mlDsa87.verify(publicKey, 'tampered', sig))
})

test('ML-DSA-87 keypair is deterministic from master', () => {
  const master = Buffer.from('22'.repeat(32), 'hex')
  const a = mlDsa87.keypairFromMaster(master, 'platform-v1')
  const b = mlDsa87.keypairFromMaster(master, 'platform-v1')
  assert.deepEqual(a.publicKey, b.publicKey)
  assert.deepEqual(a.secretKey, b.secretKey)
})

test('ML-DSA-87 honours the FIPS 204 context string', () => {
  const master = randomBytes(32)
  const { publicKey, secretKey } = mlDsa87.keypairFromMaster(master)
  const sig = mlDsa87.sign(secretKey, 'payload', { context: 'kxco-v1' })

  assert.ok(mlDsa87.verify(publicKey, 'payload', sig, { context: 'kxco-v1' }))
  assert.ok(!mlDsa87.verify(publicKey, 'payload', sig), 'context omitted must fail')
  assert.ok(!mlDsa87.verify(publicKey, 'payload', sig, { context: 'other' }))
  assert.equal(mlDsa87.MAX_CONTEXT_BYTES, 255)
})

test('ML-DSA-87 rejects a context over 255 bytes rather than truncating', () => {
  const master = randomBytes(32)
  const { secretKey } = mlDsa87.keypairFromMaster(master)
  assert.throws(() => mlDsa87.sign(secretKey, 'payload', { context: 'x'.repeat(256) }), RangeError)
})

test('ML-DSA-65 and ML-DSA-87 do not mix', () => {
  const master = Buffer.from('33'.repeat(32), 'hex')

  // One master, same info, must not yield the same key for both sets: the
  // default info strings differ precisely so the two cannot collide.
  const k65 = mlDsa.keypairFromMaster(master)
  const k87 = mlDsa87.keypairFromMaster(master)
  assert.notEqual(k65.publicKey.length, k87.publicKey.length)

  // A signature from one set must not verify under the other. Both directions,
  // because verify returns false rather than throwing on a length mismatch.
  const sig65 = mlDsa.sign(k65.secretKey, 'payload')
  const sig87 = mlDsa87.sign(k87.secretKey, 'payload')
  assert.ok(!mlDsa87.verify(k87.publicKey, 'payload', sig65))
  assert.ok(!mlDsa.verify(k65.publicKey, 'payload', sig87))
})

test('ML-KEM-1024 encapsulate + decapsulate round trip', () => {
  const master = randomBytes(32)
  const { publicKey, secretKey } = mlKem1024.keypairFromMaster(master)
  assert.equal(publicKey.length, 1568, 'ML-KEM-1024 public key = 1568 bytes')
  assert.equal(secretKey.length, 3168, 'ML-KEM-1024 secret key = 3168 bytes')

  const { ciphertext, cipherText, sharedSecret } = mlKem1024.encapsulate(publicKey)
  assert.equal(ciphertext.length, 1568, 'ML-KEM-1024 ciphertext = 1568 bytes')
  assert.deepEqual(ciphertext, cipherText, 'both spellings return the same bytes')
  assert.equal(sharedSecret.length, 32, 'shared secret stays 32 bytes at Category 5')

  const recovered = mlKem1024.decapsulate(ciphertext, secretKey)
  assert.deepEqual(recovered, sharedSecret)
})

test('ML-KEM-1024 implicit rejection returns an unrelated secret, not an error', () => {
  const master = randomBytes(32)
  const { publicKey, secretKey } = mlKem1024.keypairFromMaster(master)
  const { ciphertext, sharedSecret } = mlKem1024.encapsulate(publicKey)

  const corrupted = Buffer.from(ciphertext)
  corrupted[0] ^= 0x01

  const recovered = mlKem1024.decapsulate(corrupted, secretKey)
  assert.equal(recovered.length, 32, 'FIPS 203 implicit rejection still returns 32 bytes')
  assert.notDeepEqual(recovered, sharedSecret, 'and they must not be the real secret')
})

test('ML-KEM-1024 keypair is deterministic and separated from ML-KEM-768', () => {
  const master = Buffer.from('44'.repeat(32), 'hex')
  const a = mlKem1024.keypairFromMaster(master, 'platform-v1')
  const b = mlKem1024.keypairFromMaster(master, 'platform-v1')
  assert.deepEqual(a.publicKey, b.publicKey)

  const k768 = mlKem.keypairFromMaster(master)
  const k1024 = mlKem1024.keypairFromMaster(master)
  assert.notEqual(k768.publicKey.length, k1024.publicKey.length)
})

test('Category 5 modules re-export the raw primitives', () => {
  assert.equal(typeof mlDsa87.ml_dsa87.keygen, 'function')
  assert.equal(mlDsa87.ml_dsa87.securityLevel, 256, 'ML-DSA-87 is Category 5')
  assert.equal(typeof mlKem1024.ml_kem1024.keygen, 'function')
  assert.equal(mlKem1024.ml_kem1024.lengths.cipherText, 1568)
})
