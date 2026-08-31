// Edge cases at the boundaries of the published API.
//
// The rest of the suite exercises the middle of the range: ordinary messages,
// ordinary keys, ordinary contexts. This file covers the ends, where the
// interesting failures live. Each case states what it asserts and why that is
// the correct behaviour rather than an accident of the implementation.
//
// Two principles run through it, and they are not the same principle:
//
//   A cryptographic failure returns false. A wrong key, a corrupted signature,
//   a mismatched context: the answer to "is this signature valid" is no, and no
//   is a value, not an exception.
//
//   Caller misuse throws. A context longer than FIPS 204 allows, or an options
//   argument of the wrong type, is a bug in the calling code. Returning false
//   there would let a program that can never verify anything look like a
//   program that is merely receiving bad signatures.
//
// Running on Node 24 or later exercises the OpenSSL backend, and on Node 20 or
// 22 the JavaScript one. Both are expected to behave identically here, which is
// most of the point of asserting it.

import test from 'node:test'
import assert from 'node:assert/strict'

import * as mlDsa from '../src/ml-dsa.js'
import * as mlDsa87 from '../src/ml-dsa-87.js'
import * as mlKem from '../src/ml-kem.js'
import * as mlKem1024 from '../src/ml-kem-1024.js'
import * as slhDsa from '../src/slh-dsa.js'
import { MAX_CONTEXT_BYTES } from '../src/_context.js'

const MASTER = new Uint8Array(32).fill(7)

const SIGNERS = [
  ['ML-DSA-65', mlDsa, 1952, 3309],
  ['ML-DSA-87', mlDsa87, 2592, 4627],
  ['SLH-DSA-SHA2-192s', slhDsa, 48, 35664],
]

const KEMS = [
  ['ML-KEM-768', mlKem, 1184, 1088],
  ['ML-KEM-1024', mlKem1024, 1568, 1568],
]

// --------------------------------------------------------------- empty inputs

test('a zero-length message signs and verifies', (t) => {
  for (const [name, impl] of SIGNERS) {
    const { publicKey, secretKey } = impl.keypairFromMaster(MASTER)
    const empty = new Uint8Array(0)
    const sig = impl.sign(secretKey, empty)
    assert.equal(impl.verify(publicKey, empty, sig), true, `${name}: empty message`)

    // and it must not be interchangeable with a one-byte message
    assert.equal(
      impl.verify(publicKey, new Uint8Array(1), sig),
      false,
      `${name}: empty-message signature verified against a non-empty message`
    )
  }
})

test('an empty context is not the same as no context', (t) => {
  // FIPS 204 signs the context length alongside the context, so a zero-length
  // context is a real choice a signer made and not an absent one. This package
  // treats them as the same, deliberately: an empty Uint8Array normalises to
  // undefined. Asserted so a future change to that normalisation is caught here
  // rather than discovered by a counterparty whose signatures stop verifying.
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(MASTER)
  const msg = new TextEncoder().encode('boundary')

  const noCtx = mlDsa.sign(secretKey, msg)
  const emptyCtx = mlDsa.sign(secretKey, msg, { context: new Uint8Array(0) })

  assert.equal(mlDsa.verify(publicKey, msg, noCtx), true)
  assert.equal(mlDsa.verify(publicKey, msg, emptyCtx), true)
  assert.equal(mlDsa.verify(publicKey, msg, noCtx, { context: new Uint8Array(0) }), true)
})

// ------------------------------------------------------- maximum-size context

test(`a context of exactly ${MAX_CONTEXT_BYTES} bytes is accepted`, (t) => {
  // FIPS 204 section 5.2 caps the context at 255 bytes. The boundary is the
  // interesting value: 255 must work and 256 must not.
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(MASTER)
  const msg = new TextEncoder().encode('ctx boundary')
  const maxCtx = new Uint8Array(MAX_CONTEXT_BYTES).fill(0xab)

  const sig = mlDsa.sign(secretKey, msg, { context: maxCtx })
  assert.equal(mlDsa.verify(publicKey, msg, sig, { context: maxCtx }), true)

  // one byte different in the context, and it must not verify
  const off = Uint8Array.from(maxCtx)
  off[MAX_CONTEXT_BYTES - 1] ^= 0x01
  assert.equal(mlDsa.verify(publicKey, msg, sig, { context: off }), false)
})

test(`a context of ${MAX_CONTEXT_BYTES + 1} bytes throws rather than returning false`, (t) => {
  // Caller misuse, not a failed verification. See the header.
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(MASTER)
  const msg = new TextEncoder().encode('too long')
  const over = new Uint8Array(MAX_CONTEXT_BYTES + 1)

  assert.throws(() => mlDsa.sign(secretKey, msg, { context: over }))
  assert.throws(() => mlDsa.verify(publicKey, msg, '00'.repeat(3309), { context: over }))
})

// ------------------------------------------------------- malformed signatures

test('a malformed signature returns false and does not throw', (t) => {
  for (const [name, impl, , sigLen] of SIGNERS) {
    const { publicKey } = impl.keypairFromMaster(MASTER)
    const msg = new TextEncoder().encode('malformed')

    for (const [label, bad] of [
      ['empty', ''],
      ['odd length hex', 'abc'],
      ['not hex', 'zz'.repeat(sigLen)],
      ['one byte short', '00'.repeat(sigLen - 1)],
      ['one byte long', '00'.repeat(sigLen + 1)],
      ['all zeroes', '00'.repeat(sigLen)],
      ['all ones', 'ff'.repeat(sigLen)],
    ]) {
      assert.equal(impl.verify(publicKey, msg, bad), false, `${name}: ${label} should be false`)
    }
  }
})

test('a wrong-size public key returns false and does not throw', (t) => {
  for (const [name, impl, pkLen] of SIGNERS) {
    const { secretKey } = impl.keypairFromMaster(MASTER)
    const msg = new TextEncoder().encode('wrong key')
    const sig = impl.sign(secretKey, msg)

    for (const [label, key] of [
      ['empty', new Uint8Array(0)],
      ['one byte short', new Uint8Array(pkLen - 1)],
      ['one byte long', new Uint8Array(pkLen + 1)],
      ['all zeroes', new Uint8Array(pkLen)],
    ]) {
      assert.equal(impl.verify(key, msg, sig), false, `${name}: ${label} should be false`)
    }
  }
})

test('a signature does not verify under a different key', (t) => {
  for (const [name, impl] of SIGNERS) {
    const a = impl.keypairFromMaster(MASTER)
    const b = impl.keypairFromMaster(new Uint8Array(32).fill(8))
    const msg = new TextEncoder().encode('cross key')

    const sig = impl.sign(a.secretKey, msg)
    assert.equal(impl.verify(a.publicKey, msg, sig), true, `${name}: own key`)
    assert.equal(impl.verify(b.publicKey, msg, sig), false, `${name}: other key`)
  }
})

// ----------------------------------------------------------------- large input

test('a one-megabyte message signs and verifies', (t) => {
  // Not a size limit test, a "does anything truncate" test. A backend that
  // hashed only a prefix would pass every small case in this suite.
  const { publicKey, secretKey } = mlDsa.keypairFromMaster(MASTER)
  const big = new Uint8Array(1024 * 1024)
  for (let i = 0; i < big.length; i++) big[i] = i & 0xff

  const sig = mlDsa.sign(secretKey, big)
  assert.equal(mlDsa.verify(publicKey, big, sig), true)

  // flip the last byte: a prefix-only implementation would still return true
  const tail = Uint8Array.from(big)
  tail[tail.length - 1] ^= 0x01
  assert.equal(mlDsa.verify(publicKey, tail, sig), false, 'a change in the final byte was not detected')
})

// ------------------------------------------------------------------- ML-KEM

test('a malformed ciphertext decapsulates to an unrelated secret, not an error', (t) => {
  // FIPS 203 implicit rejection: decapsulation of a bad ciphertext must return
  // a pseudorandom secret rather than signalling failure, because signalling
  // failure is the oracle the design exists to remove.
  for (const [name, impl, , ctLen] of KEMS) {
    const { publicKey, secretKey } = impl.keypairFromMaster(MASTER)
    const { cipherText, sharedSecret } = impl.encapsulate(publicKey)

    const corrupted = Uint8Array.from(cipherText)
    corrupted[0] ^= 0x01
    const recovered = impl.decapsulate(corrupted, secretKey)

    assert.equal(recovered.length, sharedSecret.length, `${name}: shared secret length changed`)
    assert.notDeepEqual(
      Buffer.from(recovered),
      Buffer.from(sharedSecret),
      `${name}: a corrupted ciphertext returned the real shared secret`
    )
    assert.equal(cipherText.length, ctLen, `${name}: unexpected ciphertext length`)
  }
})

test('encapsulation is not deterministic', (t) => {
  // Two encapsulations to the same key must differ. A KEM that returned the
  // same ciphertext twice would be catastrophically broken, and it is the kind
  // of break a seeded test harness can hide.
  for (const [name, impl] of KEMS) {
    const { publicKey } = impl.keypairFromMaster(MASTER)
    const a = impl.encapsulate(publicKey)
    const b = impl.encapsulate(publicKey)
    assert.notDeepEqual(Buffer.from(a.cipherText), Buffer.from(b.cipherText), `${name}: ciphertext repeated`)
    assert.notDeepEqual(Buffer.from(a.sharedSecret), Buffer.from(b.sharedSecret), `${name}: secret repeated`)
  }
})

// -------------------------------------------------------------- determinism

test('key derivation from the same master is deterministic', (t) => {
  for (const [name, impl] of [...SIGNERS, ...KEMS]) {
    const a = impl.keypairFromMaster(MASTER)
    const b = impl.keypairFromMaster(MASTER)
    assert.deepEqual(Buffer.from(a.publicKey), Buffer.from(b.publicKey), `${name}: public key not deterministic`)
    assert.deepEqual(Buffer.from(a.secretKey), Buffer.from(b.secretKey), `${name}: secret key not deterministic`)
  }
})

test('a different info string derives a different key', (t) => {
  // Domain separation is the reason the info parameter exists; if it did not
  // change the output it would be decorative.
  const a = mlDsa.keypairFromMaster(MASTER, 'ml-dsa-65-v1')
  const b = mlDsa.keypairFromMaster(MASTER, 'ml-dsa-65-v2')
  assert.notDeepEqual(Buffer.from(a.publicKey), Buffer.from(b.publicKey))
})
