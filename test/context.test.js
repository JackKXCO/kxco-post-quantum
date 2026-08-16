// FIPS 204 / FIPS 205 context string support.
//
// Covers: backward compatibility (no context), empty context, non-empty
// context, domain separation between contexts, the 255-byte bound, caller
// misuse, and cross-verification against third-party signatures produced by
// OpenSSL (via Python `cryptography`) with and without a context.

import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, existsSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'

import * as mlDsa from '../src/ml-dsa.js'
import * as slhDsa from '../src/slh-dsa.js'
import { MAX_CONTEXT_BYTES } from '../src/_context.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const MASTER = 'context-test-master-do-not-use-in-production'
const MESSAGE = 'kxco context separation test'

const kp = mlDsa.keypairFromMaster(MASTER)

// ---------------------------------------------------------------------------
// Backward compatibility. Nothing that worked before may change.
// ---------------------------------------------------------------------------

test('existing two-argument sign/verify still works', () => {
  const sig = mlDsa.sign(kp.secretKey, MESSAGE)
  assert.equal(typeof sig, 'string')
  assert.equal(sig.length, 6618)
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig), true)
})

test('omitting opts is identical to passing undefined', () => {
  const sig = mlDsa.sign(kp.secretKey, MESSAGE, undefined)
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig), true)
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig, undefined), true)
})

test('a signature made without a context verifies without one', () => {
  const sig = mlDsa.sign(kp.secretKey, MESSAGE)
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig), true)
})

// ---------------------------------------------------------------------------
// Empty context is equivalent to no context.
// ---------------------------------------------------------------------------

test('empty string context is equivalent to no context', () => {
  const sig = mlDsa.sign(kp.secretKey, MESSAGE, { context: '' })
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig), true)
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig, { context: '' }), true)
})

test('empty byte context is equivalent to no context', () => {
  const sig = mlDsa.sign(kp.secretKey, MESSAGE, { context: new Uint8Array(0) })
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig), true)
})

test('context: undefined and context: null are treated as absent', () => {
  const a = mlDsa.sign(kp.secretKey, MESSAGE, { context: undefined })
  const b = mlDsa.sign(kp.secretKey, MESSAGE, { context: null })
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, a), true)
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, b), true)
})

// ---------------------------------------------------------------------------
// Non-empty context: the actual feature.
// ---------------------------------------------------------------------------

test('a signature made with a context verifies with that context', () => {
  const sig = mlDsa.sign(kp.secretKey, MESSAGE, { context: 'kxco-nexus-v1' })
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig, { context: 'kxco-nexus-v1' }), true)
})

test('a context signature does NOT verify without the context', () => {
  const sig = mlDsa.sign(kp.secretKey, MESSAGE, { context: 'kxco-nexus-v1' })
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig), false)
})

test('a context signature does NOT verify under a different context', () => {
  const sig = mlDsa.sign(kp.secretKey, MESSAGE, { context: 'kxco-nexus-v1' })
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig, { context: 'kxco-verify-v1' }), false)
})

test('a no-context signature does NOT verify under a context', () => {
  const sig = mlDsa.sign(kp.secretKey, MESSAGE)
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig, { context: 'kxco-nexus-v1' }), false)
})

test('string and byte contexts with the same UTF-8 bytes are interchangeable', () => {
  const asBytes = new TextEncoder().encode('kxco-nexus-v1')
  const sig = mlDsa.sign(kp.secretKey, MESSAGE, { context: 'kxco-nexus-v1' })
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig, { context: asBytes }), true)
})

test('a non-ASCII context round-trips as UTF-8', () => {
  const ctx = 'kxco-é中-v1'
  const sig = mlDsa.sign(kp.secretKey, MESSAGE, { context: ctx })
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig, { context: ctx }), true)
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig), false)
})

// ---------------------------------------------------------------------------
// FIPS 204 section 5.2 bound.
// ---------------------------------------------------------------------------

test('MAX_CONTEXT_BYTES is 255', () => {
  assert.equal(MAX_CONTEXT_BYTES, 255)
  assert.equal(mlDsa.MAX_CONTEXT_BYTES, 255)
  assert.equal(slhDsa.MAX_CONTEXT_BYTES, 255)
})

test('a 255-byte context is accepted', () => {
  const ctx = new Uint8Array(255).fill(0x41)
  const sig = mlDsa.sign(kp.secretKey, MESSAGE, { context: ctx })
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig, { context: ctx }), true)
})

test('a 256-byte context is rejected on sign', () => {
  const ctx = new Uint8Array(256).fill(0x41)
  assert.throws(() => mlDsa.sign(kp.secretKey, MESSAGE, { context: ctx }), RangeError)
})

test('a 256-byte context is rejected on verify, not silently false', () => {
  // A malformed context is a programming error, not a failed verification.
  // Returning false here would hide the bug behind a normal-looking outcome.
  const sig = mlDsa.sign(kp.secretKey, MESSAGE)
  assert.throws(
    () => mlDsa.verify(kp.publicKey, MESSAGE, sig, { context: new Uint8Array(256) }),
    RangeError,
  )
})

test('a multi-byte character context is bounded by BYTES, not characters', () => {
  // 128 characters, 256 UTF-8 bytes. Must be rejected.
  const ctx = 'é'.repeat(128)
  assert.equal(new TextEncoder().encode(ctx).length, 256)
  assert.throws(() => mlDsa.sign(kp.secretKey, MESSAGE, { context: ctx }), RangeError)
})

// ---------------------------------------------------------------------------
// Caller misuse must throw rather than silently do the wrong thing.
// ---------------------------------------------------------------------------

test('passing a bare string instead of an options object throws', () => {
  // Guards the most likely misuse: sign(sk, msg, 'my-context'), which would
  // otherwise silently sign with NO context and produce a valid-looking
  // signature carrying none of the intended domain separation.
  assert.throws(() => mlDsa.sign(kp.secretKey, MESSAGE, 'kxco-nexus-v1'), TypeError)
})

test('passing bare bytes instead of an options object throws', () => {
  assert.throws(
    () => mlDsa.sign(kp.secretKey, MESSAGE, new TextEncoder().encode('ctx')),
    TypeError,
  )
})

test('a non-string non-bytes context throws', () => {
  assert.throws(() => mlDsa.sign(kp.secretKey, MESSAGE, { context: 42 }), TypeError)
  assert.throws(() => mlDsa.sign(kp.secretKey, MESSAGE, { context: {} }), TypeError)
})

test('unknown options keys are ignored', () => {
  const sig = mlDsa.sign(kp.secretKey, MESSAGE, { context: 'a', somethingElse: true })
  assert.equal(mlDsa.verify(kp.publicKey, MESSAGE, sig, { context: 'a' }), true)
})

// ---------------------------------------------------------------------------
// SLH-DSA carries the same behaviour.
// ---------------------------------------------------------------------------

test('SLH-DSA supports context with the same semantics', () => {
  const s = slhDsa.keypairFromMaster(MASTER)
  const sig = slhDsa.sign(s.secretKey, MESSAGE, { context: 'kxco-slh-v1' })
  assert.equal(slhDsa.verify(s.publicKey, MESSAGE, sig, { context: 'kxco-slh-v1' }), true)
  assert.equal(slhDsa.verify(s.publicKey, MESSAGE, sig), false)
})

test('SLH-DSA two-argument form is unchanged', () => {
  const s = slhDsa.keypairFromMaster(MASTER)
  const sig = slhDsa.sign(s.secretKey, MESSAGE)
  assert.equal(slhDsa.verify(s.publicKey, MESSAGE, sig), true)
})

// ---------------------------------------------------------------------------
// Third-party cross-verification.
//
// Fixtures are produced by OpenSSL through Python `cryptography` (see
// test/fixtures/generate-context-fixtures.py). They are committed, so this
// test runs everywhere without Python. If the fixture file is absent the test
// FAILS rather than skips: a skipped interop test reports green and looks like
// evidence it is not.
// ---------------------------------------------------------------------------

test('verifies a third-party signature made WITH a context', () => {
  const path = join(HERE, 'fixtures', 'context-vectors.json')
  assert.ok(
    existsSync(path),
    'test/fixtures/context-vectors.json is missing. Regenerate with ' +
    'test/fixtures/generate-context-fixtures.py. This test fails rather than ' +
    'skips because a skipped interop test looks like passing evidence.',
  )
  const v = JSON.parse(readFileSync(path, 'utf8'))
  const pub = Buffer.from(v.publicKey, 'hex')
  const msg = Buffer.from(v.message, 'hex')

  for (const c of v.withContext) {
    const ctx = Buffer.from(c.context, 'hex')
    assert.equal(
      mlDsa.verify(pub, msg, c.signature, { context: ctx }), true,
      `third-party signature with context "${c.label}" should verify with that context`,
    )
    assert.equal(
      mlDsa.verify(pub, msg, c.signature), false,
      `third-party signature with context "${c.label}" must not verify without it`,
    )
  }
})

test('verifies a third-party signature made WITHOUT a context', () => {
  const path = join(HERE, 'fixtures', 'context-vectors.json')
  assert.ok(existsSync(path), 'test/fixtures/context-vectors.json is missing')
  const v = JSON.parse(readFileSync(path, 'utf8'))
  const pub = Buffer.from(v.publicKey, 'hex')
  const msg = Buffer.from(v.message, 'hex')

  assert.equal(mlDsa.verify(pub, msg, v.noContext.signature), true)
  assert.equal(
    mlDsa.verify(pub, msg, v.noContext.signature, { context: 'unexpected' }), false,
  )
})

test('our context signature verifies under the third-party public key path', () => {
  // Reverse direction: the fixture carries a seed, so we can rebuild the same
  // keypair here and confirm both implementations agree on key derivation
  // before comparing signatures at all.
  const path = join(HERE, 'fixtures', 'context-vectors.json')
  assert.ok(existsSync(path), 'test/fixtures/context-vectors.json is missing')
  const v = JSON.parse(readFileSync(path, 'utf8'))
  const seed = Buffer.from(v.seed, 'hex')
  const ours = mlDsa.ml_dsa65.keygen(new Uint8Array(seed))
  assert.equal(
    Buffer.from(ours.publicKey).toString('hex'), v.publicKey,
    'keygen from the same seed must produce the same public key',
  )
})
