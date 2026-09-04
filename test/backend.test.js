// requireNativeBackend: the fail-closed assertion for deployments that must not
// silently fall back to the JavaScript implementation.
//
// This file is its own negative control, without any mocking. CI runs the suite
// on Node 20, 22 and 24. Node 20 and 22 have no OpenSSL 3.5 post-quantum
// primitives, so the JavaScript backend is live there and the refusal path is
// exercised for real; Node 24 exercises the accept path. Each test asserts the
// behaviour the live backend should produce, so both are covered by CI rather
// than by a stub that could drift from the real module.

import { test } from 'node:test'
import assert from 'node:assert/strict'

import { backend, isNative, requireNativeBackend } from '../src/index.js'

const NATIVE = backend().kind === 'openssl'

test('it agrees with backend() about which implementation is live', () => {
  if (NATIVE) {
    const b = requireNativeBackend()
    assert.equal(b.kind, 'openssl')
    assert.ok(b.openssl, 'the accepted backend should name its OpenSSL version')
  } else {
    assert.throws(
      () => requireNativeBackend(),
      (e) => {
        assert.equal(e.code, 'ERR_KXCO_PQ_BACKEND')
        assert.equal(e.actual, 'javascript')
        assert.match(e.message, /native backend is required/)
        return true
      },
      'it must refuse when the JavaScript backend is live',
    )
  }
})

test('a parameter set the backend cannot provide is refused by name', () => {
  if (!NATIVE) return   // covered by the test above on this runtime
  assert.throws(
    () => requireNativeBackend(['ML-DSA-65', 'NOT-A-REAL-SET']),
    (e) => {
      assert.equal(e.code, 'ERR_KXCO_PQ_BACKEND')
      assert.deepEqual(e.missing, ['NOT-A-REAL-SET'])
      assert.ok(Array.isArray(e.available), 'it should say what is available')
      return true
    },
  )
})

test('the sets it reports as native are the sets it accepts', () => {
  if (!NATIVE) return
  const sets = backend().parameterSets ?? []
  assert.ok(sets.length > 0, 'the native backend should list its parameter sets')
  for (const alg of sets) {
    assert.ok(isNative(alg), `${alg} is listed but isNative says otherwise`)
  }
  assert.doesNotThrow(() => requireNativeBackend(sets))
})

test('it asserts, it does not switch', () => {
  const before = backend()
  try { requireNativeBackend(['NOT-A-REAL-SET']) } catch {}
  assert.deepEqual(backend(), before, 'calling it must not change which backend is live')
})
