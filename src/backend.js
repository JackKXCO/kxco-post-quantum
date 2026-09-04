// Which implementation is actually doing the maths, right now, on this box.
//
// The package picks its backend at import time by probing the runtime, not by
// reading a version number, so the only honest way to state which one a given
// deployment used is to ask it. This exists so that an evidence bundle, a
// support ticket or a customer's own conformance run can record the answer
// instead of inferring it from `process.version`.
//
// It reports; it does not switch. There is deliberately no way to force a
// backend from here: the two produce identical wire bytes, and a runtime flag
// that changed which one signed would be a flag that changes what a customer's
// evidence means.
//
// `requireNativeBackend` at the bottom is not an exception to that. It cannot
// change which backend runs. It refuses to let the process continue on the
// wrong one, which is a different thing, and the thing a deployment under a
// validated-module control actually needs.

import { native } from '#native'

// An operator control. A deployment under a validated-module requirement is
// usually not the same team as the one calling this library, so the
// requirement has to be enforceable from the environment rather than only from
// application code. Set KXCO_PQ_REQUIRE_NATIVE=1 and a process that has landed
// on the JavaScript backend fails at import, not at its first signature.
//
// Read defensively: this module is also loaded in browsers, where `process`
// does not exist.
const REQUIRE_NATIVE = (() => {
  try {
    const v = globalThis.process?.env?.KXCO_PQ_REQUIRE_NATIVE
    return v === '1' || v === 'true'
  } catch {
    return false
  }
})()

/**
 * Describe the active backend.
 *
 * @returns {{ kind: 'openssl'|'javascript', library: string, openssl?: string,
 *             parameterSets?: string[], reason?: string }}
 */
export function backend() {
  if (native === null) {
    return {
      kind: 'javascript',
      library: '@noble/post-quantum',
      reason: 'the runtime does not provide the FIPS 203/204/205 primitives',
    }
  }
  return {
    kind: 'openssl',
    library: 'node:crypto',
    openssl: native.openssl,
    // Only the sets OpenSSL can express. Anything absent here still works, on
    // the JavaScript backend, which is why this is a list rather than a flag.
    parameterSets: native.algorithms(),
  }
}

/**
 * Whether a given parameter set runs on the native backend in this process.
 *
 * @param {string} alg — e.g. 'ML-DSA-65'
 * @returns {boolean}
 */
export function isNative(alg) {
  return native !== null && native.supports(alg)
}

/**
 * Refuse to run unless the cryptography is executing in the native backend.
 *
 * This is an assertion, not a switch. It cannot change which implementation
 * signs, for the reason given at the top of this file. What it does is stop a
 * process that has silently landed on the JavaScript backend when the operator
 * required otherwise, before it produces its first signature rather than after.
 *
 * The default behaviour of this package is to fall back, and that default is
 * correct: the two backends produce identical wire bytes. It is wrong in one
 * specific situation, which is a deployment under a control that says the
 * cryptography must execute inside a validated module. There, a silent fallback
 * means the control is not in force and nothing says so.
 *
 * Note what this does and does not claim. It asserts that OpenSSL is doing the
 * maths. Whether that OpenSSL is a FIPS-validated module is a property of the
 * operator's build, not of this package, and this function cannot see it. It
 * removes the fallback, which is the part we can be responsible for.
 *
 * @param {string[]} [algorithms] — parameter sets that must run natively.
 *   Omit to require only that the native backend is present at all.
 * @throws {Error} with `code: 'ERR_KXCO_PQ_BACKEND'` when the requirement fails.
 */
export function requireNativeBackend(algorithms) {
  const b = backend()
  if (b.kind !== 'openssl') {
    throw backendError(
      `the native backend is required and is not present: ${b.reason}`,
      { required: 'openssl', actual: b.kind, reason: b.reason },
    )
  }
  const missing = (algorithms ?? []).filter((a) => !isNative(a))
  if (missing.length) {
    throw backendError(
      `the native backend is required for ${missing.join(', ')}, ` +
        `and this OpenSSL does not provide ${missing.length > 1 ? 'them' : 'it'}`,
      { required: 'openssl', actual: b.kind, missing, available: b.parameterSets },
    )
  }
  return b
}

function backendError(message, detail) {
  const err = new Error(message)
  err.code = 'ERR_KXCO_PQ_BACKEND'
  Object.assign(err, detail)
  return err
}

if (REQUIRE_NATIVE) requireNativeBackend()
