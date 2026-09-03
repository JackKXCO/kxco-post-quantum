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

import { native } from '#native'

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
