// ML-KEM-1024 helpers (NIST FIPS 203, Kyber1024).
//
// Module-lattice key encapsulation. Security Category 5 (≈ AES-256). Public
// key 1568 bytes, ciphertext 1568 bytes, shared secret 32 bytes. Resistant to
// attacks by quantum computers.
//
// Same API as ./ml-kem.js, one security category higher. Use this where a
// counterparty specifies Category 5 or names ML-KEM-1024. ML-KEM-768 remains
// the default for the KXCO stack.
//
// Isomorphic: works in Node and modern browsers. Returns Buffer on Node
// (backwards compatible), Uint8Array in browsers.
//
// ---------------------------------------------------------------------------
// Parameter choice, and what this module does NOT establish
//
// CNSA 2.0 names ML-KEM-1024 for National Security Systems. Exporting this
// module makes that parameter set available to callers. It does not make any
// deployed system CNSA 2.0 compliant, and it must not be cited as a compliance
// badge. Compliance is a property of a deployment, not of an available
// function. The accurate sentence is "supports ML-KEM-1024".
// See CONFORMANCE.md.
//
// The shared secret is 32 bytes at both parameter sets, so moving up does not
// change key-derivation code downstream. Public keys and ciphertexts do grow:
// 1568 bytes each, against 1184 and 1088 at ML-KEM-768.
//
// As with ML-KEM-768: do not use the returned shared secret as a key directly.
// Run it through a KDF with a context label. That is what deriveSeed is for.
// ---------------------------------------------------------------------------

import { ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { deriveSeed } from './derive.js'
import { native } from '#native'

const HAS_BUFFER = typeof Buffer !== 'undefined'

function wrap(bytes) {
  return HAS_BUFFER ? Buffer.from(bytes) : bytes
}

// Where the runtime provides the FIPS primitives through OpenSSL (Node 24 and
// later) they are used in place of the JavaScript backend. Everywhere else,
// including every browser, `native` is null and nothing about this module
// changes. The two backends are checked against each other for this parameter
// set in both directions by the interoperability matrix.
const NATIVE_ALG = 'ML-KEM-1024'
const usesNative = () =>
  native !== null && native.supports(NATIVE_ALG)

/**
 * Generate an ML-KEM-1024 keypair from a master + domain-separation info.
 *
 * The default info differs from the ML-KEM-768 default, so the same master
 * yields unrelated keys for the two parameter sets rather than colliding.
 *
 * @returns {{ publicKey: Buffer|Uint8Array, secretKey: Buffer|Uint8Array }}
 */
export function keypairFromMaster(master, info = 'ml-kem-1024-v1') {
  const seed = deriveSeed(master, info, 64)
  const seedU8 = seed instanceof Uint8Array ? seed : new Uint8Array(seed)
  const k = ml_kem1024.keygen(seedU8)
  return {
    publicKey: wrap(k.publicKey),
    secretKey: wrap(k.secretKey),
    // The seed this key was expanded from. Additive: callers destructuring
    // { publicKey, secretKey } are unaffected. It is here because an expanded
    // key does not contain its seed, so this is the only moment it can be
    // captured, and seed form is what RFC 9964 JWKs and KMS custody take.
    seed:      wrap(seedU8),
  }
}

/**
 * Encapsulate a shared secret to the recipient's public key.
 *
 * @param {Buffer|Uint8Array} publicKey
 * @returns {{ ciphertext: Buffer|Uint8Array, cipherText: Buffer|Uint8Array, sharedSecret: Buffer|Uint8Array }}
 */
export function encapsulate(publicKey) {
  const r = usesNative()
    ? native.encapsulate(NATIVE_ALG, publicKey)
    : ml_kem1024.encapsulate(publicKey)
  const ct = wrap(r.cipherText ?? r.ciphertext)
  return {
    ciphertext:   ct,
    cipherText:   ct,
    sharedSecret: wrap(r.sharedSecret),
  }
}

/**
 * Decapsulate: recover the shared secret from a ciphertext using the secret key.
 *
 * A corrupted ciphertext yields an unrelated 32-byte secret rather than an
 * error, which is FIPS 203 implicit rejection and is deliberate. Never treat a
 * successful return as proof the ciphertext was authentic.
 *
 * @param {Buffer|Uint8Array} ciphertext
 * @param {Buffer|Uint8Array} secretKey
 * @returns {Buffer|Uint8Array} shared secret (32 bytes)
 */
export function decapsulate(ciphertext, secretKey) {
  if (usesNative()) {
    return wrap(native.decapsulate(NATIVE_ALG, ciphertext, secretKey))
  }
  return wrap(ml_kem1024.decapsulate(ciphertext, secretKey))
}

export { ml_kem1024 }
