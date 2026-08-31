// ML-KEM-768 helpers (NIST FIPS 203, Kyber768).
//
// Module-lattice key encapsulation. Security Category 3 (≈ AES-192). Public
// key 1184 bytes, ciphertext 1088 bytes, shared secret 32 bytes. Resistant
// to attacks by quantum computers.
//
// Isomorphic: works in Node and modern browsers. Returns Buffer on Node
// (backwards compatible), Uint8Array in browsers.

import { ml_kem768 } from '@noble/post-quantum/ml-kem.js'
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
const NATIVE_ALG = 'ML-KEM-768'
const usesNative = () =>
  native !== null && native.supports(NATIVE_ALG)

/**
 * Generate an ML-KEM-768 keypair from a master + domain-separation info.
 *
 * @returns {{ publicKey: Buffer|Uint8Array, secretKey: Buffer|Uint8Array }}
 */
export function keypairFromMaster(master, info = 'ml-kem-768-v1') {
  const seed = deriveSeed(master, info, 64)
  const seedU8 = seed instanceof Uint8Array ? seed : new Uint8Array(seed)
  const k = ml_kem768.keygen(seedU8)
  return {
    publicKey: wrap(k.publicKey),
    secretKey: wrap(k.secretKey),
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
    : ml_kem768.encapsulate(publicKey)
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
 * @param {Buffer|Uint8Array} ciphertext
 * @param {Buffer|Uint8Array} secretKey
 * @returns {Buffer|Uint8Array} shared secret (32 bytes)
 */
export function decapsulate(ciphertext, secretKey) {
  if (usesNative()) {
    return wrap(native.decapsulate(NATIVE_ALG, ciphertext, secretKey))
  }
  return wrap(ml_kem768.decapsulate(ciphertext, secretKey))
}

export { ml_kem768 }
