// ML-DSA-65 helpers (NIST FIPS 204, Dilithium3).
//
// Module-lattice signatures. Security Category 3 (≈ AES-192). Public key 1952
// bytes, signature 3309 bytes. Resistant to attacks by quantum computers.
//
// Isomorphic: works in Node and modern browsers. Returns Buffer on Node
// (backwards compatible), Uint8Array in browsers.

import { ml_dsa65 } from '@noble/post-quantum/ml-dsa.js'
import { deriveSeed } from './derive.js'
import { normalizeContext, MAX_CONTEXT_BYTES } from './_context.js'

export { MAX_CONTEXT_BYTES }

const HAS_BUFFER = typeof Buffer !== 'undefined'
const enc = new TextEncoder()

function toBytes(input) {
  if (input instanceof Uint8Array) return input
  if (typeof input === 'string') return enc.encode(input)
  throw new Error('expected Uint8Array or string')
}
function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2) throw new Error('invalid hex')
  const b = new Uint8Array(hex.length / 2)
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return b
}
function bytesToHex(bytes) {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0')
  return s
}
function wrap(bytes) {
  return HAS_BUFFER ? Buffer.from(bytes) : bytes
}

/**
 * Generate an ML-DSA-65 keypair from a master + domain-separation info.
 *
 * @returns {{ publicKey: Buffer|Uint8Array, secretKey: Buffer|Uint8Array }}
 */
export function keypairFromMaster(master, info = 'ml-dsa-65-v1') {
  const seed = deriveSeed(master, info, 32)
  const seedU8 = seed instanceof Uint8Array ? seed : new Uint8Array(seed)
  const k = ml_dsa65.keygen(seedU8)
  return {
    publicKey: wrap(k.publicKey),
    secretKey: wrap(k.secretKey),
  }
}

/**
 * Sign a message. Returns the signature as a hex string.
 *
 * An optional FIPS 204 section 5.2 context string gives domain separation: a
 * signature made under a context does not verify without it. Omit it and the
 * behaviour is exactly as before this parameter existed.
 *
 * @param {Buffer|Uint8Array} secretKey
 * @param {Buffer|Uint8Array|string} message
 * @param {{ context?: Uint8Array|Buffer|string }} [opts] at most 255 context bytes
 * @returns {string} hex-encoded signature (6618 chars)
 */
export function sign(secretKey, message, opts) {
  const context = normalizeContext(opts)
  const sig = context === undefined
    ? ml_dsa65.sign(toBytes(message), secretKey)
    : ml_dsa65.sign(toBytes(message), secretKey, { context })
  return bytesToHex(sig)
}

/**
 * Verify a hex-encoded signature.
 *
 * Pass the same context the signer used. A signature made under a context
 * returns false here if the context is omitted or differs, which is the point
 * of it.
 *
 * Returns false for any cryptographic failure. Throws only on caller misuse of
 * `opts` (wrong type, or a context over 255 bytes), because that is a bug
 * rather than a failed verification and should not be silently swallowed.
 *
 * @param {Buffer|Uint8Array} publicKey
 * @param {Buffer|Uint8Array|string} message
 * @param {string} sigHex
 * @param {{ context?: Uint8Array|Buffer|string }} [opts]
 * @returns {boolean}
 */
export function verify(publicKey, message, sigHex, opts) {
  // Outside the try: misuse must surface, not be swallowed as "invalid".
  const context = normalizeContext(opts)
  try {
    return context === undefined
      ? ml_dsa65.verify(hexToBytes(sigHex), toBytes(message), publicKey)
      : ml_dsa65.verify(hexToBytes(sigHex), toBytes(message), publicKey, { context })
  } catch {
    return false
  }
}

export { ml_dsa65 }
