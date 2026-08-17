// ML-DSA-87 helpers (NIST FIPS 204, Dilithium5).
//
// Module-lattice signatures. Security Category 5 (≈ AES-256). Public key 2592
// bytes, secret key 4896 bytes, signature 4627 bytes. Resistant to attacks by
// quantum computers.
//
// Same API as ./ml-dsa.js, one security category higher. Use this where a
// counterparty specifies Category 5 or names ML-DSA-87. ML-DSA-65 remains the
// default for the KXCO stack; see the note on parameter choice below.
//
// Isomorphic: works in Node and modern browsers. Returns Buffer on Node
// (backwards compatible), Uint8Array in browsers.
//
// ---------------------------------------------------------------------------
// Parameter choice, and what this module does NOT establish
//
// CNSA 2.0 names ML-DSA-87 for National Security Systems. Exporting this module
// makes that parameter set available to callers. It does not make any deployed
// system CNSA 2.0 compliant, and it must not be cited as a compliance badge.
// Compliance is a property of a deployment, not of an available function: the
// KXCO estate signs with ML-DSA-65 at Category 3, including Armature L1 from
// block 0 and every issued KXCO ID, none of which this module changes.
//
// The accurate sentence is "supports ML-DSA-87". See CONFORMANCE.md.
//
// Cost of moving up: a signature is 4627 bytes against 3309 for ML-DSA-65, and
// a public key is 2592 against 1952. Once both sets are in use, anything
// downstream with a fixed-width signature field will meet both sizes.
// ---------------------------------------------------------------------------

import { ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
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
 * Generate an ML-DSA-87 keypair from a master + domain-separation info.
 *
 * The default info differs from the ML-DSA-65 default, so the same master
 * yields unrelated keys for the two parameter sets rather than colliding.
 *
 * @returns {{ publicKey: Buffer|Uint8Array, secretKey: Buffer|Uint8Array }}
 */
export function keypairFromMaster(master, info = 'ml-dsa-87-v1') {
  const seed = deriveSeed(master, info, 32)
  const seedU8 = seed instanceof Uint8Array ? seed : new Uint8Array(seed)
  const k = ml_dsa87.keygen(seedU8)
  return {
    publicKey: wrap(k.publicKey),
    secretKey: wrap(k.secretKey),
  }
}

/**
 * Sign a message. Returns the signature as a hex string.
 *
 * An optional FIPS 204 section 5.2 context string gives domain separation: a
 * signature made under a context does not verify without it.
 *
 * @param {Buffer|Uint8Array} secretKey
 * @param {Buffer|Uint8Array|string} message
 * @param {{ context?: Uint8Array|Buffer|string }} [opts] at most 255 context bytes
 * @returns {string} hex-encoded signature (9254 chars)
 */
export function sign(secretKey, message, opts) {
  const context = normalizeContext(opts)
  const sig = context === undefined
    ? ml_dsa87.sign(toBytes(message), secretKey)
    : ml_dsa87.sign(toBytes(message), secretKey, { context })
  return bytesToHex(sig)
}

/**
 * Verify a hex-encoded signature.
 *
 * Pass the same context the signer used. A signature made under a context
 * returns false here if the context is omitted or differs, which is the point
 * of it.
 *
 * Returns false for any cryptographic failure, including a signature produced
 * under a different parameter set. Throws only on caller misuse of `opts`
 * (wrong type, or a context over 255 bytes), because that is a bug rather than
 * a failed verification and should not be silently swallowed.
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
      ? ml_dsa87.verify(hexToBytes(sigHex), toBytes(message), publicKey)
      : ml_dsa87.verify(hexToBytes(sigHex), toBytes(message), publicKey, { context })
  } catch {
    return false
  }
}

export { ml_dsa87 }
