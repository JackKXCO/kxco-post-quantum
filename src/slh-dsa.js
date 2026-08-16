// SLH-DSA-SHA2-192s helpers (NIST FIPS 205, SPHINCS+).
//
// Stateless hash-based signatures. Security Category 3 (≈ AES-192), matching
// ML-DSA-65's security level. Public key 48 bytes, secret key 96 bytes,
// signature 16224 bytes. Security rests only on the SHA-2 hash function — no
// lattice or number-theoretic assumptions — which makes it the conservative
// hedge alongside ML-DSA-65.
//
// Tradeoff: signatures are ~5x larger than ML-DSA-65 (16224 vs 3309 bytes) and
// signing is slower. Use ML-DSA-65 as the default; reach for SLH-DSA when you
// want a signature whose security does not depend on lattice hardness.
//
// Isomorphic: works in Node and modern browsers. Returns Buffer on Node
// (consistent with ml-dsa.js), Uint8Array in browsers.

import { slh_dsa_sha2_192s } from '@noble/post-quantum/slh-dsa.js'
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

// Seed length for SLH-DSA-SHA2-192s keygen (FIPS 205: SK.seed || SK.prf || PK.seed).
const SEED_BYTES = slh_dsa_sha2_192s.lengths.seed

/**
 * Generate an SLH-DSA-SHA2-192s keypair from a master + domain-separation info.
 *
 * @returns {{ publicKey: Buffer|Uint8Array, secretKey: Buffer|Uint8Array }}
 */
export function keypairFromMaster(master, info = 'slh-dsa-sha2-192s-v1') {
  const seed = deriveSeed(master, info, SEED_BYTES)
  const seedU8 = seed instanceof Uint8Array ? seed : new Uint8Array(seed)
  const k = slh_dsa_sha2_192s.keygen(seedU8)
  return {
    publicKey: wrap(k.publicKey),
    secretKey: wrap(k.secretKey),
  }
}

/**
 * Sign a message. Returns the signature as a hex string.
 *
 * Accepts the same optional context string as ml-dsa.js (FIPS 205 allows it on
 * the same terms as FIPS 204, at most 255 bytes). Omit it and the behaviour is
 * exactly as before this parameter existed.
 *
 * @param {Buffer|Uint8Array} secretKey
 * @param {Buffer|Uint8Array|string} message
 * @param {{ context?: Uint8Array|Buffer|string }} [opts] at most 255 context bytes
 * @returns {string} hex-encoded signature (32448 chars)
 */
export function sign(secretKey, message, opts) {
  const context = normalizeContext(opts)
  const sig = context === undefined
    ? slh_dsa_sha2_192s.sign(toBytes(message), secretKey)
    : slh_dsa_sha2_192s.sign(toBytes(message), secretKey, { context })
  return bytesToHex(sig)
}

/**
 * Verify a hex-encoded signature.
 *
 * Pass the same context the signer used. Returns false for any cryptographic
 * failure; throws only on caller misuse of `opts`.
 *
 * @param {Buffer|Uint8Array} publicKey
 * @param {Buffer|Uint8Array|string} message
 * @param {string} sigHex
 * @param {{ context?: Uint8Array|Buffer|string }} [opts]
 * @returns {boolean}
 */
export function verify(publicKey, message, sigHex, opts) {
  const context = normalizeContext(opts)
  try {
    return context === undefined
      ? slh_dsa_sha2_192s.verify(hexToBytes(sigHex), toBytes(message), publicKey)
      : slh_dsa_sha2_192s.verify(hexToBytes(sigHex), toBytes(message), publicKey, { context })
  } catch {
    return false
  }
}

export { slh_dsa_sha2_192s }
