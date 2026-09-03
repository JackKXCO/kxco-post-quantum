// Seed-form keys: the 32 bytes an ML-DSA key really is, and the 64 an ML-KEM
// key really is.
//
// FIPS 204 and FIPS 203 both generate a keypair by expanding a short seed. The
// expanded private key this package has always returned (4032 bytes for
// ML-DSA-65, 2400 for ML-KEM-768) is derived FROM that seed and does not
// contain it: rho, K, tr, s1, s2 and t0 are what expansion produces, not what
// it consumed. So a seed cannot be recovered from an expanded key, and any
// caller who wants seed-form storage has to hold the seed from the moment of
// derivation. `keypairFromMaster` therefore returns it alongside the keypair.
//
// Why seed form matters commercially: 32 bytes fits in a KMS secret, an HSM
// object, an env var and a QR code; 4032 bytes fits in none of them
// comfortably. It is also the only private form Node's AKP JWK accepts, and
// the form RFC 9964 and the LAMPS certificate drafts standardise on, so it is
// what an institution's existing key custody actually knows how to hold.
//
// Everything here is derivation and encoding, so it is pure JavaScript and
// runs unchanged in a browser. It does not import node:crypto.
//
// The encodings are not inferred from the specifications. Each one was read
// off a key OpenSSL 3.5 generated itself and checked byte-for-byte against
// what this module produces; test/seed.test.js reproduces that comparison on
// any runtime that has the native backend, so a build whose OpenSSL disagreed
// would fail rather than ship a subtly wrong encoding.

import { ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'
import { ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js'
import { deriveSeed } from './derive.js'

const HAS_BUFFER = typeof Buffer !== 'undefined'

function wrap(bytes) {
  return HAS_BUFFER ? Buffer.from(bytes) : bytes
}

// ── Parameter sets ──────────────────────────────────────────────────────────
//
// `oid` is the DER content of the algorithm OID under the NIST arc
// 2.16.840.1.101.3.4 (= 60 86 48 01 65 03 04). ML-DSA hangs off .3, ML-KEM off
// .4. These are registry values and do not vary by implementation; the test
// suite asserts each one against what this machine's OpenSSL emits rather than
// trusting the table.
//
// SLH-DSA is deliberately absent. OpenSSL keys it by its full private key
// rather than a seed, so there is no seed form to export, and FIPS 205 signing
// is far too slow for the hot path this module exists to serve.

const NIST_ARC = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04]

const PARAMS = {
  'ML-DSA-65': {
    kind: 'sig', seedBytes: 32, publicKeyBytes: 1952, secretKeyBytes: 4032,
    oid: [...NIST_ARC, 0x03, 0x12], impl: ml_dsa65, info: 'ml-dsa-65-v1',
  },
  'ML-DSA-87': {
    kind: 'sig', seedBytes: 32, publicKeyBytes: 2592, secretKeyBytes: 4896,
    oid: [...NIST_ARC, 0x03, 0x13], impl: ml_dsa87, info: 'ml-dsa-87-v1',
  },
  'ML-KEM-768': {
    kind: 'kem', seedBytes: 64, publicKeyBytes: 1184, secretKeyBytes: 2400,
    oid: [...NIST_ARC, 0x04, 0x02], impl: ml_kem768, info: 'ml-kem-768-v1',
  },
  'ML-KEM-1024': {
    kind: 'kem', seedBytes: 64, publicKeyBytes: 1568, secretKeyBytes: 3168,
    oid: [...NIST_ARC, 0x04, 0x03], impl: ml_kem1024, info: 'ml-kem-1024-v1',
  },
}

/** Parameter sets this module can express in seed form. */
export const SEED_ALGORITHMS = Object.keys(PARAMS)

function paramsFor(alg) {
  const p = PARAMS[alg]
  if (!p) {
    throw new Error(
      `unsupported algorithm '${alg}' — seed form is defined for ${SEED_ALGORITHMS.join(', ')}`,
    )
  }
  return p
}

function asBytes(value, what) {
  if (value instanceof Uint8Array) return value
  if (ArrayBuffer.isView(value) || value instanceof ArrayBuffer) return new Uint8Array(value)
  throw new TypeError(`${what} must be a Uint8Array`)
}

// ── base64url ───────────────────────────────────────────────────────────────
//
// Buffer where it exists, btoa/atob where it does not. Neither path is a
// polyfill of the other: this is the same two-runtime split the rest of the
// package makes, kept local so nothing here reaches for a Node global in a
// browser.

function b64url(bytes) {
  if (HAS_BUFFER) return Buffer.from(bytes).toString('base64url')
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function fromB64url(str) {
  if (typeof str !== 'string') throw new TypeError('expected a base64url string')
  if (HAS_BUFFER) return new Uint8Array(Buffer.from(str, 'base64url'))
  const padded = str.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4))
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < out.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

// ── Keys from seeds ─────────────────────────────────────────────────────────

/**
 * Expand a seed into a keypair.
 *
 * Deterministic, and identical to what OpenSSL 3.5 derives from the same seed:
 * the interoperability test compares the public halves byte-for-byte.
 *
 * @param {string} alg  — one of SEED_ALGORITHMS
 * @param {Uint8Array} seed — 32 bytes for ML-DSA, 64 for ML-KEM
 * @returns {{ publicKey: Buffer|Uint8Array, secretKey: Buffer|Uint8Array, seed: Buffer|Uint8Array }}
 */
export function keypairFromSeed(alg, seed) {
  const p = paramsFor(alg)
  const bytes = asBytes(seed, 'seed')
  if (bytes.length !== p.seedBytes) {
    throw new RangeError(`${alg} seed must be ${p.seedBytes} bytes, got ${bytes.length}`)
  }
  const k = p.impl.keygen(bytes)
  return {
    publicKey: wrap(k.publicKey),
    secretKey: wrap(k.secretKey),
    seed:      wrap(bytes),
  }
}

/**
 * Derive the seed for a parameter set from a master secret, using the same
 * HKDF-SHA-512 derivation `keypairFromMaster` has always used.
 *
 * Passing the default `info` for a set reproduces exactly the key that
 * `mlDsa.keypairFromMaster(master)` or `mlKem.keypairFromMaster(master)`
 * produces, which is what makes seed export possible for keys that already
 * exist in production.
 *
 * @param {string} alg
 * @param {Buffer|Uint8Array|string} master
 * @param {string} [info] — defaults to the parameter set's own domain tag
 * @returns {Buffer|Uint8Array}
 */
export function seedFromMaster(alg, master, info) {
  const p = paramsFor(alg)
  return deriveSeed(master, info ?? p.info, p.seedBytes)
}

// ── JWK, RFC 9964 ───────────────────────────────────────────────────────────
//
// RFC 9964 gives the algorithm-key-pair key type: kty "AKP", the parameter set
// in "alg", the public key in "pub", and — for a private key — the SEED in
// "priv". Not the expanded key. Node rejects an expanded key here outright,
// which is the specification being enforced rather than a Node limitation.

/**
 * Export an AKP JWK (RFC 9964).
 *
 * With `seed`, the result is a private JWK carrying the seed in `priv` and is
 * accepted directly by `crypto.createPrivateKey({ format: 'jwk' })` on Node
 * 24+. Without it, the result is a public JWK.
 *
 * An expanded secret key is NOT accepted in place of a seed: RFC 9964 has no
 * encoding for one, and silently deriving something else would produce a JWK
 * that names a key it does not contain.
 *
 * @param {string} alg
 * @param {{ publicKey: Uint8Array, seed?: Uint8Array }} key
 * @param {{ kid?: string, use?: string }} [opts]
 * @returns {{ kty: 'AKP', alg: string, pub: string, priv?: string, kid?: string }}
 */
export function exportJwk(alg, key, opts = {}) {
  const p = paramsFor(alg)
  if (!key || typeof key !== 'object') {
    throw new TypeError('expected a key object such as { publicKey, seed }')
  }
  const publicKey = asBytes(key.publicKey, 'publicKey')
  if (publicKey.length !== p.publicKeyBytes) {
    throw new RangeError(`${alg} public key must be ${p.publicKeyBytes} bytes, got ${publicKey.length}`)
  }

  const jwk = { kty: 'AKP', alg, pub: b64url(publicKey) }

  if (key.seed !== undefined && key.seed !== null) {
    const seed = asBytes(key.seed, 'seed')
    if (seed.length === p.secretKeyBytes) {
      throw new RangeError(
        `${alg} seed must be ${p.seedBytes} bytes; got ${seed.length}, which is the expanded secret key. ` +
        'RFC 9964 encodes the seed, and a seed cannot be recovered from an expanded key — ' +
        'hold the seed returned by keypairFromMaster or keypairFromSeed.',
      )
    }
    if (seed.length !== p.seedBytes) {
      throw new RangeError(`${alg} seed must be ${p.seedBytes} bytes, got ${seed.length}`)
    }
    jwk.priv = b64url(seed)
  }

  if (opts.kid) jwk.kid = opts.kid
  if (opts.use) jwk.use = opts.use
  return jwk
}

/**
 * Import an AKP JWK (RFC 9964).
 *
 * A private JWK is expanded back to a full keypair, and the expansion is
 * checked against the `pub` the JWK carried: a JWK whose seed and public key
 * disagree is rejected rather than quietly preferring one of them.
 *
 * @param {object} jwk
 * @returns {{ alg: string, publicKey: Buffer|Uint8Array, seed?: Buffer|Uint8Array, secretKey?: Buffer|Uint8Array }}
 */
export function importJwk(jwk) {
  if (!jwk || typeof jwk !== 'object') throw new TypeError('expected a JWK object')
  if (jwk.kty !== 'AKP') {
    throw new Error(`unsupported JWK kty '${jwk.kty}' — expected 'AKP' (RFC 9964)`)
  }
  const p = paramsFor(jwk.alg)

  const publicKey = fromB64url(jwk.pub)
  if (publicKey.length !== p.publicKeyBytes) {
    throw new RangeError(`${jwk.alg} JWK 'pub' must decode to ${p.publicKeyBytes} bytes, got ${publicKey.length}`)
  }

  if (jwk.priv === undefined || jwk.priv === null) {
    return { alg: jwk.alg, publicKey: wrap(publicKey) }
  }

  const seed = fromB64url(jwk.priv)
  if (seed.length !== p.seedBytes) {
    throw new RangeError(`${jwk.alg} JWK 'priv' must decode to ${p.seedBytes} bytes (the seed), got ${seed.length}`)
  }

  const expanded = p.impl.keygen(seed)
  if (!bytesEqual(expanded.publicKey, publicKey)) {
    throw new Error(
      `${jwk.alg} JWK is inconsistent: the public key derived from 'priv' does not match 'pub'`,
    )
  }

  return {
    alg:       jwk.alg,
    publicKey: wrap(expanded.publicKey),
    secretKey: wrap(expanded.secretKey),
    seed:      wrap(seed),
  }
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i]
  return diff === 0
}

// ── PKCS#8, seed form ───────────────────────────────────────────────────────
//
// OneAsymmetricKey (RFC 5958) whose privateKey OCTET STRING wraps the seed
// CHOICE from the LAMPS certificate drafts:
//
//   SEQUENCE {
//     INTEGER 0
//     SEQUENCE { OID <parameter set> }
//     OCTET STRING { [0] IMPLICIT OCTET STRING <seed> }
//   }
//
// The [0] tag (0x80) is what distinguishes seed form from the expanded form,
// which appears as a bare OCTET STRING in the same position. This package's
// existing expanded-key PKCS#8 export is untouched and both forms remain
// importable by OpenSSL 3.5.

const DER_SEQUENCE = 0x30
const DER_INTEGER = 0x02
const DER_OCTET_STRING = 0x04
const DER_OID = 0x06
const DER_SEED_CHOICE = 0x80 // [0] IMPLICIT OCTET STRING

function derLength(length) {
  if (length < 0x80) return [length]
  if (length < 0x100) return [0x81, length]
  return [0x82, length >> 8, length & 0xff]
}

function der(tag, payload) {
  return [tag, ...derLength(payload.length), ...payload]
}

/**
 * Export a seed as a PKCS#8 private key in LAMPS seed form.
 *
 * The result loads directly into OpenSSL 3.5 and into
 * `crypto.createPrivateKey({ format: 'der', type: 'pkcs8' })` on Node 24+.
 *
 * @param {string} alg
 * @param {Uint8Array} seed
 * @returns {Buffer|Uint8Array} DER
 */
export function exportSeedPkcs8(alg, seed) {
  const p = paramsFor(alg)
  const bytes = asBytes(seed, 'seed')
  if (bytes.length !== p.seedBytes) {
    throw new RangeError(`${alg} seed must be ${p.seedBytes} bytes, got ${bytes.length}`)
  }
  const body = [
    ...der(DER_INTEGER, [0x00]),
    ...der(DER_SEQUENCE, der(DER_OID, p.oid)),
    ...der(DER_OCTET_STRING, der(DER_SEED_CHOICE, [...bytes])),
  ]
  return wrap(Uint8Array.from(der(DER_SEQUENCE, body)))
}

/**
 * Read a seed-form PKCS#8 private key back.
 *
 * Rejects the expanded form rather than guessing: an expanded key in this
 * position is a valid PKCS#8 key but not a seed, and returning its first 32
 * bytes as one would produce a completely different keypair.
 *
 * @param {Uint8Array} der8
 * @returns {{ alg: string, seed: Buffer|Uint8Array }}
 */
export function importSeedPkcs8(der8) {
  const buf = asBytes(der8, 'pkcs8')
  const r = { i: 0, buf }

  expectTag(r, DER_SEQUENCE, 'PKCS#8')
  readLength(r)

  expectTag(r, DER_INTEGER, 'version')
  const versionLen = readLength(r)
  r.i += versionLen

  expectTag(r, DER_SEQUENCE, 'AlgorithmIdentifier')
  const algIdLen = readLength(r)
  const algIdEnd = r.i + algIdLen
  expectTag(r, DER_OID, 'algorithm OID')
  const oidLen = readLength(r)
  const oid = buf.subarray(r.i, r.i + oidLen)
  r.i = algIdEnd

  const alg = SEED_ALGORITHMS.find((name) => bytesEqual(Uint8Array.from(PARAMS[name].oid), oid))
  if (!alg) {
    throw new Error(
      `unrecognised algorithm OID in PKCS#8 — seed form is defined for ${SEED_ALGORITHMS.join(', ')}`,
    )
  }

  expectTag(r, DER_OCTET_STRING, 'privateKey')
  readLength(r)

  const inner = buf[r.i]
  if (inner === DER_OCTET_STRING) {
    throw new Error(
      `this PKCS#8 key is in expanded form, not seed form. A seed cannot be recovered ` +
      `from an expanded ${alg} key; re-export from the seed the key was derived from.`,
    )
  }
  if (inner !== DER_SEED_CHOICE) {
    throw new Error(`unexpected privateKey encoding: tag 0x${inner.toString(16)}`)
  }
  r.i += 1
  const seedLen = readLength(r)
  if (seedLen !== PARAMS[alg].seedBytes) {
    throw new RangeError(`${alg} seed must be ${PARAMS[alg].seedBytes} bytes, got ${seedLen}`)
  }
  return { alg, seed: wrap(buf.subarray(r.i, r.i + seedLen)) }
}

function expectTag(r, tag, what) {
  if (r.buf[r.i] !== tag) {
    throw new Error(`malformed DER: expected ${what} tag 0x${tag.toString(16)} at offset ${r.i}`)
  }
  r.i += 1
}

function readLength(r) {
  const first = r.buf[r.i++]
  if (first < 0x80) return first
  const count = first & 0x7f
  if (count === 0 || count > 3) throw new Error('malformed DER: unsupported length encoding')
  let length = 0
  for (let n = 0; n < count; n++) length = (length << 8) | r.buf[r.i++]
  return length
}
