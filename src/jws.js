// Compact JWS with ML-DSA, using the RFC 9964 algorithm names.
//
// Format only. Nothing here contacts a network, reads a chain, or needs a
// licence: a token signed by this module verifies in any process that holds
// the public key, forever, offline. The paid behaviour that decides whether a
// key is still ALLOWED to sign lives in kxco-pq-network and above, never here.
//
// Why a JWS at all when this package already has its own envelopes. Because an
// institution's existing stack already parses JWS. Their gateway, their IdP,
// their audit tooling and their partner's verifier all speak it, and RFC 9964
// registered "ML-DSA-44", "ML-DSA-65" and "ML-DSA-87" as JWS algorithms
// precisely so a post-quantum signature can travel that path unchanged. Giving
// them one is the difference between a migration and a rewrite.
//
// The header is the protected header and the whole of it is signed. There is
// no unprotected header, no JSON serialisation and no detached payload in this
// release: each is a place where a verifier can be talked into checking
// something other than what it thinks it is checking, and none of them is
// needed to carry a signature between two services.
//
// SLH-DSA is not offered here. FIPS 205 signing takes on the order of a second
// and a half per signature, which is not something to put on a request path.

import * as mlDsa from './ml-dsa.js'
import * as mlDsa87 from './ml-dsa-87.js'

const HAS_BUFFER = typeof Buffer !== 'undefined'
const enc = new TextEncoder()
const dec = new TextDecoder()

// The `alg` allowlist. A verifier resolves the implementation from THIS table
// and nowhere else, so a token cannot name its own verification routine — the
// alg-confusion failure that has broken JWT libraries repeatedly.
const ALGORITHMS = {
  'ML-DSA-65': { mod: mlDsa,   publicKeyBytes: 1952, signatureBytes: 3309 },
  'ML-DSA-87': { mod: mlDsa87, publicKeyBytes: 2592, signatureBytes: 4627 },
}

/** JWS `alg` values this module will sign or verify. */
export const JWS_ALGORITHMS = Object.keys(ALGORITHMS)

const DEFAULT_ALG = 'ML-DSA-65'

function b64url(bytes) {
  if (HAS_BUFFER) return Buffer.from(bytes).toString('base64url')
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function fromB64url(str) {
  if (HAS_BUFFER) return new Uint8Array(Buffer.from(str, 'base64url'))
  const padded = str.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(padded + '='.repeat((4 - (padded.length % 4)) % 4))
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < out.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

// base64url is not a canonical encoding of arbitrary text: two different
// strings can decode to the same bytes if one carries padding or non-alphabet
// characters. A token whose segments re-encode differently from how they
// arrived is rejected, so a verifier and a downstream parser cannot be shown
// two different payloads for one signature.
function strictB64url(str, what) {
  if (typeof str !== 'string' || str.length === 0 || !/^[A-Za-z0-9_-]+$/.test(str)) {
    throw new Error(`malformed JWS: ${what} is not base64url`)
  }
  const bytes = fromB64url(str)
  if (b64url(bytes) !== str) throw new Error(`malformed JWS: ${what} is not canonically encoded`)
  return bytes
}

function bytesToHex(bytes) {
  let s = ''
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0')
  return s
}

function hexToBytes(hex) {
  const b = new Uint8Array(hex.length / 2)
  for (let i = 0; i < b.length; i++) b[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return b
}

function payloadBytes(payload) {
  if (payload instanceof Uint8Array) return payload
  if (typeof payload === 'string') return enc.encode(payload)
  if (payload === null || payload === undefined) {
    throw new TypeError('payload is required')
  }
  if (typeof payload === 'object') return enc.encode(JSON.stringify(payload))
  throw new TypeError('payload must be an object, a string or a Uint8Array')
}

/**
 * Sign a payload into a compact JWS.
 *
 * @param {object|string|Uint8Array} payload — objects are JSON-serialised
 * @param {Buffer|Uint8Array} secretKey
 * @param {{ alg?: string, kid?: string, typ?: string, header?: object }} [opts]
 * @returns {string} compact JWS: header.payload.signature
 */
export function signJws(payload, secretKey, opts = {}) {
  if (opts === null || typeof opts !== 'object') {
    throw new TypeError('expected an options object such as { kid, alg }')
  }
  const alg = opts.alg ?? DEFAULT_ALG
  const spec = ALGORITHMS[alg]
  if (!spec) {
    throw new Error(`unsupported JWS alg '${alg}' — this module signs ${JWS_ALGORITHMS.join(' and ')}`)
  }

  // Extra header members are allowed but may not restate or override the ones
  // this module is responsible for, which would let a caller sign under one
  // alg while the header advertises another.
  const extra = opts.header ?? {}
  for (const reserved of ['alg', 'kid', 'typ']) {
    if (Object.hasOwn(extra, reserved)) {
      throw new Error(`header.${reserved} is set through opts.${reserved}, not opts.header`)
    }
  }

  const header = {
    alg,
    ...(opts.typ !== undefined ? { typ: opts.typ } : {}),
    ...(opts.kid !== undefined ? { kid: opts.kid } : {}),
    ...extra,
  }

  const protectedB64 = b64url(enc.encode(JSON.stringify(header)))
  const payloadB64 = b64url(payloadBytes(payload))
  const signingInput = enc.encode(`${protectedB64}.${payloadB64}`)

  // Goes through the module's own sign(), so the OpenSSL backend is used
  // wherever the runtime has it and the JavaScript one everywhere else. The
  // wire bytes are identical either way.
  const sigHex = spec.mod.sign(secretKey, signingInput)
  return `${protectedB64}.${payloadB64}.${b64url(hexToBytes(sigHex))}`
}

/**
 * Verify a compact JWS.
 *
 * Returns `{ valid: false, error }` for anything that fails, and throws only on
 * caller misuse, matching how `mlDsa.verify` already behaves.
 *
 * The algorithm is resolved from this module's allowlist using the header's
 * `alg`, and the public key's length must match what that algorithm expects.
 * Pass `{ alg }` to require a specific one, and `{ kid }` to require the header
 * to name a specific key.
 *
 * @param {string} token
 * @param {Buffer|Uint8Array} publicKey
 * @param {{ alg?: string, kid?: string }} [opts]
 * @returns {{ valid: true, header: object, payload: Uint8Array, text: string }
 *           | { valid: false, error: string }}
 */
export function verifyJws(token, publicKey, opts = {}) {
  if (opts === null || typeof opts !== 'object') {
    throw new TypeError('expected an options object such as { alg, kid }')
  }
  if (typeof token !== 'string') return { valid: false, error: 'token must be a string' }

  const parts = token.split('.')
  if (parts.length !== 3) {
    return { valid: false, error: 'malformed JWS: expected three dot-separated segments' }
  }
  const [protectedB64, payloadB64, sigB64] = parts

  let header, payload, signature
  try {
    header = JSON.parse(dec.decode(strictB64url(protectedB64, 'header')))
    payload = strictB64url(payloadB64, 'payload')
    signature = strictB64url(sigB64, 'signature')
  } catch (err) {
    return { valid: false, error: err.message }
  }

  if (!header || typeof header !== 'object' || Array.isArray(header)) {
    return { valid: false, error: 'malformed JWS: header is not an object' }
  }

  const spec = ALGORITHMS[header.alg]
  if (!spec) {
    return { valid: false, error: `unsupported JWS alg '${header.alg}'` }
  }
  if (opts.alg !== undefined && header.alg !== opts.alg) {
    return { valid: false, error: `alg mismatch: expected '${opts.alg}', token declares '${header.alg}'` }
  }
  if (opts.kid !== undefined && header.kid !== opts.kid) {
    return { valid: false, error: `kid mismatch: expected '${opts.kid}', token declares '${header.kid ?? '(none)'}'` }
  }

  // RFC 7515 section 4.1.11: a verifier that does not understand every member
  // named in `crit` must reject the token. This module understands none of the
  // extensions that would be named there, so any `crit` at all is a rejection.
  if (header.crit !== undefined) {
    return { valid: false, error: 'JWS declares crit header parameters this verifier does not implement' }
  }
  // RFC 7797 unencoded payloads change what the signature covers. Not accepted.
  if (header.b64 !== undefined) {
    return { valid: false, error: 'JWS declares b64, which this verifier does not implement' }
  }

  // The key must be the size the declared algorithm uses. Without this a token
  // could name ML-DSA-87 while being checked against an ML-DSA-65 key, and the
  // failure would look like a bad signature rather than a mixed-up key.
  const keyBytes = publicKey instanceof Uint8Array ? publicKey : new Uint8Array(publicKey)
  if (keyBytes.length !== spec.publicKeyBytes) {
    return {
      valid: false,
      error: `key is ${keyBytes.length} bytes, but ${header.alg} public keys are ${spec.publicKeyBytes}`,
    }
  }
  if (signature.length !== spec.signatureBytes) {
    return {
      valid: false,
      error: `signature is ${signature.length} bytes, but ${header.alg} signatures are ${spec.signatureBytes}`,
    }
  }

  const signingInput = enc.encode(`${protectedB64}.${payloadB64}`)
  const ok = spec.mod.verify(keyBytes, signingInput, bytesToHex(signature))
  if (!ok) return { valid: false, error: 'signature invalid' }

  return { valid: true, header, payload, text: dec.decode(payload) }
}

/**
 * Read a token's header without verifying anything.
 *
 * For dispatch only — picking which public key to fetch from a `kid`. The
 * header is unauthenticated until `verifyJws` returns valid, and nothing in it
 * should be acted on before that.
 *
 * @param {string} token
 * @returns {object|null} null if the token is not parseable
 */
export function decodeJwsHeader(token) {
  if (typeof token !== 'string') return null
  const first = token.split('.')[0]
  try {
    const header = JSON.parse(dec.decode(strictB64url(first, 'header')))
    return header && typeof header === 'object' && !Array.isArray(header) ? header : null
  } catch {
    return null
  }
}
