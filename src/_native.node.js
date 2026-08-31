// OpenSSL-backed primitives, used when the runtime provides them.
//
// Node 24 and later expose the FIPS 203/204/205 parameter sets through OpenSSL
// 3.5. Where that is available this module supplies the primitives and the
// JavaScript backend is not called; on Node 20 and 22, and on any runtime
// without them, `native` is null and nothing changes.
//
// Why prefer it. The C implementation is the one the wider ecosystem tests
// against, it carries a constant-time story no JavaScript implementation can
// make, and it removes the runtime dependency from the signing path entirely on
// Node 24+. It is also faster by a wide margin, measured on this machine:
//
//   ML-DSA-65 sign          1.34 ms   against 11.54 ms   (8.6x)
//   ML-DSA-65 verify        0.28 ms   against  2.22 ms   (7.9x)
//   SLH-DSA-SHA2-192s sign  1595 ms   against  4717 ms   (3.0x)
//
// The two implementations are interchangeable on the wire, which is checked
// rather than assumed: the interoperability matrix runs every parameter set
// against both backends in both directions, and `npm run conformance:interop`
// reproduces it.
//
// Keys cross the boundary in the encodings this package already uses. Private
// keys go in as PKCS8 carrying the expanded key, or as a JWK for SLH-DSA, whose
// private key is not seed-derived in OpenSSL's representation. Public keys go in
// as SPKI wrapping the raw bytes. Every one of those was verified against the
// JavaScript backend before this module was written; none of it is inferred
// from the specification.

import crypto from 'node:crypto'

// FIPS 204 section 5.2 context strings are not reachable through Node's sign and
// verify, which take no context argument. A call that uses one falls back to the
// JavaScript backend rather than being signed without it: a signature made
// without the caller's context verifies against nothing and would look like a
// cross-implementation disagreement rather than a missing feature.

const DER_SEQUENCE = 0x30
const DER_OCTET_STRING = 0x04
const DER_BIT_STRING = 0x03

function derLength(length) {
  if (length < 0x80) return Buffer.from([length])
  if (length < 0x100) return Buffer.from([0x81, length])
  return Buffer.from([0x82, length >> 8, length & 0xff])
}

function der(tag, payload) {
  return Buffer.concat([Buffer.from([tag]), derLength(payload.length), payload])
}

// The AlgorithmIdentifier is read back off a key OpenSSL generates itself rather
// than hard-coded from the OID registry, so a build that spells one differently
// cannot produce a subtly wrong encoding here.
function algorithmIdentifier(nodeName) {
  const { privateKey } = crypto.generateKeyPairSync(nodeName)
  const pkcs8 = privateKey.export({ format: 'der', type: 'pkcs8' })
  const headerLength = pkcs8[1] & 0x80 ? 2 + (pkcs8[1] & 0x7f) : 2
  const start = headerLength + 3 // skip the version INTEGER
  return pkcs8.subarray(start, start + 2 + pkcs8[start + 1])
}

function toPkcs8(algid, privateBytes) {
  const body = Buffer.concat([
    Buffer.from('020100', 'hex'),
    algid,
    der(DER_OCTET_STRING, der(DER_OCTET_STRING, Buffer.from(privateBytes))),
  ])
  return der(DER_SEQUENCE, body)
}

function toSpki(algid, publicBytes) {
  const bits = der(DER_BIT_STRING, Buffer.concat([Buffer.from([0x00]), Buffer.from(publicBytes)]))
  return der(DER_SEQUENCE, Buffer.concat([algid, bits]))
}

const base64url = (bytes) => Buffer.from(bytes).toString('base64url')

// Each entry records how this package's representation maps onto OpenSSL's.
// `privateForm` is the difference that matters: ML-DSA and ML-KEM accept the
// expanded private key inside PKCS8, while OpenSSL keys SLH-DSA by its full
// private key through a JWK.
const ALGORITHMS = {
  'ML-DSA-44': { nodeName: 'ml-dsa-44', kind: 'sig', privateForm: 'pkcs8' },
  'ML-DSA-65': { nodeName: 'ml-dsa-65', kind: 'sig', privateForm: 'pkcs8' },
  'ML-DSA-87': { nodeName: 'ml-dsa-87', kind: 'sig', privateForm: 'pkcs8' },
  'ML-KEM-512': { nodeName: 'ml-kem-512', kind: 'kem', privateForm: 'pkcs8' },
  'ML-KEM-768': { nodeName: 'ml-kem-768', kind: 'kem', privateForm: 'pkcs8' },
  'ML-KEM-1024': { nodeName: 'ml-kem-1024', kind: 'kem', privateForm: 'pkcs8' },
  'SLH-DSA-SHA2-128f': { nodeName: 'slh-dsa-sha2-128f', kind: 'sig', privateForm: 'jwk' },
  'SLH-DSA-SHA2-192s': { nodeName: 'slh-dsa-sha2-192s', kind: 'sig', privateForm: 'jwk' },
  'SLH-DSA-SHAKE-256f': { nodeName: 'slh-dsa-shake-256f', kind: 'sig', privateForm: 'jwk' },
}

// Probed once, by actually generating a key. Asking the Node version would be a
// guess about which build shipped which OpenSSL; generating a key is the fact.
function probe() {
  const table = new Map()
  for (const [name, spec] of Object.entries(ALGORITHMS)) {
    try {
      // jwkAlg is the FIPS name: SLH-DSA goes in as a JWK, which names the
      // algorithm in the payload rather than in an AlgorithmIdentifier.
      table.set(name, { ...spec, jwkAlg: name, algid: algorithmIdentifier(spec.nodeName) })
    } catch {
      // Not in this build. The JavaScript backend covers it.
    }
  }
  return table
}

const SUPPORTED = probe()

function privateKeyObject(spec, secretKey, publicKey) {
  if (spec.privateForm === 'jwk') {
    // FIPS 205 lays the private key out as SK.seed || SK.prf || PK.seed ||
    // PK.root, and the public key is PK.seed || PK.root, so the public half is
    // the back half of the private key. Callers that already hold it pass it;
    // this package's sign() does not, and recovering it here is exact rather
    // than a reconstruction.
    const pub = publicKey ?? secretKey.subarray(secretKey.length / 2)
    return crypto.createPrivateKey({
      key: {
        kty: 'AKP',
        alg: spec.jwkAlg,
        pub: base64url(pub),
        priv: base64url(secretKey),
      },
      format: 'jwk',
    })
  }
  return crypto.createPrivateKey({
    key: toPkcs8(spec.algid, secretKey),
    format: 'der',
    type: 'pkcs8',
  })
}

function publicKeyObject(spec, publicKey) {
  return crypto.createPublicKey({
    key: toSpki(spec.algid, publicKey),
    format: 'der',
    type: 'spki',
  })
}

export const native = SUPPORTED.size === 0 ? null : {
  /** Parameter sets this build can do. Anything else falls through to JS.
   *
   * The Buffer check is not defensive padding. This package's browser-mode
   * tests simulate a browser by removing Buffer from the global scope, and a
   * real browser resolves `#native` to the stub and never reaches this module
   * at all. Without this, those tests would exercise the OpenSSL path while
   * claiming to cover the browser one, which is a false pass rather than a
   * crash: the very thing the suite exists to catch.
   */
  supports(alg) {
    return typeof Buffer !== 'undefined' && SUPPORTED.has(alg)
  },

  /** Names of the supported sets, for the conformance report to record. */
  algorithms() {
    return [...SUPPORTED.keys()].sort()
  },

  openssl: process.versions.openssl,

  sign(alg, secretKey, message, publicKey) {
    const spec = SUPPORTED.get(alg)
    if (!spec) return null
    return crypto.sign(null, Buffer.from(message), privateKeyObject(spec, secretKey, publicKey))
  },

  verify(alg, publicKey, message, signature) {
    const spec = SUPPORTED.get(alg)
    if (!spec) return null
    try {
      return crypto.verify(
        null,
        Buffer.from(message),
        publicKeyObject(spec, publicKey),
        Buffer.from(signature)
      )
    } catch {
      // A malformed key or signature is a failed verification, not a crash,
      // which matches what the JavaScript backend does with the same input.
      return false
    }
  },

  encapsulate(alg, publicKey) {
    const spec = SUPPORTED.get(alg)
    if (!spec || spec.kind !== 'kem') return null
    // Node names these sharedKey and ciphertext; this package has always called
    // them sharedSecret and cipherText, so the rename happens here rather than
    // leaking a second vocabulary into the public API.
    const { sharedKey, ciphertext } = crypto.encapsulate(publicKeyObject(spec, publicKey))
    return { cipherText: ciphertext, sharedSecret: sharedKey }
  },

  decapsulate(alg, cipherText, secretKey) {
    const spec = SUPPORTED.get(alg)
    if (!spec || spec.kind !== 'kem') return null
    return crypto.decapsulate(privateKeyObject(spec, secretKey), Buffer.from(cipherText))
  },
}
