// Protocol-level conformance: can this package verify the PKI artefacts that
// standard tooling produces?
//
// The ACVP run proves the primitives compute what FIPS says. The interoperability
// matrix proves the encodings agree with three other libraries. Neither answers
// the question a PKI team asks first, which is whether a certificate issued by
// the tooling they already run will validate here.
//
// So OpenSSL 3.5 issues, and this package verifies. Nothing in the chain is ours
// on both sides. The artefacts are generated fresh on every run rather than
// committed, because a fixture cannot catch an encoding that drifted.
//
// Usage:  node conformance/protocol/run-protocol.mjs [--json PATH] [--quiet]

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const pkg = JSON.parse(readFileSync(join(HERE, '..', '..', 'package.json'), 'utf8'))
const args = process.argv.slice(2)
const jsonOut = args.includes('--json') ? args[args.indexOf('--json') + 1] : null
const quiet = args.includes('--quiet')

const IMPL = { 'ML-DSA-44': ml_dsa44, 'ML-DSA-65': ml_dsa65, 'ML-DSA-87': ml_dsa87 }
const PK_LEN = { 'ML-DSA-44': 1312, 'ML-DSA-65': 1952, 'ML-DSA-87': 2592 }
// The NIST-assigned signature OIDs. Checking these is not decoration: an
// implementation that verifies the bytes but disagrees about which algorithm
// they belong to still fails to interoperate.
const SIG_OID = {
  'ML-DSA-44': '2.16.840.1.101.3.4.3.17',
  'ML-DSA-65': '2.16.840.1.101.3.4.3.18',
  'ML-DSA-87': '2.16.840.1.101.3.4.3.19',
}
const OID_SHA256 = '2.16.840.1.101.3.4.2.1'
const IMAGE = 'kxco-protocol-openssl:3.5'

// ------------------------------------------------------------------ DER walker
//
// Minimal, and deliberately so. Reading a length and stepping to the next field
// is all this needs; pulling in an ASN.1 library would put a third party between
// the certificate and the check, which is the opposite of the point.

function readTag(buf, i) {
  const tagStart = i
  const tag = buf[i++]
  let len = buf[i++]
  if (len & 0x80) {
    const n = len & 0x7f
    len = 0
    for (let k = 0; k < n; k++) len = (len << 8) | buf[i++]
  }
  // tagStart is what the caller needs to slice a field back out WITH its header,
  // and forgetting it is the whole reason the first version of this verified
  // nothing: the bytes a certificate signs are the tbsCertificate element
  // including its own tag and length, not its contents.
  return { tag, tagStart, start: i, end: i + len, len }
}

function children(buf, seq) {
  const out = []
  let i = seq.start
  while (i < seq.end) {
    const t = readTag(buf, i)
    out.push(t)
    i = t.end
  }
  return out
}

/**
 * Split a Certificate into the two things verification needs.
 *
 * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
 *
 * signature is a BIT STRING, so its first content octet is the unused-bit count
 * and the signature proper starts one byte later.
 */
function splitCertificate(der) {
  const outer = readTag(der, 0)
  const [tbs, , sigBits] = children(der, outer)
  return {
    signedBytes: der.subarray(tbs.tagStart, tbs.end),
    signature: der.subarray(sigBits.start + 1, sigBits.end),
  }
}

/** The raw public key out of a SubjectPublicKeyInfo. */
function rawKeyFromSpki(spki, expectedLen) {
  const outer = readTag(spki, 0)
  const [, bits] = children(spki, outer)
  const raw = spki.subarray(bits.start + 1, bits.end)
  if (raw.length !== expectedLen) {
    throw new Error(`expected a ${expectedLen}-byte key, got ${raw.length}`)
  }
  return raw
}

/** An OBJECT IDENTIFIER's contents as a dotted string. */
function oidToString(buf, el) {
  const b = buf.subarray(el.start, el.end)
  const first = b[0]
  const parts = [Math.floor(first / 40), first % 40]
  let acc = 0
  for (let i = 1; i < b.length; i++) {
    acc = acc * 128 + (b[i] & 0x7f)
    if (!(b[i] & 0x80)) {
      parts.push(acc)
      acc = 0
    }
  }
  return parts.join('.')
}

/** The AlgorithmIdentifier OID out of a SEQUENCE { OID, params OPTIONAL }. */
function algOid(buf, seq) {
  const [oid] = children(buf, seq)
  return oidToString(buf, oid)
}

// ------------------------------------------------------------------- CMS
//
// The signature in a SignedData does not cover the message. It covers the DER
// encoding of the signed attributes, one of which is a digest of the message.
// So verifying it is two steps: check the signature over the attributes, then
// check the digest attribute against the content. Only both together tie the
// signature to the payload, and either one alone would be a check that looks
// like it proves something and does not.

const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3'

/**
 * ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT SignedData }
 *
 * SignedData ::= SEQUENCE { version, digestAlgorithms SET, encapContentInfo,
 *                          certificates [0] OPTIONAL, crls [1] OPTIONAL,
 *                          signerInfos SET }
 *
 * digestAlgorithms and signerInfos are both SETs, so they cannot be told apart
 * by tag. Position is what separates them: the first SET after the version, and
 * the last element of the sequence.
 */
function parseSignedData(der) {
  const [, content] = children(der, readTag(der, 0))
  const sd = readTag(der, content.start)
  const kids = children(der, sd)

  const encap = kids[2]
  const signerInfos = kids[kids.length - 1]
  if (signerInfos.tag !== 0x31) throw new Error('signerInfos is not a SET')

  // EncapsulatedContentInfo ::= SEQUENCE { eContentType OID,
  //                                        eContent [0] EXPLICIT OCTET STRING OPTIONAL }
  // -nodetach puts the message inline, which is what makes the digest check
  // possible without carrying the payload separately.
  const encapKids = children(der, encap)
  if (encapKids.length < 2) throw new Error('no eContent: the message is detached')
  const eContentWrap = readTag(der, encapKids[1].start)
  const eContent = der.subarray(eContentWrap.start, eContentWrap.end)

  // SignerInfo ::= SEQUENCE { version, sid, digestAlgorithm,
  //                           signedAttrs [0] IMPLICIT OPTIONAL,
  //                           signatureAlgorithm, signature OCTET STRING, ... }
  const si = readTag(der, signerInfos.start)
  const siKids = children(der, si)

  const digestAlgorithm = algOid(der, siKids[2])
  const signedAttrs = siKids.find((k) => k.tag === 0xa0)
  if (!signedAttrs) throw new Error('no signedAttrs: nothing for the signature to cover')

  const after = siKids.slice(siKids.indexOf(signedAttrs) + 1)
  const signatureAlgorithm = algOid(der, after.find((k) => k.tag === 0x30))
  const sigOctets = after.find((k) => k.tag === 0x04)
  if (!sigOctets) throw new Error('no signature OCTET STRING in the SignerInfo')

  // What is signed is the attributes as a SET OF, not as the [0] IMPLICIT they
  // are transmitted in. RFC 5652 section 5.4. Re-tagging is the whole of the
  // transformation, and the length octets are unchanged because the length is.
  const signedBytes = Buffer.from(der.subarray(signedAttrs.tagStart, signedAttrs.end))
  signedBytes[0] = 0x31

  const attrs = {}
  for (const attr of children(der, signedAttrs)) {
    const [type, values] = children(der, readTag(der, attr.tagStart))
    const value = children(der, values)[0]
    attrs[oidToString(der, type)] = der.subarray(value.start, value.end)
  }

  return {
    eContent,
    eContentType: oidToString(der, children(der, encap)[0]),
    signedBytes,
    signature: der.subarray(sigOctets.start, sigOctets.end),
    digestAlgorithm,
    signatureAlgorithm,
    attrs,
  }
}

// ---------------------------------------------------------------------- checks

const rows = []
let failures = 0

function record(row) {
  rows.push(row)
  const bad = Object.values(row.checks).filter((c) => c.ok === false).length
  failures += bad
  if (quiet) return
  const marks = Object.entries(row.checks)
    .map(([k, v]) => `${v.ok === true ? '+' : v.ok === false ? 'x' : '-'}${k}`)
    .join(' ')
  console.log(`${bad === 0 ? 'PASS' : 'FAIL'}  ${row.kind.padEnd(6)} ${row.set.padEnd(11)} ${marks}`)
  for (const [k, v] of Object.entries(row.checks)) {
    if (v.ok === false) console.log(`        ${k}: ${v.detail}`)
  }
}

let artefacts
try {
  execFileSync('docker', ['image', 'inspect', IMAGE], { stdio: 'pipe' })
  artefacts = execFileSync('docker', ['run', '--rm', IMAGE], { maxBuffer: 64 * 1024 * 1024 })
    .toString()
    .trim()
    .split('\n')
    .filter(Boolean)
    .map((l) => JSON.parse(l))
} catch (e) {
  console.log(`SKIP  the OpenSSL generator image is unavailable: ${e.message.split('\n')[0]}`)
  console.log(`      build it with: docker build -f conformance/protocol/openssl.Dockerfile -t ${IMAGE} conformance/protocol`)
  process.exit(0)
}

const opensslVersion = artefacts.find((a) => a.kind === 'meta')?.openssl ?? 'unknown'
if (!quiet) console.log(`issuer: ${opensslVersion}
`)

for (const a of artefacts) {
  if (a.kind === 'meta') continue
  const impl = IMPL[a.set]
  const checks = {}

  // OpenSSL's own verdict, carried through so a disagreement is attributable
  checks.opensslAccepts = { ok: a.opensslVerify === true, detail: 'OpenSSL rejected its own artefact' }

  if (a.kind === 'x509') {
    const der = Buffer.from(a.cert, 'hex')
    try {
      const { signedBytes, signature } = splitCertificate(der)
      const key = rawKeyFromSpki(Buffer.from(a.spki, 'hex'), PK_LEN[a.set])

      checks.verifies = {
        ok: impl.verify(new Uint8Array(signature), new Uint8Array(signedBytes), new Uint8Array(key)) === true,
        detail: 'this package rejected a certificate OpenSSL issued and accepts',
      }

      // Negative control. Without it, a verify that returned true unconditionally
      // would pass the check above and the whole row would be worthless.
      const tampered = Uint8Array.from(signedBytes)
      tampered[tampered.length - 1] ^= 0x01
      checks.tamperRejected = {
        ok: impl.verify(new Uint8Array(signature), tampered, new Uint8Array(key)) === false,
        detail: 'a modified certificate body still verified',
      }
    } catch (e) {
      checks.verifies = { ok: false, detail: e.message }
    }
    record({ kind: 'x509', set: a.set, checks })
  }

  if (a.kind === 'cms') {
    const der = Buffer.from(a.blob, 'hex')
    checks.opensslRoundTrip = { ok: a.opensslVerify === true, detail: 'OpenSSL could not verify its own CMS blob' }
    try {
      const sd = parseSignedData(der)
      const key = rawKeyFromSpki(Buffer.from(a.spki, 'hex'), PK_LEN[a.set])

      checks.algorithmOid = {
        ok: sd.signatureAlgorithm === SIG_OID[a.set],
        detail: `SignerInfo names ${sd.signatureAlgorithm}, expected ${SIG_OID[a.set]} for ${a.set}`,
      }

      // The signature covers the attributes, so this is the signature check.
      checks.signatureVerified = {
        ok: impl.verify(new Uint8Array(sd.signature), new Uint8Array(sd.signedBytes), new Uint8Array(key)) === true,
        detail: 'this package rejected a CMS signature OpenSSL produced and accepts',
      }

      // And this is what ties that signature to the payload. Without it the
      // check above proves only that some attributes were signed, which would
      // hold just as well for a signature over somebody else's message.
      const md = sd.attrs[OID_MESSAGE_DIGEST]
      const actual = createHash(sd.digestAlgorithm === OID_SHA256 ? 'sha256' : sd.digestAlgorithm).update(sd.eContent).digest()
      checks.digestBindsMessage = {
        ok: md != null && Buffer.compare(md, actual) === 0,
        detail: md == null
          ? 'no messageDigest attribute, so nothing binds the signature to the content'
          : `messageDigest ${md.toString('hex').slice(0, 16)} does not match the content digest ${actual.toString('hex').slice(0, 16)}`,
      }

      checks.contentTypeBound = {
        ok: sd.attrs[OID_CONTENT_TYPE] != null
          && oidToString(sd.attrs[OID_CONTENT_TYPE], { start: 0, end: sd.attrs[OID_CONTENT_TYPE].length }) === sd.eContentType,
        detail: 'the signed contentType attribute does not match eContentType (RFC 5652 s5.3)',
      }

      checks.contentMatches = {
        ok: Buffer.compare(sd.eContent, Buffer.from(a.message, 'hex')) === 0,
        detail: 'the embedded eContent is not the message that was signed',
      }

      // Negative control, same reasoning as the certificate row.
      const tampered = Uint8Array.from(sd.signedBytes)
      tampered[tampered.length - 1] ^= 0x01
      checks.tamperRejected = {
        ok: impl.verify(new Uint8Array(sd.signature), tampered, new Uint8Array(key)) === false,
        detail: 'modified signed attributes still verified',
      }
    } catch (e) {
      checks.signatureVerified = { ok: false, detail: e.message }
    }
    record({ kind: 'cms', set: a.set, checks })
  }
}

const passed = rows.reduce((s, r) => s + Object.values(r.checks).filter((c) => c.ok === true).length, 0)
const na = rows.reduce((s, r) => s + Object.values(r.checks).filter((c) => c.ok === null).length, 0)

if (!quiet) {
  console.log(`\n${passed} protocol checks passed, ${failures} failed, ${na} not applicable across ${rows.length} rows`)
}

if (jsonOut) {
  mkdirSync(dirname(jsonOut), { recursive: true })
  writeFileSync(jsonOut, JSON.stringify({
    subject: { package: pkg.name, version: pkg.version },
    issuer: { name: 'OpenSSL', version: opensslVersion, image: IMAGE },
    runtime: { node: process.version, platform: `${process.platform}-${process.arch}` },
    totals: { passed, failed: failures, notApplicable: na },
    rows,
  }, null, 2) + '\n')
  if (!quiet) console.log(`report written to ${jsonOut}`)
}

process.exit(failures ? 1 : 0)
