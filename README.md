# kxco-post-quantum

Post-quantum cryptography primitives for the KXCO stack.

[![npm](https://img.shields.io/npm/v/kxco-post-quantum)](https://www.npmjs.com/package/kxco-post-quantum)
[![CI](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/actions/workflows/ci.yml/badge.svg)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/actions/workflows/ci.yml)
[![conformance](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/actions/workflows/conformance.yml/badge.svg)](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/actions/workflows/conformance.yml)
[![license](https://img.shields.io/badge/license-Apache--2.0-blue)](./LICENSE)

ML-DSA-65 (FIPS 204) and SLH-DSA-SHA2-192s (FIPS 205) signatures, ML-KEM-768 (FIPS 203) key encapsulation, and key fingerprinting utilities. Category 5 sets ML-DSA-87 and ML-KEM-1024 are also available. All other `kxco-pq-*` packages depend on this one.

**On Node 24 and later the primitives run in OpenSSL 3.5**, not in JavaScript. Older Node and browsers use [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum). The two are interchangeable on the wire, which is checked rather than assumed: the interoperability matrix runs in full against both, and every report records which one produced it.

**Evidence, not adjectives:**

- [CONFORMANCE.md](./CONFORMANCE.md): NIST ACVP vectors for FIPS 203/204/205 (2,103 tests, 0 failed), and a cross-implementation interop matrix against liboqs, Bouncy Castle and two pure-Python implementations (225 checks, 0 failed, both directions, with negative controls), run against both backends. Reproducible: `npm run conformance:acvp`, `npm run conformance:interop`.
- [BENCHMARKS.md](./BENCHMARKS.md): per-algorithm latency at p95/p99 on both backends and on x86-64 and arm64, plus memory. Two figures worth designing around: ML-DSA signing keeps a rejection-sampling tail on either backend (5.1x median-to-p99 in JavaScript, 3.5x on OpenSSL), and SLH-DSA-SHA2-192s signs in seconds rather than milliseconds (4.3 s and 1.7 s).
- [THREAT-MODEL.md](./THREAT-MODEL.md): what this defends against and what it does not. Read the side-channel section before deciding where a signing key lives.
- [MIGRATION.md](./MIGRATION.md): moving an RSA or ECDSA system across, and moving between versions of this package.
- [SECURITY.md](./SECURITY.md): reporting, release integrity, and the dependency policy.
- **Every release is reproducible and attested.** The published tarball rebuilds bit-for-bit from its own tag, verified in CI on every run, and each release carries a SLSA provenance attestation plus a CycloneDX SBOM at a permanent unauthenticated URL. A provenance attestation says a build happened in CI; the reproducible build says the artefact is the source. They are different claims and both are checkable without asking us for anything.

---

## Install

```bash
npm install kxco-post-quantum
```

Requires Node.js 20.19+. ESM-only.

---

## Quick start

```js
import { mlDsa, mlKem, slhDsa, fingerprint, kidEquals } from 'kxco-post-quantum'

// ML-DSA-65 — sign and verify
const { publicKey, secretKey } = mlDsa.keypairFromMaster(masterSecret, 'signing-v1')
const sig = mlDsa.sign(secretKey, 'hello')
const ok  = mlDsa.verify(publicKey, 'hello', sig)  // true

// SLH-DSA-SHA2-192s — hash-based signatures (same API shape as mlDsa)
const slh = slhDsa.keypairFromMaster(masterSecret, 'signing-v1')
const slhSig = slhDsa.sign(slh.secretKey, 'hello')
const slhOk  = slhDsa.verify(slh.publicKey, 'hello', slhSig)  // true

// Key fingerprint
const kid = fingerprint(publicKey)  // e.g. '4a7c9e2f1b3d5680'
kidEquals(kid, kid)                 // true (constant-time)

// ML-KEM-768 — key encapsulation
const kemKeys = mlKem.keypairFromMaster(masterSecret, 'encryption-v1')
const { ciphertext, sharedSecret } = mlKem.encapsulate(kemKeys.publicKey)
const recovered = mlKem.decapsulate(ciphertext, kemKeys.secretKey)
// sharedSecret and recovered are the same 32 bytes
```

`masterSecret` is a `Buffer` or `Uint8Array` with at least 16 bytes of entropy (typically 32–64 bytes from an env var or KMS).

### Category 5 parameter sets

`mlDsa87` (ML-DSA-87) and `mlKem1024` (ML-KEM-1024) have the same API as `mlDsa`
and `mlKem`, one security category higher. Reach for them when a counterparty
specifies Category 5 or names the parameter set. The KXCO default stays
Category 3.

```js
import { mlDsa87, mlKem1024 } from 'kxco-post-quantum'

const { publicKey, secretKey } = mlDsa87.keypairFromMaster(masterSecret, 'signing-v1')
const sig = mlDsa87.sign(secretKey, 'hello')      // 4627 bytes, 9254 hex chars
mlDsa87.verify(publicKey, 'hello', sig)           // true
```

| | Category 3 (default) | Category 5 |
|---|---|---|
| Signatures | `mlDsa` — pk 1952, sig 3309 | `mlDsa87` — pk 2592, sig 4627 |
| Key encapsulation | `mlKem` — pk 1184, ct 1088 | `mlKem1024` — pk 1568, ct 1568 |

The two sets do not mix, deliberately. Default derivation info differs, so one
master yields unrelated keys for each; and a signature from one set does not
verify under the other. Sizes are the migration cost, so check any fixed-width
signature or key field before mixing sets in one system.

**CNSA 2.0 names ML-DSA-87 and ML-KEM-1024, and supporting them is not a CNSA
2.0 compliance claim.** Compliance is a property of a deployment, not of an
available function. See [CONFORMANCE.md](./CONFORMANCE.md).

### Context strings (FIPS 204 / FIPS 205)

`sign` and `verify` take an optional context string, at most 255 bytes. A
signature made under a context does not verify without it, or under a different
one.

```js
const sig = mlDsa.sign(secretKey, 'hello', { context: 'kxco-nexus-v1' })

mlDsa.verify(publicKey, 'hello', sig, { context: 'kxco-nexus-v1' })  // true
mlDsa.verify(publicKey, 'hello', sig)                                // false
mlDsa.verify(publicKey, 'hello', sig, { context: 'other-v1' })       // false
```

The parameter is optional and defaults to no context, so every existing call
site is unaffected. An empty context is identical to omitting it. `slhDsa` takes
the same option.

**Context separates at the signature level; `keypairFromMaster(master, info)`
separates at the key level.** They are complementary. Use a context when one key
legitimately signs for several purposes and you need a signature from one
purpose to be unusable in another. Use a distinct derived key when the purposes
should not share a key at all.

Strings are encoded as UTF-8, so the 255-byte limit is bytes and not
characters. Over-length or wrongly typed input throws (`RangeError` /
`TypeError`) rather than returning `false`, because that is a caller bug and not
a failed verification:

```js
mlDsa.sign(secretKey, 'hello', 'kxco-nexus-v1')  // throws TypeError
                                                 // (needs { context: ... })
```

That last case is worth guarding: without the throw it would silently sign with
*no* context and produce a valid-looking signature carrying none of the intended
separation.

---

## API

### `mlDsa` — ML-DSA-65 (NIST FIPS 204)

| Export | Signature | Description |
|---|---|---|
| `keypairFromMaster` | `(master, info?) → { publicKey, secretKey }` | Deterministic keypair via HKDF-SHA-512. `info` defaults to `'ml-dsa-65-v1'`. |
| `sign` | `(secretKey, message) → string` | Signs a message. Returns a hex-encoded signature (6618 chars). |
| `verify` | `(publicKey, message, sigHex) → boolean` | Verifies a hex-encoded signature. Returns `false` on any failure. |
| `ml_dsa65` | raw primitive | The underlying `@noble/post-quantum` primitive, re-exported. |

`publicKey` is 1952 bytes. `secretKey` is 4032 bytes. `message` accepts `Buffer`, `Uint8Array`, or `string`.

### `slhDsa` — SLH-DSA-SHA2-192s (NIST FIPS 205)

Hash-based, stateless signatures. Security Category 3 (matching ML-DSA-65), but security rests only on the SHA-2 hash function — no lattice or number-theoretic assumptions. Use this as a conservative hedge alongside `mlDsa`. Tradeoff: signatures are ~5× larger (16224 vs 3309 bytes) and signing is slower.

| Export | Signature | Description |
|---|---|---|
| `keypairFromMaster` | `(master, info?) → { publicKey, secretKey }` | Deterministic keypair via HKDF-SHA-512. `info` defaults to `'slh-dsa-sha2-192s-v1'`. |
| `sign` | `(secretKey, message) → string` | Signs a message. Returns a hex-encoded signature (32448 chars). |
| `verify` | `(publicKey, message, sigHex) → boolean` | Verifies a hex-encoded signature. Returns `false` on any failure. |
| `slh_dsa_sha2_192s` | raw primitive | The underlying `@noble/post-quantum` primitive, re-exported. |

`publicKey` is 48 bytes. `secretKey` is 96 bytes. `message` accepts `Buffer`, `Uint8Array`, or `string`.

### `mlKem` — ML-KEM-768 (NIST FIPS 203)

| Export | Signature | Description |
|---|---|---|
| `keypairFromMaster` | `(master, info?) → { publicKey, secretKey }` | Deterministic keypair via HKDF-SHA-512. `info` defaults to `'ml-kem-768-v1'`. |
| `encapsulate` | `(publicKey) → { ciphertext, sharedSecret }` | Generates a shared secret and ciphertext to send to the key holder. |
| `decapsulate` | `(ciphertext, secretKey) → Buffer` | Recovers the shared secret from a ciphertext. Returns 32 bytes. |
| `ml_kem768` | raw primitive | The underlying `@noble/post-quantum` primitive, re-exported. |

`publicKey` is 1184 bytes. `ciphertext` is 1088 bytes. `sharedSecret` is 32 bytes.

### `fingerprint(publicKey)` → `string`

First 16 hex characters of SHA-256 of the public key. Stable for the lifetime of the key. Accepts raw bytes or a hex string.

### `kidEquals(a, b)` → `boolean`

Constant-time comparison of two kid strings. Use this when comparing user-supplied input — not `===`.

### `deriveSeed(master, info, length)` → `Buffer`

HKDF-SHA-512 derivation. `master` must be at least 16 bytes. `info` is a required domain-separation string. Returns `length` bytes.

### `webhook` — hybrid HMAC + ML-DSA-65 delivery signing

Low-level helpers for the KXCO hybrid webhook pattern: `envelope`, `hmacHex`, `verifyHmac`, `pqSign`, `verifyPq`, `signDelivery`, `verifyDelivery`. HMAC-SHA-256 gives symmetric verification with no library dependency; ML-DSA-65 adds non-repudiation over the same `${timestamp}.${body}` envelope. The full identity/credential surface lives in `kxco-pq-sdk`.

---

## What this does NOT do

- No identity credentials or verifiable claims (those are in `kxco-pq-sdk`)
- No relay, transport, or network layer
- No key storage or KMS integration
- No FIPS 140-3 module validation (the algorithms are FIPS-standardised; the module is not validated)

---

## Part of the KXCO stack

`kxco-post-quantum` is the primitive layer. Everything else builds on it:

- **`kxco-pq-sdk`** — identity credentials, webhook signing, verifiable claims
- Other `kxco-pq-*` packages — domain-specific integrations

Install this package directly when you need ML-DSA or ML-KEM without the rest of the identity stack.

---

## Security

Cryptographic operations delegate entirely to [`@noble/post-quantum`](https://github.com/paulmillr/noble-post-quantum) and [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) — this package does not reimplement any NIST primitive. `@noble/hashes` falls under Cure53's 2023 audit of the `@noble` ecosystem (`ciphers`, `curves`, `hashes`); `@noble/post-quantum` was **not** in that audit's scope and has been self-audited by its maintainer. See [AUDIT.md](./AUDIT.md) for the full posture.

To report a vulnerability: [open a private security advisory](https://github.com/KnightsbridgeAIQ/kxco-post-quantum/security/advisories/new) or email **john@knightsbridgelaw.com**. Acknowledgement within 2 business days, triage decision within 5. Full policy, including safe harbour for good-faith research: <https://kxco.ai/security>.

## License

Apache-2.0. See [LICENSE](./LICENSE).

## Maintainers

Shayne Heffernan and John Heffernan — [KXCO by Knightsbridge](https://kxco.ai)
