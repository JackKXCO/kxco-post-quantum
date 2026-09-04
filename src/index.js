// @kxco/post-quantum
//
// Production-tested post-quantum cryptography patterns: deterministic key
// derivation, hybrid HMAC + ML-DSA webhook signing, kid fingerprinting.
// Built on @noble/post-quantum. Used in production at KXCO across
// KnightsVault, KXCO Bank, KnightsBot, The Exchequer, and Armature L1.
//
// This package does NOT reimplement the NIST primitives. It wraps the
// @noble/post-quantum reference implementation with the integration patterns we
// have proven in production, and on Node 24+ it prefers the OpenSSL 3.5 backend.
//
// The primitives are evidenced here rather than taken on trust: every parameter
// set is checked against NIST's own ACVP vectors and cross-checked against
// liboqs, Bouncy Castle and dilithium-py/kyber-py in both directions. See
// CONFORMANCE.md, and audit/ for the dependency review.

export * as mlDsa  from './ml-dsa.js'
export * as mlKem  from './ml-kem.js'
export * as slhDsa from './slh-dsa.js'

// Category 5 parameter sets, for callers who are given ML-DSA-87 or
// ML-KEM-1024 as a requirement. The KXCO default stays Category 3
// (mlDsa / mlKem). Supporting these sets is not a CNSA 2.0 compliance claim;
// see the notes at the top of each module and CONFORMANCE.md.
export * as mlDsa87   from './ml-dsa-87.js'
export * as mlKem1024 from './ml-kem-1024.js'
export * from './derive.js'
export * from './kid.js'
export * as webhook from './webhook.js'

// Seed-form keys (RFC 9964 AKP JWKs, LAMPS seed-form PKCS#8) and compact JWS
// with the RFC 9964 algorithm names. Both are format and derivation only: they
// contact nothing, need no licence, and a token or key they produce stays
// verifiable offline for as long as the holder keeps the public key.
export * as seed from './seed.js'
export * as jws  from './jws.js'

// Reports which backend is doing the maths in this process, for evidence
// bundles and support. It reports; it never switches.
export { backend, isNative, requireNativeBackend } from './backend.js'
