// @kxco/post-quantum
//
// Production-tested post-quantum cryptography patterns: deterministic key
// derivation, hybrid HMAC + ML-DSA webhook signing, kid fingerprinting.
// Built on @noble/post-quantum. Used in production at KXCO across
// KnightsVault, KXCO Bank, KnightsBot, The Exchequer, and Armature L1.
//
// This package does NOT reimplement the NIST primitives. It wraps the
// audited @noble/post-quantum reference implementation with the integration
// patterns we have proven in production.

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
