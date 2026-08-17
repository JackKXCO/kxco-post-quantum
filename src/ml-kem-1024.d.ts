/// <reference types="node" />

export interface MlKem1024Keypair {
  /** 1568-byte public key */
  publicKey: Buffer
  /** 3168-byte secret key */
  secretKey: Buffer
}

export interface MlKem1024Encapsulation {
  /** 1568-byte KEM ciphertext to transmit to the recipient */
  ciphertext: Buffer
  /** Alias for `ciphertext` (mirrors @noble/post-quantum's camelCase) */
  cipherText: Buffer
  /** 32-byte shared secret; run it through a KDF before use as a key */
  sharedSecret: Buffer
}

/**
 * Generate an ML-KEM-1024 (NIST FIPS 203) keypair deterministically
 * from a master + domain-separation info string.
 *
 * Security Category 5. The default `info` differs from the ML-KEM-768 module's,
 * so one master yields unrelated keys for the two parameter sets.
 *
 * CNSA 2.0 names ML-KEM-1024. Support for the parameter set is not a CNSA 2.0
 * compliance claim; see the note at the top of `ml-kem-1024.js`.
 */
export function keypairFromMaster(
  master: Buffer | Uint8Array,
  info?:  string,
): MlKem1024Keypair

/**
 * Encapsulate a shared secret to the recipient's ML-KEM-1024 public key.
 *
 * The recipient calls `decapsulate(ciphertext, secretKey)` to recover
 * the same shared secret. Derive the symmetric key from it with a KDF rather
 * than using it directly.
 */
export function encapsulate(publicKey: Buffer | Uint8Array): MlKem1024Encapsulation

/**
 * Decapsulate: recover the shared secret from a KEM ciphertext
 * using the recipient's secret key.
 *
 * A corrupted ciphertext returns an unrelated 32-byte secret rather than
 * throwing (FIPS 203 implicit rejection), so a successful return is not
 * evidence the ciphertext was authentic.
 */
export function decapsulate(
  ciphertext: Buffer | Uint8Array,
  secretKey:  Buffer | Uint8Array,
): Buffer

/**
 * Raw `@noble/post-quantum` ML-KEM-1024 primitive, re-exported.
 */
export const ml_kem1024: typeof import('@noble/post-quantum/ml-kem.js').ml_kem1024
