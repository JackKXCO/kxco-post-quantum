/// <reference types="node" />

export interface MlKemKeypair {
  /** 1184-byte public key */
  publicKey: Buffer
  /** 2400-byte secret key */
  secretKey: Buffer
  /**
   * The 64-byte seed this keypair was expanded from.
   *
   * An expanded secret key does not contain its seed, so this is the only
   * point at which it can be captured. Pass it to `exportJwk` or
   * `exportSeedPkcs8` for RFC 9964 / LAMPS seed-form storage.
   */
  seed: Buffer
}

export interface MlKemEncapsulation {
  /** 1088-byte KEM ciphertext to transmit to the recipient */
  ciphertext: Buffer
  /** Alias for `ciphertext` (mirrors @noble/post-quantum's camelCase) */
  cipherText: Buffer
  /** 32-byte shared secret to use as a symmetric AEAD key */
  sharedSecret: Buffer
}

/**
 * Generate an ML-KEM-768 (NIST FIPS 203) keypair deterministically
 * from a master + domain-separation info string.
 */
export function keypairFromMaster(
  master: Buffer | Uint8Array,
  info?:  string,
): MlKemKeypair

/**
 * Encapsulate a shared secret to the recipient's ML-KEM-768 public key.
 *
 * The recipient calls `decapsulate(ciphertext, secretKey)` to recover
 * the same shared secret. Use the shared secret as a symmetric AEAD
 * key (eg. AES-256-GCM).
 */
export function encapsulate(publicKey: Buffer | Uint8Array): MlKemEncapsulation

/**
 * Decapsulate: recover the shared secret from a KEM ciphertext
 * using the recipient's secret key.
 */
export function decapsulate(
  ciphertext: Buffer | Uint8Array,
  secretKey:  Buffer | Uint8Array,
): Buffer

/**
 * Raw `@noble/post-quantum` ML-KEM-768 primitive, re-exported.
 */
export const ml_kem768: typeof import('@noble/post-quantum/ml-kem.js').ml_kem768
