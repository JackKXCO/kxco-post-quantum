/// <reference types="node" />

export interface MlDsaKeypair {
  /** 1952-byte public key */
  publicKey: Buffer
  /** 4032-byte secret key */
  secretKey: Buffer
}

/**
 * Generate an ML-DSA-65 (NIST FIPS 204) keypair deterministically
 * from a master + domain-separation info string.
 *
 * Same inputs always produce the same keypair — no state, no DB row.
 */
export function keypairFromMaster(
  master: Buffer | Uint8Array,
  info?:  string,
): MlDsaKeypair

/** Maximum context length in bytes (FIPS 204 section 5.2). */
export const MAX_CONTEXT_BYTES: 255

export interface SignatureOptions {
  /**
   * Optional FIPS 204 section 5.2 context string, at most 255 bytes.
   * Strings are encoded as UTF-8.
   *
   * Gives domain separation at the signature level: a signature made under a
   * context does not verify without it, or under a different one. An empty
   * context is identical to omitting it.
   *
   * Complements `keypairFromMaster(master, info)`, which separates domains at
   * the key level.
   */
  context?: Buffer | Uint8Array | string
}

/**
 * Sign a message under an ML-DSA-65 secret key. Returns the signature
 * as a hex string (3309 bytes = 6618 hex characters).
 *
 * @throws {TypeError}  if `opts` is not an options object, or `context` is
 *                      neither a string nor a Uint8Array
 * @throws {RangeError} if `context` exceeds 255 bytes
 */
export function sign(
  secretKey: Buffer | Uint8Array,
  message:   Buffer | Uint8Array | string,
  opts?:     SignatureOptions,
): string

/**
 * Verify a hex-encoded ML-DSA-65 signature against a public key + message.
 *
 * Returns `false` on any cryptographic failure (invalid hex, wrong length,
 * mismatch, or a missing/incorrect context).
 *
 * Throws only on caller misuse of `opts`, which is a programming error rather
 * than a failed verification and is not swallowed.
 *
 * @throws {TypeError}  if `opts` is not an options object, or `context` is
 *                      neither a string nor a Uint8Array
 * @throws {RangeError} if `context` exceeds 255 bytes
 */
export function verify(
  publicKey: Buffer | Uint8Array,
  message:   Buffer | Uint8Array | string,
  sigHex:    string,
  opts?:     SignatureOptions,
): boolean

/**
 * Raw `@noble/post-quantum` ML-DSA-65 primitive, re-exported for callers
 * who want the lower-level API. The wrapper functions above are
 * recommended for production use.
 */
export const ml_dsa65: typeof import('@noble/post-quantum/ml-dsa.js').ml_dsa65
