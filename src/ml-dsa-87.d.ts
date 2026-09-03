/// <reference types="node" />

export interface MlDsa87Keypair {
  /** 2592-byte public key */
  publicKey: Buffer
  /** 4896-byte secret key */
  secretKey: Buffer
  /**
   * The 32-byte seed this keypair was expanded from.
   *
   * An expanded secret key does not contain its seed, so this is the only
   * point at which it can be captured. Pass it to `exportJwk` or
   * `exportSeedPkcs8` for RFC 9964 / LAMPS seed-form storage.
   */
  seed: Buffer
}

/**
 * Generate an ML-DSA-87 (NIST FIPS 204) keypair deterministically
 * from a master + domain-separation info string.
 *
 * Same inputs always produce the same keypair — no state, no DB row.
 *
 * Security Category 5. The default `info` differs from the ML-DSA-65 module's,
 * so one master yields unrelated keys for the two parameter sets.
 *
 * CNSA 2.0 names ML-DSA-87. Support for the parameter set is not a CNSA 2.0
 * compliance claim; see the note at the top of `ml-dsa-87.js`.
 */
export function keypairFromMaster(
  master: Buffer | Uint8Array,
  info?:  string,
): MlDsa87Keypair

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
   */
  context?: Buffer | Uint8Array | string
}

/**
 * Sign a message under an ML-DSA-87 secret key. Returns the signature
 * as a hex string (4627 bytes = 9254 hex characters).
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
 * Verify a hex-encoded ML-DSA-87 signature against a public key + message.
 *
 * Returns `false` on any cryptographic failure, including a signature or key
 * from a different parameter set.
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
 * Raw `@noble/post-quantum` ML-DSA-87 primitive, re-exported for callers
 * who want the lower-level API. The wrapper functions above are
 * recommended for production use.
 */
export const ml_dsa87: typeof import('@noble/post-quantum/ml-dsa.js').ml_dsa87
