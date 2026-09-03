/// <reference types="node" />

/** JWS `alg` values this module signs and verifies (RFC 9964 names). */
export type JwsAlgorithm = 'ML-DSA-65' | 'ML-DSA-87'

export const JWS_ALGORITHMS: JwsAlgorithm[]

export interface JwsHeader {
  alg: JwsAlgorithm
  typ?: string
  kid?: string
  [key: string]: unknown
}

export interface SignJwsOptions {
  /** Defaults to 'ML-DSA-65'. */
  alg?: JwsAlgorithm
  /** Key identifier, e.g. the 16-hex `fingerprint()` of the public key. */
  kid?: string
  typ?: string
  /** Extra protected header members. May not restate alg, kid or typ. */
  header?: Record<string, unknown>
}

export interface VerifyJwsSuccess {
  valid: true
  header: JwsHeader
  /** Raw payload bytes. */
  payload: Uint8Array
  /** The payload decoded as UTF-8. JSON payloads are not parsed for you. */
  text: string
}

export interface VerifyJwsFailure {
  valid: false
  error: string
}

export type VerifyJwsResult = VerifyJwsSuccess | VerifyJwsFailure

/**
 * Sign a payload into a compact JWS. Objects are JSON-serialised.
 *
 * @throws {TypeError} on a bad options object or payload type
 * @throws {Error}     on an unsupported alg, or a header member that restates
 *                     alg, kid or typ
 */
export function signJws(
  payload: object | string | Uint8Array,
  secretKey: Buffer | Uint8Array,
  opts?: SignJwsOptions,
): string

/**
 * Verify a compact JWS.
 *
 * The algorithm is resolved from this module's allowlist using the header's
 * `alg`; a token cannot name its own verification routine. Pass `{ alg }` to
 * require a specific algorithm and `{ kid }` to require a specific key.
 *
 * Returns `{ valid: false, error }` for every failure. Throws only on caller
 * misuse of `opts`.
 */
export function verifyJws(
  token: string,
  publicKey: Buffer | Uint8Array,
  opts?: { alg?: JwsAlgorithm; kid?: string },
): VerifyJwsResult

/**
 * Read a token's header without verifying it — for choosing which key to fetch
 * from a `kid`. The header is unauthenticated until `verifyJws` returns valid.
 */
export function decodeJwsHeader(token: string): JwsHeader | null
