/// <reference types="node" />

/** Parameter sets that have a seed form. SLH-DSA does not and is absent. */
export type SeedAlgorithm = 'ML-DSA-65' | 'ML-DSA-87' | 'ML-KEM-768' | 'ML-KEM-1024'

export const SEED_ALGORITHMS: SeedAlgorithm[]

export interface SeededKeypair {
  publicKey: Buffer | Uint8Array
  secretKey: Buffer | Uint8Array
  /** 32 bytes for ML-DSA, 64 for ML-KEM. */
  seed: Buffer | Uint8Array
}

/** RFC 9964 algorithm-key-pair JWK. `priv` carries the SEED, not the expanded key. */
export interface AkpJwk {
  kty: 'AKP'
  alg: SeedAlgorithm
  /** base64url public key */
  pub: string
  /** base64url seed, present only on private JWKs */
  priv?: string
  kid?: string
  use?: string
}

/**
 * Expand a seed into a keypair. Deterministic, and byte-identical to what
 * OpenSSL 3.5 derives from the same seed.
 *
 * @throws {RangeError} if the seed is not the parameter set's seed length
 */
export function keypairFromSeed(
  alg: SeedAlgorithm,
  seed: Buffer | Uint8Array,
): SeededKeypair

/**
 * Derive a parameter set's seed from a master secret, using the same
 * HKDF-SHA-512 derivation `keypairFromMaster` uses. With the default `info`
 * this reproduces exactly the key `keypairFromMaster` produces.
 */
export function seedFromMaster(
  alg: SeedAlgorithm,
  master: Buffer | Uint8Array | string,
  info?: string,
): Buffer | Uint8Array

/**
 * Export an RFC 9964 AKP JWK. Supply `seed` for a private JWK.
 *
 * An expanded secret key is rejected: RFC 9964 has no encoding for one.
 *
 * @throws {RangeError} on a wrong-length public key or seed
 */
export function exportJwk(
  alg: SeedAlgorithm,
  key: { publicKey: Buffer | Uint8Array; seed?: Buffer | Uint8Array },
  opts?: { kid?: string; use?: string },
): AkpJwk

/**
 * Import an RFC 9964 AKP JWK, expanding a private one back to a full keypair.
 *
 * @throws {Error} if the key derived from `priv` disagrees with `pub`
 */
export function importJwk(jwk: AkpJwk | object): {
  alg: SeedAlgorithm
  publicKey: Buffer | Uint8Array
  secretKey?: Buffer | Uint8Array
  seed?: Buffer | Uint8Array
}

/**
 * Export a seed as PKCS#8 in LAMPS seed form — the `[0] IMPLICIT OCTET STRING`
 * CHOICE. Loads directly into OpenSSL 3.5 and Node 24+.
 */
export function exportSeedPkcs8(
  alg: SeedAlgorithm,
  seed: Buffer | Uint8Array,
): Buffer | Uint8Array

/**
 * Read a seed-form PKCS#8 key back.
 *
 * @throws {Error} on an expanded-form key, which contains no seed to return
 */
export function importSeedPkcs8(der: Buffer | Uint8Array): {
  alg: SeedAlgorithm
  seed: Buffer | Uint8Array
}
