// Internal: FIPS 204 / FIPS 205 signature context strings.
//
// Not part of the public exports map. Shared by ml-dsa.js and slh-dsa.js
// because a validator for security-relevant input should exist once, even
// though the small byte/hex helpers in those modules are duplicated.
//
// FIPS 204 section 5.2 (and FIPS 205 equivalently) allow an optional context
// string of at most 255 bytes, mixed into the message representative. It gives
// domain separation: a signature made under one context does not verify under
// another, or under no context at all.
//
// KXCO derives keys per domain via deriveSeed(master, info), which separates at
// the KEY level. Context separates at the SIGNATURE level, so one key can sign
// for several domains without a signature being replayable across them. The two
// are complementary, not alternatives.

const enc = new TextEncoder()

/** FIPS 204 section 5.2: |ctx| <= 255. */
export const MAX_CONTEXT_BYTES = 255

/**
 * Normalise the options bag into a context byte string, or undefined.
 *
 * Returns undefined for "no context", which makes the caller take the exact
 * code path it took before this parameter existed. An empty context is
 * cryptographically identical to no context, so it also returns undefined
 * rather than passing a zero-length array down.
 *
 * THROWS on caller misuse (wrong type, over-length). This is deliberate and it
 * differs from verify()'s usual fail-closed behaviour: a malformed context is a
 * programming error, not a bad signature, and silently returning false would
 * hide the bug behind an outcome that looks like a normal verification failure.
 * No existing call site passes this argument, so nothing can regress.
 *
 * @param {{ context?: Uint8Array|Buffer|string }} [opts]
 * @returns {Uint8Array|undefined}
 */
export function normalizeContext(opts) {
  if (opts === undefined || opts === null) return undefined

  if (typeof opts !== 'object' || Array.isArray(opts) || opts instanceof Uint8Array) {
    throw new TypeError(
      'expected an options object such as { context }, not a bare value',
    )
  }

  const { context } = opts
  if (context === undefined || context === null) return undefined

  let bytes
  if (context instanceof Uint8Array) {
    bytes = context
  } else if (typeof context === 'string') {
    bytes = enc.encode(context)
  } else {
    throw new TypeError('context must be a Uint8Array or a string')
  }

  if (bytes.length > MAX_CONTEXT_BYTES) {
    throw new RangeError(
      `context must be at most ${MAX_CONTEXT_BYTES} bytes (FIPS 204 section 5.2), got ${bytes.length}`,
    )
  }

  // Empty context is identical to no context under FIPS 204, so collapse it
  // and keep the legacy call path byte-for-byte.
  return bytes.length === 0 ? undefined : bytes
}
