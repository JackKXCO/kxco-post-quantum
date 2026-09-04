#!/usr/bin/env node
// Sign release assets with ML-DSA-65, using this package's own signing path.
//
// A post-quantum signing library whose own releases carry only a classical
// signature is making an argument it does not act on. These are signed with
// ML-DSA-65 through the same `mlDsa.sign` any caller uses, so the signature is
// evidence the library works as well as evidence the artefact is ours.
//
//   node scripts/sign-release.mjs <file> [<file>...]
//
// Reads the 32-byte master seed as hex from KXCO_RELEASE_SEED and writes
// <file>.sig beside each input: the ML-DSA-65 signature over the file bytes,
// as hex.
//
// Verify with the public key in release-signing-key.pub.hex:
//
//   import { mlDsa } from 'kxco-post-quantum'
//   mlDsa.verify(publicKeyBytes, fileBytes, sigHex)

import { readFileSync, writeFileSync } from 'node:fs'
import { mlDsa } from '../src/index.js'

const files = process.argv.slice(2)
if (files.length === 0) {
  console.error('usage: sign-release.mjs <file> [<file>...]')
  process.exit(2)
}

const hex = (process.env.KXCO_RELEASE_SEED ?? '').trim()
if (!/^[0-9a-f]{64}$/i.test(hex)) {
  console.error('KXCO_RELEASE_SEED must be 64 hex characters (a 32-byte master seed)')
  process.exit(2)
}

const kp = mlDsa.keypairFromMaster(Buffer.from(hex, 'hex'))

// The published public key is committed to the repository. If the seed in CI
// ever stops matching it, every signature would verify against a key nobody
// has, which is worse than not signing. Fail instead.
const expected = readFileSync(new URL('../release-signing-key.pub.hex', import.meta.url), 'utf8').trim()
const actual = Buffer.from(kp.publicKey).toString('hex')
if (actual !== expected) {
  console.error('the seed does not derive the published release signing key; refusing to sign')
  process.exit(1)
}

for (const file of files) {
  const bytes = readFileSync(file)
  const sig = mlDsa.sign(kp.secretKey, bytes)
  if (mlDsa.verify(kp.publicKey, bytes, sig) !== true) {
    console.error(`${file}: signature did not verify immediately after signing, refusing to publish it`)
    process.exit(1)
  }
  writeFileSync(`${file}.sig`, sig + '\n')
  console.log(`  ${file}.sig  (${sig.length / 2} bytes, ML-DSA-65, verified)`)
}
