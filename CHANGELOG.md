# Changelog

## 1.3.0 - unreleased

Adds FIPS 204 / FIPS 205 context string support. Purely additive: the
cryptographic surface for every existing call site is byte-for-byte unchanged,
and all 39 pinned vectors still match.

### Added
- **Optional `context` on `mlDsa.sign` / `mlDsa.verify`** via a trailing options
  object, `{ context }`. At most 255 bytes per FIPS 204 section 5.2; strings are
  encoded as UTF-8. A signature made under a context does not verify without it
  or under a different one. Closes a real incompleteness relative to FIPS 204:
  the library previously could not verify a counterparty's signature that used a
  context.
- **The same option on `slhDsa.sign` / `slhDsa.verify`**, on the same terms.
  Added alongside ML-DSA rather than after it, because one signature module
  accepting an options object while its sibling silently ignored one would be a
  footgun.
- `MAX_CONTEXT_BYTES` (255) exported from both modules.
- `test/context.test.js`, 26 tests, including cross-verification against
  third-party ML-DSA-65 signatures produced by OpenSSL through Python
  `cryptography`, covering five context shapes: short, single-byte, the 255-byte
  maximum, binary, and multi-byte UTF-8.

### Notes
- **No behaviour change without the new argument.** Omitting `opts` takes the
  identical code path as before. An empty context is collapsed to no context,
  which is what FIPS 204 specifies and what was verified empirically.
- **Misuse throws rather than returning `false`.** A context over 255 bytes, a
  wrongly typed context, or a bare value passed where an options object belongs
  raises `RangeError` / `TypeError`. These are caller bugs, not failed
  verifications, and swallowing them would hide a signature that silently
  carried no domain separation. No existing call site passes the argument, so
  nothing can regress.
- Works identically on `@noble/post-quantum` 0.6.1 and 0.7.0, verified on both,
  so this release is independent of the 0.7.0 upgrade.

## 1.2.1 — 2026-07-22

Metadata alignment. No code changes; cryptographic surface is byte-for-byte
identical to `1.2.0` (all 39 pinned vectors match).

### Changed
- **License now `Apache-2.0`** in package metadata, matching the repository
  LICENSE. `1.2.0` was published declaring `MIT` from a pre-relicense branch;
  this release corrects the published license to the canonical `Apache-2.0`.
- `author` set to **Shayne Heffernan and John Heffernan**.
- README security note corrected: `@noble/post-quantum` was **not** in scope
  of Cure53's 2023 `@noble` audit (which covered `ciphers`/`curves`/`hashes`)
  and is maintainer self-audited — the prior "audited by Cure53 (2024)"
  wording was inaccurate. See `AUDIT.md`.

## 1.2.0 — 2026-07-22

Adds SLH-DSA (FIPS 205) and modernises the underlying primitive engine to
`@noble/post-quantum@0.6.1`. **No breaking changes for consumers** — the
public API and all previously pinned outputs are byte-for-byte identical.

### Added
- **`slhDsa` — SLH-DSA-SHA2-192s (NIST FIPS 205)**, exported both from the
  package root and the `kxco-post-quantum/slh-dsa` subpath. Hash-based,
  stateless signatures at Security Category 3 (matching ML-DSA-65), whose
  security rests only on SHA-2 — the conservative hedge alongside the
  lattice-based ML-DSA-65. Deterministic `keypairFromMaster(master, info?)`
  via the same HKDF-SHA-512 derivation, plus `sign` / `verify`. Public key
  48 bytes, secret key 96 bytes, signature 16224 bytes.
- Test vectors extended to pin SLH-DSA keypairs and round-trip (39 checks,
  up from 29).

### Changed
- **`@noble/post-quantum` bumped `^0.2.1` → `^0.6.1`** — the FIPS 203/204/205
  final reference implementation. The engine's public API changed argument
  order for signature `sign`/`verify` and requires `.js` in subpath imports;
  both are absorbed inside this package's wrappers, so no downstream package
  or caller is affected.
- Description and keywords updated to reflect SLH-DSA / FIPS 205 coverage.

### Verification
- 11 node tests pass, 7 browser-smoke tests pass, 39 pinned vectors pass.
- **Compatibility gate:** every ML-DSA-65, ML-KEM-768, HKDF, fingerprint and
  webhook vector pinned under `@noble/post-quantum@0.2.1` still matches
  bit-for-bit under `0.6.1`. Deterministic keys derived from existing KXCO
  master secrets — including Armature L1 identities — are unchanged.

## 1.1.6 — 2026-05-24

Maintenance release. No breaking changes.



## 1.1.5 — 2026-05-24

Maintenance release. No breaking changes.



## 1.1.4 — 2026-05-24

Maintenance release. No breaking changes.



## 1.1.3 â€” 2026-05-23

Maintenance release. No breaking changes.


All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.2] â€” 2026-05-22

Documentation correction. No code changes; no behaviour changes; no
cryptographic surface changes vs `1.1.1`.

### Fixed
- **AUDIT.md** Â§1 previously cited a 2024 Cure53 audit of
  `@noble/post-quantum`. That citation was incorrect â€” Cure53's 2023
  NDS-01 audit covered `@noble/ciphers`, `@noble/curves`, and
  `@noble/hashes` only; the post-quantum package was not in scope. As of
  2026-05-22, upstream `@noble/post-quantum` has only been self-audited
  by its maintainer (v0.6.1, April 2026). AUDIT.md Â§1 has been rewritten
  to reflect the actual upstream audit posture. A correction notice is
  included at the top of the file. Reviewers who relied on the prior
  citation should re-read Â§1 of AUDIT.md.
- **CHANGELOG.md** 1.0.0 entry similarly stated "audited by Cure53,
  2024" alongside the upstream pin. That sentence has been corrected
  in-place in this release; the substance of the 1.0.0 release is
  otherwise unchanged.

### Why this is a patch, not an advisory
The misstatement was in documentation only. No code path, signature,
key-derivation routine, or wire format depends on the cited audit. The
fix is a documentation rewrite; affected installs upgrade by pulling
1.1.2. If your due-diligence pack referenced AUDIT.md from 1.0.1
through 1.1.1, please refresh against 1.1.2.

## [1.1.1] â€” 2026-05-21

Operational hardening release. No source-code changes; this is the first
release published via **npm Trusted Publishing** rather than a long-lived
`NPM_TOKEN`.

### Changed
- `.github/workflows/publish.yml` now publishes via npm Trusted Publishing
  (OIDC). The `NODE_AUTH_TOKEN` / `NPM_OTP` env vars are removed; the
  workflow's `id-token: write` permission is the entire credential.
  Registered at https://www.npmjs.com/package/kxco-post-quantum/access
  binding `org=JackKXCO`, `repo=kxco-post-quantum`, `workflow=publish.yml`.
- Repo-level `NPM_TOKEN` and `NPM_OTP` secrets removed â€” no long-lived
  credentials remain in the publishing path.

### Why this matters
- Every release tarball is now signed by GitHub Actions OIDC against the
  exact commit being published, with no human-held secret in the loop.
- No more burning recovery codes per release. The publish workflow now
  runs hands-free on every `v*` tag push.

## [1.1.0] â€” 2026-05-21

Same API. Same byte-for-byte outputs (all 29 pinned vectors still match).
The package now runs in **browsers** as well as Node.

### Added
- Isomorphic runtime â€” every module works identically in modern browsers
  (Chromium, Firefox, Safari) and Node, served from CDNs like esm.sh
  with zero polyfill burden
- `test/browser-smoke.test.js` runs the public API with `globalThis.Buffer`
  removed, asserts plain `Uint8Array` outputs and a clean hybrid-signing
  round trip â€” proves browser compatibility in CI

### Changed
- HKDF-SHA-512 now sourced from `@noble/hashes/hkdf` (was `node:crypto`)
- HMAC-SHA-256 now sourced from `@noble/hashes/hmac` (was `node:crypto`)
- SHA-256 for kid fingerprints now sourced from `@noble/hashes/sha256`
  (was `node:crypto`)
- Constant-time comparisons are portable byte loops (replaces
  `node:crypto.timingSafeEqual`) â€” identical security property,
  runs in browsers
- Functions return `Buffer` on Node (when `globalThis.Buffer` is defined)
  and plain `Uint8Array` in browsers. **Backwards compatible** for Node
  callers; `Buffer extends Uint8Array` so any code accepting `Uint8Array`
  already works.
- `engines.node` bumped to `>=20.19` to match the underlying
  `@noble/hashes@2` requirement (Node 18 is past EOL)

### Dependencies
- Added `@noble/hashes ^2.2.0` (peer of `@noble/post-quantum`)
- `@noble/post-quantum ^0.2.1` unchanged

### Verification
- 9 node tests pass
- 6 browser-smoke tests pass
- 29 pinned vectors still match â€” no cryptographic surface changes,
  bit-for-bit identical to 1.0.3 in Node

## [1.0.3] â€” 2026-05-21

First release ships with SLSA Level 2 provenance attestation tied to a
public GitHub Actions workflow run. No cryptographic surface changes
vs `1.0.2` â€” every diff is metadata, types, CI, and hygiene.

### Added
- SLSA Level 2 provenance on every published release via GitHub Actions OIDC
  (`publishConfig.provenance: true`)
- `.github/workflows/publish.yml` triggered by `v*` tags â€” runs tests then
  `npm publish --provenance --access public`
- `.github/workflows/ci.yml` matrix over Node 18 / 20 / 22 on every push and PR
- Hand-written TypeScript declarations (`.d.ts`) for all six modules; wired
  into `exports[*].types` so TypeScript consumers get full typings without
  any build step
- `.github/dependabot.yml` â€” weekly npm + github-actions ecosystem checks
- `sideEffects: false` for tree-shaking
- `funding` field in `package.json`
- Top-level `"types"` field in `package.json` pointing at `./src/index.d.ts`

### Changed
- `package.json` `files` allowlist tightened to `["src", "README.md", "LICENSE",
  "SECURITY.md", "CHANGELOG.md"]` â€” locks down what ships to npm
- `package.json` `exports` now declares per-subpath `types` + `import` keys
- `SECURITY.md` rewritten in the standard short-form template with explicit
  in-scope / out-of-scope split delegating primitive bugs upstream to
  `@noble/post-quantum`
- All third-party actions in workflows pinned by 40-char commit SHA, never
  floating tags
- README badge row trimmed to four (`npm`, `license`, `Socket`, `production-live`)
  and a 60-second live-verify quickstart added under the title

### Security
- No cryptographic code changed in this release â€” every change is metadata,
  types, CI, and documentation. Production behaviour is bit-for-bit identical
  to `1.0.2`.

## [1.0.2] â€” 2026-05-21

### Changed
- Repository URL on the npm package metadata now points to
  `github.com/JackKXCO/kxco-post-quantum`. No code change.

## [1.0.1] â€” 2026-05-21

### Added
- `AUDIT.md` â€” self-attested audit posture with roadmap (external audit
  Q3 2026, public bug bounty Q4 2026, FIPS 140-3 CMVP application 2027)
- `test/vectors.json` â€” 29 deterministic test vectors pinning every primitive
  output bit-for-bit
- `test/run-vectors.js` â€” runner anyone can use to verify reproducibility
- `npm test` runs both the functional tests and vector verification
- `npm run test:vectors` for vector check only

### Changed
- `SECURITY.md` sharpened with explicit threat model and pinned upstream
  `@noble/post-quantum@0.2.1` integrity hash
- `README.md` "Used in production at" section with file refs to chain.kxco.ai

No API changes from `1.0.0`.

## [1.0.0] â€” 2026-05-21

First stable release. Committed public API surface:

- `mlDsa.keypairFromMaster(master, info—)`, `mlDsa.sign`, `mlDsa.verify`
- `mlKem.keypairFromMaster(master, info—)`, `mlKem.encapsulate`, `mlKem.decapsulate`
- `deriveSeed(master, info, length)`
- `fingerprint(publicKey)`, `kidEquals(a, b)`
- `webhook.envelope`, `webhook.hmacHex`, `webhook.verifyHmac`,
  `webhook.pqSign`, `webhook.verifyPq`, `webhook.signDelivery`,
  `webhook.verifyDelivery`

Verified at release: 9/9 functional tests + 29/29 vector checks pass.

Underlying primitives via `@noble/post-quantum@^0.2.1`. See `AUDIT.md` for
upstream audit posture (no third-party audit of the PQ package; self-audited
by maintainer at v0.6.1, April 2026). ESM-only. Node.js 18+.

## [0.1.0] â€” 2026-05-21

Initial pre-release.

[Unreleased]: https://github.com/JackKXCO/kxco-post-quantum/compare/v1.1.2...HEAD
[1.1.2]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.1.1...v1.1.2
[1.1.1]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.1.0...v1.1.1
[1.1.0]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.0.3...v1.1.0
[1.0.3]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.0.2...v1.0.3
[1.0.2]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.0.1...v1.0.2
[1.0.1]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v1.0.0...v1.0.1
[1.0.0]:      https://github.com/JackKXCO/kxco-post-quantum/compare/v0.1.0...v1.0.0
[0.1.0]:      https://github.com/JackKXCO/kxco-post-quantum/releases/tag/v0.1.0