# Changelog

## 1.5.1

Dependency bump: `@noble/post-quantum` 0.7.0 to **0.7.1**, published 2026-08-27.
Exact pin as always, never a range.

Worth taking rather than waiting for the scheduled Dependabot run, because one of
its changes touches how this package calls it: 0.7.1 snapshots options on entry
so a caller's object cannot be mutated afterwards. Every FIPS 204 context string
this package passes goes in as an options object, so that hardening is directly
on our path.

It also adds a WebCrypto wrapper for ML-KEM upstream. Nothing here uses it yet,
but it is worth knowing that the backend is converging on the same thing this
package did in 1.5.0: use the platform's implementation where the platform has
one.

Verified before merging, on all three runtimes: 39 pinned vectors bit-for-bit and
53 tests on Node 20 and 22 (the JavaScript path, where this bump actually
applies) and on Node 24+ (the OpenSSL path).

AUDIT.md carries the new pin and its integrity hash. The conservative bound is
unchanged and restated: the maintainer's self-audit covers 0.6.1, we ship 0.7.1,
so **the version we ship is covered by no audit at all**.

## 1.5.0

**The FIPS primitives now run in OpenSSL where the runtime has them.** On Node 24
and later this package uses OpenSSL 3.5 for ML-KEM, ML-DSA and SLH-DSA. On Node
20 and 22, in browsers, and on any runtime without them, the JavaScript backend
is used exactly as before.

Additive. No export changed, no signature changed, no key format changed, and
`@noble/post-quantum` is still a dependency and still the backend on every
runtime that lacks the native primitives. Nothing is removed.

**Both backends are checked against each other rather than assumed to agree.**
The interoperability matrix runs in full on both, against liboqs, Bouncy Castle
and dilithium-py / kyber-py, and both return **225 passed, 0 failed, 42 not
applicable across 38 rows**. CI runs both legs. Every generated report now
records which backend produced it under `wrapperBackend`, because a run that
does not say is not evidence about either one.

Keys and signatures are unchanged on the wire, which is what makes this safe to
do silently: a signature made by one backend verifies under the other, in both
directions, for all nine parameter sets. Existing keys keep working. Nothing
needs migrating.

Measured on the development machine:

| | OpenSSL | JavaScript | |
|---|---|---|---|
| ML-DSA-65 sign | 1.34 ms | 11.54 ms | 8.6x |
| ML-DSA-65 verify | 0.28 ms | 2.22 ms | 7.9x |
| SLH-DSA-SHA2-192s sign | 1595 ms | 4717 ms | 3.0x |

**A FIPS 204 context string keeps the JavaScript path.** Node's `sign` and
`verify` take no context argument, and signing without the caller's context
would produce a signature that verifies against nothing. That is a deliberate
fallback, not a gap.

**THREAT-MODEL.md is updated, and the change is narrower than it looks.** That
document argued the timing and cache attacker was out of scope *structurally*,
because the property cannot be established from inside JavaScript. On the
OpenSSL path that argument no longer applies. It does not follow that this
package is constant-time: we have published no timing measurements, and
OpenSSL's side-channel posture is theirs to state rather than ours to assert.
The honest position is that the attacker moves from structurally out of scope to
**unmeasured** on Node 24+, and stays out of scope everywhere else.

## 1.4.1

Evidence and documentation only. **No `src/` module changed**, no export was
added or removed, and the dependency set is unchanged, so no call site can
behave differently than it did on 1.4.0.

**liboqs is now a third interop implementation.** The cross-implementation
matrix ran against two peers and now runs against three: liboqs 0.16.0 (C),
Bouncy Castle 1.85.2 (Java) and dilithium-py 1.4.0 / kyber-py 1.2.0 (Python).
**225 checks passed, 0 failed, 42 not applicable, across 38 rows**, up from
156/0/10 across 24. The previous figures are reproduced exactly when the new
peer is excluded, so nothing about the existing evidence moved.

SLH-DSA had one peer and now has two. liboqs runs from a container built from
source at a tag pinned in `peers-lock.json`, and CI builds it, so the version
tested is the version named.

A peer that cannot do something now records as not-applicable rather than as a
disagreement. The 42 not-applicable are itemised in CONFORMANCE.md: ten from our
own hedged signing, thirty-two from two liboqs API limits.

**AUDIT.md corrections.** The reviewer checklist told anyone doing due diligence
to fetch an endpoint that returns 500. Verification now goes to Armature L1 over
public JSON-RPC, with the calldata layout documented and a named article page
for the other half of the join. Both documented commands were run verbatim
against production before publishing.

Two false claims in the same file are withdrawn. It said we pin
`@noble/post-quantum@0.6.1`, "the exact version covered by the maintainer's own
self-audit"; we ship `0.7.0`, the self-audit covers `0.6.1`, and **the version we
ship is covered by no audit at all**. It also described the dependency as
"itself audited", contradicting its own section 1.

**Supply chain.** Each release now publishes its CycloneDX SBOM as a GitHub
Release asset at `releases/download/<tag>/sbom.cyclonedx.json`, a permanent
unauthenticated URL. It was previously generated but retained only as an
expiring Actions artifact, which is not a published SBOM. The dependency policy
is now stated in SECURITY.md rather than living only in `dependabot.yml`.

## 1.4.0

Adds the Security Category 5 parameter sets, and publishes conformance and
interoperability evidence for everything the package computes.

Additive throughout. Two new modules appear under `src/`, and no existing module,
export, default or call path changes: the dependency set is unchanged, the
default parameter sets stay at Category 3, and all 39 pinned vectors still match
bit-for-bit. Nothing here can alter the behaviour of an existing call site.

### Added
- **`mlDsa87` (ML-DSA-87) and `mlKem1024` (ML-KEM-1024)**, Security Category 5,
  as new modules with the same API as their Category 3 counterparts. Purely
  additive: no existing module, export or call path changes, and the KXCO
  default stays Category 3. Subpath exports `./ml-dsa-87` and `./ml-kem-1024`.
  Both are exercised by the ACVP harness and the interop matrix through their
  wrapper path, not only as primitives.

  Default derivation info differs from the Category 3 modules
  (`ml-dsa-87-v1`, `ml-kem-1024-v1`), so one master yields unrelated keys per
  parameter set rather than colliding, and `test/category5.test.js` asserts that
  a signature from one set does not verify under the other in either direction.

  **Supporting these sets is not a CNSA 2.0 compliance claim.** CNSA 2.0 names
  both, and compliance is a property of a deployment rather than of an available
  function: the KXCO estate signs at Category 3, including Armature L1 from
  block 0 and every issued KXCO ID, none of which these modules change. The
  accurate sentence is "supports ML-DSA-87 and ML-KEM-1024". This is stated in
  both module headers, both type declarations, the README, MIGRATION.md and
  CONFORMANCE.md, because it is the claim most likely to drift.

  Sizes, since they are the real migration cost: ML-DSA-87 public key 2592 and
  signature 4627 bytes, against 1952 and 3309 at ML-DSA-65. ML-KEM-1024 public
  key and ciphertext 1568 bytes each, against 1184 and 1088. The ML-KEM shared
  secret stays 32 bytes at both sets, so downstream key derivation is unaffected.
- **`conformance/`, a NIST ACVP harness** for FIPS 203, 204 and 205, covering
  every parameter set NIST publishes vectors for: ML-KEM-512/768/1024,
  ML-DSA-44/65/87 and all twelve SLH-DSA sets. The signature sets cover the
  external and internal interfaces, pure and pre-hashed, external-mu, and
  deterministic and randomized signing. Vectors are pinned by upstream commit
  and per-file SHA-256 in `conformance/acvp-lock.json`, so a rewritten upstream
  file fails the fetch instead of quietly changing the result.
- **`conformance/interop/`, a cross-implementation matrix** against Bouncy
  Castle (Java) and dilithium-py / kyber-py (Python), neither of which shares
  code with our backend. Every check runs in both directions, and includes
  negative controls: a tampered signature that the peer must reject, and a
  corrupted ML-KEM ciphertext that must decapsulate to an unrelated secret.
  Without those, a peer that always returned true would pass the whole matrix.
- **`CONFORMANCE.md`** reporting both, including what the evidence does not
  cover: no side-channel claim, no FIPS 140-3 validation, no CNSA 2.0
  assertion, no protocol-level encoding claim.
- **`THREAT-MODEL.md`** stating the security boundary. In particular it states
  plainly that constant-time execution cannot be established from inside
  JavaScript, that timing, cache and power attackers are therefore out of
  scope, and what to do instead when a key needs to withstand them.
- **`MIGRATION.md`** covering the add-then-remove path off RSA or ECDSA, and
  version-to-version upgrades.
- **`.github/workflows/conformance.yml`** running both harnesses on every push
  and in full weekly, so the reports describe current behaviour rather than the
  day someone ran them by hand. The SLH-DSA signature sets run as a separate job
  because a full pass of them takes over an hour, and per-push runs subsample
  with a per-group cap, which the generated report records so a subsampled run
  cannot be mistaken for a full one.
- **A CycloneDX SBOM generated during publish**, from the tree that was actually
  installed for the build, and attached to the release artifacts.
- Scripts: `conformance:fetch`, `conformance:acvp`, `conformance:interop`, `sbom`.

### Notes
- **The pre-hash skips in the ACVP report are the library being stricter than
  NIST's sample files, not a coverage gap.** The backend refuses a pre-hash
  whose collision strength is below the parameter set's security category;
  NIST's vectors pair every approved hash with every parameter set. Those cases
  are counted as skipped, never as passed.
- **Hedged signing means wrapper signatures are not reproducible.** `sign` draws
  fresh randomness per signature, which FIPS 204 permits and recommends, so the
  byte-equality check does not apply on the wrapper path. It is asserted on the
  backend path for the same parameter sets. This is reported rather than hidden.
- **Provenance:** a release published from a workstation instead of through
  `publish.yml` carries no npm attestation. The Trusted Publishing binding still
  names the old `JackKXCO` org after the move to `KnightsbridgeAIQ` and needs
  repointing before the OIDC path can work. See the comment in `publish.yml`.

## 1.3.0

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