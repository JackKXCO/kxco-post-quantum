# Dependency audit

Four production dependencies. No development dependencies. Every one of them
reviewed by a person, and every mechanical fact in that review re-checked by a
harness that fails when reality moves away from it.

```
npm run audit:deps
```

- Curated review: [audit/dependency-review.json](audit/dependency-review.json)
- Harness: [audit/run-audit.mjs](audit/run-audit.mjs)
- Report: `audit/results/dependencies.json`, published as a CI artefact

Current result: **26 checks passed, 0 failed, 0 skipped.**

---

## The tree

| Package | Version | Licence | Pinning | On the code path | Independently reviewed by |
|---|---|---|---|---|---|
| `@noble/post-quantum` | 0.7.0 | MIT | exact | yes | maintainer self-audit at 0.6.1, Apr 2026 |
| `@noble/hashes` | 2.3.0 | MIT | exact | yes | Cure53, Jan 2022 |
| `@noble/curves` | 2.3.0 | MIT | transitive | yes | Trail of Bits, Feb 2023; Kudelski Security, Sep 2023; Cure53, Sep 2024 |
| `@noble/ciphers` | 2.3.0 | MIT | transitive | no | Cure53, Sep 2024 |

One maintainer publishes all four, and all four carry a verified npm registry
signature and a verified SLSA provenance attestation, with nothing invalid and
nothing missing across the installed tree. Nothing in the tree runs code at
install time, and `npm audit` reports no advisory at any severity.

## Why each one is there

**`@noble/post-quantum`** supplies the FIPS 203, 204 and 205 primitives. This
package is the layer above: parameter-set selection, FIPS 204 context strings,
key derivation, fingerprinting, webhook signing and the OpenSSL backend. It does
not reimplement the arithmetic.

It is also the one package in the tree with no independent review, and that is
the reason [conformance/](CONFORMANCE.md) exists. Every parameter set is checked
against NIST's own ACVP vectors, cross-checked against liboqs, Bouncy Castle and
dilithium-py / kyber-py in both directions, and checked against certificates and
signed messages that OpenSSL 3.5 issued. The primitives are evidenced here rather
than accepted on the dependency's word, and that evidence is reproducible on any
machine.

The pin is exact and deliberately so. Version 0.7.1 regressed nine NIST SLH-DSA
verification vectors that 0.7.0 passes. It shipped in this package's 1.5.1, was
reverted in 1.5.2, is deprecated on npm and is blocked in dependabot. A caret
range would have taken that regression automatically, which is why the harness
fails the build on any range in `dependencies`.

**`@noble/hashes`** supplies SHA-256, SHA-512, SHAKE-256 and HKDF, for key
derivation from a master secret, public-key fingerprinting and the hashing FIPS
205 requires. It is declared directly rather than inherited, so the version in
use is visible in this package's own manifest instead of resolved out of a
transitive range. The 2022 Cure53 scope covered everything except `blake3`,
`sha3-addons`, `sha1` and `argon2`; none of those four are used here.

**`@noble/curves`** is not named anywhere in this package's source. It arrives
through `@noble/post-quantum`, and it is on the hot path: `ml-dsa.js` takes
`abool` from `@noble/curves/utils.js`, and `_crystals.js`, which both ML-DSA and
ML-KEM are built on, takes `FFTCore` and `reverseBits` from
`@noble/curves/abstract/fft.js`. So every signature and every encapsulation this
package performs runs through it.

That was established by the reachability walk, not by reading manifests. It is
also the most heavily reviewed package in the tree: three independent firms
across four years.

**`@noble/ciphers`** arrives the same way and is the one package in the tree that
nothing here reaches. It is present in `node_modules` and absent from every code
path from every published entry point.

## What the harness checks

The review is a human document. The harness re-derives each of its mechanical
claims from the lockfile, the registry and the installed tree, and exits non-zero
on any disagreement:

| Check | Source of truth |
|---|---|
| every dependency in the tree appears in the review | `package-lock.json` |
| the review names nothing that has left the tree | `package-lock.json` |
| the tree is within the declared ceiling of four | `package-lock.json` |
| every direct dependency is pinned to an exact version | `package.json` |
| no development dependencies | `package.json` |
| each package is at the reviewed version | `package-lock.json` |
| each licence is on the allowed list | `package-lock.json` |
| no package declares an install script | lockfile flag and every installed manifest |
| reachability matches the review, in both directions | static import walk |
| no known advisories | `npm audit` |
| no invalid registry signature or attestation anywhere | `npm audit signatures --json` |
| no missing registry signature or attestation anywhere | `npm audit signatures --json` |

The reachability check is bidirectional, and that matters. A package the review
calls unused becoming reachable fails the build, and so does a package the review
calls used becoming unreachable. The first version of the review recorded
`@noble/curves` as unused; the harness rejected it, and the entry above is what
replaced it.

Adding or bumping a dependency fails this harness until somebody updates the
review. That is the mechanism by which the document stays true, rather than being
accurate on the day it was written.

## How reachability is derived

A breadth-first walk from all nine entry points in the `exports` map, reading
every import, export-from, dynamic `import()` and `require()` specifier out of
the source and resolving each with `import.meta.resolve` from the importing file.
Using Node's own resolver means subpath exports, export maps and the `#native`
conditional import resolve the way Node resolves them at run time.

Both branches of `#native` are walked, because the Node backend and the browser
stub both live in `src/`. The reported set is therefore the union of the Node and
browser paths, which can only over-report what is reachable. Current figures: 33
files walked, three packages reached, and one Node builtin, `node:crypto`, used
by the OpenSSL backend.

## Supply-chain posture in one paragraph

Four packages, one publisher, all MIT, all exactly locked by integrity hash, all
carrying registry signatures and SLSA provenance with nothing invalid or missing,
none able to execute at install time, none carrying an advisory, three of four independently reviewed by named
firms, and the fourth evidenced directly against NIST's vectors and three
independent implementations in this repository. The whole tree is small enough
that "all dependencies audited" is a statement someone can check in an afternoon,
which is the only reason it is worth making.

---

## Correcting this document

Every figure comes from `npm run audit:deps`. If one does not reproduce on your
machine, that is a defect worth reporting through [SECURITY.md](SECURITY.md);
include the generated `audit/results/dependencies.json` from your run.
