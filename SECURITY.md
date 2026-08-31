# Security Policy

## Reporting a vulnerability
Email **john@knightsbridgelaw.com**. Do not open public issues for security reports.
PGP key available on request. We credit reporters in `CHANGELOG.md` unless they
request otherwise.

Acknowledgement within **2 business days**. Triage decision within **5 business days**.

Full policy: <https://kxco.ai/security>

## Safe harbour
If you make a good-faith effort to comply with this policy, we will treat your
research as authorised, and we will not pursue or support legal action against
you. Good faith means: do not access, modify, exfiltrate, or destroy data that
is not yours; use test accounts where possible; do not degrade service for
others; and stop and report as soon as you have established that a
vulnerability exists. This cannot bind third parties, and it does not cover
extortion, data sale, or public disclosure ahead of the window below.

## Scope
In scope:
- Cryptographic correctness of the wrappers in this package
- Constant-time guarantees on signature/HMAC comparison
- Replay-window enforcement in `webhook.verify`
- HKDF domain separation in `derive`
- Kid fingerprint collision behaviour

Out of scope (report upstream to https://github.com/paulmillr/noble-post-quantum):
- Bugs in the underlying ML-DSA-65, ML-KEM-768, SLH-DSA-SHA2-192s, or HKDF primitives

## Algorithms used
- ML-DSA-65 — NIST FIPS 204 (lattice signatures)
- ML-KEM-768 — NIST FIPS 203 (key encapsulation)
- SLH-DSA-SHA2-192s — NIST FIPS 205 (hash-based signatures)
- HMAC-SHA-256
- HKDF-SHA-512 (RFC 5869)

## Dependency policy
Both runtime dependencies are pinned to an exact version, never a range:
`@noble/post-quantum` and `@noble/hashes`. A range would let the code that runs
the cryptography change without a release of this package, which is not a
property we are willing to give up for convenience. Every GitHub Action in our
workflows is pinned by 40-character commit SHA for the same reason.

Updates are proposed, never automatic. Dependabot opens pull requests weekly for
both npm and GitHub Actions, and Dependabot security updates are enabled at the
repository level so an advisory does not wait for the Monday run. The
configuration is in [.github/dependabot.yml](.github/dependabot.yml).

A dependency bump is not merged on the strength of a green test run alone. A
change to `@noble/post-quantum` is a change to the primitives themselves, so it
is gated on the full conformance evidence regenerating clean: the NIST ACVP
vectors and the cross-implementation interoperability matrix, both described in
[CONFORMANCE.md](CONFORMANCE.md).

Each release publishes a CycloneDX SBOM as a GitHub Release asset, at
`releases/download/<tag>/sbom.cyclonedx.json`, generated from the tree that was
actually installed for that build.

## Disclosure
We follow coordinated disclosure with a 90-day default window.
For actively-exploited issues we ship a patch release within 48 hours.
