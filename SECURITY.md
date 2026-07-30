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

## Disclosure
We follow coordinated disclosure with a 90-day default window.
For actively-exploited issues we ship a patch release within 48 hours.
