# Audit Posture

**Status as of v1.2.0 release (2026-07-22).** Self-attested. No third-party audit of this wrapper library has been performed yet. This document exists to make our posture **legible to reviewers** so the right questions get asked of the right party.

If you are doing institutional due diligence, read this end-to-end before the README.

> **Correction (v1.1.2):** earlier releases (1.0.1 – 1.1.1) of this file cited a 2024 Cure53 audit of `@noble/post-quantum`. **That citation was wrong.** Cure53's 2023 NDS-01 audit covered `@noble/ciphers`, `@noble/curves`, and `@noble/hashes` — **not** `@noble/post-quantum`. As of 2026-05-22, `@noble/post-quantum` has only been self-audited by its maintainer (v0.6.1, April 2026). No third-party audit of the post-quantum package exists. Section 1 has been rewritten accordingly. No code path changed; this is a documentation correction only.

---

## 1. Upstream audit posture

**`@noble/post-quantum@0.6.1`** — the underlying NIST primitives we wrap — has **not** been independently audited by a third party. As of v1.2.0 we pin `0.6.1`, which is the exact version covered by the maintainer's own self-audit (see table below).

| Review | Year | Scope | Source |
|---|---|---|---|
| Maintainer self-audit (`@noble/post-quantum` v0.6.1) | April 2026 | Full library | https://github.com/paulmillr/noble-post-quantum#security |

The wider `@noble/*` ecosystem has been audited by Cure53 (NDS-01, 2023), but that engagement covered `@noble/ciphers`, `@noble/curves`, and `@noble/hashes` — not the post-quantum package.

The primitives themselves are reference implementations of NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA), with test vectors matching NIST's published reference outputs. Reviewers wanting a fully third-party-audited PQ primitive layer should evaluate whether this posture meets their requirements before adopting in production.

When you `npm install kxco-post-quantum`, the upstream `@noble/post-quantum` code is what runs the math. This wrapper does not reimplement the primitives.

The exact upstream we pin:

```
@noble/post-quantum@0.6.1
integrity: sha512-+pormrDZwjRw05U8ADK4JpHejo87+gBd+muRBB/ozztH5yhDLMDF4jHQWN3NQQAsu1zBNPWTG0ZwVI0CR29H0A==
```

## 2. What has NOT been audited (this wrapper)

The integration patterns in this package — `pqSigner` derivation, kid fingerprinting, webhook envelope construction, hybrid HMAC + ML-DSA signing, timestamp replay enforcement — have not been independently audited.

What we have done:

- **Internal review** by the KXCO engineering team and KXCO Cybersecurity (lead: Sean O'Coiligh, 30+ years cybersecurity, formerly led Offensive Cyber at the DTCC Cyber Threat Fusion Center)
- **Reproducible test vectors** in `test/vectors.json` covering every primitive — anyone running `npm test` gets the same outputs the maintainers see
- **Production deployment** across the KXCO platform (KnightsVault, KXCO Bank, KnightsBot, The Exchequer, Armature L1) since November 2025
- **Public verifiable proof** of the signing identity at https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey — anyone can fetch the kid, install this library, and verify signatures from the production fleet

What we have **not** done:

- ❌ Engaged a third-party auditor for this wrapper
- ❌ Held a public security review window with bug bounty
- ❌ Obtained CMVP FIPS 140-3 module certification
- ❌ Submitted to ENISA / NCSC / BSI evaluation schemes

## 3. Audit roadmap

| Milestone | Target | Owner |
|---|---|---|
| Engage external auditor for wrapper integration patterns | Q3 2026 | KXCO Engineering |
| Public bug bounty programme | Q4 2026 | KXCO Security |
| Apply for FIPS 140-3 CMVP validation of a cryptographic module deployment using this library + an HSM | 2027 | KXCO Compliance |
| NIST PQC Workshop presentation (production lessons) | When workshop opens for 2026/27 | Shayne Heffernan + Sean O'Coiligh |

The exact dates depend on engineering and budget capacity. The order is committed.

## 4. Reproducibility checks (run these yourself)

You do not have to trust us. Run these to verify:

```bash
# Clone and install
git clone https://github.com/JackKXCO/kxco-post-quantum
npm install

# Run the full test suite — primitives + vectors
npm test

# Run vector verification only
npm run test:vectors

# Fetch the live production platform key and verify offline
curl https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey
```

Expected: `npm test` reports `✓ All 39 checks pass — library output matches pinned vectors bit-for-bit.`

## 5. Threat model summary

See [SECURITY.md](./SECURITY.md) for the full threat model. In short:

- **In scope:** quantum signature non-repudiation, quantum-safe KEM, webhook forgery resistance, replay rejection, body tamper detection, wrong-key rejection.
- **Out of scope:** master secret storage (use KMS/HSM), TLS termination (use OpenSSL 3.5+), receiving raw bodies byte-for-byte (use `express.raw` or equivalent), key rotation procedures (caller's responsibility).

## 6. Bug-finding signals

If you are evaluating this library, look at:

- **Test coverage:** 11 functional tests + 39 vector checks covering every export (plus 7 browser-mode smoke tests)
- **Code size:** small enough to review end-to-end in an afternoon, across 7 single-purpose modules
- **Dependency surface:** one runtime dependency (`@noble/post-quantum`), itself audited
- **Determinism:** every output is reproducible from inputs — no hidden state, no globals beyond a lazy cache, no network
- **API stability:** v1.0 commits to the public surface listed in CHANGELOG.md

## 7. Reviewer checklist

For institutional reviewers, the smallest version of "did they actually do the work":

- [ ] `npm view kxco-post-quantum dist.signatures` returns a signed package
- [ ] `npm test` passes after fresh clone + install
- [ ] `npm run test:vectors` matches the pinned vectors
- [ ] `curl https://chain.kxco.ai/wallet/api/.well-known/kxco-pq-pubkey` returns a valid ML-DSA-65 public key
- [ ] The kid (`kid` field above) matches `fingerprint()` of the returned `publicKey` field
- [ ] An outbound webhook from `chain.kxco.ai` verifies with `webhook.verifyDelivery` against the pinned kid

All six are reproducible without any cooperation from KXCO. That's the standard we hold ourselves to.

---

**Contact:** john@knightsbridgelaw.com, for vulnerability reports and for due-diligence or review requests. One monitored mailbox, not a rota of aliases. Acknowledgement within 2 business days, triage decision within 5. Our coordinated vulnerability disclosure policy, including safe harbour for good-faith research and how we prioritise using SSVC, is published at <https://kxco.ai/security>.
