# Audit Posture

**Status as of v1.4.0 release (2026-08-18).** Self-attested. No third-party audit of this wrapper library has been performed yet. This document exists to make our posture **legible to reviewers** so the right questions get asked of the right party.

If you are doing institutional due diligence, read this end-to-end before the README.

> **Correction (v1.1.2):** earlier releases (1.0.1 – 1.1.1) of this file cited a 2024 Cure53 audit of `@noble/post-quantum`. **That citation was wrong.** Cure53's 2023 NDS-01 audit covered `@noble/ciphers`, `@noble/curves`, and `@noble/hashes` — **not** `@noble/post-quantum`. As of 2026-05-22, `@noble/post-quantum` has only been self-audited by its maintainer (v0.6.1, April 2026). No third-party audit of the post-quantum package exists. Section 1 has been rewritten accordingly. No code path changed; this is a documentation correction only.

---

## 1. Upstream audit posture

**`@noble/post-quantum@0.7.0`**, the underlying NIST primitives we wrap, has **not** been independently audited by a third party.

> **Correction (v1.4.0):** this section previously stated that we pin `0.6.1`, "the exact version covered by the maintainer's own self-audit." That is no longer true and the claim has been withdrawn. Since v1.3.0 we ship **`0.7.0`**, published 2026-08-09. The maintainer's self-audit covers **`0.6.1`**. **The version we ship is not covered by any audit, self- or third-party.** We ship it anyway because 0.7.0 reproduces all 39 pinned vectors bit-for-bit and cross-verifies against 0.6.1 in both directions, but that is our own regression evidence, not an audit. Stated here as the conservative bound.

| Review | Year | Scope | Source |
|---|---|---|---|
| Maintainer self-audit (`@noble/post-quantum` v0.6.1) | April 2026 | Full library | https://github.com/paulmillr/noble-post-quantum#security |

The wider `@noble/*` ecosystem has been audited by Cure53 (NDS-01, 2023), but that engagement covered `@noble/ciphers`, `@noble/curves`, and `@noble/hashes` — not the post-quantum package.

The primitives themselves are reference implementations of NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA), with test vectors matching NIST's published reference outputs. Reviewers wanting a fully third-party-audited PQ primitive layer should evaluate whether this posture meets their requirements before adopting in production.

When you `npm install kxco-post-quantum`, the upstream `@noble/post-quantum` code is what runs the math. This wrapper does not reimplement the primitives.

The exact upstream we pin:

```
@noble/post-quantum@0.7.0
integrity: sha512-IH2tpuGV4vBMdpCCua2BN7EuUICtmGp6DlBMNBYAYcL6QQ7eHt85GjLyD7ZT6Qx/xgIPIMqsSLDGvYqOm8Vqag==
```

## 2. What has NOT been audited (this wrapper)

The integration patterns in this package — `pqSigner` derivation, kid fingerprinting, webhook envelope construction, hybrid HMAC + ML-DSA signing, timestamp replay enforcement — have not been independently audited.

What we have done:

- **Internal review** by the KXCO engineering team and KXCO Cybersecurity (lead: Sean O'Coiligh, 30+ years cybersecurity, formerly led Offensive Cyber at the DTCC Cyber Threat Fusion Center)
- **Reproducible test vectors** in `test/vectors.json` covering every primitive — anyone running `npm test` gets the same outputs the maintainers see
- **Production deployment** across the KXCO platform (KnightsVault, KXCO Bank, KnightsBot, The Exchequer, Armature L1) since November 2025
- **Public verifiable proof** of the signing identity **on Armature L1**, not on a KXCO web endpoint. A published signature is anchored on chain and can be read back over public JSON-RPC by anyone, with no KXCO account, endpoint or cooperation in the path. Worked example in section 4.

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
git clone https://github.com/KnightsbridgeAIQ/kxco-post-quantum
npm install

# Run the full test suite — primitives + vectors
npm test

# Run vector verification only
npm run test:vectors

# Read a production signature back off Armature L1 over public JSON-RPC
curl -s -X POST https://chain.kxco.ai/rpc -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_getTransactionByHash","params":["0xbb7c7cc5fca921e151b457ad18a5b9c4f2c562e70b7c2afb66e23fbd826563c1"]}'
```

That transaction is on chainId **1111111**, block **90633**. Its 164-byte
calldata is a plain ABI-encoded call and decodes with no tooling of ours:

| Bytes | Field | Value |
|---|---|---|
| 0-3 | selector | `0xeabb11c8` |
| 4-35 | `bytes8` kid, left aligned | `6b8e4750027cfe89` |
| 36-67 | `bytes32` envelope digest | `8935e56a9a45a7c044c84ae3e3973356fedf842b4c97d1b7c47ddfe2e7bb4db4` |
| 68- | `string` event type | `article-published` |

Now fetch the other half of the join, which is a page we do not control the
chain from:

```bash
curl -s https://www.livetradingnews.com/kxco-native-post-quantum-cryptography-for-the-ai-and-blockchain-era   | grep -oE '"name":"(content|chain)-[a-z-]*","value":"[^"]*"'
```

That page declares `content-signature-algorithm` ML-DSA-65,
`content-signature-kid` `6b8e4750027cfe89`, `content-envelope-digest`
`8935e56a...4db4`, `chain-block` 90633 and the same `chain-tx-hash` you just
queried: **the same kid and the same digest that the chain returns above**.

The page claims, the chain confirms, and the two were written by different
systems at different times. Neither can be edited to agree with the other after
the fact. Any published article works; this is simply one we have quoted the
values for.

Expected: `npm test` reports `✓ All 39 checks pass — library output matches pinned vectors bit-for-bit.`

## 5. Threat model summary

See [SECURITY.md](./SECURITY.md) for the full threat model. In short:

- **In scope:** quantum signature non-repudiation, quantum-safe KEM, webhook forgery resistance, replay rejection, body tamper detection, wrong-key rejection.
- **Out of scope:** master secret storage (use KMS/HSM), TLS termination (use OpenSSL 3.5+), receiving raw bodies byte-for-byte (use `express.raw` or equivalent), key rotation procedures (caller's responsibility).

## 6. Bug-finding signals

If you are evaluating this library, look at:

- **Test coverage:** 11 functional tests + 39 vector checks covering every export (plus 7 browser-mode smoke tests)
- **Code size:** small enough to review end-to-end in an afternoon, across 7 single-purpose modules
- **Dependency surface:** one runtime dependency (`@noble/post-quantum`), which is **not** independently audited (see section 1)
- **Determinism:** every output is reproducible from inputs — no hidden state, no globals beyond a lazy cache, no network
- **API stability:** v1.0 commits to the public surface listed in CHANGELOG.md

## 7. Reviewer checklist

For institutional reviewers, the smallest version of "did they actually do the work":

- [ ] `npm view kxco-post-quantum dist.signatures` returns a signed package
- [ ] `npm test` passes after fresh clone + install
- [ ] `npm run test:vectors` matches the pinned vectors
- [ ] The `eth_getTransactionByHash` call in section 4 returns that transaction from Armature L1
- [ ] Its calldata decodes to the kid and digest in the table above, at the stated byte offsets
- [ ] The article page's schema.org `content-signature-kid` and `content-envelope-digest` match those two values
- [ ] An outbound webhook from `chain.kxco.ai` verifies with `webhook.verifyDelivery` against the pinned kid

All seven are reproducible without any cooperation from KXCO. That's the standard we hold ourselves to.

---

**Contact:** john@knightsbridgelaw.com, for vulnerability reports and for due-diligence or review requests. One monitored mailbox, not a rota of aliases. Acknowledgement within 2 business days, triage decision within 5. Our coordinated vulnerability disclosure policy, including safe harbour for good-faith research and how we prioritise using SSVC, is published at <https://kxco.ai/security>.
