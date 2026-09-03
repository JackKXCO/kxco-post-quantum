# Licensing: what is free, what is paid

Two different things share the KXCO name, and confusing them wastes everyone's time. This document draws the line.

---

## Free, and permanently so: the maths

Apache-2.0. Use it commercially, fork it, ship it inside a product, never speak to us.

| Package | What it does |
|---|---|
| [`kxco-post-quantum`](https://www.npmjs.com/package/kxco-post-quantum) | ML-DSA-65, ML-KEM-768, SLH-DSA, seed-form keys, compact JWS, deterministic derivation, kid fingerprints |
| [`kxco-verify`](https://www.npmjs.com/package/kxco-verify) | Verify a site's deploy attestation, in a terminal or a browser |

These are **chain-agnostic**. There is no chain id, no relay URL and no licence check anywhere in their source. They do not phone home. Signing and verification work with the network unplugged and keep working if KXCO stops existing, which is the only sense in which a signature is worth anything ten years from now.

The other Apache-2.0 packages — `kxco-pq-attest`, `kxco-pq-audit`, `kxco-pq-hsm`, `kxco-pq-tls`, `kxco-pq-vault`, `kxco-post-quantum-webhook`, `kxco-pq-sdk`, `kxco-pq-agent`, `kxco-pq-chain`, `kxco-pq-network` — are also Apache-2.0 source. **The licence covers the code, not the service.** Reading and modifying the source is free. Calling the KXCO-operated registry and relay is not.

---

## Paid: the service

What you buy is not cryptography. Cryptography is free, and we could not charge for it honestly if we wanted to.

What you buy is **an answer about the present**.

A signature made by a key that was revoked an hour ago is still a perfectly valid signature. No amount of offline mathematics can tell you it was revoked. Only something that knows what happened after the signature was made can, and that something has to be operated, kept available, and answerable when it is wrong.

| Paid | Why it cannot be free |
|---|---|
| **Hosted key registry** (`chain.kxco.ai/kids/:kid`) | Answers whether a key is active, revoked or rotated. Someone has to run it and stand behind the answer |
| **Meta-transaction relay** (`relay.kxco.ai`) | KXCO validates your signed intent, **pays the gas in ARMR**, and submits the transaction. You never hold a token or run a node |
| **On-chain anchoring** | Writes to Armature L1, chain 1111111 |
| **Live revocation** (`anchored+live`) | The registry lookup at verification time |
| **Support and SLA** | Availability commitments, an escalation path, a name to call |

Priced **in USD, per seat**. You do not need to hold ARMR, run a node, configure an RPC endpoint or touch a wallet. If a vendor tells you post-quantum identity requires you to buy a token, that is a different product from this one.

See [`SALES-SKU.md`](https://github.com/KnightsbridgeAIQ/kxco-pq-network/blob/main/SALES-SKU.md) in `kxco-pq-network` for the seat definitions.

---

## Which mode you are in

| Mode | Network at verify time | Licence | What it proves |
|---|---|---|---|
| `signature` | none | no | The holder of this key signed this |
| `anchored` | none | no | …and it was written to Armature L1 |
| `anchored+live` | yes, fails closed | **yes** | …and that key is still trusted **now** |

`signature` and `anchored` will not start requiring a licence. Envelopes issued today verify in those modes forever, with no KXCO server in the path. That is a commitment about the format, not a pricing tier that may move.

Writes to the hosted relay require a licence, and always did in substance — this is now enforced in the client rather than only at the server, so a misconfigured service fails at boot instead of at a customer's first transaction.

---

## Trademark

The name **KXCO** and the mark **"KXCO Verified"** are not covered by the Apache-2.0 licence.

You may fork the code, ship it, and say so. You may not describe your deployment as "KXCO Verified", or use the mark on a badge, a certificate, a report or a sales page, without a written agreement with us. The mark is meant to tell a reader that KXCO stands behind a specific claim, and it is worthless the moment anyone can apply it to themselves.

Describing your product as "built on kxco-post-quantum" is fine and accurate. Describing it as "KXCO Verified" is not, unless it is.

---

## What has not been assessed

**No third party has assessed this code.**

There has been no external cryptographic audit of this wrapper, and none of `@noble/post-quantum`, the JavaScript backend, which has been self-audited by its maintainer only (v0.6.1, April 2026).

The other Noble packages **have** been audited, but separately and at different dates, and none of those engagements reached the post-quantum package: `@noble/hashes` by Cure53 in January 2022, `@noble/curves` by Trail of Bits in February 2023, Kudelski Security in September 2023 and Cure53 in September 2024, and `@noble/ciphers` by Cure53 in September 2024. These dates come from `audit/dependency-review.json`, which is generated rather than written by hand.

We do not claim FIPS 140-3 validation, CNSA 2.0 compliance, or that anything here is "quantum-proof". The algorithms are NIST-standardised; the module is not validated, and those are different statements.

**What exists instead is evidence you can re-run.** Every parameter set is checked against NIST's own ACVP vectors and cross-checked against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py in both directions. `node scripts/build-evidence.mjs --full` produces the bundle, and every figure in it came from a command you can run yourself on the same commit.

**A customer may re-run the published vectors, at any time, without asking us and without telling us.** If your result differs from ours, that is a finding and we want it: `john@knightsbridgelaw.com`, acknowledged within 2 business days.

This section is not marketing modesty. If you need an independent assessment before deploying, you do not have one yet, and you should plan for that rather than around it.

---

## Support

Commercial terms, seat pricing and SLA: **hello@kxco.ai**
Security and vulnerability reports: **john@knightsbridgelaw.com**, or a private advisory on the relevant repository. Full policy, including safe harbour for good-faith research: <https://kxco.ai/security>
