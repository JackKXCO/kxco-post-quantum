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

### Why the chain is permissioned

Because the question a regulated institution has to answer is not "is this
decentralised" but **"who approved this, and can you prove it?"**

On Armature that has a name attached. Four known validators, screened and
contractually bound, in a jurisdiction, with a legal entity behind them. A
permissionless validator set cannot answer it — which is also why it cannot
satisfy a sanctions obligation, and why an institution's records end up sharing
permanent state with whatever else anyone chose to write.

A known counterparty is the product, not a compromise on one. See
[`ACCOUNTABILITY.md`](https://github.com/KnightsbridgeAIQ/kxco-chain-live/blob/main/docs/ACCOUNTABILITY.md).

---

## Trademark

The name **KXCO** and the mark **"KXCO Verified"** are not covered by the Apache-2.0 licence.

You may fork the code, ship it, and say so. You may not describe your deployment as "KXCO Verified", or use the mark on a badge, a certificate, a report or a sales page, without a written agreement with us. The mark is meant to tell a reader that KXCO stands behind a specific claim, and it is worthless the moment anyone can apply it to themselves.

Describing your product as "built on kxco-post-quantum" is fine and accurate. Describing it as "KXCO Verified" is not, unless it is.

---

## Assurance

The cryptography is NIST-standardised and the conformance is published, pinned and reproducible.

| | |
|---|---|
| Algorithms | ML-DSA-65 (FIPS 204), ML-KEM-768 (FIPS 203), SLH-DSA (FIPS 205) |
| Category 5 | **ML-DSA-87 and ML-KEM-1024 are shipped** — the parameter sets CNSA 2.0 specifies. Available today via `mlDsa87` / `mlKem1024`, ACVP-checked like every other set. Compliance is a property of a deployment, not of a library, so we state the capability and leave the claim to the deployment |
| Backend | OpenSSL 3.5 where the runtime provides it, `@noble/post-quantum` elsewhere. Identical on the wire, checked in both directions |
| Conformance | 2,103 NIST ACVP vectors across FIPS 203, 204 and 205. Vectors pinned by digest |
| Interoperability | 225 checks against OpenSSL 3.5, liboqs, Bouncy Castle and dilithium-py/kyber-py |
| Supply chain | SLSA provenance attestation on every release; CycloneDX SBOM; reproducible build |
| Evidence bundle | `npm run evidence` regenerates all of it from source, on your machine |
| On-chain verification | Armature L1 verifies ML-DSA-65 **in consensus** — `MLDSA65VerifyPrecompiledContract` at `0x0b`, executed by every validator, ~50,000 gas |
| Accountability | Four **named** validators under QBFT proof-of-authority. Every block has an identified proposer and every write an accountable operator |

**You do not have to take any of it on our word.** Every figure above comes from a command you can run yourself against the same commit, and the vectors are NIST's, not ours. A customer may re-run them at any time without asking us and without telling us. If your result differs from ours we want to know: `john@knightsbridgelaw.com`, acknowledged within 2 business days.

Dependency audit history — which upstream libraries were reviewed, by whom, and when — is recorded in [`AUDIT.md`](AUDIT.md), kept current by a generated dependency review rather than by hand.

---

## Support

Commercial terms, seat pricing and SLA: **hello@kxco.ai**
Security and vulnerability reports: **john@knightsbridgelaw.com**, or a private advisory on the relevant repository. Full policy, including safe harbour for good-faith research: <https://kxco.ai/security>
