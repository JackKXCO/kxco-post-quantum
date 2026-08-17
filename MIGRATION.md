# Migration guide

How to move an existing system onto post-quantum signatures and key
establishment with this package, and how to move between versions of it.

Two separate problems, in order:

1. [Choosing a parameter set](#choosing-a-parameter-set)
2. [Migrating a classical system](#migrating-a-classical-system) — RSA or ECDSA today
3. [Migrating between versions](#migrating-between-versions) of this package

---

## Choosing a parameter set

| You need | Use | Why |
|---|---|---|
| Signatures, general use | `mlDsa` (ML-DSA-65) | Category 3. Fast, 3309-byte signatures. The default. |
| Signatures, Category 5 required | `mlDsa87` (ML-DSA-87) | When a counterparty specifies Category 5 or names ML-DSA-87. Signatures are 4627 bytes. |
| Signatures, no lattice assumption | `slhDsa` (SLH-DSA-SHA2-192s) | Hash-based, so it does not share ML-DSA's underlying assumption. Signatures are 16 KB and signing takes seconds. |
| Key establishment | `mlKem` (ML-KEM-768) | Category 3, matching ML-DSA-65. |
| Key establishment, Category 5 required | `mlKem1024` (ML-KEM-1024) | Public key and ciphertext are 1568 bytes each. The shared secret stays 32 bytes. |

**On CNSA 2.0.** It names ML-DSA-87 and ML-KEM-1024, and both are available
here. Availability is not compliance: CNSA 2.0 compliance is a property of a
deployment, and picking `mlDsa87` for one call path does not confer it on a
system whose other signatures, identities and anchors are Category 3. Use the
Category 5 sets when someone asks for the parameter set. Do not use their
presence as the basis for a compliance statement.

Two points that catch people out:

**Sizes are the migration cost, not speed.** An ML-DSA-65 signature is 3309
bytes against 64 for Ed25519, roughly 50 times larger. Anything with a size
limit on the signature field needs looking at before anything else: database
columns, cookie and header size limits, QR codes, embedded firmware slots,
protocol frames with a fixed-width length. Signing and verification are fast
enough that throughput is rarely the blocker.

**SLH-DSA is slow enough to change designs.** Signing with a `...s` (small)
parameter set takes on the order of seconds. It suits infrequent, high-value
signatures such as firmware releases or root attestations. It does not suit
per-request signing. The `...f` (fast) sets trade signature size for speed.

---

## Migrating a classical system

### Do not swap. Add, then remove.

The failure mode is replacing RSA or ECDSA with ML-DSA in one release, then
finding that data signed before the switch no longer verifies, or that a peer
you do not control has not migrated. Run both, then retire the old one.

**Stage 1: verify both, sign classically.** Deploy verification for ML-DSA
alongside your existing scheme. Nothing signs with it yet. This is the cheap
stage and it proves your storage and transport handle the larger signatures
before anything depends on them.

**Stage 2: sign both.** Attach both signatures. Consumers verify whichever they
support. Both must be bound to the same message, and a consumer that verifies
only one must not be able to be tricked into treating a valid classical
signature as covering a message the PQ signature does not, so sign identical
bytes with both.

**Stage 3: require both.** Verification fails unless both are present and valid.
This is the point at which you have post-quantum security and have not yet lost
compatibility. It is a good place to stay for a long time.

**Stage 4: drop the classical signature.** Only once every producer and consumer
is on stage 3, and only once you no longer need to verify anything signed before
stage 2.

For key establishment the same shape applies, and the hybrid step is not
optional in the same way: combine the ML-KEM shared secret with a classical
ECDH secret through a KDF so the session is secure if *either* holds. Do not
use a raw ML-KEM shared secret as a key. Run it through HKDF with a context
label, which is what `deriveSeed` is for.

### Store what you will need later

Migrations stall on missing metadata, not on cryptography. From stage 1, record
alongside every signature:

- **Which algorithm and parameter set** produced it. Do not infer it from
  signature length; ML-DSA-65 and some SLH-DSA sets are distinguishable by
  length today but that is not a property to depend on.
- **Which key** produced it. The KXCO ID from `kid` identifies a public key
  compactly and is safe to publish.
- **The context string**, if any. A signature made under a context does not
  verify without it, so a lost context is a lost signature.

Adding these fields later means backfilling them for data you can no longer
attribute.

### Test the negative cases

The interop matrix in this repository tests that a tampered signature is
rejected, for the reason that a verifier which returns true unconditionally
passes every positive test. Your integration deserves the same check: assert
that a flipped bit fails, that a signature under the wrong context fails, and
that a signature from the wrong key fails. Do this before stage 3, not after.

---

## Migrating between versions

The `CHANGELOG.md` is authoritative. The notes below cover the changes that
require action rather than a version bump.

### 1.2.x to 1.3.0

**The FIPS 204 / FIPS 205 context parameter arrived.** `sign` and `verify` take
an optional `{ context }`. Existing calls that pass no context are unaffected:
no context means the empty context, which is what earlier versions produced.

A context is part of the signature. Adding one to a signing call invalidates
verification by any caller that does not pass the same context, so roll context
adoption out to verifiers first, exactly as in stage 1 above.

**The backend moved to `@noble/post-quantum` 0.7.0**, exact-pinned. If your
project also depends on `@noble/post-quantum` directly, align it. Two copies of
a cryptographic backend in one dependency tree is a hazard worth removing, and
`falcon.js` and `hybrid.js` from that release are not part of what this package
tests or supports.

### Upgrading across any version

1. Read `CHANGELOG.md` for the versions you are skipping, not just the target.
2. Run your own negative tests, above, against the new version.
3. Verify a signature produced by the old version with the new one, and the
   reverse. This is the check that catches an encoding change.

---

## Verifying what you deploy

Release integrity is covered in [SECURITY.md](SECURITY.md); conformance evidence,
including the cross-implementation matrix, is in
[CONFORMANCE.md](CONFORMANCE.md). Before putting a key in production, read
[THREAT-MODEL.md](THREAT-MODEL.md), specifically the section on where the
residual risk sits. It will tell you whether the key should be in this library
at all or in an HSM.
