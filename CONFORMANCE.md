# Conformance and interoperability evidence

Two claims, each with a harness in this repository that anyone can run:

1. **This package computes what FIPS 203, 204 and 205 say it should.** Evidenced
   against NIST's own ACVP test vectors.
2. **Independent implementations can consume what it produces, and it can
   consume theirs.** Evidenced against liboqs (C), Bouncy Castle (Java) and
   dilithium-py / kyber-py (Python), in both directions.

The second claim is the one that matters in deployment and the one that vector
files cannot make. Passing NIST's vectors proves agreement with NIST. It does
not prove that a counterparty running a different stack can verify your
signature.

Everything below is reproducible:

```
npm run conformance:fetch      # pinned NIST vectors, digest-checked
npm run conformance:acvp       # claim 1
npm run conformance:interop    # claim 2
```

Both harnesses run in CI on every push and in full weekly. See
[.github/workflows/conformance.yml](.github/workflows/conformance.yml).

---

## 1. NIST ACVP vectors

Source: [`usnistgov/ACVP-Server`](https://github.com/usnistgov/ACVP-Server) at
commit `975de31eb83d87039ec88934fdc47d8c312b892d`, pinned with per-file SHA-256
digests in [conformance/acvp-lock.json](conformance/acvp-lock.json). A rewritten
upstream file fails the fetch rather than silently changing the result.

Every parameter set NIST publishes vectors for is exercised, not only the five
this package wraps in its own helpers.

| Vector set | Tests | Passed | Failed | Skipped |
|---|---:|---:|---:|---:|
| ML-KEM-keyGen (FIPS 203) | 75 | 75 | 0 | 0 |
| ML-KEM-encapDecap (FIPS 203) | 165 | 165 | 0 | 0 |
| ML-DSA-keyGen (FIPS 204) | 75 | 75 | 0 | 0 |
| ML-DSA-sigGen (FIPS 204) | 360 | 316 | 0 | 44 |
| ML-DSA-sigVer (FIPS 204) | 180 | 157 | 0 | 23 |
| SLH-DSA-keyGen (FIPS 205) | 120 | 120 | 0 | 0 |
| SLH-DSA-sigGen (FIPS 205) | 624 | 472 | 0 | 152 |
| SLH-DSA-sigVer (FIPS 205) | 504 | 413 | 0 | 91 |
| **Total** | **2103** | **1793** | **0** | **310** |

A full pass takes hours, almost all of it SLH-DSA signing with the slow
parameter sets. CI subsamples per push with `--max-per-group` and runs the full
suite weekly; the generated report records which of the two it was, so a
subsampled run is never mistaken for a full one. To reproduce one expensive set
on its own: `node conformance/run-acvp.mjs --set SLH-DSA-sigGen-FIPS205`. The
generated report for that full run is committed at
[conformance/results/acvp-slh-dsa-siggen.json](conformance/results/acvp-slh-dsa-siggen.json),
with each skip and its reason.

Parameter sets covered: ML-KEM-512/768/1024, ML-DSA-44/65/87, and all twelve
SLH-DSA sets (SHA2 and SHAKE, 128/192/256, f and s).

The signature sets cover every interface variant in NIST's vectors: the external
and internal interfaces, pure and pre-hashed (HashML-DSA / HashSLH-DSA),
external-mu, deterministic and randomized signing, empty and non-empty context
strings. Deterministic groups reproduce NIST's expected signature bytes exactly;
randomized groups reproduce them from the `rnd` / `additionalRandomness` value
the vector supplies.

**Zero failures. The skips are all one thing, and it is not a gap in coverage.**

Every skipped case is a pre-hash pairing the backend refuses because the hash's
collision strength falls below the parameter set's security category, for example
SHA2-256 with ML-DSA-87 (128 bits offered against 256 required), or SHAKE-128
with ML-DSA-65 (128 against 192). NIST's sample files pair every approved hash
with every parameter set, including those combinations. The backend rejects them
rather than signing.

This is the library being stricter than the vector file, and it is counted
separately rather than folded into a pass total, because a skip is not a pass.
Every skip is listed with its reason in the generated reports, which CI writes as
`conformance/results/acvp-fast.json` and
`conformance/results/acvp-slh-signatures.json`. The SLH-DSA signature sets run as
their own job because a full pass of them takes over an hour, so a single
combined job would time out.

---

## 2. Cross-implementation interoperability

Peers, both pinned in
[conformance/interop/peers-lock.json](conformance/interop/peers-lock.json):

| Peer | Implementation | Language | Covers |
|---|---|---|---|
| `liboqs` | `liboqs` 0.16.0 with binding 0.16.0, built from source | C | ML-DSA, ML-KEM, SLH-DSA |
| `bouncycastle` | `org.bouncycastle:bcprov-jdk18on:1.85.2`, SHA-256 pinned | Java | ML-DSA, ML-KEM, SLH-DSA |
| `python` | `dilithium-py==1.4.0`, `kyber-py==1.2.0` | Python | ML-DSA, ML-KEM |

SLH-DSA is covered by liboqs and Bouncy Castle, not by the Python pair, because
no maintained pure-Python implementation was available to pin. That is a
narrower base than the other two families and is stated rather than averaged
away.

None of the three shares code with this package's backend. liboqs is the
reference C implementation the wider ecosystem tests against; Bouncy Castle is a
widely deployed independent implementation; the Python pair are independent
spec-derived implementations.

liboqs needs a C toolchain, so its peer runs in a container built from
[conformance/interop/peers/liboqs.Dockerfile](conformance/interop/peers/liboqs.Dockerfile)
rather than requiring every contributor to install one. If the image is absent
the peer reports unavailable, which is not a failure but is also not evidence.

**Result: 225 checks passed, 0 failed, 42 not applicable, across 38 rows.**

Per row, in both directions:

| Check | What it establishes |
|---|---|
| `keys` | The same seed derives the same public key bytes in both stacks, independently |
| `ours>theirs` | We sign, the peer verifies |
| `theirs>ours` | The peer signs, we verify |
| `bytes` | Deterministic signing produces byte-identical output in both stacks |
| `tamper` | One flipped bit in our signature, and the peer rejects it |
| `reject` | A corrupted ML-KEM ciphertext yields an unrelated secret, not the real one |

The `tamper` and `reject` rows are negative controls and they are the reason to
trust the positive ones. Without them, a peer whose verify function returned
`true` unconditionally would pass every other check in the matrix.

Test material is derived from published labels rather than shipped as opaque
fixtures, so a third party can recompute the seeds and rerun the matrix without
trusting anything in this repository. See `fixtureSeed` in
[conformance/interop/run-interop.mjs](conformance/interop/run-interop.mjs).

Each parameter set this package publishes a helper for is run twice: once
through that helper (`wrapper`) and once through the primitive (`backend`), so
the evidence covers the published API and not only its dependency.

### The forty-two not-applicable checks

A check is recorded as not applicable when a peer says it cannot do something,
never when a peer disagrees with us. A peer that cannot honour a request answers
`unsupported` and the matrix records N/A; any other error is a failure and is
counted as one.

**Ten from hedged signing.** This package's `sign` is hedged: it draws fresh
randomness per signature, which FIPS 204 permits and recommends, so its output is
deliberately not reproducible. Byte equality is asserted on the `backend` rows
for the same parameter sets, so determinism is still evidenced everywhere it is
meaningful. Reasoning is in [THREAT-MODEL.md](THREAT-MODEL.md).

They are the `bytes` check on each signature `wrapper` row, in each of two
context modes: three such rows against Bouncy Castle (ML-DSA-65, ML-DSA-87,
SLH-DSA-SHA2-192s) and two against the Python pair, which has no SLH-DSA. The
KEM wrapper rows carry no `bytes` check, because a KEM produces a fresh
ciphertext by design and byte equality is not defined for it.

**Thirty-two from two liboqs API limits**, both properties of that library
rather than of this one:

- `keys` on all fourteen liboqs rows. liboqs exposes no seed-derived keygen, so
  it cannot rebuild a key from a FIPS 203 / FIPS 204 seed the way the other
  peers do. It is addressed by encoded secret key instead, which still tests
  something real: the private key encodings are themselves standardised, so a
  key of ours that failed to load into liboqs and produce interoperable output
  would be a genuine defect.
- `bytes` on all eighteen liboqs signature checks. liboqs signs hedged and
  exposes no deterministic mode through its Python binding, so byte equality
  against it is not defined. Bouncy Castle and the Python pair both cover it.

Everything else is exercised against liboqs, in both directions, including FIPS
204 context strings and both negative controls.

---

## What this evidence does not cover

Stated plainly, because a conformance report that only lists what passed is
marketing.

- **No side-channel claim.** Nothing here measures timing, cache or power
  behaviour, and this package makes no constant-time claim. See
  [THREAT-MODEL.md](THREAT-MODEL.md).
- **No FIPS 140-3 validation.** This is algorithm-level conformance against
  NIST's vectors, run by us. It is not CAVP or CMVP validation, and it is not
  equivalent to either. No certificate number is claimed because none exists.
- **No CNSA 2.0 assertion.** CNSA 2.0 names ML-KEM-1024 and ML-DSA-87. This
  package supports both: they pass NIST's vectors above, they interoperate in
  the matrix above, and `mlDsa87` and `mlKem1024` are published helpers. That is
  a support claim, not a compliance claim, and the distinction is not
  decorative. CNSA 2.0 compliance is a property of a deployment, not of an
  available function. The KXCO estate signs at Category 3 with ML-DSA-65,
  including Armature L1 from block 0 and every issued KXCO ID, none of which
  these modules change. The accurate sentences are "NIST FIPS 203/204/205
  conformant" and "supports ML-DSA-87 and ML-KEM-1024". Anything stronger,
  including "CNSA 2.0 ready", would be an overclaim.
- **Protocol-level interop is not covered here.** Key and signature bytes
  interoperate. Certificate and message encodings, X.509, CMS, COSE, JOSE and
  TLS group negotiation are separate surfaces and no claim is made about them.
- **Self-administered.** Every number above was produced by harnesses in this
  repository, run by us. That is why they are reproducible and why the pins,
  digests and negative controls are there. It is not third-party attestation and
  should not be read as any.

## Correcting this document

If any figure here does not reproduce on your machine, that is a defect worth
reporting through [SECURITY.md](SECURITY.md). Include the generated
`conformance/results/*.json` from your run.
