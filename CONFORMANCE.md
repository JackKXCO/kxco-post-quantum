# Conformance and interoperability evidence

Two claims, each with a harness in this repository that anyone can run:

1. **This package computes what FIPS 203, 204 and 205 say it should.** Evidenced
   against NIST's own ACVP test vectors.
2. **Independent implementations can consume what it produces, and it can
   consume theirs.** Evidenced against Bouncy Castle (Java) and
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

Every parameter set NIST publishes vectors for is exercised, not only the three
this package wraps in its own helpers.

| Vector set | Tests | Passed | Failed | Skipped |
|---|---:|---:|---:|---:|
| ML-KEM-keyGen (FIPS 203) | 75 | 75 | 0 | 0 |
| ML-KEM-encapDecap (FIPS 203) | 165 | 165 | 0 | 0 |
| ML-DSA-keyGen (FIPS 204) | 75 | 75 | 0 | 0 |
| ML-DSA-sigGen (FIPS 204) | 360 | 316 | 0 | 44 |
| ML-DSA-sigVer (FIPS 204) | 180 | 157 | 0 | 23 |
| SLH-DSA-keyGen (FIPS 205) | 120 | 120 | 0 | 0 |
| SLH-DSA-sigVer (FIPS 205) | 504 | 413 | 0 | 91 |

**SLH-DSA-sigGen (FIPS 205), 624 tests, is exercised by the harness but is not
in the table above.** Signing with the twelve SLH-DSA sets takes hours, so the
figure comes from the weekly full CI pass rather than from a hand-run local one.
Run it yourself with `node conformance/run-acvp.mjs --set SLH-DSA-sigGen-FIPS205`,
or subsample with `--max-per-group 3`. It is called out rather than omitted
because a table that quietly drops the expensive set would overstate coverage.

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
The full list with per-case reasons is in the generated report at
`conformance/results/acvp.json`.

---

## 2. Cross-implementation interoperability

Peers, both pinned in
[conformance/interop/peers-lock.json](conformance/interop/peers-lock.json):

| Peer | Implementation | Language | Covers |
|---|---|---|---|
| `bouncycastle` | `org.bouncycastle:bcprov-jdk18on:1.85.2`, SHA-256 pinned | Java | ML-DSA, ML-KEM, SLH-DSA |
| `python` | `dilithium-py==1.4.0`, `kyber-py==1.2.0` | Python | ML-DSA, ML-KEM |

Neither shares code with this package's backend. Bouncy Castle is a widely
deployed independent implementation; the Python pair are independent
spec-derived implementations.

**Result: 134 checks passed, 0 failed, 6 not applicable, across 20 rows.**

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

### The six not-applicable checks

`bytes` on the three `wrapper` rows, in each of two context modes. This package's
`sign` is hedged: it draws fresh randomness per signature, which FIPS 204 permits
and recommends, so its output is deliberately not reproducible. Byte equality is
asserted on the `backend` rows for the same parameter sets, so determinism is
still evidenced everywhere it is meaningful. Reasoning is in
[THREAT-MODEL.md](THREAT-MODEL.md).

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
- **No CNSA 2.0 assertion.** CNSA 2.0 names ML-KEM-1024 and ML-DSA-87. The
  primitives pass NIST's vectors for both, but the package's own helpers wrap
  ML-KEM-768, ML-DSA-65 and SLH-DSA-SHA2-192s, so no CNSA 2.0 claim is made.
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
