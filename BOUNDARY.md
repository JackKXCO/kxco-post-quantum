# Product boundary

Which cryptography this package performs, which it depends on, and which it
merely offers to a caller. The three are routinely collapsed into one claim,
and collapsing them is how "quantum-safe" gets asserted for a product whose own
update path is classical.

## What the assessed thing is

A library. It has no server, no console and no runtime service connections:
nothing in `src/` opens a socket. That is a narrow boundary and it makes most
of the questions below short, but the short answers are the point.

Record the configuration alongside any claim, because the answers differ by
runtime. `backend()` returns it: implementation, OpenSSL version, and the
parameter sets that implementation can express.

## Start and update

**Quantum-safe.** Every release asset is signed with ML-DSA-65 by this
package's own signing path, and the public key is committed to the repository
rather than served only beside the artefact. Verification is four lines and is
in [README.md](README.md#verifying-a-release). Releases also carry SLSA
provenance recording the workflow that built them, and npm provenance is on.

**The classical part, stated.** Fetching the release is TLS to the npm registry
or to GitHub, and that TLS is classical. So is the transport that delivered the
git clone. This is outside our control and it is a real residual: an attacker
who could break that transport today could serve a different artefact, and the
ML-DSA signature is what would catch it, provided the verifier has the key from
a second path. That proviso is why the key is in the repository and why the
README says to compare the two copies.

## Operate

**No required service connections.** The library performs no network operation
at any point. There is no licence check, no telemetry, no key server and no
call home. Nothing in the operating path can be a classical dependency, because
there is no operating path outside the caller's process.

**Key management is the caller's, with one supported escape.** Keys live in the
caller's memory unless the caller puts them somewhere better. `kxco-pq-hsm`
generates ML-DSA keys on a PKCS#11 token with `CKA_EXTRACTABLE=false`, at which
point this library handles verification only and touches no secret. The channel
to that token is the HSM vendor's, not ours, and its own post-quantum posture
is a question for the vendor.

**Storage and diagnostics.** Neither exists here. The package writes no files
and keeps no state between calls.

## Protect records

Not this package's role, and it does not pretend otherwise. Log integrity and
timestamping in the KXCO estate are `kxco-pq-audit`: SHA-256 hash-chained
entries, each ML-DSA-65 signed, with periodic seals anchored on Armature L1 so
a verifier who does not trust the log operator has an independent time bound.

What this package contributes to that is the signature primitive and nothing
else.

## Enforce policy

A prohibited fallback can be rejected. The package's default is to fall back
from OpenSSL to JavaScript, and that default is correct for almost everyone
because both produce identical wire bytes. It is wrong in one situation: a
deployment under a control requiring the cryptography to execute inside a
validated module, where a silent fallback means the control is not in force and
nothing says so.

`KXCO_PQ_REQUIRE_NATIVE=1`, or `requireNativeBackend([...])` in code, fails the
process at import instead. Note the limit of the assertion: it establishes that
OpenSSL is doing the maths, not that the OpenSSL it found is a validated
module. That is a property of the operator's build and this package cannot see
it.

## Retain history

**Verification of old records: yes.** A signature made by any version of this
package verifies under any later version. Wire formats have not changed and the
conformance evidence is regenerated against pinned vectors on every dependency
bump, which is what would catch a change that broke them.

**Long-term trust: not solved here, and it is not the same question.** This
package has no notion of key validity windows, revocation or trusted
timestamps, so it can tell you a signature is arithmetically valid and cannot
tell you the key was still trusted when it was made. Anything that has to hold
for years needs a time anchor outside the signature. In the KXCO estate that is
`kxco-pq-audit`'s on-chain seals. For a deployment outside it, that is a gap
the deployment has to close.

## Customer-selected outputs

The library will sign at whatever parameter set the caller selects, Category 1
included, and will verify Category 1 signatures from a peer. That is a customer
output, not a statement about this package's own operation, and the two should
not be reported as one number.

The KXCO estate itself signs at Category 3 with ML-DSA-65, including Armature
L1 from block 0 and every issued KXCO ID. Support for ML-DSA-87 and ML-KEM-1024
is a support claim and not a CNSA 2.0 compliance claim, for the reasons set out
in [CONFORMANCE.md](CONFORMANCE.md#what-this-evidence-does-not-cover).

## The gaps, collected

Repeated here so they are not spread across six sections:

1. Release transport is classical TLS, mitigated by an ML-DSA signature and a
   second copy of the key, not eliminated.
2. The PKCS#11 channel to an HSM is the vendor's, and outside our assessment.
3. No long-term validation: no timestamps, no validity windows, no revocation.
4. `requireNativeBackend` asserts OpenSSL, not a validated OpenSSL.
