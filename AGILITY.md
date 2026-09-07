# Cryptographic agility

What has to change, and what does not, when the algorithm changes.

"Crypto-agility" is used for three different things: a plan to replace an
algorithm, a mechanism that performs the replacement, and a transition that
peers can follow without breaking. They are not the same claim and this
document keeps them apart. Where the answer is "we do not have that", it says
so.

## 1. A replacement plan

[MIGRATION.md](MIGRATION.md) carries the plan, in four stages: verify both,
sign both, require both, drop the classical signature. The rule it exists to
enforce is *do not swap, add then remove*, because a one-release swap strands
everything signed before it and every peer you do not control.

The same shape covers a move between post-quantum parameter sets, with one
difference: there is no classical side to retire, so stage 4 is reached as soon
as every consumer verifies the new set.

For key establishment the plan is not optional in the same way. Combine the
ML-KEM shared secret with a classical secret through a KDF, so the session
holds if either does. `deriveSeed` is what that HKDF step is for.

## 2. An implemented mechanism

Three mechanisms exist in this package today.

**Parameter set selection.** Five sets are published helpers with their own
entry points: ML-DSA-65, ML-DSA-87, ML-KEM-768, ML-KEM-1024 and
SLH-DSA-SHA2-192s. Category 5 is not a future item; `mlDsa87` and `mlKem1024`
ship today. Changing set is an import change at the call site rather than a
redesign, because every set is reached through the same function shapes.

Be precise about the difference between those five and what the backend can
express. `backend().parameterSets` reports nine on OpenSSL 3.5, including
ML-DSA-44, ML-KEM-512 and two further SLH-DSA sets, and
[BENCHMARKS.md](BENCHMARKS.md) measures all of them. Reporting a set is not the
same as wrapping it: a set outside the five is visible to an evidence bundle
and is not an API this package offers.

**Two interchangeable backends.** The primitives run in OpenSSL 3.5 where the
runtime provides them and in JavaScript everywhere else. They produce identical
wire bytes, which is what makes the substitution safe: a signature made on one
verifies on the other, and the interoperability matrix in
[CONFORMANCE.md](CONFORMANCE.md) is what establishes that rather than an
assertion here.

**One abstraction, enforced.** [`eslint-plugin-kxco-pq`](https://www.npmjs.com/package/eslint-plugin-kxco-pq)
fails a build that reaches past the wrapper into `.ml_dsa65` or `.ml_kem768` on
the underlying library. The point is not style. A call site bound to a
primitive is a call site that a backend or parameter-set change has to rewrite
by hand, and the rule is what keeps the abstraction from being quietly holed.

The mechanism reports its own state. `backend()` returns which implementation
is doing the maths, its OpenSSL version and the sets it can express, so an
evidence bundle or a support ticket records the answer rather than inferring it
from `process.version`. It reports and does not switch, deliberately: a runtime
flag that changed which implementation signed would be a flag that changed what
a customer's evidence means.

The one operator control is the opposite of a switch. `requireNativeBackend()`,
or `KXCO_PQ_REQUIRE_NATIVE=1` in the environment, refuses to let a process
continue on the JavaScript backend when the deployment is under a control that
says the cryptography must execute inside a validated module. It fails at
import rather than at the first signature. It cannot make OpenSSL appear, and
it does not claim that the OpenSSL it found is a validated module, which is a
property of the operator's build.

## 3. An interoperable transition

**Algorithm identifiers on the wire.** The JWS module resolves the
implementation from its own allowlist using the header `alg`, and rejects
anything outside it. That is what lets a verifier accept two algorithms during
a transition without becoming vulnerable to the algorithm-confusion failure
that has broken JWT libraries repeatedly. `JWS_ALGORITHMS` is the allowlist;
the RFC 9964 names are used, not private ones.

**Key identifiers.** `fingerprint()` gives a key a stable kid, and both signing
and verification take one, so a consumer can be pinned to a specific key while
the algorithm around it moves.

**Two signatures over identical bytes.** The webhook envelope signs
`${timestamp}.${rawBody}` with HMAC-SHA-256 and with ML-DSA-65, both covering
exactly the same bytes. A receiver that verifies only one cannot be tricked
into treating it as covering a different message. This is stage 2 and stage 3
of the plan, already built.

**Evidence that peers accept the output.** The transition claim is only worth
the interoperability behind it. Bouncy Castle, liboqs, two independent Python
implementations and OpenSSL 3.5 verify what this package produces, and it
verifies theirs, both directions, pinned by version, in
[CONFORMANCE.md](CONFORMANCE.md).

## What this package does not give you

- **No runtime negotiation protocol.** Nothing here discovers what a peer
  supports. The JWS allowlist lets a verifier accept more than one algorithm;
  it does not ask a peer which one to use.
- **No automatic downgrade, ever.** There is no path that silently drops to a
  weaker set when the stronger one is unavailable. A missing set is an error.
- **The set list is fixed at release.** A parameter set this package does not
  wrap needs a release of this package, not a configuration change. That is the
  honest ceiling of the abstraction.
- **The JWS allowlist is ML-DSA only.** SLH-DSA and ML-KEM are reached at the
  key and signature layer, not through `alg`.
- **No TLS group negotiation.** Channel-level agility is not this package's
  surface. See `kxco-pq-tls`.

## Correcting this document

Every mechanism above is in `src/` and every evidence claim is in
[CONFORMANCE.md](CONFORMANCE.md). If a statement here does not match the code,
that is a defect worth reporting through [SECURITY.md](SECURITY.md).
