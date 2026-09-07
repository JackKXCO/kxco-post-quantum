# Lifecycle, ceiling and dependencies

The questions a buyer needs answered before committing to a migration date,
rather than after. Maturity describes what has been achieved; none of it says
whether the thing will still be maintained, how far it can go without new
hardware, or what could block it. Those are here.

## Guidance followed

FIPS 203, 204 and 205 for the primitives, verified against NIST's own ACVP
vectors rather than asserted. RFC 9964 for the JWS algorithm names. RFC 5869
for HKDF. Where a standard is supported but compliance is a property of a
deployment rather than of this package, the distinction is stated instead of
blurred: see the CNSA 2.0 entry in
[CONFORMANCE.md](CONFORMANCE.md#what-this-evidence-does-not-cover).

Risk review happened before the evidence, not after it:
[THREAT-MODEL.md](THREAT-MODEL.md) names what is in scope, what is out, and
where the residual risk actually sits, which is a long-lived signing key in the
memory of a general-purpose process.

Update and agility needs are in [AGILITY.md](AGILITY.md), including the
mechanisms this package does not have.

## Supported versions

One line, moving forward. Releases run v1.x in sequence with no maintenance
branches, and fixes land in the next release rather than being backported.
Anyone on an older 1.x upgrades forward to receive a fix.

Upgrading forward is intended to be cheap and is treated as a compatibility
obligation: signatures made by earlier versions verify under later ones, and
[MIGRATION.md](MIGRATION.md#migrating-between-versions) records what changed at
each step where a caller had to do anything.

**Not yet decided:** a formal end-of-support window, expressed in months rather
than in practice. Until it is decided, the honest statement is the one above,
which describes what happens rather than what is promised. A buyer who needs a
contractual window should ask for one rather than infer it.

## Ceiling without hardware replacement

There is no hardware ceiling in this package. It is software, the highest
parameter sets are already shipped rather than planned, and Category 5 needs no
different machine than Category 3: `mlDsa87` and `mlKem1024` are published
entry points today.

The ceiling that does exist is the runtime, and it is a performance ceiling
rather than a capability one:

| Runtime | Backend | Effect |
|---|---|---|
| Node 24 and later | OpenSSL 3.5 primitives | Roughly 4x to 8x faster, measured per operation in [BENCHMARKS.md](BENCHMARKS.md) |
| Node 20.19 to 23, browsers | JavaScript | Every algorithm available, identical wire bytes, slower |

Nothing becomes unavailable on the slower path. If a request budget cannot
absorb the JavaScript figures, the fix is a Node upgrade, which is not a
hardware replacement.

Two real ceilings sit outside this package and belong to whatever it is
deployed with. An HSM can only perform the algorithms its firmware implements,
and firmware is where hardware replacement genuinely appears; that question
belongs to `kxco-pq-hsm` and the token vendor. Signature size is the other:
ML-DSA-65 signatures are far larger than ECDSA, and a protocol with a fixed
field or an MTU assumption may need changing. [MIGRATION.md](MIGRATION.md) puts
proving that at stage 1 for exactly this reason.

## Blocking supplier dependency

**The dependency.** `@noble/post-quantum`, pinned at exactly 0.7.0, supplies
the FIPS 203/204/205 arithmetic. This package does not reimplement it.

**Why it is a blocker and not just a dependency.** It is the one package in the
tree with no independent review. The maintainer's own self-audit covers 0.6.1,
which is not the version shipped. Version 0.7.1 regressed nine NIST SLH-DSA
verification vectors that 0.7.0 passes, shipped in this package's 1.5.1 and was
reverted in 1.5.2. So the supply risk here is demonstrated rather than
theoretical.

**Mitigations, in the order they actually help.**

1. *Evidence instead of trust.* Every parameter set is checked against NIST's
   ACVP vectors and cross-checked against liboqs, Bouncy Castle and two Python
   implementations in both directions. That regression was caught by this
   harness within hours of the dependency's release, which is the concrete
   demonstration that the control works.
2. *A second implementation on the same wire format.* On Node 24 and later the
   OpenSSL backend performs ML-DSA, ML-KEM and SLH-DSA for the sets OpenSSL
   expresses, and the dependency is not doing that arithmetic at all. The
   exception is precise and worth stating: a FIPS 204 context string takes the
   JavaScript path, because OpenSSL does not express it. So the dependency is
   reduced on modern runtimes rather than removed.
3. *An exact pin, enforced.* No ranges in `dependencies`, and the audit harness
   fails the build on one. 0.7.1 is separately blocked in dependabot so it
   cannot return through an automated bump.
4. *A conformance gate on every bump.* A change to this dependency is a change
   to the primitives, so it is not merged on a green test run. The full ACVP
   and interoperability evidence has to regenerate clean.

**Milestone.** The route off this being a single point of review is external
audit, and that is on the roadmap rather than done. See below.

**Second-order dependency, disclosed.** `@noble/curves` is not imported by name
anywhere in this package and is on the hot path regardless: both ML-DSA and
ML-KEM reach it through the primitives. That was established by a reachability
walk rather than by reading manifests, and it is in
[DEPENDENCIES.md](DEPENDENCIES.md). It is the most heavily reviewed package in
the tree.

## Roadmap status, beside the maturity result

The commitments and what has not happened yet are in
[AUDIT.md](AUDIT.md#3-audit-roadmap): an external auditor for the wrapper
integration patterns, a public bug bounty, and a FIPS 140-3 CMVP application
for a module deployment using this library with an HSM. Dates depend on
capacity; the order is committed.

Read that table beside any maturity claim, not after it. Nothing on it has been
delivered, and a roadmap entry is a vendor commitment rather than a result.

## Correcting this document

If a figure or a pin here does not match the tree, that is a defect worth
reporting through [SECURITY.md](SECURITY.md).
