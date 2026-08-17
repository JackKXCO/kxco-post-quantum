# Threat model

What this package defends against, what it does not, and where the boundary
falls. Read this before deciding where to run it.

The short version: this is a software library written in JavaScript. It gives
you correct, standards-conformant ML-KEM, ML-DSA and SLH-DSA. It does not give
you resistance to an attacker who can measure the machine while it runs. If your
threat model includes that attacker, the key needs to live somewhere else.

---

## What is being protected

| Asset | Where it lives | Consequence if lost |
|---|---|---|
| ML-DSA / SLH-DSA private key | Caller-owned bytes in process memory | Attacker can forge signatures indefinitely |
| ML-KEM decapsulation key | Caller-owned bytes in process memory | Attacker can recover past and future shared secrets |
| ML-KEM shared secret | Return value, caller-owned | Attacker can decrypt the session that used it |
| Master seed used with `deriveSeed` | Caller-owned | Attacker can regenerate every derived key |

The library holds no keys of its own, opens no sockets, reads no files and keeps
no state between calls. Everything above is caller-owned material passed in and
returned. That places most of the security boundary in the calling application,
not here.

---

## Attackers in scope

**A remote attacker who can choose messages, signatures, ciphertexts and
context strings.** They submit arbitrary and malformed input across the network
and observe accept/reject and returned bytes. This is the attacker the library
is built to withstand.

- Forgery is resisted by the parameter sets themselves. The signature and
  verification paths follow FIPS 204 and FIPS 205 including the context-string
  binding, so a signature made under one context does not verify under another.
  Cross-implementation evidence is in [CONFORMANCE.md](CONFORMANCE.md).
- Malformed input is rejected rather than misinterpreted. Key and ciphertext
  lengths are checked, ML-KEM performs the FIPS 203 §7.2/§7.3 input checks, and
  a corrupted ciphertext yields an unrelated shared secret through implicit
  rejection instead of an error that would distinguish the failure.
- Signature malleability is not a defence the caller has to add: verification is
  over the exact encoded signature.

**An attacker who tampers with data at rest or in transit.** Detecting this is
the library's purpose and it does so as well as the underlying parameter sets.

**A quantum adversary running Shor's algorithm.** The three algorithm families
here rest on module-lattice and hash-based problems with no known efficient
quantum attack, which is the reason to use them. This is a statement about the
current state of cryptanalysis, not a proof, and it is the same assumption every
FIPS 203/204/205 deployment makes.

---

## Attackers out of scope

These are real attackers. They are excluded because this library genuinely does
not defend against them, and saying otherwise would be worse than saying nothing.

**An attacker who can measure execution on the same machine.** Timing, cache
occupancy, branch prediction, memory access patterns, power draw,
electromagnetic emission. Nothing here is hardened against any of it.

This is not an oversight that a future release closes. It follows from the
runtime. JavaScript exposes no control over instruction selection, branch
layout, memory placement or cache behaviour; the JIT may specialise a hot path
on the values flowing through it; the garbage collector may copy secret bytes to
places the caller cannot reach and cannot clear. Constant-time execution cannot
be established, let alone maintained across engine versions, from inside the
language. The backend states this about itself in plain terms: *"There is no
protection against side-channel attacks."*

Two consequences worth being blunt about:

- Do not run signing or decapsulation on hardware that also runs untrusted
  code. Shared-tenancy compute where another tenant can co-schedule on your
  physical core is exactly the setting this fails in.
- Do not run it where an adversary can attach measurement equipment. Smart
  cards, payment terminals, anything physically in an attacker's hands.

**An attacker who can read process memory.** A core dump, a debugger, a heap
snapshot or an in-process code-execution bug exposes every key the process is
holding. Best-effort zeroization is documented below and it does not change this.

**An attacker who has already achieved code execution in your process.** They
can call the library themselves with the keys it was given.

**A weak or predictable random source.** Key generation and hedged signing draw
from the platform CSPRNG through the backend. On a host whose entropy source is
broken or replayed, for example a VM image cloned after boot, the keys are
predictable and no property here survives that.

**An attacker positioned in the supply chain.** Addressed separately, by
release provenance and pinning rather than by anything in the runtime. See
[SECURITY.md](SECURITY.md).

---

## Where the residual risk actually sits

If you accept the two boxes above, the risk that remains is concentrated in one
place: **a long-lived signing key held in the memory of a general-purpose
process on shared hardware.**

Mitigations in rough order of how much they buy:

1. **Keep the key out of the process.** An HSM or KMS that performs ML-DSA
   internally removes the whole out-of-scope column for that key, because the
   key never enters a JavaScript heap. This library then handles verification
   only, which touches no secrets and is therefore unaffected by every
   side-channel concern above.
2. **Isolate the signer.** A dedicated host or a VM with no untrusted
   co-tenancy, running only the signing service, reachable through a narrow
   authenticated interface. This does not make the code constant-time; it
   removes the attacker who could exploit that.
3. **Prefer short-lived keys where the design allows it.** A key rotated
   frequently limits what a successful measurement attack yields.
4. **Keep verification and signing on separate hosts.** Verification is the
   operation exposed to hostile input, and it holds no secrets. Nothing is
   gained by placing it next to the key.

---

## Choices this library makes, and why

**Hedged signing by default.** `mlDsa.sign` and `slhDsa.sign` do not pass
`extraEntropy`, so the backend draws fresh randomness for each signature. FIPS
204 permits both, and hedged signing is the recommended default: it removes the
class of fault and differential attacks that recover a key from two signatures
produced over the same message with the same nonce. The cost is that signatures
are not reproducible, which the interop matrix reports rather than glosses over.
Callers who need reproducible output should use the backend primitives directly
and accept the trade.

**Pre-hash strength is enforced, and it is stricter than NIST's sample
vectors.** The backend refuses a HashML-DSA or HashSLH-DSA pre-hash whose
collision strength falls below the parameter set's security category, for
example SHA2-256 with ML-DSA-87. NIST's published vector files pair every
approved hash with every parameter set, so a run against them shows those
combinations as skipped. That is the intended behaviour, and the conformance
report counts them explicitly rather than hiding them in a pass total.

**Dependencies are exact-pinned, not range-pinned.** `@noble/post-quantum` and
`@noble/hashes` are pinned to single versions. A cryptographic backend that
floats within a semver range means the bytes you ship are not the bytes you
tested. The cost is manual review at each upgrade, which is the point.

**Context strings are supported and bounded.** FIPS 204 §5.2 folds a caller
context into the signed message, which is how a signature made for one purpose
is prevented from verifying for another. The 255-byte limit is enforced rather
than truncated, because silent truncation would merge two contexts a caller
meant to keep apart.

**Constant-time comparison is claimed; constant-time cryptography is not.**
`kidEquals` compares key fingerprints without an early return, so it does not
leak how many leading bytes matched. That is an achievable property in
JavaScript for a fixed-length byte comparison and it is asserted. It says
nothing about the algorithm implementations, where the property is not
achievable and is not claimed. Two different statements about two different
things; do not read the first as implying the second.

**Zeroization is best effort and is not a security control here.** Key bytes are
cleared where the library owns the buffer. In a garbage-collected runtime with
immutable strings and copying collection, no library can guarantee that no copy
survives. Treat memory disclosure as total key compromise regardless.

---

## What would change this assessment

Not a roadmap, and none of it is in the package today. Stated so the boundary is
falsifiable rather than permanent by assertion.

- A native or WebAssembly backend built from a constant-time implementation
  would move the timing and cache attacker from out of scope to partly in
  scope, with published measurements to show it. It would not cover power or
  electromagnetic analysis.
- Published timing measurements under a statistical test such as dudect would
  turn "no claim" into a measured bound. Absence of a detected leak is not
  absence of a leak, and any such result would be reported that way.
- FIPS 140-3 validation of a module used underneath would change what can be
  asserted about the boundary, and is not the same as the algorithm-level
  conformance evidence in [CONFORMANCE.md](CONFORMANCE.md).

---

## Reporting

Security contact and disclosure timelines are in [SECURITY.md](SECURITY.md).
If you find that any statement in this document is wrong, that is a finding
worth reporting on its own.
