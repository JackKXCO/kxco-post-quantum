# Performance

Per-algorithm latency and memory, reported as tail latency rather than a mean.

A mean hides the tail, and the tail is what a request budget has to absorb. For
ML-DSA that distinction is not cosmetic: signing uses rejection sampling, so it
loops until the candidate signature falls in range, and the slow tail is inherent
to the algorithm rather than measurement noise. Anyone sizing a timeout from a
mean will size it wrong.

Reproduce with:

```
node --expose-gc bench/primitives.mjs --iterations 100 --json bench/results/primitives.json
```

Every parameter set the package can reach is measured, not only the five it wraps
in its own helpers.

## Signatures

Milliseconds. 100 iterations except where the `n` column says otherwise.

| Algorithm | Operation | n | median | p95 | p99 | ops/s |
|---|---|---:|---:|---:|---:|---:|
| ML-DSA-44 | keygen | 100 | 1.695 | 2.847 | 3.317 | 545 |
| ML-DSA-44 | sign | 100 | 8.880 | 24.104 | 30.193 | 91 |
| ML-DSA-44 | verify | 100 | 1.554 | 3.000 | 3.650 | 552 |
| ML-DSA-65 | keygen | 100 | 3.394 | 9.058 | 11.699 | 238 |
| ML-DSA-65 | sign | 100 | 11.308 | 36.752 | 51.084 | 64 |
| ML-DSA-65 | verify | 100 | 3.456 | 5.032 | 5.553 | 288 |
| ML-DSA-87 | keygen | 100 | 5.226 | 8.270 | 9.635 | 194 |
| ML-DSA-87 | sign | 100 | 13.148 | 33.932 | 42.381 | 62 |
| ML-DSA-87 | verify | 100 | 4.877 | 11.119 | 21.760 | 167 |
| SLH-DSA-SHA2-128f | sign | 20 | 151.319 | 194.915 | 205.881 | 7 |
| SLH-DSA-SHA2-128f | verify | 20 | 6.412 | 10.672 | 30.298 | 121 |
| SLH-DSA-SHA2-192s | sign | 3 | 6788.860 | 7229.209 | 7229.209 | 0 |
| SLH-DSA-SHA2-192s | verify | 10 | 4.997 | 62.287 | 62.287 | 89 |
| SLH-DSA-SHAKE-256f | sign | 5 | 3333.195 | 3786.271 | 3786.271 | 0 |
| SLH-DSA-SHAKE-256f | verify | 10 | 72.219 | 86.779 | 86.779 | 14 |

**Two numbers to design around.**

**ML-DSA signing has a long tail.** ML-DSA-65 signs in 11 ms at the median and
51 ms at p99, a factor of 4.5. Rejection sampling means an unlucky signature does
several more rounds. Size request budgets from p99, not the median.

**SLH-DSA-SHA2-192s signs in about 6.8 seconds.** That is the set `slhDsa` wraps,
and it is not a per-request operation. It suits infrequent, high-value signatures
such as firmware or root attestations. Verification is cheap, around 5 ms, so an
SLH-DSA signature is expensive to make and cheap to check. The `f` variants trade
signature size for signing speed: SHA2-128f signs in 151 ms.

## Key encapsulation

| Algorithm | Operation | n | median | p95 | p99 | ops/s |
|---|---|---:|---:|---:|---:|---:|
| ML-KEM-512 | keygen | 100 | 0.338 | 0.969 | 1.277 | 2222 |
| ML-KEM-512 | encapsulate | 100 | 0.512 | 1.043 | 1.617 | 1720 |
| ML-KEM-512 | decapsulate | 100 | 0.845 | 2.133 | 2.561 | 965 |
| ML-KEM-768 | keygen | 100 | 0.645 | 1.357 | 1.757 | 1344 |
| ML-KEM-768 | encapsulate | 100 | 0.822 | 2.050 | 5.067 | 971 |
| ML-KEM-768 | decapsulate | 100 | 1.292 | 2.750 | 4.048 | 674 |
| ML-KEM-1024 | keygen | 100 | 1.062 | 2.043 | 2.776 | 860 |
| ML-KEM-1024 | encapsulate | 100 | 1.066 | 1.902 | 10.844 | 641 |
| ML-KEM-1024 | decapsulate | 100 | 0.917 | 1.813 | 2.169 | 918 |

ML-KEM is sub-millisecond at the median across all three sets. Moving from
Category 3 to Category 5 costs well under a millisecond per operation, so the
migration cost of ML-KEM-1024 is its 1568-byte keys and ciphertexts, not its
speed. See [MIGRATION.md](MIGRATION.md).

## Wrapper overhead

The package helpers derive keys from a master secret through HKDF, which the raw
primitives do not. That is the only overhead they add:

| Helper | median | raw keygen median | HKDF cost |
|---|---:|---:|---:|
| `mlDsa.keypairFromMaster` | 3.945 | 3.394 | ~0.55 ms |
| `mlKem.keypairFromMaster` | 1.129 | 0.645 | ~0.48 ms |

Signing and verification go straight through, so they carry no wrapper cost
beyond hex encoding.

## Memory

Heap growth per operation, in bytes, from `process.memoryUsage().heapUsed` across
a batch:

| Algorithm | keygen | sign or encapsulate |
|---|---:|---:|
| ML-KEM-768 | ~11.7 kB | ~13.0 kB |
| ML-KEM-1024 | ~20.6 kB | ~6.1 kB |
| ML-DSA-65 | ~12.9 kB | ~21.0 kB |
| ML-DSA-87 | ~3.3 kB | ~11.4 kB |
| SLH-DSA-SHA2-128f | ~143 kB | |
| SLH-DSA-SHA2-192s | ~192 kB | |
| SLH-DSA-SHAKE-256f | ~864 kB | |

SLH-DSA allocates one to three orders of magnitude more than the lattice schemes,
which is consistent with building a hypertree per key. The lattice figures are
tens of kilobytes and are not a constraint at these rates.

**Read these as orders of magnitude, not exact allocations.** Garbage collection
can run mid-batch, so a figure smaller than a sibling's does not reliably mean
less allocation. ML-DSA-87 keygen reading lower than ML-DSA-65 is an artefact of
collection timing, not evidence that the larger parameter set allocates less.

## What these figures are not

- **One machine, one run.** Node v26.1.0 on win32-x64. Absolute numbers move with
  hardware and runtime; the ratios between operations are the portable part.
- **Not a cross-vendor comparison.** Nothing here was measured against another
  implementation, so it says nothing about how this compares to a native or
  hardware-backed stack. It will be slower than both.
- **Reduced samples where marked.** SLH-DSA slow variants take 3 to 20 samples
  rather than 100, because 100 signatures at 6.8 seconds each is not a benchmark,
  it is an afternoon. Where n is small, p95 and p99 collapse onto the maximum and
  are reported that way rather than dressed up.
- **Not a side-channel measurement.** Timing here is throughput, gathered without
  any attempt to detect secret-dependent variation, and it must not be read as
  evidence about constant-time behaviour. See [THREAT-MODEL.md](THREAT-MODEL.md),
  which states plainly that no such property is claimed.
