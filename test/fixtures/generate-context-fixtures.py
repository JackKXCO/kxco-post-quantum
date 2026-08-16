#!/usr/bin/env python3
"""
Generate third-party ML-DSA-65 context fixtures for test/context.test.js.

Signatures are produced by OpenSSL, through Python `cryptography` (>= 48),
which is an independent implementation of FIPS 204. Committing the output
means the JS test suite can cross-verify against a foreign implementation
without requiring Python at test time.

Run when the fixture set needs to change, not on every test run:

    pip install 'cryptography>=50'
    python test/fixtures/generate-context-fixtures.py > test/fixtures/context-vectors.json

The seed is fixed and public. These keys are test material and must never be
used for anything.
"""

import json
import sys

try:
    from cryptography.hazmat.primitives.asymmetric.mldsa import MLDSA65PrivateKey
except ImportError as e:
    sys.exit(
        f"cryptography with ML-DSA support not available ({e}).\n"
        "Requires cryptography >= 48. Install: pip install 'cryptography>=50'"
    )

# Fixed, public, test-only.
SEED = bytes.fromhex("00" * 16 + "kxcoctxfixture01".encode().hex())[:32]
MESSAGE = b"kxco third-party context interop vector"

CONTEXTS = [
    ("short",      b"kxco-nexus-v1"),
    ("single",     b"x"),
    ("max-255",    b"A" * 255),
    ("binary",     bytes(range(0, 32))),
    ("utf8",       "kxco-é中-v1".encode("utf-8")),
]


def main():
    if len(SEED) != 32:
        sys.exit(f"seed must be 32 bytes, got {len(SEED)}")

    sk = MLDSA65PrivateKey.from_seed_bytes(SEED)
    pk = sk.public_key().public_bytes_raw()

    out = {
        "_comment": (
            "Third-party ML-DSA-65 signatures produced by OpenSSL via Python "
            "cryptography. Consumed by test/context.test.js to cross-verify "
            "FIPS 204 context handling against an independent implementation. "
            "Test material only; the seed is public."
        ),
        "generator": "python cryptography (OpenSSL)",
        "algorithm": "ML-DSA-65",
        "seed": SEED.hex(),
        "publicKey": pk.hex(),
        "message": MESSAGE.hex(),
        "noContext": {
            "signature": sk.sign(MESSAGE).hex(),
        },
        "withContext": [
            {
                "label": label,
                "context": ctx.hex(),
                "signature": sk.sign(MESSAGE, ctx).hex(),
            }
            for label, ctx in CONTEXTS
        ],
    }
    json.dump(out, sys.stdout, indent=2)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
