"""Interop peer backed by dilithium-py and kyber-py.

Two pure-Python FIPS 203 / FIPS 204 implementations that share no code with
this package's backend, so agreement between them is real cross-implementation
evidence rather than the same library agreeing with itself.

Protocol: one JSON request per line on stdin, one JSON response per line on
stdout. Byte fields are lowercase hex. See ../run-interop.mjs.

    python python-peer.py < requests.jsonl > responses.jsonl
"""

import json
import sys

from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024

DSA = {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}
KEM = {"ML-KEM-512": ML_KEM_512, "ML-KEM-768": ML_KEM_768, "ML-KEM-1024": ML_KEM_1024}

IMPLEMENTATION = {
    "name": "dilithium-py + kyber-py",
    "language": "Python",
    "algorithms": sorted(DSA) + sorted(KEM),
}


def h(b):
    return b.hex()


def unhex(s):
    return bytes.fromhex(s or "")


def secret_key(impl, req):
    """Resolve the private key.

    The orchestrator addresses keys by seed rather than by encoded private key,
    because the seed-form encoding differs between libraries while the seed
    itself is fixed by FIPS 203 / FIPS 204. An explicit secretKey is still
    accepted for callers that have one.
    """
    if req.get("seed"):
        return impl.key_derive(unhex(req["seed"]))[1]
    return unhex(req["secretKey"])


def handle(req):
    op = req["op"]

    if op == "identify":
        return dict(IMPLEMENTATION, python=sys.version.split()[0])

    alg = req["alg"]

    if alg in DSA:
        impl = DSA[alg]
        if op == "keyDerive":
            pk, sk = impl.key_derive(unhex(req["seed"]))
            return {"publicKey": h(pk), "secretKey": h(sk)}
        if op == "sign":
            sig = impl.sign(
                secret_key(impl, req),
                unhex(req["message"]),
                ctx=unhex(req.get("context")),
                deterministic=bool(req.get("deterministic")),
            )
            return {"signature": h(sig)}
        if op == "verify":
            valid = impl.verify(
                unhex(req["publicKey"]),
                unhex(req["message"]),
                unhex(req["signature"]),
                ctx=unhex(req.get("context")),
            )
            return {"valid": bool(valid)}

    if alg in KEM:
        impl = KEM[alg]
        if op == "keyDerive":
            ek, dk = impl.key_derive(unhex(req["seed"]))
            return {"publicKey": h(ek), "secretKey": h(dk)}
        if op == "encapsulate":
            # Seeding the DRBG makes the peer's encapsulation reproducible, so a
            # rerun of the matrix produces the same ciphertext rather than a
            # fresh one each time.
            if req.get("entropy"):
                # kyber-py's DRBG takes a 48-byte seed; the orchestrator sends
                # 48 bytes and peers take the prefix they need.
                impl.set_drbg_seed(unhex(req["entropy"])[:48])
            shared, ct = impl.encaps(unhex(req["publicKey"]))
            return {"ciphertext": h(ct), "sharedSecret": h(shared)}
        if op == "decapsulate":
            shared = impl.decaps(secret_key(impl, req), unhex(req["ciphertext"]))
            return {"sharedSecret": h(shared)}

    raise ValueError(f"unsupported op/alg: {op}/{alg}")


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        try:
            out = {"id": req.get("id"), "ok": True, **handle(req)}
        except Exception as err:  # a peer failure is a result, not a crash
            out = {"id": req.get("id"), "ok": False, "error": f"{type(err).__name__}: {err}"}
        sys.stdout.write(json.dumps(out) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
