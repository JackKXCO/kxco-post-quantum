"""Interop peer backed by liboqs (Open Quantum Safe).

liboqs is the reference C implementation the wider PQC ecosystem tests against,
and it shares no code with this package's backend, so agreement with it is real
cross-implementation evidence. It runs in a container because it needs a C
toolchain; see liboqs.Dockerfile and peers-lock.json.

Protocol: one JSON request per line on stdin, one JSON response per line on
stdout. Byte fields are lowercase hex. See ../run-interop.mjs.

Two capability gaps, declared honestly rather than papered over:

  * liboqs exposes no seed-derived keygen. Keys are addressed by seed elsewhere
    in this matrix; this peer answers `keyDerive` with an explicit unsupported
    error, and the orchestrator addresses it by encoded secret key instead. That
    still tests the thing that matters, because the FIPS 203 / FIPS 204 private
    key encodings are themselves standardised: if our encoded key did not load
    into liboqs and produce interoperable output, that would be a real defect.

  * liboqs signs hedged and exposes no deterministic mode through this binding,
    so byte-equality of signatures cannot be checked against it. The other peers
    cover that.

FIPS 204 context strings are supported and exercised, through the binding's
sign_with_ctx_str / verify_with_ctx_str. A parameter set whose liboqs build
reports sig_with_ctx_support false is answered as unsupported rather than
silently signed without the context, which would produce a signature that
verifies against nothing and read as a conformance failure.
"""

import json
import sys

# Protocol responses go on stdout, so nothing else may.
_OUT = sys.stdout
sys.stdout = sys.stderr

import oqs

class Unsupported(Exception):
    pass


DSA = {"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"}
KEM = {"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}


SIG_AVAILABLE = set(oqs.get_enabled_sig_mechanisms())
KEM_AVAILABLE = set(oqs.get_enabled_kem_mechanisms())

# liboqs spells the FIPS 205 parameter sets its own way, and the distinction that
# matters is PURE vs PREHASH: our backend implements pure SLH-DSA, so pairing it
# with one of liboqs' prehash variants would produce a spurious disagreement that
# looks like a conformance bug. Map explicitly rather than transforming the name,
# so an unmapped set is reported as unsupported instead of guessed at.
SLH_ALIAS = {
    "SLH-DSA-SHA2-128f": "SLH_DSA_PURE_SHA2_128F",
    "SLH-DSA-SHA2-128s": "SLH_DSA_PURE_SHA2_128S",
    "SLH-DSA-SHA2-192f": "SLH_DSA_PURE_SHA2_192F",
    "SLH-DSA-SHA2-192s": "SLH_DSA_PURE_SHA2_192S",
    "SLH-DSA-SHA2-256f": "SLH_DSA_PURE_SHA2_256F",
    "SLH-DSA-SHA2-256s": "SLH_DSA_PURE_SHA2_256S",
    "SLH-DSA-SHAKE-128f": "SLH_DSA_PURE_SHAKE_128F",
    "SLH-DSA-SHAKE-128s": "SLH_DSA_PURE_SHAKE_128S",
    "SLH-DSA-SHAKE-192f": "SLH_DSA_PURE_SHAKE_192F",
    "SLH-DSA-SHAKE-192s": "SLH_DSA_PURE_SHAKE_192S",
    "SLH-DSA-SHAKE-256f": "SLH_DSA_PURE_SHAKE_256F",
    "SLH-DSA-SHAKE-256s": "SLH_DSA_PURE_SHAKE_256S",
}


def resolve(alg):
    """Map a FIPS parameter set name onto the name this liboqs build uses."""
    name = SLH_ALIAS.get(alg, alg)
    if name not in SIG_AVAILABLE and name not in KEM_AVAILABLE:
        raise Unsupported(f"{alg} not enabled in this liboqs build")
    return name


IMPLEMENTATION = {
    "name": "liboqs",
    "language": "C",
    "algorithms": (
        sorted(a for a in DSA if a in SIG_AVAILABLE)
        + sorted(a for a in KEM if a in KEM_AVAILABLE)
        + sorted(a for a, n in SLH_ALIAS.items() if n in SIG_AVAILABLE)
    ),
    "derivesFromSeed": False,
    "deterministicSigning": False,
}


def h(b):
    return bytes(b).hex()


def unhex(s):
    return bytes.fromhex(s or "")


def _context(sig, req):
    """Resolve the FIPS 204 context string for this request.

    Returns None when there is no context, so the caller uses the plain sign or
    verify path. A non-empty context against a parameter set that cannot carry
    one is an explicit unsupported: signing without it would produce a signature
    that verifies against nothing and would read as a cross-implementation
    disagreement rather than a missing feature.
    """
    ctx = unhex(req.get("context"))
    if not ctx:
        return None
    if not sig.sig_with_ctx_support:
        raise Unsupported(f"{req['alg']} in this liboqs build carries no context string")
    return ctx


def handle(req):
    op = req["op"]

    if op == "identify":
        return dict(
            IMPLEMENTATION,
            liboqs=oqs.oqs_version(),
            binding=oqs.oqs_python_version(),
        )

    if op == "keyDerive":
        raise Unsupported("liboqs exposes no seed-derived keygen; address this peer by secretKey")

    alg = req["alg"]
    name = resolve(alg)
    is_kem = alg in KEM

    if op == "keypairRandom":
        ctor = oqs.KeyEncapsulation if is_kem else oqs.Signature
        with ctor(name) as k:
            return {"publicKey": h(k.generate_keypair()), "secretKey": h(k.export_secret_key())}

    if is_kem:
        if op == "encapsulate":
            # liboqs draws its own randomness and exposes no DRBG seeding through
            # this binding, so its ciphertext is fresh each run. The check that
            # consumes it compares recovered shared secrets, not ciphertext bytes,
            # so it stays meaningful; it is simply not reproducible.
            with oqs.KeyEncapsulation(name) as k:
                ct, ss = k.encap_secret(unhex(req["publicKey"]))
                return {"ciphertext": h(ct), "sharedSecret": h(ss)}

        if op == "decapsulate":
            with oqs.KeyEncapsulation(name, unhex(req["secretKey"])) as k:
                return {"sharedSecret": h(k.decap_secret(unhex(req["ciphertext"])))}

    else:
        if op == "sign":
            with oqs.Signature(name, unhex(req["secretKey"])) as sig:
                msg = unhex(req["message"])
                ctx = _context(sig, req)
                out = sig.sign(msg) if ctx is None else sig.sign_with_ctx_str(msg, ctx)
                return {"signature": h(out)}

        if op == "verify":
            with oqs.Signature(name) as sig:
                msg, sg, pk = unhex(req["message"]), unhex(req["signature"]), unhex(req["publicKey"])
                ctx = _context(sig, req)
                valid = (
                    sig.verify(msg, sg, pk)
                    if ctx is None
                    else sig.verify_with_ctx_str(msg, sg, ctx, pk)
                )
                return {"valid": bool(valid)}

    raise Unsupported(f"unsupported op/alg: {op}/{alg}")


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        try:
            out = {"id": req.get("id"), "ok": True, **handle(req)}
        except Unsupported as err:
            out = {"id": req.get("id"), "ok": False, "unsupported": True, "error": str(err)}
        except Exception as err:  # a peer failure is a result, not a crash
            out = {"id": req.get("id"), "ok": False, "error": f"{type(err).__name__}: {err}"}
        _OUT.write(json.dumps(out) + "\n")
        _OUT.flush()


if __name__ == "__main__":
    main()
