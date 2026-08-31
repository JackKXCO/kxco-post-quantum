# Third-implementation interop peer: liboqs (Open Quantum Safe).
#
# liboqs is C and needs a toolchain this repo does not assume any contributor
# has, so the peer runs in a container instead. The image pins liboqs by tag and
# liboqs-python by tag; both are recorded in peers-lock.json.
#
# libssl-dev is not optional: liboqs 0.16.0 configures against OpenSSL for its
# symmetric primitives and cmake fails at find_package(OpenSSL) without it.
#
# Built and driven by ../run-interop.mjs. Speaks the same one-JSON-object-per-line
# protocol on stdin/stdout as the other peers.

FROM python:3.12-slim

ARG LIBOQS_TAG=0.16.0
ARG LIBOQS_PYTHON_TAG=0.16.0

RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential cmake ninja-build git ca-certificates libssl-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch ${LIBOQS_TAG} \
      https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
 && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja \
      -DBUILD_SHARED_LIBS=ON \
      -DOQS_BUILD_ONLY_LIB=ON \
      -DCMAKE_BUILD_TYPE=Release \
 && cmake --build /tmp/liboqs/build --parallel \
 && cmake --install /tmp/liboqs/build \
 && ldconfig \
 && rm -rf /tmp/liboqs

RUN git clone --depth 1 --branch ${LIBOQS_PYTHON_TAG} \
      https://github.com/open-quantum-safe/liboqs-python /tmp/liboqs-python \
 && pip install --no-cache-dir /tmp/liboqs-python \
 && rm -rf /tmp/liboqs-python

COPY liboqs-peer.py /peer/liboqs-peer.py
ENTRYPOINT ["python", "-u", "/peer/liboqs-peer.py"]
