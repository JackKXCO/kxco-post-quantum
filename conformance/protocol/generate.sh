#!/bin/sh
# Produce real PKI artefacts with OpenSSL, for this package to verify.
#
# Passing NIST's vectors proves the primitives are right. Agreeing with three
# other libraries proves the encodings are right. Neither proves a certificate
# this package can verify came out of the tooling an institution actually runs,
# which is the question a PKI team asks first.
#
# OpenSSL issues here and this package verifies in Node, so nothing in the chain
# is ours on both sides.
#
# Emits one JSON object per line on stdout: artefacts as hex, so the Node side
# needs no ASN.1 tooling to read the file, only to parse what it is testing.
set -eu

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

emit() { printf '%s\n' "$1"; }
hex() { od -An -v -tx1 < "$1" | tr -d ' \n'; }

# Name the issuer exactly. "OpenSSL 3.5" in a report is a claim about a family;
# the build string is a claim about what actually signed these bytes.
emit "{\"kind\":\"meta\",\"openssl\":\"$(openssl version)\"}"

for SET in ML-DSA-44 ML-DSA-65 ML-DSA-87; do
  openssl genpkey -algorithm "$SET" -out "$WORK/key.pem" 2>/dev/null

  # ---- X.509: a self-signed certificate, the artefact a PKI team hands over
  openssl req -new -x509 -key "$WORK/key.pem" \
    -subj "/CN=kxco-conformance-$SET/O=KXCO" -days 30 \
    -outform DER -out "$WORK/cert.der" 2>/dev/null

  # OpenSSL's own verdict on it, so a disagreement is visible rather than assumed
  openssl x509 -in "$WORK/cert.der" -inform DER -out "$WORK/cert.pem" 2>/dev/null
  if openssl verify -CAfile "$WORK/cert.pem" "$WORK/cert.pem" >/dev/null 2>&1; then
    SELFOK=true
  else
    SELFOK=false
  fi

  # the raw public key, so the Node side can be given it directly as a control
  # against whatever it extracts from the certificate itself
  openssl pkey -in "$WORK/key.pem" -pubout -outform DER -out "$WORK/pub.der" 2>/dev/null

  emit "{\"kind\":\"x509\",\"set\":\"$SET\",\"opensslVerify\":$SELFOK,\"cert\":\"$(hex "$WORK/cert.der")\",\"spki\":\"$(hex "$WORK/pub.der")\"}"

  # ---- CMS: a signed message.
  #
  # ML-DSA carries no default digest in OpenSSL 3.5, so CMS_add1_signer fails
  # with "no default digest" unless -md is given. That is a property of the CMS
  # layer, not of the key, and naming the digest is the whole fix.
  printf 'kxco protocol conformance %s' "$SET" > "$WORK/msg.txt"
  openssl cms -sign -in "$WORK/msg.txt" -signer "$WORK/cert.pem" -inkey "$WORK/key.pem" \
    -md sha256 -nodetach -binary -outform DER -out "$WORK/cms.der" 2>/dev/null

  if openssl cms -verify -in "$WORK/cms.der" -inform DER \
       -CAfile "$WORK/cert.pem" -out /dev/null >/dev/null 2>&1; then
    CMSOK=true
  else
    CMSOK=false
  fi

  emit "{\"kind\":\"cms\",\"set\":\"$SET\",\"digest\":\"sha256\",\"opensslVerify\":$CMSOK,\"blob\":\"$(hex "$WORK/cms.der")\",\"message\":\"$(hex "$WORK/msg.txt")\",\"spki\":\"$(hex "$WORK/pub.der")\"}"
done
