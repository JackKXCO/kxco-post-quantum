# OpenSSL 3.5 for issuing the PKI artefacts this package then verifies.
#
# Alpine carries a current OpenSSL, and 3.5 is the first line with ML-DSA in the
# signature algorithm list, so an older base silently produces nothing to test.
# The version is asserted at build time rather than hoped for.
# Pinned by digest, not just by tag: this container is the OpenSSL peer the
# protocol conformance results are measured against, and a moving base image
# silently changes what those results mean.
FROM alpine:3.22@sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce

RUN apk add --no-cache openssl \
 && openssl version \
 && openssl list -signature-algorithms | grep -q 'ML-DSA-65' \
 || (echo "this OpenSSL has no ML-DSA; nothing to generate" && exit 1)

COPY generate.sh /generate.sh
RUN chmod +x /generate.sh
ENTRYPOINT ["/generate.sh"]
