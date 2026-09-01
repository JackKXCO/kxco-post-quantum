# OpenSSL 3.5 for issuing the PKI artefacts this package then verifies.
#
# Alpine carries a current OpenSSL, and 3.5 is the first line with ML-DSA in the
# signature algorithm list, so an older base silently produces nothing to test.
# The version is asserted at build time rather than hoped for.
FROM alpine:3.22

RUN apk add --no-cache openssl \
 && openssl version \
 && openssl list -signature-algorithms | grep -q 'ML-DSA-65' \
 || (echo "this OpenSSL has no ML-DSA; nothing to generate" && exit 1)

COPY generate.sh /generate.sh
RUN chmod +x /generate.sh
ENTRYPOINT ["/generate.sh"]
