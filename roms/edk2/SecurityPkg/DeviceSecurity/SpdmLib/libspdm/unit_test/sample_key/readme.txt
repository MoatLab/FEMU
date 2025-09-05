==== Note ====
Please use auto_gen_cert.sh to gen all cert in sample_key, then the raw_data_key_gen.py need run to generate sync raw data key.
Note: the rsa3072_Expiration have 1 day valid time.

==== RSA ====
Generate a root key:

    openssl genrsa -out TestRoot.key 2048

Generate a self-signed root certificate:

    openssl req -extensions v3_ca -new -x509 -days 3650 -key TestRoot.key -out TestRoot.crt
    openssl x509 -in TestRoot.crt -out TestRoot.cer -outform DER
    openssl x509 -inform DER -in TestRoot.cer -outform PEM -out TestRoot.pub.pem

==== ECC ====
Generate a root key: prime256v1(secp256r1/NIST P-256) / secp384r1 / secp521r1

    openssl ecparam -out EccTestRoot.key -name prime256v1 -genkey

Generate a self-signed root certificate:

    openssl req -extensions v3_ca -new -x509 -days 3650 -key EccTestRoot.key -out EccTestRoot.crt
    openssl x509 -in EccTestRoot.crt -out EccTestRoot.cer -outform DER
    openssl x509 -inform DER -in EccTestRoot.cer -outform PEM -out EccTestRoot.pub.pem

==== EdDSA ====
Generate a root key: ED25519  / ED448

    openssl genpkey -algorithm ED25519 > ed25519.key

Generate a self-signed root certificate:

    openssl req -new -out ed25519.csr -key ed25519.key -config openssl-25519.cnf
    openssl x509 -req -days 700 -in ed25519.csr -signkey ed25519.key -out ed25519.crt

=== RSA Certificate Chains ===

NOTE: Use "//CN" for windows and use "/CN" for Linux system.
RECOMMEND: Use openssl 1.1.1k


=== long_chains Certificate Chains(ShorterMAXUINT16_xxx.cert/ShorterMAXINT16_xxx.cert/Shorter1024B_xxx.cert) ===

For CA cert:
openssl req -nodes -x509 -days 3650 -newkey rsa:2048 -keyout ShorterMAXUINT16_ca.key -out ShorterMAXUINT16_ca.cert -sha256 -subj "/CN=DMTF libspdm RSA CA"

For inter cert:
Generate the remain cert in order

Generate cert chain:
cat ShorterMAXUINT16_ca.cert.der ShorterMAXUINT16_inter*.cert.der ShorterMAXUINT16_end_responder.cert.der >ShorterMAXUINT16_bundle_responder.certchain.der


==== More cert_chain for ecp256/384/521 rsa2048/3072/4096 ed448/25519 sm2 to gen ====

NOTE: The bundle_requester.certchain1.der and bundle_requester.certchain.der have same leaf cert key.
As same as bundle_responder.certchain1.der.
Gen new ca1.key; use old inter.key and end.key.


=== Add test cert in ecp256===
Gen ecp256/end_requester_ca_false.cert.der is same with ecp256/end_requester.cert.der, expect the openssl.cnf is follow:
[ v3_end_with_false_basicConstraints]
basicConstraints = critical,CA:true

Gen ecp256/end_requester_without_basic_constraint.cert.der is same with ecp256/end_requester.cert.der, expect the
basicConstraints is excluded in openssl.cnf [ v3_end_without_basicConstraints].

=== Gen rsa3072_Expiration ===
Gen rsa3072_Expiration is same with rsa3072, expect the cert validaty time is 1 day.


==== More alias_cert model cert_chain to gen ====
NOTE: The bundle_responder.certchain_alias_cert_partial_set.der and bundle_requester.certchain.der have same ca_cert and inter cert.
The only different is: the basic constraints is: CA: ture in leaf cert of bundle_responder.certchain_alias_cert_partial_set.der.
This alias cert chain is partial, from root CA to device certificate CA.

The bundle_responder.certchain_alias.der is the entire cert_chain in the alias_cert mode.
