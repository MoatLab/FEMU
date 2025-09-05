#!/bin/bash

# Auto gen cert script.
# Please run: ./auto_gen_cert.sh in linux.
# Use the openssl version in linux: openssl 1.1.1f


# === RSA Certificate Chains ===
pushd rsa2048
openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ca.key -out ca.cert -sha256 -subj "/CN=DMTF libspdm RSA CA"
openssl rsa -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey rsa:3072 -keyout inter.key -out inter.req -sha256 -batch -subj "/CN=DMTF libspdm RSA intermediate cert"
openssl req -nodes -newkey rsa:2048 -keyout end_requester.key -out end_requester.req -sha256 -batch -subj "/CN=DMTF libspdm RSA requseter cert"
openssl req -nodes -newkey rsa:2048 -keyout end_responder.key -out end_responder.req -sha256 -batch -subj "/CN=DMTF libspdm RSA responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha256 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl rsa -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl rsa -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkey -in end_requester.key -inform PEM -pubout -outform PEM -out end_requester.key.pub
openssl pkey -in end_requester.key -inform PEM -pubout -outform DER -out end_requester.key.pub.der
openssl pkey -in end_responder.key -inform PEM -pubout -outform PEM -out end_responder.key.pub
openssl pkey -in end_responder.key -inform PEM -pubout -outform DER -out end_responder.key.pub.der
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 4 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 5 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 6 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_requester_with_spdm_req_rsp_eku.cert -out end_requester_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_req_eku.cert -out end_requester_with_spdm_req_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_rsp_eku.cert -out end_requester_with_spdm_rsp_eku.cert.der
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 7 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 8 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 9 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_responder_with_spdm_req_rsp_eku.cert -out end_responder_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_req_eku.cert -out end_responder_with_spdm_req_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_rsp_eku.cert -out end_responder_with_spdm_rsp_eku.cert.der
popd

pushd rsa3072
openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ca.key -out ca.cert -sha384 -subj "/CN=DMTF libspdm RSA CA"
openssl rsa -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey rsa:3072 -keyout inter.key -out inter.req -sha384 -batch -subj "/CN=DMTF libspdm RSA intermediate cert"
openssl req -nodes -newkey rsa:3072 -keyout end_requester.key -out end_requester.req -sha384 -batch -subj "/CN=DMTF libspdm RSA requseter cert"
openssl req -nodes -newkey rsa:3072 -keyout end_responder.key -out end_responder.req -sha384 -batch -subj "/CN=DMTF libspdm RSA responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl rsa -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl rsa -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkey -in end_requester.key -inform PEM -pubout -outform PEM -out end_requester.key.pub
openssl pkey -in end_requester.key -inform PEM -pubout -outform DER -out end_requester.key.pub.der
openssl pkey -in end_responder.key -inform PEM -pubout -outform PEM -out end_responder.key.pub
openssl pkey -in end_responder.key -inform PEM -pubout -outform DER -out end_responder.key.pub.der
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 4 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 5 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 6 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_requester_with_spdm_req_rsp_eku.cert -out end_requester_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_req_eku.cert -out end_requester_with_spdm_req_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_rsp_eku.cert -out end_requester_with_spdm_rsp_eku.cert.der
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 7 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 8 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 9 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_responder_with_spdm_req_rsp_eku.cert -out end_responder_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_req_eku.cert -out end_responder_with_spdm_req_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_rsp_eku.cert -out end_responder_with_spdm_rsp_eku.cert.der
popd

pushd rsa4096
openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ca.key -out ca.cert -sha512 -subj "/CN=DMTF libspdm RSA CA"
openssl rsa -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey rsa:3072 -keyout inter.key -out inter.req -sha512 -batch -subj "/CN=DMTF libspdm RSA intermediate cert"
openssl req -nodes -newkey rsa:4096 -keyout end_requester.key -out end_requester.req -sha512 -batch -subj "/CN=DMTF libspdm RSA requseter cert"
openssl req -nodes -newkey rsa:4096 -keyout end_responder.key -out end_responder.req -sha512 -batch -subj "/CN=DMTF libspdm RSA responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha512 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl rsa -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl rsa -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkey -in end_requester.key -inform PEM -pubout -outform PEM -out end_requester.key.pub
openssl pkey -in end_requester.key -inform PEM -pubout -outform DER -out end_requester.key.pub.der
openssl pkey -in end_responder.key -inform PEM -pubout -outform PEM -out end_responder.key.pub
openssl pkey -in end_responder.key -inform PEM -pubout -outform DER -out end_responder.key.pub.der
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 4 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 5 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 6 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_requester_with_spdm_req_rsp_eku.cert -out end_requester_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_req_eku.cert -out end_requester_with_spdm_req_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_rsp_eku.cert -out end_requester_with_spdm_rsp_eku.cert.der
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 7 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 8 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 9 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_responder_with_spdm_req_rsp_eku.cert -out end_responder_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_req_eku.cert -out end_responder_with_spdm_req_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_rsp_eku.cert -out end_responder_with_spdm_rsp_eku.cert.der
popd

# === EC Certificate Chains ===

pushd ecp256
openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca.key -out ca.cert -sha256 -subj "/CN=DMTF libspdm ECP256 CA"
openssl pkey -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey ec:param.pem -keyout inter.key -out inter.req -sha256 -batch -subj "/CN=DMTF libspdm ECP256 intermediate cert"
openssl req -nodes -newkey ec:param.pem -keyout end_requester.key -out end_requester.req -sha256 -batch -subj "/CN=DMTF libspdm ECP256 requseter cert"
openssl req -nodes -newkey ec:param.pem -keyout end_responder.key -out end_responder.req -sha256 -batch -subj "/CN=DMTF libspdm ECP256 responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha256 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl ec -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl pkcs8 -in end_responder.key.der -inform DER -topk8 -nocrypt -outform DER > end_responder.key.p8
openssl ec -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkcs8 -in end_requester.key.der -inform DER -topk8 -nocrypt -outform DER > end_requester.key.p8
openssl pkey -in end_requester.key -inform PEM -pubout -outform PEM -out end_requester.key.pub
openssl pkey -in end_requester.key -inform PEM -pubout -outform DER -out end_requester.key.pub.der
openssl pkey -in end_responder.key -inform PEM -pubout -outform PEM -out end_responder.key.pub
openssl pkey -in end_responder.key -inform PEM -pubout -outform DER -out end_responder.key.pub.der
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 4 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 5 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 6 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_requester_with_spdm_req_rsp_eku.cert -out end_requester_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_req_eku.cert -out end_requester_with_spdm_req_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_rsp_eku.cert -out end_requester_with_spdm_rsp_eku.cert.der
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 7 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 8 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 9 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_responder_with_spdm_req_rsp_eku.cert -out end_responder_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_req_eku.cert -out end_responder_with_spdm_req_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_rsp_eku.cert -out end_responder_with_spdm_rsp_eku.cert.der
popd

pushd ecp384
openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-384
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca.key -out ca.cert -sha384 -subj "/CN=DMTF libspdm ECP384 CA"
openssl pkey -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey ec:param.pem -keyout inter.key -out inter.req -sha384 -batch -subj "/CN=DMTF libspdm ECP384 intermediate cert"
openssl req -nodes -newkey ec:param.pem -keyout end_requester.key -out end_requester.req -sha384 -batch -subj "/CN=DMTF libspdm ECP384 requseter cert"
openssl req -nodes -newkey ec:param.pem -keyout end_responder.key -out end_responder.req -sha384 -batch -subj "/CN=DMTF libspdm ECP384 responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl ec -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl pkcs8 -in end_responder.key.der -inform DER -topk8 -nocrypt -outform DER > end_responder.key.p8
openssl ec -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkcs8 -in end_requester.key.der -inform DER -topk8 -nocrypt -outform DER > end_requester.key.p8
openssl pkey -in end_requester.key -inform PEM -pubout -outform PEM -out end_requester.key.pub
openssl pkey -in end_requester.key -inform PEM -pubout -outform DER -out end_requester.key.pub.der
openssl pkey -in end_responder.key -inform PEM -pubout -outform PEM -out end_responder.key.pub
openssl pkey -in end_responder.key -inform PEM -pubout -outform DER -out end_responder.key.pub.der
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 4 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 5 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 6 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_requester_with_spdm_req_rsp_eku.cert -out end_requester_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_req_eku.cert -out end_requester_with_spdm_req_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_rsp_eku.cert -out end_requester_with_spdm_rsp_eku.cert.der
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 7 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 8 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 9 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_responder_with_spdm_req_rsp_eku.cert -out end_responder_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_req_eku.cert -out end_responder_with_spdm_req_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_rsp_eku.cert -out end_responder_with_spdm_rsp_eku.cert.der
popd

pushd ecp521
openssl genpkey -genparam -out param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-521
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca.key -out ca.cert -sha512 -subj "/CN=DMTF libspdm ECP521 CA"
openssl pkey -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey ec:param.pem -keyout inter.key -out inter.req -sha512 -batch -subj "/CN=DMTF libspdm ECP521 intermediate cert"
openssl req -nodes -newkey ec:param.pem -keyout end_requester.key -out end_requester.req -sha512 -batch -subj "/CN=DMTF libspdm ECP521 requseter cert"
openssl req -nodes -newkey ec:param.pem -keyout end_responder.key -out end_responder.req -sha512 -batch -subj "/CN=DMTF libspdm ECP521 responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha512 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl ec -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl pkcs8 -in end_responder.key.der -inform DER -topk8 -nocrypt -outform DER > end_responder.key.p8
openssl ec -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkcs8 -in end_requester.key.der -inform DER -topk8 -nocrypt -outform DER > end_requester.key.p8
openssl pkey -in end_requester.key -inform PEM -pubout -outform PEM -out end_requester.key.pub
openssl pkey -in end_requester.key -inform PEM -pubout -outform DER -out end_requester.key.pub.der
openssl pkey -in end_responder.key -inform PEM -pubout -outform PEM -out end_responder.key.pub
openssl pkey -in end_responder.key -inform PEM -pubout -outform DER -out end_responder.key.pub.der
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 4 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 5 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 6 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_requester_with_spdm_req_rsp_eku.cert -out end_requester_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_req_eku.cert -out end_requester_with_spdm_req_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_rsp_eku.cert -out end_requester_with_spdm_rsp_eku.cert.der
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 7 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 8 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 9 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_responder_with_spdm_req_rsp_eku.cert -out end_responder_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_req_eku.cert -out end_responder_with_spdm_req_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_rsp_eku.cert -out end_responder_with_spdm_rsp_eku.cert.der
popd

#=== Ed Certificate Chains ===

pushd ed25519
openssl genpkey -algorithm ed25519 -out ca.key
openssl req -nodes -x509 -days 3650 -key ca.key -out ca.cert -subj "/CN=DMTF libspdm ED25519 CA"
openssl genpkey -algorithm ed25519 -out inter.key
openssl genpkey -algorithm ed25519 -out end_requester.key
openssl genpkey -algorithm ed25519 -out end_responder.key
openssl req -new -key inter.key -out inter.req -batch -subj "/CN=DMTF libspdm ED25519 intermediate cert"
openssl req -new -key end_requester.key -out end_requester.req -batch -subj "/CN=DMTF libspdm ED25519 requseter cert"
openssl req -new -key end_responder.key -out end_responder.req -batch -subj "/CN=DMTF libspdm ED25519 responder cert"
openssl x509 -req -days 3650 -in inter.req -CA ca.cert -CAkey ca.key -out inter.cert -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester.cert -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder.cert -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl pkey -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl pkcs8 -in end_responder.key.der -inform DER -topk8 -nocrypt -outform DER > end_responder.key.p8
openssl pkey -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkcs8 -in end_requester.key.der -inform DER -topk8 -nocrypt -outform DER > end_requester.key.p8
openssl pkey -in end_requester.key -inform PEM -pubout -outform PEM -out end_requester.key.pub
openssl pkey -in end_requester.key -inform PEM -pubout -outform DER -out end_requester.key.pub.der
openssl pkey -in end_responder.key -inform PEM -pubout -outform PEM -out end_responder.key.pub
openssl pkey -in end_responder.key -inform PEM -pubout -outform DER -out end_responder.key.pub.der
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester_with_spdm_req_rsp_eku.cert -set_serial 4 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester_with_spdm_req_eku.cert -set_serial 5 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester_with_spdm_rsp_eku.cert -set_serial 6 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_requester_with_spdm_req_rsp_eku.cert -out end_requester_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_req_eku.cert -out end_requester_with_spdm_req_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_rsp_eku.cert -out end_requester_with_spdm_rsp_eku.cert.der
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder_with_spdm_req_rsp_eku.cert -set_serial 7 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder_with_spdm_req_eku.cert -set_serial 8 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder_with_spdm_rsp_eku.cert -set_serial 9 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_responder_with_spdm_req_rsp_eku.cert -out end_responder_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_req_eku.cert -out end_responder_with_spdm_req_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_rsp_eku.cert -out end_responder_with_spdm_rsp_eku.cert.der
popd

pushd ed448
openssl genpkey -algorithm ed448 -out ca.key
openssl req -nodes -x509 -days 3650 -key ca.key -out ca.cert -subj "/CN=DMTF libspdm ED448 CA"
openssl genpkey -algorithm ed448 -out inter.key
openssl genpkey -algorithm ed448 -out end_requester.key
openssl genpkey -algorithm ed448 -out end_responder.key
openssl req -new -key inter.key -out inter.req -batch -subj "/CN=DMTF libspdm ED448 intermediate cert"
openssl req -new -key end_requester.key -out end_requester.req -batch -subj "/CN=DMTF libspdm ED448 requseter cert"
openssl req -new -key end_responder.key -out end_responder.req -batch -subj "/CN=DMTF libspdm ED448 responder cert"
openssl x509 -req -days 3650 -in inter.req -CA ca.cert -CAkey ca.key -out inter.cert -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester.cert -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder.cert -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl pkey -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl pkcs8 -in end_responder.key.der -inform DER -topk8 -nocrypt -outform DER > end_responder.key.p8
openssl pkey -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkcs8 -in end_carequester.key.der -inform DER -topk8 -nocrypt -outform DER > end_requester.key.p8
openssl pkey -in end_requester.key -inform PEM -pubout -outform PEM -out end_requester.key.pub
openssl pkey -in end_requester.key -inform PEM -pubout -outform DER -out end_requester.key.pub.der
openssl pkey -in end_responder.key -inform PEM -pubout -outform PEM -out end_responder.key.pub
openssl pkey -in end_responder.key -inform PEM -pubout -outform DER -out end_responder.key.pub.der
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester_with_spdm_req_rsp_eku.cert -set_serial 4 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester_with_spdm_req_eku.cert -set_serial 5 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester_with_spdm_rsp_eku.cert -set_serial 6 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_requester_with_spdm_req_rsp_eku.cert -out end_requester_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_req_eku.cert -out end_requester_with_spdm_req_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_rsp_eku.cert -out end_requester_with_spdm_rsp_eku.cert.der
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder_with_spdm_req_rsp_eku.cert -set_serial 7 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder_with_spdm_req_eku.cert -set_serial 8 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder_with_spdm_rsp_eku.cert -set_serial 9 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_responder_with_spdm_req_rsp_eku.cert -out end_responder_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_req_eku.cert -out end_responder_with_spdm_req_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_rsp_eku.cert -out end_responder_with_spdm_rsp_eku.cert.der
popd

#=== sm2 Certificate Chains ===

pushd sm2
openssl ecparam -genkey -name SM2 -out ca.key
openssl req -nodes -x509 -days 3650 -key ca.key -out ca.cert -sha256 -subj "/CN=DMTF libspdm SM2 CA"
openssl ecparam -genkey -name SM2 -out inter.key
openssl ecparam -genkey -name SM2 -out end_requester.key
openssl ecparam -genkey -name SM2 -out end_responder.key
openssl req -new -key inter.key -out inter.req -sha256 -batch -subj '/CN=DMTF libspdm SM2 intermediate cert'
openssl req -new -key end_requester.key -out end_requester.req -sha256 -batch -subj '/CN=DMTF libspdm SM2 requseter cert'
openssl req -new -key end_responder.key -out end_responder.req -sha256 -batch -subj '/CN=DMTF libspdm SM2 responder cert'
openssl x509 -req -days 3650 -in inter.req -CA ca.cert -CAkey ca.key -out inter.cert -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester.cert -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder.cert -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl pkey -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl pkcs8 -in end_responder.key.der -inform DER -topk8 -nocrypt -outform DER > end_responder.key.p8
openssl pkey -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkcs8 -in end_requester.key.der -inform DER -topk8 -nocrypt -outform DER > end_requester.key.p8
openssl pkey -in end_requester.key -inform PEM -pubout -outform PEM -out end_requester.key.pub
openssl pkey -in end_requester.key -inform PEM -pubout -outform DER -out end_requester.key.pub.der
openssl pkey -in end_responder.key -inform PEM -pubout -outform PEM -out end_responder.key.pub
openssl pkey -in end_responder.key -inform PEM -pubout -outform DER -out end_responder.key.pub.der
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester_with_spdm_req_rsp_eku.cert -set_serial 4 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester_with_spdm_req_eku.cert -set_serial 5 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_requester.req -CA inter.cert -CAkey inter.key -out end_requester_with_spdm_rsp_eku.cert -set_serial 6 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_requester_with_spdm_req_rsp_eku.cert -out end_requester_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_req_eku.cert -out end_requester_with_spdm_req_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_rsp_eku.cert -out end_requester_with_spdm_rsp_eku.cert.der
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder_with_spdm_req_rsp_eku.cert -set_serial 7 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder_with_spdm_req_eku.cert -set_serial 8 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -days 3650 -in end_responder.req -CA inter.cert -CAkey inter.key -out end_responder_with_spdm_rsp_eku.cert -set_serial 9 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_responder_with_spdm_req_rsp_eku.cert -out end_responder_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_req_eku.cert -out end_responder_with_spdm_req_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_rsp_eku.cert -out end_responder_with_spdm_rsp_eku.cert.der
popd

#=== long_chains Certificate Chains ===

pushd long_chains


#== ShorterMAXUINT16_xx.cert ==
openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ShorterMAXUINT16_ca.key -out ShorterMAXUINT16_ca.cert -sha256 -subj "/CN=DMTF libspdm RSA CA"
openssl asn1parse -in ShorterMAXUINT16_ca.cert -out ShorterMAXUINT16_ca.cert.der 

openssl req -nodes -newkey rsa:4096 -keyout ShorterMAXUINT16_inter01.key -out ShorterMAXUINT16_inter01.req -sha256 -batch -subj "/CN=DMTF libspdm RSA intermediate 1 cert"
openssl x509 -req -in ShorterMAXUINT16_inter01.req -out ShorterMAXUINT16_inter01.cert -CA ShorterMAXUINT16_ca.cert -CAkey ShorterMAXUINT16_ca.key -sha256 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl asn1parse -in ShorterMAXUINT16_inter01.cert -out ShorterMAXUINT16_inter01.cert.der 

# cert number
cert_number=47
# loop to gen cert
for ((i=2; i<=9; i++)); do
	openssl req -nodes -newkey rsa:2048 -keyout ShorterMAXUINT16_inter0$i.key -out ShorterMAXUINT16_inter0$i.req -sha256 -batch -subj "/CN=DMTF libspdm RSA intermediate $i cert"
	openssl x509 -req -in ShorterMAXUINT16_inter0$i.req -out ShorterMAXUINT16_inter0$i.cert -CA ShorterMAXUINT16_inter0$((i-1)).cert -CAkey ShorterMAXUINT16_inter0$((i-1)).key -sha256 -days 3650 -set_serial $i -extensions v3_inter -extfile ../openssl.cnf
	openssl asn1parse -in ShorterMAXUINT16_inter0$i.cert -out ShorterMAXUINT16_inter0$i.cert.der 
done

openssl req -nodes -newkey rsa:4096 -keyout ShorterMAXUINT16_inter10.key -out ShorterMAXUINT16_inter10.req -sha256 -batch -subj "/CN=DMTF libspdm RSA intermediate 10 cert"
openssl x509 -req -in ShorterMAXUINT16_inter10.req -out ShorterMAXUINT16_inter10.cert -CA ShorterMAXUINT16_inter09.cert -CAkey ShorterMAXUINT16_inter09.key -sha256 -days 3650 -set_serial 10 -extensions v3_inter -extfile ../openssl.cnf
openssl asn1parse -in ShorterMAXUINT16_inter10.cert -out ShorterMAXUINT16_inter10.cert.der 

for ((i=11; i<=$cert_number; i++)); do
	openssl req -nodes -newkey rsa:4096 -keyout ShorterMAXUINT16_inter$i.key -out ShorterMAXUINT16_inter$i.req -sha256 -batch -subj "/CN=DMTF libspdm RSA intermediate $i cert"
	openssl x509 -req -in ShorterMAXUINT16_inter$i.req -out ShorterMAXUINT16_inter$i.cert -CA ShorterMAXUINT16_inter$((i-1)).cert -CAkey ShorterMAXUINT16_inter$((i-1)).key -sha256 -days 3650 -set_serial $i -extensions v3_inter -extfile ../openssl.cnf
	openssl asn1parse -in ShorterMAXUINT16_inter$i.cert -out ShorterMAXUINT16_inter$i.cert.der 
done

openssl req -nodes -newkey rsa:2048 -keyout ShorterMAXUINT16_end_responder.key -out ShorterMAXUINT16_end_responder.req -sha256 -batch -subj "/CN=DMTF libspdm RSA responder cert"
openssl x509 -req -in ShorterMAXUINT16_end_responder.req -out ShorterMAXUINT16_end_responder.cert -CA ShorterMAXUINT16_inter47.cert -CAkey ShorterMAXUINT16_inter47.key -sha256 -days 3650 -set_serial 48 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ShorterMAXUINT16_end_responder.cert -out ShorterMAXUINT16_end_responder.cert.der 
cat ShorterMAXUINT16_ca.cert.der ShorterMAXUINT16_inter*.cert.der ShorterMAXUINT16_end_responder.cert.der >ShorterMAXUINT16_bundle_responder.certchain.der

openssl req -nodes -newkey rsa:2048 -keyout ShorterMAXUINT16_end_requester.key -out ShorterMAXUINT16_end_requester.req -sha256 -batch -subj "/CN=DMTF libspdm RSA requseter cert"
openssl x509 -req -in ShorterMAXUINT16_end_requester.req -out ShorterMAXUINT16_end_requester.cert -CA ShorterMAXUINT16_inter47.cert -CAkey ShorterMAXUINT16_inter47.key -sha256 -days 3650 -set_serial 48 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ShorterMAXUINT16_end_requester.cert -out ShorterMAXUINT16_end_requester.cert.der 
cat ShorterMAXUINT16_ca.cert.der ShorterMAXUINT16_inter*.cert.der ShorterMAXUINT16_end_requester.cert.der >ShorterMAXUINT16_bundle_requester.certchain.der


#== ShorterMAXINT16_xx.cert ==

openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ShorterMAXINT16_ca.key -out ShorterMAXINT16_ca.cert -sha256 -subj "/CN=DMTF libspdm RSA CA"
openssl asn1parse -in ShorterMAXINT16_ca.cert -out ShorterMAXINT16_ca.cert.der 

openssl req -nodes -newkey rsa:4096 -keyout ShorterMAXINT16_inter01.key -out ShorterMAXINT16_inter01.req -sha256 -batch -subj "/CN=DMTF libspdm RSA intermediate 1 cert"
openssl x509 -req -in ShorterMAXINT16_inter01.req -out ShorterMAXINT16_inter01.cert -CA ShorterMAXINT16_ca.cert -CAkey ShorterMAXINT16_ca.key -sha256 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl asn1parse -in ShorterMAXINT16_inter01.cert -out ShorterMAXINT16_inter01.cert.der 

# cert number
cert_number=22

# loop to gen cert
for ((i=2; i<=9; i++)); do
	openssl req -nodes -newkey rsa:4096 -keyout ShorterMAXINT16_inter0$i.key -out ShorterMAXINT16_inter0$i.req -sha256 -batch -subj "/CN=DMTF libspdm RSA intermediate $i cert"
	openssl x509 -req -in ShorterMAXINT16_inter0$i.req -out ShorterMAXINT16_inter0$i.cert -CA ShorterMAXINT16_inter0$((i-1)).cert -CAkey ShorterMAXINT16_inter0$((i-1)).key -sha256 -days 3650 -set_serial $i -extensions v3_inter -extfile ../openssl.cnf
	openssl asn1parse -in ShorterMAXINT16_inter0$i.cert -out ShorterMAXINT16_inter0$i.cert.der 
done

openssl req -nodes -newkey rsa:4096 -keyout ShorterMAXINT16_inter10.key -out ShorterMAXINT16_inter10.req -sha256 -batch -subj "/CN=DMTF libspdm RSA intermediate 10 cert"
openssl x509 -req -in ShorterMAXINT16_inter10.req -out ShorterMAXINT16_inter10.cert -CA ShorterMAXINT16_inter09.cert -CAkey ShorterMAXINT16_inter09.key -sha256 -days 3650 -set_serial 10 -extensions v3_inter -extfile ../openssl.cnf
openssl asn1parse -in ShorterMAXINT16_inter10.cert -out ShorterMAXINT16_inter10.cert.der 


for ((i=11; i<=$cert_number; i++)); do
	openssl req -nodes -newkey rsa:4096 -keyout ShorterMAXINT16_inter$i.key -out ShorterMAXINT16_inter$i.req -sha256 -batch -subj "/CN=DMTF libspdm RSA intermediate $i cert"
	openssl x509 -req -in ShorterMAXINT16_inter$i.req -out ShorterMAXINT16_inter$i.cert -CA ShorterMAXINT16_inter$((i-1)).cert -CAkey ShorterMAXINT16_inter$((i-1)).key -sha256 -days 3650 -set_serial $i -extensions v3_inter -extfile ../openssl.cnf
	openssl asn1parse -in ShorterMAXINT16_inter$i.cert -out ShorterMAXINT16_inter$i.cert.der 
done


openssl req -nodes -newkey rsa:2048 -keyout ShorterMAXINT16_end_responder.key -out ShorterMAXINT16_end_responder.req -sha256 -batch -subj "/CN=DMTF libspdm RSA responder cert"
openssl x509 -req -in ShorterMAXINT16_end_responder.req -out ShorterMAXINT16_end_responder.cert -CA ShorterMAXINT16_inter22.cert -CAkey ShorterMAXINT16_inter22.key -sha256 -days 3650 -set_serial 23 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ShorterMAXINT16_end_responder.cert -out ShorterMAXINT16_end_responder.cert.der 
cat ShorterMAXINT16_ca.cert.der ShorterMAXINT16_inter*.cert.der ShorterMAXINT16_end_responder.cert.der >ShorterMAXINT16_bundle_responder.certchain.der


openssl req -nodes -newkey rsa:2048 -keyout ShorterMAXINT16_end_requester.key -out ShorterMAXINT16_end_requester.req -sha256 -batch -subj "/CN=DMTF libspdm RSA requseter cert"
openssl x509 -req -in ShorterMAXINT16_end_requester.req -out ShorterMAXINT16_end_requester.cert -CA ShorterMAXINT16_inter22.cert -CAkey ShorterMAXINT16_inter22.key -sha256 -days 3650 -set_serial 23 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ShorterMAXINT16_end_requester.cert -out ShorterMAXINT16_end_requester.cert.der 
cat ShorterMAXINT16_ca.cert.der ShorterMAXINT16_inter*.cert.der ShorterMAXINT16_end_requester.cert.der >ShorterMAXINT16_bundle_requester.certchain.der


#== Shorter1024B_xx.cert ==
openssl genpkey -genparam -out Shorter1024B_param.pem -algorithm EC -pkeyopt ec_paramgen_curve:P-256
openssl req -nodes -x509 -days 3650 -newkey ec:Shorter1024B_param.pem -keyout Shorter1024B_ca.key -out Shorter1024B_ca.cert -sha256 -subj "/CN=DMTF libspdm ECP256 CA"
openssl pkey -in Shorter1024B_ca.key -outform der -out Shorter1024B_ca.key.der
openssl req -nodes -newkey ec:Shorter1024B_param.pem -keyout Shorter1024B_end_requester.key -out Shorter1024B_end_requester.req -sha256 -batch -subj "/CN=DMTF libspdm ECP256 requseter cert"
openssl req -nodes -newkey ec:Shorter1024B_param.pem -keyout Shorter1024B_end_responder.key -out Shorter1024B_end_responder.req -sha256 -batch -subj "/CN=DMTF libspdm ECP256 responder cert"
openssl x509 -req -in Shorter1024B_end_requester.req -out Shorter1024B_end_requester.cert -CA Shorter1024B_ca.cert -CAkey Shorter1024B_ca.key -sha256 -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in Shorter1024B_end_responder.req -out Shorter1024B_end_responder.cert -CA Shorter1024B_ca.cert -CAkey Shorter1024B_ca.key -sha256 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in Shorter1024B_ca.cert -out Shorter1024B_ca.cert.der
openssl asn1parse -in Shorter1024B_end_requester.cert -out Shorter1024B_end_requester.cert.der
openssl asn1parse -in Shorter1024B_end_responder.cert -out Shorter1024B_end_responder.cert.der
cat Shorter1024B_ca.cert.der Shorter1024B_end_requester.cert.der > Shorter1024B_bundle_requester.certchain.der
cat Shorter1024B_ca.cert.der Shorter1024B_end_responder.cert.der > Shorter1024B_bundle_responder.certchain.der
popd

#==== More cert_chain to gen ====

#NOTE: The bundle_requester.certchain1.der and bundle_requester.certchain.der have same leaf cert key.
#As same as bundle_responder.certchain1.der.
#Gen new ca1.key; use old inter.key and end.key.

#=== ecc256 Certificate Chains ===
pushd ecp256
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca1.key -out ca1.cert -sha256 -subj "/CN=DMTF libspdm ECP256 CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha256 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha256  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha256 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der
popd

#=== ecc384 Certificate Chains ===
pushd ecp384
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca1.key -out ca1.cert -sha384 -subj "/CN=DMTF libspdm ECP384 CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha384  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha384 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der
popd

#=== ecc521 Certificate Chains ===
pushd ecp521
openssl req -nodes -x509 -days 3650 -newkey ec:param.pem -keyout ca1.key -out ca1.cert -sha512 -subj "/CN=DMTF libspdm ECP521 CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha512 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha512  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha512 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der
popd

#=== rsa2048 Certificate Chains ===
pushd rsa2048
openssl req -nodes -x509 -days 3650 -newkey rsa:2048 -keyout ca1.key -out ca1.cert -sha256 -subj "/CN=DMTF libspdm RSA CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha256 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha256  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha256 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der
popd

#=== rsa3072 Certificate Chains ===
pushd rsa3072
openssl req -nodes -x509 -days 3650 -newkey rsa:3072 -keyout ca1.key -out ca1.cert -sha384 -subj "/CN=DMTF libspdm RSA CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha384 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha384  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha384 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der
popd

#=== rsa4096 Certificate Chains ===
pushd rsa4096
openssl req -nodes -x509 -days 3650 -newkey rsa:4096 -keyout ca1.key -out ca1.cert -sha512 -subj "/CN=DMTF libspdm RSA CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha512 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha512  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha512 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der
popd

#=== ed25519 Certificate Chains ===
pushd ed25519
openssl genpkey -algorithm ed25519 -out ca1.key
openssl req -nodes -x509 -days 3650 -key ca1.key -out ca1.cert -subj "/CN=DMTF libspdm ED25519 CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der
popd

#=== ed448 Certificate Chains ===
pushd ed448
openssl genpkey -algorithm ed448 -out ca1.key
openssl req -nodes -x509 -days 3650 -key ca1.key -out ca1.cert -subj "/CN=DMTF libspdm ED448 CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der
popd

#=== sm2 Certificate Chains ===
pushd sm2
openssl ecparam -genkey -name SM2 -out ca1.key
openssl req -nodes -x509 -days 3650 -key ca1.key -out ca1.cert -sha256 -subj "/CN=DMTF libspdm SM2 CA"
openssl pkey -in ca1.key -outform der -out ca1.key.der
openssl x509 -req -in inter.req -out inter1.cert -CA ca1.cert -CAkey ca1.key -sha256 -days 3650 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester1.cert -CA inter1.cert -CAkey inter.key -sha256  -days 3650 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder1.cert -CA inter1.cert -CAkey inter.key -sha256 -days 3650 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca1.cert -out ca1.cert.der
openssl asn1parse -in inter1.cert -out inter1.cert.der
openssl asn1parse -in end_requester1.cert -out end_requester1.cert.der
openssl asn1parse -in end_responder1.cert -out end_responder1.cert.der
cat ca1.cert.der inter1.cert.der end_requester1.cert.der > bundle_requester.certchain1.der
cat ca1.cert.der inter1.cert.der end_responder1.cert.der > bundle_responder.certchain1.der
popd


#=== Add test cert in ecp256===
pushd ecp256
openssl x509 -req -in end_requester.req -out end_requester_ca_false.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 2 -extensions v3_end_with_false_basicConstraints -extfile ../openssl.cnf
openssl asn1parse -in end_requester_ca_false.cert -out end_requester_ca_false.cert.der

openssl x509 -req -in end_requester.req -out end_requester_without_basic_constraint.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 2 -extensions v3_end_without_basicConstraints -extfile ../openssl.cnf
openssl asn1parse -in end_requester_without_basic_constraint.cert -out end_requester_without_basic_constraint.cert.der
popd

#=== Gen rsa3072_Expiration===
#Gen rsa3072_Expiration is same with rsa3072, expect the cert validaty time is 1 day.
pushd rsa3072_Expiration
openssl req -nodes -x509 -days 1 -newkey rsa:4096 -keyout ca.key -out ca.cert -sha384 -subj "/CN=DMTF libspdm RSA CA"
openssl rsa -in ca.key -outform der -out ca.key.der
openssl req -nodes -newkey rsa:3072 -keyout inter.key -out inter.req -sha384 -batch -subj "/CN=DMTF libspdm RSA intermediate cert"
openssl req -nodes -newkey rsa:3072 -keyout end_requester.key -out end_requester.req -sha384 -batch -subj "/CN=DMTF libspdm RSA requseter cert"
openssl req -nodes -newkey rsa:3072 -keyout end_responder.key -out end_responder.req -sha384 -batch -subj "/CN=DMTF libspdm RSA responder cert"
openssl x509 -req -in inter.req -out inter.cert -CA ca.cert -CAkey ca.key -sha384 -days 1 -set_serial 1 -extensions v3_inter -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester.cert -CA inter.cert -CAkey inter.key -sha384 -days 1 -set_serial 2 -extensions v3_end -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder.cert -CA inter.cert -CAkey inter.key -sha384 -days 1 -set_serial 3 -extensions v3_end -extfile ../openssl.cnf
openssl asn1parse -in ca.cert -out ca.cert.der
openssl asn1parse -in inter.cert -out inter.cert.der
openssl asn1parse -in end_requester.cert -out end_requester.cert.der
openssl asn1parse -in end_responder.cert -out end_responder.cert.der
cat ca.cert.der inter.cert.der end_requester.cert.der > bundle_requester.certchain.der
cat ca.cert.der inter.cert.der end_responder.cert.der > bundle_responder.certchain.der
openssl rsa -inform PEM -outform DER -in end_responder.key -out end_responder.key.der
openssl rsa -inform PEM -outform DER -in end_requester.key -out end_requester.key.der
openssl pkey -in end_requester.key -inform PEM -pubout -outform PEM -out end_requester.key.pub
openssl pkey -in end_requester.key -inform PEM -pubout -outform DER -out end_requester.key.pub.der
openssl pkey -in end_responder.key -inform PEM -pubout -outform PEM -out end_responder.key.pub
openssl pkey -in end_responder.key -inform PEM -pubout -outform DER -out end_responder.key.pub.der
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 1 -set_serial 4 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 1 -set_serial 5 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_requester.req -out end_requester_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 1 -set_serial 6 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_requester_with_spdm_req_rsp_eku.cert -out end_requester_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_req_eku.cert -out end_requester_with_spdm_req_eku.cert.der
openssl asn1parse -in end_requester_with_spdm_rsp_eku.cert -out end_requester_with_spdm_rsp_eku.cert.der
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 1 -set_serial 7 -extensions v3_end_with_spdm_req_rsp_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_req_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 1 -set_serial 8 -extensions v3_end_with_spdm_req_eku -extfile ../openssl.cnf
openssl x509 -req -in end_responder.req -out end_responder_with_spdm_rsp_eku.cert -CA inter.cert -CAkey inter.key -sha384 -days 1 -set_serial 9 -extensions v3_end_with_spdm_rsp_eku -extfile ../openssl.cnf
openssl asn1parse -in end_responder_with_spdm_req_rsp_eku.cert -out end_responder_with_spdm_req_rsp_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_req_eku.cert -out end_responder_with_spdm_req_eku.cert.der
openssl asn1parse -in end_responder_with_spdm_rsp_eku.cert -out end_responder_with_spdm_rsp_eku.cert.der
popd

#==== More alias_cert model cert_chain to gen ====

#=== ecc256 Certificate alias Chains ===
pushd ecp256
openssl req -nodes -newkey ec:param.pem -keyout end_responder_alias_partial.key -out end_responder_alias_partial.req -sha256 -batch -subj "/CN=DMTF libspdm ECP256 responder alias end cert"
openssl x509 -req -in end_responder_alias_partial.req -out end_responder_alias_cert_partial_set.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 3 -extensions v3_end_alias_part -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias_cert_partial_set.cert -out end_responder_alias_cert_partial_set.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der > bundle_responder.certchain_alias_cert_partial_set.der

openssl x509 -req -in end_responder.req -out end_responder_alias.cert -CA end_responder_alias_cert_partial_set.cert -CAkey end_responder_alias_partial.key -sha256 -days 3650 -set_serial 4 -extensions v3_end_alias_entire -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias.cert -out end_responder_alias.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der end_responder_alias.cert.der > bundle_responder.certchain_alias.der
popd

#=== ecc384 Certificate alias Chains ===
pushd ecp384
openssl req -nodes -newkey ec:param.pem -keyout end_responder_alias_partial.key -out end_responder_alias_partial.req -sha384 -batch -subj "/CN=DMTF libspdm ECP384 responder alias end cert"
openssl x509 -req -in end_responder_alias_partial.req -out end_responder_alias_cert_partial_set.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 3 -extensions v3_end_alias_part -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias_cert_partial_set.cert -out end_responder_alias_cert_partial_set.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der > bundle_responder.certchain_alias_cert_partial_set.der

openssl x509 -req -in end_responder.req  -out end_responder_alias.cert -CA end_responder_alias_cert_partial_set.cert -CAkey end_responder_alias_partial.key -sha384 -days 3650 -set_serial 4 -extensions v3_end_alias_entire -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias.cert -out end_responder_alias.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der end_responder_alias.cert.der > bundle_responder.certchain_alias.der
popd

#=== ecc521 Certificate alias Chains ===
pushd ecp521
openssl req -nodes -newkey ec:param.pem -keyout end_responder_alias_partial.key -out end_responder_alias_partial.req -sha512 -batch -subj "/CN=DMTF libspdm ECP521 responder alias end cert"
openssl x509 -req -in end_responder_alias_partial.req -out end_responder_alias_cert_partial_set.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 3 -extensions v3_end_alias_part -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias_cert_partial_set.cert -out end_responder_alias_cert_partial_set.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der > bundle_responder.certchain_alias_cert_partial_set.der

openssl x509 -req -in end_responder.req  -out end_responder_alias.cert -CA end_responder_alias_cert_partial_set.cert -CAkey end_responder_alias_partial.key -sha512 -days 3650 -set_serial 4 -extensions v3_end_alias_entire -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias.cert -out end_responder_alias.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der end_responder_alias.cert.der > bundle_responder.certchain_alias.der
popd

#=== rsa2048 Certificate alias Chains ===
pushd rsa2048
openssl req -nodes -newkey rsa:2048 -keyout end_responder_alias_partial.key -out end_responder_alias_partial.req -sha256 -batch -subj "/CN=DMTF libspdm RSA responder alias end cert"
openssl x509 -req -in end_responder_alias_partial.req -out end_responder_alias_cert_partial_set.cert -CA inter.cert -CAkey inter.key -sha256 -days 3650 -set_serial 3 -extensions v3_end_alias_part -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias_cert_partial_set.cert -out end_responder_alias_cert_partial_set.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der > bundle_responder.certchain_alias_cert_partial_set.der

openssl x509 -req -in end_responder.req  -out end_responder_alias.cert -CA end_responder_alias_cert_partial_set.cert -CAkey end_responder_alias_partial.key -sha256 -days 3650 -set_serial 4 -extensions v3_end_alias_entire -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias.cert -out end_responder_alias.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der end_responder_alias.cert.der > bundle_responder.certchain_alias.der
popd

#=== rsa3072 Certificate alias Chains ===
pushd rsa3072
openssl req -nodes -newkey rsa:3072 -keyout end_responder_alias_partial.key -out end_responder_alias_partial.req -sha384 -batch -subj "/CN=DMTF libspdm RSA responder alias end cert"
openssl x509 -req -in end_responder_alias_partial.req -out end_responder_alias_cert_partial_set.cert -CA inter.cert -CAkey inter.key -sha384 -days 3650 -set_serial 3 -extensions v3_end_alias_part -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias_cert_partial_set.cert -out end_responder_alias_cert_partial_set.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der > bundle_responder.certchain_alias_cert_partial_set.der

openssl x509 -req -in end_responder.req  -out end_responder_alias.cert -CA end_responder_alias_cert_partial_set.cert -CAkey end_responder_alias_partial.key -sha384 -days 3650 -set_serial 4 -extensions v3_end_alias_entire -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias.cert -out end_responder_alias.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der end_responder_alias.cert.der > bundle_responder.certchain_alias.der
popd

#=== rsa4096 Certificate alias Chains ===
pushd rsa4096
openssl req -nodes -newkey rsa:4096 -keyout end_responder_alias_partial.key -out end_responder_alias_partial.req -sha512 -batch -subj "/CN=DMTF libspdm RSA responder alias end cert"
openssl x509 -req -in end_responder_alias_partial.req -out end_responder_alias_cert_partial_set.cert -CA inter.cert -CAkey inter.key -sha512 -days 3650 -set_serial 3 -extensions v3_end_alias_part -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias_cert_partial_set.cert -out end_responder_alias_cert_partial_set.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der > bundle_responder.certchain_alias_cert_partial_set.der

openssl x509 -req -in end_responder.req  -out end_responder_alias.cert -CA end_responder_alias_cert_partial_set.cert -CAkey end_responder_alias_partial.key -sha512 -days 3650 -set_serial 4 -extensions v3_end_alias_entire -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias.cert -out end_responder_alias.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der end_responder_alias.cert.der > bundle_responder.certchain_alias.der
popd

#=== ed25519 Certificate alias Chains ===
pushd ed25519
openssl genpkey -algorithm ed25519 -out end_responder_alias_partial.key
openssl req -new -key end_responder_alias_partial.key -out end_responder_alias_partial.req -batch -subj "/CN=DMTF libspdm ED25519 responder alias end cert"
openssl x509 -req -days 3650 -in end_responder_alias_partial.req -CA inter.cert -CAkey inter.key -out end_responder_alias_cert_partial_set.cert -set_serial 3 -extensions v3_end_alias_part -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias_cert_partial_set.cert -out end_responder_alias_cert_partial_set.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der > bundle_responder.certchain_alias_cert_partial_set.der

openssl x509 -req -days 3650 -in end_responder.req -CA end_responder_alias_cert_partial_set.cert -CAkey end_responder_alias_partial.key -out end_responder_alias.cert -set_serial 4 -extensions v3_end_alias_entire -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias.cert -out end_responder_alias.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der end_responder_alias.cert.der > bundle_responder.certchain_alias.der
popd

#=== ed448 Certificate Chains ===
pushd ed448
openssl genpkey -algorithm ed448 -out end_responder_alias_partial.key
openssl req -new -key end_responder_alias_partial.key -out end_responder_alias_partial.req -batch -subj "/CN=DMTF libspdm ED448 responder alias end cert"
openssl x509 -req -days 3650 -in end_responder_alias_partial.req -CA inter.cert -CAkey inter.key -out end_responder_alias_cert_partial_set.cert -set_serial 3 -extensions v3_end_alias_part -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias_cert_partial_set.cert -out end_responder_alias_cert_partial_set.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der > bundle_responder.certchain_alias_cert_partial_set.der

openssl x509 -req -days 3650 -in end_responder.req -CA end_responder_alias_cert_partial_set.cert -CAkey end_responder_alias_partial.key -out end_responder_alias.cert -set_serial 4 -extensions v3_end_alias_entire -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias.cert -out end_responder_alias.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der end_responder_alias.cert.der > bundle_responder.certchain_alias.der
popd

#=== sm2 Certificate Chains ===
pushd sm2
openssl ecparam -genkey -name SM2 -out end_responder_alias_partial.key
openssl req -new -key end_responder_alias_partial.key -out end_responder_alias_partial.req -sha256 -batch -subj "/CN=DMTF libspdm SM2 responder alias end cert"
openssl x509 -req -days 3650 -in end_responder_alias_partial.req -CA inter.cert -CAkey inter.key -out end_responder_alias_cert_partial_set.cert -set_serial 3 -extensions v3_end_alias_part -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias_cert_partial_set.cert -out end_responder_alias_cert_partial_set.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der > bundle_responder.certchain_alias_cert_partial_set.der

openssl x509 -req -days 3650 -in end_responder.req -CA end_responder_alias_cert_partial_set.cert -CAkey end_responder_alias_partial.key -out end_responder_alias.cert -set_serial 4 -extensions v3_end_alias_entire -extfile ../openssl.cnf
openssl asn1parse -in end_responder_alias.cert -out end_responder_alias.cert.der
cat ca.cert.der inter.cert.der end_responder_alias_cert_partial_set.cert.der end_responder_alias.cert.der > bundle_responder.certchain_alias.der
popd


echo "All cert generated, please check the log to ensure that there are no issues."
