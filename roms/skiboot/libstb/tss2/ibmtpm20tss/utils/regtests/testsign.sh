#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2015 - 2020					#
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################

echo ""
echo "RSA Signing key"
echo ""

for BITS in 2048 3072
do

    echo "Create an RSA $BITS key pair in PEM format using openssl"
    openssl genrsa -out tmpkeypairrsa${BITS}.pem -aes256 -passout pass:rrrr 2048 > run.out 2>&1

    echo "Convert RSA $BITS key pair to plaintext DER format"
    openssl rsa -inform pem -outform der -in tmpkeypairrsa${BITS}.pem -out tmpkeypairrsa${BITS}.der -passin pass:rrrr > run.out 2>&1

    echo "Load the RSA $BITS signing key under the primary key"
    ${PREFIX}load -hp 80000000 -ipr signrsa${BITS}priv.bin -ipu signrsa${BITS}pub.bin -pwdp sto > run.out
    checkSuccess $?

    for HALG in ${ITERATE_ALGS}
    do

	for SCHEME in rsassa rsapss
	do

	    echo "Sign a digest - $HALG $SCHEME $BITS"
	    ${PREFIX}sign -hk 80000001 -halg $HALG -scheme $SCHEME -if policies/aaa -os sig.bin -pwdk sig -ipu signrsa${BITS}pub.bin > run.out
	    checkSuccess $?

	    echo "Verify the signature using the TPM - $HALG"
	    ${PREFIX}verifysignature -hk 80000001 -halg $HALG -if policies/aaa -is sig.bin > run.out
	    checkSuccess $?

	    echo "Verify the signature using PEM - $HALG"
	    ${PREFIX}verifysignature -ipem signrsa${BITS}pub.pem -halg $HALG -if policies/aaa -is sig.bin > run.out
	    checkSuccess $?

	    echo "Read the public part"
	    ${PREFIX}readpublic -ho 80000001 -opem tmppub.pem > run.out
	    checkSuccess $?

	    echo "Verify the signature using readpublic PEM - $HALG"
	    ${PREFIX}verifysignature -ipem tmppub.pem -halg $HALG -if policies/aaa -is sig.bin > run.out
	    checkSuccess $?

	    echo "Load the openssl key pair in the NULL hierarchy 80000002 - $HALG $SCHEME $BITS"
	    ${PREFIX}loadexternal -halg $HALG -scheme $SCHEME -ider tmpkeypairrsa${BITS}.der > run.out
	    checkSuccess $?

	    echo "Use the TPM as a crypto coprocessor to sign - $HALG $SCHEME" 
	    ${PREFIX}sign -hk 80000002 -halg $HALG -scheme $SCHEME -if policies/aaa -os sig.bin > run.out
	    checkSuccess $?

	    echo "Verify the signature - $HALG"
	    ${PREFIX}verifysignature -hk 80000002 -halg $HALG -if policies/aaa -is sig.bin > run.out
	    checkSuccess $?

	    echo "Flush the openssl signing key"
	    ${PREFIX}flushcontext -ha 80000002 > run.out
	    checkSuccess $?

	done
    
    done

    echo "Flush the RSA signing key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "ECC Signing key"
echo ""

echo "Load the ECC signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr signeccpriv.bin -ipu signeccpub.bin -pwdp sto > run.out
checkSuccess $?

echo "Create an ECC key pair in PEM format using openssl"
  
openssl ecparam -name prime256v1 -genkey -noout -out tmpkeypairecc.pem > run.out 2>&1

echo "Convert key pair to plaintext DER format"

openssl ec -inform pem -outform der -in tmpkeypairecc.pem -out tmpkeypairecc.der -passin pass:rrrr > run.out 2>&1

for HALG in ${ITERATE_ALGS}
do

    echo "Sign a digest - $HALG"
    ${PREFIX}sign -hk 80000001 -halg $HALG -salg ecc -if policies/aaa -os sig.bin -pwdk sig > run.out
    checkSuccess $?

    echo "Verify the ECC signature using the TPM - $HALG"
    ${PREFIX}verifysignature -hk 80000001 -halg $HALG -ecc -if policies/aaa -is sig.bin > run.out
    checkSuccess $?

    echo "Verify the signature using PEM - $HALG"
    ${PREFIX}verifysignature -ipem signeccpub.pem -halg $HALG -if policies/aaa -is sig.bin > run.out
    checkSuccess $?

    echo "Read the public part"
    ${PREFIX}readpublic -ho 80000001 -opem tmppub.pem > run.out
    checkSuccess $?

    echo "Verify the signature using readpublic PEM - $HALG"
    ${PREFIX}verifysignature -ipem tmppub.pem -halg $HALG -if policies/aaa -is sig.bin > run.out
    checkSuccess $?

    echo "Load the openssl key pair in the NULL hierarchy 80000002 - $HALG"
    ${PREFIX}loadexternal -halg $HALG -ecc -ider tmpkeypairecc.der > run.out
    checkSuccess $?

    echo "Use the TPM as a crypto coprocessor to sign - $HALG" 
    ${PREFIX}sign -hk 80000002 -halg $HALG -salg ecc -if policies/aaa -os sig.bin > run.out
    checkSuccess $?

    echo "Verify the signature - $HALG"
    ${PREFIX}verifysignature -hk 80000002 -halg $HALG -ecc -if policies/aaa -is sig.bin > run.out
    checkSuccess $?

    echo "Flush the openssl signing key"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

done

echo "Flush the ECC signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Primary RSA Signing Key"
echo ""

echo "Create primary signing key - RSA 80000001"
${PREFIX}createprimary -si -opu tmppub.bin -opem tmppub.pem -pwdk sig > run.out
checkSuccess $?

for HALG in ${ITERATE_ALGS}
do
    
    echo "Sign a digest - $HALG"
    ${PREFIX}sign -hk 80000001 -halg $HALG -if policies/aaa -os sig.bin -pwdk sig -ipu tmppub.bin > run.out
    checkSuccess $?

    echo "Verify the signature - $HALG"
    ${PREFIX}verifysignature -hk 80000001 -halg $HALG -if policies/aaa -is sig.bin > run.out
    checkSuccess $?

    echo "Verify the signature using PEM - $HALG"
    ${PREFIX}verifysignature -ipem tmppub.pem -halg $HALG -if policies/aaa -is sig.bin > run.out
    checkSuccess $?

    echo "Read the public part and convert to PEM"
    ${PREFIX}readpublic -ho 80000001 -opem tmppub.pem > run.out
    checkSuccess $?

    echo "Verify the signature using readpublic PEM - $HALG"
    ${PREFIX}verifysignature -ipem tmppub.pem -halg $HALG -if policies/aaa -is sig.bin > run.out
    checkSuccess $?

    echo "Convert TPM public key to PEM"
    ${PREFIX}tpm2pem -ipu tmppub.bin -opem tmppub.pem > run.out
    checkSuccess $?

    echo "Verify the signature using createprimary converted PEM - $HALG"
    ${PREFIX}verifysignature -ipem tmppub.pem -halg $HALG -if policies/aaa -is sig.bin > run.out
    checkSuccess $?

done

echo "Flush the primary signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Primary ECC Signing Key"
echo ""

echo "Create primary signing key - ECC 80000001"
${PREFIX}createprimary -si -opu tmppub.bin -opem tmppub.pem -ecc nistp256 -pwdk sig > run.out
checkSuccess $?

for HALG in ${ITERATE_ALGS}
do
    
    echo "Sign a digest - $HALG"
    ${PREFIX}sign -hk 80000001 -halg $HALG -salg ecc -if policies/aaa -os sig.bin -pwdk sig > run.out 
    checkSuccess $?

    echo "Verify the signature - $HALG"
    ${PREFIX}verifysignature -hk 80000001 -halg $HALG -if policies/aaa -is sig.bin > run.out
    checkSuccess $?

    echo "Verify the signature using PEM - $HALG"
    ${PREFIX}verifysignature -ipem tmppub.pem -halg $HALG -if policies/aaa -is sig.bin > run.out
    checkSuccess $?

    echo "Read the public part"
    ${PREFIX}readpublic -ho 80000001 -opem tmppub.pem > run.out
    checkSuccess $?

    echo "Verify the signature using readpublic PEM - $HALG"
    ${PREFIX}verifysignature -ipem tmppub.pem -halg $HALG -if policies/aaa -is sig.bin > run.out
    checkSuccess $?

    echo "Convert TPM public key to PEM"
    ${PREFIX}tpm2pem -ipu tmppub.bin -opem tmppub.pem > run.out
    checkSuccess $?

    echo "Verify the signature using createprimary converted PEM - $HALG"
    ${PREFIX}verifysignature -ipem tmppub.pem -halg $HALG -if policies/aaa -is sig.bin > run.out
    checkSuccess $?

done

echo "Flush the primary signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Restricted Signing Key"
echo ""

echo "Create primary signing key - restricted"
${PREFIX}createprimary -sir -opu tmppub.bin -pwdk sig > run.out
checkSuccess $?

echo "Sign a digest - SHA256 - should fail TPM_RC_TICKET"
${PREFIX}sign -hk 80000001 -halg sha256  -if policies/aaa -os sig.bin -pwdk sig -ipu tmppub.bin > run.out
checkFailure $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "External Verification Key"
echo ""

# create rsaprivkey.pem
# > openssl genrsa -out rsaprivkey.pem -aes256 -passout pass:rrrr 2048
# convert to der
# > openssl rsa -inform pem -outform der -in rsaprivkey.pem -out rsaprivkey.der -passin pass:rrrr
# extract the public key
# > openssl pkey -inform pem -outform pem -in rsaprivkey.pem -passin pass:rrrr -pubout -out rsapubkey.pem 
# sign a test message msg.bin
# > openssl dgst -sha1 -sign rsaprivkey.pem -passin pass:rrrr -out pssig.bin msg.bin

echo "Load external just the public part of PEM RSA"
${PREFIX}loadexternal -halg sha1 -nalg sha1 -ipem policies/rsapubkey.pem > run.out
checkSuccess $?

echo "Sign a test message with openssl RSA"
openssl dgst -sha1 -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin msg.bin > run.out 2>&1

echo "Verify the RSA signature"
${PREFIX}verifysignature -hk 80000001 -halg sha1 -if msg.bin -is pssig.bin -raw > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

# generate the p256 key
# > openssl ecparam -name prime256v1 -genkey -noout -out p256privkey.pem
# extract public key
# > openssl pkey -inform pem -outform pem -in p256privkey.pem -pubout -out p256pubkey.pem

echo "Load external just the public part of PEM ECC"
${PREFIX}loadexternal -halg sha1 -nalg sha1 -ipem policies/p256pubkey.pem -ecc > run.out
checkSuccess $?

echo "Sign a test message with openssl ECC"
openssl dgst -sha1 -sign policies/p256privkey.pem -out pssig.bin msg.bin > run.out 2>&1

echo "Verify the ECC signature"
${PREFIX}verifysignature -hk 80000001 -halg sha1 -if msg.bin -is pssig.bin -raw -ecc > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Sign with restricted HMAC key"
echo ""

for HALG in ${ITERATE_ALGS}

do

    echo "Create a ${HALG} restricted keyed hash key under the primary key"
    ${PREFIX}create -hp 80000000 -khr -kt f -kt p -opr khrpriv${HALG}.bin -opu khrpub${HALG}.bin -pwdp sto -pwdk khk -halg ${HALG} > run.out
    checkSuccess $?

    echo "Load the signing key under the primary key 80000001"
    ${PREFIX}load -hp 80000000 -ipr  khrpriv${HALG}.bin -ipu khrpub${HALG}.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Hash and create ticket"
    ${PREFIX}hash -hi p -halg ${HALG} -if msg.bin -tk tkt.bin > run.out
    checkSuccess $?

    echo "Sign a digest with a restricted signing key and ticket"
    ${PREFIX}sign -hk 80000001 -halg ${HALG} -salg hmac -if msg.bin -tk tkt.bin -os sig.bin -pwdk khk > run.out
    checkSuccess $?

    echo "Sign a digest with a restricted signing key and no ticket - should fail"
    ${PREFIX}sign -hk 80000001 -halg ${HALG} -salg hmac -if msg.bin -os sig.bin -pwdk khk > run.out
    checkFailure $?
    
    echo "Flush the signing key 80000001 "
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "Sign with unrestricted HMAC key"
echo ""

for HALG in ${ITERATE_ALGS}

do

    echo "Create a ${HALG} unrestricted keyed hash key under the primary key"
    ${PREFIX}create -hp 80000000 -kh -kt f -kt p -opr khpriv${HALG}.bin -opu khpub${HALG}.bin -pwdp sto -pwdk khk -halg ${HALG} > run.out
    checkSuccess $?

    echo "Load the signing key under the primary key 80000001"
    ${PREFIX}load -hp 80000000 -ipr  khpriv${HALG}.bin -ipu khpub${HALG}.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Hash"
    ${PREFIX}hash -hi p -halg ${HALG} -if msg.bin > run.out
    checkSuccess $?

    echo "Sign a digest with an unrestricted signing key"
    ${PREFIX}sign -hk 80000001 -halg ${HALG} -salg hmac -if msg.bin -os sig.bin -pwdk khk > run.out
    checkSuccess $?
    
    echo "Flush the signing key 80000001 "
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

rm -f tmpkeypairrsa2048.pem
rm -f tmpkeypairrsa2048.der
rm -f tmpkeypairrsa3072.pem
rm -f tmpkeypairrsa3072.der
rm -f tmpkeypairecc.pem
rm -f tmpkeypairecc.der
rm -r pssig.bin
rm -r tmppub.bin
rm -r tmppub.pem

# ${PREFIX}getcapability  -cap 1 -pr 80000000
# ${PREFIX}getcapability  -cap 1 -pr 02000000
