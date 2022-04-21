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

# openssl keys to use in this file

echo ""
echo "Test RSA"
echo ""

for BITS in 2048 3072
do

    echo "generate the RSA $BITS encryption key with openssl"
    openssl genrsa -out tmpkeypairrsa${BITS}.pem -aes256 -passout pass:rrrr 2048 > run.out 2>&1

    echo "Convert key pair to plaintext DER format"
    openssl rsa -inform pem -outform der -in tmpkeypairrsa${BITS}.pem -out tmpkeypairrsa${BITS}.der -passin pass:rrrr > run.out 2>&1

done

echo ""
echo "RSA decryption key"
echo ""

for BITS in 2048 3072
do

    echo "Load the RSA $BITS decryption key under the primary key"
    ${PREFIX}load -hp 80000000 -ipr derrsa${BITS}priv.bin -ipu derrsa${BITS}pub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "RSA encrypt with the $BITS encryption key"
    ${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
    checkSuccess $?

    echo "RSA decrypt with the ${BITS} decryption key"
    ${PREFIX}rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin -pwdk dec > run.out
    checkSuccess $?

    echo "Verify the decrypt result"
    tail -c 3 dec.bin > tmp.bin
    diff policies/aaa tmp.bin > run.out
    checkSuccess $?

    echo "Flush the $BITS decryption key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "RSA decryption key to sign with OID"
echo ""

for BITS in 2048 3072
do

    echo "Load the RSA $BITS decryption key"
    ${PREFIX}load -hp 80000000 -ipu derrsa${BITS}pub.bin -ipr derrsa${BITS}priv.bin -pwdp sto > run.out
    checkSuccess $?

    HALG=(${ITERATE_ALGS})
    HSIZ=("20" "32" "48" "64")

    for ((i = 0 ; i < 4 ; i++))
    do

	echo "Decrypt/Sign with a caller specified OID - ${HALG[i]}"
	${PREFIX}rsadecrypt -hk 80000001 -pwdk dec -ie policies/${HALG[i]}aaa.bin -od tmpsig.bin -oid ${HALG[i]} > run.out
	checkSuccess $?

	echo "Encrypt/Verify - ${HALG[i]}"
	${PREFIX}rsaencrypt -hk 80000001 -id tmpsig.bin -oe tmpmsg.bin > run.out
	checkSuccess $?

	echo "Verify Result - ${HALG[i]} ${HSIZ[i]} bytes"
	tail -c ${HSIZ[i]} tmpmsg.bin > tmpdig.bin
	diff tmpdig.bin policies/${HALG[i]}aaa.bin > run.out
	checkSuccess $?

    done

    echo "Flush the RSA ${BITS} decryption key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "Import PEM RSA encryption key"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for BITS in 2048 3072
do

    for SESS in "" "-se0 02000000 1"
    do

	echo "Import the $BITS encryption key under the primary key"
	${PREFIX}importpem -hp 80000000 -den -pwdp sto -ipem tmpkeypairrsa${BITS}.pem -pwdk rrrr -opu tmppub.bin -opr tmppriv.bin > run.out
	checkSuccess $?

	echo "Load the TPM encryption key"
	${PREFIX}load -hp 80000000 -pwdp sto -ipu tmppub.bin -ipr tmppriv.bin > run.out
	checkSuccess $?

	echo "Sign the message ${SESS} - should fail"
	${PREFIX}sign -hk 80000001 -pwdk rrrr -if policies/aaa -os tmpsig.bin ${SESS} > run.out
	checkFailure $?

	echo "RSA encrypt with the encryption key"
	${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
	checkSuccess $?

	echo "RSA decrypt with the decryption key ${SESS}"
	${PREFIX}rsadecrypt -hk 80000001 -pwdk rrrr -ie enc.bin -od dec.bin ${SESS} > run.out
	checkSuccess $?

	echo "Verify the decrypt result"
	tail -c 3 dec.bin > tmp.bin
	diff policies/aaa tmp.bin > run.out
	checkSuccess $?

	echo "Flush the encryption key"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

    done

done

echo "Flush the session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Loadexternal DER encryption key"
echo ""

for BITS in 2048 3072
do

    echo "Start an HMAC auth session"
    ${PREFIX}startauthsession -se h > run.out
    checkSuccess $?

    for SESS in "" "-se0 02000000 1"
    do

	echo "Load the openssl key pair in the NULL hierarchy 80000001"
	${PREFIX}loadexternal -den -ider tmpkeypairrsa${BITS}.der -pwdk rrrr > run.out
	checkSuccess $?

	echo "RSA encrypt with the encryption key"
	${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
	checkSuccess $?

	echo "RSA decrypt with the decryption key ${SESS}"
	${PREFIX}rsadecrypt -hk 80000001 -pwdk rrrr -ie enc.bin -od dec.bin ${SESS} > run.out
	checkSuccess $?

	echo "Verify the decrypt result"
	tail -c 3 dec.bin > tmp.bin
	diff policies/aaa tmp.bin > run.out
	checkSuccess $?

	echo "Flush the encryption key"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

    done

    echo "Flush the session"
    ${PREFIX}flushcontext -ha 02000000 > run.out
    checkSuccess $?

done

echo ""
echo "Encrypt with OpenSSL OAEP, decrypt with TPM"
echo ""

echo "Create OAEP encryption key"
${PREFIX}create -hp 80000000 -pwdp sto -deo -kt f -kt p -halg sha1 -opr tmpprivkey.bin -opu tmppubkey.bin -opem tmppubkey.pem > run.out	
checkSuccess $?

echo "Load encryption key at 80000001"
${PREFIX}load -hp 80000000 -pwdp sto -ipr tmpprivkey.bin -ipu tmppubkey.bin  > run.out
checkSuccess $?

echo "Encrypt using OpenSSL and the PEM public key"
openssl rsautl -oaep -encrypt -inkey tmppubkey.pem -pubin -in policies/aaa -out enc.bin > run.out 2>&1
checkSuccess $?

echo "Decrypt using TPM key at 80000001"
${PREFIX}rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin > run.out
checkSuccess $?

echo "Verify the decrypt result"
diff policies/aaa dec.bin > run.out
checkSuccess $?

echo "Flush the encryption key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Child RSA decryption key RSAES"
echo ""

echo "Create RSAES encryption key"
${PREFIX}create -hp 80000000 -pwdp sto -dee -opr deepriv.bin -opu deepub.bin > run.out	
checkSuccess $?

echo "Load encryption key at 80000001"
${PREFIX}load -hp 80000000 -pwdp sto -ipr deepriv.bin -ipu deepub.bin > run.out
checkSuccess $?

echo "RSA encrypt with the encryption key"
${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
checkSuccess $?

echo "RSA decrypt with the decryption key"
${PREFIX}rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin > run.out
checkSuccess $?

echo "Verify the decrypt result"
tail -c 3 dec.bin > tmp.bin
diff policies/aaa tmp.bin > run.out
checkSuccess $?

echo "Flush the encryption key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Primary RSA decryption key RSAES"
echo ""

echo "Create Primary RSAES encryption key"
${PREFIX}createprimary -hi p -dee -halg sha256 -opem tmppubkey.pem > run.out	
checkSuccess $?

echo "RSA encrypt with the encryption key"
${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
checkSuccess $?

echo "RSA decrypt with the decryption key"
${PREFIX}rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin > run.out
checkSuccess $?

echo "Verify the decrypt result"
tail -c 3 dec.bin > tmp.bin
diff policies/aaa tmp.bin > run.out
checkSuccess $?

echo "Flush the encryption key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Primary Create Loaded RSA decryption key RSAES"
echo ""

echo "CreateLoaded primary key, storage parent 80000001"
${PREFIX}createloaded -hp 40000001 -dee > run.out
checkSuccess $?

echo "RSA encrypt with the encryption key"
${PREFIX}rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
checkSuccess $?

echo "RSA decrypt with the decryption key"
${PREFIX}rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin > run.out
checkSuccess $?

echo "Verify the decrypt result"
tail -c 3 dec.bin > tmp.bin
diff policies/aaa tmp.bin > run.out
checkSuccess $?

echo "Flush the encryption key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

# cleanup

rm -f tmp.bin
rm -f enc.bin
rm -f dec.bin
rm -f deepriv.bin
rm -f deepub.bin
rm -f tmpmsg.bin
rm -f tmpdig.bin
rm -f tmpsig.bin
rm -f tmpkeypairrsa2048.der
rm -f tmpkeypairrsa2048.pem
rm -f tmpkeypairrsa3072.der
rm -f tmpkeypairrsa3072.pem
rm -f tmppubkey.bin
rm -f tmppubkey.pem
rm -f tmpprivkey.bin 

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 02000000

# ${PREFIX}flushcontext -ha 80000001
