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

# 80000001 K1 storage key
# 80000002 K2 signing key to be duplicated
# 80000002 K2 duplicated
# 03000000 policy session

# policy
# be f5 6b 8c 1c c8 4e 11 ed d7 17 52 8d 2c d9 93 
# 56 bd 2b bf 8f 01 52 09 c3 f8 4a ee ab a8 e8 a2 

# used for the name in rewrap

if [ -z $TPM_DATA_DIR ]; then
    TPM_DATA_DIR=.
fi

echo ""
echo "Duplication"
echo ""

echo ""
echo "Duplicate Child Key"
echo ""

# primary key		80000000
# target storage key K1 80000001
#	originally under primary key
#	duplicate to K1
#	import to K1
# signing key        K2 80000002

SALG=(rsa ecc)
SKEY=(rsa2048 ecc)

for ((i = 0 ; i < 2 ; i++))
do
    for ENC in "" "-salg aes -ik tmprnd.bin"
    do 
	for HALG in ${ITERATE_ALGS}
	do

	    echo "Create a signing key K2 under the primary key, with policy"
	    ${PREFIX}create -hp 80000000 -si -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyccduplicate.bin > run.out
	    checkSuccess $?

	    echo "Load the ${SALG[i]} storage key K1 80000001"
	    ${PREFIX}load -hp 80000000 -ipr store${SKEY[i]}priv.bin -ipu store${SKEY[i]}pub.bin -pwdp sto > run.out
	    checkSuccess $?

	    echo "Load the signing key K2 80000002"
	    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
	    checkSuccess $?

	    echo "Sign a digest, $HALG"
	    ${PREFIX}sign -hk 80000002 -halg $HALG -if policies/aaa -os tmpsig.bin -pwdk sig > run.out
	    checkSuccess $?

	    echo "Verify the signature, $HALG"
	    ${PREFIX}verifysignature -hk 80000002 -halg $HALG -if policies/aaa -is tmpsig.bin > run.out
	    checkSuccess $?

	    echo "Start a policy session"
	    ${PREFIX}startauthsession -se p > run.out
	    checkSuccess $?

	    echo "Policy command code, duplicate"
	    ${PREFIX}policycommandcode -ha 03000000 -cc 14b > run.out
	    checkSuccess $?

	    echo "Get policy digest"
	    ${PREFIX}policygetdigest -ha 03000000 > run.out 
	    checkSuccess $?

	    echo "Get random AES encryption key"
	    ${PREFIX}getrandom -by 16 -of tmprnd.bin > run.out 
	    checkSuccess $?

	    echo "Duplicate K2 under ${SALG[i]} K1, ${ENC}"
	    ${PREFIX}duplicate -ho 80000002 -pwdo sig -hp 80000001 -od tmpdup.bin -oss tmpss.bin ${ENC} -se0 03000000 1 > run.out
	    checkSuccess $?

	    echo "Flush the original K2 to free object slot for import"
	    ${PREFIX}flushcontext -ha 80000002 > run.out
	    checkSuccess $?

	    echo "Import K2 under ${SALG[i]} K1, ${ENC}"
	    ${PREFIX}import -hp 80000001 -pwdp sto -ipu tmppub.bin -id tmpdup.bin -iss tmpss.bin ${ENC} -opr tmppriv.bin > run.out
	    checkSuccess $?

	    echo "Sign under K2, $HALG - should fail"
	    ${PREFIX}sign -hk 80000002 -halg $HALG -if policies/aaa -os tmpsig.bin -pwdk sig > run.out
	    checkFailure $?

	    echo "Load the duplicated signing key K2"
	    ${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
	    checkSuccess $?

	    echo "Sign using duplicated K2, $HALG"
	    ${PREFIX}sign -hk 80000002 -halg $HALG -if policies/aaa -os tmpsig.bin -pwdk sig > run.out
	    checkSuccess $?

	    echo "Verify the signature, $HALG"
	    ${PREFIX}verifysignature -hk 80000002 -halg $HALG -if policies/aaa -is tmpsig.bin > run.out
	    checkSuccess $?

	    echo "Flush the duplicated K2"
	    ${PREFIX}flushcontext -ha 80000002 > run.out
	    checkSuccess $?

	    echo "Flush the parent K1"
	    ${PREFIX}flushcontext -ha 80000001 > run.out
	    checkSuccess $?

	    echo "Flush the session"
	    ${PREFIX}flushcontext -ha 03000000 > run.out
	    checkSuccess $?

	done
    done
done

echo ""
echo "Duplicate Primary Key"
echo ""

echo "Create a platform primary signing key K2 80000001"
${PREFIX}createprimary -hi p -si -kt nf -kt np -pol policies/policyccduplicate.bin -opu tmppub.bin > run.out
checkSuccess $?

echo "Sign a digest"
${PREFIX}sign -hk 80000001 -if policies/aaa > run.out
checkSuccess $?

echo "Start a policy session 03000000"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy command code, duplicate"
${PREFIX}policycommandcode -ha 03000000 -cc 14b > run.out
checkSuccess $?

echo "Duplicate K2 under storage key"
${PREFIX}duplicate -ho 80000001 -hp 80000000 -od tmpdup.bin -oss tmpss.bin -se0 03000000 1 > run.out
checkSuccess $?

echo "Import K2 under storage key"
${PREFIX}import -hp 80000000 -pwdp sto -ipu tmppub.bin -id tmpdup.bin -iss tmpss.bin -opr tmppriv.bin > run.out
checkSuccess $?

echo "Load the duplicated signing key K2 80000002"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Sign a digest"
${PREFIX}sign -hk 80000002 -if policies/aaa > run.out
checkSuccess $?

echo "Flush the primary key 8000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the duplicated key 80000002 "
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flush the session 03000000 "
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo ""
echo "Import PEM RSA signing key under RSA and ECC storage key"
echo ""

echo "generate the signing key with openssl"
openssl genrsa -out tmpprivkey.pem -aes256 -passout pass:rrrr 2048 > run.out 2>&1

echo "load the ECC storage key"
${PREFIX}load -hp 80000000 -pwdp sto -ipr storeeccpriv.bin -ipu storeeccpub.bin > run.out
checkSuccess $?

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do
    for HALG in ${ITERATE_ALGS}
    do

	for PARENT in 80000000 80000001
	do

		echo "Import the signing key under the parent key ${PARENT} ${HALG}"
		${PREFIX}importpem -hp ${PARENT} -pwdp sto -ipem tmpprivkey.pem -pwdk rrrr -opu tmppub.bin -opr tmppriv.bin -halg ${HALG} > run.out
		checkSuccess $?

		echo "Load the TPM signing key"
		${PREFIX}load -hp ${PARENT} -pwdp sto -ipu tmppub.bin -ipr tmppriv.bin > run.out
		checkSuccess $?

		echo "Sign the message ${HALG} ${SESS}"
		${PREFIX}sign -hk 80000002 -pwdk rrrr -if policies/aaa -os tmpsig.bin -halg ${HALG} ${SESS} > run.out
		checkSuccess $?

		echo "Verify the signature ${HALG}"
		${PREFIX}verifysignature -hk 80000002 -if policies/aaa -is tmpsig.bin -halg ${HALG} > run.out
		checkSuccess $?

		echo "Flush the signing key"
		${PREFIX}flushcontext -ha 80000002 > run.out
		checkSuccess $?

	done
    done
done

echo ""
echo "Import PEM EC signing key under RSA and ECC storage key"
echo ""

# mbedtls appears to only support the legacy PEM format
# -----BEGIN EC PRIVATE KEY-----
# and not the PKCS8 format
# -----BEGIN ENCRYPTED PRIVATE KEY-----
#

echo "generate the signing key with openssl"
if   [ ${CRYPTOLIBRARY} == "openssl" ]; then
    openssl ecparam -name prime256v1 -genkey -noout | openssl pkey -aes256 -passout pass:rrrr -text > tmpecprivkey.pem 2>&1

elif [ ${CRYPTOLIBRARY} == "mbedtls" ]; then
# plaintext key pair, legacy plaintext -----BEGIN PRIVATE KEY-----
    openssl ecparam -name prime256v1 -genkey -noout | openssl pkey -text -out tmpecprivkeydec.pem > run.out 2>&1
# encrypt key pair, legacy encrypted -----BEGIN EC PRIVATE KEY-----
    openssl ec -aes128 -passout pass:rrrr -in tmpecprivkeydec.pem -out tmpecprivkey.pem > run.out 2>&1

else
    echo "Error: crypto library ${CRYPTOLIBRARY} not supported"
    exit 255
fi

for SESS in "" "-se0 02000000 1"
do
    for HALG in ${ITERATE_ALGS}
    do

	for PARENT in 80000000 80000001
	do

	    echo "Import the signing key under the parent key ${PARENT} ${HALG}"
	    ${PREFIX}importpem -hp ${PARENT} -pwdp sto -ipem tmpecprivkey.pem -ecc -pwdk rrrr -opu tmppub.bin -opr tmppriv.bin -halg ${HALG} > run.out
	    checkSuccess $?

	    echo "Load the TPM signing key"
	    ${PREFIX}load -hp ${PARENT} -pwdp sto -ipu tmppub.bin -ipr tmppriv.bin > run.out
	    checkSuccess $?

	    echo "Sign the message ${HALG} ${SESS}"
	    ${PREFIX}sign -hk 80000002 -salg ecc -pwdk rrrr -if policies/aaa -os tmpsig.bin -halg ${HALG} ${SESS} > run.out
	    checkSuccess $?

	    echo "Verify the signature ${HALG}"
	    ${PREFIX}verifysignature -hk 80000002 -ecc -if policies/aaa -is tmpsig.bin -halg ${HALG} > run.out
	    checkSuccess $?

	    echo "Flush the signing key"
	    ${PREFIX}flushcontext -ha 80000002 > run.out
	    checkSuccess $?

	done
    done
done

echo "Flush the ECC storage key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Rewrap"
echo ""

# duplicate object O1 to K1 (the outer wrapper, knows inner wrapper)
# rewrap O1 from K1 to K2 (does not know inner wrapper)
# import O1 to K2 (knows inner wrapper)

# 03000000 policy session for duplicate

# at TPM 1, duplicate object to K1 outer wrapper, AES wrapper

echo "Create a storage key K2"
${PREFIX}create -hp 80000000 -st -kt f -kt p -opr tmpk2priv.bin -opu tmpk2pub.bin -pwdp sto -pwdk k2 > run.out
checkSuccess $?

echo "Load the storage key K1 80000001 public key "
${PREFIX}loadexternal -hi p -ipu storersa2048pub.bin > run.out
checkSuccess $?

echo "Create a signing key O1 with policy"
${PREFIX}create -hp 80000000 -si -opr tmpsignpriv.bin -opu tmpsignpub.bin -pwdp sto -pwdk sig -pol policies/policyccduplicate.bin > run.out
checkSuccess $?

echo "Load the signing key O1 80000002 under the primary key"
${PREFIX}load -hp 80000000 -ipr tmpsignpriv.bin -ipu tmpsignpub.bin -pwdp sto > run.out
checkSuccess $?

echo "Save the signing key O1 name"
cp ${TPM_DATA_DIR}/h80000002.bin tmpo1name.bin

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy command code, duplicate"
${PREFIX}policycommandcode -ha 03000000 -cc 14b > run.out
checkSuccess $?

echo "Get random AES encryption key"
${PREFIX}getrandom -by 16 -of tmprnd.bin > run.out
checkSuccess $?

echo "Duplicate O1 80000002 under K1 80000001 outer wrapper, using AES inner wrapper"
${PREFIX}duplicate -ho 80000002 -pwdo sig -hp 80000001 -ik tmprnd.bin -od tmpdup.bin -oss tmpss.bin -salg aes -se0 03000000 1 > run.out
checkSuccess $?

echo "Flush signing key O1 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flush storage key K1 80000001 public key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the policy session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

# at TPM 2

echo "Load storage key K1 80000001 public and private key"
${PREFIX}load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Load storage key K2 80000002 public key"
${PREFIX}loadexternal -hi p -ipu tmpk2pub.bin > run.out
checkSuccess $?

echo "Rewrap O1 from K1 80000001 to K2 80000002 "
${PREFIX}rewrap -ho 80000001 -hn 80000002 -pwdo sto -id tmpdup.bin -in tmpo1name.bin -iss tmpss.bin -od tmpdup.bin -oss tmpss.bin > run.out
checkSuccess $?

echo "Flush old key K1 80000001"
${PREFIX}flushcontext -ha 80000002 > run.out 
checkSuccess $?

echo "Flush new key K2 80000002 public key"
${PREFIX}flushcontext -ha 80000001 > run.out 
checkSuccess $?

# at TPM 3

echo "Load storage key K2 80000001 public key"
${PREFIX}load -hp 80000000 -ipr tmpk2priv.bin -ipu tmpk2pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Import rewraped O1 to K2"
${PREFIX}import -hp 80000001 -pwdp k2 -ipu tmpsignpub.bin -id tmpdup.bin -iss tmpss.bin -salg aes -ik tmprnd.bin -opr tmpsignpriv3.bin > run.out
checkSuccess $?

echo "Load the imported signing key O1 80000002 under K2 80000001"
${PREFIX}load -hp 80000001 -ipr tmpsignpriv3.bin -ipu tmpsignpub.bin -pwdp k2 > run.out
checkSuccess $?

echo "Sign using duplicated K2"
${PREFIX}sign -hk 80000002  -if policies/aaa -os tmpsig.bin -pwdk sig > run.out
checkSuccess $?

echo "Verify the signature"
${PREFIX}verifysignature -hk 80000002 -if policies/aaa -is tmpsig.bin > run.out
checkSuccess $?

echo "Flush storage key K2 80000001"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flush signing key O1 80000002"
${PREFIX}flushcontext -ha 80000001 > run.out 
checkSuccess $?

echo ""
echo "Duplicate Primary Sealed AES from Source to Target EK"
echo ""

# source creates AES key, sends to target

# Real code would send the target EK X509 certificate.  The target could
# defer recreating the EK until later.

# Target

# The mbedtls port does not support EC certificate creation yet */

if   [ ${CRYPTOLIBRARY} == "openssl" ]; then
    for ((i = 0 ; i < 2 ; i++))
    do

	echo "Target: Provision a target ${SALG[i]} EK certificate"
	${PREFIX}createekcert -alg ${SALG[i]} -cakey cakey.pem -capwd rrrr > run.out
	checkSuccess $?

	echo "Target: Recreate the ${SALG[i]} EK at 80000001"
	${PREFIX}createek -alg ${SALG[i]} -cp -noflush > run.out
	checkSuccess $?

	echo "Target: Convert the EK public key to PEM format for transmission to source"
	${PREFIX}readpublic -ho 80000001 -opem tmpekpub.pem > run.out
	checkSuccess $?

	echo "Target: Flush the EK"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

# Here, target would send the EK PEM public key to the source

# The real source would
#
# 1 - walk the EK X509 certificate chain.  I have to add that sample code to createEK or make a new utility.
# 2 - use openssl to convert the X509 EK certificate the the PEM public key file
# 
# for now, the source trusts the target EK PEM public key

# Source

	echo "Source: Create an AES 256 bit key"
	${PREFIX}getrandom -by 32 -ns -of tmpaeskeysrc.bin > run.out
	checkSuccess $?

	echo "Source: Create primary duplicable sealed AES key 80000001"
	${PREFIX}createprimary -bl -kt nf -kt np -if tmpaeskeysrc.bin -pol policies/policyccduplicate.bin -opu tmpsdbpub.bin > run.out
	checkSuccess $?

	echo "Source: Load the target ${SALG[i]} EK public key as a storage key 80000002"
	${PREFIX}loadexternal -${SALG[i]} -st -ipem tmpekpub.pem > run.out
	checkSuccess $?

	echo "Source: Start a policy session, duplicate needs a policy 03000000"
	${PREFIX}startauthsession -se p > run.out
	checkSuccess $?

	echo "Source: Policy command code, duplicate"
	${PREFIX}policycommandcode -ha 03000000 -cc 14b > run.out
	checkSuccess $?

	echo "Source: Read policy digest, for debug"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Source: Wrap the sealed AES key with the target EK public key"
	${PREFIX}duplicate -ho 80000001 -hp 80000002 -od tmpsdbdup.bin -oss tmpss.bin -se0 03000000 0 > run.out
	checkSuccess $?

	echo "Source: Flush the sealed AES key 80000001"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

	echo "Source: Flush the EK public key 80000002"
	${PREFIX}flushcontext -ha 80000002 > run.out
	checkSuccess $?

# Transmit the sealed AEK key wrapped with the target EK back to the target
# tmpsdbdup.bin private part wrapped in EK public key, via symmetric seed
# tmpsdbpub.bin public part 
# tmpss.bin symmetric seed, encrypted with EK public key

# Target

# NOTE This assumes that the endorsement hierarchy password is Empty.
# This may be a bad assumption if an attacker can get access and
# change it.

	echo "Target: Recreate the -${SALG[i]} EK at 80000001"
	${PREFIX}createek -alg ${SALG[i]} -cp -noflush > run.out
	checkSuccess $?

	echo "Target: Start a policy session, EK use needs a policy"
	${PREFIX}startauthsession -se p > run.out
	checkSuccess $?

	echo "Target: Policy Secret with PWAP session and (Empty) endorsement auth"
	${PREFIX}policysecret -ha 4000000b -hs 03000000 -pwde "" > run.out
	checkSuccess $?

	echo "Target: Read policy digest for debug"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Target: Import the sealed AES key under the EK storage key"
	${PREFIX}import -hp 80000001 -ipu tmpsdbpub.bin -id tmpsdbdup.bin -iss tmpss.bin -opr tmpsdbpriv.bin -se0 03000000 1 > run.out
	checkSuccess $?

	echo "Target: Restart the policy session"
	${PREFIX}policyrestart -ha 03000000 > run.out
	checkSuccess $?

	echo "Target: Policy Secret with PWAP session and (Empty) endorsement auth"
	${PREFIX}policysecret -ha 4000000b -hs 03000000 -pwde "" > run.out
	checkSuccess $?

	echo "Target: Read policy digest for debug"
	${PREFIX}policygetdigest -ha 03000000 > run.out
	checkSuccess $?

	echo "Target: Load the sealed AES key under the EK storage key"
	${PREFIX}load -hp 80000001 -ipu tmpsdbpub.bin -ipr tmpsdbpriv.bin -se0 03000000 1 > run.out
	checkSuccess $?

	echo "Target: Unseal the AES key"
	${PREFIX}unseal -ha 80000002 -of tmpaeskeytgt.bin > run.out
	checkSuccess $?

# A real target would not have access to tmpaeskeysrc.bin for the compare

	echo "Target: Verify the unsealed result, same at source, for debug"
	diff tmpaeskeytgt.bin tmpaeskeysrc.bin > run.out
	checkSuccess $?

	echo "Flush the EK"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

	echo "Flush the sealed AES key"
	${PREFIX}flushcontext -ha 80000002 > run.out
	checkSuccess $?

	echo "Flush the policy session"
	${PREFIX}flushcontext -ha 03000000 > run.out
	checkSuccess $?

    done

# cleanup
    
echo "Undefine the RSA EK certificate index"
${PREFIX}nvundefinespace -hi p -ha 01c00002
checkSuccess $?

echo "Undefine the ECC EK certificate index"
${PREFIX}nvundefinespace -hi p -ha 01c0000a
checkSuccess $?

fi

rm -f tmpo1name.bin
rm -f tmpsignpriv.bin
rm -f tmpsignpub.bin
rm -f tmprnd.bin
rm -f tmpdup.bin
rm -f tmpss.bin
rm -f tmpsignpriv3.bin
rm -f tmpsig.bin
rm -f tmpk2priv.bin
rm -f tmpk2pub.bin
rm -f tmposs.bin 
rm -f tmpprivkey.pem
rm -f tmpecprivkey.pem
rm -f tmpecprivkeydec.pem
rm -f tmppub.bin
rm -f tmppriv.bin
rm -f tmpekpub.pem
rm -f tmpaeskeysrc.bin
rm -f tmpsdbpub.bin
rm -f tmpsdbdup.bin
rm -f tmpss.bin
rm -f tmpsdbpriv.bin
rm -f tmpaeskeytgt.bin

# ${PREFIX}flushcontext -ha 80000001
# ${PREFIX}flushcontext -ha 80000002
# ${PREFIX}flushcontext -ha 03000000

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 03000000
