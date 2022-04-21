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

# primary key 80000000
# storage key 80000001
# signing key 80000002
# policy session 03000000
# e5 87 c1 1a b5 0f 9d 87 30 f7 21 e3 fe a4 2b 46 
# c0 45 5b 24 6f 96 ae e8 5d 18 eb 3b e6 4d 66 6a 

echo ""
echo "Make and Activate Credential"
echo ""

echo "Use a random number as the credential input"
${PREFIX}getrandom -by 32 -of tmpcredin.bin > run.out
checkSuccess $?

echo "Load the storage key under the primary key, 80000001"
${PREFIX}load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Create a restricted signing key under the primary key"
${PREFIX}create -hp 80000000 -sir -kt f -kt p -opr tmprpriv.bin -opu tmprpub.bin -pwdp sto -pwdk sig -pol policies/policyccactivate.bin > run.out
checkSuccess $?

echo "Load the signing key under the primary key, 80000002"
${PREFIX}load -hp 80000000 -ipr tmprpriv.bin -ipu tmprpub.bin -pwdp sto > run.out
checkSuccess $?

echo "Encrypt the credential using makecredential"
${PREFIX}makecredential -ha 80000001 -icred tmpcredin.bin -in h80000002.bin -ocred tmpcredenc.bin -os tmpsecret.bin > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy command code - activatecredential"
${PREFIX}policycommandcode -ha 03000000 -cc 00000147 > run.out
checkSuccess $?

echo "Activate credential"
${PREFIX}activatecredential -ha 80000002 -hk 80000001 -icred tmpcredenc.bin -is tmpsecret.bin -pwdk sto -ocred tmpcreddec.bin -se0 03000000 0 > run.out
checkSuccess $?

echo "Check the decrypted result"
diff tmpcredin.bin tmpcreddec.bin > run.out
checkSuccess $?

echo "Flush the storage key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo ""
echo "EK Certificate"
echo ""

# The mbedtls port does not support EC certificate creation yet */

if [ ${CRYPTOLIBRARY} == "openssl" ]; then

    echo "Set platform hierarchy auth"
    ${PREFIX}hierarchychangeauth -hi p -pwdn ppp > run.out
    checkSuccess $?

    for ALG in "rsa" "ecc"
    do 

	echo "Create an ${ALG} EK certificate"
	${PREFIX}createekcert -alg ${ALG} -cakey cakey.pem -capwd rrrr -pwdp ppp -of tmp.der > run.out
	checkSuccess $?

	echo "Read the ${ALG} EK certificate"
	${PREFIX}createek -alg ${ALG} -ce > run.out
	checkSuccess $?

	echo "Read the ${ALG} template - should fail"
	${PREFIX}createek -alg ${ALG} -te > run.out
	checkFailure $?

	echo "Read the ${ALG} nonce - should fail"
	${PREFIX}createek -alg ${ALG} -no > run.out
	checkFailure $?

	echo "CreatePrimary and validate the ${ALG} EK against the EK certificate"
	${PREFIX}createek -alg ${ALG} -cp > run.out
	checkSuccess $?

	echo "Validate the ${ALG} EK certificate against the root"
	${PREFIX}createek -alg ${ALG} -root certificates/rootcerts.txt > run.out
	checkSuccess $?

    done

    echo "Clear platform hierarchy auth"
    ${PREFIX}hierarchychangeauth -hi p -pwda ppp > run.out
    checkSuccess $?

# openssl vs mbedtls
fi

echo ""
echo "EK Policies using optional policy in NV"
echo ""

# Section B.8.2	Computing PolicyA - the standard IWG PolicySecret with endorsement auth
# policyiwgek.txt
# 000001514000000B
# (blank line for policyRef)
#
# policymaker -if policies/policyiwgek.txt -ns -halg sha256 -of policies/policyiwgeksha256.bin
# policymaker -if policies/policyiwgek.txt -ns -halg sha384 -of policies/policyiwgeksha384.bin
# policymaker -if policies/policyiwgek.txt -ns -halg sha512 -of policies/policyiwgeksha512.bin

# 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
# 8bbf2266537c171cb56e403c4dc1d4b64f432611dc386e6f532050c3278c930e143e8bb1133824ccb431053871c6db53
# 1e3b76502c8a1425aa0b7b3fc646a1b0fae063b03b5368f9c4cddecaff0891dd682bac1a85d4d832b781ea451915de5fc5bf0dc4a1917cd42fa041e3f998e0ee

# Section B.8.3	Computing Policy Index Names - attributes 220F1008

# For test, put PolicySecret + platform auth in NV Index.  This is NOT the IWG standard, just for test.

# for prepending the hash algorithm identifier to make the TPMT_HA structure
# printf "%b" '\x00\x0b' > policies/sha256.bin
# printf "%b" '\x00\x0c' > policies/sha384.bin
# printf "%b" '\x00\x0d' > policies/sha512.bin

# policymaker -if policies/policysecretp.txt -halg sha256  -pr -of policies/policysecretpsha256.bin -pr
# policymaker -if policies/policysecretp.txt -halg sha384  -pr -of policies/policysecretpsha384.bin -pr
# policymaker -if policies/policysecretp.txt -halg sha512  -pr -of policies/policysecretpsha512.bin -pr

# prepend the algorithm identifiers
# cat policies/sha256.bin policies/policysecretpsha256.bin >! policies/policysecretpsha256ha.bin
# cat policies/sha384.bin policies/policysecretpsha384.bin >! policies/policysecretpsha384ha.bin
# cat policies/sha512.bin policies/policysecretpsha512.bin >! policies/policysecretpsha512ha.bin

# NV Index Name calculation

HALG=(sha256 sha384 sha512)
IDX=(01c07f01 01c07f02 01c07f03) 
SIZ=(34 50 66)
# algorithms from Algorithm Registry
HBIN=(000b 000c 000d)
# Name from Table 14: Policy Index Names
NVNAME=(
    000b0c9d717e9c3fe69fda41769450bb145957f8b3610e084dbf65591a5d11ecd83f
    000cdb62fca346612c976732ff4e8621fb4e858be82586486504f7d02e621f8d7d61ae32cfc60c4d120609ed6768afcf090c
    000d1c47c0bbcbd3cf7d7cae6987d31937c171015dde3b7f0d3c869bca1f7e8a223b9acfadb49b7c9cf14d450f41e9327de34d9291eece2c58ab1dc10e9059cce560
)

for ((i = 0 ; i < 3; i++))
do 

    echo "Undefine optional ${HALG[i]} NV index ${IDX[i]}"
    ${PREFIX}nvundefinespace -ha ${IDX[i]} -hi o > run.out 
    echo " INFO:"

    echo "Define optional ${HALG[i]} NV index ${IDX[i]} with PolicySecret for TPM_RH_ENDORSEMENT"
    ${PREFIX}nvdefinespace -ha ${IDX[i]} -nalg ${HALG[i]} -hi o -pol policies/policyiwgek${HALG[i]}.bin -sz ${SIZ[i]} +at wa +at or +at ppr +at ar -at aw > run.out
    checkSuccess $?

    echo "Start a ${HALG[i]} policy session"
    ${PREFIX}startauthsession -se p -halg ${HALG[i]} > run.out
    checkSuccess $?

    echo "Satisfy the policy"
    ${PREFIX}policysecret -hs 03000000 -ha 4000000B > run.out
    checkSuccess $?

    echo "Get the session digest for debug"
    ${PREFIX}policygetdigest -ha 03000000 > run.out
    checkSuccess $?

    echo "Write the ${HALG[i]} ${IDX[i]} index to set the written bit before reading the Name"
    ${PREFIX}nvwrite -ha ${IDX[i]} -if policies/policysecretp${HALG[i]}ha.bin  -se0 03000000 0 > run.out
    checkSuccess $?

    echo "Read the ${HALG[i]} Name"
    ${PREFIX}nvreadpublic -ha ${IDX[i]} -ns > run.out
    checkSuccess $?

    echo "Verify the ${HALG[i]} Name"
    ACTUAL=`grep ${HBIN[i]} run.out |grep -v nvreadpublic`
    diff <(echo "${ACTUAL}" ) <(echo "${NVNAME[i]}" )
    checkSuccess $?

done

# B.8.4	Computing PolicyC - TPM_CC_PolicyAuthorizeNV || nvIndex->Name)

# policyiwgekcsha256.txt 
# 00000192000b0c9d717e9c3fe69fda41769450bb145957f8b3610e084dbf65591a5d11ecd83f

# policyiwgekcsha384.txt 
# 00000192000cdb62fca346612c976732ff4e8621fb4e858be82586486504f7d02e621f8d7d61ae32cfc60c4d120609ed6768afcf090c

# policyiwgekcsha512.txt 
# 00000192000d1c47c0bbcbd3cf7d7cae6987d31937c171015dde3b7f0d3c869bca1f7e8a223b9acfadb49b7c9cf14d450f41e9327de34d9291eece2c58ab1dc10e9059cce560

# policymaker -if policies/policyiwgekcsha256.txt -ns -halg sha256 -pr -of policies/policyiwgekcsha256.bin
# 3767e2edd43ff45a3a7e1eaefcef78643dca964632e7aad82c673a30d8633fde

# policymaker -if policies/policyiwgekcsha384.txt -ns -halg sha384 -pr -of policies/policyiwgekcsha384.bin
# d6032ce61f2fb3c240eb3cf6a33237ef2b6a16f4293c22b455e261cffd217ad5b4947c2d73e63005eed2dc2b3593d165

# policymaker -if policies/policyiwgekcsha512.txt -ns -halg sha512 -pr -of policies/policyiwgekcsha512.bin
# 589ee1e146544716e8deafe6db247b01b81e9f9c7dd16b814aa159138749105fba5388dd1dea702f35240c184933121e2c61b8f50d3ef91393a49a38c3f73fc8

# B.8.5	Computing PolicyB - TPM_CC_PolicyOR || digests

# policyiwgekbsha256.txt
# 00000171
# 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
# 3767e2edd43ff45a3a7e1eaefcef78643dca964632e7aad82c673a30d8633fde
# policymaker -if policies/policyiwgekbsha256.txt -halg sha256 -pr -of policies/policyiwgekbsha256.bin
 # ca 3d 0a 99 a2 b9 39 06 f7 a3 34 24 14 ef cf b3 
 # a3 85 d4 4c d1 fd 45 90 89 d1 9b 50 71 c0 b7 a0 

# policyiwgekbsha384.txt
# 00000171
# 8bbf2266537c171cb56e403c4dc1d4b64f432611dc386e6f532050c3278c930e143e8bb1133824ccb431053871c6db53
# d6032ce61f2fb3c240eb3cf6a33237ef2b6a16f4293c22b455e261cffd217ad5b4947c2d73e63005eed2dc2b3593d165
# policymaker -if policies/policyiwgekbsha384.txt -halg sha384 -pr -of policies/policyiwgekbsha384.bin
 # b2 6e 7d 28 d1 1a 50 bc 53 d8 82 bc f5 fd 3a 1a 
 # 07 41 48 bb 35 d3 b4 e4 cb 1c 0a d9 bd e4 19 ca 
 # cb 47 ba 09 69 96 46 15 0f 9f c0 00 f3 f8 0e 12 

# policyiwgekbsha512.txt
# 00000171
# 1e3b76502c8a1425aa0b7b3fc646a1b0fae063b03b5368f9c4cddecaff0891dd682bac1a85d4d832b781ea451915de5fc5bf0dc4a1917cd42fa041e3f998e0ee
# 589ee1e146544716e8deafe6db247b01b81e9f9c7dd16b814aa159138749105fba5388dd1dea702f35240c184933121e2c61b8f50d3ef91393a49a38c3f73fc8
# policymaker -if policies/policyiwgekbsha512.txt -halg sha512 -pr -of policies/policyiwgekbsha512.bin
 # b8 22 1c a6 9e 85 50 a4 91 4d e3 fa a6 a1 8c 07 
 # 2c c0 12 08 07 3a 92 8d 5d 66 d5 9e f7 9e 49 a4 
 # 29 c4 1a 6b 26 95 71 d5 7e db 25 fb db 18 38 42 
 # 56 08 b4 13 cd 61 6a 5f 6d b5 b6 07 1a f9 9b ea 

echo ""
echo "Test the EK policies"
echo ""

# test message to be signed
echo -n "1234567890123456" > msg.bin

# Change endorsement and platform hierarchy passwords for testing

echo "Change endorsement hierarchy password"
${PREFIX}hierarchychangeauth -hi e -pwdn eee
checkSuccess $?

echo "Change platform hierarchy password"
${PREFIX}hierarchychangeauth -hi p -pwdn ppp
checkSuccess $?

for ((i = 0 ; i < 3; i++))
do 

    echo "Create an RSA primary key ${HALG[i]} 80000001"
    ${PREFIX}createprimary -si -nalg ${HALG[i]} -pwdk kkk -pol policies/policyiwgekb${HALG[i]}.bin -rsa 2048 > run.out 
    checkSuccess $?

    echo "Start a policy session ${HALG[i]} 03000000"
    ${PREFIX}startauthsession -se p -halg ${HALG[i]} > run.out
    checkSuccess $?

    echo "Satisfy Policy A - Policy Secret with PWAP session and endorsement hierarchy auth"
    ${PREFIX}policysecret -ha 4000000b -hs 03000000 -pwde eee > run.out
    checkSuccess $?

    echo "Get the session digest for debug"
    ${PREFIX}policygetdigest -ha 03000000 > run.out
    checkSuccess $?

    echo "Policy OR ${HALG[i]}"
    ${PREFIX}policyor -ha 03000000 -if policies/policyiwgek${HALG[i]}.bin -if policies/policyiwgekc${HALG[i]}.bin > run.out
    checkSuccess $?

    echo "Get the ${HALG[i]} session digest for debug"
    ${PREFIX}policygetdigest -ha 03000000 > run.out
    checkSuccess $?

    echo "Sign a digest - policy A"
    ${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
    checkSuccess $?

    echo "Policy restart ${HALG[i]} 03000000"
    ${PREFIX}policyrestart -ha 03000000 > run.out 
    checkSuccess $?

    echo "Satisfy NV Index Policy - Policy Secret with PWAP session and platform hierarchy auth"
    ${PREFIX}policysecret -ha 4000000c -hs 03000000 -pwde ppp > run.out
    checkSuccess $?

    echo "Get the ${HALG[i]} session digest for debug"
    ${PREFIX}policygetdigest -ha 03000000 > run.out
    checkSuccess $?

    echo "Satisfy Policy C - Policy Authorize NV"
    ${PREFIX}policyauthorizenv -ha ${IDX[i]} -hs 03000000 > run.out
    checkSuccess $?

    echo "Get the ${HALG[i]} session digest for debug"
    ${PREFIX}policygetdigest -ha 03000000 > run.out
    checkSuccess $?

    echo "Policy OR ${HALG[i]}"
    ${PREFIX}policyor -ha 03000000 -if policies/policyiwgek${HALG[i]}.bin -if policies/policyiwgekc${HALG[i]}.bin > run.out
    checkSuccess $?

    echo "Get the ${HALG[i]} session digest for debug"
    ${PREFIX}policygetdigest -ha 03000000 > run.out
    checkSuccess $?

    echo "Sign a digest - policy A"
    ${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
    checkSuccess $?

    echo "Flush the policy session ${HALG[i]} 03000000"
    ${PREFIX}flushcontext -ha 03000000 > run.out
    checkSuccess $?
    
    echo "Flush the primary key ${HALG[i]} 80000001"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "Cleanup"
echo ""

echo "Reset endorsement hierarchy password"
${PREFIX}hierarchychangeauth -hi e -pwda eee
checkSuccess $?

echo "Reset platform hierarchy password"
${PREFIX}hierarchychangeauth -hi p -pwda ppp
checkSuccess $?

for ((i = 0 ; i < 3; i++))
do 

    echo "Undefine optional ${HALG[i]} NV index ${IDX[i]}"
    ${PREFIX}nvundefinespace -ha ${IDX[i]} -hi o > run.out
    checkSuccess $?

done

rm -f run.out
rm -f sig.bin
rm -f tmprpub.bin
rm -f tmprpriv.bin
rm -f tmpcredin.bin
rm -f tmpcredenc.bin
rm -f tmpcreddec.bin
rm -f tmpsecret.bin
rm -f tmp.der

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 02000000
