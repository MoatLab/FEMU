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

# used for the name in policy ticket

if [ -z $TPM_DATA_DIR ]; then
    TPM_DATA_DIR=.
fi


echo ""
echo "Policy Command Code"
echo ""

echo "Create a signing key under the primary key - policy command code - sign"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyccsign.bin > run.out
checkSuccess $?

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Sign a digest"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -pwdk sig > run.out
checkSuccess $?

# sign with correct policy command code
# cc69 18b2 2627 3b08 f5bd 406d 7f10 cf16
# 0f0a 7d13 dfd8 3b77 70cc bcd1 aa80 d811

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Sign a digest - policy, should fail"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
checkFailure $?

echo "Policy command code - sign"
${PREFIX}policycommandcode -ha 03000000 -cc 15d > run.out
checkSuccess $?

echo "Policy get digest - should be cc69 ..."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Sign a digest - policy and wrong password"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk xxx > run.out
checkSuccess $?

echo "Sign a digest - policy, should fail, session used "
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
checkFailure $?

# quote with bad policy or bad command 

# echo "Start a policy session"
# ${PREFIX}startauthsession -se p > run.out
# checkSuccess $?

echo "Policy command code - sign"
${PREFIX}policycommandcode -ha 03000000 -cc 15d > run.out
checkSuccess $?

echo "Quote - PWAP"
${PREFIX}quote -hp 0 -hk 80000001 -os sig.bin -pwdk sig > run.out
checkSuccess $?

echo "Quote - policy, should fail"
${PREFIX}quote -hp 0 -hk 80000001 -os sig.bin -se0 03000000 1 > run.out
checkFailure $?

echo "Policy restart, set back to zero"
${PREFIX}policyrestart -ha 03000000 > run.out 
checkSuccess $?

# echo "Flush the session"
# ${PREFIX}flushcontext -ha 03000000 > run.out
# checkSuccess $?

# echo "Start a policy session"
# ${PREFIX}startauthsession -se p > run.out
# checkSuccess $?

echo "Policy command code - quote"
${PREFIX}policycommandcode -ha 03000000 -cc 158 > run.out
checkSuccess $?

echo "Quote - policy, should fail"
${PREFIX}quote -hp 0 -hk 80000001 -os sig.bin -se0 03000000 1 > run.out
checkFailure $?

# echo "Flush the session"
# ${PREFIX}flushcontext -ha 03000000 > run.out
# checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Policy Command Code and Policy Password / Authvalue"
echo ""

echo "Create a signing key under the primary key - policy command code - sign, auth"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyccsign-auth.bin > run.out
checkSuccess $?

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

# policypassword

echo "Policy restart, set back to zero"
${PREFIX}policyrestart -ha 03000000 > run.out 
checkSuccess $?

echo "Sign a digest - policy, should fail"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
checkFailure $?

echo "Policy command code - sign"
${PREFIX}policycommandcode -ha 03000000 -cc 15d > run.out
checkSuccess $?

echo "Sign a digest - policy, should fail"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
checkFailure $?

echo "Policy password"
${PREFIX}policypassword -ha 03000000 > run.out
checkSuccess $?

echo "Sign a digest - policy, no password should fail"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
checkFailure $?

echo "Sign a digest - policy, password"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk sig > run.out
checkSuccess $?

# policyauthvalue

# echo "Start a policy session"
# ${PREFIX}startauthsession -se p > run.out
# checkSuccess $?

echo "Policy command code - sign"
${PREFIX}policycommandcode -ha 03000000 -cc 15d > run.out
checkSuccess $?

echo "Policy authvalue"
${PREFIX}policyauthvalue -ha 03000000 > run.out
checkSuccess $?

echo "Sign a digest - policy, no password should fail"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
checkFailure $?

echo "Sign a digest - policy, password"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 -pwdk sig > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Policy Password and Policy Authvalue flags"
echo ""

for COMMAND in policypassword policyauthvalue 

do

    echo "Create a signing key under the primary key - policy command code - sign, auth"
    ${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyccsign-auth.bin > run.out
    checkSuccess $?

    echo "Load the signing key under the primary key"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Start a policy session"
    ${PREFIX}startauthsession -se p > run.out
    checkSuccess $?

    echo "Policy command code - sign"
    ${PREFIX}policycommandcode -ha 03000000 -cc 15d > run.out
    checkSuccess $?

    echo "Policy ${COMMAND}"
    ${PREFIX}${COMMAND} -ha 03000000 > run.out
    checkSuccess $?

    echo "Sign a digest - policy, password"
    ${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk sig > run.out
    checkSuccess $?

    echo "Flush signing key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Create a signing key under the primary key - policy command code - sign"
    ${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyccsign.bin > run.out
    checkSuccess $?

    echo "Load the signing key under the primary key"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Policy command code - sign"
    ${PREFIX}policycommandcode -ha 03000000 -cc 15d > run.out
    checkSuccess $?

    echo "Sign a digest - policy and wrong password"
    ${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk xxx > run.out
    checkSuccess $?

    echo "Flush signing key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Flush policy session"
    ${PREFIX}flushcontext -ha 03000000 > run.out
    checkSuccess $?

done

echo ""
echo "Policy Signed"
echo ""

# create rsaprivkey.pem
# > openssl genrsa -out rsaprivkey.pem -aes256 -passout pass:rrrr 2048
# extract the public key
# > openssl pkey -inform pem -outform pem -in rsaprivkey.pem -passin pass:rrrr -pubout -out rsapubkey.pem 
# sign a test message msg.bin
# > openssl dgst -sha1 -sign rsaprivkey.pem -passin pass:rrrr -out pssig.bin msg.bin
#
# create the policy:
# use loadexternal -ns to get the name

# sha1
# 00044234c24fc1b9de6693a62453417d2734d7538f6f
# sha256
# 000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
# sha384
# 000ca8bfb42e75b4c22b366b372cd9994bafe8558aa182cf12c258406d197dab63ac46f5a5255b1deb2993a4e9fc92b1e26c
# sha512
# 000d0c36b2a951eccc7e3e12d03175a71304dc747f222a02af8fa2ac8b594ef973518d20b9a5452d0849e325710f587d8a55082e7ae321173619bc12122f3ad71466

# 00000160 plus the above name as text, add a blank line for empty policyRef
# to create policies/policysigned$HALG.txt
#
# 0000016000044234c24fc1b9de6693a62453417d2734d7538f6f
# 00000160000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
# 00000160000ca8bfb42e75b4c22b366b372cd9994bafe8558aa182cf12c258406d197dab63ac46f5a5255b1deb2993a4e9fc92b1e26c
# 00000160000d0c36b2a951eccc7e3e12d03175a71304dc747f222a02af8fa2ac8b594ef973518d20b9a5452d0849e325710f587d8a55082e7ae321173619bc12122f3ad71466
#
# use sha256 policies, policymaker default (policy session digest
# algorithm is separate from Name and signature hash algorithm)
#
# > policymaker -if policies/policysigned$HALG.txt -of policies/policysigned$HALG.bin -pr
#
# sha1
# 9d 81 7a 4e e0 76 eb b5 cf ee c1 82 05 cc 4c 01 
# b3 a0 5e 59 a9 b9 65 a1 59 af 1e cd 3d bf 54 fb 
# sha256
# de bf 9d fa 3c 98 08 0b f1 7d d1 d0 7b 54 fd e1 
# 07 93 7f e5 40 50 9e 70 96 aa 73 27 53 b3 83 31 
# sha384
# 45 c5 da 90 76 92 3a 70 03 6f df 56 ea e7 df db 
# 41 e2 01 75 24 49 54 94 66 93 6b c4 fc 88 ab 5c 
# sha512
# cd 34 96 08 39 ea 40 88 5e fa 7f 37 8b a7 21 f1 
# 78 6d 52 bb 93 47 9c 73 45 88 3c dc 1f 09 06 6f 
#
# 80000000 primary key
# 80000001 verification public key
# 80000002 signing key with policy
# 03000000 policy session

for HALG in ${ITERATE_ALGS}
do

    echo "Load external just the public part of PEM at 80000001 - $HALG"
    ${PREFIX}loadexternal -halg $HALG -nalg $HALG -ipem policies/rsapubkey.pem -ns > run.out
    checkSuccess $?

    echo "Sign a test message with openssl - $HALG"
    openssl dgst -$HALG -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin msg.bin > run.out 2>&1

    echo "Verify the signature with 80000001 - $HALG"
    ${PREFIX}verifysignature -hk 80000001 -halg $HALG -if msg.bin -is pssig.bin -raw > run.out
    checkSuccess $?

    echo "Create a signing key under the primary key - policy signed - $HALG"
    ${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policysigned$HALG.bin > run.out
    checkSuccess $?

    echo "Load the signing key under the primary key, at 80000002"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Start a policy session"
    ${PREFIX}startauthsession -se p > run.out
    checkSuccess $?

    echo "Sign a digest - policy, should fail"
    ${PREFIX}sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
    checkFailure $?

    echo "Policy signed, sign with PEM key - $HALG"
    ${PREFIX}policysigned -hk 80000001 -ha 03000000 -sk policies/rsaprivkey.pem -halg $HALG -pwdk rrrr > run.out
    checkSuccess $?

    echo "Get policy digest"
    ${PREFIX}policygetdigest -ha 03000000 -of tmppol.bin > run.out
    checkSuccess $?

    echo "Sign a digest - policy signed"
    ${PREFIX}sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
    checkSuccess $?

    echo "Policy restart, set back to zero"
    ${PREFIX}policyrestart -ha 03000000 > run.out 
    checkSuccess $?

    echo "Sign just expiration (uint32_t 4 zeros) with openssl - $HALG"
    openssl dgst -$HALG -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policies/zero4.bin > run.out 2>&1

    echo "Policy signed, signature generated externally - $HALG"
    ${PREFIX}policysigned -hk 80000001 -ha 03000000 -halg $HALG -is pssig.bin > run.out
    checkSuccess $?

    echo "Sign a digest - policy signed"
    ${PREFIX}sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
    checkSuccess $?

    echo "Start a policy session - save nonceTPM"
    ${PREFIX}startauthsession -se p -on noncetpm.bin > run.out
    checkSuccess $?

    echo "Policy signed with nonceTPM and expiration, create a ticket - $HALG"
    ${PREFIX}policysigned -hk 80000001 -ha 03000000 -sk policies/rsaprivkey.pem -halg $HALG -pwdk rrrr -in noncetpm.bin -exp -200 -tk tkt.bin -to to.bin > run.out
    checkSuccess $?

    echo "Sign a digest - policy signed"
    ${PREFIX}sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
    checkSuccess $?

    echo "Start a policy session"
    ${PREFIX}startauthsession -se p > run.out
    checkSuccess $?

    echo "Policy ticket"
    ${PREFIX}policyticket -ha 03000000 -to to.bin -na ${TPM_DATA_DIR}/h80000001.bin -tk tkt.bin > run.out
    checkSuccess $?

    echo "Sign a digest - policy ticket"
    ${PREFIX}sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
    checkSuccess $?

    echo "Flush the verification public key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Flush the signing key"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

done

# getcapability  -cap 1 -pr 80000000
# getcapability  -cap 1 -pr 02000000
# getcapability  -cap 1 -pr 03000000

# exit 0

echo ""
echo "Policy Secret with Platform Auth"
echo ""

# 4000000c platform
# 80000000 primary key
# 80000001 signing key with policy
# 03000000 policy session
# 02000001 hmac session

echo "Change platform hierarchy auth"
${PREFIX}hierarchychangeauth -hi p -pwdn ppp > run.out
checkSuccess $?

echo "Create a signing key under the primary key - policy secret using platform auth"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policysecretp.bin > run.out
checkSuccess $?

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p -on noncetpm.bin > run.out
checkSuccess $?

echo "Sign a digest - policy, should fail"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
checkFailure $?

echo "Policy Secret with PWAP session, create a ticket"
${PREFIX}policysecret -ha 4000000c -hs 03000000 -pwde ppp -in noncetpm.bin -exp -200 -tk tkt.bin -to to.bin > run.out
checkSuccess $?

echo "Sign a digest - policy secret"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p -on noncetpm.bin > run.out
checkSuccess $?

echo "Policy Secret using primary key, create a ticket"
${PREFIX}policysecret -ha 4000000c -hs 03000000 -pwde ppp -in noncetpm.bin -exp -200 -tk tkt.bin -to to.bin > run.out
checkSuccess $?

echo "Sign a digest - policy secret"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy ticket"
${PREFIX}policyticket -ha 03000000 -to to.bin -hi p -tk tkt.bin > run.out
checkSuccess $?

echo "Sign a digest - policy ticket"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p -on noncetpm.bin > run.out
checkSuccess $?

echo "Start an HMAC session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

echo "Policy Secret with HMAC session"
${PREFIX}policysecret -ha 4000000c -hs 03000000 -pwde ppp -se0 02000001 0 > run.out
checkSuccess $?

echo "Sign a digest - policy secret"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
checkSuccess $?

echo "Change platform hierarchy auth back to null"
${PREFIX}hierarchychangeauth -hi p -pwda ppp > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Policy Secret with NV Auth"
echo ""

# Name is 
# 00 0b e0 65 10 81 c2 fc da 30 69 93 da 43 d1 de 
# 5b 24 be 42 6e 2d 61 90 7b 42 83 54 69 13 6c 97 
# 68 1f 

# Policy is
# c6 93 f9 b0 ef 1a b7 1e ca ae 00 af 1f 0b f4 88 
# 37 9e ab 16 c1 f8 0d 9f f9 6d 90 41 4e 2f c6 b3 

echo "NV Define Space 0100000"
${PREFIX}nvdefinespace -hi p -ha 01000000 -pwdn nnn -sz 16 -pwdn nnn > run.out
checkSuccess $?

echo "Create a signing key under the primary key - policy secret NV auth"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policysecretnv.bin > run.out
checkSuccess $?

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p -on noncetpm.bin > run.out
checkSuccess $?

echo "Sign a digest - policy, should fail"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
checkFailure $?

echo "Policy Secret with PWAP session"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn -in noncetpm.bin > run.out
checkSuccess $?

echo "Sign a digest - policy secret"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "NV Undefine Space 0100000"
${PREFIX}nvundefinespace -hi p -ha 01000000 > run.out
checkSuccess $?


echo ""
echo "Policy Secret with Object"
echo ""

# Use a externally generated object so that the Name is known and thus
# the policy can be precalculated

# Name
# 00 0b 64 ac 92 1a 03 5c 72 b3 aa 55 ba 7d b8 b5 
# 99 f1 72 6f 52 ec 2f 68 20 42 fc 0e 0d 29 fa e8 
# 17 99 

# 000001151 plus the above name as text, add a blank line for empty policyRef
# to create policies/policysecretsha256.txt
# 00000151000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799

# 4b 7f ca c2 b7 c3 ac a2 7c 5c da 9c 71 e6 75 28 
# 63 d2 87 d2 33 ec 49 0e 7a be 88 f1 ef 94 5d 5c 

echo "Load the RSA openssl key pair in the NULL hierarchy 80000001"
${PREFIX}loadexternal -rsa -ider policies/rsaprivkey.der -pwdk rrrr > run.out
checkSuccess $?

echo "Create a signing key under the primary key - policy secret of object 80000001"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -uwa -pol policies/policysecretsha256.bin > run.out
checkSuccess $?

echo "Load the signing key under the primary key 80000002"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Sign a digest - password auth - should fail"
${PREFIX}sign -hk 80000002 -if policies/aaa -pwdk sig > run.out
checkFailure $?

echo "Start a policy session 03000000"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy Secret with PWAP session"
${PREFIX}policysecret -ha 80000001 -hs 03000000 -pwde rrrr > run.out
checkSuccess $?

echo "Sign a digest - policy secret"
${PREFIX}sign -hk 80000002 -if msg.bin -se0 03000000 1 > run.out
checkSuccess $?

echo "Flush the policysecret key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Load the RSA openssl key pair in the NULL hierarchy, userWithAuth false 80000001"
${PREFIX}loadexternal -rsa -ider policies/rsaprivkey.der -pwdk rrrr -uwa > run.out
checkSuccess $?

echo "Policy Secret with PWAP session - should fail"
${PREFIX}policysecret -ha 80000001 -hs 03000000 -pwde rrrr > run.out
checkFailure $?

echo "Flush the policysecret key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flush the session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo ""
echo "Policy Authorize"
echo ""

# 80000000 primary
# 80000001 verification public key, openssl
# 80000002 signing key
# 03000000 policy session

# Name for 80000001 0004 4234 c24f c1b9 de66 93a6 2453 417d 2734 d753 8f6f
#
# policyauthorizesha256.txt
# 0000016a000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
#
# (need blank line for policyRef)
#
# > policymaker -if policies/policyauthorizesha256.txt -of policies/policyauthorizesha256.bin -pr
#
# eb a3 f9 8c 5e af 1e a8 f9 4f 51 9b 4d 2a 31 83 
# ee 79 87 66 72 39 8e 23 15 d9 33 c2 88 a8 e5 03 

echo "Create a signing key with policy authorize"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyauthorizesha256.bin > run.out
checkSuccess $?

echo "Load external just the public part of PEM authorizing key 80000001"
${PREFIX}loadexternal -hi p -halg sha256 -nalg sha256 -ipem policies/rsapubkey.pem > run.out
checkSuccess $?

echo "Load the signing key under the primary key 80000002 "
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Get policy digest, should be zero"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy command code - sign"
${PREFIX}policycommandcode -ha 03000000 -cc 15d > run.out
checkSuccess $?

echo "Get policy digest, should be policy to approve, aHash input, same as policies/policyccsign.bin"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Openssl generate and sign aHash (empty policyRef)"
openssl dgst -sha256 -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policies/policyccsign.bin > run.out 2>&1

echo "Verify the signature to generate ticket 80000001"
${PREFIX}verifysignature -hk 80000001 -halg sha256 -if policies/policyccsign.bin -is pssig.bin -raw -tk tkt.bin > run.out
checkSuccess $?

echo "Policy authorize using the ticket"
${PREFIX}policyauthorize -ha 03000000 -appr policies/policyccsign.bin -skn ${TPM_DATA_DIR}/h80000001.bin -tk tkt.bin > run.out
checkSuccess $?

echo "Get policy digest, should be policy authorize"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Sign a digest"
${PREFIX}sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
checkSuccess $?

echo "Flush the verification public key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

# getcapability  -cap 1 -pr 80000000
# getcapability  -cap 1 -pr 02000000
# getcapability  -cap 1 -pr 03000000

# exit 0

echo ""
echo "Set Primary Policy"
echo ""

echo "Platform policy empty"
${PREFIX}setprimarypolicy -hi p > run.out
checkSuccess $?

echo "Platform policy empty, bad password"
${PREFIX}setprimarypolicy -hi p -pwda ppp > run.out
checkFailure $?

echo "Set platform hierarchy auth"
${PREFIX}hierarchychangeauth -hi p -pwdn ppp > run.out
checkSuccess $?

echo "Platform policy empty, bad password"
${PREFIX}setprimarypolicy -hi p > run.out
checkFailure $?

echo "Platform policy empty"
${PREFIX}setprimarypolicy -hi p -pwda ppp > run.out
checkSuccess $?

echo "Platform policy to policy secret platform auth"
${PREFIX}setprimarypolicy -hi p -pwda ppp -halg sha256 -pol policies/policysecretp.bin > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy Secret with PWAP session"
${PREFIX}policysecret -ha 4000000c -hs 03000000 -pwde ppp > run.out
checkSuccess $?

echo "Change platform hierarchy auth to null with policy secret"
${PREFIX}hierarchychangeauth -hi p -se0 03000000 0 > run.out
checkSuccess $?

echo ""
echo "Policy PCR no select"
echo ""

# create AND term for policy PCR
# > policymakerpcr -halg sha1 -bm 0 -v -pr -of policies/policypcr.txt
# 0000017f00000001000403000000da39a3ee5e6b4b0d3255bfef95601890afd80709

# convert to binary policy
# > policymaker -halg sha1 -if policies/policypcr.txt -of policies/policypcrbm0.bin -pr -v

# 6d 38 49 38 e1 d5 8b 56 71 92 55 94 3f 06 69 66 
# b6 fa 2c 23 

echo "Create a signing key with policy PCR no select"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -nalg sha1 -pol policies/policypcrbm0.bin > run.out
checkSuccess $?

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -halg sha1 -se p > run.out
checkSuccess $?

echo "Policy PCR, update with the correct digest"
${PREFIX}policypcr -ha 03000000 -halg sha1 -bm 0 > run.out
checkSuccess $?

echo "Policy get digest - should be 6d 38 49 38 ... "
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Sign, should succeed"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
checkSuccess $?

echo "Policy restart, set back to zero"
${PREFIX}policyrestart -ha 03000000 > run.out 
checkSuccess $?

echo "Policy PCR, update with the correct digest"
${PREFIX}policypcr -ha 03000000 -halg sha1 -bm 0 > run.out
checkSuccess $?

echo "PCR extend PCR 0, updates pcr counter"
${PREFIX}pcrextend -ha 0 -halg sha1 -if policies/aaa > run.out
checkSuccess $?

echo "Sign, should fail"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
checkFailure $?

echo "Flush the policy session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo "Flush the key"
${PREFIX}flushcontext -ha 80000001 > run.out 
checkSuccess $?

echo ""
echo "Policy PCR 16"
echo ""

# policypcr0.txt has 20 * 00

# create AND term for policy PCR
# > policymakerpcr -halg sha1 -bm 010000 -if policies/policypcr0.txt -v -pr -of policies/policypcr.txt
# 0000017f000000010004030000016768033e216468247bd031a0a2d9876d79818f8f

# convert to binary policy
# > policymaker -halg sha1 -if policies/policypcr.txt -of policies/policypcr.bin -pr -v

# 85 33 11 83 19 03 12 f5 e8 3c 60 43 34 6f 9f 37
# 21 04 76 8e

echo "Create a signing key with policy PCR PCR 16 zero"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -nalg sha1 -pol policies/policypcr.bin > run.out
checkSuccess $?

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Reset PCR 16 back to zero"
${PREFIX}pcrreset -ha 16 > run.out
checkSuccess $?

echo "Read PCR 16, should be 00 00 00 00 ..."
${PREFIX}pcrread -ha 16 -halg sha1 > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p -halg sha1 > run.out
checkSuccess $?

echo "Sign, policy not satisfied - should fail"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
checkFailure $?

echo "Policy PCR, update with the correct digest"
${PREFIX}policypcr -ha 03000000 -halg sha1 -bm 10000 > run.out
checkSuccess $?

echo "Policy get digest - should be 85 33 11 83 ..."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Sign, should succeed"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
checkSuccess $?

echo "PCR extend PCR 16"
${PREFIX}pcrextend -ha 16 -halg sha1 -if policies/aaa > run.out
checkSuccess $?

echo "Read PCR 0, should be 1d 47 f6 8a ..."
${PREFIX}pcrread -ha 16 -halg sha1 > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p -halg sha1 > run.out
checkSuccess $?

echo "Policy PCR, update with the wrong digest"
${PREFIX}policypcr -ha 03000000 -halg sha1 -bm 10000 > run.out
checkSuccess $?

echo "Policy get digest - should be 66 dd e5 e3"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Sign - should fail"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
checkFailure $?

echo "Flush the policy session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo "Flush the key"
${PREFIX}flushcontext -ha 80000001 > run.out 
checkSuccess $?

# 01000000 authorizing index
# 01000001 authorized index
# 03000000 policy session
#
# 4 byte NV index
# policynv.txt
# policy CC_PolicyNV || args || Name
#
# policynvargs.txt (binary)
# args = hash of 0000 0000 0000 0000 | 0000 | 0000 (eight bytes of zero | offset | op ==)
# hash -hi n -halg sha1 -if policies/policynvargs.txt -v
# openssl dgst -sha1 policies/policynvargs.txt
# 2c513f149e737ec4063fc1d37aee9beabc4b4bbf
#
# NV authorizing index
#
# after defining index and NV write to set written, use 
# ${PREFIX}nvreadpublic -ha 01000000 -nalg sha1
# to get name
# 00042234b8df7cdf8605ee0a2088ac7dfe34c6566c5c
#
# append Name to policynvnv.txt
#
# convert to binary policy
# > policymaker -halg sha1 -if policies/policynvnv.txt -of policies/policynvnv.bin -pr -v
# bc 9b 4c 4f 7b 00 66 19 5b 1d d9 9c 92 7e ad 57 e7 1c 2a fc 
#
# file zero8.bin has 8 bytes of hex zero

echo ""
echo "Policy NV, NV index authorizing"
echo ""

echo "Define a setbits index, authorizing index"
${PREFIX}nvdefinespace -hi p -nalg sha1 -ha 01000000 -pwdn nnn -ty b > run.out
checkSuccess $?

echo "NV Read public, get Name, not written"
${PREFIX}nvreadpublic -ha 01000000 -nalg sha1 > run.out
checkSuccess $?

echo "NV setbits to set written"
${PREFIX}nvsetbits -ha 01000000 -pwdn nnn > run.out
checkSuccess $?

echo "NV Read public, get Name, written"
${PREFIX}nvreadpublic -ha 01000000 -nalg sha1 > run.out
checkSuccess $?

echo "NV Read, should be zero"
${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 8 > run.out
checkSuccess $?

echo "Define an ordinary index, authorized index, policyNV"
${PREFIX}nvdefinespace -hi p -nalg sha1 -ha 01000001 -pwdn nnn -sz 2 -ty o -pol policies/policynvnv.bin > run.out
checkSuccess $?

echo "NV Read public, get Name, not written"
${PREFIX}nvreadpublic -ha 01000001 -nalg sha1 > run.out
checkSuccess $?

echo "NV write to set written"
${PREFIX}nvwrite -ha 01000001 -pwdn nnn -ic aa > run.out
checkSuccess $?

echo "Start policy session"
${PREFIX}startauthsession -se p -halg sha1 > run.out
checkSuccess $?
 
echo "NV write, policy not satisfied  - should fail"
${PREFIX}nvwrite -ha 01000001 -ic aa -se0 03000000 1 > run.out
checkFailure $?

echo "Policy get digest, should be 0"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy NV to satisfy the policy"
${PREFIX}policynv -ha 01000000 -pwda nnn -hs 03000000 -if policies/zero8.bin -op 0 > run.out
checkSuccess $?

echo "Policy get digest, should be bc 9b 4c 4f ..."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "NV write, policy satisfied"
${PREFIX}nvwrite -ha 01000001 -ic aa -se0 03000000 1 > run.out
checkSuccess $?

echo "Set bit in authorizing NV index"
${PREFIX}nvsetbits -ha 01000000 -pwdn nnn -bit 0 > run.out
checkSuccess $?

echo "NV Read, should be 1"
${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 8 > run.out
checkSuccess $?

echo "Policy NV to satisfy the policy - should fail"
${PREFIX}policynv -ha 01000000 -pwda nnn -hs 03000000 -if policies/zero8.bin -op 0 > run.out
checkFailure $?

echo "Policy get digest, should be 00 00 00 00 ..."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "NV Undefine authorizing index"
${PREFIX}nvundefinespace -hi p -ha 01000000 > run.out
checkSuccess $?

echo "NV Undefine authorized index"
${PREFIX}nvundefinespace -hi p -ha 01000001 > run.out 
checkSuccess $?

echo "Flush policy session"
${PREFIX}flushcontext -ha 03000000 > run.out  
checkSuccess $?

echo ""
echo "Policy NV Written"
echo ""

echo "Define an ordinary index, authorized index, policyNV"
${PREFIX}nvdefinespace -hi p -nalg sha1 -ha 01000000 -pwdn nnn -sz 2 -ty o -pol policies/policywrittenset.bin > run.out  
checkSuccess $?

echo "NV Read public, get Name, not written"
${PREFIX}nvreadpublic -ha 01000000 -nalg sha1 > run.out  
checkSuccess $?

echo "Start policy session"
${PREFIX}startauthsession -se p -halg sha1 > run.out
checkSuccess $?
 
echo "NV write, policy not satisfied  - should fail"
${PREFIX}nvwrite -ha 01000000 -ic aa -se0 03000000 1 > run.out  
checkFailure $?

echo "Policy NV Written no, does not satisfy policy"
${PREFIX}policynvwritten -hs 03000000 -ws n > run.out  
checkSuccess $?

echo "NV write, policy not satisfied - should fail"
${PREFIX}nvwrite -ha 01000000 -ic aa -se0 03000000 1 > run.out  
checkFailure $?

echo "Flush policy session"
${PREFIX}flushcontext -ha 03000000 > run.out  
checkSuccess $?

echo "Start policy session"
${PREFIX}startauthsession -se p -halg sha1 > run.out
checkSuccess $?

echo "Policy NV Written yes, satisfy policy"
${PREFIX}policynvwritten -hs 03000000 -ws y > run.out
checkSuccess $?

echo "NV write, policy satisfied but written clear - should fail"
${PREFIX}nvwrite -ha 01000000 -ic aa -se0 03000000 1 > run.out
checkFailure $?

echo "Flush policy session"
${PREFIX}flushcontext -ha 03000000 > run.out  
checkSuccess $?

echo "NV write using password, set written"
${PREFIX}nvwrite -ha 01000000 -ic aa -pwdn nnn > run.out
checkSuccess $?

echo "Start policy session"
${PREFIX}startauthsession -se p -halg sha1 > run.out
checkSuccess $?

echo "Policy NV Written yes, satisfy policy"
${PREFIX}policynvwritten -hs 03000000 -ws y > run.out
checkSuccess $?

echo "NV write, policy satisfied"
${PREFIX}nvwrite -ha 01000000 -ic aa -se0 03000000 1 > run.out
checkSuccess $?

echo "Flush policy session"
${PREFIX}flushcontext -ha 03000000 > run.out  
checkSuccess $?

echo "Start policy session"
${PREFIX}startauthsession -se p -halg sha1 > run.out
checkSuccess $?

echo "Policy NV Written no"
${PREFIX}policynvwritten -hs 03000000 -ws n > run.out
checkSuccess $?

echo "Policy NV Written yes - should fail"
${PREFIX}policynvwritten -hs 03000000 -ws y > run.out
checkFailure $?

echo "Flush policy session"
${PREFIX}flushcontext -ha 03000000 > run.out  
checkSuccess $?

echo "NV Undefine authorizing index"
${PREFIX}nvundefinespace -hi p -ha 01000000 > run.out
checkSuccess $?

echo ""
echo "Policy Signed externally signed cpHash"
echo ""

# NV Index 01000000 has policy OR

# Policy A - provisioning: policy written false + policysigned
#	demo: authorizer signs NV write all zero

# Policy B - application: policy written true + policysigned
#	demo: authorizer signs NV write abcdefgh

echo "Load external just the public part of PEM at 80000001"
${PREFIX}loadexternal -ipem policies/rsapubkey.pem > run.out
checkSuccess $?

echo "Get the Name of the signing key at 80000001"
${PREFIX}readpublic -ho 80000001 -ns > run.out
checkSuccess $?
# 000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799

# construct policy A

# policies/policywrittenclrsigned.txt
# 0000018f00
# 00000160000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
# Add the extra blank line here for policyRef

# policymaker -if policies/policywrittenclrsigned.txt -of policies/policywrittenclrsigned.bin -pr -ns -v
# intermediate policy digest length 32
#  3c 32 63 23 67 0e 28 ad 37 bd 57 f6 3b 4c c3 4d 
#  26 ab 20 5e f2 2f 27 5c 58 d4 7f ab 24 85 46 6e 
#  intermediate policy digest length 32
#  6b 0d 2d 2b 55 4d 68 ec bc 6c d5 b8 c0 96 c1 70 
#  57 5a 95 25 37 56 38 7e 83 d7 76 d9 5b 1b 8e f3 
#  intermediate policy digest length 32
#  48 0b 78 2e 02 82 c2 40 88 32 c4 df 9c 0e be 87 
#  18 6f 92 54 bd e0 5b 0c 2e a9 52 48 3e b7 69 f2 
#  policy digest length 32
#  48 0b 78 2e 02 82 c2 40 88 32 c4 df 9c 0e be 87 
#  18 6f 92 54 bd e0 5b 0c 2e a9 52 48 3e b7 69 f2 
# policy digest:
# 480b782e0282c2408832c4df9c0ebe87186f9254bde05b0c2ea952483eb769f2

# construct policy B

# policies/policywrittensetsigned.txt
# 0000018f01
# 00000160000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
# Add the extra blank line here for policyRef

# policymaker -if policies/policywrittensetsigned.txt -of policies/policywrittensetsigned.bin -pr -ns -v
#  intermediate policy digest length 32
#  f7 88 7d 15 8a e8 d3 8b e0 ac 53 19 f3 7a 9e 07 
#  61 8b f5 48 85 45 3c 7a 54 dd b0 c6 a6 19 3b eb 
#  intermediate policy digest length 32
#  7d c2 8f b0 dd 4f ee 97 78 2b 55 43 b1 dc 6b 1e 
#  e2 bc 79 05 d4 a1 f6 8d e2 97 69 5f a9 aa 78 5f 
#  intermediate policy digest length 32
#  09 43 ba 3c 3b 4d b1 c8 3f c3 97 85 f9 dc 0a 82 
#  49 f6 79 4a 04 38 e6 45 0a 50 56 8f b4 eb d2 46 
#  policy digest length 32
#  09 43 ba 3c 3b 4d b1 c8 3f c3 97 85 f9 dc 0a 82 
#  49 f6 79 4a 04 38 e6 45 0a 50 56 8f b4 eb d2 46 
# policy digest:
# 0943ba3c3b4db1c83fc39785f9dc0a8249f6794a0438e6450a50568fb4ebd246

# construct the Policy OR of A and B

# policyorwrittensigned.txt - command code plus two policy digests
# 00000171480b782e0282c2408832c4df9c0ebe87186f9254bde05b0c2ea952483eb769f20943ba3c3b4db1c83fc39785f9dc0a8249f6794a0438e6450a50568fb4ebd246
# policymaker -if policies/policyorwrittensigned.txt -of policies/policyorwrittensigned.bin -pr 
#  policy digest length 32
#  06 00 ae 34 7a 30 b0 67 36 d3 32 85 a0 cc ad 46 
#  54 1e 62 71 f5 d0 85 10 a7 ff 0e 90 30 54 d6 c9 

echo "Define index 01000000 with the policy OR"
${PREFIX}nvdefinespace -ha 01000000 -hi o -sz 8 -pwdn "" -pol policies/policyorwrittensigned.bin -at aw > run.out
checkSuccess $?

echo "Get the Name of the NV index not written, should be 00 0b ... bb 0b"
${PREFIX}nvreadpublic -ha 01000000 -ns > run.out
checkSuccess $?

# 000b366258674dcf8aa16d344f24dde1c799fc60f9427a7286bb8cd1e4e9fd1fbb0b

echo "Start a policy session 03000000"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo ""
echo "Policy A - not written"
echo ""

# construct cpHash for Policy A - not written, writing zeros
 
# (commandCode || authHandle Name || NV Index Name || data + offset) - data 8 bytes of 0's at offset 0000
# For index auth, authHandle Name and index Name are the same
# policies/nvwritecphasha.txt
# 00000137000b366258674dcf8aa16d344f24dde1c799fc60f9427a7286bb8cd1e4e9fd1fbb0b000b366258674dcf8aa16d344f24dde1c799fc60f9427a7286bb8cd1e4e9fd1fbb0b000800000000000000000000
# policymaker -nz -if policies/nvwritecphasha.txt -of policies/nvwritecphasha.bin -pr -ns
#  policy digest length 32
#  cf 98 1e ee 68 04 3b dd ee 0c ab bc 75 b3 63 be 
#  3c f9 ee 22 2a 78 b8 26 3f 06 7b b3 55 2c a6 11 
# policy digest:
# cf981eee68043bddee0cabbc75b363be3cf9ee222a78b8263f067bb3552ca611

# construct aHash for Policy A

# expiration + cpHashA
# policies/nvwriteahasha.txt
# 00000000cf981eee68043bddee0cabbc75b363be3cf9ee222a78b8263f067bb3552ca611
# just convert to binary, because openssl does the hash before signing
# xxd -r -p policies/nvwriteahasha.txt policies/nvwriteahasha.bin

echo "Policy NV Written no, satisfy policy"
${PREFIX}policynvwritten -hs 03000000 -ws n > run.out
checkSuccess $?

echo "Should be policy A first intermediate value 3c 32 63 23 ..."
${PREFIX}policygetdigest -ha 03000000 > run.out 
checkSuccess $?

echo "Sign aHash with openssl 8813 6530 ..."
openssl dgst -sha256 -sign policies/rsaprivkey.pem -passin pass:rrrr -out sig.bin policies/nvwriteahasha.bin > run.out 2>&1
echo ""

echo "Policy signed, signature generated externally"
${PREFIX}policysigned -hk 80000001 -ha 03000000 -halg sha256 -cp policies/nvwritecphasha.bin -is sig.bin > run.out
checkSuccess $?

echo "Should be policy A final value 48 0b 78 2e ..."
${PREFIX}policygetdigest -ha 03000000 > run.out 
checkSuccess $?

echo "Policy OR"
${PREFIX}policyor -ha 03000000 -if policies/policywrittenclrsigned.bin -if policies/policywrittensetsigned.bin > run.out
checkSuccess $?

echo "Should be policy OR final value 06 00 ae 34 "
${PREFIX}policygetdigest -ha 03000000 > run.out 
checkSuccess $?

echo "NV write to set written"
${PREFIX}nvwrite -ha 01000000 -if policies/zero8.bin -se0 03000000 1 > run.out
checkSuccess $?

echo ""
echo "Policy B - written"
echo ""

echo "Get the new (written) Name of the NV index not written, should be 00 0b f5 75"
${PREFIX}nvreadpublic -ha 01000000 -ns > run.out
checkSuccess $?

# 000bf575f09107d38c4cb82e8ec054b1aca9a91e40a06ec074b578bdd9cdaf4b76c8

# construct cpHash for Policy B
 
# (commandCode || authHandle Name || NV Index Name || data + offset) - data 8 bytes of abcdefgh at offset 00000
# For index auth, authHandle Name and index Name are the same
# policies/nvwritecphashb.txt
# 00000137000bf575f09107d38c4cb82e8ec054b1aca9a91e40a06ec074b578bdd9cdaf4b76c8000bf575f09107d38c4cb82e8ec054b1aca9a91e40a06ec074b578bdd9cdaf4b76c8000861626364656667680000
# policymaker -nz -if policies/nvwritecphashb.txt -of policies/nvwritecphashb.bin -pr -ns
#  policy digest length 32
#  df 58 08 f9 ab cb 23 7f 8c d7 c9 09 1c 86 12 2d 
#  88 6f 02 d4 6e db 53 c8 da 39 bf a2 d6 cf 07 63 
# policy digest:
# df5808f9abcb237f8cd7c9091c86122d886f02d46edb53c8da39bfa2d6cf0763

# construct aHash for Policy B

# expiration + cpHashA
# policies/nvwriteahashb.txt
# 00000000df5808f9abcb237f8cd7c9091c86122d886f02d46edb53c8da39bfa2d6cf0763
# just convert to binary, because openssl does the hash before signing
# xxd -r -p policies/nvwriteahashb.txt policies/nvwriteahashb.bin

echo "Policy NV Written yes, satisfy policy"
${PREFIX}policynvwritten -hs 03000000 -ws y > run.out
checkSuccess $?

echo "Should be policy A first intermediate value f7 88 7d 15 ..."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Sign aHash with openssl 3700 0a91 ..."
openssl dgst -sha256 -sign policies/rsaprivkey.pem -passin pass:rrrr -out sig.bin policies/nvwriteahashb.bin > run.out 2>&1
echo ""

echo "Policy signed, signature generated externally"
${PREFIX}policysigned -hk 80000001 -ha 03000000 -halg sha256 -cp policies/nvwritecphashb.bin -is sig.bin > run.out
checkSuccess $?

echo "Should be policy B final value 09 43 ba 3c ..."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy OR"
${PREFIX}policyor -ha 03000000 -if policies/policywrittenclrsigned.bin -if policies/policywrittensetsigned.bin > run.out
checkSuccess $?

echo "Should be policy OR final value 06 00 ae 34 "
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "NV write new data"
${PREFIX}nvwrite -ha 01000000 -ic abcdefgh -se0 03000000 1 > run.out
checkSuccess $?

echo ""
echo "Cleanup"
echo ""

echo "Flush the policy session 03000000"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo "Flush the signature verification key 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Undefine the NV Index 01000000"
${PREFIX}nvundefinespace -hi o -ha 01000000 > run.out 
checkSuccess $?

# test using clockrateadjust
# policycphashhash.txt is (hex) 00000130 4000000c 000
# hash -if policycphashhash.txt -oh policycphashhash.bin -halg sha1 -v
# openssl dgst -sha1 policycphashhash.txt
# cpHash is
# b5f919bbc01f0ebad02010169a67a8c158ec12f3
# append to policycphash.txt 00000163 + cpHash
# policymaker -halg sha1 -if policies/policycphash.txt -of policies/policycphash.bin -pr
#  06 e4 6c f9 f3 c7 0f 30 10 18 7c a6 72 69 b0 84 b4 52 11 6f 

echo ""
echo "Policy cpHash"
echo ""

echo "Set the platform policy to policy cpHash"
${PREFIX}setprimarypolicy -hi p -pol policies/policycphash.bin -halg sha1 > run.out
checkSuccess $?

echo "Clockrate adjust using wrong password - should fail"
${PREFIX}clockrateadjust -hi p -pwdp ppp -adj 0 > run.out 
checkFailure $?

echo "Start policy session"
${PREFIX}startauthsession -se p -halg sha1 > run.out 
checkSuccess $?

echo "Clockrate adjust, policy not satisfied - should fail"
${PREFIX}clockrateadjust -hi p -pwdp ppp -adj 0 -se0 03000000 1 > run.out
checkFailure $?

echo "Policy cpHash, satisfy policy"
${PREFIX}policycphash -ha 03000000 -cp policies/policycphashhash.bin > run.out
checkSuccess $?
 
echo "Policy get digest, should be 06 e4 6c f9"
${PREFIX}policygetdigest -ha 03000000 > run.out 
checkSuccess $?

echo "Clockrate adjust, policy satisfied but bad command params - should fail"
${PREFIX}clockrateadjust -hi p -pwdp ppp -adj 1 -se0 03000000 1 > run.out 
checkFailure $?

echo "Clockrate adjust, policy satisfied"
${PREFIX}clockrateadjust -hi p -pwdp ppp -adj 0 -se0 03000000 1 > run.out 
checkSuccess $?

echo "Clear the platform policy"
${PREFIX}setprimarypolicy -hi p > run.out 
checkSuccess $?

echo "Flush policy session"
${PREFIX}flushcontext -ha 03000000 > run.out 
checkSuccess $?

echo ""
echo "Policy Duplication Select with includeObject FALSE"
echo ""

# These tests uses a new parent and object to be duplicated generated
# externally.  This makes the Names repeatable and permits the
# policy to be pre-calculated and static.

# command code 00000188
# newParentName
# 000b 1a5d f667 7533 4527 37bc 79a5 5ab6 
# d9fa 9174 5c03 3dfe 3f82 cdf0 903b a9d6
# 55f1
# includeObject 00
# policymaker -if policies/policydupsel-no.txt -of policies/policydupsel-no.bin -pr -v
# 5f 55 ba 2b 69 0f b0 38 ac 15 ff 2a 86 ef 65 66 
# be a8 23 68 43 97 4c 3f a7 36 37 72 56 ec bc 45 

# 80000000 SK storage primary key
# 80000001 NP new parent, the target of the duplication
# 80000002 SI signing key, duplicate from SK to NP
# 03000000 policy session

echo "Import the new parent storage key NP under the primary key"
${PREFIX}importpem -hp 80000000 -pwdp sto -ipem policies/rsaprivkey.pem -st -pwdk rrrr -opu tmpstpub.bin -opr tmpstpriv.bin -halg sha256 > run.out
checkSuccess $?
	
echo "Load the new parent TPM storage key NP at 80000001"
${PREFIX}load -hp 80000000 -pwdp sto -ipu tmpstpub.bin -ipr tmpstpriv.bin > run.out
checkSuccess $?

echo "Import a signing key SI under the primary key 80000000, with policy duplication select"
${PREFIX}importpem -hp 80000000 -pwdp sto -ipem policies/rsaprivkey.pem -si -pwdk rrrr -opr tmpsipriv.bin -opu tmpsipub.bin -pol policies/policydupsel-no.bin > run.out
checkSuccess $?

echo "Load the signing key SI at 80000002"
${PREFIX}load -hp 80000000 -pwdp sto -ipu tmpsipub.bin -ipr tmpsipriv.bin > run.out
checkSuccess $?

echo "Sign a digest"
${PREFIX}sign -hk 80000002 -halg sha256 -if policies/aaa -os tmpsig.bin -pwdk rrrr > run.out
checkSuccess $?

echo "Verify the signature"
${PREFIX}verifysignature -hk 80000002 -halg sha256 -if policies/aaa -is tmpsig.bin > run.out
checkSuccess $?

echo "Start a policy session 03000000"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy duplication select, object SI 80000002 to new parent NP 80000001"
${PREFIX}policyduplicationselect -ha 03000000 -inpn h80000001.bin -ion h80000002.bin > run.out
checkSuccess $?

echo "Get policy digest, should be 5f 55 ba 2b ...."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Duplicate signing key SI at 80000002 under new parent TPM storage key NP 80000001"
${PREFIX}duplicate -ho 80000002 -hp 80000001 -od tmpdup.bin -oss tmpss.bin -se0 03000000 0 > run.out
checkSuccess $?

echo "Flush the original SI at 80000002 to free object slot for import"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Import signing key SI under new parent TPM storage key NP 80000001"
${PREFIX}import -hp 80000001 -pwdp rrrr -ipu tmpsipub.bin -id tmpdup.bin -iss tmpss.bin -opr tmpsipriv1.bin > run.out
checkSuccess $?

echo "Load the signing key SI at 80000002"
${PREFIX}load -hp 80000001 -pwdp rrrr -ipu tmpsipub.bin -ipr tmpsipriv1.bin > run.out
checkSuccess $?

echo "Sign a digest"
${PREFIX}sign -hk 80000002 -halg sha256 -if policies/aaa -os tmpsig.bin -pwdk rrrr > run.out
checkSuccess $?

echo "Verify the signature"
${PREFIX}verifysignature -hk 80000002 -halg sha256 -if policies/aaa -is tmpsig.bin > run.out
checkSuccess $?

echo "Flush the duplicated SI at 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo ""
echo "Policy Duplication Select with includeObject TRUE"
echo ""

# command code 00000188
# SI objectName
# 000b 6319 28da 1624 3135 3a59 c03a 2ca7
# dbb7 0989 1440 4236 3c7f a838 39d9 da6c
# 437a
# HP newParentName
# 000b 
# 1a5d f667 7533 4527 37bc 79a5 5ab6 d9fa 
# 9174 5c03 3dfe 3f82 cdf0 903b a9d6 55f1
# includeObject 01
#
# policymaker -if policies/policydupsel-yes.txt -of policies/policydupsel-yes.bin -pr -v
# 14 64 06 4c 80 cb e3 4f f5 03 82 15 38 62 43 17 
# 93 94 8f f1 e8 8a c6 23 4d d1 b0 c5 4c 05 f7 3b 

# 80000000 SK storage primary key
# 80000001 NP new parent, the target of the duplication
# 80000002 SI signing key, duplicate from SK to NP
# 03000000 policy session

echo "Import a signing key SI under the primary key 80000000, with policy authorize"
${PREFIX}importpem -hp 80000000 -pwdp sto -ipem policies/rsaprivkey.pem -si -pwdk rrrr -opr tmpsipriv.bin -opu tmpsipub.bin -pol policies/policyauthorizesha256.bin > run.out
checkSuccess $?

echo "Load the signing key SI with objectName 000b 6319 28da at 80000002"
${PREFIX}load -hp 80000000 -pwdp sto -ipu tmpsipub.bin -ipr tmpsipriv.bin > run.out
checkSuccess $?

echo "Sign a digest"
${PREFIX}sign -hk 80000002 -halg sha256 -if policies/aaa -os tmpsig.bin -pwdk rrrr > run.out
checkSuccess $?

echo "Verify the signature"
${PREFIX}verifysignature -hk 80000002 -halg sha256 -if policies/aaa -is tmpsig.bin > run.out
checkSuccess $?

echo "Start a policy session 03000000"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy duplication select, object SI 80000002 to new parent NP 80000001 with includeObject"
${PREFIX}policyduplicationselect -ha 03000000 -inpn h80000001.bin -ion h80000002.bin -io > run.out
checkSuccess $?

echo "Get policy digest, should be policy to approve, aHash input 14 64 06 4c same as policies/policydupsel-yes.bin"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Flush the original SI at 80000002 to free object slot for loadexternal "
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Openssl generate and sign aHash (empty policyRef)"
openssl dgst -sha256 -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policies/policydupsel-yes.bin > run.out 2>&1

echo "Load external just the public part of PEM authorizing key 80000002"
${PREFIX}loadexternal -hi p -halg sha256 -nalg sha256 -ipem policies/rsapubkey.pem > run.out
checkSuccess $?

echo "Verify the signature against 80000002 to generate ticket"
${PREFIX}verifysignature -hk 80000002 -halg sha256 -if policies/policydupsel-yes.bin -is pssig.bin -raw -tk tkt.bin > run.out
checkSuccess $?

echo "Policy authorize using the ticket"
${PREFIX}policyauthorize -ha 03000000 -appr policies/policydupsel-yes.bin -skn ${TPM_DATA_DIR}/h80000002.bin -tk tkt.bin > run.out
checkSuccess $?

echo "Get policy digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Flush the PEM authorizing verification key at 80000002 to free object slot for import"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Load the original signing key SI at 80000002"
${PREFIX}load -hp 80000000 -pwdp sto -ipu tmpsipub.bin -ipr tmpsipriv.bin > run.out
checkSuccess $?

echo "Duplicate signing key SI at 80000002 under new parent TPM storage key NP 80000001 000b 1a5d f667"
${PREFIX}duplicate -ho 80000002 -hp 80000001 -od tmpdup.bin -oss tmpss.bin -se0 03000000 0 > run.out
checkSuccess $?

echo "Flush the original SI at 80000002 to free object slot for import"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Import signing key SI under new parent TPM storage key NP 80000001"
${PREFIX}import -hp 80000001 -pwdp rrrr -ipu tmpsipub.bin -id tmpdup.bin -iss tmpss.bin -opr tmpsipriv1.bin > run.out
checkSuccess $?

echo "Load the signing key SI at 80000002"
${PREFIX}load -hp 80000001 -pwdp rrrr -ipu tmpsipub.bin -ipr tmpsipriv1.bin > run.out
checkSuccess $?

echo "Sign a digest"
${PREFIX}sign -hk 80000002 -halg sha256 -if policies/aaa -os tmpsig.bin -pwdk rrrr > run.out
checkSuccess $?

echo "Verify the signature"
${PREFIX}verifysignature -hk 80000002 -halg sha256 -if policies/aaa -is tmpsig.bin > run.out
checkSuccess $?

echo "Flush the duplicated SI at 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flush the new parent TPM storage key NP 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Policy Name Hash"
echo ""

# signing key SI Name
# 000b
# 6319 28da 1624 3135 3a59 c03a 2ca7 dbb7 
# 0989 1440 4236 3c7f a838 39d9 da6c 437a 

# compute nameHash

# nameHash - just a hash, not an extend
# policymaker -if policies/pnhnamehash.txt -of policies/pnhnamehash.bin -nz -pr -v -ns
# 18 e0 0c 62 77 18 d9 fc 81 22 3d 8a 56 33 7e eb 
# 0e 7d 98 28 bd 7b c7 29 1d 3c 27 3f 7a c4 04 f1 
# 18e00c627718d9fc81223d8a56337eeb0e7d9828bd7bc7291d3c273f7ac404f1

# compute policy (based on 

# 00000170 TPM_CC_PolicyNameHash
# signing key SI Name
# 18e00c627718d9fc81223d8a56337eeb0e7d9828bd7bc7291d3c273f7ac404f1

# policymaker -if policies/policynamehash.txt -of policies/policynamehash.bin -pr -v
# 96 30 f9 00 c3 4c 66 09 c1 c5 92 41 78 c1 b2 3d 
# 9f d4 93 f4 f9 c2 98 c8 30 4a e3 0f 97 a2 fd 49 

# 80000000 SK storage primary key
# 80000001 SI signing key
# 80000002 Authorizing public key
# 03000000 policy session

echo "Import a signing key SI under the primary key 80000000, with policy authorize"
${PREFIX}importpem -hp 80000000 -pwdp sto -ipem policies/rsaprivkey.pem -si -pwdk rrrr -opr tmpsipriv.bin -opu tmpsipub.bin -pol policies/policyauthorizesha256.bin > run.out
checkSuccess $?

echo "Load the signing key SI at 80000001"
${PREFIX}load -hp 80000000 -pwdp sto -ipu tmpsipub.bin -ipr tmpsipriv.bin > run.out
checkSuccess $?

echo "Sign a digest using the password"
${PREFIX}sign -hk 80000001 -halg sha256 -if policies/aaa -os tmpsig.bin -pwdk rrrr > run.out
checkSuccess $?

echo "Verify the signature"
${PREFIX}verifysignature -hk 80000001 -halg sha256 -if policies/aaa -is tmpsig.bin > run.out
checkSuccess $?

echo "Start a policy session 03000000"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy name hash, object SI 80000001"
${PREFIX}policynamehash -ha 03000000 -nh policies/pnhnamehash.bin > run.out
checkSuccess $?

echo "Get policy digest,should be policy to approve, 96 30 f9 00"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Openssl generate and sign aHash (empty policyRef)"
openssl dgst -sha256 -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policies/policynamehash.bin > run.out 2>&1

echo "Load external just the public part of PEM authorizing key 80000002"
${PREFIX}loadexternal -hi p -halg sha256 -nalg sha256 -ipem policies/rsapubkey.pem > run.out
checkSuccess $?

echo "Verify the signature against 80000002 to generate ticket"
${PREFIX}verifysignature -hk 80000002 -halg sha256 -if policies/policynamehash.bin -is pssig.bin -raw -tk tkt.bin > run.out
checkSuccess $?

echo "Policy authorize using the ticket"
${PREFIX}policyauthorize -ha 03000000 -appr policies/policynamehash.bin -skn ${TPM_DATA_DIR}/h80000002.bin -tk tkt.bin > run.out
checkSuccess $?

echo "Get policy digest, should be eb a3 f9 8c ...."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Sign a digest using the policy"
${PREFIX}sign -hk 80000001 -halg sha256 -if policies/aaa -os tmpsig.bin -se0 03000000 0 > run.out
checkSuccess $?

echo "Verify the signature"
${PREFIX}verifysignature -hk 80000001 -halg sha256 -if policies/aaa -is tmpsig.bin > run.out
checkSuccess $?

echo "Flush the signing key at 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the authorizing key 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

# test using clockrateadjust and platform policy

# operand A time is 64 bits at offset 0, operation GT (2)
# 0000016d 0000 0000 0000 0000 | 0000 | 0002
# 
# convert to binary policy
# > policymaker -halg sha1 -if policies/policycountertimer.txt -of policies/policycountertimer.bin -pr -v
# e6 84 81 27 55 c0 39 d3 68 63 21 c8 93 50 25 dd 
# aa 26 42 9a 

echo ""
echo "Policy Counter Timer"
echo ""

echo "Set the platform policy to policy "
${PREFIX}setprimarypolicy -hi p -pol policies/policycountertimer.bin -halg sha1 > run.out
checkSuccess $?

echo "Clockrate adjust using wrong password - should fail"
${PREFIX}clockrateadjust -hi p -pwdp ppp -adj 0 > run.out
checkFailure $?

echo "Start policy session"
${PREFIX}startauthsession -se p -halg sha1 > run.out
checkSuccess $?

echo "Clockrate adjust, policy not satisfied - should fail"
${PREFIX}clockrateadjust -hi p -adj 0 -se0 03000000 1 > run.out
checkFailure $?

echo "Policy counter timer, zero operandB, op EQ satisfy policy - should fail"
${PREFIX}policycountertimer -ha 03000000 -if policies/zero8.bin -op 0 > run.out
checkFailure $?
 
echo "Policy counter timer, zero operandB, op GT satisfy policy"
${PREFIX}policycountertimer -ha 03000000 -if policies/zero8.bin -op 2 > run.out 
checkSuccess $?
 
echo "Policy get digest, should be e6 84 81 27"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Clockrate adjust, policy satisfied"
${PREFIX}clockrateadjust -hi p -adj 0 -se0 03000000 1 > run.out 
checkSuccess $?

echo "Clear the platform policy"
${PREFIX}setprimarypolicy -hi p > run.out 
checkSuccess $?

echo "Flush policy session"
${PREFIX}flushcontext -ha 03000000 > run.out 
checkSuccess $?


# policyccsign.txt  0000016c 0000015d (policy command code | sign)
# policyccquote.txt 0000016c 00000158 (policy command code | quote)
#
# > policymaker -if policies/policyccsign.txt -of policies/policyccsign.bin -pr -v
# cc6918b226273b08f5bd406d7f10cf160f0a7d13dfd83b7770ccbcd1aa80d811
#
# > policymaker -if policies/policyccquote.txt -of policies/policyccquote.bin -pr -v
# a039cad5fe68870688f8233c3e3ee3cf27aac9e2efe3486aeb4e304c0e90cd27
#
# policyor.txt is CC_PolicyOR || digests
# 00000171 | cc69 ... | a039 ...
# > policymaker -if  policies/policyor.txt -of  policies/policyor.bin -pr -v
# 6b fe c2 3a be 57 b0 2a ce 39 dd 13 bb 60 fa 39 
# 4d ac 7b 38 96 56 57 84 b3 73 fc 61 92 94 29 db 

echo ""
echo "PolicyOR"
echo ""

echo "Create an unrestricted signing key, policy command code sign or quote"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyor.bin > run.out
checkSuccess $?

echo "Load the signing key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy get digest"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Sign a digest - should fail"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
checkFailure $?

echo "Quote - should fail"
${PREFIX}quote -hp 0 -hk 80000001 -se0 03000000 1 > run.out
checkFailure $?

echo "Get time - should fail, policy not set"
${PREFIX}gettime -hk 80000001 -qd policies/aaa -se1 03000000 1 > run.out
checkFailure $?

echo "Policy OR - should fail"
${PREFIX}policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
checkFailure $?

echo "Policy Command code - sign"
${PREFIX}policycommandcode -ha 03000000 -cc 0000015d > run.out
checkSuccess $?

echo "Policy get digest, should be cc 69 18 b2"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy OR"
${PREFIX}policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
checkSuccess $?

echo "Policy get digest, should be 6b fe c2 3a"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Sign with policy OR"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
checkSuccess $?

echo "Policy Command code - sign"
${PREFIX}policycommandcode -ha 03000000 -cc 0000015d > run.out
checkSuccess $?

echo "Policy OR"
${PREFIX}policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
checkSuccess $?

echo "Quote - should fail, wrong command code"
${PREFIX}quote -hp 0 -hk 80000001 -se0 03000000 1 > run.out
checkFailure $?

echo "Policy restart, set back to zero"
${PREFIX}policyrestart -ha 03000000 > run.out 
checkSuccess $?

echo "Policy Command code - quote, digest a0 39 ca d5"
${PREFIX}policycommandcode -ha 03000000 -cc 00000158 > run.out
checkSuccess $?

echo "Policy OR, digest 6b fe c2 3a"
${PREFIX}policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
checkSuccess $?

echo "Quote with policy OR"
${PREFIX}quote -hp 0 -hk 80000001 -se0 03000000 1 > run.out
checkSuccess $?

echo "Policy Command code - gettime 7a 3e bd aa"
${PREFIX}policycommandcode -ha 03000000 -cc 0000014c > run.out
checkSuccess $?

echo "Policy OR, gettime not an AND term - should fail"
${PREFIX}policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
checkFailure $?

echo "Flush policy session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo "Flush signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

# There are times that a policy creator has TPM, PEM, or DER format
# information, but does not have access to a TPM.  The publicname
# utility accepts these inputs and outputs the name in the 'no spaces'
# format suitable for pasting into a policy.

echo ""
echo "publicname RSA"
echo ""

for HALG in ${ITERATE_ALGS}
do

    echo "Create an rsa ${HALG} key under the primary key"
    ${PREFIX}create -hp 80000000 -rsa 2048 -nalg ${HALG} -si -opr tmppriv.bin -opu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Load the rsa ${HALG} key 80000001"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Compute the TPM2B_PUBLIC Name"
    ${PREFIX}publicname -ipu tmppub.bin -on tmp.bin > run.out
    checkSuccess $?

    echo "Verify the TPM2B_PUBLIC result"
    diff tmp.bin h80000001.bin > run.out
    checkSuccess $?

    echo "Convert the rsa public key to PEM format"
    ${PREFIX}readpublic -ho 80000001 -opem tmppub.pem > run.out
    checkSuccess $?

    echo "Flush the rsa ${HALG} key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "loadexternal the rsa PEM public key"
    ${PREFIX}loadexternal -ipem tmppub.pem -si -rsa -nalg ${HALG} -halg ${HALG} -scheme rsassa > run.out
    checkSuccess $?

    echo "Compute the PEM Name"
    ${PREFIX}publicname -ipem tmppub.pem -rsa -si -nalg ${HALG} -halg ${HALG} -on tmp.bin > run.out
    checkSuccess $?

    echo "Verify the PEM result"
    diff tmp.bin h80000001.bin > run.out
    checkSuccess $?

    echo "Convert the TPM PEM key to DER"
    openssl pkey -inform pem -outform der -in tmppub.pem -out tmppub.der -pubin > run.out 2>&1
    echo "INFO:"

    echo "Compute the DER Name"
    ${PREFIX}publicname -ider tmppub.der -rsa -si -nalg ${HALG} -halg ${HALG} -on tmp.bin -v > run.out
    checkSuccess $?

    echo "Verify the DER result"
    diff tmp.bin h80000001.bin > run.out
    checkSuccess $?

    echo "Flush the rsa ${HALG} key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "publicname ECC"
echo ""

for HALG in ${ITERATE_ALGS}
do

    echo "Create an ecc nistp256 ${HALG} key under the primary key"
    ${PREFIX}create -hp 80000000 -ecc nistp256 -nalg ${HALG} -si -opr tmppriv.bin -opu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Load the ecc ${HALG} key 80000001"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Compute the TPM2B_PUBLIC Name"
    ${PREFIX}publicname -ipu tmppub.bin -on tmp.bin > run.out
    checkSuccess $?

    echo "Verify the TPM2B_PUBLIC result"
    diff tmp.bin h80000001.bin > run.out
    checkSuccess $?

    echo "Convert the ecc public key to PEM format"
    ${PREFIX}readpublic -ho 80000001 -opem tmppub.pem > run.out
    checkSuccess $?

    echo "Flush the ecc ${HALG} key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "loadexternal the ecc PEM public key"
    ${PREFIX}loadexternal -ipem tmppub.pem -si -ecc -nalg ${HALG} -halg ${HALG} > run.out
    checkSuccess $?

    echo "Compute the PEM Name"
    ${PREFIX}publicname -ipem tmppub.pem -ecc -si -nalg ${HALG} -halg ${HALG} -on tmp.bin > run.out
    checkSuccess $?

    echo "Verify the PEM result"
    diff tmp.bin h80000001.bin > run.out
    checkSuccess $?

    echo "Convert the TPM PEM key to DER"
    openssl pkey -inform pem -outform der -in tmppub.pem -out tmppub.der -pubin -pubout > run.out 2>&1
    echo "INFO:"

    echo "Compute the DER Name"
    ${PREFIX}publicname -ider tmppub.der -ecc -si -nalg ${HALG} -halg ${HALG} -on tmp.bin -v > run.out
    checkSuccess $?

    echo "Verify the DER result"
    diff tmp.bin h80000001.bin > run.out
    checkSuccess $?

    echo "Flush the ecc ${HALG} key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "publicname NV"
echo ""

for HALG in ${ITERATE_ALGS}
do

    echo "NV Define Space ${HALG}"
    ${PREFIX}nvdefinespace -hi o -ha 01000000 -sz 16 -nalg ${HALG} > run.out
    checkSuccess $?

    echo "NV Read Public"
    ${PREFIX}nvreadpublic -ha 01000000 -opu tmppub.bin -on tmpname.bin > run.out
    checkSuccess $?

    echo "Compute the NV Index Name"
    ${PREFIX}publicname -invpu tmppub.bin -on tmp.bin > run.out
    checkSuccess $?

    echo "Verify the NV Index result"
    diff tmp.bin tmpname.bin > run.out
    checkSuccess $?

    echo "NV Undefine Space"
    ${PREFIX}nvundefinespace -hi o -ha 01000000 > run.out
    checkSuccess $?

done

# cleanup

rm -f pssig.bin
rm -f run.out
rm -f sig.bin
rm -f tkt.bin
rm -f tmp.bin
rm -f tmpdup.bin
rm -f tmphkey.bin
rm -f tmpname.bin
rm -f tmppol.bin
rm -f tmppriv.bin
rm -f tmppriv.bin 
rm -f tmppub.bin
rm -f tmppub.der
rm -f tmppub.pem
rm -f tmpsig.bin
rm -f tmpsipriv.bin
rm -f tmpsipriv1.bin
rm -f tmpsipub.bin
rm -f tmpss.bin
rm -f tmpstpriv.bin
rm -f tmpstpub.bin

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 01000000
# ${PREFIX}getcapability -cap 1 -pr 02000000
# ${PREFIX}getcapability -cap 1 -pr 03000000
