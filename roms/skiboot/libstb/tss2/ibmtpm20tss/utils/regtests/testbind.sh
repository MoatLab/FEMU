#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	$Id: testbind.sh 1277 2018-07-23 20:30:23Z kgoldman $			#
#										#
# (c) Copyright IBM Corporation 2015 - 2018					#
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
echo "Bind session"
echo ""

echo ""
echo "Bind session to Primary Key"
echo ""

echo "Bind session bound to primary key at 80000000"
${PREFIX}startauthsession -se h -bi 80000000 -pwdb sto > run.out
checkSuccess $?

echo "Create storage key using that bind session, same object 80000000"
${PREFIX}create -hp 80000000 -st -kt f -kt p -pwdp sto -pwdk 222 -se0 02000000 1 > run.out
checkSuccess $?

echo "Create storage key using that bind session, same object 80000000, wrong password does not matter"
${PREFIX}create -hp 80000000 -st -kt f -kt p -pwdp xxx -pwdk 222 -se0 02000000 0 > run.out
checkSuccess $?

echo "Create second primary key with different password 000 and Name"
${PREFIX}createprimary -hi o -pwdk 000 > run.out
checkSuccess $?

echo "Bind session bound to second primary key at 80000001, correct password"
${PREFIX}startauthsession -se h -bi 80000001 -pwdb 000 > run.out
checkSuccess $?

echo "Create storage key using that bind session, different object 80000000"
${PREFIX}create -hp 80000000 -st -kt f -kt p -pwdp sto -pwdk 222 -se0 02000000 1 > run.out
checkSuccess $?

echo "Create storage key using that bind session, different object 80000000, wrong password - should fail"
${PREFIX}create -hp 80000000 -st -kt f -kt p -pwdp xxx -pwdk 222 -se0 02000000 1 > run.out
checkFailure $?

echo "Flush the session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo "Bind session bound to primary key at 80000000, wrong password"
${PREFIX}startauthsession -se h -bi 80000000 -pwdb xxx > run.out
checkSuccess $?

echo "Create storage key using that bind session, same object 80000000 - should fail"
${PREFIX}create -hp 80000000 -st -kt f -kt p -pwdp sto -pwdk 222 -se0 02000000 0 > run.out
checkFailure $?

echo "Flush the failing session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo "Flush the second primary key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Bind session to Hierarchy"
echo ""

echo "Change platform hierarchy auth"
${PREFIX}hierarchychangeauth -hi p -pwdn ppp > run.out
checkSuccess $?

echo "Bind session bound to platform hierarchy"
${PREFIX}startauthsession -se h -bi 4000000c -pwdb ppp > run.out
checkSuccess $?

echo "Create storage key using that bind session, wrong password - should fail"
${PREFIX}create -hp 80000000 -st -kt f -kt p -pwdp xxx -pwdk 222 -se0 02000000 0 > run.out
checkFailure $?

echo "Create storage key using that bind session"
${PREFIX}create -hp 80000000 -st -kt f -kt p -pwdp sto -pwdk 222 -se0 02000000 0 > run.out
checkSuccess $?

echo "Bind session bound to platform hierarchy, wrong password"
${PREFIX}startauthsession -se h -bi 4000000c -pwdb xxx > run.out
checkSuccess $?

echo "Create storage key using that bind session - should fail"
${PREFIX}create -hp 80000000 -st -kt f -kt p -pwdp sto -pwdk 222 -se0 02000000 0 > run.out
checkFailure $?

echo "Change platform hierarchy auth back to null"
${PREFIX}hierarchychangeauth -hi p -pwda ppp > run.out
checkSuccess $?

echo "Flush the session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Bind session to NV"
echo ""

echo "NV Undefine Space"
${PREFIX}nvundefinespace -hi o -ha 01000000 > run.out

echo "NV Define Space"
${PREFIX}nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 3 > run.out
checkSuccess $?

echo "NV Read Public, unwritten Name"
${PREFIX}nvreadpublic -ha 01000000 > run.out
checkSuccess $?

echo "Bind session bound to unwritten NV index at 01000000"
${PREFIX}startauthsession -se h -bi 01000000 -pwdb nnn > run.out
checkSuccess $?

echo "NV write HMAC using bind session to set written"
${PREFIX}nvwrite -ha 01000000 -pwdn nnn -ic 123 -se0 02000000 0 > run.out
checkSuccess $?

echo "Bind session bound to written NV index at 01000000"
${PREFIX}startauthsession -se h -bi 01000000 -pwdb nnn > run.out
checkSuccess $?

echo "NV Write HMAC using bind session"
${PREFIX}nvwrite -ha 01000000 -pwdn nnn -ic 123 -se0 02000000 1 > run.out
checkSuccess $?

echo "NV Read HMAC using bind session"
${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 3 -se0 02000000 1 > run.out
checkSuccess $?

echo "NV Read HMAC using bind session, wrong password does not matter"
${PREFIX}nvread -ha 01000000 -pwdn xxx -sz 3 -se0 02000000 1 > run.out
checkSuccess $?

echo "Create storage key using that bind session"
${PREFIX}create -hp 80000000 -st -kt f -kt p -pwdp sto -pwdk 222 -se0 02000000 0 > run.out
checkSuccess $?

echo "NV Undefine Space"
${PREFIX}nvundefinespace -hi o -ha 01000000 > run.out
checkSuccess $?

echo ""
echo "Encrypt with bind to same object"
echo ""

for MODE0 in xor aes

do

    echo "Start an HMAC auth session with $MODE0 encryption and bind to primary key at 80000000"
    ${PREFIX}startauthsession -se h -sym $MODE0 -bi 80000000 -pwdb sto > run.out
    checkSuccess $?

    echo "Create storage key using bind session, same object, wrong password"
    ${PREFIX}create -hp 80000000 -st -kt f -kt p -pwdk 222 -pwdp xxx -opr tmppriv.bin -opu tmppub.bin -se0 02000000 61 > run.out
    checkSuccess $?

    echo "Create storage key using bind session, same object 80000000"
    ${PREFIX}create -hp 80000000 -st -kt f -kt p -pwdk 222 -opr tmppriv.bin -opu tmppub.bin -se0 02000000 61 > run.out
    checkSuccess $?

    echo "Load the key, with $MODE0 encryption"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto -se0 02000000 61 > run.out
    checkSuccess $?

    echo "Flush the sealed object"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Flush the $MODE0 session"
    ${PREFIX}flushcontext -ha 02000000 > run.out
    checkSuccess $?

done

echo ""
echo "Encrypt with bind to different object"
echo ""

for MODE0 in xor aes

do

    echo "Start an HMAC auth session with $MODE0 encryption and bind to platform auth"
    ${PREFIX}startauthsession -se h -sym $MODE0 -bi 4000000c > run.out
    checkSuccess $?

    echo "Create storage key using bind session, different object, wrong password, should fail"
    ${PREFIX}create -hp 80000000 -st -kt f -kt p -pwdk 222 -pwdp xxx -opr tmppriv.bin -opu tmppub.bin -se0 02000000 61 > run.out
    checkFailure $?

    echo "Create storage key using bind session, different object"
    ${PREFIX}create -hp 80000000 -st -kt f -kt p -pwdk 222 -pwdp sto -opr tmppriv.bin -opu tmppub.bin -se0 02000000 61 > run.out
    checkSuccess $?

    echo "Load the key, with $MODE0 encryption"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto -se0 02000000 61 > run.out
    checkSuccess $?

    echo "Flush the sealed object"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Flush the $MODE0 session"
    ${PREFIX}flushcontext -ha 02000000 > run.out
    checkSuccess $?

done

echo ""
echo "PolicyAuthValue and bind to different object, command encryption"
echo ""

echo "Create a signing key under the primary key - policy command code - sign, auth"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyccsign-auth.bin > run.out
checkSuccess $?

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start a policy session, bind to primary key"
${PREFIX}startauthsession -se p -bi 80000000 -pwdb sto > run.out
checkSuccess $?

echo "Policy command code - sign"
${PREFIX}policycommandcode -ha 03000000 -cc 15d > run.out
checkSuccess $?

echo "Policy authvalue"
${PREFIX}policyauthvalue -ha 03000000 > run.out
checkSuccess $?

echo "Sign a digest - policy, command encrypt"
${PREFIX}sign -hk 80000001 -if policies/aaa -os sig.bin -ipu tmppub.bin -se0 03000000 21 -pwdk sig > run.out
checkSuccess $?

echo "Verify the signature"
${PREFIX}verifysignature -hk 80000001 -if policies/aaa -is sig.bin > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out 
checkSuccess $?

echo "Flush the session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo ""
echo "PolicyAuthValue and bind to same object, command encryption"
echo ""

echo "Create a signing key under the primary key - policy command code - sign, auth"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyccsign-auth.bin > run.out
checkSuccess $?

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p -bi 80000001 -pwdb sig > run.out
checkSuccess $?

echo "Policy command code - sign"
${PREFIX}policycommandcode -ha 03000000 -cc 15d > run.out
checkSuccess $?

echo "Policy authvalue"
${PREFIX}policyauthvalue -ha 03000000 > run.out
checkSuccess $?

echo "Sign a digest - policy, command encrypt"
${PREFIX}sign -hk 80000001 -if policies/aaa -os sig.bin -ipu tmppub.bin -se0 03000000 21 -pwdk sig > run.out
checkSuccess $?

echo "Verify the signature"
${PREFIX}verifysignature -hk 80000001 -if policies/aaa -is sig.bin > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo ""
echo "PolicyAuthValue and bind to different object, response encryption"
echo ""

#intermediate policy digest length 32
# 54 a0 de 17 1d 03 c6 9b 17 b3 61 22 33 a5 e8 b2 
# d8 ee e0 87 f9 c6 ea 85 8c 9c 2e 51 05 52 8b 14 
# policy
# 4b 50 04 f7 3f 2e f8 c0 96 c9 18 d0 bc 18 0e 6b 
# 49 0c 8a ed 14 bb 8f 86 fc 5a 54 ef 0c d3 90 44 

echo "Create a storage key under the primary key - policy command code - create, auth"
${PREFIX}create -hp 80000000 -st -kt f -kt p -opr tmpspriv.bin -opu tmpspub.bin -pwdp sto -pwdk sto -pol policies/policycccreate-auth.bin > run.out
checkSuccess $?

echo "Load the storage key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmpspriv.bin -ipu tmpspub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start a policy session, bind to primary key"
${PREFIX}startauthsession -se p -bi 80000000 -pwdb sto > run.out
checkSuccess $?

echo "Policy command code - create"
${PREFIX}policycommandcode -ha 03000000 -cc 153 > run.out
checkSuccess $?

echo "Policy authvalue"
${PREFIX}policyauthvalue -ha 03000000 > run.out
checkSuccess $?

echo "Create a signing key with response encryption"
${PREFIX}create -hp 80000001 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -se0 03000000 41 > run.out
checkSuccess $?

echo "Load the signing key to verify response encryption"
${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Flush the storage key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000002 > run.out 
checkSuccess $?

echo "Flush the session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo ""
echo "PolicyAuthValue and bind to same object, response encryption"
echo ""

echo "Create a storage key under the primary key - policy command code - create, auth"
${PREFIX}create -hp 80000000 -st -kt f -kt p -opr tmpspriv.bin -opu tmpspub.bin -pwdp sto -pwdk sto -pol policies/policycccreate-auth.bin > run.out
checkSuccess $?

echo "Load the storage key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmpspriv.bin -ipu tmpspub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start a policy session, bind to storage key"
${PREFIX}startauthsession -se p -bi 80000001 -pwdb sto > run.out
checkSuccess $?

echo "Policy command code - create"
${PREFIX}policycommandcode -ha 03000000 -cc 153 > run.out
checkSuccess $?

echo "Policy authvalue"
${PREFIX}policyauthvalue -ha 03000000 > run.out
checkSuccess $?

echo "Create a signing key with response encryption"
${PREFIX}create -hp 80000001 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -se0 03000000 41 > run.out
checkSuccess $?

echo "Load the signing key to verify response encryption"
${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Flush the storage key"
${PREFIX}flushcontext -ha 80000001 > run.out 
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000002 > run.out 
checkSuccess $?

echo "Flush the session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 02000000
