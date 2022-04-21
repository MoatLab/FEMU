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

TWOAUTH0=(01 01 01 01 21 21 41 41 61)
TWOAUTH1=(01 21 41 61 01 41 01 21 01)

THREEAUTH0=(01 01 01 01 01 21 41)
THREEAUTH1=(01 01 01 21 41 01 01)
THREEAUTH2=(21 41 61 41 21 41 21)

echo ""
echo "Parameter Encryption - Basic"
echo ""

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
checkSuccess $?

for MODE0 in xor aes
do 

    for MODE1 in xor aes
    do

	for MODE2 in xor aes
	do

	    echo "Start an HMAC auth session with $MODE0 encryption"
	    ${PREFIX}startauthsession -se h -sym $MODE0 > run.out
	    checkSuccess $?

	    echo "Start an HMAC auth session with $MODE1 encryption"
	    ${PREFIX}startauthsession -se h -sym $MODE1 > run.out
	    checkSuccess $?

	    echo "Start an HMAC auth session with $MODE2 encryption"
	    ${PREFIX}startauthsession -se h -sym $MODE2 > run.out
	    checkSuccess $?

	    # one auth

	    for AUTH0 in 21 41 61
	    do

		echo "Signing Key Self Certify, one auth $AUTH0"
		${PREFIX}certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -qd policies/aaa -os sig.bin -oa tmp.bin -se0 02000000 $AUTH0 > run.out
		checkSuccess $?

	    done

	    # two auth
		
	    for ((i = 0 ; i < 9; i++))
	    do

		echo "Signing Key Self Certify, two auth ${TWOAUTH0[i]} ${TWOAUTH1[i]}"
		${PREFIX}certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -qd policies/aaa -os sig.bin -oa tmp.bin -se0 02000000 ${TWOAUTH0[i]} -se1 02000001 ${TWOAUTH1[i]} > run.out
		checkSuccess $?

	    done

	    # three auth

	    for ((i = 0 ; i < 7; i++))
	    do

		echo "Signing Key Self Certify, three auth ${THREEAUTH0[i]} ${THREEAUTH1[i]} ${THREEAUTH2[i]}"
		${PREFIX}certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -qd policies/aaa -os sig.bin -oa tmp.bin -se0 02000000 ${THREEAUTH0[i]} -se1 02000001 ${THREEAUTH1[i]} -se2 02000002 ${THREEAUTH2[i]} > run.out
		checkSuccess $?

	    done

	    echo "Flush the sessions"
	    ${PREFIX}flushcontext -ha 02000000 > run.out
	    checkSuccess $?

	    echo "Flush the sessions"
	    ${PREFIX}flushcontext -ha 02000001 > run.out
	    checkSuccess $?

	    echo "Flush the sessions"
	    ${PREFIX}flushcontext -ha 02000002 > run.out
	    checkSuccess $?
	done
    done
done

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Create a signing key, policy command code certify"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policycccertify.bin > run.out
checkSuccess $?

echo ""
echo "Salt encrypt and decrypt HMAC sessions"
echo ""

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start an auth session"
${PREFIX}startauthsession -se h -hs 80000000 > run.out
checkSuccess $?

echo "Start an auth session"
${PREFIX}startauthsession -se h -hs 80000000 > run.out
checkSuccess $?

echo "Start an encrypt session"
${PREFIX}startauthsession -se h -hs 80000000 > run.out
checkSuccess $?

for ((i = 0 ; i < 7 ; i++))
do

    echo "Signing Key Self Certify, three auth, salted parameter encryption ${THREEAUTH0[i]} ${THREEAUTH1[i]} ${THREEAUTH2[i]}"
    ${PREFIX}certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -qd policies/aaa -os sig.bin -oa tmp.bin -se0 02000000 ${THREEAUTH0[i]} -se1 02000001 ${THREEAUTH1[i]} -se2 02000002 ${THREEAUTH2[i]} > run.out
    checkSuccess $?

done

echo "Flush the sessions"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo "Flush the sessions"
${PREFIX}flushcontext -ha 02000001 > run.out
checkSuccess $?

echo "Flush the sessions"
${PREFIX}flushcontext -ha 02000002 > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Bind encrypt and decrypt HMAC sessions"
echo ""

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start an auth session"
${PREFIX}startauthsession -se h -bi 80000001 -pwdb sig > run.out
checkSuccess $?

echo "Start an auth session"
${PREFIX}startauthsession -se h -bi 80000001 -pwdb sig > run.out
checkSuccess $?

echo "Start an encrypt session"
${PREFIX}startauthsession -se h -bi 80000001 -pwdb sig > run.out
checkSuccess $?

for ((i = 0 ; i < 7 ; i++))
do

    echo "Signing Key Self Certify, three auth, bind parameter encryption ${THREEAUTH0[i]} ${THREEAUTH1[i]} ${THREEAUTH2[i]}"
    ${PREFIX}certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -qd policies/aaa -os sig.bin -oa tmp.bin -se0 02000000 ${THREEAUTH0[i]} -se1 02000001 ${THREEAUTH1[i]} -se2 02000002 ${THREEAUTH2[i]} > run.out
    checkSuccess $?

done

echo "Flush the sessions"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo "Flush the sessions"
${PREFIX}flushcontext -ha 02000001 > run.out
checkSuccess $?

echo "Flush the sessions"
${PREFIX}flushcontext -ha 02000002 > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?


# policycccertify.txt 0000016c00000148
# policymaker -if policies/policycccertify.txt -of policies/policycccertify.bin -v -pr 
# 04 8e 9a 3a ce 08 58 3f 79 f3 44 ff 78 5b be a9 
# f0 7a c7 fa 33 25 b3 d4 9a 21 dd 51 94 c6 58 50 

echo ""
echo "Salt encrypt and decrypt policy sessions"
echo ""

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start an auth session"
${PREFIX}startauthsession -se h -hs 80000000 > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p -hs 80000000 > run.out
checkSuccess $?

echo "Start an encrypt session"
${PREFIX}startauthsession -se h -hs 80000000 > run.out
checkSuccess $?

for ((i = 0 ; i < 7 ; i++))
do

    echo "Policy restart"
    ${PREFIX}policyrestart -ha 03000001 > run.out
    checkSuccess $?

    echo "Policy command code - certify"
    ${PREFIX}policycommandcode -ha 03000001 -cc 148 > run.out
    checkSuccess $?

    echo "Signing Key Self Certify, three auth, salted parameter encryption ${THREEAUTH0[i]} ${THREEAUTH1[i]} ${THREEAUTH2[i]}"
    ${PREFIX}certify -hk 80000001 -ho 80000001 -pwdo sig -pwdk sig -qd policies/aaa -os sig.bin -oa tmp.bin -se0 02000000 ${THREEAUTH0[i]} -se1 03000001 ${THREEAUTH1[i]} -se2 02000002 ${THREEAUTH2[i]} > run.out
    checkSuccess $?

done

echo "Flush the sessions"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo "Flush the sessions"
${PREFIX}flushcontext -ha 03000001 > run.out
checkSuccess $?

echo "Flush the sessions"
${PREFIX}flushcontext -ha 02000002 > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Bind encrypt and decrypt policy sessions"
echo ""

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start an auth session"
${PREFIX}startauthsession -se h -bi 80000001 -pwdb sig > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p -bi 80000001 -pwdb sig > run.out
checkSuccess $?

echo "Start an encrypt session"
${PREFIX}startauthsession -se h -bi 80000001 -pwdb sig > run.out
checkSuccess $?

for ((i = 0 ; i < 7 ; i++))
do

    echo "Policy restart"
    ${PREFIX}policyrestart -ha 03000001 > run.out
    checkSuccess $?

    echo "Policy command code - certify"
    ${PREFIX}policycommandcode -ha 03000001 -cc 148 > run.out
    checkSuccess $?

    echo "Signing Key Self Certify, three auth, bind parameter encryption ${THREEAUTH0[i]} ${THREEAUTH1[i]} ${THREEAUTH2[i]}"
    ${PREFIX}certify -hk 80000001 -ho 80000001 -pwdo sig -pwdk xxx -qd policies/aaa -os sig.bin -oa tmp.bin -se0 02000000 ${THREEAUTH0[i]} -se1 03000001 ${THREEAUTH1[i]} -se2 02000002 ${THREEAUTH2[i]} > run.out
    checkSuccess $?

done

echo "Flush the sessions"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo "Flush the sessions"
${PREFIX}flushcontext -ha 03000001 > run.out
checkSuccess $?

echo "Flush the sessions"
${PREFIX}flushcontext -ha 02000002 > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?



# getcapability  -cap 1 -pr 80000000
# getcapability  -cap 1 -pr 02000000
