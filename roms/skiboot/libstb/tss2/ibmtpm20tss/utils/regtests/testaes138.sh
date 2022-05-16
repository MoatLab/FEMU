#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	$Id: testaes.sh 714 2016-08-11 21:46:03Z kgoldman $			#
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
echo "AES symmetric key"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    echo "Load the symmetric cipher key under the primary key ${SESS}"
    ${PREFIX}load -hp 80000000 -ipr despriv.bin -ipu despub.bin -pwdp sto ${SESS} > run.out
    checkSuccess $?

    echo "Encrypt using the symmetric cipher key ${SESS}"
    ${PREFIX}encryptdecrypt -2 -hk 80000001 -if msg.bin -of enc.bin -pwdk aes ${SESS} > run.out
    checkSuccess $?

    echo "Decrypt using the symmetric cipher key ${SESS}"
    ${PREFIX}encryptdecrypt -2 -hk 80000001 -d -if enc.bin -of dec.bin -pwdk aes ${SESS} > run.out
    checkSuccess $?

    echo "Verify the decrypt result"
    diff msg.bin dec.bin > run.out
    checkSuccess $?

    echo "Encrypt using the symmetric cipher key 0 length message ${SESS}"
    ${PREFIX}encryptdecrypt -2 -hk 80000001 -if zero.bin -of enc.bin -pwdk aes ${SESS} > run.out
    checkSuccess $?

    echo "Decrypt using the symmetric cipher key ${SESS}"
    ${PREFIX}encryptdecrypt -2 -hk 80000001 -d -if enc.bin -of dec.bin -pwdk aes ${SESS} > run.out
    checkSuccess $?

    echo "Verify the decrypt result"
    diff zero.bin dec.bin > run.out
    checkSuccess $?

    echo "Flush the symmetric cipher key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Create a primary symmetric cipher key ${SESS}"
    ${PREFIX}createprimary -des -pwdk aesp ${SESS} > run.out
    checkSuccess $?
 
    echo "Encrypt using the symmetric cipher primary key ${SESS}"
    ${PREFIX}encryptdecrypt -2 -hk 80000001 -if msg.bin -of enc.bin -pwdk aesp ${SESS}> run.out
    checkSuccess $?

    echo "Decrypt using the symmetric cipher primary key ${SESS}"
    ${PREFIX}encryptdecrypt -2 -hk 80000001 -d -if enc.bin -of dec.bin -pwdk aesp ${SESS}> run.out
    checkSuccess $?

    echo "Verify the decrypt result"
    diff msg.bin dec.bin > run.out
    checkSuccess $?

    echo "Flush the symmetric cipher key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 02000000
