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

# Primary storage key at 80000000 password sto
# storage key at 80000001 password sto

echo ""
echo "RSA Storage key"
echo ""

echo "Load the RSA storage key 80000001 under the primary key 80000000"
${PREFIX}load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for NALG in ${ITERATE_ALGS}
do

    for SESS in "" "-se0 02000000 1"
    do

	echo "Create an unrestricted signing key under the RSA storage key 80000001 ${NALG} ${SESS}"
	${PREFIX}create -hp 80000001 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 111 -nalg ${NALG} ${SESS} > run.out
	checkSuccess $?

	echo "Load the signing key 80000002 under the storage key 80000001 ${SESS}"
	${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto ${SESS} > run.out
	checkSuccess $?

	echo "Read the signing key 80000002 public area"
	${PREFIX}readpublic -ho 80000002 -opu tmppub2.bin > run.out
	checkSuccess $?

	echo "Flush the signing key 80000002"
	${PREFIX}flushcontext -ha 80000002 > run.out
	checkSuccess $?

	echo "Load external just the storage key public part 80000002 ${NALG}"
	${PREFIX}loadexternal -halg sha256 -nalg ${NALG} -ipu storersa2048pub.bin > run.out
	checkSuccess $?

	echo "Flush the public key 80000002"
	${PREFIX}flushcontext -ha 80000002 > run.out
	checkSuccess $?

	echo "Load external, signing key public part 80000002 ${NALG}"
	${PREFIX}loadexternal -halg sha256 -nalg ${NALG} -ipu tmppub2.bin > run.out
	checkSuccess $?

	echo "Flush the public key 80000002"
	${PREFIX}flushcontext -ha 80000002 > run.out
	checkSuccess $?
    done
done

echo "Flush the RSA storage key 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "ECC Storage key"
echo ""

echo "Load ECC the storage key 80000001 under the primary key 80000000"
${PREFIX}load -hp 80000000 -ipr storeeccpriv.bin -ipu storeeccpub.bin -pwdp sto > run.out
checkSuccess $?

for NALG in ${ITERATE_ALGS}
do

    for SESS in "" "-se0 02000000 1"
    do

	echo "Create an unrestricted signing key under the ECC storage key 80000001 ${NALG} ${SESS}"
	${PREFIX}create -hp 80000001 -si -kt f -kt p -ecc nistp256 -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 111 -nalg ${NALG} ${SESS} > run.out
	checkSuccess $?

	echo "Load the ECC signing key 80000002 under the ECC storage key 80000001 ${SESS}"
	${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto ${SESS}> run.out
	checkSuccess $?

	echo "Read the signing key 80000002 public area"
	${PREFIX}readpublic -ho 80000002 -opu tmppub2.bin > run.out
	checkSuccess $?

	echo "Flush the signing key 80000002"
	${PREFIX}flushcontext -ha 80000002 > run.out
	checkSuccess $?

	echo "Load external, storage key public part 80000002 ${NALG}"
	${PREFIX}loadexternal -halg sha256 -nalg ${NALG} -ipu storeeccpub.bin > run.out
	checkSuccess $?

	echo "Flush the public key 80000002"
	${PREFIX}flushcontext -ha 80000002 > run.out
	checkSuccess $?

	echo "Load external, signing key public part 80000002 ${NALG}"
	${PREFIX}loadexternal -halg sha256 -nalg ${NALG} -ipu tmppub2.bin > run.out
	checkSuccess $?

	echo "Flush the signing key 80000002"
	${PREFIX}flushcontext -ha 80000002 > run.out
	checkSuccess $?
    done
done

echo "Flush the ECC storage key 80000001 "
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

rm -f tmppub2.bin
rm -f tmppub.bin
rm -f tmppriv.bin
rm -f tmpsig.bin

# ${PREFIX}getcapability  -cap 1 -pr 80000000
# ${PREFIX}getcapability  -cap 1 -pr 02000000
