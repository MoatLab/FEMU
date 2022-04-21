#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2019 - 2020					#
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
echo "Attestation - rev 155"
echo ""

# 80000001 RSA signing key
# 80000002 ECC signing key

echo "Load the RSA signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Load the ECC signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr signeccpriv.bin -ipu signeccpub.bin -pwdp sto > run.out
checkSuccess $?

echo "NV Define Space"
${PREFIX}nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 > run.out
checkSuccess $?

echo "NV Read Public, unwritten Name"
${PREFIX}nvreadpublic -ha 01000000 > run.out
checkSuccess $?

echo "NV write"
${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if msg.bin > run.out
checkSuccess $?

echo "Start an HMAC session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do
    for HALG in ${ITERATE_ALGS}
    do

	for SALG in rsa ecc
	do

	    if [ ${SALG} == rsa ]; then
		HANDLE=80000001
	    else
		HANDLE=80000002
	    fi

	    echo "NV Certify a digest ${HALG} ${SALG} ${SESS}"
	    ${PREFIX}nvcertify -ha 01000000 -pwdn nnn -hk ${HANDLE} -pwdk sig -halg ${HALG} -sz 0 ${SESS} -os sig.bin -oa tmp.bin -salg ${SALG} -od tmpdigest1.bin > run.out
	    checkSuccess $?

	    echo "Verify the ${SALG} signature ${HALG}"
	    ${PREFIX}verifysignature -hk ${HANDLE} -halg ${HALG} -if tmp.bin -is sig.bin > run.out
	    checkSuccess $?

	    echo "NV read"
	    ${PREFIX}nvread -ha 01000000 -pwdn nnn -of tmpdata.bin > run.out
	    checkSuccess $?

	    echo "Digest the hashed and certified NV data ${HALG}"
	    ${PREFIX}hash -halg ${HALG} -if tmpdata.bin -oh tmpdigest2.bin
	    checkSuccess $?

	    echo "Check the digest ${HALG} results"
	    diff tmpdigest1.bin tmpdigest2.bin
	    checkSuccess $?

	done
    done
done

echo "Flush the RSA attestation key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the ECC attestation key"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "NV Undefine Space"
${PREFIX}nvundefinespace -hi o -ha 01000000 > run.out
checkSuccess $?

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

# cleanup

rm -f tmpdigest1.bin
rm -f tmpdata.bin
rm -f tmpdigest2.bin
