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
echo "Keyed hash HMAC key"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

# session 02000000
# loaded HMAC key 80000001
# primary HMAC key 80000001
# sequence object 80000002

for HALG in ${ITERATE_ALGS}
do

    for SESS in "" "-se0 02000000 1"
    do

	echo "Load the ${HALG} keyed hash key under the primary key"
	${PREFIX}load -hp 80000000 -ipr khpriv${HALG}.bin -ipu khpub${HALG}.bin -pwdp sto > run.out
	checkSuccess $?

	echo "HMAC ${HALG} using the keyed hash key, message from file ${SESS}"
	${PREFIX}hmac -hk 80000001 -if msg.bin -os sig.bin -pwdk khk -halg ${HALG} ${SESS} > run.out
	checkSuccess $?

	echo "HMAC ${HALG} start using the keyed hash key ${SESS}"
	${PREFIX}hmacstart -hk 80000001 -pwdk khk -pwda aaa ${SESS} -halg ${HALG} > run.out
	checkSuccess $?

	echo "HMAC ${HALG} sequence update ${SESS}"
	${PREFIX}sequenceupdate -hs 80000002 -pwds aaa -if msg.bin ${SESS} > run.out
	checkSuccess $?

	echo "HMAC ${HALG} sequence complete ${SESS}"
	${PREFIX}sequencecomplete -hs 80000002 -pwds aaa -of tmp.bin ${SESS} > run.out
	checkSuccess $?

	echo "Verify the HMAC ${HALG} using the two methods"
	diff sig.bin tmp.bin > run.out
	checkSuccess $?

	echo "HMAC ${HALG} using the keyed hash key, message from command line ${SESS}"
	${PREFIX}hmac -hk 80000001 -ic 1234567890123456 -os sig.bin -pwdk khk -halg ${HALG} ${SESS} > run.out
	checkSuccess $?

	echo "Verify the HMAC ${HALG} using the two methods"
	diff sig.bin tmp.bin > run.out
	checkSuccess $?

	echo "Flush the ${HALG} HMAC key"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

	echo "Create primary HMAC key - $HALG"
	${PREFIX}createprimary -kh -halg ${HALG} -pwdk khp > run.out
	checkSuccess $?

	echo "HMAC ${HALG} using the keyed hash primary key ${SESS}"
	${PREFIX}hmac -hk 80000001 -if msg.bin -os sig.bin -pwdk khp -halg ${HALG} ${SESS} > run.out
	checkSuccess $?

	echo "HMAC ${HALG} start using the keyed hash primary key ${SESS}"
	${PREFIX}hmacstart -hk 80000001 -pwdk khp -pwda aaa ${SESS} -halg ${HALG} > run.out
	checkSuccess $?

	echo "HMAC ${HALG} sequence update ${SESS}"
	${PREFIX}sequenceupdate -hs 80000002 -pwds aaa -if msg.bin ${SESS} > run.out
	checkSuccess $?

	echo "HMAC ${HALG} sequence complete ${SESS}"
	${PREFIX}sequencecomplete -hs 80000002 -pwds aaa -of tmp.bin ${SESS} > run.out
	checkSuccess $?

	echo "Verify the HMAC ${HALG} using the two methods"
	diff sig.bin tmp.bin > run.out
	checkSuccess $?

	echo "Flush the ${HALG} primary HMAC key"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

    done
done

echo ""
echo "Hash"
echo ""

for HALG in ${ITERATE_ALGS}
do

    for SESS in "" "-se0 02000000 1"
    do

	echo "Hash ${HALG} in one call, data from file"
	${PREFIX}hash -hi p -halg ${HALG} -if policies/aaa -oh tmp.bin > run.out
	checkSuccess $?

	echo "Verify the hash ${HALG}"
	diff tmp.bin policies/${HALG}aaa.bin > run.out
	checkSuccess $?

	echo "Hash ${HALG} in one call, data on command line"
	${PREFIX}hash -hi p -halg ${HALG} -ic aaa -oh tmp.bin > run.out
	checkSuccess $?

	echo "Verify the hash ${HALG}"
	diff tmp.bin policies/${HALG}aaa.bin > run.out
	checkSuccess $?

	echo "Hash ${HALG} sequence start"
	${PREFIX}hashsequencestart -halg ${HALG} -pwda aaa > run.out
	checkSuccess $?

	echo "Hash ${HALG} sequence update ${SESS}"
	${PREFIX}sequenceupdate -hs 80000001 -pwds aaa -if policies/aaa ${SESS} > run.out
	checkSuccess $?

	echo "Hash ${HALG} sequence complete ${SESS}"
	${PREFIX}sequencecomplete -hi p -hs 80000001 -pwds aaa -of tmp.bin ${SESS} > run.out
	checkSuccess $?

	echo "Verify the ${HALG} hash"
	diff tmp.bin policies/${HALG}aaa.bin > run.out
	checkSuccess $?

    done
done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 02000000

echo ""
echo "Sign with ticket"
echo ""

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr signrsa2048rpriv.bin -ipu signrsa2048rpub.bin -pwdp sto > run.out
checkSuccess $?

echo "Hash and create ticket"
${PREFIX}hash -hi p -halg sha256 -if msg.bin -oh sig.bin -tk tkt.bin > run.out
checkSuccess $?

echo "Sign a digest with a restricted signing key and no ticket - should fail"
${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig > run.out
checkFailure $?

echo "Sign a digest with a restricted signing key and ticket"
${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -tk tkt.bin -os sig.bin -pwdk sig > run.out
checkSuccess $?

echo "Hash and create null ticket, msg with TPM_GENERATED"
${PREFIX}hash -hi p -halg sha256 -if policies/msgtpmgen.bin -oh sig.bin -tk tkt.bin > run.out
checkSuccess $?

echo "Sign a digest with a restricted signing key and ticket - should fail"
${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -tk tkt.bin -os sig.bin -pwdk sig > run.out
checkFailure $?

echo "Hash sequence start"
${PREFIX}hashsequencestart -halg sha256 -pwda aaa > run.out
checkSuccess $?

echo "Hash sequence update "
${PREFIX}sequenceupdate -hs 80000002 -pwds aaa -if msg.bin > run.out
checkSuccess $?

echo "Hash sequence complete"
${PREFIX}sequencecomplete -hi p -hs 80000002 -pwds aaa -of tmp.bin -tk tkt.bin > run.out
checkSuccess $?

echo "Sign a digest with a restricted signing key and no ticket - should fail"
${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig > run.out
checkFailure $?

echo "Sign a digest with a restricted signing key and ticket"
${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -tk tkt.bin -os sig.bin -pwdk sig > run.out
checkSuccess $?

echo "Hash sequence start"
${PREFIX}hashsequencestart -halg sha256 -pwda aaa -halg sha256 > run.out
checkSuccess $?

echo "Hash sequence update, msg with TPM_GENERATED"
${PREFIX}sequenceupdate -hs 80000002 -pwds aaa -if policies/msgtpmgen.bin > run.out
checkSuccess $?

echo "Hash sequence complete"
${PREFIX}sequencecomplete -hi p -hs 80000002 -pwds aaa -of tmp.bin -tk tkt.bin > run.out
checkSuccess $?

echo "Sign a digest with a restricted signing key and ticket - should fail"
${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -tk tkt.bin -os sig.bin -pwdk sig > run.out
checkFailure $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

rm -f tmp.bin
rm -f tmp1.bin

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 02000000

