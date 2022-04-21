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
echo "Object Change Auth"
echo ""

for BIND in "" "-bi 80000001 -pwdb sig"
do

    for SESS in "" "-se0 02000000 1"
    do

	echo "Load the signing key under the primary key"
	${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
	checkSuccess $?

	echo "Start an HMAC session ${BIND}"
	${PREFIX}startauthsession -se h ${BIND} > run.out
	checkSuccess $?

	echo "Object change auth, change password to xxx ${SESS}"
	${PREFIX}objectchangeauth -ho 80000001 -pwdo sig -pwdn xxx -hp 80000000 -opr tmppriv.bin ${SESS} > run.out
	checkSuccess $?

	echo "Load the signing key with the changed auth ${SESS}"
	${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu signrsa2048pub.bin -pwdp sto ${SESS} > run.out
	checkSuccess $?

	echo "Sign a digest with the original key ${SESS}"
	${PREFIX}sign -hk 80000001 -halg sha1 -if policies/aaa -os sig.bin -pwdk sig ${SESS} > run.out
	checkSuccess $?

	echo "Sign a digest with the changed key"
	${PREFIX}sign -hk 80000002 -halg sha1 -if policies/aaa -os sig.bin -pwdk xxx > run.out
	checkSuccess $?

	echo "Flush the key"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

	echo "Flush the key"
	${PREFIX}flushcontext -ha 80000002 > run.out
	checkSuccess $?

	echo "Flush the auth session"
	${PREFIX}flushcontext -ha 02000000 > run.out
	checkSuccess $?

    done
done

echo ""
echo "Object Change Auth with password from file"
echo ""

echo "Load the decryption key under the primary key 80000001"
${PREFIX}load -hp 80000000 -ipr derrsa2048priv.bin -ipu derrsa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Generate a random password"
RANDOM_PASSWORD=`${PREFIX}getrandom -by 16 -ns -nz -of tmppwd.bin`
echo " INFO: Random password ${RANDOM_PASSWORD}"

echo "Object change auth, change password to ${RANDOM_PASSWORD}"
${PREFIX}objectchangeauth -hp 80000000 -ho 80000001 -pwdo dec -ipwdn tmppwd.bin -opr tmppriv.bin > run.out
checkSuccess $?

echo "Load the decryption key with the changed auth 800000002"
${PREFIX}load -hp 80000000 -pwdp sto -ipr tmppriv.bin -ipu derrsa2048pub.bin > run.out
checkSuccess $?

echo "Encrypt the message"
${PREFIX}rsaencrypt -hk 80000002 -id policies/aaa -oe tmpenc.bin > run.out
checkSuccess $?

echo "Decrypt the message"
${PREFIX}rsadecrypt -hk 80000002 -ipwdk tmppwd.bin -ie tmpenc.bin -od tmpdec.bin > run.out
checkSuccess $?

echo "Compare the result"
tail -c 3 tmpdec.bin > tmp.bin
diff policies/aaa tmp.bin
checkSuccess $?

echo "Flush the keypair 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the keypair 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

# cleanup

rm -f tmppwd.bin
rm -f tmpenc.bin
rm -f tmpdec.bin

# ${PREFIX}getcapability  -cap 1 -pr 80000000
# ${PREFIX}getcapability  -cap 1 -pr 02000000

# ${PREFIX}flushcontext -ha 80000001
# ${PREFIX}flushcontext -ha 80000002
# ${PREFIX}flushcontext -ha 02000000
