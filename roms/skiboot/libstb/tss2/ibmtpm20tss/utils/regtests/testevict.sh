#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#		$Id: testevict.sh 1277 2018-07-23 20:30:23Z kgoldman $		#
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
echo "Evict Control"
echo ""

echo "Create an unrestricted signing key"
${PREFIX}create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig > run.out
checkSuccess $?

echo "Load the signing key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Make the signing key persistent"
${PREFIX}evictcontrol -ho 80000001 -hp 81800000 -hi p > run.out
checkSuccess $?

echo "Sign a digest with the transient key"
${PREFIX}sign -hk 80000001 -halg sha1 -if policies/aaa -os sig.bin -pwdk sig > run.out
checkSuccess $?

echo "Sign a digest with the persistent key"
${PREFIX}sign -hk 81800000 -halg sha1 -if policies/aaa -os sig.bin -pwdk sig > run.out
checkSuccess $?

echo "Flush the transient key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the persistent key - should fail"
${PREFIX}flushcontext -ha 81800000 > run.out
checkFailure $?

echo "Sign a digest with the transient key- should fail"
${PREFIX}sign -hk 80000001 -halg sha1 -if policies/aaa -os sig.bin -pwdk sig > run.out
checkFailure $?

echo "Sign a digest with the persistent key"
${PREFIX}sign -hk 81800000 -halg sha1 -if policies/aaa -os sig.bin -pwdk sig > run.out
checkSuccess $?

echo "Flush the persistent key"
${PREFIX}evictcontrol -ho 81800000 -hp 81800000 -hi p > run.out
checkSuccess $?

echo "Sign a digest with the persistent key - should fail"
${PREFIX}sign -hk 81800000 -halg sha1 -if policies/aaa -os sig.bin -pwdk sig > run.out
checkFailure $?

echo "Sign a digest with the transient key - should fail"
${PREFIX}sign -hk 80000001 -halg sha1 -if policies/aaa -os sig.bin -pwdk sig > run.out
checkFailure $?

# ${PREFIX}getcapability  -cap 1 -pr 80000000
# ${PREFIX}getcapability  -cap 1 -pr 81000000
# ${PREFIX}getcapability  -cap 1 -pr 02000000
# ${PREFIX}getcapability  -cap 1 -pr 01000000
