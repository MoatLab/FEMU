#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#		$Id: testchangeseed.sh 1277 2018-07-23 20:30:23Z kgoldman $	#
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
echo "Change PPS"
echo ""

echo "Flush the primary key"
${PREFIX}flushcontext -ha 80000000 > run.out
checkSuccess $?

echo "Change PPS, no password"
${PREFIX}changepps > run.out
checkSuccess $?

echo "Set platform hierarchy auth"
${PREFIX}hierarchychangeauth -hi p -pwdn ppp > run.out
checkSuccess $?

echo "Change PPS, bad password"
${PREFIX}changepps > run.out
checkFailure $?

echo "Change PPS, good password"
${PREFIX}changepps -pwda ppp > run.out
checkSuccess $?

echo "Clear platform hierarchy auth"
${PREFIX}hierarchychangeauth -hi p -pwda ppp > run.out
checkSuccess $?

echo "Create a primary key - platform hierarchy"
${PREFIX}createprimary -hi p -pwdk 111 > run.out
checkSuccess $?

echo "Create a storage key under the primary key"
${PREFIX}create -hp 80000000 -st -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp 111 -pwdk 222 > run.out
checkSuccess $?

echo "Load the storage key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp 111 > run.out
checkSuccess $?

echo "Change PPS - flushes primary key"
${PREFIX}changepps > run.out
checkSuccess $?

echo "Load the storage key under the flushed primary key, should fail"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp 111 > run.out
checkFailure $?

echo "Create a different primary key - new PPS"
${PREFIX}createprimary -hi p -pwdk 111 > run.out
checkSuccess $?

echo "Load the storage key under the new primary key, should fail"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp 111 > run.out
checkFailure $?

# getcapability  -cap 1 -pr 80000000
# getcapability  -cap 1 -pr 02000000

echo ""
echo "Change EPS"
echo ""

echo "Flush the primary key"
${PREFIX}flushcontext -ha 80000000 > run.out
checkSuccess $?

echo "Change EPS, no password"
${PREFIX}changeeps > run.out
checkSuccess $?

echo "Create a primary key - endorsement hierarchy"
${PREFIX}createprimary -hi e -pwdk 111 > run.out
checkSuccess $?

echo "Create a storage key under the primary key"
${PREFIX}create -hp 80000000 -st -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp 111 -pwdk 222 > run.out
checkSuccess $?

echo "Load the storage key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp 111 > run.out
checkSuccess $?

echo "Change EPS, no password"
${PREFIX}changeeps > run.out
checkSuccess $?

echo "Load the storage key under the flushed primary key, should fail"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp 111 > run.out
checkFailure $?

echo "Create a different primary key - new EPS"
${PREFIX}createprimary -hi e -pwdk 111 > run.out
checkSuccess $?

echo "Load the storage key under the new primary key, should fail"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp 111 > run.out
checkFailure $?

echo "Create a storage key under the new primary key"
${PREFIX}create -hp 80000000 -st -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp 111 -pwdk 222 > run.out
checkSuccess $?

echo "Load the storage key under the new primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp 111 > run.out
checkSuccess $?

echo "Flush the storage key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

# getcapability  -cap 1 -pr 80000000
# getcapability  -cap 1 -pr 02000000

