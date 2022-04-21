#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#		$Id: testhierarchy.sh 990 2017-04-19 13:31:24Z kgoldman $	#
#										#
# (c) Copyright IBM Corporation 2015, 2016					#
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
echo "Hierarchy Change Auth"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

echo "Generate a random authorization value"
${PREFIX}getrandom -by 32 -nz -of tmp.bin > run.out
checkSuccess $?

AUTH=("" "-pwda ppp " "" "-pwdai tmp.bin ")
NEWAUTH=("-pwdn ppp " "" "-pwdni tmp.bin " "")
CPAUTH=("-pwdp ppp " "" "-pwdpi tmp.bin " "")

for ((i = 0 ; i < 4 ; i+=2))
do 
    for SESS in "" "-se0 02000000 1"
    do

	echo "Change platform hierarchy auth ${AUTH[i]} ${NEWAUTH[i]} ${SESS}"
	${PREFIX}hierarchychangeauth -hi p ${AUTH[i]} ${NEWAUTH[i]} ${SESS} > run.out
	checkSuccess $?

	echo "Create a primary storage key - should fail"
	${PREFIX}createprimary -hi p -pwdk 111 > run.out
	checkFailure $?

	echo "Create a primary storage key ${CPAUTH[i]}"
	${PREFIX}createprimary -hi p -pwdk 111 ${CPAUTH[i]} > run.out
	checkSuccess $?

	echo "Flush the primary key"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

	echo "Change platform hierarchy auth back to null ${AUTH[i+1]} ${NEWAUTH[i+1]} ${SESS}"
	${PREFIX}hierarchychangeauth -hi p ${AUTH[i+1]} ${NEWAUTH[i+1]} ${SESS} > run.out
	checkSuccess $?

	echo "Create a primary storage key"
	${PREFIX}createprimary -pwdk 111 > run.out
	checkSuccess $?

	echo "Flush the primary key"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

    done
done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Hierarchy Change Auth with bind"
echo ""

echo "Change platform hierarchy auth"
${PREFIX}hierarchychangeauth -hi p -pwdn ppp > run.out
checkSuccess $?

echo "Create a primary storage key - should fail"
${PREFIX}createprimary -hi p -pwdk 111 > run.out
checkFailure $?

echo "Create a primary storage key"
${PREFIX}createprimary -hi p -pwdk 111 -pwdp ppp > run.out
checkSuccess $?

echo "Flush the primary key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Start an HMAC auth session, bind to platform hierarchy"
${PREFIX}startauthsession -se h -bi 4000000c -pwdb ppp > run.out
checkSuccess $?

echo "Change platform hierarchy auth back to null"
${PREFIX}hierarchychangeauth -hi p -pwda ppp -se0 02000000 1 > run.out
checkSuccess $?

echo "Create a primary storage key"
${PREFIX}createprimary -pwdk 111 > run.out
checkSuccess $?

echo "Flush the primary key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Hierarchy Control"
echo ""

echo "Enable the owner hierarchy"
${PREFIX}hierarchycontrol -hi p -he o > run.out
checkSuccess $?

echo "Change the platform hierarchy password"
${PREFIX}hierarchychangeauth -hi p -pwdn ppp > run.out
checkSuccess $?

echo "Enable the owner hierarchy - no platform hierarchy password, should fail"
${PREFIX}hierarchycontrol -hi p -he o > run.out
checkFailure $?

echo "Enable the owner hierarchy using platform hierarchy password"
${PREFIX}hierarchycontrol -hi p -he o -pwda ppp > run.out
checkSuccess $?

echo "Create a primary key in the owner hierarchy - bad password, should fail"
${PREFIX}createprimary -hi o -pwdp xxx > run.out
checkFailure $?

echo "Create a primary key in the owner hierarchy"
${PREFIX}createprimary -hi o > run.out
checkSuccess $?

echo "Disable the owner hierarchy using platform hierarchy password"
${PREFIX}hierarchycontrol -hi p -he o -pwda ppp -state 0 > run.out
checkSuccess $?

echo "Create a primary key in the owner hierarchy, disabled, should fail"
${PREFIX}createprimary -hi o > run.out
checkFailure $?

echo "Enable the owner hierarchy using platform hierarchy password"
${PREFIX}hierarchycontrol -hi p -he o -pwda ppp -state 1 > run.out
checkSuccess $?

echo "Create a primary key in the owner hierarchy"
${PREFIX}createprimary -hi o > run.out
checkSuccess $?

echo "Remove the platform hierarchy password"
${PREFIX}hierarchychangeauth -hi p -pwda ppp > run.out
checkSuccess $?

echo "Flush the primary key in the owner hierarchy"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Clear"
echo ""

echo "Set storage hierarchy auth"
${PREFIX}hierarchychangeauth -hi o -pwdn ooo > run.out
checkSuccess $?

echo "Create a primary key - storage hierarchy"
${PREFIX}createprimary -hi o -pwdp ooo > run.out
checkSuccess $?

echo "Read the public part"
${PREFIX}readpublic -ho 80000001 > run.out
checkSuccess $?

echo "ClearControl disable"
${PREFIX}clearcontrol -hi p -state 1 > run.out
checkSuccess $?

echo "Clear - should fail"
${PREFIX}clear -hi p > run.out
checkFailure $?

echo "ClearControl enable"
${PREFIX}clearcontrol -hi p -state 0 > run.out
checkSuccess $?

echo "Clear"
${PREFIX}clear -hi p > run.out
checkSuccess $?

echo "Read the public part - should fail"
${PREFIX}readpublic -ho 80000001 > run.out
checkFailure $?

echo "Create a primary key - old owner password should fail"
${PREFIX}createprimary -hi o -pwdp ooo > run.out
checkFailure $?

echo "Create a primary key"
${PREFIX}createprimary -hi o > run.out
checkSuccess $?

echo "Flush the primary key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

# getcapability  -cap 1 -pr 80000000
# getcapability  -cap 1 -pr 02000000

# cleanup
rm -f tmp.bin
