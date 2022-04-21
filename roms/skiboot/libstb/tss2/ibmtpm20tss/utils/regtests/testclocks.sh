#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	$Id: testclocks.sh 1115 2017-12-13 23:35:20Z kgoldman $			#
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
echo "Clocks"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    echo "Read Clock"
    ${PREFIX}readclock -oclock tmpclk.bin > run.out
    checkSuccess $?

    echo "Clock set, current time ${SESS} - should fail"
    ${PREFIX}clockset -iclock tmpclk.bin ${SESS} > run.out
    checkFailure $?

    echo "Clock set, time plus 20 sec ${SESS}"
    ${PREFIX}clockset -iclock tmpclk.bin -addsec 20 ${SESS} > run.out
    checkSuccess $?

    for ADJ in -3 0 3
    do

	echo "Clock rate adjust ${ADJ} ${SESS}"
	${PREFIX}clockrateadjust -adj ${ADJ} ${SESS} > run.out
	checkSuccess $?

    done

    for ADJ in -4 4
    do

	echo "Clock rate adjust ${ADJ} ${SESS} - should fail"
	${PREFIX}clockrateadjust -adj ${ADJ} ${SESS} > run.out
	checkFailure $?

    done

done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

rm -f tmpclk.bin
