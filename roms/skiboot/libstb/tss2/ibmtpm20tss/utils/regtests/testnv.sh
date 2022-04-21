#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#		$Id: testnv.sh 1301 2018-08-15 21:46:19Z kgoldman $		#
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
echo "NV"
echo ""

echo ""
echo "NV Ordinary Index"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

NALG=(${ITERATE_ALGS})
BADNALG=(${BAD_ITERATE_ALGS})

for ((i = 0 ; i < 4; i++))
do

    for SESS in "" "-se0 02000000 1"
    do

	echo "NV Define Space ${NALG[$i]}"
	${PREFIX}nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 -nalg ${NALG[$i]} > run.out
	checkSuccess $?

	echo "NV Read Public, unwritten Name  bad Name algorithm ${BADNALG[$i]} - should fail"
	${PREFIX}nvreadpublic -ha 01000000 -nalg ${BADNALG[$i]} > run.out
	checkFailure $?

	echo "NV read - should fail before write ${SESS}"
	${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 16 ${SESS} > run.out
	checkFailure $?

	echo "NV write ${SESS}"
	${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa ${SESS} > run.out
	checkSuccess $?

	echo "NV read ${SESS}"
	${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 3 -of tmp.bin ${SESS} > run.out
	checkSuccess $?

	echo "Verify the read data"
	diff policies/aaa tmp.bin > run.out
	checkSuccess $?

	echo "NV read, invalid offset - should fail ${SESS}"
	${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 16 -off 1 -of tmp.bin ${SESS} > run.out
	checkFailure $?

	echo "NV read, invalid size - should fail ${SESS}"
	${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 17 -of tmp.bin ${SESS} > run.out
	checkFailure $?

	echo "NV Undefine Space"
	${PREFIX}nvundefinespace -hi o -ha 01000000 > run.out
	checkSuccess $?

    done
done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo "NV Undefine Space again should fail"
${PREFIX}nvundefinespace -hi o -ha 01000000 > run.out
checkFailure $?

echo "NV Define Space out of range - should fail"
${PREFIX}nvdefinespace -hi o -ha 02000000 -pwdn nnn  -sz 16 > run.out
checkFailure $?

echo ""
echo "NV Set Bits Index"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    echo "NV Define Space"
    ${PREFIX}nvdefinespace -hi o -ha 01000000 -pwdn nnn -ty b > run.out
    checkSuccess $?

    echo "NV read - should fail before write ${SESS}"
    ${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 16  ${SESS} > run.out
    checkFailure $?

    echo "Set bits 0, 16, 32, 48 ${SESS}" 
    ${PREFIX}nvsetbits -ha 01000000 -pwdn nnn -bit 0 -bit 16 -bit 32 -bit 48 ${SESS} > run.out
    checkSuccess $?

    echo "Read the set bits ${SESS}" 
    ${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 8 -of tmp.bin ${SESS} > run.out
    checkSuccess $?

    echo "Verify the read data"
    diff policies/bits48321601.bin tmp.bin > run.out
    checkSuccess $?

    echo "NV Undefine Space"
    ${PREFIX}nvundefinespace -hi o -ha 01000000 > run.out
    checkSuccess $?

done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "NV Counter Index"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    echo "NV Define Space"
    ${PREFIX}nvdefinespace -hi o -ha 01000000 -pwdn nnn -ty c > run.out
    checkSuccess $?

    echo "NV Read Public, unwritten Name"
    ${PREFIX}nvreadpublic -ha 01000000 > run.out
    checkSuccess $?

    echo "Read the count - should fail before write ${SESS}" 
    ${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 8 -of tmp.bin  ${SESS} > run.out
    checkFailure $?

    echo "Increment the count ${SESS}" 
    ${PREFIX}nvincrement -ha 01000000 -pwdn nnn  ${SESS} > run.out
    checkSuccess $?

    echo "Read the count ${SESS}" 
    ${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 8 -of tmp.bin  ${SESS} > run.out
    checkSuccess $?

# FIXME need some way to verify the count

    echo "NV Undefine Space"
    ${PREFIX}nvundefinespace -hi o -ha 01000000 > run.out
    checkSuccess $?

done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

# The test data was created using policymaker with a text file 616161
# (three a's).  pcrexted cannot be used because it zero extends the
# input to the hash size

echo ""
echo "NV Extend Index"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    SZ=(20 32 48 64)
    HALG=(${ITERATE_ALGS})

    for ((i = 0 ; i < 4; i++))
    do

	echo "NV Define Space ${HALG[$i]}"
	${PREFIX}nvdefinespace -hi o -ha 01000000 -pwdn nnn -ty e -nalg ${HALG[$i]} > run.out
	checkSuccess $?

	echo "NV Read Public ${HALG[$i]}"
	${PREFIX}nvreadpublic -ha 01000000 -nalg ${HALG[$i]} > run.out
	checkSuccess $?

	echo "NV read, unwritten Name - should fail before write ${SESS}"
	${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 32 -of tmp.bin ${SESS} > run.out
	checkFailure $?

	echo "NV extend ${SESS}"
	${PREFIX}nvextend -ha 01000000 -pwdn nnn -if policies/aaa ${SESS} > run.out
	checkSuccess $?

	echo "NV read size ${SZ[$i]} ${SESS}"
	${PREFIX}nvread -ha 01000000 -pwdn nnn -sz ${SZ[$i]} -of tmp.bin ${SESS} > run.out
	checkSuccess $?

	echo "Verify the read data ${HALG[$i]}"
	diff policies/${HALG[$i]}extaaa.bin tmp.bin > run.out
	checkSuccess $?

	echo "NV Undefine Space"
	${PREFIX}nvundefinespace -hi o -ha 01000000 > run.out
	checkSuccess $?

    done
done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

# getcapability  -cap 1 -pr 80000000
# getcapability  -cap 1 -pr 02000000
# getcapability  -cap 1 -pr 01000000

echo ""
echo "NV Owner auth"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    echo "Set owner auth ${SESS}"
    ${PREFIX}hierarchychangeauth -hi o -pwdn ooo ${SESS} > run.out
    checkSuccess $?

    echo "Define an NV index with owner auth ${SESS}"
    ${PREFIX}nvdefinespace -hi o -hia o -ha 01000000 -pwdp ooo ${SESS} > run.out
    checkSuccess $?

    echo "NV Read public, get Name, not written"
    ${PREFIX}nvreadpublic -ha 01000000 > run.out
    checkSuccess $?

    echo "NV write with NV password ${SESS} - should fail"
    ${PREFIX}nvwrite -ha 01000000 -pwdn nnn ${SESS}> run.out
    checkFailure $?

    echo "NV write with owner password ${SESS}"
    ${PREFIX}nvwrite -ha 01000000 -hia o -pwdn ooo  ${SESS}> run.out 
    checkSuccess $?

    echo "NV read with NV password ${SESS} - should fail"
    ${PREFIX}nvread -ha 01000000 ${SESS} -pwdn nnn > run.out
    checkFailure $?

    echo "NV read with owner password ${SESS}"
    ${PREFIX}nvread -ha 01000000 -hia o -pwdn ooo ${SESS} > run.out 
    checkSuccess $?

    echo "NV Undefine authorizing index ${SESS}"
    ${PREFIX}nvundefinespace -hi o -ha 01000000 -pwdp ooo ${SESS} > run.out
    checkSuccess $?

    echo "Clear owner auth ${SESS}"
    ${PREFIX}hierarchychangeauth -hi o -pwda ooo ${SESS} > run.out
    checkSuccess $?

done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

# getcapability  -cap 1 -pr 80000000
# getcapability  -cap 1 -pr 02000000
# getcapability  -cap 1 -pr 01000000

echo ""
echo "NV Platform auth"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    echo "Set platform auth ${SESS}"
    ${PREFIX}hierarchychangeauth -hi p -pwdn ppp  ${SESS}> run.out
    checkSuccess $?

    echo "Define an NV index with platform auth ${SESS}"
    ${PREFIX}nvdefinespace -hi p -hia p -ha 01000000 -pwdp ppp ${SESS} > run.out
    checkSuccess $?

    echo "NV Read public, get Name, not written"
    ${PREFIX}nvreadpublic -ha 01000000 > run.out
    checkSuccess $?

    echo "NV write with NV password ${SESS} - should fail"
    ${PREFIX}nvwrite -ha 01000000 -pwdn nnn ${SESS} > run.out
    checkFailure $?

    echo "NV write with platform password ${SESS}"
    ${PREFIX}nvwrite -ha 01000000 -hia p -pwdn ppp ${SESS} > run.out 
    checkSuccess $?

    echo "NV read with NV password ${SESS} - should fail"
    ${PREFIX}nvread -ha 01000000 -pwdn nnn ${SESS} > run.out
    checkFailure $?

    echo "NV write with platform password ${SESS}"
    ${PREFIX}nvread -ha 01000000 -hia p -pwdn ppp ${SESS} > run.out 
    checkSuccess $?

    echo "NV Undefine authorizing index ${SESS}"
    ${PREFIX}nvundefinespace -hi p -ha 01000000 -pwdp ppp ${SESS} > run.out
    checkSuccess $?

    echo "Clear platform auth ${SESS}"
    ${PREFIX}hierarchychangeauth -hi p -pwda ppp ${SESS} > run.out
    checkSuccess $?

done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Write Lock"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    echo "NV Define Space with write define"
    ${PREFIX}nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 +at wd > run.out
    checkSuccess $?

    echo "NV Read Public, unwritten Name"
    ${PREFIX}nvreadpublic -ha 01000000 > run.out
    checkSuccess $?

    echo "NV write ${SESS}"
    ${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa ${SESS} > run.out
    checkSuccess $?

    echo "NV read ${SESS}"
    ${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 16 ${SESS} > run.out
    checkSuccess $?

    echo "Write lock ${SESS}"
    ${PREFIX}nvwritelock -ha 01000000 -pwdn nnn ${SESS} > run.out  
    checkSuccess $?

    echo "NV write ${SESS} - should fail"
    ${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa ${SESS} > run.out
    checkFailure $?

    echo "NV read ${SESS}"
    ${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 16 ${SESS} > run.out
    checkSuccess $?

    echo "NV Undefine Space"
    ${PREFIX}nvundefinespace -hi p -ha 01000000 > run.out
    checkSuccess $?

done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Read Lock"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    echo "NV Define Space with read stclear"
    ${PREFIX}nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 +at rst > run.out
    checkSuccess $?

    echo "NV Read Public, unwritten Name"
    ${PREFIX}nvreadpublic -ha 01000000 > run.out
    checkSuccess $?

    echo "NV write ${SESS}"
    ${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa ${SESS} > run.out
    checkSuccess $?

    echo "NV read ${SESS}"
    ${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 16 ${SESS} > run.out
    checkSuccess $?

     echo "Read lock ${SESS}"
    ${PREFIX}nvreadlock -ha 01000000 -pwdn nnn ${SESS} > run.out 
    checkSuccess $?

    echo "NV write ${SESS}"
    ${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa ${SESS} > run.out
    checkSuccess $?

    echo "NV read ${SESS} - should fail"
    ${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 16 ${SESS} > run.out
    checkFailure $?

    echo "NV Undefine Space"
    ${PREFIX}nvundefinespace -hi p -ha 01000000 > run.out
    checkSuccess $?

done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Global Lock"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    echo "NV Define Space 01000000 with global lock"
    ${PREFIX}nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 +at gl > run.out
    checkSuccess $?

    echo "NV Define Space 01000001 with global lock"
    ${PREFIX}nvdefinespace -hi o -ha 01000001 -pwdn nnn -sz 16 +at gl > run.out
    checkSuccess $?

    echo "NV write 01000000 ${SESS}"
    ${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa ${SESS} > run.out
    checkSuccess $?

    echo "NV write 01000001 ${SESS}"
    ${PREFIX}nvwrite -ha 01000001 -pwdn nnn -if policies/aaa ${SESS} > run.out
    checkSuccess $?

    echo "NV global lock"
    ${PREFIX}nvglobalwritelock -hia p > run.out
    checkSuccess $?

    echo "NV Read Public, 01000000, locked"
    ${PREFIX}nvreadpublic -ha 01000000 > run.out
    checkSuccess $?

    echo "NV Read Public, 01000001, locked"
    ${PREFIX}nvreadpublic -ha 01000001 > run.out
    checkSuccess $?

    echo "NV write 01000000 ${SESS} - should fail"
    ${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa ${SESS} > run.out
    checkFailure $?

    echo "NV write 01000001 ${SESS} - should fail"
    ${PREFIX}nvwrite -ha 01000001 -pwdn nnn -if policies/aaa ${SESS} > run.out
    checkFailure $?

    echo "NV read 01000000 ${SESS}"
    ${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 16 ${SESS} > run.out
    checkSuccess $?

    echo "NV read 01000001 ${SESS}"
    ${PREFIX}nvread -ha 01000001 -pwdn nnn -sz 16 ${SESS} > run.out
    checkSuccess $?

    echo "NV Undefine Space 01000000"
    ${PREFIX}nvundefinespace -hi p -ha 01000000 > run.out
    checkSuccess $?

    echo "NV Undefine Space 01000001"
    ${PREFIX}nvundefinespace -hi p -ha 01000001 > run.out
    checkSuccess $?

done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

# policy is policycommandcode + policyauthvalue
# aa 83 a5 98 d9 3a 56 c9 ca 6f ea 7c 3f fc 4e 10 
# 63 57 ff 6d 93 e1 1a 9b 4a c2 b6 aa e1 2b a0 de 

echo "NV Define Space with POLICY_DELETE and no policy - should fail"
${PREFIX}nvdefinespace -hi o -ha 01000000 +at pold > run.out
checkFailure $?

echo ""
echo "NV Change Authorization"
echo ""

echo "Start an HMAC session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    echo "NV Define Space 0100000"
    ${PREFIX}nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 -pol policies/policyccnvchangeauth-auth.bin > run.out
    checkSuccess $?

    echo "NV Read Public, unwritten Name"
    ${PREFIX}nvreadpublic -ha 01000000 > run.out
    checkSuccess $?

    echo "NV write ${SESS}"
    ${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa ${SESS} > run.out
    checkSuccess $?

    echo "NV read ${SESS}"
    ${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 16 ${SESS} > run.out
    checkSuccess $?

    echo "Start a policy session"
    ${PREFIX}startauthsession -se p > run.out
    checkSuccess $?

    echo "Policy command code"    
    ${PREFIX}policycommandcode -ha 03000001 -cc 0000013b > run.out
    checkSuccess $?

    echo "Policy authvalue"    
    ${PREFIX}policyauthvalue -ha 03000001 > run.out
    checkSuccess $?

    echo "NV Change authorization"
    ${PREFIX}nvchangeauth -ha 01000000 -pwdo nnn -pwdn xxx -se0 03000001 1 > run.out 
    checkSuccess $?

    echo "NV write ${SESS}, old auth - should fail"
    ${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa ${SESS} > run.out
    checkFailure $?

    echo "NV read ${SESS}, old auth - should fail"
    ${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 3 ${SESS} > run.out
    checkFailure $?

    echo "NV write ${SESS}"
    ${PREFIX}nvwrite -ha 01000000 -pwdn xxx -if policies/aaa ${SESS} > run.out
    checkSuccess $?

    echo "NV read ${SESS}"
    ${PREFIX}nvread -ha 01000000 -pwdn xxx -sz 3 ${SESS} > run.out
    checkSuccess $?

    echo "NV Undefine Space"
    ${PREFIX}nvundefinespace -hi p -ha 01000000 > run.out
    checkSuccess $?

    echo "Flush the auth session"
    ${PREFIX}flushcontext -ha 03000001 > run.out
    checkSuccess $?

done

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "NV Change Authorization with bind"
echo ""

echo "NV Define Space 0100000"
${PREFIX}nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 -pol policies/policyccnvchangeauth-auth.bin > run.out
checkSuccess $?

echo "Start an HMAC session, bind to NV index"
${PREFIX}startauthsession -se h -bi 01000000 -pwdb nnn > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy command code"    
${PREFIX}policycommandcode -ha 03000001 -cc 0000013b > run.out
checkSuccess $?

echo "Policy authvalue"    
${PREFIX}policyauthvalue -ha 03000001 > run.out
checkSuccess $?

echo "NV Change authorization"
${PREFIX}nvchangeauth -ha 01000000 -pwdo nnn -pwdn xxx -se0 03000001 1 > run.out 
checkSuccess $?

echo "NV Undefine Space"
${PREFIX}nvundefinespace -hi p -ha 01000000 > run.out
checkSuccess $?

echo "Flush the auth session"
${PREFIX}flushcontext -ha 03000001 > run.out
checkSuccess $?

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "NV Undefine space special"
echo ""

# policy is policy command code + policy password

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

for POL in "policyauthvalue" "policypassword"
do

    echo "NV Define Space 0100000"
    ${PREFIX}nvdefinespace -hi p -ha 01000000 -pwdn nnn -sz 16 +at pold -pol policies/policyccundefinespacespecial-auth.bin > run.out
    checkSuccess $?

    echo "Undefine space special - should fail"
    ${PREFIX}nvundefinespacespecial -ha 01000000 -pwdn nnn > run.out
    checkFailure $?

    echo "Undefine space special - should fail"
    ${PREFIX}nvundefinespacespecial -ha 01000000 -se0 03000000 1 -pwdn nnn > run.out
    checkFailure $?

    echo "Policy command code, NV undefine space special"
    ${PREFIX}policycommandcode -ha 03000000 -cc 11f > run.out
    checkSuccess $?

    echo "Undefine space special - should fail"
    ${PREFIX}nvundefinespacespecial -ha 01000000 -se0 03000000 1 -pwdn nnn > run.out
    checkFailure $?

    echo "Policy ${POL}"
    ${PREFIX}${POL} -ha 03000000 > run.out
    checkSuccess $?

    echo "Undefine space special"
    ${PREFIX}nvundefinespacespecial -ha 01000000 -se0 03000000 1 -pwdn nnn > run.out
    checkSuccess $?

done

echo "Flush the session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

# ${PREFIX}getcapability  -cap 1 -pr 80000000
# ${PREFIX}getcapability  -cap 1 -pr 02000000
# ${PREFIX}getcapability  -cap 1 -pr 01000000
