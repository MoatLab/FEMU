#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2015 - 2019					#
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
echo "CreateLoaded"
echo ""

echo ""
echo "CreateLoaded Primary Key, Hierarchy Parent"
echo ""

for HIER in "40000001" "4000000c" "4000000b"
do

    echo "CreateLoaded primary key, parent ${HIER}"
    ${PREFIX}createloaded -hp ${HIER} -st -kt f -kt p -pwdk ppp > run.out
    checkSuccess $?

    echo "Create a storage key under the primary key"
    ${PREFIX}create -hp 80000001 -st -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp ppp > run.out
    checkSuccess $?

    echo "Load the storage key under the primary key"
    ${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
    checkSuccess $?

    echo "Flush the storage key"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

    echo "Flush the primary storage key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Load the storage key under the primary key - should fail"
    ${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
    checkFailure $?

    echo "CreateLoaded recreate owner primary key"
    ${PREFIX}createloaded -hp ${HIER} -st -kt f -kt p -pwdk ppp > run.out
    checkSuccess $?

    echo "Load the storage key under the primary key"
    ${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
    checkSuccess $?

    echo "Flush the storage key"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

    echo "Flush the primary storage key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "CreateLoaded Child Key, Primary Parent"
echo ""

echo "CreateLoaded child storage key at 80000001, parent 80000000"
${PREFIX}createloaded -hp 80000000 -st -kt f -kt p -pwdp sto -pwdk ppp -opu tmpppub.bin -opr tmpppriv.bin > run.out
checkSuccess $?

echo "Create a signing key under the child storage key 80000001"
${PREFIX}create -hp 80000001 -si -opr tmppriv.bin -opu tmppub.bin -pwdp ppp > run.out
checkSuccess $?

echo "Load the signing key at 80000002 under the child storage key 80000001"
${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
checkSuccess $?

echo "Flush the child storage key 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flush the child signing key 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Reload the createloaded child storage key at 80000001, parent 80000000"
${PREFIX}load -hp 80000000 -ipr tmpppriv.bin -ipu tmpppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Reload the child signing key at 80000002 under the child storage key 80000001"
${PREFIX}load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
checkSuccess $?

echo "Flush the child storage key 80000002 "
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flush the child signing key 80000001 "
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "CreateLoaded Primary Derived Key, Hierarchy Parent"
echo ""

for HIER in "e" "o" "p"
do

    echo "Create a primary ${HIER} derivation parent 80000001"
    ${PREFIX}createprimary -hi ${HIER} -dp > run.out
    checkSuccess $?

    echo "Create a derived key 80000002"
    ${PREFIX}createloaded -hp 80000001 -der -ecc bnp256 -den -kt f -kt p -opu tmppub.bin > run.out
    checkSuccess $?

    echo "Flush the derived key 80000002"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

    echo "Create a derived key 80000002"
    ${PREFIX}createloaded -hp 80000001 -der -ecc bnp256 -den -kt f -kt p -opu tmppub1.bin > run.out
    checkSuccess $?

    echo "Flush the derived key 80000002"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

    echo "Verify that the two derived keys are the same"
    diff tmppub.bin tmppub1.bin > run.out
    checkSuccess $?

    echo "Flush the derivation parent"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo ""
echo "CreateLoaded Child Derived Key, Primary Parent"
echo ""

echo "Create a derivation parent under the primary key"
${PREFIX}create -hp 80000000 -dp -opr tmpdppriv.bin -opu tmpdppub.bin -pwdp sto -pwdk dp > run.out
checkSuccess $?

echo "Load the derivation parent to 80000001"
${PREFIX}load -hp 80000000 -ipr tmpdppriv.bin -ipu tmpdppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Create an EC signing key 80000002 under the derivation parent key"
${PREFIX}createloaded -hp 80000001 -der -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -opem tmppub.pem -pwdp dp -ecc nistp256 > run.out
checkSuccess $?

echo "Sign a digest"
${PREFIX}sign -hk 80000002 -halg sha256 -salg ecc -if policies/aaa -os sig.bin > run.out
checkSuccess $?

echo "Verify the ECC signature using the TPM"
${PREFIX}verifysignature -hk 80000002 -halg sha256 -ecc -if policies/aaa -is sig.bin > run.out
checkSuccess $?

echo "Verify the signature using PEM"
${PREFIX}verifysignature -ipem tmppub.pem -halg sha256 -if policies/aaa -is sig.bin > run.out
checkSuccess $?

echo "Flush the signing key 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Create another EC signing key 80000002 under the derivation parent key"
${PREFIX}createloaded -hp 80000001 -der -si -kt f -kt p -opr tmppriv1.bin -opu tmppub1.bin -opem tmppub1.pem -pwdp dp -ecc nistp256 > run.out
checkSuccess $?

echo "Verify that the two derived keys are the same"
diff tmppub.bin tmppub1.bin > run.out
checkSuccess $?

echo "Flush the signing key 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flush the derivation parent"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

rm -f tmpppriv.bin
rm -f tmpppub.bin
rm -f tmpppub1.bin
rm -f tmpppub.pem
rm -f tmppub.pem
rm -f tmppub1.pem
rm -f tmppriv.bin
rm -f tmppriv1.bin
rm -f tmppub1.bin
rm -f tmpdppriv.bin
rm -f tmpdppub.bin
