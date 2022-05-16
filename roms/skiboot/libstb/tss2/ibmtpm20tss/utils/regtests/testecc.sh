#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#	$Id: testecc.sh 1277 2018-07-23 20:30:23Z kgoldman $			#
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
echo "ECC Ephemeral"
echo ""

echo ""
echo "ECC Parameters and Ephemeral"
echo ""

for CURVE in "bnp256" "nistp256" "nistp384"
do

    echo "ECC Parameters for curve ${CURVE}"
    ${PREFIX}eccparameters -cv ${CURVE} > run.out
    checkSuccess $?

    for ATTR in "-si" "-sir"
    do

	echo "Create ${ATTR} for curve ${CURVE}"
	${PREFIX}create -hp 80000000 -pwdp sto ${ATTR} -ecc ${CURVE} > run.out
	checkSuccess $?

    done

    echo "EC Ephemeral for curve ${CURVE}"
    ${PREFIX}ecephemeral -ecc ${CURVE} > run.out
    checkSuccess $?

done

echo ""
echo "ECC Commit"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for KEYTYPE in "-dau" "-dar"
do 

    for SESS in "" "-se0 02000000 1"
    do

	echo "Create a $KEYTYPE ECDAA signing key under the primary key"
	${PREFIX}create -hp 80000000 -ecc bnp256 $KEYTYPE -nalg sha256 -halg sha256 -kt f -kt p -opr tmprpriv.bin -opu tmprpub.bin -pwdp sto -pwdk siga > run.out
	checkSuccess $?

	echo "Load the signing key 80000001 under the primary key 80000000"
	${PREFIX}load -hp 80000000 -ipr tmprpriv.bin -ipu tmprpub.bin -pwdp sto > run.out
	checkSuccess $?

    	#${PREFIX}getcapability -cap 1 -pr 80000001
    	
    	# The trick with commit is first use - empty ECC point and no s2 and y2 parameters
    	# which means no P1, no s2 and no y2. 
    	# and output the result and get the efile.bin
    	# feed back the point in efile.bin as the new p1 because it is on the curve.
	
    	# There is no test case for s2 and y2. To construct a y2 requires using Cipolla's algorithm.
    	# example of normal command    
    	# ${PREFIX}commit -hk 80000001 -pt p1.bin -s2 s2.bin -y2 y2_a.bin -Kf kfile.bin -Lf lfile.bin -Ef efile.bin -cf counterfile.bin -pwdk siga > run.out
    	# checkSuccess $?
	
	echo "Create new point E, based on point-multiply of TPM's commit random scalar and Generator point ${SESS}"
	${PREFIX}commit -hk 80000001 -Ef efile.bin -pwdk siga ${SESS} > run.out
	checkSuccess $?

        # copy efile as new p1 - for hash operation
        cp efile.bin p1.bin

        # We have a point on the curve - in efile.bin.  Use E as P1 and feed it back in
		
	# All this does is simulate the commit that the FIDO alliance wants to
	# use in its TPM Join operation.
		
	echo "Create new point E, based on point-multiply of TPM's commit random scalar and input point ${SESS}"
	${PREFIX}commit -hk 80000001 -pt p1.bin -Ef efile.bin -cf counterfile.bin -pwdk siga ${SESS} > run.out
	checkSuccess $?

        cat efile.bin p1.bin tmprpub.bin > hashinput.bin

        echo "Hash the E, P1, and Q to create the ticket to use in signing"
        ${PREFIX}hash -hi p -halg sha256 -if hashinput.bin -oh outhash.bin -tk tfile.bin > run.out
        checkSuccess $?
        
        echo "Sign the hash of the points made from commit"
        ${PREFIX}sign -hk 80000001 -pwdk siga -salg ecc -scheme ecdaa -cf counterfile.bin -if hashinput.bin -os sig.bin -tk tfile.bin > run.out
        checkSuccess $?
        
	echo "Flush the signing key"
	${PREFIX}flushcontext -ha 80000001 > run.out
	checkSuccess $?

    done
done

# save old counterfile for off nominal error check
cp counterfile.bin counterfileold.bin

for KEYTYPE in "-dau" "-dar"
do 

    for SESS in "" "-se0 02000000 1"
    do

        echo "Create a $KEYTYPE ECDAA signing primary key"
        ${PREFIX}createprimary -ecc bnp256 $KEYTYPE -nalg sha256 -halg sha256 -kt f -kt p -opu tmprpub.bin -pwdk siga > run.out
        checkSuccess $?
        
        #${PREFIX}getcapability -cap 1 -pr 80000001
        
        # The trick with commit is first use - empty ECC point and no s2 and y2 parameters
        # which means no P1, no s2 and no y2. 
        # and output the result and get the efile.bin
        # feed back the point in efile.bin as the new p1 because it is on the curve.
        
        # There is no test case for s2 and y2. To construct a y2 requires using Cipolla's algorithm.
        # example of normal command    
        # ${PREFIX}commit -hk 80000001 -pt p1.bin -s2 s2.bin -y2 y2_a.bin -Kf kfile.bin -Lf lfile.bin -Ef efile.bin -cf counterfile.bin -pwdk siga > run.out
        # checkSuccess $?
        
        echo "Create new point E, based on point-multiply of TPM's commit random scalar and Generator point ${SESS}"
        ${PREFIX}commit -hk 80000001 -Ef efile.bin -pwdk siga ${SESS} > run.out
        checkSuccess $?
        
        # copy efile as new p1 - for hash operation
        cp efile.bin p1.bin
       
        # We have a point on the curve - in efile.bin.  Use E as P1 and feed it back in
        
        # All this does is simulate the commit that the FIDO alliance wants to
        # use in its TPM Join operation.
        
        echo "Create new point E, based on point-multiply of TPM's commit random scalar and input point ${SESS}"
        ${PREFIX}commit -hk 80000001 -pt p1.bin -Ef efile.bin -cf counterfile.bin -pwdk siga ${SESS} > run.out
        checkSuccess $?
        
        cat efile.bin p1.bin tmprpub.bin > hashinput.bin

        echo "Hash the E, P1, and Q to create the ticket to use in signing"
        ${PREFIX}hash -hi p -halg sha256 -if hashinput.bin -oh outhash.bin -tk tfile.bin > run.out
        checkSuccess $?

        echo "Check error case bad counter"
        ${PREFIX}sign -hk 80000001 -pwdk siga -ecdaa -cf counterfileold.bin -if hashinput.bin -os sig.bin -tk tfile.bin  > run.out
        checkFailure $?

        echo "Sign the hash of the points made from commit"
        ${PREFIX}sign -hk 80000001 -pwdk siga -salg ecc -scheme ecdaa -cf counterfile.bin -if hashinput.bin -os sig.bin -tk tfile.bin  > run.out
        checkSuccess $?

        echo "Flush the signing key"
        ${PREFIX}flushcontext -ha 80000001 > run.out
        checkSuccess $?

    done
done

echo "Flush the session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "ECC zgen2phase"
echo ""

echo "ECC Parameters for curve nistp256"
${PREFIX}eccparameters -cv nistp256 > run.out
checkSuccess $?

# This is just a script for a B "remote" side to create a static key
# pair and ephemeral for use in demonstrating (on the local side) a
# two-phase operation involving ecephemeral and zgen2phase

echo "Create decryption key for curve nistp256"
${PREFIX}create -hp 80000000 -pwdp sto -den -ecc nistp256 -opu QsBpub.bin > run.out
checkSuccess $?

echo "EC Ephemeral for curve nistp256"
${PREFIX}ecephemeral -ecc nistp256 -oq QeBpt.bin > run.out
checkSuccess $?

# local side

# scp or cp the QsBpub.bin and QeBpt.bin from the B side over to the
# A side. This assumes QsBpub is a TPM2B_PUBLIC from a create command
# on B side.  QeBpt is already in TPM2B_ECC_POINT form since it was
# created by ecephemeral on B side QsBpub.bin is presumed in a form
# produced by a create commamnd using another TPM

echo "Create decryption key for curve nistp256"
${PREFIX}create -hp 80000000 -pwdp sto -den -ecc nistp256 -opr QsApriv.bin -opu QsApub.bin > run.out
checkSuccess $?

echo "Load the decryption key under the primary key, 80000001"
${PREFIX}load -hp 80000000 -ipr QsApriv.bin -ipu QsApub.bin -pwdp sto > run.out
checkSuccess $?

echo "EC Ephemeral for curve nistp256"
${PREFIX}ecephemeral -ecc nistp256 -oq QeApt.bin -cf counter.bin  > run.out
checkSuccess $?

echo "Convert public raw to TPM2B_ECC_POINT"
${PREFIX}tpmpublic2eccpoint -ipu QsBpub.bin -pt QsBpt.bin > run.out
checkSuccess $?

echo "Execute zgen2phase for curve ${CURVE}"
${PREFIX}zgen2phase -hk 80000001 -scheme ecdh -qsb QsBpt.bin -qeb QeBpt.bin -cf counter.bin > run.out
checkSuccess $?

echo "Flush the key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

rm -rf efile.bin
rm -rf tmprpub.bin
rm -rf tmprpriv.bin
rm -rf counterfile.bin
rm -rf counterfileold.bin
rm -rf p1.bin
rm -rf hashinput.bin
rm -rf outhash.bin
rm -rf sig.bin
rm -rf tfile.bin

rm -rf QsBpub.bin
rm -rf QeBpt.bin
rm -rf QsApriv.bin
rm -rf QsApub.bin
rm -rf QeApt.bin
rm -rf counter.bin
rm -rf QsBpt.bin

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 02000000
