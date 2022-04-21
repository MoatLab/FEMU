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
echo "Attestation"
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

	    echo "Signing Key Self Certify ${HALG} ${SALG} ${SESS}"
	    ${PREFIX}certify -hk ${HANDLE} -ho 80000001 -halg ${HALG} -pwdk sig -pwdo sig ${SESS} -os sig.bin -oa tmp.bin -qd policies/aaa -salg ${SALG} > run.out
	    checkSuccess $?

	    echo "Verify the ${SALG} signature ${HALG}"
	    ${PREFIX}verifysignature -hk ${HANDLE} -halg ${HALG} -if tmp.bin -is sig.bin > run.out
	    checkSuccess $?

	    echo "Quote ${HALG} ${SALG} ${SALG} ${SESS}"
	    ${PREFIX}quote -hp 0 -hk ${HANDLE} -halg ${HALG} -palg ${HALG} -pwdk sig ${SESS} -os sig.bin -oa tmp.bin -qd policies/aaa -salg ${SALG} > run.out
	    checkSuccess $?

	    echo "Verify the ${SALG} signature ${HALG}"
	    ${PREFIX}verifysignature -hk ${HANDLE} -halg ${HALG} -if tmp.bin -is sig.bin > run.out
	    checkSuccess $?

	    echo "Get Time ${HALG} ${SALG} ${SESS}"
	    ${PREFIX}gettime -hk ${HANDLE} -halg ${HALG} -pwdk sig ${SESS} -os sig.bin -oa tmp.bin -qd policies/aaa -salg ${SALG} > run.out
	    checkSuccess $?

	    echo "Verify the ${SALG} signature ${HALG}"
	    ${PREFIX}verifysignature -hk ${HANDLE} -halg ${HALG} -if tmp.bin -is sig.bin > run.out
	    checkSuccess $?

	    echo "NV Certify ${HALG} ${SALG} ${SESS}"
	    ${PREFIX}nvcertify -ha 01000000 -pwdn nnn -hk ${HANDLE} -pwdk sig -halg ${HALG} -sz 16 ${SESS} -os sig.bin -oa tmp.bin -salg ${SALG} > run.out
	    checkSuccess $?

	    echo "Verify the ${SALG} signature ${HALG}"
	    ${PREFIX}verifysignature -hk ${HANDLE} -halg ${HALG} -if tmp.bin -is sig.bin > run.out
	    checkSuccess $?

	    echo "Set command audit digest ${HALG}"
	    ${PREFIX}setcommandcodeauditstatus -hi p -halg null -clr 00000144 > run.out
	    checkSuccess $?

	    echo "Get command audit digest ${HALG} ${SALG} ${SESS}"
	    ${PREFIX}getcommandauditdigest -hk ${HANDLE} -halg ${HALG} ${SESS} -pwdk sig -os sig.bin -oa tmp.bin -qd policies/aaa -salg ${SALG} > run.out
	    checkSuccess $?

	    echo "Verify the ${SALG} signature ${HALG}"
	    ${PREFIX}verifysignature -hk ${HANDLE} -halg ${HALG} -if tmp.bin -is sig.bin > run.out
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

echo "Flush the auth session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Attestation with an HMAC key"
echo ""

echo "Generate an HMAC key"
${PREFIX}getrandom -by 32 -of tmphkey.bin -ns > run.out
checkSuccess $?

for HALG in ${ITERATE_ALGS}
do

    echo "Create a ${HALG} HMAC key ${HMACKEY}"
    ${PREFIX}create -hp 80000000 -pwdp sto -kh -halg ${HALG} -if tmphkey.bin -opu tmppub.bin -opr tmppriv.bin > run.out
    checkSuccess $?

    echo "Load the ${HALG} HMAC key"
    ${PREFIX}load -hp 80000000 -pwdp sto -ipu tmppub.bin -ipr tmppriv.bin > run.out
    checkSuccess $?

    echo "Signing Key Self Certify with an HMAC key ${HALG}"
    ${PREFIX}certify -hk 80000001 -ho 80000001 -halg ${HALG} -salg hmac -os sig.bin -oa tmp.bin -qd policies/aaa > run.out
    checkSuccess $?

    echo "Verify the signature ${HALG} using TPM"
    ${PREFIX}verifysignature -hk 80000001 -halg ${HALG} -if tmp.bin -is sig.bin > run.out
    checkSuccess $?

    echo "Verify the signature ${HALG} using OpenSSL"
    ${PREFIX}verifysignature -halg ${HALG} -if tmp.bin -is sig.bin -ihmac tmphkey.bin > run.out
    checkSuccess $?

    echo "Quote with an HMAC key ${HALG}"
    ${PREFIX}quote -hp 0 -hk 80000001 -halg ${HALG} -salg hmac -os sig.bin -oa tmp.bin -qd policies/aaa > run.out
    checkSuccess $?

    echo "Verify the signature ${HALG} using TPM"
    ${PREFIX}verifysignature -hk 80000001 -halg ${HALG} -if tmp.bin -is sig.bin > run.out
    checkSuccess $?

    echo "Verify the signature ${HALG} using OpenSSL"
    ${PREFIX}verifysignature -halg ${HALG} -if tmp.bin -is sig.bin -ihmac tmphkey.bin > run.out
    checkSuccess $?

    echo "Gettime signed with an HMAC key ${HALG}"
    ${PREFIX}gettime -hk 80000001 -halg ${HALG} -salg hmac -os sig.bin -oa tmp.bin -qd policies/aaa > run.out
    checkSuccess $?

    echo "Verify the signature ${HALG} using TPM"
    ${PREFIX}verifysignature -hk 80000001 -halg ${HALG} -if tmp.bin -is sig.bin > run.out
    checkSuccess $?

    echo "Verify the signature ${HALG} using OpenSSL"
    ${PREFIX}verifysignature -halg ${HALG} -if tmp.bin -is sig.bin -ihmac tmphkey.bin > run.out
    checkSuccess $?

    echo "NV Certify with an HMAC key ${HALG}"
    ${PREFIX}nvcertify -ha 01000000 -pwdn nnn -hk 80000001 -halg ${HALG} -salg hmac -sz 16 -os sig.bin -oa tmp.bin > run.out
    checkSuccess $?

    echo "Verify the signature ${HALG} using TPM"
    ${PREFIX}verifysignature -hk 80000001 -halg ${HALG} -if tmp.bin -is sig.bin > run.out
    checkSuccess $?

    echo "Verify the signature ${HALG} using OpenSSL"
    ${PREFIX}verifysignature -halg ${HALG} -if tmp.bin -is sig.bin -ihmac tmphkey.bin > run.out
    checkSuccess $?

    echo "Get command audit digest with an HMAC key ${HALG}"
    ${PREFIX}getcommandauditdigest -hk 80000001 -halg ${HALG} -salg hmac -os sig.bin -oa tmp.bin -qd policies/aaa > run.out
    checkSuccess $?

    echo "Verify the signature ${HALG} using TPM"
    ${PREFIX}verifysignature -hk 80000001 -halg ${HALG} -if tmp.bin -is sig.bin > run.out
    checkSuccess $?

    echo "Verify the signature ${HALG} using OpenSSL"
    ${PREFIX}verifysignature -halg ${HALG} -if tmp.bin -is sig.bin -ihmac tmphkey.bin > run.out
    checkSuccess $?

    echo "Flush the ${HALG} HMAC key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

done

echo "NV Undefine Space"
${PREFIX}nvundefinespace -hi o -ha 01000000 > run.out
checkSuccess $?

echo ""
echo "Audit"
echo ""

# 80000001 signing key
# 02000000 hmac and audit session

echo ""
echo "Audit with one session"
echo ""

echo "Load the audit signing key"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
checkSuccess $?

for BIND in "" "-bi 80000001 -pwdb sig"
do
    for HALG in ${ITERATE_ALGS}
    do

	echo "Start an HMAC auth session ${HALG} ${BIND}"
	${PREFIX}startauthsession -se h -halg ${HALG} ${BIND} > run.out
	checkSuccess $?

	echo "Sign a digest ${HALG}"
	${PREFIX}sign -hk 80000001 -halg ${HALG} -if policies/aaa -os sig.bin -pwdk sig -ipu signrsa2048pub.bin -se0 02000000 81 > run.out
	checkSuccess $?

	echo "Sign a digest ${HALG}"
	${PREFIX}sign -hk 80000001 -halg ${HALG} -if policies/aaa -os sig.bin -pwdk sig -se0 02000000 81 -ipu signrsa2048pub.bin > run.out
	checkWarning $? "Interaction between bind and audit session response HMAC may not be fixed"

	echo "Get Session Audit Digest ${HALG}"
	${PREFIX}getsessionauditdigest -hs 02000000 -hk 80000001 -pwdk sig -halg ${HALG} -os sig.bin -oa tmp.bin -qd policies/aaa > run.out
	checkSuccess $?

	echo "Verify the signature ${HALG}"
	${PREFIX}verifysignature -hk 80000001 -halg ${HALG} -if tmp.bin -is sig.bin > run.out
	checkSuccess $?

	echo "Flush the session"
	${PREFIX}flushcontext -ha 02000000 > run.out
	checkSuccess $?

    done
done

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

# 80000001 signing key
# 02000000 hmac session
# 02000001 audit session

echo ""
echo "Audit with HMAC and audit sessions"
echo ""

echo "Load the audit signing key"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

for SESS in "" "-se0 02000000 1"
do

    for HALG in ${ITERATE_ALGS}
    do

	echo "Start an audit session ${HALG}"
	${PREFIX}startauthsession -se h -halg ${HALG} > run.out
	checkSuccess $?

	echo "Sign a digest ${HALG}"
	${PREFIX}sign -hk 80000001 -halg $HALG -if policies/aaa -os sig.bin -pwdk sig -ipu signrsa2048pub.bin -se0 02000001 81 > run.out
	checkSuccess $?

	echo "Get Session Audit Digest ${SESS}"
	${PREFIX}getsessionauditdigest -hs 02000001 -hk 80000001 -pwdk sig -os sig.bin -oa tmp.bin ${SESS} -qd policies/aaa > run.out
	checkSuccess $?

	echo "Verify the signature"
	${PREFIX}verifysignature -hk 80000001 -if tmp.bin -is sig.bin > run.out
	checkSuccess $?

	echo "Flush the session"
	${PREFIX}flushcontext -ha 02000001 > run.out
	checkSuccess $?

    done
done

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Certify Creation"
echo ""

echo "Load the RSA signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Certify the creation data for the primary key 80000000"
${PREFIX}certifycreation -ho 80000000 -hk 80000001 -pwdk sig -tk pritk.bin -ch prich.bin -os sig.bin -oa tmp.bin > run.out
checkSuccess $?

echo "Verify the signature"
${PREFIX}verifysignature -hk 80000001 -if tmp.bin -is sig.bin > run.out
checkSuccess $?

echo "Load the RSA storage key under the primary key"
${PREFIX}load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Certify the creation data for the storage key 80000002"
${PREFIX}certifycreation -ho 80000002 -hk 80000001 -pwdk sig -tk storsatk.bin -ch storsach.bin -os sig.bin -oa tmp.bin > run.out
checkSuccess $?

echo "Verify the signature"
${PREFIX}verifysignature -hk 80000001 -if tmp.bin -is sig.bin > run.out
checkSuccess $?

echo "Flush the storage key 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flush the signing key 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Audit a PCR Read"
echo ""

for HALG in ${ITERATE_ALGS}
do

    echo "Start an audit session ${HALG}"
    ${PREFIX}startauthsession -se h -halg  ${HALG} > run.out
    checkSuccess $?

    echo "PCR 16 reset"
    ${PREFIX}pcrreset -ha 16 > run.out
    checkSuccess $?

    cp policies/zero${HALG}.bin tmpdigestr.bin

    echo "PCR 16 read ${HALG}"
    ${PREFIX}pcrread -ha 16 -halg ${HALG} -se0 02000000 81 -ahalg ${HALG} -iosad tmpdigestr.bin > run.out
    checkSuccess $?

    echo "Get session audit digest"
    ${PREFIX}getsessionauditdigest -hs 02000000 -od tmpdigestg.bin > run.out
    checkSuccess $?

    echo "Check session audit digest"
    diff tmpdigestr.bin tmpdigestg.bin
    checkSuccess $?

    echo "Extend PCR 16"
    ${PREFIX}pcrextend -ha 16 -halg ${HALG} -ic aaa > run.out
    checkSuccess $?

    echo "PCR 16 read ${HALG}"
    ${PREFIX}pcrread -ha 16 -halg ${HALG} -se0 02000000 81 -ahalg ${HALG} -iosad tmpdigestr.bin > run.out
    checkSuccess $?

     echo "Get session audit digest"
    ${PREFIX}getsessionauditdigest -hs 02000000 -od tmpdigestg.bin > run.out
    checkSuccess $?

    echo "Check session audit digest"
    diff tmpdigestr.bin tmpdigestg.bin
    checkSuccess $?

    echo "Flush the audit session"
    ${PREFIX}flushcontext -ha 02000000
    checkSuccess $?

done

# cleanup

rm -f tmppriv.bin
rm -f tmppub.bin
rm -f tmpdigestr.bin
rm -f tmpdigestg.bin
rm -f sig.bin
rm -f tmp.bin
rm -f tmphkey.bin

exit ${WARN}

# ${PREFIX}getcapability -cap 1 -pr 80000000
# ${PREFIX}getcapability -cap 1 -pr 02000000
