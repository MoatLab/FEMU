#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2014 - 2020					#
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

# handles are
# 80000000 platform hierarchy primary storage key
#    password pps
# storage key under primary
#    password sto
#    storepriv.bin
# signing key under primary
#    password sig
#    signpriv.bin
# RSA encryption key under primary
#    password dec
#    decpriv.bin

# at test entry and exit, there is a platform primary key at 80000000 and
# storage and signing keys under them, ready to load.
# The exception is the last test case, which rolls the seeds.

# This is a namespace prefix 
# For the basic tarball, PREFIX is set to ./   (the current directory)

PREFIX=./

# The distro releases prefix all the TPM 2.0 utility names with tss,
# so PREFIX is set to tss

# PREFIX=tss

#PREFIX="valgrind ./"

# hash algorithms to be used for testing

export ITERATE_ALGS="sha1 sha256 sha384 sha512"
export BAD_ITERATE_ALGS="sha256 sha384 sha512 sha1"

printUsage ()
{
    echo ""
    echo ""
    echo "-h help"
    echo "-a all tests"
    echo "-1 random number generator"
    echo "-2 PCR"
    echo "-3 primary keys"
    echo "-4 createloaded - rev 146"
    echo "-5 HMAC session - no bind or salt"
    echo "-6 HMAC session - bind"
    echo "-7 HMAC session - salt"
    echo "-8 Hierarchy"
    echo "-9 Storage"
    echo "-10 Object Change Auth"
    echo "-11 Encrypt and decrypt sessions"
    echo "-12 Sign"
    echo "-13 NV"
    echo "-14 NV PIN Index - rev 138"
    echo "-15 Evict control"
    echo "-16 RSA encrypt decrypt"
    echo "-17 AES encrypt decrypt"
    echo "-18 AES encrypt decrypt - rev 138"
    echo "-19 HMAC and Hash"
    echo "-20 Attestation"
    echo "-21 Policy"
    echo "-22 Policy - rev 138"
    echo "-23 Context"
    echo "-24 Clocks and Timers"
    echo "-25 DA logic"
    echo "-26 Unseal"
    echo "-27 Duplication"
    echo "-28 ECC"
    echo "-29 Credential"
    echo "-30 Attestation - rev 155" 
    echo "-31 X509 - rev 155" 
    echo "-32 Get Capability"
    echo "-35 Shutdown (only run for simulator)"
    echo "-40 Tests under development (not part of all)"
    echo ""
    echo "-50 Change seed"
}

checkSuccess()
{
if [ $1 -ne 0 ]; then
    echo " ERROR:"
    cat run.out
    exit 255
else
    echo " INFO:"
fi

}

# FIXME should not increment past 254

checkWarning()
{
if [ $1 -ne 0 ]; then
    echo " WARN: $2"
    ((WARN++))
else
    echo " INFO:"
fi
}

checkFailure()
{
if [ $1 -eq 0 ]; then
    echo " ERROR:"
    cat run.out
    exit 255
else
    echo " INFO:"
fi
}

cleanup()
{
# stdout
    rm -f run.out
# general purpose keys
    rm -f derrsa2048priv.bin
    rm -f derrsa2048pub.bin
    rm -f derrsa3072priv.bin
    rm -f derrsa3072pub.bin
    rm -f despriv.bin
    rm -f despub.bin
    rm -f khprivsha1.bin
    rm -f khprivsha256.bin
    rm -f khprivsha384.bin
    rm -f khprivsha512.bin
    rm -f khpubsha1.bin
    rm -f khpubsha256.bin
    rm -f khpubsha384.bin
    rm -f khpubsha512.bin
    rm -f khrprivsha1.bin
    rm -f khrprivsha256.bin
    rm -f khrprivsha384.bin
    rm -f khrprivsha512.bin
    rm -f khrpubsha1.bin
    rm -f khrpubsha256.bin
    rm -f khrpubsha384.bin
    rm -f khrpubsha512.bin
    rm -f prich.bin
    rm -f pritk.bin
    rm -f signeccnfpriv.bin
    rm -f signeccnfpub.bin
    rm -f signeccnfpub.pem
    rm -f signeccpriv.bin
    rm -f signeccpub.bin
    rm -f signeccpub.pem
    rm -f signeccrpriv.bin
    rm -f signeccrpub.bin
    rm -f signeccrpub.pem
    rm -f signrsa2048nfpriv.bin
    rm -f signrsa2048nfpub.bin
    rm -f signrsa2048nfpub.pem
    rm -f signrsa2048priv.bin
    rm -f signrsa2048pub.bin
    rm -f signrsa2048pub.pem
    rm -f signrsa3072priv.bin
    rm -f signrsa3072pub.bin
    rm -f signrsa3072pub.pem
    rm -f signrsa2048rpriv.bin
    rm -f signrsa2048rpub.bin
    rm -f signrsa2048rpub.pem
    rm -f stoch.bin
    rm -f storeeccpriv.bin
    rm -f storeeccpub.bin
    rm -f storsach.bin
    rm -f storsatk.bin
    rm -f stotk.bin
    rm -r storersa2048priv.bin
    rm -r storersa2048pub.bin

# misc
    rm -f dec.bin
    rm -f enc.bin
    rm -f msg.bin
    rm -f noncetpm.bin
    rm -f policyapproved.bin
    rm -f pssig.bin
    rm -f sig.bin
    rm -f tkt.bin
    rm -f tmp.bin
    rm -f tmp1.bin
    rm -f tmp2.bin
    rm -f tmpsha1.bin
    rm -f tmpsha256.bin
    rm -f tmpsha384.bin
    rm -f tmpsha512.bin
    rm -f tmppriv.bin
    rm -f tmppub.bin
    rm -f tmpspriv.bin
    rm -f tmpspub.bin
    rm -f to.bin
    rm -f zero.bin
}

initprimary()
{
    echo "Create a platform primary RSA storage key"
    ${PREFIX}createprimary -hi p -pwdk sto -pol policies/zerosha256.bin -tk pritk.bin -ch prich.bin > run.out
    checkSuccess $?
}


export -f checkSuccess
export -f checkWarning
export -f checkFailure
export WARN
export PREFIX
export -f initprimary
# hack because the mbedtls port is incomplete
export CRYPTOLIBRARY=`${PREFIX}getcryptolibrary`

# example for running scripts with encrypted sessions, see TPM_SESSION_ENCKEY=getrandom below
export TPM_SESSION_ENCKEY

main ()
{
    RC=0
    I=0
    ((WARN=0))

    if [ "$1" == "-h" ]; then
	printUsage
	echo ""
	echo "crypto library is ${CRYPTOLIBRARY}"
	echo ""
	exit 0
    else
	# the MS simulator needs power up and startup
	if [ -z ${TPM_INTERFACE_TYPE} ] || [ ${TPM_INTERFACE_TYPE} == "socsim" ];  then
	    if [ -z ${TPM_SERVER_TYPE} ] || [ ${TPM_SERVER_TYPE} == "mssim" ]; then
		./regtests/inittpm.sh
	    fi
	fi
    	RC=$?
	if [ $RC -ne 0 ]; then
	    exit 255
	fi
	# example for running scripts with encrypted sessions, see TPM_ENCRYPT_SESSIONS above
	# getrandom must wait until after inittpm.sh (powerup and startup)
	TPM_SESSION_ENCKEY=`${PREFIX}getrandom -by 16 -ns`
	./regtests/initkeys.sh
	RC=$?
	if [ $RC -ne 0 ]; then
	    exit 255
	fi
	((WARN=$RC))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-1" ]; then
    	./regtests/testrng.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-2" ]; then
    	./regtests/testpcr.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-3" ]; then
    	./regtests/testprimary.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-4" ]; then
    	./regtests/testcreateloaded.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
    	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-5" ]; then
    	./regtests/testhmacsession.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-6" ]; then
    	./regtests/testbind.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-7" ]; then
    	./regtests/testsalt.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-8" ]; then
    	./regtests/testhierarchy.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-9" ]; then
    	./regtests/teststorage.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-10" ]; then
    	./regtests/testchangeauth.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-11" ]; then
    	./regtests/testencsession.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-12" ]; then
    	./regtests/testsign.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-13" ]; then
    	./regtests/testnv.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-14" ]; then
    	./regtests/testnvpin.sh
    	RC=$?
	if [ $RC -ne 0 ]; then
	    exit 255
	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-15" ]; then
    	./regtests/testevict.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-16" ]; then
    	./regtests/testrsa.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-17" ]; then
    	./regtests/testaes.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-18" ]; then
    	./regtests/testaes138.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-19" ]; then
    	./regtests/testhmac.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-20" ]; then
    	./regtests/testattest.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
	((WARN=$RC))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-21" ]; then
    	./regtests/testpolicy.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-22" ]; then
    	./regtests/testpolicy138.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-23" ]; then
    	./regtests/testcontext.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-24" ]; then
    	./regtests/testclocks.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-25" ]; then
    	./regtests/testda.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-26" ]; then
    	./regtests/testunseal.sh
    	RC=$?
    	if [ $RC -ne 0 ]; then
    	    exit 255
    	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-27" ]; then
    	./regtests/testdup.sh
    	RC=$?
	if [ $RC -ne 0 ]; then
	    exit 255
	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-28" ]; then
    	./regtests/testecc.sh
    	RC=$?
	if [ $RC -ne 0 ]; then
	    exit 255
	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-29" ]; then
    	./regtests/testcredential.sh
    	RC=$?
	if [ $RC -ne 0 ]; then
	    exit 255
	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-30" ]; then
    	./regtests/testattest155.sh
    	RC=$?
	if [ $RC -ne 0 ]; then
	    exit 255
	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-31" ]; then
    	./regtests/testx509.sh
    	RC=$?
	if [ $RC -ne 0 ]; then
	    exit 255
	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-32" ]; then
    	./regtests/testgetcap.sh
    	RC=$?
	if [ $RC -ne 0 ]; then
	    exit 255
	fi
	((I++))
    fi
    if [ "$1" == "-a" ] || [ "$1" == "-35" ]; then
	# the MS simulator supports power cycling
	if [ -z ${TPM_INTERFACE_TYPE} ] || [ ${TPM_INTERFACE_TYPE} == "socsim" ];  then
	    if [ -z ${TPM_SERVER_TYPE} ] || [ ${TPM_SERVER_TYPE} == "mssim" ]; then
		./regtests/testshutdown.sh
	    fi
	fi
   	RC=$?
	if [ $RC -ne 0 ]; then
	    exit 255
	fi
	((I++))
    fi
    if [ "$1" == "-40" ]; then
     	./regtests/testdevel.sh
     	RC=$?
     	if [ $RC -ne 0 ]; then
     	    exit 255
     	fi
     	((I++))
     	((WARN=$RC))
    fi
# this must be the last test
    if [ "$1" == "-a" ] || [ "$1" == "-50" ]; then
    	./regtests/testchangeseed.sh
    	RC=$?
	if [ $RC -ne 0 ]; then
	    exit 255
	fi
	((I++))
    fi
    if [ $RC -ne 0 ]; then
	echo ""
	echo "Failed"
	echo ""
	exit 255
    else
	# -0 is a debug mode that initializes and does not clean up
	if [ "$1" != "-0" ]; then
	    ${PREFIX}flushcontext -ha 80000000
	    cleanup
	fi

	echo ""
	echo "Success - ${I} Tests ${WARN} Warnings"
	echo ""
    fi
}


main "$@"
