REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #										#
REM # (c) Copyright IBM Corporation 2015 - 2020					#
REM # 										#
REM # All rights reserved.							#
REM # 										#
REM # Redistribution and use in source and binary forms, with or without	#
REM # modification, are permitted provided that the following conditions are	#
REM # met:									#
REM # 										#
REM # Redistributions of source code must retain the above copyright notice,	#
REM # this list of conditions and the following disclaimer.			#
REM # 										#
REM # Redistributions in binary form must reproduce the above copyright		#
REM # notice, this list of conditions and the following disclaimer in the	#
REM # documentation and/or other materials provided with the distribution.	#
REM # 										#
REM # Neither the names of the IBM Corporation nor the names of its		#
REM # contributors may be used to endorse or promote products derived from	#
REM # this software without specific prior written permission.			#
REM # 										#
REM # THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS	#
REM # "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
REM # LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	#
REM # A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT	#
REM # HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
REM # SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
REM # LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	#
REM # DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	#
REM # THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT	#
REM # (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	#
REM # OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.	#
REM #										#
REM #############################################################################

setlocal enableDelayedExpansion

REM 80000001 K1 storage key
REM 80000002 K2 signing key to be duplicated
REM 80000002 K2 duplicated
REM 03000000 policy session

REM policy
REM be f5 6b 8c 1c c8 4e 11 ed d7 17 52 8d 2c d9 93 
REM 56 bd 2b bf 8f 01 52 09 c3 f8 4a ee ab a8 e8 a2 

REM used for the name in rewrap

echo ""
echo "Duplication"
echo ""

echo ""
echo "Duplicate Child Key"
echo ""

REM # primary key		80000000
REM # target storage key K1 	80000001
REM #	originally under primary key
REM #	duplicate to K1
REM #	import to K1
REM # signing key        K2	80000002

set SALG=rsa ecc
set SKEY=rsa2048 ecc

set i=0
for %%a in (!SALG!) do set /A i+=1 & set SALG[!i!]=%%a
set i=0
for %%b in (!SKEY!) do set /A i+=1 & set SKEY[!i!]=%%b
set L=!i!

for /L %%i in (1,1,!L!) do (

    for %%E in ("" "-salg aes -ik tmprnd.bin") do (

    	for %%H in (%ITERATE_ALGS%) do (

	    echo "Create a signing key K2 under the primary key, with policy"
	    %TPM_EXE_PATH%create -hp 80000000 -si -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyccduplicate.bin > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Load the !SALG[%%i]! storage key K1"
	    %TPM_EXE_PATH%load -hp 80000000 -ipr store!SKEY[%%i]!priv.bin -ipu store!SKEY[%%i]!pub.bin -pwdp sto > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Load the signing key K2"
	    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Sign a digest, %%H"
	    %TPM_EXE_PATH%sign -hk 80000002 -halg %%H -if policies/aaa -os sig.bin -pwdk sig  > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Verify the signature, %%H"
	    %TPM_EXE_PATH%verifysignature -hk 80000002 -halg %%H -if policies/aaa -is sig.bin > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	    echo "Start a policy session"
	    %TPM_EXE_PATH%startauthsession -se p > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Policy command code, duplicate"
	    %TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 14b > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	    echo "Get policy digest"
	    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out 
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	    echo "Get random AES encryption key"
	    %TPM_EXE_PATH%getrandom -by 16 -of tmprnd.bin > run.out 
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )
	    
	    echo "Duplicate K2 under !SALG[%%i]! K1, %%~E"
	    %TPM_EXE_PATH%duplicate -ho 80000002 -pwdo sig -hp 80000001 -od tmpdup.bin -oss tmpss.bin %%~E -se0 03000000 1 > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	    echo "Flush the original K2 to free object slot for import"
	    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	    echo "Import K2 under !SALG[%%i]! K1, %%~E"
	    %TPM_EXE_PATH%import -hp 80000001 -pwdp sto -ipu tmppub.bin -id tmpdup.bin -iss tmpss.bin %%~E -opr tmppriv.bin > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	    echo "Sign under K2, %%H - should fail"
	    %TPM_EXE_PATH%sign -hk 80000002 -halg %%H -if policies/aaa -os sig.bin -pwdk sig > run.out
    	    IF !ERRORLEVEL! EQU 0 (
       	       exit /B 1
    	    )

	    echo "Load the duplicated signing key K2"
	    %TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Sign using duplicated K2, %%H"
	    %TPM_EXE_PATH%sign -hk 80000002 -halg %%H -if policies/aaa -os sig.bin -pwdk sig > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Verify the signature, %%H"
	    %TPM_EXE_PATH%verifysignature -hk 80000002 -halg %%H -if policies/aaa -is sig.bin > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Flush the duplicated K2"
	    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Flush the parent K1"
	    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Flush the session"
	    %TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )
	)
    )
)

echo ""
echo "Duplicate Primary Key"
echo ""

echo "Create a platform primary signing key K2 80000001"
%TPM_EXE_PATH%createprimary -hi p -si -kt nf -kt np -pol policies/policyccduplicate.bin -opu tmppub.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Sign a digest"
%TPM_EXE_PATH%sign -hk 80000001 -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Start a policy session 03000000"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Policy command code, duplicate"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 14b > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Duplicate K2 under storage key"
%TPM_EXE_PATH%duplicate -ho 80000001 -hp 80000000 -od tmpdup.bin -oss tmpss.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Import K2 under storage key"
%TPM_EXE_PATH%import -hp 80000000 -pwdp sto -ipu tmppub.bin -id tmpdup.bin -iss tmpss.bin -opr tmppriv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Load the duplicated signing key K2 80000002"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Sign a digest"
%TPM_EXE_PATH%sign -hk 80000002 -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the primary key 8000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the duplicated key 80000002 "
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the session 03000000 "
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo ""
echo "Import PEM RSA signing key under RSA and ECC storage key"
echo ""

echo "generate the signing key with openssl"
openssl genrsa -out tmpprivkey.pem -aes256 -passout pass:rrrr 2048

echo "load the ECC storage key"
%TPM_EXE_PATH%load -hp 80000000 -pwdp sto -ipr storeeccpriv.bin -ipu storeeccpub.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (
    for %%H in (%ITERATE_ALGS%) do (
        for %%P in (80000000 80000001) do (

	    echo "Import the signing key under the parent key %%P %%H"
	    %TPM_EXE_PATH%importpem -hp %%P -pwdp sto -ipem tmpprivkey.pem -pwdk rrrr -opu tmppub.bin -opr tmppriv.bin -halg %%H > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	    echo "Load the TPM signing key"
	    %TPM_EXE_PATH%load -hp  %%P -pwdp sto -ipu tmppub.bin -ipr tmppriv.bin > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	    echo "Sign the message %%H  %%~S"
	    %TPM_EXE_PATH%sign -hk 80000002 -pwdk rrrr -if policies/aaa -os tmpsig.bin -halg %%H  %%~S > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	    echo "Verify the signature %%H"
	    %TPM_EXE_PATH%verifysignature -hk 80000002 -if policies/aaa -is tmpsig.bin -halg %%H > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	    echo "Flush the signing key"
	    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	)
    )
)

echo ""
echo "Import PEM EC signing key under RSA and ECC storage key"
echo ""

echo "generate the signing key with openssl"
openssl ecparam -name prime256v1 -genkey -noout | openssl pkey -aes256 -passout pass:rrrr -text > tmpecprivkey.pem

for %%S in ("" "-se0 02000000 1") do (
    for %%H in (%ITERATE_ALGS%) do (
        for %%P in (80000000 80000001) do (

	    echo "Import the signing key under the parent key %%P %%H"
	    %TPM_EXE_PATH%importpem -hp %%P -pwdp sto -ipem tmpecprivkey.pem -ecc -pwdk rrrr -opu tmppub.bin -opr tmppriv.bin -halg %%H > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	    echo "Load the TPM signing key"
	    %TPM_EXE_PATH%load -hp %%P -pwdp sto -ipu tmppub.bin -ipr tmppriv.bin > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	    echo "Sign the message %%H %%~S"
	    %TPM_EXE_PATH%sign -hk 80000002 -salg ecc -pwdk rrrr -if policies/aaa -os tmpsig.bin -halg %%H %%~S > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1test
	    )

	    echo "Verify the signature %%H"
	    %TPM_EXE_PATH%verifysignature -hk 80000002 -ecc -if policies/aaa -is tmpsig.bin -halg %%H > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	    echo "Flush the signing key"
	    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	        exit /B 1
	    )

	)
    )
)

echo "Flush the ECC storage key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo ""
echo "Rewrap"
echo ""

REM duplicate object O1 to K1 (the outer wrapper, knows inner wrapper)
REM rewrap O1 from K1 to K2 (does not know inner wrapper)
REM import O1 to K2 (knows inner wrapper)

REM 03000000 policy session for duplicate
    
REM at TPM 1, duplicate object to K1 outer wrapper, AES wrapper

echo "Create a storage key K2"
%TPM_EXE_PATH%create -hp 80000000 -st -kt f -kt p -opr tmpk2priv.bin -opu tmpk2pub.bin -pwdp sto -pwdk k2 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the storage key K1 80000001 public key "
%TPM_EXE_PATH%loadexternal -hi p -ipu storersa2048pub.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key O1 with policy"
%TPM_EXE_PATH%create -hp 80000000 -si -opr tmpsignpriv.bin -opu tmpsignpub.bin -pwdp sto -pwdk sig -pol policies/policyccduplicate.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key O1 80000002 under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmpsignpriv.bin -ipu tmpsignpub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Save the signing key O1 name"
cp h80000002.bin tmpo1name.bin

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code, duplicate"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 14b > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get random AES encryption key"
%TPM_EXE_PATH%getrandom -by 16 -of tmprnd.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Duplicate O1 80000002 under K1 80000001 outer wrapper, using AES inner wrapper"
%TPM_EXE_PATH%duplicate -ho 80000002 -pwdo sig -hp 80000001 -ik tmprnd.bin -od tmpdup.bin -oss tmpss.bin -salg aes -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush signing key O1 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush storage key K1 80000001 public key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM at TPM 2

echo "Load storage key K1 80000001 public and private key"
%TPM_EXE_PATH%load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load storage key K2 80000002 public key"
%TPM_EXE_PATH%loadexternal -hi p -ipu tmpk2pub.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Rewrap O1 from K1 80000001 to K2 80000002 "
%TPM_EXE_PATH%rewrap -ho 80000001 -hn 80000002 -pwdo sto -id tmpdup.bin -in tmpo1name.bin -iss tmpss.bin -od tmpdup.bin -oss tmpss.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush old key K1 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush new key K2 80000002 public key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM at TPM 3

echo "Load storage key K2 80000001 public key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmpk2priv.bin -ipu tmpk2pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Import rewraped O1 to K2"
%TPM_EXE_PATH%import -hp 80000001 -pwdp k2 -ipu tmpsignpub.bin -id tmpdup.bin -iss tmpss.bin -salg aes -ik tmprnd.bin -opr tmpsignpriv3.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the imported signing key O1 80000002 under K2 80000001"
%TPM_EXE_PATH%load -hp 80000001 -ipr tmpsignpriv3.bin -ipu tmpsignpub.bin -pwdp k2 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign using duplicated K2"
%TPM_EXE_PATH%sign -hk 80000002  -if policies/aaa -os sig.bin -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature"
%TPM_EXE_PATH%verifysignature -hk 80000002 -if policies/aaa -is sig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush storage key K2 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush signing key O1 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Duplicate Primary Sealed AES from Source to Target EK"
echo ""

REM # source creates AES key, sends to target

REM # Real code would send the target EK X509 certificate.  The target could
REM # defer recreating the EK until later.

REM # Target

for /L %%i in (1,1,!L!) do (

    echo "Target: Provision a target !SALG[%%i]! EK certificate"
    %TPM_EXE_PATH%createekcert -alg !SALG[%%i]! -cakey cakey.pem -capwd rrrr > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Target: Recreate the !SALG[%%i]! EK at 80000001"
    %TPM_EXE_PATH%createek -alg !SALG[%%i]! -cp -noflush > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Target: Convert the EK public key to PEM format for transmission to source"
    %TPM_EXE_PATH%readpublic -ho 80000001 -opem tmpekpub.pem > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Target: Flush the EK"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

REM # Here, target would send the EK PEM public key to the source

REM # The real source would
REM #
REM # 1 - walk the EK X509 certificate chain.  I have to add that sample code to createEK or make a new utility.
REM # 2 - use openssl to convert the X509 EK certificate the the PEM public key file
REM # 
REM # for now, the source trusts the target EK PEM public key

REM # Source

    echo "Source: Create an AES 256 bit key"
    %TPM_EXE_PATH%getrandom -by 32 -ns -of tmpaeskeysrc.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Source: Create primary duplicable sealed AES key 80000001"
    %TPM_EXE_PATH%createprimary -bl -kt nf -kt np -if tmpaeskeysrc.bin -pol policies/policyccduplicate.bin -opu tmpsdbpub.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Source: Load the target !SALG[%%i]! EK public key as a storage key 80000002"
    %TPM_EXE_PATH%loadexternal -!SALG[%%i]! -st -ipem tmpekpub.pem > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Source: Start a policy session, duplicate needs a policy 03000000"
    %TPM_EXE_PATH%startauthsession -se p > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Source: Policy command code, duplicate"
    %TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 14b > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Source: Read policy digest, for debug"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Source: Wrap the sealed AES key with the target EK public key"
    %TPM_EXE_PATH%duplicate -ho 80000001 -hp 80000002 -od tmpsdbdup.bin -oss tmpss.bin -se0 03000000 0 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Source: Flush the sealed AES key 80000001"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Source: Flush the EK public key 80000002"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

REM # Transmit the sealed AEK key wrapped with the target EK back to the target
REM # tmpsdbdup.bin private part wrapped in EK public key, via symmetric seed
REM # tmpsdbpub.bin public part 
REM # tmpss.bin symmetric seed, encrypted with EK public key

REM # Target

REM # NOTE This assumes that the endorsement hierarchy password is Empty.
REM # This may be a bad assumption if an attacker can get access and
REM # change it.

    echo "Target: Recreate the -!SALG[%%i]! EK at 80000001"
    %TPM_EXE_PATH%createek -alg !SALG[%%i]! -cp -noflush > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Target: Start a policy session, EK use needs a policy"
    %TPM_EXE_PATH%startauthsession -se p > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Target: Policy Secret with PWAP session and (Empty) endorsement auth"
    %TPM_EXE_PATH%policysecret -ha 4000000b -hs 03000000 -pwde "" > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Target: Read policy digest for debug"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Target: Import the sealed AES key under the EK storage key"
    %TPM_EXE_PATH%import -hp 80000001 -ipu tmpsdbpub.bin -id tmpsdbdup.bin -iss tmpss.bin -opr tmpsdbpriv.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Target: Restart the policy session"
    %TPM_EXE_PATH%policyrestart -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Target: Policy Secret with PWAP session and (Empty) endorsement auth"
    %TPM_EXE_PATH%policysecret -ha 4000000b -hs 03000000 -pwde "" > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Target: Read policy digest for debug"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Target: Load the sealed AES key under the EK storage key"
    %TPM_EXE_PATH%load -hp 80000001 -ipu tmpsdbpub.bin -ipr tmpsdbpriv.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Target: Unseal the AES key"
    %TPM_EXE_PATH%unseal -ha 80000002 -of tmpaeskeytgt.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

REM # A real target would not have access to tmpaeskeysrc.bin for the compare

    echo "Target: Verify the unsealed result, same at source, for debug"
    diff tmpaeskeytgt.bin tmpaeskeysrc.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the EK"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the sealed AES key"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the policy session"
    %TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

REM cleanup
    
echo "Undefine the RSA EK certificate index"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01c00002
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Undefine the ECC EK certificate index"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01c0000a
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

rm -f tmpo1name.bin
rm -f tmpsignpriv.bin
rm -f tmpsignpub.bin
rm -f tmprnd.bin
rm -f tmpdup.bin
rm -f tmpss.bin
rm -f tmpsignpriv3.bin
rm -f tmpsig.bin
rm -f tmpk2priv.bin
rm -f tmpk2pub.bin
rm -f tmposs.bin 
rm -f tmpprivkey.pem
rm -f tmpecprivkey.pem
rm -f tmppub.bin
rm -f tmppriv.bin
rm -f tmpekpub.pem
rm -f tmpaeskeysrc.bin
rm -f tmpsdbpub.bin
rm -f tmpsdbdup.bin
rm -f tmpss.bin
rm -f tmpsdbpriv.bin
rm -f tmpaeskeytgt.bin

exit /B 0

REM flushcontext -ha 80000001
REM flushcontext -ha 80000002
REM flushcontext -ha 03000000

REM getcapability -cap 1 -pr 80000000
REM getcapability -cap 1 -pr 03000000
