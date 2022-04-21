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

REM # used for the name in policy ticket

REM if [ -z $TPM_DATA_DIR ]; then
REM     TPM_DATA_DIR=.
REM fi

setlocal enableDelayedExpansion

echo ""
echo "Policy Command Code"
echo ""

echo "Create a signing key under the primary key - policy command code - sign"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyccsign.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM sign with correct policy command code

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy and wrong password"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk xxx > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, should fail, session used "
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

REM quote with bad policy or bad command 

REM echo "Start a policy session"
REM ./startauthsession -se p > run.out
REM     IF !ERRORLEVEL! NEQ 0 (
REM exit /B 1
REM )

echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Quote - PWAP"
%TPM_EXE_PATH%quote -hp 0 -hk 80000001 -os sig.bin -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Quote - policy, should fail"
%TPM_EXE_PATH%quote -hp 0 -hk 80000001 -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # echo "Flush the session"
REM # ./flushcontext -ha 03000000 > run.out
REM #     IF !ERRORLEVEL! NEQ 0 (
REM exit /B 1
REM )


REM # echo "Start a policy session"
REM # ./startauthsession -se p > run.out
REM #     IF !ERRORLEVEL! NEQ 0 (
REM exit /B 1
REM )

echo "Policy command code - quote"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 158 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

echo "Quote - policy, should fail"
%TPM_EXE_PATH%quote -hp 0 -hk 80000001 -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)


REM # echo "Flush the session"
REM # ./flushcontext -ha 03000000 > run.out
REM #     IF !ERRORLEVEL! NEQ 0 (
REM exit /B 1
REM )

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Command Code and Policy Password / Authvalue"
echo ""

echo "Create a signing key under the primary key - policy command code - sign, auth"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyccsign-auth.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # policypassword

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy password"
%TPM_EXE_PATH%policypassword -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, no password should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Sign a digest - policy, password"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # policyauthvalue

REM # echo "Start a policy session"
REM # startauthsession -se p > run.out
REM #     IF !ERRORLEVEL! NEQ 0 (
REM    exit /B 1
REM    )


echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy authvalue"
%TPM_EXE_PATH%policyauthvalue -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, no password should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Sign a digest - policy, password"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Password and Policy Authvalue flags"
echo ""

for %%C in (policypassword policyauthvalue) do (


    echo "Create a signing key under the primary key - policy command code - sign, auth"
    %TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyccsign-auth.bin > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Load the signing key under the primary key"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Start a policy session"
    %TPM_EXE_PATH%startauthsession -se p > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Policy command code - sign"
    %TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Policy %%C"
    %TPM_EXE_PATH%%%C -ha 03000000 > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Sign a digest - policy, password"
    %TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk sig > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Flush signing key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Create a signing key under the primary key - policy command code - sign"
    %TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyccsign.bin > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Load the signing key under the primary key"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Policy command code - sign"
    %TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Sign a digest - policy and wrong password"
    %TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk xxx > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Flush signing key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

    echo "Flush policy session"
    %TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
        IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
       )

)

echo ""
echo "Policy Signed"
echo ""

REM # create rsaprivkey.pem
REM # > openssl genrsa -out rsaprivkey.pem -aes256 -passout pass:rrrr 2048
REM # extract the public key
REM # > openssl pkey -inform pem -outform pem -in rsaprivkey.pem -passin pass:rrrr -pubout -out rsapubkey.pem 
REM # sign a test message msg.bin
REM # > openssl dgst -sha1 -sign rsaprivkey.pem -passin pass:rrrr -out pssig.bin msg.bin
REM #
REM # create the policy:
REM # use loadexternal -ns to get the name
REM 
REM # sha1
REM # 00044234c24fc1b9de6693a62453417d2734d7538f6f
REM # sha256
REM # 000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
REM # sha384
REM # 000ca8bfb42e75b4c22b366b372cd9994bafe8558aa182cf12c258406d197dab63ac46f5a5255b1deb2993a4e9fc92b1e26c
REM # sha512
REM # 000d0c36b2a951eccc7e3e12d03175a71304dc747f222a02af8fa2ac8b594ef973518d20b9a5452d0849e325710f587d8a55082e7ae321173619bc12122f3ad71466
REM 
REM # 00000160 plus the above name as text, add a blank line for empty policyRef
REM # to create policies/policysigned$HALG.txt
REM #
REM # 0000016000044234c24fc1b9de6693a62453417d2734d7538f6f
REM # 00000160000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
REM # 00000160000ca8bfb42e75b4c22b366b372cd9994bafe8558aa182cf12c258406d197dab63ac46f5a5255b1deb2993a4e9fc92b1e26c
REM # 00000160000d0c36b2a951eccc7e3e12d03175a71304dc747f222a02af8fa2ac8b594ef973518d20b9a5452d0849e325710f587d8a55082e7ae321173619bc12122f3ad71466
REM #
REM # use sha256 policies, policymaker default (policy session digest
REM # algorithm is separate from Name and signature hash algorithm)
REM #
REM # > policymaker -if policies/policysigned$HALG.txt -of policies/policysigned$HALG.bin -pr
REM #
REM # sha1
REM # 9d 81 7a 4e e0 76 eb b5 cf ee c1 82 05 cc 4c 01 
REM # b3 a0 5e 59 a9 b9 65 a1 59 af 1e cd 3d bf 54 fb 
REM # sha256
REM # de bf 9d fa 3c 98 08 0b f1 7d d1 d0 7b 54 fd e1 
REM # 07 93 7f e5 40 50 9e 70 96 aa 73 27 53 b3 83 31 
REM # sha384
REM # 45 c5 da 90 76 92 3a 70 03 6f df 56 ea e7 df db 
REM # 41 e2 01 75 24 49 54 94 66 93 6b c4 fc 88 ab 5c 
REM # sha512
REM # cd 34 96 08 39 ea 40 88 5e fa 7f 37 8b a7 21 f1 
REM # 78 6d 52 bb 93 47 9c 73 45 88 3c dc 1f 09 06 6f 
REM #
REM # 80000000 primary key
REM # 80000001 verification public key
REM # 80000002 signing key with policy
REM # 03000000 policy session

for %%H in (%ITERATE_ALGS%) do (

    echo "Load external just the public part of PEM at 80000001 - %%H"
    %TPM_EXE_PATH%loadexternal -halg %%H -nalg %%H -ipem policies/rsapubkey.pem -ns > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign a test message with openssl - %%H"
    openssl dgst -%%H -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin msg.bin

    echo "Verify the signature with 80000001 - %%H"
    %TPM_EXE_PATH%verifysignature -hk 80000001 -halg %%H -if msg.bin -is pssig.bin -raw > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Create a signing key under the primary key - policy signed - %%H"
    %TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policysigned%%H.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Load the signing key under the primary key at 80000002"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Start a policy session"
    %TPM_EXE_PATH%startauthsession -se p > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign a digest - policy, should fail"
    %TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! EQU 0 (
    exit /B 1
    )

    echo "Policy signed - sign with PEM key - %%H"
    %TPM_EXE_PATH%policysigned -hk 80000001 -ha 03000000 -sk policies/rsaprivkey.pem -halg %%H -pwdk rrrr > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Get policy digest"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 -of tmppol.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign a digest - policy signed"
    %TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

     echo "Policy restart, set back to zero"
    %TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign just expiration (uint32_t 4 zeros) with openssl - %%H"
    openssl dgst -%%H -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policies/zero4.bin

    echo "Policy signed, signature generated externally - %%H"
    %TPM_EXE_PATH%policysigned -hk 80000001 -ha 03000000 -halg %%H -is pssig.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign a digest - policy signed"
    %TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Start a policy session - save nonceTPM"
    %TPM_EXE_PATH%startauthsession -se p -on noncetpm.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Policy signed with nonceTPM and expiration, create a ticket - %%H"
    %TPM_EXE_PATH%policysigned -hk 80000001 -ha 03000000 -sk policies/rsaprivkey.pem -halg %%H -pwdk rrrr -in noncetpm.bin -exp -200 -tk tkt.bin -to to.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign a digest - policy signed"
    %TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Start a policy session"
    %TPM_EXE_PATH%startauthsession -se p > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Policy ticket"
    %TPM_EXE_PATH%policyticket -ha 03000000 -to to.bin -na h80000001.bin -tk tkt.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Sign a digest - policy ticket"
    %TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Flush the verification public key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Flush the signing key"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

)

REM # getcapability  -cap 1 -pr 80000000
REM # getcapability  -cap 1 -pr 02000000
REM # getcapability  -cap 1 -pr 03000000

REM # exit 0

echo ""
echo "Policy Secret"
echo ""

REM # 4000000c platform
REM # 80000000 primary key
REM # 80000001 signing key with policy
REM # 03000000 policy session
REM # 02000001 hmac session

echo "Change platform hierarchy auth"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key under the primary key - policy secret using platform auth"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policysecretp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -on noncetpm.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy Secret with PWAP session, create a ticket"
%TPM_EXE_PATH%policysecret -ha 4000000c -hs 03000000 -pwde ppp -in noncetpm.bin -exp -200 -tk tkt.bin -to to.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy secret"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -on noncetpm.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Secret using primary key, create a ticket"
%TPM_EXE_PATH%policysecret -ha 4000000c -hs 03000000 -pwde ppp -in noncetpm.bin -exp -200 -tk tkt.bin -to to.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy secret"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy ticket"
%TPM_EXE_PATH%policyticket -ha 03000000 -to to.bin -hi p -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy ticket"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -on noncetpm.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start an HMAC session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Secret with HMAC session"
%TPM_EXE_PATH%policysecret -ha 4000000c -hs 03000000 -pwde ppp -se0 02000001 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy secret"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Change platform hierarchy auth back to null"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwda ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Secret with NV Auth"
echo ""

REM Name is 
REM 00 0b e0 65 10 81 c2 fc da 30 69 93 da 43 d1 de 
REM 5b 24 be 42 6e 2d 61 90 7b 42 83 54 69 13 6c 97 
REM 68 1f 
REM
REM Policy is
REM c6 93 f9 b0 ef 1a b7 1e ca ae 00 af 1f 0b f4 88 
REM 37 9e ab 16 c1 f8 0d 9f f9 6d 90 41 4e 2f c6 b3 

echo "NV Define Space 0100000"
%TPM_EXE_PATH%nvdefinespace -hi p -ha 01000000 -pwdn nnn -sz 16 -pwdn nnn > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key under the primary key - policy secret NV auth"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policysecretnv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -on noncetpm.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy, should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy Secret with PWAP session"
%TPM_EXE_PATH%policysecret -ha 01000000 -hs 03000000 -pwde nnn -in noncetpm.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy secret"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine Space 0100000"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Secret with Object"
echo ""

REM # Use a externally generated object so that the Name is known and thus
REM # the policy can be precalculated

REM # Name
REM # 00 0b 64 ac 92 1a 03 5c 72 b3 aa 55 ba 7d b8 b5 
REM # 99 f1 72 6f 52 ec 2f 68 20 42 fc 0e 0d 29 fa e8 
REM # 17 99 

REM # 000001151 plus the above name as text, add a blank line for empty policyRef
REM # to create policies/policysecretsha256.txt
REM # 00000151000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799

REM # 4b 7f ca c2 b7 c3 ac a2 7c 5c da 9c 71 e6 75 28 
REM # 63 d2 87 d2 33 ec 49 0e 7a be 88 f1 ef 94 5d 5c 

echo "Load the RSA openssl key pair in the NULL hierarchy 80000001"
%TPM_EXE_PATH%loadexternal -rsa -ider policies/rsaprivkey.der -pwdk rrrr > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key under the primary key - policy secret of object 80000001"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -uwa -pol policies/policysecretsha256.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key 80000002"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - password auth - should fail"
%TPM_EXE_PATH%sign -hk 80000002 -if policies/aaa -pwdk sig > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Start a policy session 03000000"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Secret with PWAP session"
%TPM_EXE_PATH%policysecret -ha 80000001 -hs 03000000 -pwde rrrr > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy secret"
%TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the policysecret key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the RSA openssl key pair in the NULL hierarchy, userWithAuth false 80000001"
%TPM_EXE_PATH%loadexternal -rsa -ider policies/rsaprivkey.der -pwdk rrrr -uwa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Secret with PWAP session - should fail"
%TPM_EXE_PATH%policysecret -ha 80000001 -hs 03000000 -pwde rrrr > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush the policysecret key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Authorize"
echo ""

REM # 80000000 primary
REM # 80000001 verification public key, openssl
REM # 80000002 signing key
REM # 03000000 policy session

REM # Name for 80000001 0004 4234 c24f c1b9 de66 93a6 2453 417d 2734 d753 8f6f
REM #
REM # policyauthorizesha256.txt
REM # 0000016a000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
REM #
REM # (need blank line for policyRef)
REM #
REM # > policymaker -if policies/policyauthorizesha256.txt -of policies/policyauthorizesha256.bin -pr
REM #
REM # eb a3 f9 8c 5e af 1e a8 f9 4f 51 9b 4d 2a 31 83 
REM # ee 79 87 66 72 39 8e 23 15 d9 33 c2 88 a8 e5 03 

echo "Create a signing key with policy authorize"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyauthorizesha256.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load external just the public part of PEM authorizing key"
%TPM_EXE_PATH%loadexternal -hi p -halg sha256 -nalg sha256 -ipem policies/rsapubkey.pem > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest, should be zero"
%TPM_EXE_PATH%policygetdigest -ha 03000000 -of policyapproved.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest, should be policy to approve, aHash input"
%TPM_EXE_PATH%policygetdigest -ha 03000000 -of policyapproved.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Openssl generate aHash"
openssl dgst -sha256 -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policyapproved.bin

echo "Verify the signature to generate ticket"
%TPM_EXE_PATH%verifysignature -hk 80000001 -halg sha256 -if policyapproved.bin -is pssig.bin -raw -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy authorize using the ticket"
%TPM_EXE_PATH%policyauthorize -ha 03000000 -appr policyapproved.bin -skn h80000001.bin -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest, should be policy authorize"
%TPM_EXE_PATH%policygetdigest -ha 03000000 -of policyapproved.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest"
%TPM_EXE_PATH%sign -hk 80000002 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the verification public key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # getcapability  -cap 1 -pr 80000000
REM # getcapability  -cap 1 -pr 02000000
REM # getcapability  -cap 1 -pr 03000000

REM # exit 0

echo ""
echo "Set Primary Policy"
echo ""

echo "Platform policy empty"
%TPM_EXE_PATH%setprimarypolicy -hi p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Platform policy empty, bad password"
%TPM_EXE_PATH%setprimarypolicy -hi p -pwda ppp > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Set platform hierarchy auth"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Platform policy empty, bad password"
%TPM_EXE_PATH%setprimarypolicy -hi p > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Platform policy empty"
%TPM_EXE_PATH%setprimarypolicy -hi p -pwda ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Platform policy to policy secret platform auth"
%TPM_EXE_PATH%setprimarypolicy -hi p -pwda ppp -halg sha256 -pol policies/policysecretp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Secret with PWAP session"
%TPM_EXE_PATH%policysecret -ha 4000000c -hs 03000000 -pwde ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Change platform hierarchy auth to null with policy secret"
%TPM_EXE_PATH%hierarchychangeauth -hi p -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy PCR no select"
echo ""

REM # create AND term for policy PCR
REM # > policymakerpcr -halg sha1 -bm 0 -v -pr -of policies/policypcr.txt
REM # 0000017f00000001000403000000da39a3ee5e6b4b0d3255bfef95601890afd80709
REM 
REM # convert to binary policy
REM # > policymaker -halg sha1 -if policies/policypcr.txt -of policies/policypcrbm0.bin -pr -v
REM 
REM # 6d 38 49 38 e1 d5 8b 56 71 92 55 94 3f 06 69 66 
REM # b6 fa 2c 23 

echo "Create a signing key with policy PCR no select"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -nalg sha1 -pol policies/policypcrbm0.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -halg sha1 -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy PCR, update with the correct digest"
%TPM_EXE_PATH%policypcr -ha 03000000 -halg sha1 -bm 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be 6d 38 49 38 ... "
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign, should succeed"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy PCR, update with the correct digest"
%TPM_EXE_PATH%policypcr -ha 03000000 -halg sha1 -bm 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "PCR extend PCR 0, updates pcr counter"
%TPM_EXE_PATH%pcrextend -ha 0 -halg sha1 -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign, should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush the policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # policypcr0.txt has 20 * 00

REM # create AND term for policy PCR
REM # > policymakerpcr -halg sha1 -bm 10000 -if policies/policypcr0.txt -v -pr -of policies/policypcr.txt

REM # convert to binary policy
REM # > policymaker -halg sha1 -if policies/policypcr.txt -of policies/policypcr.bin -pr -v

echo ""
echo "Policy PCR"
echo ""

echo "Create a signing key with policy PCR PCR 16 zero"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -nalg sha1 -pol policies/policypcr.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Reset PCR 16 back to zero"
%TPM_EXE_PATH%pcrreset -ha 16 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Read PCR 16, should be 00 00 00 00 ..."
%TPM_EXE_PATH%pcrread -ha 16 -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign, policy not satisfied - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy PCR, update with the correct digest"
%TPM_EXE_PATH%policypcr -ha 03000000 -halg sha1 -bm 10000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be 85 33 11 83"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign, should succeed"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "PCR extend PCR 16"
%TPM_EXE_PATH%pcrextend -ha 16 -halg sha1 -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Read PCR 0, should be 1d 47 f6 8a ..."
%TPM_EXE_PATH%pcrread -ha 16 -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy PCR, update with the wrong digest"
%TPM_EXE_PATH%policypcr -ha 03000000 -halg sha1 -bm 10000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be 66 dd e5 e3"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush the policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # 01000000 authorizing ndex
REM # 01000001 authorized index
REM # 03000000 policy session
REM #
REM # 4 byte NV index
REM # policynv.txt
REM # policy CC_PolicyNV || args || Name
REM #
REM # policynvargs.txt (binary)
REM # args = hash of 0000 0000 0000 0000 | 0000 | 0000 (eight bytes of zero | offset | op ==)
REM # hash -hi n -halg sha1 -if policies/policynvargs.txt -v
REM # openssl dgst -sha1  policies/policynvargs.txt
REM # 2c513f149e737ec4063fc1d37aee9beabc4b4bbf
REM #
REM # NV authorizing index
REM #
REM # after defining index and NV write to set written, use 
REM # nvreadpublic -ha 01000000 -nalg sha1
REM # to get name
REM # 00042234b8df7cdf8605ee0a2088ac7dfe34c6566c5c
REM #
REM # append Name to policynvnv.txt
REM #
REM # convert to binary policy
REM # > policymaker -halg sha1 -if policies/policynvnv.txt -of policies/policynvnv.bin -pr -v
REM # bc 9b 4c 4f 7b 00 66 19 5b 1d d9 9c 92 7e ad 57 e7 1c 2a fc 
REM #
REM # file zero8.bin has 8 bytes of hex zero

echo ""
echo "Policy NV, NV index authorizing"
echo ""

echo "Define a setbits index, authorizing index"
%TPM_EXE_PATH%nvdefinespace -hi p -nalg sha1 -ha 01000000 -pwdn nnn -ty b > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read public, get Name, not written"
%TPM_EXE_PATH%nvreadpublic -ha 01000000 -nalg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV setbits to set written"
%TPM_EXE_PATH%nvsetbits -ha 01000000 -pwdn nnn > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read public, get Name, written"
%TPM_EXE_PATH%nvreadpublic -ha 01000000 -nalg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read, should be zero"
%TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 8 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Define an ordinary index, authorized index, policyNV"
%TPM_EXE_PATH%nvdefinespace -hi p -nalg sha1 -ha 01000001 -pwdn nnn -sz 2 -ty o -pol policies/policynvnv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read public, get Name, not written"
%TPM_EXE_PATH%nvreadpublic -ha 01000001 -nalg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write to set written"
%TPM_EXE_PATH%nvwrite -ha 01000001 -pwdn nnn -ic aa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
 
echo "NV write, policy not satisfied  - should fail"
%TPM_EXE_PATH%nvwrite -ha 01000001 -ic aa -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy get digest, should be 0"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy NV to satisfy the policy"
%TPM_EXE_PATH%policynv -ha 01000000 -pwda nnn -hs 03000000 -if policies/zero8.bin -op 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest, should be bc 9b 4c 4f ..."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write, policy satisfied"
%TPM_EXE_PATH%nvwrite -ha 01000001 -ic aa -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Set bit in authorizing NV index"
%TPM_EXE_PATH%nvsetbits -ha 01000000 -pwdn nnn -bit 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read, should be 1"
%TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 8 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy NV to satisfy the policy - should fail"
%TPM_EXE_PATH%policynv -ha 01000000 -pwda nnn -hs 03000000 -if policies/zero8.bin -op 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy get digest, should be 00 00 00 00 ..."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine authorizing index"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine authorized index"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000001 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy NV Written"
echo ""

echo "Define an ordinary index, authorized index, policyNV"
%TPM_EXE_PATH%nvdefinespace -hi p -nalg sha1 -ha 01000000 -pwdn nnn -sz 2 -ty o -pol policies/policywrittenset.bin > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read public, get Name, not written"
%TPM_EXE_PATH%nvreadpublic -ha 01000000 -nalg sha1 > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
 
echo "NV write, policy not satisfied  - should fail"
%TPM_EXE_PATH%nvwrite -ha 01000000 -ic aa -se0 03000000 1 > run.out  
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy NV Written no, does not satisfy policy"
%TPM_EXE_PATH%policynvwritten -hs 03000000 -ws n > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write, policy not satisfied - should fail"
%TPM_EXE_PATH%nvwrite -ha 01000000 -ic aa -se0 03000000 1 > run.out  
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy NV Written yes, satisfy policy"
%TPM_EXE_PATH%policynvwritten -hs 03000000 -ws y > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write, policy satisfied but written clear - should fail"
%TPM_EXE_PATH%nvwrite -ha 01000000 -ic aa -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write using password, set written"
%TPM_EXE_PATH%nvwrite -ha 01000000 -ic aa -pwdn nnn > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy NV Written yes, satisfy policy"
%TPM_EXE_PATH%policynvwritten -hs 03000000 -ws y > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write, policy satisfied"
%TPM_EXE_PATH%nvwrite -ha 01000000 -ic aa -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy NV Written no"
%TPM_EXE_PATH%policynvwritten -hs 03000000 -ws n > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy NV Written yes - should fail"
%TPM_EXE_PATH%policynvwritten -hs 03000000 -ws y > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out  
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine authorizing index"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Signed externally signed cpHash"
echo ""

REM # NV Index 01000000 has policy OR
REM 
REM # Policy A - provisioning: policy written false + policysigned
REM #	demo: authorizer signs NV write all zero
REM 
REM # Policy B - application: policy written true + policysigned
REM #	demo: authorizer signs NV write abcdefgh

echo "Load external just the public part of PEM at 80000001"
%TPM_EXE_PATH%loadexternal -ipem policies/rsapubkey.pem > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get the Name of the signing key at 80000001"
%TPM_EXE_PATH%readpublic -ho 80000001 -ns > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # 000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
REM 
REM # construct policy A
REM 
REM # policies/policywrittenclrsigned.txt
REM # 0000018f00
REM # 00000160000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
REM # Add the extra blank line here for policyRef
REM 
REM # policymaker -if policies/policywrittenclrsigned.txt -of policies/policywrittenclrsigned.bin -pr -ns -v
REM # intermediate policy digest length 32
REM #  3c 32 63 23 67 0e 28 ad 37 bd 57 f6 3b 4c c3 4d 
REM #  26 ab 20 5e f2 2f 27 5c 58 d4 7f ab 24 85 46 6e 
REM #  intermediate policy digest length 32
REM #  6b 0d 2d 2b 55 4d 68 ec bc 6c d5 b8 c0 96 c1 70 
REM #  57 5a 95 25 37 56 38 7e 83 d7 76 d9 5b 1b 8e f3 
REM #  intermediate policy digest length 32
REM #  48 0b 78 2e 02 82 c2 40 88 32 c4 df 9c 0e be 87 
REM #  18 6f 92 54 bd e0 5b 0c 2e a9 52 48 3e b7 69 f2 
REM #  policy digest length 32
REM #  48 0b 78 2e 02 82 c2 40 88 32 c4 df 9c 0e be 87 
REM #  18 6f 92 54 bd e0 5b 0c 2e a9 52 48 3e b7 69 f2 
REM # policy digest:
REM # 480b782e0282c2408832c4df9c0ebe87186f9254bde05b0c2ea952483eb769f2
REM 
REM # construct policy B
REM 
REM # policies/policywrittensetsigned.txt
REM # 0000018f01
REM # 00000160000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
REM # Add the extra blank line here for policyRef
REM 
REM # policymaker -if policies/policywrittensetsigned.txt -of policies/policywrittensetsigned.bin -pr -ns -v
REM #  intermediate policy digest length 32
REM #  f7 88 7d 15 8a e8 d3 8b e0 ac 53 19 f3 7a 9e 07 
REM #  61 8b f5 48 85 45 3c 7a 54 dd b0 c6 a6 19 3b eb 
REM #  intermediate policy digest length 32
REM #  7d c2 8f b0 dd 4f ee 97 78 2b 55 43 b1 dc 6b 1e 
REM #  e2 bc 79 05 d4 a1 f6 8d e2 97 69 5f a9 aa 78 5f 
REM #  intermediate policy digest length 32
REM #  09 43 ba 3c 3b 4d b1 c8 3f c3 97 85 f9 dc 0a 82 
REM #  49 f6 79 4a 04 38 e6 45 0a 50 56 8f b4 eb d2 46 
REM #  policy digest length 32
REM #  09 43 ba 3c 3b 4d b1 c8 3f c3 97 85 f9 dc 0a 82 
REM #  49 f6 79 4a 04 38 e6 45 0a 50 56 8f b4 eb d2 46 
REM # policy digest:
REM # 0943ba3c3b4db1c83fc39785f9dc0a8249f6794a0438e6450a50568fb4ebd246
REM 
REM # construct the Policy OR of A and B
REM 
REM # policyorwrittensigned.txt - command code plus two policy digests
REM # 00000171480b782e0282c2408832c4df9c0ebe87186f9254bde05b0c2ea952483eb769f20943ba3c3b4db1c83fc39785f9dc0a8249f6794a0438e6450a50568fb4ebd246
REM # policymaker -if policies/policyorwrittensigned.txt -of policies/policyorwrittensigned.bin -pr 
REM #  policy digest length 32
REM #  06 00 ae 34 7a 30 b0 67 36 d3 32 85 a0 cc ad 46 
REM #  54 1e 62 71 f5 d0 85 10 a7 ff 0e 90 30 54 d6 c9 

echo "Define index 01000000 with the policy OR"
%TPM_EXE_PATH%nvdefinespace -ha 01000000 -hi o -sz 8 -pwdn "" -pol policies/policyorwrittensigned.bin -at aw > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get the Name of the NV index not written, should be 00 0b ... bb 0b"
%TPM_EXE_PATH%nvreadpublic -ha 01000000 -ns > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # 000b366258674dcf8aa16d344f24dde1c799fc60f9427a7286bb8cd1e4e9fd1fbb0b

echo "Start a policy session 03000000"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy A - not written"
echo ""

REM # construct cpHash for Policy A - not written, writing zeros
REM  
REM # (commandCode || authHandle Name || NV Index Name || data + offset) - data 8 bytes of 0's at offset 0000
REM # For index auth, authHandle Name and index Name are the same
REM # policies/nvwritecphasha.txt
REM # 00000137000b366258674dcf8aa16d344f24dde1c799fc60f9427a7286bb8cd1e4e9fd1fbb0b000b366258674dcf8aa16d344f24dde1c799fc60f9427a7286bb8cd1e4e9fd1fbb0b000800000000000000000000
REM # policymaker -nz -if policies/nvwritecphasha.txt -of policies/nvwritecphasha.bin -pr -ns
REM #  policy digest length 32
REM #  cf 98 1e ee 68 04 3b dd ee 0c ab bc 75 b3 63 be 
REM #  3c f9 ee 22 2a 78 b8 26 3f 06 7b b3 55 2c a6 11 
REM # policy digest:
REM # cf981eee68043bddee0cabbc75b363be3cf9ee222a78b8263f067bb3552ca611
REM 
REM # construct aHash for Policy A
REM 
REM # expiration + cpHashA
REM # policies/nvwriteahasha.txt
REM # 00000000cf981eee68043bddee0cabbc75b363be3cf9ee222a78b8263f067bb3552ca611
REM # just convert to binary, because openssl does the hash before signing
REM # xxd -r -p policies/nvwriteahasha.txt policies/nvwriteahasha.bin

echo "Policy NV Written no, satisfy policy"
%TPM_EXE_PATH%policynvwritten -hs 03000000 -ws n > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Should be policy A first intermediate value 3c 32 63 23 ..."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign aHash with openssl 8813 6530 ..."
openssl dgst -sha256 -sign policies/rsaprivkey.pem -passin pass:rrrr -out sig.bin policies/nvwriteahasha.bin
echo ""

echo "Policy signed, signature generated externally"
%TPM_EXE_PATH%policysigned -hk 80000001 -ha 03000000 -halg sha256 -cp policies/nvwritecphasha.bin -is sig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Should be policy A final value 48 0b 78 2e ..."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policywrittenclrsigned.bin -if policies/policywrittensetsigned.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Should be policy OR final value 06 00 ae 34 "
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write to set written"
%TPM_EXE_PATH%nvwrite -ha 01000000 -if policies/zero8.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy B - written"
echo ""

echo "Get the new (written) Name of the NV index not written, should be 00 0b f5 75"
%TPM_EXE_PATH%nvreadpublic -ha 01000000 -ns > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # 000bf575f09107d38c4cb82e8ec054b1aca9a91e40a06ec074b578bdd9cdaf4b76c8
REM 
REM # construct cpHash for Policy B
REM  
REM # (commandCode || authHandle Name || NV Index Name || data + offset) - data 8 bytes of abcdefgh at offset 00000
REM # For index auth, authHandle Name and index Name are the same
REM # policies/nvwritecphashb.txt
REM # 00000137000bf575f09107d38c4cb82e8ec054b1aca9a91e40a06ec074b578bdd9cdaf4b76c8000bf575f09107d38c4cb82e8ec054b1aca9a91e40a06ec074b578bdd9cdaf4b76c8000861626364656667680000
REM # policymaker -nz -if policies/nvwritecphashb.txt -of policies/nvwritecphashb.bin -pr -ns
REM #  policy digest length 32
REM #  df 58 08 f9 ab cb 23 7f 8c d7 c9 09 1c 86 12 2d 
REM #  88 6f 02 d4 6e db 53 c8 da 39 bf a2 d6 cf 07 63 
REM # policy digest:
REM # df5808f9abcb237f8cd7c9091c86122d886f02d46edb53c8da39bfa2d6cf0763
REM 
REM # construct aHash for Policy B
REM 
REM # expiration + cpHashA
REM # policies/nvwriteahashb.txt
REM # 00000000df5808f9abcb237f8cd7c9091c86122d886f02d46edb53c8da39bfa2d6cf0763
REM # just convert to binary, because openssl does the hash before signing
REM # xxd -r -p policies/nvwriteahashb.txt policies/nvwriteahashb.bin

echo "Policy NV Written yes, satisfy policy"
%TPM_EXE_PATH%policynvwritten -hs 03000000 -ws y > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Should be policy A first intermediate value f7 88 7d 15 ..."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign aHash with openssl 3700 0a91 ..."
openssl dgst -sha256 -sign policies/rsaprivkey.pem -passin pass:rrrr -out sig.bin policies/nvwriteahashb.bin > run.out
echo ""

echo "Policy signed, signature generated externally"
%TPM_EXE_PATH%policysigned -hk 80000001 -ha 03000000 -halg sha256 -cp policies/nvwritecphashb.bin -is sig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Should be policy B final value 09 43 ba 3c ..."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policywrittenclrsigned.bin -if policies/policywrittensetsigned.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Should be policy OR final value 06 00 ae 34 "
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write new data"
%TPM_EXE_PATH%nvwrite -ha 01000000 -ic abcdefgh -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Cleanup"
echo ""

echo "Flush the policy session 03000000"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signature verification key 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Undefine the NV Index 01000000"
%TPM_EXE_PATH%nvundefinespace -hi o -ha 01000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # test using clockrateadjust
REM # policycphashhash.txt is (hex) 00000130 4000000c 000
REM # hash -if policycphashhash.txt -oh policycphashhash.bin -halg sha1 -v
REM # openssl dgst -sha1 policycphashhash.txt
REM # cpHash is
REM # b5f919bbc01f0ebad02010169a67a8c158ec12f3
REM # append to policycphash.txt 00000163 + cpHash
REM # policymaker -halg sha1 -if policies/policycphash.txt -of policies/policycphash.bin -pr
REM #  06 e4 6c f9 f3 c7 0f 30 10 18 7c a6 72 69 b0 84 b4 52 11 6f 

echo ""
echo "Policy cpHash"
echo ""

echo "Set the platform policy to policy cpHash"
%TPM_EXE_PATH%setprimarypolicy -hi p -pol policies/policycphash.bin -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clockrate adjust using wrong password - should fail"
%TPM_EXE_PATH%clockrateadjust -hi p -pwdp ppp -adj 0  > run.out 
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clockrate adjust, policy not satisfied - should fail"
%TPM_EXE_PATH%clockrateadjust -hi p -pwdp ppp -adj 0 -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy cpHash, satisfy policy"
%TPM_EXE_PATH%policycphash -ha 03000000 -cp policies/policycphashhash.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
 
echo "Policy get digest, should be 06 e4 6c f9"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clockrate adjust, policy satisfied but bad command params - should fail"
%TPM_EXE_PATH%clockrateadjust -hi p -pwdp ppp -adj 1 -se0 03000000 1 > run.out 
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Clockrate adjust, policy satisfied"
%TPM_EXE_PATH%clockrateadjust -hi p -pwdp ppp -adj 0 -se0 03000000 1 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clear the platform policy"
%TPM_EXE_PATH%setprimarypolicy -hi p > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Duplication Select with includeObject FALSE"
echo ""

REM # These tests uses a new parent and object to be duplicated generated
REM # externally.  This makes the Names repeatable and permits the
REM # policy to be pre-calculated and static.
REM 
REM # command code 00000188
REM # newParentName
REM # 000b 1a5d f667 7533 4527 37bc 79a5 5ab6 
REM # d9fa 9174 5c03 3dfe 3f82 cdf0 903b a9d6
REM # 55f1
REM # includeObject 00
REM # policymaker -if policies/policydupsel-no.txt -of policies/policydupsel-no.bin -pr -v
REM # 5f 55 ba 2b 69 0f b0 38 ac 15 ff 2a 86 ef 65 66 
REM # be a8 23 68 43 97 4c 3f a7 36 37 72 56 ec bc 45 
REM 
REM # 80000000 SK storage primary key
REM # 80000001 NP new parent, the target of the duplication
REM # 80000002 SI signing key, duplicate from SK to NP
REM # 03000000 policy session

echo "Import the new parent storage key NP under the primary key"
%TPM_EXE_PATH%importpem -hp 80000000 -pwdp sto -ipem policies/rsaprivkey.pem -st -pwdk rrrr -opu tmpstpub.bin -opr tmpstpriv.bin -halg sha256 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
	
echo "Load the new parent TPM storage key NP at 80000001"
%TPM_EXE_PATH%load -hp 80000000 -pwdp sto -ipu tmpstpub.bin -ipr tmpstpriv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Import a signing key SI under the primary key 80000000, with policy duplication select"
%TPM_EXE_PATH%importpem -hp 80000000 -pwdp sto -ipem policies/rsaprivkey.pem -si -pwdk rrrr -opr tmpsipriv.bin -opu tmpsipub.bin -pol policies/policydupsel-no.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key SI at 80000002"
%TPM_EXE_PATH%load -hp 80000000 -pwdp sto -ipu tmpsipub.bin -ipr tmpsipriv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest"
%TPM_EXE_PATH%sign -hk 80000002 -halg sha256 -if policies/aaa -os tmpsig.bin -pwdk rrrr > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature"
%TPM_EXE_PATH%verifysignature -hk 80000002 -halg sha256 -if policies/aaa -is tmpsig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session 03000000"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy duplication select, object SI 80000002 to new parent NP 80000001"
%TPM_EXE_PATH%policyduplicationselect -ha 03000000 -inpn h80000001.bin -ion h80000002.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest, should be 5f 55 ba 2b ...."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Duplicate signing key SI at 80000002 under new parent TPM storage key NP 80000001"
%TPM_EXE_PATH%duplicate -ho 80000002 -hp 80000001 -od tmpdup.bin -oss tmpss.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the original SI at 80000002 to free object slot for import"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Import signing key SI under new parent TPM storage key NP 80000001"
%TPM_EXE_PATH%import -hp 80000001 -pwdp rrrr -ipu tmpsipub.bin -id tmpdup.bin -iss tmpss.bin -opr tmpsipriv1.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key SI at 80000002"
%TPM_EXE_PATH%load -hp 80000001 -pwdp rrrr -ipu tmpsipub.bin -ipr tmpsipriv1.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest"
%TPM_EXE_PATH%sign -hk 80000002 -halg sha256 -if policies/aaa -os tmpsig.bin -pwdk rrrr > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature"
%TPM_EXE_PATH%verifysignature -hk 80000002 -halg sha256 -if policies/aaa -is tmpsig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the duplicated SI at 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Duplication Select with includeObject TRUE"
echo ""

REM # command code 00000188
REM # SI objectName
REM # 000b 6319 28da 1624 3135 3a59 c03a 2ca7
REM # dbb7 0989 1440 4236 3c7f a838 39d9 da6c
REM # 437a
REM # HP newParentName
REM # 000b 
REM # 1a5d f667 7533 4527 37bc 79a5 5ab6 d9fa 
REM # 9174 5c03 3dfe 3f82 cdf0 903b a9d6 55f1
REM # includeObject 01
REM
REM # policymaker -if policies/policydupsel-yes.txt -of policies/policydupsel-yes.bin -pr -v
REM # 14 64 06 4c 80 cb e3 4f f5 03 82 15 38 62 43 17 
REM # 93 94 8f f1 e8 8a c6 23 4d d1 b0 c5 4c 05 f7 3b 
REM 
REM # 80000000 SK storage primary key
REM # 80000001 NP new parent, the target of the duplication
REM # 80000002 SI signing key, duplicate from SK to NP
REM # 03000000 policy session

echo "Import a signing key SI under the primary key 80000000, with policy authorize"
%TPM_EXE_PATH%importpem -hp 80000000 -pwdp sto -ipem policies/rsaprivkey.pem -si -pwdk rrrr -opr tmpsipriv.bin -opu tmpsipub.bin -pol policies/policyauthorizesha256.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key SI  with objectName 000b 6319 28da at 80000002"
%TPM_EXE_PATH%load -hp 80000000 -pwdp sto -ipu tmpsipub.bin -ipr tmpsipriv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest"
%TPM_EXE_PATH%sign -hk 80000002 -halg sha256 -if policies/aaa -os tmpsig.bin -pwdk rrrr > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature"
%TPM_EXE_PATH%verifysignature -hk 80000002 -halg sha256 -if policies/aaa -is tmpsig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session 03000000"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy duplication select, object SI 80000002 to new parent NP 80000001 with includeObject"
%TPM_EXE_PATH%policyduplicationselect -ha 03000000 -inpn h80000001.bin -ion h80000002.bin -io > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest,should be policy to approve, aHash input 14 64 06 4c same as policies/policydupsel-yes.bin"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the original SI at 80000002 to free object slot for loadexternal "
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Openssl generate and sign aHash (empty policyRef)"
openssl dgst -sha256 -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policies/policydupsel-yes.bin

echo "Load external just the public part of PEM authorizing key 80000002"
%TPM_EXE_PATH%loadexternal -hi p -halg sha256 -nalg sha256 -ipem policies/rsapubkey.pem > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature against 80000002 to generate ticket"
%TPM_EXE_PATH%verifysignature -hk 80000002 -halg sha256 -if policies/policydupsel-yes.bin -is pssig.bin -raw -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy authorize using the ticket"
%TPM_EXE_PATH%policyauthorize -ha 03000000 -appr policies/policydupsel-yes.bin -skn h80000002.bin -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the PEM authorizing verification key at 80000002 to free object slot for import"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the original signing key SI at 80000002"
%TPM_EXE_PATH%load -hp 80000000 -pwdp sto -ipu tmpsipub.bin -ipr tmpsipriv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Duplicate signing key SI at 80000002 under new parent TPM storage key NP 80000001 000b 1a5d f667"
%TPM_EXE_PATH%duplicate -ho 80000002 -hp 80000001 -od tmpdup.bin -oss tmpss.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the original SI at 80000002 to free object slot for import"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Import signing key SI under new parent TPM storage key NP 80000001"
%TPM_EXE_PATH%import -hp 80000001 -pwdp rrrr -ipu tmpsipub.bin -id tmpdup.bin -iss tmpss.bin -opr tmpsipriv1.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key SI at 80000002"
%TPM_EXE_PATH%load -hp 80000001 -pwdp rrrr -ipu tmpsipub.bin -ipr tmpsipriv1.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest"
%TPM_EXE_PATH%sign -hk 80000002 -halg sha256 -if policies/aaa -os tmpsig.bin -pwdk rrrr > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature"
%TPM_EXE_PATH%verifysignature -hk 80000002 -halg sha256 -if policies/aaa -is tmpsig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the duplicated SI at 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the new parent TPM storage key NP 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Name Hash"
echo ""

REM # signing key SI Name
REM # 000b 
REM # 6319 28da 1624 3135 3a59 c03a 2ca7 dbb7 
REM # 0989 1440 4236 3c7f a838 39d9 da6c 437a 
REM 
REM # compute nameHash
REM 
REM # nameHash - just a hash, not an extend
REM # policymaker -if policies/pnhnamehash.txt -of policies/pnhnamehash.bin -nz -pr -v -ns
REM # 18 e0 0c 62 77 18 d9 fc 81 22 3d 8a 56 33 7e eb 
REM # 0e 7d 98 28 bd 7b c7 29 1d 3c 27 3f 7a c4 04 f1 
REM # 18e00c627718d9fc81223d8a56337eeb0e7d9828bd7bc7291d3c273f7ac404f1
REM 
REM # compute policy (based on 
REM 
REM # 00000170 TPM_CC_PolicyNameHash
REM # signing key SI Name
REM # 18e00c627718d9fc81223d8a56337eeb0e7d9828bd7bc7291d3c273f7ac404f1
REM 
REM # policymaker -if policies/policynamehash.txt -of policies/policynamehash.bin -pr -v
REM # 96 30 f9 00 c3 4c 66 09 c1 c5 92 41 78 c1 b2 3d 
REM # 9f d4 93 f4 f9 c2 98 c8 30 4a e3 0f 97 a2 fd 49 
REM 
REM # 80000000 SK storage primary key
REM # 80000001 SI signing key
REM # 80000002 Authorizing public key
REM # 03000000 policy session

echo "Import a signing key SI under the primary key 80000000, with policy authorize"
%TPM_EXE_PATH%importpem -hp 80000000 -pwdp sto -ipem policies/rsaprivkey.pem -si -pwdk rrrr -opr tmpsipriv.bin -opu tmpsipub.bin -pol policies/policyauthorizesha256.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key SI at 80000001"
%TPM_EXE_PATH%load -hp 80000000 -pwdp sto -ipu tmpsipub.bin -ipr tmpsipriv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest using the password"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if policies/aaa -os tmpsig.bin -pwdk rrrr > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature"
%TPM_EXE_PATH%verifysignature -hk 80000001 -halg sha256 -if policies/aaa -is tmpsig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session 03000000"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy name hash, object SI 80000001"
%TPM_EXE_PATH%policynamehash -ha 03000000 -nh policies/pnhnamehash.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest, should be policy to approve, 96 30 f9 00"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Openssl generate and sign aHash (empty policyRef)"
openssl dgst -sha256 -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policies/policynamehash.bin

echo "Load external just the public part of PEM authorizing key 80000002"
%TPM_EXE_PATH%loadexternal -hi p -halg sha256 -nalg sha256 -ipem policies/rsapubkey.pem > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature against 80000002 to generate ticket"
%TPM_EXE_PATH%verifysignature -hk 80000002 -halg sha256 -if policies/policynamehash.bin -is pssig.bin -raw -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy authorize using the ticket"
%TPM_EXE_PATH%policyauthorize -ha 03000000 -appr policies/policynamehash.bin -skn h80000002.bin -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest, should be eb a3 f9 8c ...."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest using the policy"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if policies/aaa -os tmpsig.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature"
%TPM_EXE_PATH%verifysignature -hk 80000001 -halg sha256 -if policies/aaa -is tmpsig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key at 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the authorizing key 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # test using clockrateadjust and platform policy

REM # operand A time is 64 bits at offset 0, operation GT (2)
REM # 0000016d 0000 0000 0000 0000 | 0000 | 0002
REM # 
REM # convert to binary policy
REM # > policymaker -halg sha1 -if policies/policycountertimer.txt -of policies/policycountertimer.bin -pr -v
REM # e6 84 81 27 55 c0 39 d3 68 63 21 c8 93 50 25 dd 
REM # aa 26 42 9a 

echo ""
echo "Policy Counter Timer"
echo ""

echo "Set the platform policy to policy "
%TPM_EXE_PATH%setprimarypolicy -hi p -pol policies/policycountertimer.bin -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clockrate adjust using wrong password - should fail"
%TPM_EXE_PATH%clockrateadjust -hi p -pwdp ppp -adj 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clockrate adjust, policy not satisfied - should fail"
%TPM_EXE_PATH%clockrateadjust -hi p -adj 0 -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy counter timer, zero operandB, op EQ satisfy policy - should fail"
%TPM_EXE_PATH%policycountertimer -ha 03000000 -if policies/zero8.bin -op 0 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)
 
echo "Policy counter timer, zero operandB, op GT satisfy policy"
%TPM_EXE_PATH%policycountertimer -ha 03000000 -if policies/zero8.bin -op 2 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
 
echo "Policy get digest, should be e6 84 81 27"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clockrate adjust, policy satisfied"
%TPM_EXE_PATH%clockrateadjust -hi p -adj 0 -se0 03000000 1 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clear the platform policy"
%TPM_EXE_PATH%setprimarypolicy -hi p > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # policyccsign.txt  0000016c 0000015d (policy command code | sign)
REM # policyccquote.txt 0000016c 00000158 (policy command code | quote)
REM #
REM # > policymaker -if policies/policyccsign.txt -of policies/policyccsign.bin -pr -v
REM # cc6918b226273b08f5bd406d7f10cf160f0a7d13dfd83b7770ccbcd1aa80d811
REM #
REM # > policymaker -if policies/policyccquote.txt -of policies/policyccquote.bin -pr -v
REM # a039cad5fe68870688f8233c3e3ee3cf27aac9e2efe3486aeb4e304c0e90cd27
REM #
REM # policyor.txt is CC_PolicyOR || digests
REM # 00000171 | cc69 ... | a039 ...
REM # > policymaker -if policies/policyor.txt -of policies/policyor.bin -pr -v
REM # 6b fe c2 3a be 57 b0 2a ce 39 dd 13 bb 60 fa 39 
REM # 4d ac 7b 38 96 56 57 84 b3 73 fc 61 92 94 29 db 

echo ""
echo "PolicyOR"
echo ""

echo "Create an unrestricted signing key, policy command code sign or quote"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyor.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Quote - should fail"
%TPM_EXE_PATH%quote -hp 0 -hk 80000001 -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Get time - should fail, policy not set"
%TPM_EXE_PATH%gettime -hk 80000001 -qd policies/aaa -se1 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy OR - should fail"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy Command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 0000015d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest, should be cc 69 18 b2"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest, should be 6b fe c2 3a"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign with policy OR"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 0000015d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Quote - should fail, wrong command code"
%TPM_EXE_PATH%quote -hp 0 -hk 80000001 -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Command code - quote, digest a0 39 ca d5"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 00000158 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR, digest 6b fe c2 3a"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Quote with policy OR"
%TPM_EXE_PATH%quote -hp 0 -hk 80000001 -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Command code - gettime 7a 3e bd aa"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 0000014c > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy OR, gettime not an AND term - should fail"
%TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyccsign.bin -if policies/policyccquote.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # There are times that a policy creator has TPM, PEM, or DER format
REM # information, but does not have access to a TPM.  The publicname
REM # utility accepts these inputs and outputs the name in the 'no spaces'
REM # format suitable for pasting into a policy.

echo ""
echo "publicname RSA"
echo ""

for %%H in (%ITERATE_ALGS%) do (

    echo "Create an rsa %%H key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -rsa 2048 -nalg %%H -si -opr tmppriv.bin -opu tmppub.bin -pwdp sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Load the rsa %%H key 80000001"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Compute the TPM2B_PUBLIC Name"
    %TPM_EXE_PATH%publicname -ipu tmppub.bin -on tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the TPM2B_PUBLIC result"
    diff tmp.bin h80000001.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Convert the rsa public key to PEM format"
    %TPM_EXE_PATH%readpublic -ho 80000001 -opem tmppub.pem > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the rsa %%H key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "loadexternal the rsa PEM public key"
    %TPM_EXE_PATH%loadexternal -ipem tmppub.pem -si -rsa -nalg %%H -halg %%H -scheme rsassa > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Compute the PEM Name"
    %TPM_EXE_PATH%publicname -ipem tmppub.pem -rsa -si -nalg %%H -halg %%H -on tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the PEM result"
    diff tmp.bin h80000001.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Convert the TPM PEM key to DER"
    openssl pkey -inform pem -outform der -in tmppub.pem -out tmppub.der -pubin
    echo "INFO:"

    echo "Compute the DER Name"
    %TPM_EXE_PATH%publicname -ider tmppub.der -rsa -si -nalg %%H -halg %%H -on tmp.bin -v > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the DER result"
    diff tmp.bin h80000001.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the rsa %%H key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

echo ""
echo "publicname ECC"
echo ""

for %%H in (%ITERATE_ALGS%) do (

    echo "Create an ecc nistp256 %%H key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -ecc nistp256 -nalg %%H -si -opr tmppriv.bin -opu tmppub.bin -pwdp sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Load the ecc %%H key 80000001"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Compute the TPM2B_PUBLIC Name"
    %TPM_EXE_PATH%publicname -ipu tmppub.bin -on tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the TPM2B_PUBLIC result"
    diff tmp.bin h80000001.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Convert the ecc public key to PEM format"
    %TPM_EXE_PATH%readpublic -ho 80000001 -opem tmppub.pem > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the ecc %%H key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "loadexternal the ecc PEM public key"
    %TPM_EXE_PATH%loadexternal -ipem tmppub.pem -si -ecc -nalg %%H -halg %%H > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Compute the PEM Name"
    %TPM_EXE_PATH%publicname -ipem tmppub.pem -ecc -si -nalg %%H -halg %%H -on tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the PEM result"
    diff tmp.bin h80000001.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Convert the TPM PEM key to DER"
    openssl pkey -inform pem -outform der -in tmppub.pem -out tmppub.der -pubin -pubout
    echo "INFO:"

    echo "Compute the DER Name"
    %TPM_EXE_PATH%publicname -ider tmppub.der -ecc -si -nalg %%H -halg %%H -on tmp.bin -v > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the DER result"
    diff tmp.bin h80000001.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the ecc %%H key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

echo ""
echo "publicname NV"
echo ""

for %%H in (%ITERATE_ALGS%) do (

    echo "NV Define Space %%H"
    %TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -sz 16 -nalg %%H > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "NV Read Public"
    %TPM_EXE_PATH%nvreadpublic -ha 01000000 -opu tmppub.bin -on tmpname.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Compute the NV Index Name"
    %TPM_EXE_PATH%publicname -invpu tmppub.bin -on tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the NV Index result"
    diff tmp.bin tmpname.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "NV Undefine Space"
    %TPM_EXE_PATH%nvundefinespace -hi o -ha 01000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

rm pssig.bin
rm run.out
rm sig.bin
rm tkt.bin
rm tmp.bin
rm tmpdup.bin
rm tmphkey.bin
rm tmpname.bin
rm tmppol.bin
rm tmppriv.bin
rm tmppub.bin
rm tmppub.der
rm tmppub.pem
rm tmpsig.bin
rm tmpsipriv.bin
rm tmpsipriv1.bin
rm tmpsipub.bin
rm tmpss.bin
rm tmpstpriv.bin
rm tmpstpub.bin

exit /B 0

REM # getcapability -cap 1 -pr 80000000
REM # getcapability -cap 1 -pr 01000000
REM # getcapability -cap 1 -pr 02000000
REM # getcapability -cap 1 -pr 03000000
