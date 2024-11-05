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
REM 
REM # primary key 80000000
REM # storage key 80000001
REM # signing key 80000002test
REM # policy session 03000000
REM # e5 87 c1 1a b5 0f 9d 87 30 f7 21 e3 fe a4 2b 46 
REM # c0 45 5b 24 6f 96 ae e8 5d 18 eb 3b e6 4d 66 6a 

setlocal enableDelayedExpansion

echo ""
echo "Credential"
echo ""

echo "Use a random number as the credential input"
%TPM_EXE_PATH%getrandom -by 32 -of tmpcredin.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the storage key under the primary key, 80000001"
%TPM_EXE_PATH%load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a restricted signing key under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -sir -kt f -kt p -opr tmprpriv.bin -opu tmprpub.bin -pwdp sto -pwdk sig -pol policies/policyccactivate.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key, 80000002"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmprpriv.bin -ipu tmprpub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Encrypt the credential using makecredential"
%TPM_EXE_PATH%makecredential -ha 80000001 -icred tmpcredin.bin -in h80000002.bin -ocred tmpcredenc.bin -os tmpsecret.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code - activatecredential"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 00000147 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Activate credential"
%TPM_EXE_PATH%activatecredential -ha 80000002 -hk 80000001 -icred tmpcredenc.bin -is tmpsecret.bin -pwdk sto -ocred tmpcreddec.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Check the decrypted result"
diff tmpcredin.bin tmpcreddec.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the storage key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "EK Certificate"
echo ""

echo "Set platform hierarchy auth"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%A in (rsa ecc) do (

    echo "Create an %%A EK certificate"
    %TPM_EXE_PATH%createekcert -alg %%A -cakey cakey.pem -capwd rrrr -pwdp ppp -of tmp.der > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Read the %%A EK certificate"
    %TPM_EXE_PATH%createek -alg %%A -ce > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Read the %%A template - should fail"
    %TPM_EXE_PATH%createek -alg %%A -te > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "Read the %%A nonce - should fail"
    %TPM_EXE_PATH%createek -alg %%A -no > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "CreatePrimary and validate the %%A EK against the EK certificate"
    %TPM_EXE_PATH%createek -alg %%A -cp > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Validate the %%A EK certificate against the root"
    %TPM_EXE_PATH%createek -alg %%A -root certificates/rootcerts.windows.txt > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

echo "Clear platform hierarchy auth"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwda ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo ""
echo "EK Policies using optional policy in NV"
echo ""

REM # Section B.8.2	Computing PolicyA - the standard IWG PolicySecret with endorsement auth
REM # policyiwgek.txt
REM # 000001514000000B
REM # (blank line for policyRef)
REM #
REM # policymaker -if policies/policyiwgek.txt -ns -halg sha256 -of policies/policyiwgeksha256.bin
REM # policymaker -if policies/policyiwgek.txt -ns -halg sha384 -of policies/policyiwgeksha384.bin
REM # policymaker -if policies/policyiwgek.txt -ns -halg sha512 -of policies/policyiwgeksha512.bin
REM 
REM # 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
REM # 8bbf2266537c171cb56e403c4dc1d4b64f432611dc386e6f532050c3278c930e143e8bb1133824ccb431053871c6db53
REM # 1e3b76502c8a1425aa0b7b3fc646a1b0fae063b03b5368f9c4cddecaff0891dd682bac1a85d4d832b781ea451915de5fc5bf0dc4a1917cd42fa041e3f998e0ee
REM 
REM # Section B.8.3	Computing Policy Index Names - attributes 220F1008
REM 
REM # For test, put PolicySecret + platform auth in NV Index.  This is NOT the IWG standard, just for test.
REM 
REM # for prepending the hash algorithm identifier to make the TPMT_HA structure
REM # printf "%b" '\x00\x0b' > policies/sha256.bin
REM # printf "%b" '\x00\x0c' > policies/sha384.bin
REM # printf "%b" '\x00\x0d' > policies/sha512.bin
REM 
REM # policymaker -if policies/policysecretp.txt -halg sha256  -pr -of policies/policysecretpsha256.bin -pr
REM # policymaker -if policies/policysecretp.txt -halg sha384  -pr -of policies/policysecretpsha384.bin -pr
REM # policymaker -if policies/policysecretp.txt -halg sha512  -pr -of policies/policysecretpsha512.bin -pr
REM 
REM # prepend the algorithm identifiers
REM # cat policies/sha256.bin policies/policysecretpsha256.bin >! policies/policysecretpsha256ha.bin
REM # cat policies/sha384.bin policies/policysecretpsha384.bin >! policies/policysecretpsha384ha.bin
REM # cat policies/sha512.bin policies/policysecretpsha512.bin >! policies/policysecretpsha512ha.bin
REM 
REM # NV Index Name calculation
REM

set HALG=sha256 sha384 sha512
set IDX=01c07f01 01c07f02 01c07f03
set SIZ=34 50 66
REM # algorithms from Algorithm Registry
set HBIN=000b 000c 000d
REM # Name from Table 14: Policy Index Names
set NVNAME=000b0c9d717e9c3fe69fda41769450bb145957f8b3610e084dbf65591a5d11ecd83f 000cdb62fca346612c976732ff4e8621fb4e858be82586486504f7d02e621f8d7d61ae32cfc60c4d120609ed6768afcf090c 000d1c47c0bbcbd3cf7d7cae6987d31937c171015dde3b7f0d3c869bca1f7e8a223b9acfadb49b7c9cf14d450f41e9327de34d9291eece2c58ab1dc10e9059cce560
)

set j=0
for %%h in (!HALG!)   do set /A j+=1 & set HALG[!j!]=%%h
set j=0
for %%i in (!IDX!)    do set /A j+=1 & set IDX[!j!]=%%i
set j=0
for %%z in (!SIZ!)    do set /A j+=1 & set SIZ[!j!]=%%z
set j=0
for %%b in (!HBIN!)   do set /A j+=1 & set HBIN[!j!]=%%b
set j=0
for %%n in (!NVNAME!) do set /A j+=1 & set NVNAME[!j!]=%%n
set L=!j!

for /L %%j in (1,1,!L!) do (

    echo "Undefine optional !HALG[%%j]! NV index !IDX[%%j]!"
    %TPM_EXE_PATH%nvundefinespace -ha !IDX[%%j]! -hi o > run.out 

    echo "Define optional !HALG[%%j]! NV index !IDX[%%j]! size !SIZ[%%j]! with PolicySecret for TPM_RH_ENDORSEMENT"
    %TPM_EXE_PATH%nvdefinespace -ha !IDX[%%j]! -nalg !HALG[%%j]! -hi o -pol policies/policyiwgek!HALG[%%j]!.bin -sz !SIZ[%%j]! +at wa +at or +at ppr +at ar -at aw > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Start a !HALG[%%j]! policy session"
    %TPM_EXE_PATH%startauthsession -se p -halg !HALG[%%j]! > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Satisfy the policy"
    %TPM_EXE_PATH%policysecret -hs 03000000 -ha 4000000B > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the session digest for debug"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Write the !HALG[%%j]! index !IDX[%%j]! to set the written bit before reading the Name"
    %TPM_EXE_PATH%nvwrite -ha !IDX[%%j]! -if policies/policysecretp!HALG[%%j]!ha.bin  -se0 03000000 0 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Read the !HALG[%%j]! Name"
    %TPM_EXE_PATH%nvreadpublic -ha !IDX[%%j]! -ns > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the !HALG[%%j]! !HBIN[%%j]! Name"
    grep !HBIN[%%j]! run.out > tmp.txt
    grep -v nvreadpublic tmp.txt > tmpactual.txt
    echo !NVNAME[%%j]! > tmpexpect.txt
    diff -w tmpactual.txt tmpexpect.txt > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

REM # B.8.4	Computing PolicyC - TPM_CC_PolicyAuthorizeNV || nvIndex->Name)
REM 
REM # policyiwgekcsha256.txt 
REM # 00000192000b0c9d717e9c3fe69fda41769450bb145957f8b3610e084dbf65591a5d11ecd83f
REM 
REM # policyiwgekcsha384.txt 
REM # 00000192000cdb62fca346612c976732ff4e8621fb4e858be82586486504f7d02e621f8d7d61ae32cfc60c4d120609ed6768afcf090c
REM 
REM # policyiwgekcsha512.txt 
REM # 00000192000d1c47c0bbcbd3cf7d7cae6987d31937c171015dde3b7f0d3c869bca1f7e8a223b9acfadb49b7c9cf14d450f41e9327de34d9291eece2c58ab1dc10e9059cce560
REM 
REM # policymaker -if policies/policyiwgekcsha256.txt -ns -halg sha256 -pr -of policies/policyiwgekcsha256.bin
REM # 3767e2edd43ff45a3a7e1eaefcef78643dca964632e7aad82c673a30d8633fde
REM 
REM # policymaker -if policies/policyiwgekcsha384.txt -ns -halg sha384 -pr -of policies/policyiwgekcsha384.bin
REM # d6032ce61f2fb3c240eb3cf6a33237ef2b6a16f4293c22b455e261cffd217ad5b4947c2d73e63005eed2dc2b3593d165
REM 
REM # policymaker -if policies/policyiwgekcsha512.txt -ns -halg sha512 -pr -of policies/policyiwgekcsha512.bin
REM # 589ee1e146544716e8deafe6db247b01b81e9f9c7dd16b814aa159138749105fba5388dd1dea702f35240c184933121e2c61b8f50d3ef91393a49a38c3f73fc8
REM 
REM # B.8.5	Computing PolicyB - TPM_CC_PolicyOR || digests
REM 
REM # policyiwgekbsha256.txt
REM # 00000171
REM # 837197674484b3f81a90cc8d46a5d724fd52d76e06520b64f2a1da1b331469aa
REM # 3767e2edd43ff45a3a7e1eaefcef78643dca964632e7aad82c673a30d8633fde
REM # policymaker -if policies/policyiwgekbsha256.txt -halg sha256 -pr -of policies/policyiwgekbsha256.bin
REM  # ca 3d 0a 99 a2 b9 39 06 f7 a3 34 24 14 ef cf b3 
REM  # a3 85 d4 4c d1 fd 45 90 89 d1 9b 50 71 c0 b7 a0 
REM 
REM # policyiwgekbsha384.txt
REM # 00000171
REM # 8bbf2266537c171cb56e403c4dc1d4b64f432611dc386e6f532050c3278c930e143e8bb1133824ccb431053871c6db53
REM # d6032ce61f2fb3c240eb3cf6a33237ef2b6a16f4293c22b455e261cffd217ad5b4947c2d73e63005eed2dc2b3593d165
REM # policymaker -if policies/policyiwgekbsha384.txt -halg sha384 -pr -of policies/policyiwgekbsha384.bin
REM  # b2 6e 7d 28 d1 1a 50 bc 53 d8 82 bc f5 fd 3a 1a 
REM  # 07 41 48 bb 35 d3 b4 e4 cb 1c 0a d9 bd e4 19 ca 
REM  # cb 47 ba 09 69 96 46 15 0f 9f c0 00 f3 f8 0e 12 
REM 
REM # policyiwgekbsha512.txt
REM # 00000171
REM # 1e3b76502c8a1425aa0b7b3fc646a1b0fae063b03b5368f9c4cddecaff0891dd682bac1a85d4d832b781ea451915de5fc5bf0dc4a1917cd42fa041e3f998e0ee
REM # 589ee1e146544716e8deafe6db247b01b81e9f9c7dd16b814aa159138749105fba5388dd1dea702f35240c184933121e2c61b8f50d3ef91393a49a38c3f73fc8
REM # policymaker -if policies/policyiwgekbsha512.txt -halg sha512 -pr -of policies/policyiwgekbsha512.bin
REM  # b8 22 1c a6 9e 85 50 a4 91 4d e3 fa a6 a1 8c 07 
REM  # 2c c0 12 08 07 3a 92 8d 5d 66 d5 9e f7 9e 49 a4 
REM  # 29 c4 1a 6b 26 95 71 d5 7e db 25 fb db 18 38 42 
REM  # 56 08 b4 13 cd 61 6a 5f 6d b5 b6 07 1a f9 9b ea 
 
echo ""
echo "Test the EK policies"
echo ""

REM # Change endorsement and platform hierarchy passwords for testing

echo "Change endorsement hierarchy password"
%TPM_EXE_PATH%hierarchychangeauth -hi e -pwdn eee
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Change platform hierarchy password"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

for /L %%j in (1,1,!L!) do (

    echo "Create an RSA primary key !HALG[%%j]! 80000001"
    %TPM_EXE_PATH%createprimary -si -nalg !HALG[%%j]! -pwdk kkk -pol policies/policyiwgekb!HALG[%%j]!.bin -rsa 2048 > run.out 
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Start a policy session !HALG[%%j]! 03000000"
    %TPM_EXE_PATH%startauthsession -se p -halg !HALG[%%j]! > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Satisfy Policy A - Policy Secret with PWAP session and endorsement hierarchy auth"
    %TPM_EXE_PATH%policysecret -ha 4000000b -hs 03000000 -pwde eee > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the session digest for debug"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy OR !HALG[%%j]!"
    %TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyiwgek!HALG[%%j]!.bin -if policies/policyiwgekc!HALG[%%j]!.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the !HALG[%%j]! session digest for debug"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Sign a digest - policy A"
    %TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy restart !HALG[%%j]! 03000000"
    %TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Satisfy NV Index Policy - Policy Secret with PWAP session and platform hierarchy auth"
    %TPM_EXE_PATH%policysecret -ha 4000000c -hs 03000000 -pwde ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the !HALG[%%j]! session digest for debug"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Satisfy Policy C - Policy Authorize NV"
    %TPM_EXE_PATH%policyauthorizenv -ha !IDX[%%j]! -hs 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the !HALG[%%j]! session digest for debug"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy OR !HALG[%%j]!"
    %TPM_EXE_PATH%policyor -ha 03000000 -if policies/policyiwgek!HALG[%%j]!.bin -if policies/policyiwgekc!HALG[%%j]!.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get the !HALG[%%j]! session digest for debug"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Sign a digest - policy A"
    %TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the policy session !HALG[%%j]! 03000000"
    %TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )
 
    echo "Flush the primary key !HALG[%%j]! 80000001"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

echo ""
echo "Cleanup"
echo ""

echo "Reset endorsement hierarchy password"
%TPM_EXE_PATH%hierarchychangeauth -hi e -pwda eee
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Reset platform hierarchy password"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwda ppp
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

set L=!j!

for /L %%j in (1,1,!L!) do (

    echo "Undefine optional !HALG[%%j]! NV index !IDX[%%j]!"
    %TPM_EXE_PATH%nvundefinespace -ha !IDX[%%j]! -hi o > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

rm run.out
rm sig.bin
rm tmp.der
rm tmpcreddec.bin
rm tmpcredenc.bin
rm tmpcredin.bin
rm tmprpriv.bin
rm tmprpub.bin
rm tmpsecret.bin
rm tmp.txt
rm tmpactual.txt
rm tmpexpect.txt


REM %TPM_EXE_PATH%getcapability -cap 1 -pr 80000000
REM %TPM_EXE_PATH%getcapability -cap 1 -pr 02000000

exit /B 0
