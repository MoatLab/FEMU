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

echo ""
echo "Seal and Unseal to Password"
echo ""

echo "Create a sealed data object"
%TPM_EXE_PATH%create -hp 80000000 -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the sealed data object"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Unseal the data blob"
%TPM_EXE_PATH%unseal -ha 80000001 -pwd sea -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the unsealed result"
diff msg.bin tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Unseal with bad password - should fail"
%TPM_EXE_PATH%unseal -ha 80000001 -pwd xxx > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Flush the sealed object"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Create a primary sealed data object"
%TPM_EXE_PATH%createprimary -bl -kt f -kt p -pwdk seap -if msg.bin  > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Unseal the primary data blob"
%TPM_EXE_PATH%unseal -ha 80000001 -pwd seap -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Verify the unsealed result"
diff msg.bin tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the primary sealed object"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo ""
echo "Seal and Unseal to PolicySecret Platform Auth"
echo ""

REM # policy is policy secret pointing to platform auth
REM # 000001514000000C plus newline for policyRef

echo "Change platform hierarchy auth"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Create a sealed data object with policysecret platform auth under primary key"
%TPM_EXE_PATH%create -hp 80000000 -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policysecretp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Load the sealed data object under primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Unseal the data blob - policy failure, policysecret not run"
%TPM_EXE_PATH%unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Policy Secret with PWAP session and platform auth"
%TPM_EXE_PATH%policysecret -ha 4000000c -hs 03000000 -pwde ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Unseal the data blob"
%TPM_EXE_PATH%unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Verify the unsealed result"
diff msg.bin tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Change platform hierarchy auth back to null"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwda ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the sealed object"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the policy session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

REM # extend of aaa + 0 pad to digest length
REM # pcrreset -ha 16
REM # pcrextend -ha 16 -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ic aaa
REM # pcrread   -ha 16 -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ns
REM #
REM # 1d47f68aced515f7797371b554e32d47981aa0a0
REM # c2119764d11613bf07b7e204c35f93732b4ae336b4354ebc16e8d0c3963ebebb
REM # 292963e31c34c272bdea27154094af9250ad97d9e7446b836d3a737c90ca47df2c399021cedd00853ef08497c5a42384
REM # 7fe1e4cf015293136bf130183039b6a646ea008b75afd0f8466a9bfe531af8ada867a65828cfce486077529e54f1830aa49ab780562baea49c67a87334ffe778
REM #
REM # paste that with no white space to file policypcr16aaasha1.txt, etc.
REM #
REM # create AND term for policy PCR, PCR 16
REM # and then convert to binary policy
REM 
REM # > policymakerpcr -halg sha1   -bm 10000 -if policies/policypcr16aaasha1.txt   -v -pr -of policies/policypcr.txt
REM # 0000017f00000001000403000001cbf1e9f771d215a017e17979cfd7184f4b674a4d
REM # convert to binary policy
REM # > policymaker -halg sha1   -if policies/policypcr.txt -of policies/policypcr16aaasha1.bin -pr -v
REM # 12 b6 dd 16 43 82 ca e4 5d 0e d0 7f 9e 51 d1 63 
REM # a4 24 f5 f2 
REM 
REM # > policymakerpcr -halg sha256 -bm 10000 -if policies/policypcr16aaasha256.txt -v -pr -of policies/policypcr.txt
REM # 0000017f00000001000b030000012c28901f71751debfba3f3b5bf3be9c54b8b2f8c1411f2c117a0e838ee4e6c13
REM # > policymaker -halg sha256 -if policies/policypcr.txt -of policies/policypcr16aaasha256.bin -pr -v
REM # 76 44 f6 11 ea 10 d7 60 da b9 36 c3 95 1e 1d 85 
REM # ec db 84 ce 9a 79 03 dd e1 c7 e0 a2 d9 09 a0 13 
REM 
REM # > policymakerpcr -halg sha384 -bm 10000 -if policies/policypcr16aaasha384.txt -v -pr -of policies/policypcr.txt
REM # 0000017f00000001000c0300000132edb1c501cb0af4f958c9d7f04a8f3122c1025067e3832a5137234ee0d875e9fa99d8d400ca4a37fe13a6f53aeb4932
REM # > policymaker -halg sha384 -if policies/policypcr.txt -of policies/policypcr16aaasha384.bin -pr -v
REM # ea aa 8b 90 d2 69 b6 31 c0 85 91 e4 bf 29 a3 12 
REM # 87 04 f2 18 4c 02 ee 83 6a fb c4 c6 7f 28 c1 7f 
REM # 86 ea 22 b7 00 3d 06 fc b4 57 a3 b5 c4 f7 3c 95 
REM 
REM # > policymakerpcr -halg sha512 -bm 10000 -if policies/policypcr16aaasha512.txt -v -pr -of policies/policypcr.txt
REM # 0000017f00000001000d03000001ea5218788d9d3a79e6f58608e321880aeb33e2282a3a0a87fb5b8868e7c6b3eedb9b66019409d8ea52d77e0dbfee5822c10ad0de3fd5cc776813a60423a7531f
REM # policymaker -halg sha512 -if policies/policypcr.txt -of policies/policypcr16aaasha512.bin -pr -v
REM # 1a 57 25 8d 99 64 d8 74 f0 85 0f 2c 8d 70 41 cc 
REM # be 21 c2 0f df 7e 07 e6 b1 99 ea 05 66 46 b7 fb 
REM # 23 55 77 4b 96 7e ab e2 65 db 5a 52 82 08 9c af 
REM # 3c c0 10 e4 99 36 5d ec 7f 0d 3e 6d 2a 62 6d 2e 

REM sealed blob    80000001
REM policy session 03000000

echo ""
echo "Seal and Unseal to PCR 16"
echo ""

for %%H in (%ITERATE_ALGS%) do (

    echo "Create a sealed data object %%H"
    %TPM_EXE_PATH%create -hp 80000000 -nalg %%H -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policypcr16aaa%%H.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Load the sealed data object"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Start a policy session %%H"
    %TPM_EXE_PATH%startauthsession -se p -halg %%H > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "PCR 16 Reset"
    %TPM_EXE_PATH%pcrreset -ha 16 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Unseal the data blob - policy failure, policypcr not run"
    %TPM_EXE_PATH%unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! EQU 0 (
        exit /B 1
    )

    echo "Policy PCR, update with the wrong PCR 16 value"
    %TPM_EXE_PATH%policypcr -halg %%H -ha 03000000 -bm 10000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Unseal the data blob - policy failure, PCR 16 incorrect"
    %TPM_EXE_PATH%unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! EQU 0 (
        exit /B 1
    )

    echo "Extend PCR 16 to correct value"
    %TPM_EXE_PATH%pcrextend -halg %%H -ha 16 -if policies/aaa > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy restart, set back to zero"
    %TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy PCR, update with the correct PCR 16 value"
    %TPM_EXE_PATH%policypcr -halg %%H -ha 03000000 -bm 10000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Unseal the data blob"
    %TPM_EXE_PATH%unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the unsealed result"
    diff msg.bin tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the sealed object"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )
    
    echo "Flush the policy session"
    %TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

rem # This test uses the same values for PCR 16 and PCR 23 for simplicity.
rem # For different values, calculate the PCR white list value and change
rem # the cat line to use two different values.

rem # extend of aaa + 0 pad to digest length
rem # pcrreset -ha 16
rem # pcrextend -ha 16 -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ic aaa
rem # pcrread   -ha 16 -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ns
rem #
rem # 1d47f68aced515f7797371b554e32d47981aa0a0
rem # c2119764d11613bf07b7e204c35f93732b4ae336b4354ebc16e8d0c3963ebebb
rem # 292963e31c34c272bdea27154094af9250ad97d9e7446b836d3a737c90ca47df2c399021cedd00853ef08497c5a42384
rem # 7fe1e4cf015293136bf130183039b6a646ea008b75afd0f8466a9bfe531af8ada867a65828cfce486077529e54f1830aa49ab780562baea49c67a87334ffe778
rem #
rem # paste that with no white space to file policypcr16aaasha1.txt, etc.
rem #
rem # create AND term for policy PCR, PCR 16 and 23
rem # and then convert to binary policy

rem # > cat policies/policypcr16aaasha1.txt policies/policypcr16aaasha1.txt >! policypcra.txt
rem # > policymakerpcr -halg sha1   -bm 810000 -if policypcra.txt -v -pr -of policypcr.txt
rem #0000017f0000000100040300008173820c1f0f279933a5a58629fe44d081e740d4ae
rem # > policymaker -halg sha1   -if policypcr.txt -of policies/policypcr1623aaasha1.bin -pr -v
rem  # policy digest length 20
rem  # b4 ed de a3 35 87 d7 43 29 f6 a8 d1 e7 89 92 64 
rem  # 46 f0 4c 85 

rem # > cat policies/policypcr16aaasha256.txt policies/policypcr16aaasha256.txt >! policypcra.txt
rem # > policymakerpcr -halg sha256   -bm 810000 -if policypcra.txt -v -pr -of policypcr.txt
rem # 0000017f00000001000b030000815a9f104273886b7ec8919a449d440d107d0da5df367e28c6ac145c9023cb5e76
rem # > policymaker -halg sha256   -if policypcr.txt -of policies/policypcr1623aaasha256.bin -pr -v
rem  # policy digest length 32
rem  # 84 ff 2f f1 2d 37 cb 23 fb 3d 14 d9 66 77 ca ec 
rem  # 48 94 5c 0b 83 e5 ea a2 be 98 e9 75 aa 21 e3 d6 

rem # > cat policies/policypcr16aaasha384.txt policies/policypcr16aaasha384.txt >! policypcra.txt
rem # > policymakerpcr -halg sha384   -bm 810000 -if policypcra.txt -v -pr -of policypcr.txt
rem # 0000017f00000001000c0300008105f7f12c86c3b0ed988d369a96d401bb4a58b74f982eb03e8474cb66076114ba2b933dd95cde1c7ea69d0a797abc99d4
rem # > policymaker -halg sha384   -if policypcr.txt -of policies/policypcr1623aaasha384.bin -pr -v
rem  # policy digest length 48
rem  # 4b 03 cd b3 eb 07 15 14 7c 49 93 43 a5 65 ee dc 
rem  # 86 22 7c 86 36 20 97 a2 5e 0f 34 2e d2 4f 7e ad 
rem  # a0 61 8b 5e d7 ba bb e3 5e f0 ab ea 99 55 df 84 

rem # > cat policies/policypcr16aaasha512.txt policies/policypcr16aaasha512.txt >! policypcra.txt
rem # > policymakerpcr -halg sha512   -bm 810000 -if policypcra.txt -v -pr -of policypcr.txt
rem # 0000017f00000001000d03000081266ae24c92f63b30322e9c22e44e9540313a2223ae79b27eafe798168bef373ac55de22a0ca78ec8b2e9402aa1f8b47b6ef40e9e53aebaa694af58f240efa0fd
rem # > policymaker -halg sha512   -if policypcr.txt -of policies/policypcr1623aaasha512.bin -pr -v
rem  # policy digest length 64
rem  # 13 84 59 76 b8 d4 d8 a9 a4 7d 75 0e 3e 81 cd c2 
rem  # 78 08 ec 95 d7 13 e8 ef 0c 0b 85 c7 38 2e ad 46 
rem  # e4 72 31 1d 11 a3 38 17 54 e5 cf 2e 6d 23 67 6d 
rem  # 39 5a 93 51 9d f3 f0 90 56 4d 66 f8 7b 90 fc 61 

rem # sealed blob    80000001
rem # policy session 03000000

echo ""
echo "Seal and Unseal to PCR 16 and 23"
echo ""

for %%H in (%ITERATE_ALGS%) do (

    echo "Create a sealed data object %%H"
    %TPM_EXE_PATH%create -hp 80000000 -nalg %%H -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policypcr1623aaa%%H.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Load the sealed data object"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Start a policy session %%H"
    %TPM_EXE_PATH%startauthsession -se p -halg %%H > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "PCR 16 Reset"
    %TPM_EXE_PATH%pcrreset -ha 16 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "PCR 23 Reset"
    %TPM_EXE_PATH%pcrreset -ha 23 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Extend PCR 16 to correct value"
    %TPM_EXE_PATH%pcrextend -halg %%H -ha 16 -if policies/aaa > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Extend PCR 23 to correct value"
    %TPM_EXE_PATH%pcrextend -halg %%H -ha 23 -if policies/aaa > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy PCR, update with the correct PCR 16 and 23 values"
    %TPM_EXE_PATH%policypcr -halg %%H -ha 03000000 -bm 810000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Unseal the data blob"
    %TPM_EXE_PATH%unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the unsealed result"
    diff msg.bin tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the sealed object"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the policy session"
    %TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )
)


REM #
REM # Sample application to demonstrate the policy authorize solution to
REM # the PCR brittleness problem when sealing.  Rather than sealing
REM # directly to the PCRs, the blob is sealed to an authorizing public
REM # key.  The authorizing private key signs the approved policy PCR
REM # digest.
REM #
REM # Name for 80000001 authorizing key (output of loadexternal below) is
REM # used to calculate the policy authorize policy
REM #
REM # 00044234c24fc1b9de6693a62453417d2734d7538f6f
REM # 000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
REM # 000ca8bfb42e75b4c22b366b372cd9994bafe8558aa182cf12c258406d197dab63ac46f5a5255b1deb2993a4e9fc92b1e26c
REM # 000d0c36b2a951eccc7e3e12d03175a71304dc747f222a02af8fa2ac8b594ef973518d20b9a5452d0849e325710f587d8a55082e7ae321173619bc12122f3ad71466
REM #
REM # Use 0000016a || the above Name, with a following blank line for
REM # policyRef to make policies/policyauthorizesha[].txt. Use policymaker
REM # to create the binary policy.  This will be the session digest after
REM # the policyauthorize command.
REM #
REM # > policymaker -halg sha[] -if policies/policyauthorizesha[].txt -of policies/policyauthorizesha[].bin -pr
REM # 16 82 10 58 c0 32 8c c4 e5 2e c4 ec ce 61 6c 0a 
REM # f4 8a 30 88 
REM #
REM # eb a3 f9 8c 5e af 1e a8 f9 4f 51 9b 4d 2a 31 83 
REM # ee 79 87 66 72 39 8e 23 15 d9 33 c2 88 a8 e5 03 
REM #
REM # 5c c6 34 89 fe f9 c8 42 7e fe 2c 5f 08 39 74 b6 
REM # d9 a8 36 02 4a cd d9 70 7e f0 b9 fd 15 26 56 da 
REM # a5 07 0a 9b bf d6 66 df 49 d2 5b 8d 50 8e 16 38 
REM #
REM # c9 c8 29 fb bc 75 54 99 db 48 b7 26 88 24 d1 f8 
REM # 29 72 01 60 6b d6 5f 41 8e 06 98 7e f7 3e 6a 7e 
REM # 25 82 c7 6d 8f 1c 36 43 68 01 ee 56 51 d5 06 b4 
REM # 68 4c fe d1 d0 6a d7 65 23 3f c2 92 94 fd 2c c5 

REM # setup and policy PCR calculations
REM #
REM # 16 is the debug PCR, a typical application may seal to PCR 0-7
REM # > pcrreset -ha 16
REM #
REM # policies/aaa represents the new 'BIOS' measurement hash extended
REM # into all PCR banks
REM #
REM # > pcrextend -ha 16 -halg [] -if policies/aaa
REM #
REM # These are the new PCR values to be authorized.  Typically, these are
REM # calculated by other software based on the enterprise.  Here, they're
REM # just read from the TPM.
REM #
REM # > pcrread -ha 16 -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ns
REM #
REM # 1d47f68aced515f7797371b554e32d47981aa0a0
REM # c2119764d11613bf07b7e204c35f93732b4ae336b4354ebc16e8d0c3963ebebb
REM # 292963e31c34c272bdea27154094af9250ad97d9e7446b836d3a737c90ca47df2c399021cedd00853ef08497c5a42384
REM # 7fe1e4cf015293136bf130183039b6a646ea008b75afd0f8466a9bfe531af8ada867a65828cfce486077529e54f1830aa49ab780562baea49c67a87334ffe778
REM #
REM # Put the above authorized PCR value in an intermediate file
REM # policies/policypcr16aaasha1.txt for policymakerpcr, and create the
REM # policypcr AND term policies/policypcr.txt.  policymakerpcr prepends the command code and
REM # PCR select bit mask.
REM #
REM # > policymakerpcr -halg sha[] -bm 010000 -if policies/policypcr16aaasha1.txt -of policies/policypcr.txt -pr -v
REM #
REM # 0000017f00000001000403000001cbf1e9f771d215a017e17979cfd7184f4b674a4d
REM # 0000017f00000001000b030000012c28901f71751debfba3f3b5bf3be9c54b8b2f8c1411f2c117a0e838ee4e6c13
REM # 0000017f00000001000c0300000132edb1c501cb0af4f958c9d7f04a8f3122c1025067e3832a5137234ee0d875e9fa99d8d400ca4a37fe13a6f53aeb4932
REM # 0000017f00000001000d03000001ea5218788d9d3a79e6f58608e321880aeb33e2282a3a0a87fb5b8868e7c6b3eedb9b66019409d8ea52d77e0dbfee5822c10ad0de3fd5cc776813a60423a7531f
REM #
REM # Send the policymakerpcr AND term result to policymaker to create the
REM # Policy PCR digest.  This is the authorized policy signed by the
REM # authorizing private key.
REM #
REM # > policymaker -halg sha[] -if policies/policypcr.txt -of policies/policypcr16aaasha[].bin -v -pr -ns
REM #
REM # 12b6dd164382cae45d0ed07f9e51d163a424f5f2
REM # 7644f611ea10d760dab936c3951e1d85ecdb84ce9a7903dde1c7e0a2d909a013
REM # eaaa8b90d269b631c08591e4bf29a3128704f2184c02ee836afbc4c67f28c17f86ea22b7003d06fcb457a3b5c4f73c95
REM # 1a57258d9964d874f0850f2c8d7041ccbe21c20fdf7e07e6b199ea056646b7fb2355774b967eabe265db5a5282089caf3cc010e499365dec7f0d3e6d2a626d2e

echo ""
echo "Policy PCR with Policy Authorize (PCR brittleness solution)"
echo ""

for %%H in (%ITERATE_ALGS%) do (

    REM # One time task, create sealed blob with policy of policyauthorize
    REM # with Name of authorizing key

    echo "Create a sealed data object %%H"
    %TPM_EXE_PATH%create -hp 80000000 -nalg %%H -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -if msg.bin -pol policies/policyauthorize%%H.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    REM # Once per new PCR approved values, authorizing PCRs in policy%%H.bin

    echo "Openssl generate and sign aHash (empty policyRef) %%H"
    openssl dgst -%%H -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policies/policypcr16aaa%%H.bin

    REM # Once per boot, simulating setting PCRs to authorized values

    echo "Reset PCR 16 back to zero"
    %TPM_EXE_PATH%pcrreset -ha 16 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "PCR extend PCR 16 %%H"
    %TPM_EXE_PATH%pcrextend -ha 16 -halg %%H -if policies/aaa > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    REM # beginning of unseal process, policy PCR

    echo "Start a policy session %%H"
    %TPM_EXE_PATH%startauthsession -halg %%H -se p > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy PCR, update with the correct digest %%H"
    %TPM_EXE_PATH%policypcr -ha 03000000 -halg %%H -bm 10000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy get digest, should be policies/policypcr16aaa%%H.bin"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    REM # policyauthorize process

    echo "Load external just the public part of PEM authorizing key %%H 80000001"
    %TPM_EXE_PATH%loadexternal -hi p -halg %%H -nalg %%H -ipem policies/rsapubkey.pem -ns > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the signature to generate ticket 80000001 %%H"
    %TPM_EXE_PATH%verifysignature -hk 80000001 -halg %%H -if policies/policypcr16aaa%%H.bin -is pssig.bin -raw -tk tkt.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Policy authorize using the ticket"
    %TPM_EXE_PATH%policyauthorize -ha 03000000 -appr policies/policypcr16aaa%%H.bin -skn h80000001.bin -tk tkt.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Get policy digest, should be policies/policyauthorize%%H.bin"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the verification public key 80000001"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    REM # load the sealed blob and unseal

    echo "Load the sealed data object 80000001"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Unseal the data blob using the policy session"
    %TPM_EXE_PATH%unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the unsealed result"
    diff msg.bin tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the sealed object"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the policy session"
    %TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

)

echo ""
echo "Import and Unseal"
echo ""

REM # primary key P1 80000000
REM # sealed data S1 80000001 originally under 80000000
REM # target storage key K1 80000002

for %%A in ("rsa2048" "ecc") do (

    echo "Create a sealed data object S1 under the primary key P1 80000000"
    %TPM_EXE_PATH%create -hp 80000000 -bl -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policyccduplicate.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Load the sealed data object S1 at 80000001"
    %TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Load the %%~A storage key K1 80000002"
    %TPM_EXE_PATH%load -hp 80000000 -ipr store%%~Apriv.bin -ipu store%%~Apub.bin -pwdp sto > run.out
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

    echo "Get policy digest"
    %TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out 
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Duplicate sealed data object S1 80000001 under %%~A K1 80000002"
    %TPM_EXE_PATH%duplicate -ho 80000001 -pwdo sig -hp 80000002 -od tmpdup.bin -oss tmpss.bin -se0 03000000 1 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the original S1 to free object slot for import"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Import S1 under %%~A K1 80000002"
    %TPM_EXE_PATH%import -hp 80000002 -pwdp sto -ipu tmppub.bin -id tmpdup.bin -iss tmpss.bin -opr tmppriv1.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Load the duplicated sealed data object S1 at 80000001 under %%~A K1 80000002"
    %TPM_EXE_PATH%load -hp 80000002 -ipr tmppriv1.bin -ipu tmppub.bin -pwdp sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Unseal the data blob"
    %TPM_EXE_PATH%unseal -ha 80000001 -pwd sea -of tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Verify the unsealed result"
    diff msg.bin tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the sealed data object at 80000001"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Flush the storage key at 80000002"
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

rm tmppriv.bin
rm tmppub.bin
rm tmp.bin
rm tmpdup.bin
rm tmpss.bin
rm tmppriv1.bin

exit /B 0

REM getcapability -cap 1 -pr 80000000
