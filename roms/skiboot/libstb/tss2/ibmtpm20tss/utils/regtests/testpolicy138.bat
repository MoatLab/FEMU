REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: testpolicy138.sh 793 2016-11-10 21:27:40Z kgoldman $	#
REM #										#
REM # (c) Copyright IBM Corporation 2016					#
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
REM # Policy command code - sign
REM 
REM # cc69 18b2 2627 3b08 f5bd 406d 7f10 cf16
REM # 0f0a 7d13 dfd8 3b77 70cc bcd1 aa80 d811
REM 
REM # NV index name after written
REM 
REM # 000b 
REM # 5e8e bdf0 4581 9419 070c 7d57 77bf eb61 
REM # ffac 4996 ea4b 6fba de6d a42b 632d 4918   
REM 
REM # Policy Authorize NV with above Name
REM                               
REM # 66 1f a1 02 db cd c2 f6 a0 61 7b 33 a0 ee 6d 95 
REM # ab f6 2c 76 b4 98 b2 91 10 0d 30 91 19 f4 11 fa 
REM 
REM # Policy in NV index 01000000
REM # signing key 80000001 

setlocal enableDelayedExpansion

echo ""
echo "Policy Authorize NV"
echo ""

echo "Start a policy session 03000000"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key, policyauthnv"
%TPM_EXE_PATH%create -hp 80000000 -si -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyauthorizenv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Define Space"
%TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -sz 50 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
    
echo "NV not written, policyauthorizenv - should fail"
%TPM_EXE_PATH%policyauthorizenv -ha 01000000 -hs 03000000 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Write algorithm ID into NV index 01000000"
%TPM_EXE_PATH%nvwrite -ha 01000000 -off 0 -if policies/sha256.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Write policy command code sign into NV index 01000000"
%TPM_EXE_PATH%nvwrite -ha 01000000 -off 2 -if policies/policyccsign.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be cc 69 ..."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Authorize NV against 01000000"
%TPM_EXE_PATH%policyauthorizenv -ha 01000000 -hs 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be 66 1f ..."
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest - policy and wrong password"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk xxx > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code - sign"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 15d > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Authorize NV against 01000000"
%TPM_EXE_PATH%policyauthorizenv -ha 01000000 -hs 03000000 > run.out
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

echo "Policy command code - quote"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 158 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Authorize NV against 01000000 - should fail"
%TPM_EXE_PATH%policyauthorizenv -ha 01000000 -hs 03000000 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "NV Undefine Space"
%TPM_EXE_PATH%nvundefinespace -hi o -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the policy session 03000000"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key 80000001 "
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Template"
echo ""

REM # create template hash
REM 
REM # run createprimary -si -v, extract template 
REM 
REM # policies/policytemplate.txt
REM 
REM # 00 01 00 0b 00 04 04 72 00 00 00 10 00 10 08 00 
REM # 00 00 00 00 00 00
REM 
REM # policymaker -if policies/policytemplate.txt -pr -of policies/policytemplate.bin -nz
REM # -nz says do not extend, just hash the hexascii line
REM # yields a template hash for policytemplate
REM 
REM # ef 64 da 91 18 fc ac 82 f4 36 1b 28 84 28 53 d8 
REM # aa f8 7d fc e1 45 e9 25 cf fe 58 68 aa 2d 22 b6 
REM 
REM # prepend the command code 00000190 to ef 64 ... and construct the actual object policy
REM # policymaker -if policies/policytemplatehash.txt -pr -of policies/policytemplatehash.bin
REM 
REM # fb 94 b1 43 e5 2b 07 95 b7 ec 44 37 79 99 d6 47 
REM # 70 1c ae 4b 14 24 af 5a b8 7e 46 f2 58 af eb de 

echo ""
echo "Policy Template with TPM2_Create"
echo ""

echo "Create a primary storage key policy template, 80000001"
%TPM_EXE_PATH%createprimary -hi p -pol policies/policytemplatehash.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session 03000000"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Template"
%TPM_EXE_PATH%policytemplate -ha 03000000 -te policies/policytemplate.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be fb 94 ... "
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create signing key under primary key"
%TPM_EXE_PATH%create -si -hp 80000001 -kt f -kt p -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Template with TPM2_CreateLoaded"
echo ""

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Template"
%TPM_EXE_PATH%policytemplate -ha 03000000 -te policies/policytemplate.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be fb 94 ... "
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create loaded signing key under primary key"
%TPM_EXE_PATH%createloaded -si -hp 80000001 -kt f -kt p -se0 03000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the primary key 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the created key 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Policy Template with TPM2_CreatePrimary"
echo ""

echo "Set primary policy for platform hierarchy"
%TPM_EXE_PATH%setprimarypolicy -hi p -halg sha256 -pol policies/policytemplatehash.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy restart, set back to zero"
%TPM_EXE_PATH%policyrestart -ha 03000000 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Template"
%TPM_EXE_PATH%policytemplate -ha 03000000 -te policies/policytemplate.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be fb 94 ... "
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create loaded primary signing key policy template, 80000001"
%TPM_EXE_PATH%createprimary -si -hi p -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the primary key 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM #
REM # Use case of the PCR brittleness solution using PolicyAuthorize, but
REM # where the authorizing public key is not hard coded in the sealed
REM # blob policy.  Rather, it's in an NV Index, so that the authorizing
REM # key can be changed.  Here, the authorization to change is platform
REM # auth.  The NV index is locked until reboot as a second level of
REM # protection.
REM #

REM # Policy design

REM # PolicyAuthorizeNV and Name of NV index AND Unseal
REM # where the NV index holds PolicyAuthorize with the Name of the authorizing signing key
REM # where PolicyAuthorize will authorize command Unseal AND PCR values

REM # construct Policies

REM # Provision the NV Index data first.  The NV Index Name is needed for the policy
REM # PolicyAuthorize with the Name of the authorizing signing key.  

REM # The authorizing signing key Name can be obtained using the TPM from
REM # loadexternal below.  It can also be calculated off line using this
REM # utility

REM # > publicname -ipem policies/rsapubkey.pem -halg sha256 -nalg sha256 -v -ns

REM # policyauthorize and CA public key
REM # policies/policyauthorizesha256.txt
REM # 0000016a000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
REM # (need blank line for policyRef)
REM # > policymaker -halg sha256 -if policies/policyauthorizesha256.txt -pr -v -ns -of policies/policyauthorizesha256.bin
REM #  intermediate policy digest length 32
REM #  fc 17 cd 86 c0 4f be ca d7 17 5f ef c7 75 5b 63 
REM #  a8 90 49 12 c3 2e e6 9a 4c 99 1a 7b 5a 59 bd 82 
REM #  intermediate policy digest length 32
REM #  eb a3 f9 8c 5e af 1e a8 f9 4f 51 9b 4d 2a 31 83 
REM #  ee 79 87 66 72 39 8e 23 15 d9 33 c2 88 a8 e5 03 
REM #  policy digest length 32
REM #  eb a3 f9 8c 5e af 1e a8 f9 4f 51 9b 4d 2a 31 83 
REM #  ee 79 87 66 72 39 8e 23 15 d9 33 c2 88 a8 e5 03 
REM # policy digest:
REM # eba3f98c5eaf1ea8f94f519b4d2a3183ee79876672398e2315d933c288a8e503

REM # Once the NV Index Name is known, calculated the sealed blob policy.

REM # PolicyAuthorizeNV and Name of NV Index AND Unseal
REM #
REM # get NV Index Name from nvreadpublic after provisioning
REM # 000b56e16f0b810a6418daab06822be142858beaf9a79d66f66ad7e8e541f142498e
REM #
REM # policies/policyauthorizenv-unseal.txt
REM # 
REM # policyauthorizenv and Name of NV Index
REM # 00000192000b56e16f0b810a6418daab06822be142858beaf9a79d66f66ad7e8e541f142498e
REM # policy command code unseal
REM # 0000016c0000015e
REM #
REM # > policymaker -halg sha256 -if policies/policyauthorizenv-unseal.txt -of policies/policyauthorizenv-unseal.bin -pr -v -ns
REM # intermediate policy digest length 32
REM #  2f 7a d9 b7 53 26 35 e5 03 8c e7 7b 8f 63 5e 4c 
REM #  f9 96 c8 62 18 13 98 94 c2 71 45 e7 7d d5 e8 e8 
REM #  intermediate policy digest length 32
REM #  cd 1b 24 26 fe 10 08 6c 52 35 85 94 22 a0 59 69 
REM #  33 4b 88 47 82 0d 0b d9 8c 43 1f 7f f7 36 34 5d 
REM #  policy digest length 32
REM #  cd 1b 24 26 fe 10 08 6c 52 35 85 94 22 a0 59 69 
REM #  33 4b 88 47 82 0d 0b d9 8c 43 1f 7f f7 36 34 5d 
REM # policy digest:
REM # cd1b2426fe10086c5235859422a05969334b8847820d0bd98c431f7ff736345d

REM # The authorizing signer signs the PCR white list, here just PCR 16 extended with aaa
REM # PCR 16 is the resettable debug PCR, convenient for development

echo ""
echo "PolicyAuthorizeNV -> PolicyAuthorize -> PolicyPCR"
echo ""

REM # Initial provisioning (NV Index)

echo "NV Define Space"
%TPM_EXE_PATH%nvdefinespace -ha 01000000 -hi p -hia p -sz 34 +at wst +at ar > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Write algorithm ID into NV index 01000000"
%TPM_EXE_PATH%nvwrite -ha 01000000 -hia p -off 0 -if policies/sha256.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Write the NV index at offset 2 with policy authorize and the Name of the CA signing key"
%TPM_EXE_PATH%nvwrite -ha 01000000 -hia p -off 2 -if policies/policyauthorizesha256.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Lock the NV Index"
%TPM_EXE_PATH%nvwritelock -ha 01000000 -hia p
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Read the NV Index Name to be used above in Policy"
%TPM_EXE_PATH%nvreadpublic -ha 01000000 -ns > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # Initial provisioning (Sealed Data)

echo "Create a sealed data object"
%TPM_EXE_PATH%create -hp 80000000 -nalg sha256 -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto  -uwa -if msg.bin -pol policies/policyauthorizenv-unseal.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # Once per new PCR approved values, signer authorizing PCRs in policysha256.bin

echo "Openssl generate and sign aHash (empty policyRef)"
openssl dgst -sha256 -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policies/policypcr16aaasha256.bin

REM # Once per boot, simulating setting PCRs to authorized values, lock
REM # the NV index, which is unloaded at reboot to permit platform auth to
REM # roll the authorized signing key

echo "Lock the NV Index"
%TPM_EXE_PATH%nvwritelock -ha 01000000 -hia p
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "PCR 16 Reset"
%TPM_EXE_PATH%pcrreset -ha 16 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Extend PCR 16 to correct value"
%TPM_EXE_PATH%pcrextend -halg sha256 -ha 16 -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # At each unseal, or reuse the ticket tkt.bin for its lifetime

echo "Load external just the public part of PEM authorizing key sha256 80000001"
%TPM_EXE_PATH%loadexternal -hi p -halg sha256 -nalg sha256 -ipem policies/rsapubkey.pem -ns > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature to generate ticket 80000001 sha256"
%TPM_EXE_PATH%verifysignature -hk 80000001 -halg sha256 -if policies/policypcr16aaasha256.bin -is pssig.bin -raw -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # Run time unseal

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p -halg sha256 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy PCR, update with the correct PCR 16 value"
%TPM_EXE_PATH%policypcr -halg sha256 -ha 03000000 -bm 10000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy get digest - should be policies/policypcr16aaasha256.bin"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM # policyauthorize process

echo "Policy authorize using the ticket"
%TPM_EXE_PATH%policyauthorize -ha 03000000 -appr policies/policypcr16aaasha256.bin -skn h80000001.bin -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest, should be policies/policyauthorizesha256.bin"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the authorizing public key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy Authorize NV against NV Index 01000000"
%TPM_EXE_PATH%policyauthorizenv -ha 01000000 -hs 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest, should be policies/policyauthorizenv-unseal.bin intermediate"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code - unseal"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 0000015e > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get policy digest, should be policies/policyauthorizenv-unseal.bin final"
%TPM_EXE_PATH%policygetdigest -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the sealed data object"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
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

echo "NV Undefine Space"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM cleanup 

rm -f tmppriv.bin
rm -f tmppub.bin

