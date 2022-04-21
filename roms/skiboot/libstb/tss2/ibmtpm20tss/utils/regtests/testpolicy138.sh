#!/bin/bash

#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2016 - 2020					#
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

# used for the name in policy ticket

if [ -z $TPM_DATA_DIR ]; then
    TPM_DATA_DIR=.
fi

# PolicyCommandCode - sign

# cc69 18b2 2627 3b08 f5bd 406d 7f10 cf16
# 0f0a 7d13 dfd8 3b77 70cc bcd1 aa80 d811

# NV index name after written

# 000b 
# 5e8e bdf0 4581 9419 070c 7d57 77bf eb61 
# ffac 4996 ea4b 6fba de6d a42b 632d 4918   

# PolicyAuthorizeNV with above Name
                              
# 66 1f a1 02 db cd c2 f6 a0 61 7b 33 a0 ee 6d 95 
# ab f6 2c 76 b4 98 b2 91 10 0d 30 91 19 f4 11 fa 

# Policy in NV index 01000000
# signing key 80000001 

echo ""
echo "Policy Authorize NV"
echo ""

echo "Start a policy session 03000000"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Create a signing key, policyauthnv"
${PREFIX}create -hp 80000000 -si -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -pol policies/policyauthorizenv.bin > run.out
checkSuccess $?

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "NV Define Space"
${PREFIX}nvdefinespace -hi o -ha 01000000 -sz 50 > run.out
checkSuccess $?
    
echo "NV not written, policyauthorizenv - should fail"
${PREFIX}policyauthorizenv -ha 01000000 -hs 03000000 > run.out
checkFailure $?

echo "Write algorithm ID into NV index 01000000"
${PREFIX}nvwrite -ha 01000000 -off 0 -if policies/sha256.bin > run.out
checkSuccess $?

echo "Write policy command code sign into NV index 01000000"
${PREFIX}nvwrite -ha 01000000 -off 2 -if policies/policyccsign.bin > run.out
checkSuccess $?

echo "Policy command code - sign"
${PREFIX}policycommandcode -ha 03000000 -cc 15d > run.out
checkSuccess $?

echo "Policy get digest - should be cc 69 ..."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy Authorize NV against 01000000"
${PREFIX}policyauthorizenv -ha 01000000 -hs 03000000 > run.out
checkSuccess $?

echo "Policy get digest - should be 66 1f ..."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Sign a digest - policy and wrong password"
${PREFIX}sign -hk 80000001 -if msg.bin -os sig.bin -se0 03000000 1 -pwdk xxx > run.out
checkSuccess $?

echo "Policy restart, set back to zero"
${PREFIX}policyrestart -ha 03000000 > run.out 
checkSuccess $?

echo "Policy command code - sign"
${PREFIX}policycommandcode -ha 03000000 -cc 15d > run.out
checkSuccess $?

echo "Policy Authorize NV against 01000000"
${PREFIX}policyauthorizenv -ha 01000000 -hs 03000000 > run.out
checkSuccess $?

echo "Quote - policy, should fail"
${PREFIX}quote -hp 0 -hk 80000001 -os sig.bin -se0 03000000 1 > run.out
checkFailure $?

echo "Policy restart, set back to zero"
${PREFIX}policyrestart -ha 03000000 > run.out 
checkSuccess $?

echo "Policy command code - quote"
${PREFIX}policycommandcode -ha 03000000 -cc 158 > run.out
checkSuccess $?

echo "Policy Authorize NV against 01000000 - should fail"
${PREFIX}policyauthorizenv -ha 01000000 -hs 03000000 > run.out
checkFailure $?

echo "NV Undefine Space"
${PREFIX}nvundefinespace -hi o -ha 01000000 > run.out
checkSuccess $?

echo "Flush the policy session 03000000"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo "Flush the signing key 80000001 "
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Policy Template"
echo ""

# create template hash

# run createprimary -si -v, extract template 

# policies/policytemplate.txt

# 00 01 00 0b 00 04 04 72 00 00 00 10 00 10 08 00 
# 00 00 00 00 00 00

# policymaker -if policies/policytemplate.txt -pr -of policies/policytemplate.bin -nz
# -nz says do not extend, just hash the hexascii line
# yields a template hash for policytemplate

# ef 64 da 91 18 fc ac 82 f4 36 1b 28 84 28 53 d8 
# aa f8 7d fc e1 45 e9 25 cf fe 58 68 aa 2d 22 b6 

# prepend the command code 00000190 to ef 64 ... and construct the actual object policy
# policymaker -if policies/policytemplatehash.txt -pr -of policies/policytemplatehash.bin

# fb 94 b1 43 e5 2b 07 95 b7 ec 44 37 79 99 d6 47 
# 70 1c ae 4b 14 24 af 5a b8 7e 46 f2 58 af eb de 

echo ""
echo "Policy Template with TPM2_Create"
echo ""

echo "Create a primary storage key policy template, 80000001"
${PREFIX}createprimary -hi p -pol policies/policytemplatehash.bin > run.out
checkSuccess $?

echo "Start a policy session 03000000"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy Template"
${PREFIX}policytemplate -ha 03000000 -te policies/policytemplate.bin > run.out
checkSuccess $?

echo "Policy get digest - should be fb 94 ... "
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Create signing key under primary key"
${PREFIX}create -si -hp 80000001 -kt f -kt p -se0 03000000 1 > run.out
checkSuccess $?

echo ""
echo "Policy Template with TPM2_CreateLoaded"
echo ""

echo "Policy restart, set back to zero"
${PREFIX}policyrestart -ha 03000000 > run.out 
checkSuccess $?

echo "Policy Template"
${PREFIX}policytemplate -ha 03000000 -te policies/policytemplate.bin > run.out
checkSuccess $?

echo "Policy get digest - should be fb 94 ... "
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Create loaded signing key under primary key"
${PREFIX}createloaded -si -hp 80000001 -kt f -kt p -se0 03000000 1 > run.out
checkSuccess $?

echo "Flush the primary key 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the created key 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo ""
echo "Policy Template with TPM2_CreatePrimary"
echo ""

echo "Set primary policy for platform hierarchy"
${PREFIX}setprimarypolicy -hi p -halg sha256 -pol policies/policytemplatehash.bin > run.out
checkSuccess $?

echo "Policy restart, set back to zero"
${PREFIX}policyrestart -ha 03000000 > run.out 
checkSuccess $?

echo "Policy Template"
${PREFIX}policytemplate -ha 03000000 -te policies/policytemplate.bin > run.out
checkSuccess $?

echo "Policy get digest - should be fb 94 ... "
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Create loaded primary signing key policy template, 80000001"
${PREFIX}createprimary -si -hi p -se0 03000000 0 > run.out
checkSuccess $?

echo "Flush the primary key 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

#
# Use case of the PCR brittleness solution using PolicyAuthorize, but
# where the authorizing public key is not hard coded in the sealed
# blob policy.  Rather, it's in an NV Index, so that the authorizing
# key can be changed.  Here, the authorization to change is platform
# auth.  The NV index is locked until reboot as a second level of
# protection.
#

# Policy design

# PolicyAuthorizeNV and Name of NV index AND Unseal
# where the NV index holds PolicyAuthorize with the Name of the authorizing signing key
# where PolicyAuthorize will authorize command Unseal AND PCR values

# construct Policies

# Provision the NV Index data first.  The NV Index Name is needed for the policy
# PolicyAuthorize with the Name of the authorizing signing key.  

# The authorizing signing key Name can be obtained using the TPM from
# loadexternal below.  It can also be calculated off line using this
# utility

# > publicname -ipem policies/rsapubkey.pem -halg sha256 -nalg sha256 -v -ns

# policyauthorize and CA public key
# policies/policyauthorizesha256.txt
# 0000016a000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
# (need blank line for policyRef)
# > policymaker -halg sha256 -if policies/policyauthorizesha256.txt -pr -v -ns -of policies/policyauthorizesha256.bin
#  intermediate policy digest length 32
#  fc 17 cd 86 c0 4f be ca d7 17 5f ef c7 75 5b 63 
#  a8 90 49 12 c3 2e e6 9a 4c 99 1a 7b 5a 59 bd 82 
#  intermediate policy digest length 32
#  eb a3 f9 8c 5e af 1e a8 f9 4f 51 9b 4d 2a 31 83 
#  ee 79 87 66 72 39 8e 23 15 d9 33 c2 88 a8 e5 03 
#  policy digest length 32
#  eb a3 f9 8c 5e af 1e a8 f9 4f 51 9b 4d 2a 31 83 
#  ee 79 87 66 72 39 8e 23 15 d9 33 c2 88 a8 e5 03 
# policy digest:
# eba3f98c5eaf1ea8f94f519b4d2a3183ee79876672398e2315d933c288a8e503

# Once the NV Index Name is known, calculated the sealed blob policy.

# PolicyAuthorizeNV and Name of NV Index AND Unseal
#
# get NV Index Name from nvreadpublic after provisioning
# 000b56e16f0b810a6418daab06822be142858beaf9a79d66f66ad7e8e541f142498e
#
# policies/policyauthorizenv-unseal.txt
# 
# policyauthorizenv and Name of NV Index
# 00000192000b56e16f0b810a6418daab06822be142858beaf9a79d66f66ad7e8e541f142498e
# policy command code unseal
# 0000016c0000015e
#
# > policymaker -halg sha256 -if policies/policyauthorizenv-unseal.txt -of policies/policyauthorizenv-unseal.bin -pr -v -ns
# intermediate policy digest length 32
#  2f 7a d9 b7 53 26 35 e5 03 8c e7 7b 8f 63 5e 4c 
#  f9 96 c8 62 18 13 98 94 c2 71 45 e7 7d d5 e8 e8 
#  intermediate policy digest length 32
#  cd 1b 24 26 fe 10 08 6c 52 35 85 94 22 a0 59 69 
#  33 4b 88 47 82 0d 0b d9 8c 43 1f 7f f7 36 34 5d 
#  policy digest length 32
#  cd 1b 24 26 fe 10 08 6c 52 35 85 94 22 a0 59 69 
#  33 4b 88 47 82 0d 0b d9 8c 43 1f 7f f7 36 34 5d 
# policy digest:
# cd1b2426fe10086c5235859422a05969334b8847820d0bd98c431f7ff736345d

# The authorizing signer signs the PCR white list, here just PCR 16 extended with aaa
# PCR 16 is the resettable debug PCR, convenient for development

echo ""
echo "PolicyAuthorizeNV -> PolicyAuthorize -> PolicyPCR"
echo ""

# Initial provisioning (NV Index)

echo "NV Define Space"
${PREFIX}nvdefinespace -ha 01000000 -hi p -hia p -sz 34 +at wst +at ar > run.out
checkSuccess $?

echo "Write algorithm ID into NV index 01000000"
${PREFIX}nvwrite -ha 01000000 -hia p -off 0 -if policies/sha256.bin > run.out
checkSuccess $?

echo "Write the NV index at offset 2 with policy authorize and the Name of the CA signing key"
${PREFIX}nvwrite -ha 01000000 -hia p -off 2 -if policies/policyauthorizesha256.bin > run.out
checkSuccess $?

echo "Lock the NV Index"
${PREFIX}nvwritelock -ha 01000000 -hia p
checkSuccess $?

echo "Read the NV Index Name to be used above in Policy"
${PREFIX}nvreadpublic -ha 01000000 -ns > run.out
checkSuccess $?

# Initial provisioning (Sealed Data)

echo "Create a sealed data object"
${PREFIX}create -hp 80000000 -nalg sha256 -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto  -uwa -if msg.bin -pol policies/policyauthorizenv-unseal.bin > run.out
checkSuccess $?

# Once per new PCR approved values, signer authorizing PCRs in policysha256.bin

echo "Openssl generate and sign aHash (empty policyRef) ${HALG}"
openssl dgst -sha256 -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policies/policypcr16aaasha256.bin > run.out 2>&1
echo " INFO:"

# Once per boot, simulating setting PCRs to authorized values, lock
# the NV index, which is unloaded at reboot to permit platform auth to
# roll the authorized signing key

echo "Lock the NV Index"
${PREFIX}nvwritelock -ha 01000000 -hia p
checkSuccess $?

echo "PCR 16 Reset"
${PREFIX}pcrreset -ha 16 > run.out
checkSuccess $?

echo "Extend PCR 16 to correct value"
${PREFIX}pcrextend -halg sha256 -ha 16 -if policies/aaa > run.out
checkSuccess $?

# At each unseal, or reuse the ticket tkt.bin for its lifetime

echo "Load external just the public part of PEM authorizing key sha256 80000001"
${PREFIX}loadexternal -hi p -halg sha256 -nalg sha256 -ipem policies/rsapubkey.pem -ns > run.out
checkSuccess $?

echo "Verify the signature to generate ticket 80000001 sha256"
${PREFIX}verifysignature -hk 80000001 -halg sha256 -if policies/policypcr16aaasha256.bin -is pssig.bin -raw -tk tkt.bin > run.out
checkSuccess $?

# Run time unseal

echo "Start a policy session"
${PREFIX}startauthsession -se p -halg sha256 > run.out
checkSuccess $?

echo "Policy PCR, update with the correct PCR 16 value"
${PREFIX}policypcr -halg sha256 -ha 03000000 -bm 10000 > run.out
checkSuccess $?

echo "Policy get digest - should be policies/policypcr16aaasha256.bin"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

# policyauthorize process

echo "Policy authorize using the ticket"
${PREFIX}policyauthorize -ha 03000000 -appr policies/policypcr16aaasha256.bin -skn ${TPM_DATA_DIR}/h80000001.bin -tk tkt.bin > run.out
checkSuccess $?

echo "Get policy digest, should be policies/policyauthorizesha256.bin"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Flush the authorizing public key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Policy Authorize NV against NV Index 01000000"
${PREFIX}policyauthorizenv -ha 01000000 -hs 03000000 > run.out
checkSuccess $?

echo "Get policy digest, should be policies/policyauthorizenv-unseal.bin intermediate"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Policy command code - unseal"
${PREFIX}policycommandcode -ha 03000000 -cc 0000015e > run.out
checkSuccess $?

echo "Get policy digest, should be policies/policyauthorizenv-unseal.bin final"
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Load the sealed data object"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Unseal the data blob"
${PREFIX}unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
checkSuccess $?

echo "Verify the unsealed result"
diff msg.bin tmp.bin > run.out
checkSuccess $?

echo "Flush the sealed object"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the policy session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo "NV Undefine Space"
${PREFIX}nvundefinespace -hi p -ha 01000000 > run.out
checkSuccess $?

# cleanup 


rm -f tmppriv.bin
rm -f tmppub.bin

