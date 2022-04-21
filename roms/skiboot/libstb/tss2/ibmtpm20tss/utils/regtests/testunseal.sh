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

# used for the name in policy authorize

if [ -z $TPM_DATA_DIR ]; then
    TPM_DATA_DIR=.
fi

echo ""
echo "Seal and Unseal to Password"
echo ""

echo "Create a sealed data object"
${PREFIX}create -hp 80000000 -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin > run.out
checkSuccess $?

echo "Load the sealed data object"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Unseal the data blob"
${PREFIX}unseal -ha 80000001 -pwd sea -of tmp.bin > run.out
checkSuccess $?

echo "Verify the unsealed result"
diff msg.bin tmp.bin > run.out
checkSuccess $?

echo "Unseal with bad password - should fail"
${PREFIX}unseal -ha 80000001 -pwd xxx > run.out
checkFailure $?

echo "Flush the sealed object"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Create a primary sealed data object"
${PREFIX}createprimary -bl -kt f -kt p -pwdk seap -if msg.bin > run.out
checkSuccess $?

echo "Unseal the primary data blob"
${PREFIX}unseal -ha 80000001 -pwd seap -of tmp.bin > run.out
checkSuccess $?

echo "Verify the unsealed result"
diff msg.bin tmp.bin > run.out
checkSuccess $?

echo "Flush the primary sealed object"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "Seal and Unseal to PolicySecret Platform Auth"
echo ""

# policy is policy secret pointing to platform auth
# 000001514000000C plus newline for policyRef

echo "Change platform hierarchy auth"
${PREFIX}hierarchychangeauth -hi p -pwdn ppp > run.out
checkSuccess $?

echo "Create a sealed data object with policysecret platform auth under primary key"
${PREFIX}create -hp 80000000 -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policysecretp.bin > run.out
checkSuccess $?

echo "Load the sealed data object under primary key"
${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Unseal the data blob - policy failure, policysecret not run"
${PREFIX}unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
checkFailure $?

echo "Policy Secret with PWAP session and platform auth"
${PREFIX}policysecret -ha 4000000c -hs 03000000 -pwde ppp > run.out
checkSuccess $?

echo "Unseal the data blob"
${PREFIX}unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
checkSuccess $?

echo "Verify the unsealed result"
diff msg.bin tmp.bin > run.out
checkSuccess $?

echo "Change platform hierarchy auth back to null"
${PREFIX}hierarchychangeauth -hi p -pwda ppp > run.out
checkSuccess $?

echo "Flush the sealed object"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the policy session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

# extend of aaa + 0 pad to digest length
# pcrreset -ha 16
# pcrextend -ha 16 -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ic aaa
# pcrread   -ha 16 -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ns
#
# 1d47f68aced515f7797371b554e32d47981aa0a0
# c2119764d11613bf07b7e204c35f93732b4ae336b4354ebc16e8d0c3963ebebb
# 292963e31c34c272bdea27154094af9250ad97d9e7446b836d3a737c90ca47df2c399021cedd00853ef08497c5a42384
# 7fe1e4cf015293136bf130183039b6a646ea008b75afd0f8466a9bfe531af8ada867a65828cfce486077529e54f1830aa49ab780562baea49c67a87334ffe778
#
# paste that with no white space to file policypcr16aaasha1.txt, etc.
#
# create AND term for policy PCR, PCR 16
# and then convert to binary policy

# > policymakerpcr -halg sha1   -bm 10000 -if policies/policypcr16aaasha1.txt   -v -pr -of policies/policypcr.txt
# 0000017f00000001000403000001cbf1e9f771d215a017e17979cfd7184f4b674a4d
# convert to binary policy
# > policymaker -halg sha1   -if policies/policypcr.txt -of policies/policypcr16aaasha1.bin -pr -v
# 12 b6 dd 16 43 82 ca e4 5d 0e d0 7f 9e 51 d1 63 
# a4 24 f5 f2 

# > policymakerpcr -halg sha256 -bm 10000 -if policies/policypcr16aaasha256.txt -v -pr -of policies/policypcr.txt
# 0000017f00000001000b030000012c28901f71751debfba3f3b5bf3be9c54b8b2f8c1411f2c117a0e838ee4e6c13
# > policymaker -halg sha256 -if policies/policypcr.txt -of policies/policypcr16aaasha256.bin -pr -v
# 76 44 f6 11 ea 10 d7 60 da b9 36 c3 95 1e 1d 85 
# ec db 84 ce 9a 79 03 dd e1 c7 e0 a2 d9 09 a0 13 

# > policymakerpcr -halg sha384 -bm 10000 -if policies/policypcr16aaasha384.txt -v -pr -of policies/policypcr.txt
# 0000017f00000001000c0300000132edb1c501cb0af4f958c9d7f04a8f3122c1025067e3832a5137234ee0d875e9fa99d8d400ca4a37fe13a6f53aeb4932
# > policymaker -halg sha384 -if policies/policypcr.txt -of policies/policypcr16aaasha384.bin -pr -v
# ea aa 8b 90 d2 69 b6 31 c0 85 91 e4 bf 29 a3 12 
# 87 04 f2 18 4c 02 ee 83 6a fb c4 c6 7f 28 c1 7f 
# 86 ea 22 b7 00 3d 06 fc b4 57 a3 b5 c4 f7 3c 95 

# > policymakerpcr -halg sha512 -bm 10000 -if policies/policypcr16aaasha512.txt -v -pr -of policies/policypcr.txt
# 0000017f00000001000d03000001ea5218788d9d3a79e6f58608e321880aeb33e2282a3a0a87fb5b8868e7c6b3eedb9b66019409d8ea52d77e0dbfee5822c10ad0de3fd5cc776813a60423a7531f
# policymaker -halg sha512 -if policies/policypcr.txt -of policies/policypcr16aaasha512.bin -pr -v
# 1a 57 25 8d 99 64 d8 74 f0 85 0f 2c 8d 70 41 cc 
# be 21 c2 0f df 7e 07 e6 b1 99 ea 05 66 46 b7 fb 
# 23 55 77 4b 96 7e ab e2 65 db 5a 52 82 08 9c af 
# 3c c0 10 e4 99 36 5d ec 7f 0d 3e 6d 2a 62 6d 2e 

# sealed blob    80000001
# policy session 03000000

echo ""
echo "Seal and Unseal to PCR 16"
echo ""

for HALG in ${ITERATE_ALGS}
do

    echo "Create a sealed data object ${HALG}"
    ${PREFIX}create -hp 80000000 -nalg ${HALG} -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policypcr16aaa${HALG}.bin > run.out
    checkSuccess $?

    echo "Load the sealed data object"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Start a policy session ${HALG}"
    ${PREFIX}startauthsession -se p -halg ${HALG} > run.out
    checkSuccess $?

    echo "PCR 16 Reset"
    ${PREFIX}pcrreset -ha 16 > run.out
    checkSuccess $?

    echo "Unseal the data blob - policy failure, policypcr not run"
    ${PREFIX}unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
    checkFailure $?

    echo "Policy PCR, update with the wrong PCR 16 value"
    ${PREFIX}policypcr -halg ${HALG} -ha 03000000 -bm 10000 > run.out
    checkSuccess $?

    echo "Unseal the data blob - policy failure, PCR 16 incorrect"
    ${PREFIX}unseal -ha 80000001 -of tmp.bin -se0 03000000 1 > run.out
    checkFailure $?

    echo "Extend PCR 16 to correct value"
    ${PREFIX}pcrextend -halg ${HALG} -ha 16 -if policies/aaa > run.out
    checkSuccess $?

    echo "Policy restart, set back to zero"
    ${PREFIX}policyrestart -ha 03000000 > run.out 
    checkSuccess $?

    echo "Policy PCR, update with the correct PCR 16 value"
    ${PREFIX}policypcr -halg ${HALG} -ha 03000000 -bm 10000 > run.out
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

done

# This test uses the same values for PCR 16 and PCR 23 for simplicity.
# For different values, calculate the PCR white list value and change
# the cat line to use two different values.

# extend of aaa + 0 pad to digest length
# pcrreset -ha 16
# pcrextend -ha 16 -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ic aaa
# pcrread   -ha 16 -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ns
#
# 1d47f68aced515f7797371b554e32d47981aa0a0
# c2119764d11613bf07b7e204c35f93732b4ae336b4354ebc16e8d0c3963ebebb
# 292963e31c34c272bdea27154094af9250ad97d9e7446b836d3a737c90ca47df2c399021cedd00853ef08497c5a42384
# 7fe1e4cf015293136bf130183039b6a646ea008b75afd0f8466a9bfe531af8ada867a65828cfce486077529e54f1830aa49ab780562baea49c67a87334ffe778
#
# paste that with no white space to file policypcr16aaasha1.txt, etc.
#
# create AND term for policy PCR, PCR 16 and 23
# and then convert to binary policy

# > cat policies/policypcr16aaasha1.txt policies/policypcr16aaasha1.txt >! policypcra.txt
# > policymakerpcr -halg sha1   -bm 810000 -if policypcra.txt -v -pr -of policypcr.txt
#0000017f0000000100040300008173820c1f0f279933a5a58629fe44d081e740d4ae
# > policymaker -halg sha1   -if policypcr.txt -of policies/policypcr1623aaasha1.bin -pr -v
 # policy digest length 20
 # b4 ed de a3 35 87 d7 43 29 f6 a8 d1 e7 89 92 64 
 # 46 f0 4c 85 

# > cat policies/policypcr16aaasha256.txt policies/policypcr16aaasha256.txt >! policypcra.txt
# > policymakerpcr -halg sha256   -bm 810000 -if policypcra.txt -v -pr -of policypcr.txt
# 0000017f00000001000b030000815a9f104273886b7ec8919a449d440d107d0da5df367e28c6ac145c9023cb5e76
# > policymaker -halg sha256   -if policypcr.txt -of policies/policypcr1623aaasha256.bin -pr -v
 # policy digest length 32
 # 84 ff 2f f1 2d 37 cb 23 fb 3d 14 d9 66 77 ca ec 
 # 48 94 5c 0b 83 e5 ea a2 be 98 e9 75 aa 21 e3 d6 

# > cat policies/policypcr16aaasha384.txt policies/policypcr16aaasha384.txt >! policypcra.txt
# > policymakerpcr -halg sha384   -bm 810000 -if policypcra.txt -v -pr -of policypcr.txt
# 0000017f00000001000c0300008105f7f12c86c3b0ed988d369a96d401bb4a58b74f982eb03e8474cb66076114ba2b933dd95cde1c7ea69d0a797abc99d4
# > policymaker -halg sha384   -if policypcr.txt -of policies/policypcr1623aaasha384.bin -pr -v
 # policy digest length 48
 # 4b 03 cd b3 eb 07 15 14 7c 49 93 43 a5 65 ee dc 
 # 86 22 7c 86 36 20 97 a2 5e 0f 34 2e d2 4f 7e ad 
 # a0 61 8b 5e d7 ba bb e3 5e f0 ab ea 99 55 df 84 

# > cat policies/policypcr16aaasha512.txt policies/policypcr16aaasha512.txt >! policypcra.txt
# > policymakerpcr -halg sha512   -bm 810000 -if policypcra.txt -v -pr -of policypcr.txt
# 0000017f00000001000d03000081266ae24c92f63b30322e9c22e44e9540313a2223ae79b27eafe798168bef373ac55de22a0ca78ec8b2e9402aa1f8b47b6ef40e9e53aebaa694af58f240efa0fd
# > policymaker -halg sha512   -if policypcr.txt -of policies/policypcr1623aaasha512.bin -pr -v
 # policy digest length 64
 # 13 84 59 76 b8 d4 d8 a9 a4 7d 75 0e 3e 81 cd c2 
 # 78 08 ec 95 d7 13 e8 ef 0c 0b 85 c7 38 2e ad 46 
 # e4 72 31 1d 11 a3 38 17 54 e5 cf 2e 6d 23 67 6d 
 # 39 5a 93 51 9d f3 f0 90 56 4d 66 f8 7b 90 fc 61 

# sealed blob    80000001
# policy session 03000000

echo ""
echo "Seal and Unseal to PCR 16 and 23"
echo ""

for HALG in ${ITERATE_ALGS}
do

    echo "Create a sealed data object ${HALG}"
    ${PREFIX}create -hp 80000000 -nalg ${HALG} -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policypcr1623aaa${HALG}.bin > run.out
    checkSuccess $?

    echo "Load the sealed data object"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Start a policy session ${HALG}"
    ${PREFIX}startauthsession -se p -halg ${HALG} > run.out
    checkSuccess $?

    echo "PCR 16 Reset"
    ${PREFIX}pcrreset -ha 16 > run.out
    checkSuccess $?

    echo "PCR 23 Reset"
    ${PREFIX}pcrreset -ha 23 > run.out
    checkSuccess $?

    echo "Extend PCR 16 to correct value"
    ${PREFIX}pcrextend -halg ${HALG} -ha 16 -if policies/aaa > run.out
    checkSuccess $?

    echo "Extend PCR 23 to correct value"
    ${PREFIX}pcrextend -halg ${HALG} -ha 23 -if policies/aaa > run.out
    checkSuccess $?

    echo "Policy PCR, update with the correct PCR 16 and 23 values"
    ${PREFIX}policypcr -halg ${HALG} -ha 03000000 -bm 810000 > run.out
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

done

#
# Sample application to demonstrate the policy authorize solution to
# the PCR brittleness problem when sealing.  Rather than sealing
# directly to the PCRs, the blob is sealed to an authorizing public
# key.  The authorizing private key signs the approved policy PCR
# digest.
#
# Name for 80000001 authorizing key (output of loadexternal below) is
# used to calculate the policy authorize policy
#
# 00044234c24fc1b9de6693a62453417d2734d7538f6f
# 000b64ac921a035c72b3aa55ba7db8b599f1726f52ec2f682042fc0e0d29fae81799
# 000ca8bfb42e75b4c22b366b372cd9994bafe8558aa182cf12c258406d197dab63ac46f5a5255b1deb2993a4e9fc92b1e26c
# 000d0c36b2a951eccc7e3e12d03175a71304dc747f222a02af8fa2ac8b594ef973518d20b9a5452d0849e325710f587d8a55082e7ae321173619bc12122f3ad71466
#
# Use 0000016a || the above Name, with a following blank line for
# policyRef to make policies/policyauthorizesha[].txt. Use policymaker
# to create the binary policy.  This will be the session digest after
# the policyauthorize command.
#
# > policymaker -halg sha[] -if policies/policyauthorizesha[].txt -of policies/policyauthorizesha[].bin -pr
# 16 82 10 58 c0 32 8c c4 e5 2e c4 ec ce 61 6c 0a 
# f4 8a 30 88 
#
# eb a3 f9 8c 5e af 1e a8 f9 4f 51 9b 4d 2a 31 83 
# ee 79 87 66 72 39 8e 23 15 d9 33 c2 88 a8 e5 03 
#
# 5c c6 34 89 fe f9 c8 42 7e fe 2c 5f 08 39 74 b6 
# d9 a8 36 02 4a cd d9 70 7e f0 b9 fd 15 26 56 da 
# a5 07 0a 9b bf d6 66 df 49 d2 5b 8d 50 8e 16 38 
#
# c9 c8 29 fb bc 75 54 99 db 48 b7 26 88 24 d1 f8 
# 29 72 01 60 6b d6 5f 41 8e 06 98 7e f7 3e 6a 7e 
# 25 82 c7 6d 8f 1c 36 43 68 01 ee 56 51 d5 06 b4 
# 68 4c fe d1 d0 6a d7 65 23 3f c2 92 94 fd 2c c5 

# setup and policy PCR calculations
#
# 16 is the debug PCR, a typical application may seal to PCR 0-7
# > pcrreset -ha 16
#
# policies/aaa represents the new 'BIOS' measurement hash extended
# into all PCR banks
#
# > pcrextend -ha 16 -halg [] -if policies/aaa
#
# These are the new PCR values to be authorized.  Typically, these are
# calculated by other software based on the enterprise.  Here, they're
# just read from the TPM.
#
# > pcrread -ha 16 -halg sha1 -halg sha256 -halg sha384 -halg sha512 -ns
#
# 1d47f68aced515f7797371b554e32d47981aa0a0
# c2119764d11613bf07b7e204c35f93732b4ae336b4354ebc16e8d0c3963ebebb
# 292963e31c34c272bdea27154094af9250ad97d9e7446b836d3a737c90ca47df2c399021cedd00853ef08497c5a42384
# 7fe1e4cf015293136bf130183039b6a646ea008b75afd0f8466a9bfe531af8ada867a65828cfce486077529e54f1830aa49ab780562baea49c67a87334ffe778
#
# Put the above authorized PCR value in an intermediate file
# policies/policypcr16aaasha1.txt for policymakerpcr, and create the
# policypcr AND term policies/policypcr.txt.  policymakerpcr prepends the command code and
# PCR select bit mask.
#
# > policymakerpcr -halg sha[] -bm 010000 -if policies/policypcr16aaasha1.txt -of policies/policypcr.txt -pr -v
#
# 0000017f00000001000403000001cbf1e9f771d215a017e17979cfd7184f4b674a4d
# 0000017f00000001000b030000012c28901f71751debfba3f3b5bf3be9c54b8b2f8c1411f2c117a0e838ee4e6c13
# 0000017f00000001000c0300000132edb1c501cb0af4f958c9d7f04a8f3122c1025067e3832a5137234ee0d875e9fa99d8d400ca4a37fe13a6f53aeb4932
# 0000017f00000001000d03000001ea5218788d9d3a79e6f58608e321880aeb33e2282a3a0a87fb5b8868e7c6b3eedb9b66019409d8ea52d77e0dbfee5822c10ad0de3fd5cc776813a60423a7531f
#
# Send the policymakerpcr AND term result to policymaker to create the
# Policy PCR digest.  This is the authorized policy signed by the
# authorizing private key.
#
# > policymaker -halg sha[] -if policies/policypcr.txt -of policies/policypcr16aaasha[].bin -v -pr -ns
#
# 12b6dd164382cae45d0ed07f9e51d163a424f5f2
# 7644f611ea10d760dab936c3951e1d85ecdb84ce9a7903dde1c7e0a2d909a013
# eaaa8b90d269b631c08591e4bf29a3128704f2184c02ee836afbc4c67f28c17f86ea22b7003d06fcb457a3b5c4f73c95
# 1a57258d9964d874f0850f2c8d7041ccbe21c20fdf7e07e6b199ea056646b7fb2355774b967eabe265db5a5282089caf3cc010e499365dec7f0d3e6d2a626d2e

echo ""
echo "Policy PCR with Policy Authorize (PCR brittleness solution)"
echo ""

for HALG in ${ITERATE_ALGS}
do
    # One time task, create sealed blob with policy of policyauthorize
    # with Name of authorizing key

    echo "Create a sealed data object ${HALG}"
    ${PREFIX}create -hp 80000000 -nalg ${HALG} -bl -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -if msg.bin -pol policies/policyauthorize${HALG}.bin > run.out
    checkSuccess $?

    # Once per new PCR approved values, authorizing PCRs in policy${HALG}.bin

    echo "Openssl generate and sign aHash (empty policyRef) ${HALG}"
    openssl dgst -${HALG} -sign policies/rsaprivkey.pem -passin pass:rrrr -out pssig.bin policies/policypcr16aaa${HALG}.bin > run.out 2>&1

    # Once per boot, simulating setting PCRs to authorized values

    echo "Reset PCR 16 back to zero"
    ${PREFIX}pcrreset -ha 16 > run.out
    checkSuccess $?

    echo "PCR extend PCR 16 ${HALG}"
    ${PREFIX}pcrextend -ha 16 -halg ${HALG} -if policies/aaa > run.out
    checkSuccess $?

    # beginning of unseal process, policy PCR

    echo "Start a policy session ${HALG}"
    ${PREFIX}startauthsession -halg ${HALG} -se p > run.out
    checkSuccess $?

    echo "Policy PCR, update with the correct digest ${HALG}"
    ${PREFIX}policypcr -ha 03000000 -halg ${HALG} -bm 10000 > run.out
    checkSuccess $?

    echo "Policy get digest, should be policies/policypcr16aaa${HALG}.bin"
    ${PREFIX}policygetdigest -ha 03000000 > run.out
    checkSuccess $?

    # policyauthorize process

    echo "Load external just the public part of PEM authorizing key ${HALG} 80000001"
    ${PREFIX}loadexternal -hi p -halg ${HALG} -nalg ${HALG} -ipem policies/rsapubkey.pem -ns > run.out
    checkSuccess $?

    echo "Verify the signature to generate ticket 80000001 ${HALG}"
    ${PREFIX}verifysignature -hk 80000001 -halg ${HALG} -if policies/policypcr16aaa${HALG}.bin -is pssig.bin -raw -tk tkt.bin > run.out
    checkSuccess $?

    echo "Policy authorize using the ticket"
    ${PREFIX}policyauthorize -ha 03000000 -appr policies/policypcr16aaa${HALG}.bin -skn ${TPM_DATA_DIR}/h80000001.bin -tk tkt.bin > run.out
    checkSuccess $?

    echo "Get policy digest, should be policies/policyauthorize${HALG}.bin"
    ${PREFIX}policygetdigest -ha 03000000 > run.out
    checkSuccess $?

    echo "Flush the verification public key 80000001"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    # load the sealed blob and unseal

    echo "Load the sealed data object 80000001"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Unseal the data blob using the policy session"
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

done

echo ""
echo "Import and Unseal"
echo ""

# primary key P1 80000000
# sealed data S1 80000001 originally under 80000000
# target storage key K1 80000002

for ALG in "rsa2048" "ecc"
do 

    echo "Create a sealed data object S1 under the primary key P1 80000000"
    ${PREFIX}create -hp 80000000 -bl -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sea -if msg.bin -pol policies/policyccduplicate.bin > run.out
    checkSuccess $?

    echo "Load the sealed data object S1 at 80000001"
    ${PREFIX}load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Load the ${ALG} storage key K1 80000002"
    ${PREFIX}load -hp 80000000 -ipr store${ALG}priv.bin -ipu store${ALG}pub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Start a policy session 03000000"
    ${PREFIX}startauthsession -se p > run.out
    checkSuccess $?

    echo "Policy command code, duplicate"
    ${PREFIX}policycommandcode -ha 03000000 -cc 14b > run.out
    checkSuccess $?

    echo "Get policy digest"
    ${PREFIX}policygetdigest -ha 03000000 > run.out 
    checkSuccess $?

    echo "Duplicate sealed data object S1 80000001 under ${ALG} K1 80000002"
    ${PREFIX}duplicate -ho 80000001 -pwdo sig -hp 80000002 -od tmpdup.bin -oss tmpss.bin -se0 03000000 1 > run.out
    checkSuccess $?

    echo "Flush the original S1 to free object slot for import"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Import S1 under ${ALG} K1 80000002"
    ${PREFIX}import -hp 80000002 -pwdp sto -ipu tmppub.bin -id tmpdup.bin -iss tmpss.bin -opr tmppriv1.bin > run.out
    checkSuccess $?

    echo "Load the duplicated sealed data object S1 at 80000001 under ${ALG} K1 80000002"
    ${PREFIX}load -hp 80000002 -ipr tmppriv1.bin -ipu tmppub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Unseal the data blob"
    ${PREFIX}unseal -ha 80000001 -pwd sea -of tmp.bin > run.out
    checkSuccess $?

    echo "Verify the unsealed result"
    diff msg.bin tmp.bin > run.out
    checkSuccess $?

    echo "Flush the sealed data object at 80000001"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

    echo "Flush the storage key at 80000002"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Flush the session"
    ${PREFIX}flushcontext -ha 03000000 > run.out
    checkSuccess $?

done

rm -r tmppriv.bin
rm -r tmppub.bin
rm -r tmp.bin
rm -f tmpdup.bin
rm -f tmpss.bin
rm -f tmppriv1.bin
rm -f pssig.bin
rm -f tkt.bin

# ${PREFIX}getcapability -cap 1 -pr 80000000
