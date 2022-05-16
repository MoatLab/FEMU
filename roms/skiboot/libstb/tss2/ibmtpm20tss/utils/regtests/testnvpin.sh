#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2016 - 2019					#
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

# PIN Pass index name is

# 00 0b da 1c bd 54 bb 81 54 6c 1c 76 30 dd d4 09 
# 50 3a 0d 6d 03 05 16 1b 15 88 d6 6b c8 fa 17 da 
# ad 81 

# Policy Secret using PIN Pass index is

# 56 e4 c7 26 d7 d7 dd 3c bd 4c ae 11 c0 1b 2e 83 
# 3c 37 33 3c fb c3 b9 c3 5f 05 ab 53 23 0c df 7d 

# PIN Fail index name is

# 00 0b 86 11 40 4a e8 0c 0a 84 e5 b8 97 05 98 f0 
# b5 60 2d 14 21 19 bf 44 9d e5 f9 61 84 bc 4c 01 
# c4 be 

# Policy Secret using PIN Fail index is
 
# 9d 56 8f da 52 27 30 dc be a8 ad 59 bc a5 0c 1c 
# 16 02 95 03 a0 0b d3 d8 20 a8 b2 d8 5b c5 12 df 

# 01000000 is PIN pass or PIN fail index
# 01000001 is ordinary index with PIN pass policy
# 01000002 is ordinary index with PIN fail policy


echo ""
echo "NV PIN Index"
echo ""

echo "NV Define Space, 01000001, ordinary index, with policysecret for pin pass index 01000000"
${PREFIX}nvdefinespace -ha 01000001 -hi o -pwdn ppi -ty o -hia p -sz 1 -pol policies/policysecretnvpp.bin > run.out
checkSuccess $?

echo "Platform write to set written bit"
${PREFIX}nvwrite -ha 01000001 -hia p -ic 0 > run.out
checkSuccess $?

echo "NV Define Space, 01000002, ordinary index, with policysecret for pin fail index 01000000"
${PREFIX}nvdefinespace -ha 01000002 -hi o -pwdn pfi -ty o -hia p -sz 1 -pol policies/policysecretnvpf.bin > run.out
checkSuccess $?

echo "Platform write to set written bit"
${PREFIX}nvwrite -ha 01000002 -hia p -ic 0 > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo ""
echo "NV PIN Pass Index"
echo ""

echo "Set phEnableNV"
${PREFIX}hierarchycontrol -hi p -he n > run.out
checkSuccess $?

echo "NV Define Space, 01000000, pin pass, read/write stclear, policy secret using platform auth"
${PREFIX}nvdefinespace -ha 01000000 -hi p -pwdn nnn -ty p +at wst +at rst -hia p -pol policies/policysecretp.bin > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, not written - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkFailure $?

echo "Platform write, 1 use, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Platform read does not affect count"
${PREFIX}nvread -ha 01000000 -hia p -sz 8 -id 0 1 > run.out
checkSuccess $?

echo "Platform read does not affect count, should succeed"
${PREFIX}nvread -ha 01000000 -hia p -sz 8 -id 0 1 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, platform auth"
${PREFIX}policysecret -ha 4000000c -hs 03000000 > run.out
checkSuccess $?

echo "Policy write, 1 use, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -id 0 1 -se0 03000000 1 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, platform auth"
${PREFIX}policysecret -ha 4000000c -hs 03000000 > run.out
checkSuccess $?

echo "Policy read should not increment pin count"
${PREFIX}nvread -ha 01000000 -id 0 1 -se0 03000000 1 > run.out
checkSuccess $?

echo "Platform write, 1 use, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Index read should increment pin count"
${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 8 -id 1 1 > run.out
checkSuccess $?

echo "Index read, no uses - should fail"
${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 8 > run.out
checkFailure $?

echo "Platform read, no uses"
${PREFIX}nvread -ha 01000000 -hia p -sz 8 -id 1 1 > run.out
checkSuccess $?

echo ""
echo "NV PIN Pass Index in Policy Secret"
echo ""

echo "Policy Secret with PWAP session, bad password - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnnx > run.out
checkFailure $?

echo "Platform write, 01000000, 1 use, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, bad password does not consume pinCount - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnnx > run.out
checkFailure $?

echo "Policy Secret with PWAP session, should consume pin couunt"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, pinCount used - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkFailure $?

echo "Policy Get Digest, 50 b9 63 d6 ..."
${PREFIX}policygetdigest -ha 03000000 > run.out
checkSuccess $?

echo "Read ordinary index using PIN pass policy secret"
${PREFIX}nvread -ha 01000001 -sz 1 -se0 03000000 1 > run.out
checkSuccess $?

echo "Platform write, 01000000, 1 use, 1 / 2"
${PREFIX}nvwrite -ha 01000000 -hia p -id 1 2 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkSuccess $?

echo "Platform write, 0 uses, 0 / 0"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 0 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, pinCount used - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkFailure $?

echo "Platform write, 1 use. 1 / 1, already used"
${PREFIX}nvwrite -ha 01000000 -hia p -id 1 1 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, pinCount used - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkFailure $?

echo "Platform write, 0 uses. 2 / 1, already used"
${PREFIX}nvwrite -ha 01000000 -hia p -id 2 1 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, pinCount used - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkFailure $?

echo ""
echo "NV PIN Pass Index with Write Lock"
echo ""

echo "Platform write, 01000000, 1 use, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Write lock, 01000000"
${PREFIX}nvwritelock -ha 01000000 -hia p > run.out 
checkSuccess $?

echo "Policy Secret with PWAP session"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, pinCount used - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkFailure $?

echo "Platform write, 01000000, locked - should fail"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkFailure $?

echo "Reboot"
${PREFIX}powerup > run.out
checkSuccess $?

echo "Startup"
${PREFIX}startup > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Platform write, 01000000, 1 use, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkSuccess $?

echo ""
echo "NV PIN Pass Index with Read Lock"
echo ""

echo "Platform write, 01000000, 1 use, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Read lock, 01000000"
${PREFIX}nvreadlock -ha 01000000 -hia p > run.out
checkSuccess $?

echo "Platform read, locked - should fail"
${PREFIX}nvread -ha 01000000 -hia p -sz 8 > run.out
checkFailure $?

echo "Policy Secret with PWAP session, read locked"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkSuccess $?

echo ""
echo "NV PIN Pass Index with phEnableNV clear"
echo ""

echo "Platform write, 01000000, 1 use, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Clear phEnableNV"
${PREFIX}hierarchycontrol -hi p -he n -state 0 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, phEnableNV disabled - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkFailure $?

echo "Set phEnableNV"
${PREFIX}hierarchycontrol -hi p -he n -state 1 > run.out
checkSuccess $?

echo ""
echo "Cleanup NV PIN Pass"
echo ""

echo "NV Undefine Space, 01000000 "
${PREFIX}nvundefinespace -hi p -ha 01000000 > run.out
checkSuccess $?

echo "Flush the policy session, 03000000 "
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

echo ""
echo "NV PIN Fail Index"
echo ""

echo "NV Define Space, 01000000, pin fail, read/write stclear, policy secret using platform auth"
${PREFIX}nvdefinespace -ha 01000000 -hi p -pwdn nnn -ty f +at wst +at rst -hia p -pol policies/policysecretp.bin > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, not written - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkFailure $?

echo "Platform write, 1 failure, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Platform read"
${PREFIX}nvread -ha 01000000 -hia p -sz 8 -id 0 1 > run.out
checkSuccess $?

echo "Platform read with bad password - should fail"
${PREFIX}nvread -ha 01000000 -hia p -sz 8 -pwdn xxx > run.out
checkFailure $?

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, platform auth"
${PREFIX}policysecret -ha 4000000c -hs 03000000 > run.out
checkSuccess $?

echo "Policy write, 01000000, platform auth"
${PREFIX}nvwrite -ha 01000000 -id 0 1 -se0 03000000 1 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, platform auth"
${PREFIX}policysecret -ha 4000000c -hs 03000000 > run.out
checkSuccess $?

echo "Policy read, 01000000"
${PREFIX}nvread -ha 01000000 -sz 8 -id 0 1 -se0 03000000 1 > run.out
checkSuccess $?

echo "Platform write, 01000000, 0 / 1 failure"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Index read, 01000000, correct password"
${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 8 -id 0 1 > run.out
checkSuccess $?

echo "Index read, 01000000, bad password - should fail"
${PREFIX}nvread -ha 01000000 -pwdn nn -sz 8 > run.out
checkFailure $?

echo "Index read, 01000000, correct password - fail because tries used"
${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 8 > run.out
checkFailure $?

echo "Platform write, 01000000, 0 / 1 failure"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Index read, 01000000"
${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 8 -id 0 1 > run.out
checkSuccess $?

echo ""
echo "NV PIN Fail Index in Policy Secret"
echo ""

echo "Platform write, 2 failures, 0 / 2"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 2 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, good password"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, bad password uses pinCount - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnnx > run.out
checkFailure $?

echo "Policy Secret with PWAP session, good password, resets pinCount"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, bad password uses pinCount - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnnx > run.out
checkFailure $?

echo "Policy Secret with PWAP session, bad password uses pinCount - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnnx > run.out
checkFailure $?

echo "Policy Secret with PWAP session, good password - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkFailure $?

echo "Platform write, 1 failure use, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, good password, resets pinCount"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkSuccess $?

echo "Platform write, 0 failures, 1 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 1 1 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, good password, resets pinCount"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkFailure $?

echo ""
echo "NV PIN Fail Index with Write Lock"
echo ""

echo "Platform write, 01000000, 1 fail, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Write lock, 01000000"
${PREFIX}nvwritelock -ha 01000000 -hia p > run.out 
checkSuccess $?

echo "Policy Secret with PWAP session"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkSuccess $?

echo "Platform write, 01000000, locked - should fail"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkFailure $?

echo "Reboot"
${PREFIX}powerup > run.out
checkSuccess $?

echo "Startup"
${PREFIX}startup > run.out
checkSuccess $?

echo "Start a policy session"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "Platform write, 01000000, unlocked, 1 failure, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo ""
echo "NV PIN Fail Index with Read Lock"
echo ""

echo "Platform write, 01000000, 1 failure, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Read lock 01000000"
${PREFIX}nvreadlock -ha 01000000 -hia p > run.out 
checkSuccess $?

echo "Platform read, locked - should fail"
${PREFIX}nvread -ha 01000000 -hia p -sz 8 > run.out
checkFailure $?

echo "Policy Secret with PWAP session, read locked"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkSuccess $?

echo ""
echo "NV PIN Fail Index with phEnableNV clear"
echo ""

echo "Platform write, 01000000, 1 failure, 0 / 1"
${PREFIX}nvwrite -ha 01000000 -hia p -id 0 1 > run.out
checkSuccess $?

echo "Clear phEnableNV"
${PREFIX}hierarchycontrol -hi p -he n -state 0 > run.out
checkSuccess $?

echo "Policy Secret with PWAP session, phEnableNV disabled - should fail"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde nnn > run.out
checkFailure $?

echo "Set phEnableNV"
${PREFIX}hierarchycontrol -hi p -he n -state 1 > run.out
checkSuccess $?

echo ""
echo "Cleanup"
echo ""

echo "NV Undefine Space 01000000"
${PREFIX}nvundefinespace -hi p -ha 01000000 > run.out 
checkSuccess $?

echo "NV Undefine Space 01000001"
${PREFIX}nvundefinespace -hi o -ha 01000001 > run.out
checkSuccess $?

echo "NV Undefine Space 01000002"
${PREFIX}nvundefinespace -hi o -ha 01000002 > run.out
checkSuccess $?

echo "Flush the session"
${PREFIX}flushcontext -ha 03000000 > run.out > run.out
checkSuccess $?

# Recreate the primary key
initprimary
checkSuccess $?

echo ""
echo "NV PIN define space"
echo ""

echo "NV Define Space, 01000000, no write auth - should fail"
${PREFIX}nvdefinespace -ha 01000000 -hi p -pwdn nnn -ty p -hia p -at ppw > run.out
checkFailure $?

echo "NV Define Space, 01000000, no read auth - should fail"
${PREFIX}nvdefinespace -ha 01000000 -hi p -pwdn nnn -ty p -hia p -at ppr -at ar> run.out
checkFailure $?

echo "NV Define Space, 01000000, PIN Pass, auth write - should fail"
${PREFIX}nvdefinespace -ha 01000000 -hi p -pwdn nnn -ty p -hia p +at aw > run.out
checkFailure $?

echo "NV Define Space, 01000000, PIN Fail, auth write - should fail"
${PREFIX}nvdefinespace -ha 01000000 -hi p -pwdn nnn -ty f -hia p +at aw > run.out
checkFailure $?

echo "NV Define Space, 01000000, PIN Fail, noDA clear - should fail"
${PREFIX}nvdefinespace -ha 01000000 -hi p -pwdn nnn -ty f -hia p -at da > run.out
checkFailure $?

#
# Additional test for pinCount update when NV auth is not used.  This
# tests for a bug fix
#

#
# policy calculation
#

echo "Create the policy digest that will be used for the NvIndex write term"
${PREFIX}startauthsession -se t > run.out
checkSuccess $?

echo "policycommandcode TPM_CC_NV_Write"
${PREFIX}policycommandcode -ha 03000000 -cc 137 > run.out
checkSuccess $?

echo "Get the policycommandcode write term"
${PREFIX}policygetdigest -ha 03000000 -of tmppw.bin > run.out
checkSuccess $?

echo "Restart the trial policy session"
${PREFIX}policyrestart -ha 03000000 > run.out
checkSuccess $?

echo "policycommandcode TPM_CC_NV_Read"
${PREFIX}policycommandcode -ha 03000000 -cc 14e > run.out
checkSuccess $?

echo "Get the policycommandcode read term"
${PREFIX}policygetdigest -ha 03000000 -of tmppr.bin > run.out
checkSuccess $?

echo "Restart the trial policy session"
${PREFIX}policyrestart -ha 03000000 > run.out
checkSuccess $?

echo "Trial Policy OR"
${PREFIX}policyor -ha 03000000 -if tmppw.bin -if tmppr.bin > run.out
checkSuccess $?

echo "Get the policyor result"
${PREFIX}policygetdigest -ha 03000000 -of tmpor.bin > run.out
checkSuccess $?

echo "Flush the trial policy session"
${PREFIX}flushcontext -ha 03000000 > run.out
checkSuccess $?

#
# Test PIN fail
#

# Write the PIN fail index

echo "Creating the NvIndex as PIN Fail, remove authwrite, authread, add ownerread"
${PREFIX}nvdefinespace -hi o -ha 01000000 -ty f -pwdn pass -pol tmpor.bin -at aw -at ar +at or > run.out
checkSuccess $?

echo "Start policy sesion"
${PREFIX}startauthsession -se p > run.out
checkSuccess $?

echo "policycommandcode TPM_CC_NV_Write"
${PREFIX}policycommandcode -ha 03000000 -cc 137 > run.out
checkSuccess $?

echo "Policy OR"
${PREFIX}policyor -ha 03000000 -if tmppw.bin -if tmppr.bin > run.out
checkSuccess $?

echo "Writing count 0, limit 2"
${PREFIX}nvwrite -ha 01000000 -id 0 2 -se0 03000000 01 > run.out
checkSuccess $?

# test the PIN fail index

echo "Using with PolicySecret, first failure case, increments count"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde pas > run.out
checkFailure $?

echo "policycommandcode TPM_CC_NV_Read"
${PREFIX}policycommandcode -ha 03000000 -cc 14e > run.out
checkSuccess $?

echo "Policy OR"
${PREFIX}policyor -ha 03000000 -if tmppw.bin -if tmppr.bin > run.out
checkSuccess $?

echo "Read the index, should be 1 2"
${PREFIX}nvread -ha 01000000 -id 1 2 -se0 03000000 01 > run.out
checkSuccess $?

echo "Using with PolicySecret, second failure case"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde pas > run.out
checkFailure $?

echo "Read the index, owner auth, should be 2 2"
${PREFIX}nvread -ha 01000000 -hia o -id 2 2 > run.out
checkSuccess $?

# cleanup

echo "Undefine the PIN fail index"
${PREFIX}nvundefinespace -ha 01000000 -hi o > run.out
checkSuccess $?

#
# Test PIN pass
#

# Write the PIN pass index

echo "Creating the NvIndex as PIN Pass, remove authwrite, authread, add ownerread"
${PREFIX}nvdefinespace -hi o -ha 01000000 -ty p -pwdn pass -pol tmpor.bin -at aw -at ar +at or > run.out
checkSuccess $?

echo "policycommandcode TPM_CC_NV_Write"
${PREFIX}policycommandcode -ha 03000000 -cc 137 > run.out
checkSuccess $?

echo "Policy OR"
${PREFIX}policyor -ha 03000000 -if tmppw.bin -if tmppr.bin > run.out
checkSuccess $?

echo "Writing count 0, limit 2"
${PREFIX}nvwrite -ha 01000000 -id 0 2 -se0 03000000 01 > run.out
checkSuccess $?

# test the PIN pass index

echo "policycommandcode TPM_CC_NV_Read"
${PREFIX}policycommandcode -ha 03000000 -cc 14e > run.out
checkSuccess $?

echo "Policy OR"
${PREFIX}policyor -ha 03000000 -if tmppw.bin -if tmppr.bin > run.out
checkSuccess $?

echo "Read the index, should be 0 2"
${PREFIX}nvread -ha 01000000 -id 0 2 -se0 03000000 01 > run.out
checkSuccess $?

echo "Read the index, owner auth, should be 0 2"
${PREFIX}nvread -ha 01000000 -hia o -id 0 2 > run.out
checkSuccess $?

echo "Using with PolicySecret, success, increments count"
${PREFIX}policysecret -ha 01000000 -hs 03000000 -pwde pass > run.out
checkSuccess $?

echo "Restart the policy session"
${PREFIX}policyrestart -ha 03000000 > run.out
checkSuccess $?

echo "policycommandcode TPM_CC_NV_Read"
${PREFIX}policycommandcode -ha 03000000 -cc 14e > run.out
checkSuccess $?

echo "Policy OR"
${PREFIX}policyor -ha 03000000 -if tmppw.bin -if tmppr.bin > run.out
checkSuccess $?

echo "Read the index, should be 1 2"
${PREFIX}nvread -ha 01000000 -id 1 2 -se0 03000000 00 > run.out
checkSuccess $?

echo "Read the index, owner auth, should be 1 2"
${PREFIX}nvread -ha 01000000 -hia o -id 1 2 > run.out
checkSuccess $?

# cleanup

echo "Undefine the PIN fail index"
${PREFIX}nvundefinespace -ha 01000000 -hi o > run.out
checkSuccess $?

rm -r tmppw.bin
rm -r tmppr.bin
rm -r tmpor.bin

# ${PREFIX}getcapability  -cap 1 -pr 80000000
# ${PREFIX}getcapability  -cap 1 -pr 02000000
# ${PREFIX}getcapability  -cap 1 -pr 03000000
# ${PREFIX}getcapability  -cap 1 -pr 01000000

