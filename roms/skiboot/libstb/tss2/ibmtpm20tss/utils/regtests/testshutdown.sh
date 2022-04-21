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

# NV Index
# 01000000    WST
# 01000001 WD WST
# 01000002 GL
# 01000003 GL WD

echo ""
echo "TPM Resume (state/state) - suspend"
echo ""

echo "PCR 0 Extend"
${PREFIX}pcrextend -ha 0 -if policies/aaa > run.out
checkSuccess $?

echo "PCR 0 Read"
${PREFIX}pcrread -ha 0 -of tmp1.bin > run.out
checkSuccess $?

echo "Start an HMAC session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

echo "Start an HMAC session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

echo "Save the session context"
${PREFIX}contextsave -ha 02000001 -of tmp.bin > run.out 
checkSuccess $?

echo "Load the signing key"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Context save the signing key"
${PREFIX}contextsave -ha 80000001 -of tmpsk.bin > run.out 
checkSuccess $?

echo "Define index 01000000 with write stclear, read stclear"
${PREFIX}nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 +at rst +at wst > run.out
checkSuccess $?

echo "Define index 01000001 with write stclear, read stclear"
${PREFIX}nvdefinespace -hi o -ha 01000001 -pwdn nnn -sz 16 +at rst +at wst +at wd > run.out
checkSuccess $?

echo "Define index 01000002 with write stclear, read stclear"
${PREFIX}nvdefinespace -hi o -ha 01000002 -pwdn nnn -sz 16 +at rst +at gl > run.out
checkSuccess $?

echo "Define index 01000003 with write stclear, read stclear"
${PREFIX}nvdefinespace -hi o -ha 01000003 -pwdn nnn -sz 16 +at rst +at gl +at wd > run.out
checkSuccess $?

echo "NV write 01000000"
${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa > run.out
checkSuccess $?

echo "NV write 01000001"
${PREFIX}nvwrite -ha 01000001 -pwdn nnn -if policies/aaa > run.out
checkSuccess $?

echo "NV write 01000002"
${PREFIX}nvwrite -ha 01000002 -pwdn nnn -if policies/aaa > run.out
checkSuccess $?

echo "NV write 01000003"
${PREFIX}nvwrite -ha 01000003 -pwdn nnn -if policies/aaa > run.out
checkSuccess $?

echo "Read lock"
${PREFIX}nvreadlock -ha 01000000 -pwdn nnn > run.out
checkSuccess $?

echo "Write lock 01000000"
${PREFIX}nvwritelock -ha 01000000 -pwdn nnn > run.out
checkSuccess $?

echo "Write lock 01000001"
${PREFIX}nvwritelock -ha 01000001 -pwdn nnn > run.out
checkSuccess $?

echo "NV global lock (01000002 and 01000003)"
${PREFIX}nvglobalwritelock -hia p > run.out
checkSuccess $?

echo "NV write 01000000 - should fail"
${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa > run.out
checkFailure $?

echo "NV write 01000001 - should fail"
${PREFIX}nvwrite -ha 01000001 -pwdn nnn -if policies/aaa > run.out
checkFailure $?

echo "NV write 01000002 - should fail"
${PREFIX}nvwrite -ha 01000002 -pwdn nnn -if policies/aaa > run.out
checkFailure $?

echo "NV write 01000003 - should fail"
${PREFIX}nvwrite -ha 01000003 -pwdn nnn -if policies/aaa > run.out
checkFailure $?

echo "Shutdown state"
${PREFIX}shutdown -s > run.out
checkSuccess $?

echo "Power cycle"
${PREFIX}powerup > run.out
checkSuccess $?

echo "Startup state"
${PREFIX}startup -s > run.out
checkSuccess $?

echo "PCR 0 Read"
${PREFIX}pcrread -ha 0 -of tmp2.bin > run.out
checkSuccess $?

echo "Verify that PCR 0 is restored"
diff tmp1.bin tmp2.bin > run.out
checkSuccess $?

echo "Context load the signing key"
${PREFIX}contextload -if tmpsk.bin > run.out 
checkSuccess $?

echo "Signing Key Self Certify"
${PREFIX}certify -hk 80000000 -ho 80000000 -pwdk sig -pwdo sig > run.out
checkSuccess $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000000 > run.out
checkSuccess $?

echo "Signing Key Self Certify - should fail, signing key missing"
${PREFIX}certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -se0 02000000 1 > run.out
checkFailure $?

echo "Load the signing key - should fail, primary key missing"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
checkFailure $?

# Create a platform primary storage key
initprimary
checkSuccess $?

echo "Signing Key Self Certify - should fail, signing key missing"
${PREFIX}certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -se0 02000000 1 > run.out
checkFailure $?

echo "Load the signing key"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Signing Key Self Certify - should fail, session missing"
${PREFIX}certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -se0 02000000 1 > run.out
checkFailure $?

echo "Load the saved session context"
${PREFIX}contextload -if tmp.bin > run.out
checkSuccess $?

echo "Signing Key Self Certify"
${PREFIX}certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -se0 02000001 0 > run.out
checkSuccess $?

echo "NV write 01000000 - should fail, still locked after TPM Resume"
${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa > run.out
checkFailure $?

echo "NV write 01000001 - should fail, still locked after TPM Resume"
${PREFIX}nvwrite -ha 01000001 -pwdn nnn -if policies/aaa > run.out
checkFailure $?

echo "NV write 01000002 - should fail, still locked after TPM Resume"
${PREFIX}nvwrite -ha 01000002 -pwdn nnn -if policies/aaa > run.out
checkFailure $?

echo "NV write 01000003 - should fail, still locked after TPM Resume"
${PREFIX}nvwrite -ha 01000003 -pwdn nnn -if policies/aaa > run.out
checkFailure $?

echo "NV read - should fail, still locked"
${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 16 > run.out
checkFailure $?

echo "Flush the signing key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo ""
echo "TPM Restart (state/clear) - hibernate"
echo ""

echo "Load the signing key"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Context save the signing key"
${PREFIX}contextsave -ha 80000001 -of tmpsk.bin > run.out 
checkSuccess $?

echo "Start a session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

echo "Save the session"
${PREFIX}contextsave -ha 02000000 -of tmp.bin > run.out
checkSuccess $?

echo "Shutdown state"
${PREFIX}shutdown -s > run.out
checkSuccess $?

echo "Power cycle"
${PREFIX}powerup > run.out
checkSuccess $?

echo "Startup clear"
${PREFIX}startup -c > run.out
checkSuccess $?

echo "Load the session"
${PREFIX}contextload -if tmp.bin > run.out
checkSuccess $?

echo "Flush the session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo "Context load the signing key"
${PREFIX}contextload -if tmpsk.bin > run.out 
checkSuccess $?

echo "PCR 0 Read"
${PREFIX}pcrread -ha 0 -halg sha1 -of tmp2.bin > run.out
checkSuccess $?

echo "Verify that PCR 0 is reset"
diff policies/policypcr0.bin tmp2.bin > run.out
checkSuccess $?

echo "NV write 01000000 - unlocked after TPM Restart"
${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa > run.out
checkSuccess $?

echo "NV write 01000001 - should fail, still locked after TPM Restart"
${PREFIX}nvwrite -ha 01000001 -pwdn nnn -if policies/aaa > run.out
checkFailure $?

echo "NV write 01000002 - unlocked after TPM Restart"
${PREFIX}nvwrite -ha 01000002 -pwdn nnn -if policies/aaa > run.out
checkSuccess $?

echo "NV write 01000003 - should fail, still locked after TPM Restart"
${PREFIX}nvwrite -ha 01000003 -pwdn nnn -if policies/aaa > run.out
checkFailure $?

echo "NV read"
${PREFIX}nvread -ha 01000000 -pwdn nnn -sz 16 > run.out
checkSuccess $?

echo "Write lock 01000000"
${PREFIX}nvwritelock -ha 01000000 -pwdn nnn > run.out
checkSuccess $?

echo "NV global lock (01000002 and 01000003)"
${PREFIX}nvglobalwritelock -hia p > run.out
checkSuccess $?

echo "Recreate a platform primary storage key"
${PREFIX}createprimary -hi p -pwdk sto > run.out
checkSuccess $?

echo ""
echo "TPM Reset (clear/clear) - cold boot"
echo ""

echo "Start a session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

echo "Save the session"
${PREFIX}contextsave -ha 02000000 -of tmp.bin > run.out
checkSuccess $?

echo "Shutdown clear"
${PREFIX}shutdown -c > run.out
checkSuccess $?

echo "Power cycle"
${PREFIX}powerup > run.out
checkSuccess $?

echo "Startup clear"
${PREFIX}startup -c > run.out
checkSuccess $?

echo "Load the session - should fail"
${PREFIX}contextload -if tmp.bin > run.out
checkFailure $?

echo "Recreate a platform primary storage key"
${PREFIX}createprimary -hi p -pwdk sto > run.out
checkSuccess $?

echo "NV write - unlocked after TPM Reset"
${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa > run.out
checkSuccess $?

echo "NV write 01000000 - unlocked after TPM Reset"
${PREFIX}nvwrite -ha 01000000 -pwdn nnn -if policies/aaa > run.out
checkSuccess $?

echo "NV write 01000001 - should fail, still locked after TPM Reset"
${PREFIX}nvwrite -ha 01000001 -pwdn nnn -if policies/aaa > run.out
checkFailure $?

echo "NV write 01000002 - unlocked after TPM Reset"
${PREFIX}nvwrite -ha 01000002 -pwdn nnn -if policies/aaa > run.out
checkSuccess $?

echo "NV write 01000003 - should fail, still locked after TPM Reset"
${PREFIX}nvwrite -ha 01000003 -pwdn nnn -if policies/aaa > run.out
checkFailure $?

# cleanup 

echo "NV Undefine Space 01000000"
${PREFIX}nvundefinespace -hi p -ha 01000000 > run.out
checkSuccess $?

echo "NV Undefine Space 01000001"
${PREFIX}nvundefinespace -hi p -ha 01000001 > run.out
checkSuccess $?

echo "NV Undefine Space 01000002"
${PREFIX}nvundefinespace -hi p -ha 01000002 > run.out
checkSuccess $?

echo "NV Undefine Space 01000003"
${PREFIX}nvundefinespace -hi p -ha 01000003 > run.out
checkSuccess $?

# shutdown removes the session
rm h02000000.bin
rm tmpsk.bin

exit


# ${PREFIX}getcapability  -cap 1 -pr 80000000
# ${PREFIX}getcapability  -cap 1 -pr 02000000
# ${PREFIX}getcapability  -cap 1 -pr 01000000
