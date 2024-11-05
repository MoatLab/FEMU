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

REM 01000000    WST
REM 01000001 WD WST
REM 01000002 GL
REM 01000003 GL WD

setlocal enableDelayedExpansion

echo ""
echo "TPM Resume (state/state) - suspend"
echo ""

echo "PCR 0 Extend"
%TPM_EXE_PATH%pcrextend -ha 0 -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "PCR 0 Read"
%TPM_EXE_PATH%pcrread -ha 0 -of tmp1.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start an HMAC session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start an HMAC session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Save the session context"
%TPM_EXE_PATH%contextsave -ha 02000001 -of tmp.bin > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Context save the signing key"
%TPM_EXE_PATH%contextsave -ha 80000001 -of tmpsk.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Define index 01000000 with write stclear, read stclear"
%TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 +at rst +at wst > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Define index 01000001 with write stclear, read stclear"
%TPM_EXE_PATH%nvdefinespace -hi o -ha 01000001 -pwdn nnn -sz 16 +at rst +at wst +at wd > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Define index 01000002 with write stclear, read stclear"
%TPM_EXE_PATH%nvdefinespace -hi o -ha 01000002 -pwdn nnn -sz 16 +at rst +at gl > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Define index 01000003 with write stclear, read stclear"
%TPM_EXE_PATH%nvdefinespace -hi o -ha 01000003 -pwdn nnn -sz 16 +at rst +at gl +at wd > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write 01000000"
%TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write 01000001"
%TPM_EXE_PATH%nvwrite -ha 01000001 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write 01000002"
%TPM_EXE_PATH%nvwrite -ha 01000002 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write 01000003"
%TPM_EXE_PATH%nvwrite -ha 01000003 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Read lock"
%TPM_EXE_PATH%nvreadlock -ha 01000000 -pwdn nnn > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Write lock 01000000"
%TPM_EXE_PATH%nvwritelock -ha 01000000 -pwdn nnn > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Write lock 01000001"
%TPM_EXE_PATH%nvwritelock -ha 01000001 -pwdn nnn > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV global lock (01000002 and 01000003)"
%TPM_EXE_PATH%nvglobalwritelock -hia p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write 01000001 - should fail"
%TPM_EXE_PATH%nvwrite -ha 01000001 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "NV write 01000002 - should fail"
%TPM_EXE_PATH%nvwrite -ha 01000002 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "NV write 01000003 - should fail"
%TPM_EXE_PATH%nvwrite -ha 01000003 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Shutdown state"
%TPM_EXE_PATH%shutdown -s > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Power cycle"
%TPM_EXE_PATH%powerup > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Startup state"
%TPM_EXE_PATH%startup -s > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "PCR 0 Read"
%TPM_EXE_PATH%pcrread -ha 0 -of tmp2.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify that PCR 0 is restored"
diff tmp1.bin tmp2.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Context load the signing key"
%TPM_EXE_PATH%contextload -if tmpsk.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Signing Key Self Certify"
%TPM_EXE_PATH%certify -hk 80000000 -ho 80000000 -pwdk sig -pwdo sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Signing Key Self Certify - should fail, signing key missing"
%TPM_EXE_PATH%certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -se0 02000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Load the signing key - should fail, primary key missing"
%TPM_EXE_PATH%load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Create a platform primary storage key"
%TPM_EXE_PATH%createprimary -hi p -pwdk sto -pol policies/zerosha256.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Signing Key Self Certify - should fail, signing key missing"
%TPM_EXE_PATH%certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -se0 02000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Load the signing key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Signing Key Self Certify - should fail, session missing"
%TPM_EXE_PATH%certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -se0 02000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Load the saved session context"
%TPM_EXE_PATH%contextload -if tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Signing Key Self Certify"
%TPM_EXE_PATH%certify -hk 80000001 -ho 80000001 -pwdk sig -pwdo sig -se0 02000001 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write 01000000 - should fail, still locked after TPM Resume"
%TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "NV write 01000001 - should fail, still locked after TPM Resume"
%TPM_EXE_PATH%nvwrite -ha 01000001 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "NV write 01000002 - should fail, still locked after TPM Resume"
%TPM_EXE_PATH%nvwrite -ha 01000002 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "NV write 01000003 - should fail, still locked after TPM Resume"
%TPM_EXE_PATH%nvwrite -ha 01000003 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "NV read - should fail, still locked"
%TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 16 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "TPM Restart (state/clear) - hibernate"
echo ""

echo "Load the signing key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Context save the signing key"
%TPM_EXE_PATH%contextsave -ha 80000001 -of tmpsk.bin > run.out 
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Start a session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Save the session"
%TPM_EXE_PATH%contextsave -ha 02000000 -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Shutdown state"
%TPM_EXE_PATH%shutdown -s > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Power cycle"
%TPM_EXE_PATH%powerup > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Startup clear"
%TPM_EXE_PATH%startup -c > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the session"
%TPM_EXE_PATH%contextload -if tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Context load the signing key"
%TPM_EXE_PATH%contextload -if tmpsk.bin > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "PCR 0 Read"
%TPM_EXE_PATH%pcrread -ha 0 -halg sha1 -of tmp2.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify that PCR 0 is reset"
diff policies/policypcr0.bin tmp2.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write 01000000 - unlocked after TPM Restart"
%TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write 01000001 - should fail, still locked after TPM Restart"
%TPM_EXE_PATH%nvwrite -ha 01000001 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "NV write 01000002 - unlocked after TPM Restart"
%TPM_EXE_PATH%nvwrite -ha 01000002 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write 01000003 - should fail, still locked after TPM Restart"
%TPM_EXE_PATH%nvwrite -ha 01000003 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "NV read"
%TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 16 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Write lock 01000000"
%TPM_EXE_PATH%nvwritelock -ha 01000000 -pwdn nnn > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV global lock (01000002 and 01000003)"
%TPM_EXE_PATH%nvglobalwritelock -hia p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Recreate a platform primary storage key"
%TPM_EXE_PATH%createprimary -hi p -pwdk sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "TPM Reset (clear/clear) - cold boot"
echo ""

echo "Start a session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Save the session"
%TPM_EXE_PATH%contextsave -ha 02000000 -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Shutdown clear"
%TPM_EXE_PATH%shutdown -c > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Power cycle"
%TPM_EXE_PATH%powerup > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Startup clear"
%TPM_EXE_PATH%startup -c > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the session - should fail"
%TPM_EXE_PATH%contextload -if tmp.bin > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Recreate a platform primary storage key"
%TPM_EXE_PATH%createprimary -hi p -pwdk sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write 01000000 - unlocked after TPM Reset"
%TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write 01000001 - should fail, still locked after TPM Reset"
%TPM_EXE_PATH%nvwrite -ha 01000001 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "NV write 01000002 - unlocked after TPM Reset"
%TPM_EXE_PATH%nvwrite -ha 01000002 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write 01000003 - should fail, still locked after TPM Reset"
%TPM_EXE_PATH%nvwrite -ha 01000003 -pwdn nnn -if policies/aaa > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "NV Undefine Space 01000000"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine Space 01000001"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine Space 01000002"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine Space 01000003"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000003 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM shutdown removes the session
rm h02000000.bin
rm tmpsk.bin

exit /B 0

REM getcapability  -cap 1 -pr 80000000
REM getcapability  -cap 1 -pr 02000000
REM getcapability  -cap 1 -pr 01000000
