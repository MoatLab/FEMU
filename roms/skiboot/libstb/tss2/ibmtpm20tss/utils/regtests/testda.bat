REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: testda.bat 1278 2018-07-23 21:20:42Z kgoldman $		#
REM #										#
REM # (c) Copyright IBM Corporation 2015					#
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
echo "DA Logic"
echo ""

echo "Create an signing key with DA protection"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sig -da > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Set DA recovery time to 0, disables DA"
%TPM_EXE_PATH%dictionaryattackparameters -nrt 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest with bad password - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -pwdk xxx > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Sign a digest with good password, no lockout"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Set DA recovery time to 120 sec, enables DA"
%TPM_EXE_PATH%dictionaryattackparameters -nrt 120 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest with bad password - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -pwdk xxx > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Sign a digest with good password, lockout - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -pwdk sig > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Reset DA lock"
%TPM_EXE_PATH%dictionaryattacklockreset > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest with good password"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Set DA recovery time to 120 sec, enables DA, max tries 2"
%TPM_EXE_PATH%dictionaryattackparameters -nrt 120 -nmt 2 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Sign a digest with bad password - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -pwdk xxx > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Sign a digest with good password, no lockout yet"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Sign a digest with bad password - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -pwdk xxx > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Sign a digest with good password, lockout - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -pwdk sig > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Reset DA lock"
%TPM_EXE_PATH%dictionaryattacklockreset > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest with good password, no lockout"
%TPM_EXE_PATH%sign -hk 80000001 -if msg.bin -os sig.bin -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Set DA recovery time to 0, disables DA"
%TPM_EXE_PATH%dictionaryattackparameters -nrt 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Lockout Auth"
echo ""

echo "Change lockout auth"
%TPM_EXE_PATH%hierarchychangeauth -hi l -pwdn lll > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Reset DA lock with good password"
%TPM_EXE_PATH%dictionaryattacklockreset -pwd lll > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Set DA recovery time to 0 with good password"
%TPM_EXE_PATH%dictionaryattackparameters -nrt 0 -pwd lll > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clear lockout auth"
%TPM_EXE_PATH%hierarchychangeauth -hi l -pwda lll > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Set DA recovery time to 0"
%TPM_EXE_PATH%dictionaryattackparameters -nrt 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Reset DA lock"
%TPM_EXE_PATH%dictionaryattacklockreset > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

exit /B 0

REM getcapability -cap 1 -pr 80000000
