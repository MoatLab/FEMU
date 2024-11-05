REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: testhierarchy.bat 507 2016-03-08 22:35:47Z kgoldman $	#
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
echo "Hierarchy Change Auth"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Generate a random authorization value"
%TPM_EXE_PATH%getrandom -by 32 -nz -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    echo "Change platform hierarchy auth %%~S"
    %TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create a primary storage key - should fail"
    %TPM_EXE_PATH%createprimary -hi p -pwdk 111 > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "Create a primary storage key"
    %TPM_EXE_PATH%createprimary -hi p -pwdk 111 -pwdp ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the primary key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Change platform hierarchy auth back to null %%~S"
    %TPM_EXE_PATH%hierarchychangeauth -hi p -pwda ppp %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create a primary storage key"
    %TPM_EXE_PATH%createprimary -pwdk 111 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the primary key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

)

echo ""

for %%S in ("" "-se0 02000000 1") do (

    echo "Change platform hierarchy auth, new auth from file %%~S"
    %TPM_EXE_PATH%hierarchychangeauth -hi p -pwdni tmp.bin %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create a primary storage key - should fail"
    %TPM_EXE_PATH%createprimary -hi p -pwdk 111 > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "Create a primary storage key, auth from file"
    %TPM_EXE_PATH%createprimary -hi p -pwdk 111 -pwdpi tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the primary key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Change platform hierarchy auth back to null, auth from file %%~S"
    %TPM_EXE_PATH%hierarchychangeauth -hi p -pwdai tmp.bin %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create a primary storage key"
    %TPM_EXE_PATH%createprimary -pwdk 111 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the primary key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Hierarchy Change Auth with bind"
echo ""

echo "Change platform hierarchy auth"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a primary storage key - should fail"
%TPM_EXE_PATH%createprimary -hi p -pwdk 111 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Create a primary storage key"
%TPM_EXE_PATH%createprimary -hi p -pwdk 111 -pwdp ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the primary key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start an HMAC auth session, bind to platform hierarchy"
%TPM_EXE_PATH%startauthsession -se h -bi 4000000c -pwdb ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Change platform hierarchy auth back to null"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwda ppp -se0 02000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a primary storage key"
%TPM_EXE_PATH%createprimary -pwdk 111 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the primary key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Hierarchy Control"
echo ""

echo "Enable the owner hierarchy"
%TPM_EXE_PATH%hierarchycontrol -hi p -he o > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Change the platform hierarchy password"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Enable the owner hierarchy - no platform hierarchy password, should fail"
%TPM_EXE_PATH%hierarchycontrol -hi p -he o > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Enable the owner hierarchy using platform hierarchy password"
%TPM_EXE_PATH%hierarchycontrol -hi p -he o -pwda ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a primary key in the owner hierarchy - bad password, should fail"
%TPM_EXE_PATH%createprimary -hi o -pwdp xxx > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Create a primary key in the owner hierarchy"
%TPM_EXE_PATH%createprimary -hi o > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Disable the owner hierarchy using platform hierarchy password"
%TPM_EXE_PATH%hierarchycontrol -hi p -he o -pwda ppp -state 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a primary key in the owner hierarchy, disabled, should fail"
%TPM_EXE_PATH%createprimary -hi o > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Enable the owner hierarchy using platform hierarchy password"
%TPM_EXE_PATH%hierarchycontrol -hi p -he o -pwda ppp -state 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a primary key in the owner hierarchy"
%TPM_EXE_PATH%createprimary -hi o > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Remove the platform hierarchy password"
%TPM_EXE_PATH%hierarchychangeauth -hi p -pwda ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the primary key in the owner hierarchy"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Clear"
echo ""

echo "Set storage hierarchy auth"
%TPM_EXE_PATH%hierarchychangeauth -hi o -pwdn ooo > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a primary key - storage hierarchy"
%TPM_EXE_PATH%createprimary -hi o -pwdp ooo > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Read the public part"
%TPM_EXE_PATH%readpublic -ho 80000001  > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "ClearControl disable"
%TPM_EXE_PATH%clearcontrol -hi p -state 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clear - should fail"
%TPM_EXE_PATH%clear -hi p > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "ClearControl enable"
%TPM_EXE_PATH%clearcontrol -hi p -state 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Clear"
%TPM_EXE_PATH%clear -hi p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Read the public part - should fail"
%TPM_EXE_PATH%readpublic -ho 80000001  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Create a primary key - old owner password should fail"
%TPM_EXE_PATH%createprimary -hi o -pwdp ooo > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Create a primary key"
%TPM_EXE_PATH%createprimary -hi o > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the primary key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM cleanup
rm -f tmp.bin

exit /B 0

REM getcapability  -cap 1 -pr 80000000
REM getcapability  -cap 1 -pr 02000000
