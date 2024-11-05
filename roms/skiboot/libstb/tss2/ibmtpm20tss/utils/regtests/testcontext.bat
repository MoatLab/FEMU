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
echo "Basic Context"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto -se0 02000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature"
%TPM_EXE_PATH%verifysignature -hk 80000001 -halg sha256 -if msg.bin -is sig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Save context for the key"
%TPM_EXE_PATH%contextsave -ha 80000001 -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign to verify that the original key is not flushed"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the original key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign with original key  - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Load context"
%TPM_EXE_PATH%contextload -if tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign with the loaded context"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Save context for the session"
%TPM_EXE_PATH%contextsave -ha 02000000 -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign with the saved session context - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 1 > run.out
IF !ERRORLEVEL! EQU 0 (
    exit /B 1
)

echo "Load context for the session"
%TPM_EXE_PATH%contextload -if tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Sign with the saved session context"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 1 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the loaded context"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo ""
echo "Context Public Key for Salt"
echo ""

echo "Load the storage key at 80000001"
%TPM_EXE_PATH%load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Save context for the storage key at 80000001"
%TPM_EXE_PATH%contextsave -ha 80000001 -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Load context at 80000002"
%TPM_EXE_PATH%contextload -if tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the original key at 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Start an HMAC auth session at 02000000 using the storage key 80000002 salt"
%TPM_EXE_PATH%startauthsession -se h -hs 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Load the signing key under the primary key at 80000001"
%TPM_EXE_PATH%load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Sign a digest"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the signing key at 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the salt key at 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo ""
echo "Context Primary Key"
echo ""

echo "Save context for the primary key at 80000000"
%TPM_EXE_PATH%contextsave -ha 80000000 -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Load context primary key at 80000001"
%TPM_EXE_PATH%contextload -if tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Load the signing key at 80000002 under the primary key at 80000001"
%TPM_EXE_PATH%load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the signing key at 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the primary key at 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

exit /B 0

REM getcapability  -cap 1 -pr 80000000
REM getcapability  -cap 1 -pr 02000000
