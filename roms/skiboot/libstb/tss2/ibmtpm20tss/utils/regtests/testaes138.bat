REM #################################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #	$Id: testaes.sh 714 2016-08-11 21:46:03Z kgoldman $			#
REM #										#
REM # (c) Copyright IBM Corporation 2015, 2016					#
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
echo "AES symmetric key"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    echo "Load the symmetric cipher key under the primary key %%~S"
    %TPM_EXE_PATH%load -hp 80000000 -ipr despriv.bin -ipu despub.bin -pwdp sto %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Encrypt using the symmetric cipher key %%~S"
    %TPM_EXE_PATH%encryptdecrypt -2 -hk 80000001 -if msg.bin -of enc.bin -pwdk aes %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Decrypt using the symmetric cipher key %%~S"
    %TPM_EXE_PATH%encryptdecrypt -2 -hk 80000001 -d -if enc.bin -of dec.bin -pwdk aes %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Verify the decrypt result"
    diff msg.bin dec.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Encrypt using the symmetric cipher key 0 length message %%~S"
    %TPM_EXE_PATH%encryptdecrypt -2 -hk 80000001 -if zero.bin -of enc.bin -pwdk aes %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Decrypt using the symmetric cipher key %%~S"
    %TPM_EXE_PATH%encryptdecrypt -2 -hk 80000001 -d -if enc.bin -of dec.bin -pwdk aes %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Verify the decrypt result"
    diff zero.bin dec.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )
    
    echo "Flush the symmetric cipher key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create a primary symmetric cipher key %%~S"
    %TPM_EXE_PATH%createprimary -des -pwdk aesp %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )
 
    echo "Encrypt using the symmetric cipher primary key %%~S"
    %TPM_EXE_PATH%encryptdecrypt -2 -hk 80000001 -if msg.bin -of enc.bin -pwdk aesp %%~S> run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Decrypt using the symmetric cipher primary key %%~S"
    %TPM_EXE_PATH%encryptdecrypt -2 -hk 80000001 -d -if enc.bin -of dec.bin -pwdk aesp %%~S> run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Verify the decrypt result"
    diff msg.bin dec.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the symmetric cipher key"
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

REM %TPM_EXE_PATH%getcapability -cap 1 -pr 80000000
REM %TPM_EXE_PATH%getcapability -cap 1 -pr 02000000
