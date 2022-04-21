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

REM Primary storage key at 80000000 password sto
REM storage key at 80000001 password sto

echo ""
echo "RSA Storage key"
echo ""

echo "Load the RSA storage key 80000001 under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%N in (%ITERATE_ALGS%) do (

    for %%S in ("" "-se0 02000000 1") do (

        echo "Create an unrestricted signing key under the RSA storage key 80000001 %%N %%~S"
        %TPM_EXE_PATH%create -hp 80000001 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 111 -nalg %%N %%~S > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )
    
        echo "Load the signing key 80000002 under the storage key 80000001 %%~S"
        %TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto %%~S > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )
    
	echo "Read the signing key 80000002 public area"
	%TPM_EXE_PATH%readpublic -ho 80000002 -opu tmppub2.bin > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )

        echo "Flush the signing key 80000002"
        %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )
    
        echo "Load external just the storage key public part 80000002 %%N"
        %TPM_EXE_PATH%loadexternal -halg sha256 -nalg %%N -ipu storersa2048pub.bin > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )
    
        echo "Flush the public key 80000002"
        %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )
    
	echo "Load external, signing key public part 80000002 %%N"
	%TPM_EXE_PATH%loadexternal -halg sha256 -nalg %%N -ipu tmppub2.bin > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )

	echo "Flush the public key 80000002"
	%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
        IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
        )
    )
)

echo "Flush the RSA storage key 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "ECC Storage key"
echo ""

echo "Load ECC the storage key 80000001 under the primary key 80000000"
%TPM_EXE_PATH%load -hp 80000000 -ipr storeeccpriv.bin -ipu storeeccpub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%N in (%ITERATE_ALGS%) do (

    for %%S in ("" "-se0 02000000 1") do (

	echo "Create an unrestricted signing key under the ECC storage key 80000001 %%N %%~S"
	%TPM_EXE_PATH%create -hp 80000001 -si -kt f -kt p -ecc nistp256 -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 111 -nalg %%N %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
   	    exit /B 1
	)

	echo "Load the ECC signing key 80000002 under the ECC storage key 80000001 %%~S"
	%TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto %%~S> run.out
	IF !ERRORLEVEL! NEQ 0 (
   	    exit /B 1
	)

	echo "Read the signing key 80000002 public area"
	%TPM_EXE_PATH%readpublic -ho 80000002 -opu tmppub2.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
   	    exit /B 1
	)

	echo "Flush the signing key 80000002"
	%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
	IF !ERRORLEVEL! NEQ 0 (
   	    exit /B 1
	)

	echo "Load external, storage key public part 80000002 %%N"
	%TPM_EXE_PATH%loadexternal -halg sha256 -nalg %%N -ipu storeeccpub.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
   	    exit /B 1
	)

	echo "Flush the public key 80000002"
	%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
	IF !ERRORLEVEL! NEQ 0 (
   	    exit /B 1
	)

	echo "Load external, signing key public part 80000002 %%N"
	%TPM_EXE_PATH%loadexternal -halg sha256 -nalg %%N -ipu tmppub2.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
   	    exit /B 1
	)

	echo "Flush the signing key 80000002"
	%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
	IF !ERRORLEVEL! NEQ 0 (
   	    exit /B 1
	)
    )
)

echo "Flush the ECC storage key 80000001 "
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

rm -f tmppub2.bin
rm -f tmppub.bin
rm -f tmppriv.bin
rm -f tmpsig.bin

exit /B 0

REM getcapability  -cap 1 -pr 80000000
REM getcapability  -cap 1 -pr 02000000
