REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #										#
REM # (c) Copyright IBM Corporation 2019 - 2020					#
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
echo "Attestation - rev 155"
echo ""

rem # 80000001 RSA signing key
rem # 80000002 ECC signing key

echo "Load the RSA signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the ECC signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signeccpriv.bin -ipu signeccpub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Define Space"
%TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read Public, unwritten Name"
%TPM_EXE_PATH%nvreadpublic -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV write"
%TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if msg.bin -v > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start an HMAC session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    for %%H in (%ITERATE_ALGS%) do (

	for %%A in (rsa ecc) do (

		IF "%%A" == "rsa" (
		   set K=80000001
		)
		IF "%%A" == "ecc" (
		   set K=80000002
		)		

	    echo "NV Certify a digest %%H %%A %%~S"
	    %TPM_EXE_PATH%nvcertify -ha 01000000 -pwdn nnn -hk !K! -pwdk sig -halg %%H -sz 0 %%~S -os sig.bin -oa tmp.bin -salg %%A -od tmpdigest1.bin > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Verify the %%A signature %%H"
	    %TPM_EXE_PATH%verifysignature -hk !K! -halg %%H -if tmp.bin -is sig.bin > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "NV read"
	    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -of tmpdata.bin > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Digest the hashed and certified NV data %%H"
	    %TPM_EXE_PATH%hash -halg %%H -if tmpdata.bin -oh tmpdigest2.bin
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	    echo "Check the digest %%H results"
	    diff tmpdigest1.bin tmpdigest2.bin
	    IF !ERRORLEVEL! NEQ 0 (
	       exit /B 1
	    )

	)
    )
)

echo "Flush the RSA attestation key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the ECC attestation key"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine Space"
%TPM_EXE_PATH%nvundefinespace -hi o -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rem # cleanup

rm tmpdigest1.bin
rm tmpdata.bin
rm tmpdigest2.bin

exit /B 0
