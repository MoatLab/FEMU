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

for %%B in (2048 3072) do (

    echo "generate the %%B encryption key with openssl"
    openssl genrsa -out tmpkeypairrsa%%B.pem -aes256 -passout pass:rrrr 2048

    echo "Convert key pair to plaintext DER format"
    openssl rsa -inform pem -outform der -in tmpkeypairrsa%%B.pem -out tmpkeypairrsa%%B.der -passin pass:rrrr > run.out
)

echo ""
echo "RSA decryption key"
echo ""

for %%B in (2048 3072) do (

    echo "Load the RSA %%B decryption key under the primary key"
    %TPM_EXE_PATH%load -hp 80000000 -ipr derrsa%%Bpriv.bin -ipu derrsa%%Bpub.bin -pwdp sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "RSA encrypt with the %%B encryption key"
    %TPM_EXE_PATH%rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "RSA decrypt with the %%B decryption key"
    %TPM_EXE_PATH%rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin -pwdk dec > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Verify the decrypt result"
    tail --bytes=3 dec.bin > tmp.bin
    diff policies/aaa tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the  %%B decryption key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

)

echo ""
echo "RSA decryption key to sign with OID"
echo ""

for %%B in (2048 3072) do (

    echo "Load the RSA %%B decryption key"
    %TPM_EXE_PATH%load -hp 80000000 -ipu derrsa%%Bpub.bin -ipr derrsa%%Bpriv.bin -pwdp sto > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    set HSIZ=20 32 48 64
    set HALG=%ITERATE_ALGS%

    set i=0
    for %%a in (!HSIZ!) do set /A i+=1 & set HSIZ[!i!]=%%a
    set i=0
    for %%b in (!HALG!) do set /A i+=1 & set HALG[!i!]=%%b
    set L=!i!

    for /L %%i in (1,1,!L!) do (

    	echo "Decrypt/Sign with a caller specified OID - !HALG[%%i]!"
	%TPM_EXE_PATH%rsadecrypt -hk 80000001 -pwdk dec -ie policies/!HALG[%%i]!aaa.bin -od tmpsig.bin -oid !HALG[%%i]! > run.out
	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
	)

    	echo "Encrypt/Verify - !HALG[%%i]!"
    	%TPM_EXE_PATH%rsaencrypt -hk 80000001 -id tmpsig.bin -oe tmpmsg.bin > run.out
    	IF !ERRORLEVEL! NEQ 0 (
    	    exit /B 1
    	)

    	echo "Verify Result - !HALG[%%i]! !HSIZ[%%i]! bytes"
    	tail --bytes=!HSIZ[%%i]! tmpmsg.bin > tmpdig.bin
    	diff tmpdig.bin policies/!HALG[%%i]!aaa.bin > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
	)

    )

    echo "Flush the RSA %%B signing key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    checkSuccess $?

)

echo ""
echo "Import PEM RSA encryption key"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%B in (2048 3072) do (

    for %%S in ("" "-se0 02000000 1") do (

    	echo "Import the %%B encryption key under the primary key"
    	%TPM_EXE_PATH%importpem -hp 80000000 -den -pwdp sto -ipem tmpkeypairrsa%%B.pem -pwdk rrrr -opu tmppub.bin -opr tmppriv.bin > run.out
    	IF !ERRORLEVEL! NEQ 0 (
       	   exit /B 1
	)

    	echo "Load the TPM encryption key"
    	%TPM_EXE_PATH%load -hp 80000000 -pwdp sto -ipu tmppub.bin -ipr tmppriv.bin > run.out
    	IF !ERRORLEVEL! NEQ 0 (
       	   exit /B 1
	)

    	echo "Sign the message %%~S - should fail"
    	%TPM_EXE_PATH%sign -hk 80000001 -pwdk rrrr -if policies/aaa -os tmpsig.bin %%~S > run.out
    	IF !ERRORLEVEL! EQU 0 (
       	   exit /B 1
	)

    	echo "RSA encrypt with the encryption key"
    	%TPM_EXE_PATH%rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
    	IF !ERRORLEVEL! NEQ 0 (
       	   exit /B 1
	)

    	echo "RSA decrypt with the decryption key %%~S"
    	%TPM_EXE_PATH%rsadecrypt -hk 80000001 -pwdk rrrr -ie enc.bin -od dec.bin %%~S > run.out
    	IF !ERRORLEVEL! NEQ 0 (
       	   exit /B 1
	)

    	echo "Verify the decrypt result"
    	tail --bytes=3 dec.bin > tmp.bin
    	diff policies/aaa tmp.bin > run.out
    	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
        )

	echo "Flush the encryption key"
    	%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    	IF !ERRORLEVEL! NEQ 0 (
       	   exit /B 1
	)
    )
)

echo "Flush the session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Loadexternal DER encryption key"
echo ""

for %%B in (2048 3072) do (

    echo "Start an HMAC auth session"
    %TPM_EXE_PATH%startauthsession -se h > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    for %%S in ("" "-se0 02000000 1") do (

    	echo "Load the openssl key pair in the NULL hierarchy 80000001"
    	%TPM_EXE_PATH%loadexternal -den -ider tmpkeypairrsa%%B.der -pwdk rrrr > run.out
    	IF !ERRORLEVEL! NEQ 0 (
       	   exit /B 1
	)

    	echo "RSA encrypt with the encryption key"
    	%TPM_EXE_PATH%rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
    	IF !ERRORLEVEL! NEQ 0 (
       	   exit /B 1
	)

    	echo "RSA decrypt with the decryption key %%~S"
    	%TPM_EXE_PATH%rsadecrypt -hk 80000001 -pwdk rrrr -ie enc.bin -od dec.bin %%~S > run.out
    	IF !ERRORLEVEL! NEQ 0 (
       	   exit /B 1
	)

    	echo "Verify the decrypt result"
    	tail --bytes=3 dec.bin > tmp.bin
    	diff policies/aaa tmp.bin > run.out
    	IF !ERRORLEVEL! NEQ 0 (
       	   exit /B 1
        )

    	echo "Flush the encryption key"
    	%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    	IF !ERRORLEVEL! NEQ 0 (
       	   exit /B 1
	)
    )

    echo "Flush the session"
    %TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )
)

echo ""
echo "Encrypt with OpenSSL OAEP, decrypt with TPM"
echo ""

echo "Create OAEP encryption key"
%TPM_EXE_PATH%create -hp 80000000 -pwdp sto -deo -kt f -kt p -halg sha1 -opr tmpprivkey.bin -opu tmppubkey.bin -opem tmppubkey.pem > run.out	
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load encryption key at 80000001"
%TPM_EXE_PATH%load -hp 80000000 -pwdp sto -ipr tmpprivkey.bin -ipu tmppubkey.bin  > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Encrypt using OpenSSL and the PEM public key"
openssl rsautl -oaep -encrypt -inkey tmppubkey.pem -pubin -in policies/aaa -out enc.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Decrypt using TPM key at 80000001"
%TPM_EXE_PATH%rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the decrypt result"
diff policies/aaa dec.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the encryption key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Child RSA decryption key RSAES"
echo ""

echo "Create RSAES encryption key"
%TPM_EXE_PATH%create -hp 80000000 -pwdp sto -dee -opr deepriv.bin -opu deepub.bin > run.out	
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load encryption key at 80000001"
%TPM_EXE_PATH%load -hp 80000000 -pwdp sto -ipr deepriv.bin -ipu deepub.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "RSA encrypt with the encryption key"
%TPM_EXE_PATH%rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "RSA decrypt with the decryption key"
%TPM_EXE_PATH%rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the decrypt result"
tail --bytes=3 dec.bin > tmp.bin
diff policies/aaa tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the encryption key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Primary RSA decryption key RSAES"
echo ""

echo "Create Primary RSAES encryption key"
%TPM_EXE_PATH%createprimary -hi p -dee -halg sha256 -opem tmppubkey.pem > run.out	
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "RSA encrypt with the encryption key"
%TPM_EXE_PATH%rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "RSA decrypt with the decryption key"
%TPM_EXE_PATH%rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the decrypt result"
tail --bytes=3 dec.bin > tmp.bin
diff policies/aaa tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the encryption key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Primary Create Loaded RSA decryption key RSAES"
echo ""

echo "CreateLoaded primary key, storage parent 80000001"
%TPM_EXE_PATH%createloaded -hp 40000001 -dee > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "RSA encrypt with the encryption key"
%TPM_EXE_PATH%rsaencrypt -hk 80000001 -id policies/aaa -oe enc.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "RSA decrypt with the decryption key"
%TPM_EXE_PATH%rsadecrypt -hk 80000001 -ie enc.bin -od dec.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
echo "Verify the decrypt result"
tail --bytes=3 dec.bin > tmp.bin
diff policies/aaa tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the encryption key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM cleanup

rm -f tmp.bin
rm -f enc.bin
rm -f dec.bin
rm -f deepub.bin
rm -f deepriv.bin
rm -f tmpmsg.bin
rm -f tmpdig.bin
rm -f tmpsig.bin
rm -f tmpkeypairrsa2048.der
rm -f tmpkeypairrsa2048.pem
rm -f tmpkeypairrsa3072.der
rm -f tmpkeypairrsa3072.pem
rm -f tmppubkey.bin
rm -f tmppubkey.pem
rm -f tmpprivkey.bin

exit /B 0

REM  getcapability -cap 1 -pr 80000000
REM  getcapability -cap 1 -pr 02000000
REM 
REM  flushcontext -ha 80000001
 
