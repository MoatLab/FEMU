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
echo "Salt Session - Load"
echo ""

for %%A in ("-rsa 2048" "-rsa 3072" "-ecc nistp256") do (

    for %%H in (%ITERATE_ALGS%) do (

	REM In general a storage key can be used.  A decryption key is
	REM used here because the hash algorithm doesn't have to match
	REM that of the parent.

    	echo "Create a %%A %%H storage key under the primary key "
	%TPM_EXE_PATH%create -hp 80000000 -nalg %%H -halg %%H %%~A -deo -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 222 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)
	
	echo "Load the %%A storage key 80000001 under the primary key"
	%TPM_EXE_PATH%load -hp 80000000 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)
	
	echo "Start a %%A salted HMAC auth session"
	%TPM_EXE_PATH%startauthsession -se h -hs 80000001 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)
	
	echo "Create a signing key using the salt"
	%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 333 -se0 02000000 0 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)
	
	echo "Flush the storage key"
	%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)
    )
)

echo ""
echo "Salt Session - Load External"
echo ""

echo "Create RSA and ECC key pairs in PEM format using openssl"
  
openssl genrsa -out tmpkeypairrsa.pem -aes256 -passout pass:rrrr 2048 > run.out
openssl ecparam -name prime256v1 -genkey -noout -out tmpkeypairecc.pem > run.out

echo "Convert key pair to plaintext DER format"

openssl rsa -inform pem -outform der -in tmpkeypairrsa.pem -out tmpkeypairrsa.der -passin pass:rrrr > run.out
openssl ec -inform pem -outform der -in tmpkeypairecc.pem -out tmpkeypairecc.der -passin pass:rrrr > run.out

for %%H in (%ITERATE_ALGS%) do (

    echo "Load the RSA openssl key pair in the NULL hierarchy 80000001 - %%H"
    %TPM_EXE_PATH%loadexternal -halg %%H -st -ider tmpkeypairrsa.der > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Start a salted HMAC auth session"
    %TPM_EXE_PATH%startauthsession -se h -hs 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create a signing key using the salt"
    %TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 333 -se0 02000000 0 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the storage key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

)

for %%H in (%ITERATE_ALGS%) do (

    echo "Load the ECC openssl key pair in the NULL hierarchy 80000001 - %%H"
    %TPM_EXE_PATH%loadexternal -ecc -halg %%H -st -ider tmpkeypairecc.der > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Start a salted HMAC auth session"
    %TPM_EXE_PATH%startauthsession -se h -hs 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create a signing key using the salt"
    %TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 333 -se0 02000000 0 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the storage key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )
)

echo ""
echo "Salt Session - CreatePrimary storage key"
echo ""

for %%H in (%ITERATE_ALGS%) do (
    
    echo "Create a primary storage key - %%H"
    %TPM_EXE_PATH%createprimary -nalg %%H -hi p > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Start a salted HMAC auth session"
    %TPM_EXE_PATH%startauthsession -se h -hs 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create a signing key using the salt"
    %TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 333 -se0 02000000 0 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the storage key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

)

echo ""
echo "Salt Session - CreatePrimary RSA key"
echo ""

for %%H in (%ITERATE_ALGS%) do (
    
    echo "Create a primary RSA key - %%H"
    %TPM_EXE_PATH%createprimary -nalg %%H -halg %%H -hi p -deo > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Start a salted HMAC auth session"
    %TPM_EXE_PATH%startauthsession -se h -hs 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create a primary HMAC key using the salt"
    %TPM_EXE_PATH%createprimary -kh -se0 02000000 0 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the HMAC key"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the RSA key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )
)

echo ""
echo "Salt Session - EvictControl"
echo ""

echo "Load the storage key"
%TPM_EXE_PATH%load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Make the storage key persistent"
%TPM_EXE_PATH%evictcontrol -ho 80000001 -hp 81800000 -hi p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a salted HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h -hs 81800000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key using the salt"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 333 -se0 02000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the storage key from transient memory"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the storage key from persistent memory"
%TPM_EXE_PATH%evictcontrol -ho 81800000 -hp 81800000 -hi p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Salt Session - ContextSave and ContextLoad"
echo ""

echo "Load the storage key at 80000001"
%TPM_EXE_PATH%load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Save context for the key at 80000001"
%TPM_EXE_PATH%contextsave -ha 80000001 -of tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the storage key at 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load context, new storage key at 80000001"
%TPM_EXE_PATH%contextload -if tmp.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a salted HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h -hs 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key using the salt"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk 333 -se0 02000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the context loaded key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Salt Audit Session - PCR Read, Read Public, NV Read Public"
echo ""

echo "Load the storage key at 80000001"
%TPM_EXE_PATH%load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a salted HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h -hs 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "PCR read with salted audit session"
%TPM_EXE_PATH%pcrread -ha 16 -se0 02000000 81 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Read public with salted audit session"
%TPM_EXE_PATH%readpublic -ho 80000001 -se0 02000000 81 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV define space"
%TPM_EXE_PATH%nvdefinespace -ha 01000000 -hi p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Read public with salted audit session"
%TPM_EXE_PATH%nvreadpublic -ha 01000000 -se0 02000000 81 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the storage key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the salt session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV undefine space"
%TPM_EXE_PATH%nvundefinespace -ha 01000000 -hi p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)


echo ""
echo "Salt Policy Session with policyauthvalue"
echo ""

echo "Load the RSA storage key 80000001 under the primary key 80000000"
%TPM_EXE_PATH%load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a salted policy session"
%TPM_EXE_PATH%startauthsession -se p -hs 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code - create"
%TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 153 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy authvalue"
%TPM_EXE_PATH%policyauthvalue -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key using the salt"
%TPM_EXE_PATH%create -hp 80000001 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the storage key 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Salt Policy Session with no policyauthvalue"
echo ""

echo "Start a salted policy session"
%TPM_EXE_PATH%startauthsession -se p -hs 80000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key using the salt"
%TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -se0 03000000 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rm -f tmpkeypairrsa.pem
rm -f tmpkeypairecc.pem
rm -f tmpkeypairrsa.der
rm -f tmpkeypairecc.der

exit /B 0

REM getcapability -cap 1 -pr 80000000

