REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #										#
REM # (c) Copyright IBM Corporation 2015 - 2019					#
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
echo "CreateLoaded"
echo ""

echo ""
echo "CreateLoaded Primary Key, Hierarchy Parent"
echo ""

for %%H in ("40000001" "4000000c" "4000000b") do (

    echo "CreateLoaded primary key, parent %%~H"
    %TPM_EXE_PATH%createloaded -hp %%~H -st -kt f -kt p -pwdk ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Create a storage key under the primary key"
    %TPM_EXE_PATH%create -hp 80000001 -st -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Load the storage key under the primary key"
    %TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Flush the storage key"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Flush the primary storage key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Load the storage key under the primary key - should fail"
    %TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
    IF !ERRORLEVEL! EQU 0 (
        exit /B 1
    )

    echo "CreateLoaded recreate owner primary key"
    %TPM_EXE_PATH%createloaded -hp %%~H -st -kt f -kt p -pwdk ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Load the storage key under the primary key"
    %TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Flush the storage key"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

    echo "Flush the primary storage key"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       	exit /B 1
    )

)

echo ""
echo "CreateLoaded Child Key, Primary Parent"
echo ""

echo "CreateLoaded child storage key at 80000001, parent 80000000"
%TPM_EXE_PATH%createloaded -hp 80000000 -st -kt f -kt p -pwdp sto -pwdk ppp  -opu tmpppub.bin -opr tmpppriv.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create a signing key under the child storage key 80000001"
%TPM_EXE_PATH%create -hp 80000001 -si -opr tmppriv.bin -opu tmppub.bin -pwdp ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the signing key at 80000002 under the child storage key 80000001"
%TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the child storage key 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the child signing key 80000001"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Reload the createloaded child storage key at 80000001, parent 80000000"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmpppriv.bin -ipu tmpppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Reload the child signing key at 80000002 under the child storage key 80000001"
%TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp ppp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the child storage key 80000002 "
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the child signing key 80000001 "
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "CreateLoaded Primary Derived Key, Hierarchy Parent"
echo ""

for %%H in ("e" "o" "p") do (

    echo "Create a primary %%~H derivation parent 80000001"
    %TPM_EXE_PATH%createprimary -hi %%~H -dp > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create a derived key 80000002"
    %TPM_EXE_PATH%createloaded -hp 80000001 -der -ecc bnp256 -den -kt f -kt p -opu tmppub.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the derived key 80000002"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create a derived key 80000002"
    %TPM_EXE_PATH%createloaded -hp 80000001 -der -ecc bnp256 -den -kt f -kt p -opu tmppub1.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the derived key 80000002"
    %TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Verify that the two derived keys are the same"
    diff tmppub.bin tmppub1.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the derivation parent"
    %TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

)

echo ""
echo "CreateLoaded Child Derived Key, Primary Parent"
echo ""

echo "Create a derivation parent under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -dp -opr tmpdppriv.bin -opu tmpdppub.bin -pwdp sto -pwdk dp > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the derivation parent to 80000001"
%TPM_EXE_PATH%load -hp 80000000 -ipr tmpdppriv.bin -ipu tmpdppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create an EC signing key under the derivation parent key"
%TPM_EXE_PATH%createloaded -hp 80000001 -der -si -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -opem tmppub.pem  -pwdp dp -ecc nistp256 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest"
%TPM_EXE_PATH%sign -hk 80000002 -halg sha256 -salg ecc -if policies/aaa -os sig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the ECC signature using the TPM"
%TPM_EXE_PATH%verifysignature -hk 80000002 -halg sha256 -ecc -if policies/aaa -is sig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify the signature using PEM"
%TPM_EXE_PATH%verifysignature -ipem tmppub.pem -halg sha256 -if policies/aaa -is sig.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Create another EC signing key 80000002 under the derivation parent key"
%TPM_EXE_PATH%createloaded -hp 80000001 -der -si -kt f -kt p -opr tmppriv1.bin -opu tmppub1.bin -opem tmppub1.pem -pwdp dp -ecc nistp256 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Verify that the two derived keys are the same"
diff tmppub.bin tmppub1.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the signing key 80000002"
%TPM_EXE_PATH%flushcontext -ha 80000002 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the derivation parent"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rm -f tmpdppriv.bin
rm -f tmpdppub.bin
rm -f tmpppriv.bin
rm -f tmpppub.bin
rm -f tmppub.pem
rm -f tmppriv1.bin
rm -f tmppub1.bin
rm -f tmppub1.pem
