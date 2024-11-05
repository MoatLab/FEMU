REM #############################################################################
REM										#
REM			TPM2 regression test					#
REM			     Written by Ken Goldman				#
REM		       IBM Thomas J. Watson Research Center			#
REM										#
REM (c) Copyright IBM Corporation 2015 - 2020					#
REM 										#
REM All rights reserved.							#
REM 										#
REM Redistribution and use in source and binary forms, with or without		#
REM modification, are permitted provided that the following conditions are	#
REM met:									#
REM 										#
REM Redistributions of source code must retain the above copyright notice,	#
REM this list of conditions and the following disclaimer.			#
REM 										#
REM Redistributions in binary form must reproduce the above copyright		#
REM notice, this list of conditions and the following disclaimer in the		#
REM documentation and/or other materials provided with the distribution.	#
REM 										#
REM Neither the names of the IBM Corporation nor the names of its		#
REM contributors may be used to endorse or promote products derived from	#
REM this software without specific prior written permission.			#
REM 										#
REM THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
REM "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
REM LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	#
REM A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT	#
REM HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
REM SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
REM LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	#
REM DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	#
REM THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
REM (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	#
REM OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.	#
REM										#
REM #############################################################################

setlocal enableDelayedExpansion
 
echo | set /p="1234567890123456" > msg.bin
touch zero.bin

REM try to undefine any NV index left over from a previous test.  Do not check for errors.
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 -pwdp ppp > run.out
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000001 > run.out
%TPM_EXE_PATH%nvundefinespace -hi o -ha 01000002 > run.out
%TPM_EXE_PATH%nvundefinespace -hi o -ha 01000003 > run.out

REM same for persistent objects
%TPM_EXE_PATH%evictcontrol -ho 81800000 -hp 81800000 -hi p > run.out

echo ""
echo "Initialize Regression Test Keys"
echo ""

echo "Create a platform primary storage key"
%TPM_EXE_PATH%createprimary -hi p -pwdk sto -pol policies/zerosha256.bin -tk pritk.bin -ch prich.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

echo "Create an RSA storage key under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -st -kt f -kt p -pol policies/policycccreate-auth.bin -opr storersa2048priv.bin -opu storersa2048pub.bin -tk storsatk.bin -ch storsach.bin -pwdp sto -pwdk sto > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

echo "Create an ECC storage key under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -ecc nistp256 -st -kt f -kt p -opr storeeccpriv.bin -opu storeeccpub.bin -pwdp sto -pwdk sto > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

for %%B in (2048 3072) do (

    echo "Create an unrestricted RSA %%B signing key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -si -kt f -kt p -opr signrsa%%Bpriv.bin -opu signrsa%%Bpub.bin -opem signrsa%%Bpub.pem -pwdp sto -pwdk sig > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
    )

    echo "Create an RSA decryption key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -den -kt f -kt p -opr derrsa%%Bpriv.bin -opu derrsa%%Bpub.bin -pwdp sto -pwdk dec > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
    )

)

echo "Create an unrestricted ECC signing key under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -ecc nistp256 -si -kt f -kt p -opr signeccpriv.bin -opu signeccpub.bin -opem signeccpub.pem -pwdp sto -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

echo "Create a restricted RSA signing key under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -sir -kt f -kt p -opr signrsa2048rpriv.bin -opu signrsa2048rpub.bin -opem signrsa2048rpub.pem -pwdp sto -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

echo "Create a restricted ECC signing key under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -ecc nistp256 -sir -kt f -kt p -opr signeccrpriv.bin -opu signeccrpub.bin -opem signeccrpub.pem -pwdp sto -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

echo "Create a not fixedTPM RSA signing key under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -sir -opr signrsa2048nfpriv.bin -opu signrsa2048nfpub.bin -opem signrsa2048nfpub.pem -pwdp sto -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

echo "Create a not fixedTPM ECC signing key under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -ecc nistp256 -sir -opr signeccnfpriv.bin -opu signeccnfpub.bin -opem signeccnfpub.pem -pwdp sto -pwdk sig > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

echo "Create a symmetric cipher key under the primary key"
%TPM_EXE_PATH%create -hp 80000000 -des -kt f -kt p -opr despriv.bin -opu despub.bin -pwdp sto -pwdk aes > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

for %%H in (%ITERATE_ALGS%) do (

    echo "Create a %%H unrestricted keyed hash key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -kh -kt f -kt p -opr khpriv%%H.bin -opu khpub%%H.bin -pwdp sto -pwdk khk -halg %%H > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Create a %%H restricted keyed hash key under the primary key"
    %TPM_EXE_PATH%create -hp 80000000 -khr -kt f -kt p -opr khrpriv%%H.bin -opu khrpub%%H.bin -pwdp sto -pwdk khk -halg %%H > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

)

exit /B 0


