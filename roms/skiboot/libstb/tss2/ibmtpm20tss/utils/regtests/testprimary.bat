REM #############################################################################
REM										#
REM			TPM2 regression test					#
REM			     Written by Ken Goldman				#
REM		       IBM Thomas J. Watson Research Center			#
REM		$Id: testprimary.bat 1278 2018-07-23 21:20:42Z kgoldman $	#
REM										#
REM (c) Copyright IBM Corporation 2015						#
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

echo ""
echo "Primary key - CreatePrimary"
echo ""

echo "Create a primary storage key"
%TPM_EXE_PATH%createprimary -hi p -pwdk sto > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
  )

echo "Read the public part"
%TPM_EXE_PATH%readpublic -ho 80000001  > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
  )

echo "Create a storage key under the primary key"
%TPM_EXE_PATH%create -hp 80000001 -st -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sto > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
  )

echo "Load the storage key under the primary key"
%TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
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
%TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! EQU 0 (
  exit /B 1
  )

echo ""
echo "Primary key - CreatePrimary with no unique field"
echo ""

REM no unique 

echo "Create a primary storage key with no unique field"
%TPM_EXE_PATH%createprimary -hi p -pwdk sto > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
  )

echo "Create a storage key under the primary key"
%TPM_EXE_PATH%create -hp 80000001 -st -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sto > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
  )

echo "Load the storage key under the primary key"
%TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
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

REM empty unique

echo "Create a primary storage key with no unique field"
touch empty.bin
%TPM_EXE_PATH%createprimary -hi p -pwdk sto -iu empty.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
  )

echo "Load the original storage key under the primary key with empty unique field"
%TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
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

echo ""
echo "Primary key - CreatePrimary with unique field"
echo ""

REM unique

echo "Create a primary storage key with unique field"
touch empty.bin
%TPM_EXE_PATH%createprimary -hi p -pwdk sto -iu policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
  )

echo "Load the original storage key under the primary key - should fail"
%TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
IF !ERRORLEVEL! EQU 0 (
  exit /B 1
  )

echo "Create a storage key under the primary key"
%TPM_EXE_PATH%create -hp 80000001 -st -kt f -kt p -opr tmppriv.bin -opu tmppub.bin -pwdp sto -pwdk sto > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
  )

echo "Load the storage key under the primary key"
%TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
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

REM same unique

echo "Create a primary storage key with same unique field"
%TPM_EXE_PATH%createprimary -hi p -pwdk sto -iu policies/aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
  )

echo "Load the previous storage key under the primary key"
%TPM_EXE_PATH%load -hp 80000001 -ipr tmppriv.bin -ipu tmppub.bin -pwdp sto > run.out
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

exit /B 0

REM getcapability  -cap 1 -pr 80000000

