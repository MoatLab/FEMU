REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: testnv.bat 1301 2018-08-15 21:46:19Z kgoldman $		#
REM #										#
REM # (c) Copyright IBM Corporation 2015 - 2018					#
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
echo "NV"
echo ""

echo ""
echo "NV Ordinary Index"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

set NALG=%ITERATE_ALGS%
set BADNALG=%BAD_ITERATE_ALGS%

set i=0
for %%N in (!NALG!) do set /A i+=1 & set NALG[!i!]=%%N
set i=0
for %%B in (!BADNALG!) do set /A i+=1 & set BADNALG[!i!]=%%B
set L=!i!

for /L %%i in (1,1,!L!) do (

    for %%S in ("" "-se0 02000000 1") do (

	echo "NV Define Space !NALG[%%i]!"
	%TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 -nalg !NALG[%%i]! > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "NV Read Public, unwritten Name  bad Name algorithm !BADNALG[%%i]! - should fail"
	%TPM_EXE_PATH%nvreadpublic -ha 01000000 -nalg !BADNALG[%%i]! > run.out
    	IF !ERRORLEVEL! EQU 0 (
       	  exit /B 1
    	)

	echo "NV read - should fail before write %%~S"
	%TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 16 %%~S > run.out
	IF !ERRORLEVEL! EQU 0 (
	  exit /B 1
	)

	echo "NV write %%~S"
	%TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if policies/aaa %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "NV read %%~S"
	%TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 3 -of tmp.bin %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Verify the read data"
	diff policies/aaa tmp.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "NV read, invalid offset - should fail %%~S"
	%TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 16 -off 1 -of tmp.bin %%~S > run.out
	IF !ERRORLEVEL! EQU 0 (
	   exit /B 1
	)

	echo "NV read, invalid size - should fail %%~S"
	%TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 17 -of tmp.bin %%~S > run.out
	IF !ERRORLEVEL! EQU 0 (
	   exit /B 1
	)

	echo "NV Undefine Space"
	%TPM_EXE_PATH%nvundefinespace -hi o -ha 01000000 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

    )
)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine Space again should fail"
%TPM_EXE_PATH%nvundefinespace -hi o -ha 01000000 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)
    
echo "NV Define Space out of range - should fail"
%TPM_EXE_PATH%nvdefinespace -hi o -ha 02000000 -pwdn nnn  -sz 16 > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo ""
echo "NV Set Bits Index"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    echo "NV Define Space"
    %TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -pwdn nnn -ty b > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV read - should fail before write %%~S"
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 16  %%~S > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "Set bits 0, 16, 32, 48 %%~S" 
    %TPM_EXE_PATH%nvsetbits -ha 01000000 -pwdn nnn -bit 0 -bit 16 -bit 32 -bit 48 %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Read the set bits %%~S" 
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 8 -of tmp.bin %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Verify the read data"
    diff policies/bits48321601.bin tmp.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Undefine Space"
    %TPM_EXE_PATH%nvundefinespace -hi o -ha 01000000 > run.out
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
echo "NV Counter Index"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    echo "NV Define Space"
    %TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -pwdn nnn -ty c > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Read Public, unwritten Name"
    %TPM_EXE_PATH%nvreadpublic -ha 01000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Read the count - should fail before write %%~S" 
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 8 -of tmp.bin  %%~S > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "Increment the count %%~S" 
    %TPM_EXE_PATH%nvincrement -ha 01000000 -pwdn nnn  %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Read the count %%~S" 
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 8 -of tmp.bin  %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

REM FIXME need some way to verify the count

    echo "NV Undefine Space"
    %TPM_EXE_PATH%nvundefinespace -hi o -ha 01000000 > run.out
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
echo "NV Extend Index"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    set SZ=20 32 48 64
    set HALG=%ITERATE_ALGS%

    set i=0
    for %%a in (!SZ!) do set /A i+=1 & set SZ[!i!]=%%a
    set i=0
    for %%b in (!HALG!) do set /A i+=1 & set HALG[!i!]=%%b
    set L=!i!

    for /L %%i in (1,1,!L!) do (

	echo "NV Define Space !HALG[%%i]!"
	%TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -pwdn nnn -ty e -nalg !HALG[%%i]! > run.out
	IF !ERRORLEVEL! NEQ 0 (
   	   exit /B 1
	)

	echo "NV Read Public !HALG[%%i]!"
	%TPM_EXE_PATH%nvreadpublic -ha 01000000 -nalg !HALG[%%i]! > run.out
	IF !ERRORLEVEL! NEQ 0 (
   	   exit /B 1
	)

	echo "NV read, unwritten Name - should fail before write %%~S"
	%TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 32 -of tmp.bin %%~S > run.out
	IF !ERRORLEVEL! EQU 0 (
   	   exit /B 1
	)

	echo "NV extend %%~S"
	%TPM_EXE_PATH%nvextend -ha 01000000 -pwdn nnn -if policies/aaa %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
   	   exit /B 1
	)

	echo "NV read size !SZ[%%i]!} %%~S"
	%TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz !SZ[%%i]! -of tmp.bin %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
   	   exit /B 1
	)

	echo "Verify the read data !HALG[%%i]!"
	diff policies/!HALG[%%i]!extaaa.bin tmp.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
   	   exit /B 1
	)

	echo "NV Undefine Space"
	%TPM_EXE_PATH%nvundefinespace -hi o -ha 01000000 > run.out
	IF !ERRORLEVEL! NEQ 0 (
   	   exit /B 1
	)

    )
)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM getcapability  -cap 1 -pr 80000000
REM getcapability  -cap 1 -pr 02000000
REM getcapability  -cap 1 -pr 01000000

echo ""
echo "NV Owner auth"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    echo "Set owner auth %%~S"
    %TPM_EXE_PATH%hierarchychangeauth -hi o -pwdn ooo %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Define an NV index with owner auth %%~S"
    %TPM_EXE_PATH%nvdefinespace -hi o -hia o -ha 01000000 -pwdp ooo %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Read public, get Name, not written"
    %TPM_EXE_PATH%nvreadpublic -ha 01000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV write with NV password %%~S - should fail"
    %TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn  %%~S> run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "NV write with owner password %%~S"
    %TPM_EXE_PATH%nvwrite -ha 01000000 -hia o -pwdn ooo  %%~S> run.out 
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV read with NV password %%~S - should fail"
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn %%~S > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "NV read with owner password %%~S"
    %TPM_EXE_PATH%nvread -ha 01000000 -hia o -pwdn ooo %%~S > run.out 
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Undefine authorizing index %%~S"
    %TPM_EXE_PATH%nvundefinespace -hi o -ha 01000000 -pwdp ooo %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Clear owner auth %%~S"
    %TPM_EXE_PATH%hierarchychangeauth -hi o -pwda ooo %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM getcapability  -cap 1 -pr 80000000
REM getcapability  -cap 1 -pr 02000000
REM getcapability  -cap 1 -pr 01000000

echo ""
echo "NV Platform auth"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    echo "Set platform auth %%~S"
    %TPM_EXE_PATH%hierarchychangeauth -hi p -pwdn ppp  %%~S> run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Define an NV index with platform auth %%~S"
    %TPM_EXE_PATH%nvdefinespace -hi p -hia p -ha 01000000 -pwdp ppp %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Read public, get Name, not written"
    %TPM_EXE_PATH%nvreadpublic -ha 01000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV write with NV password %%~S - should fail"
    %TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn %%~S > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "NV write with platform password %%~S"
    %TPM_EXE_PATH%nvwrite -ha 01000000 -hia p -pwdn ppp %%~S > run.out 
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV read with NV password %%~S - should fail"
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn %%~S > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "NV write with platform password %%~S"
    %TPM_EXE_PATH%nvread -ha 01000000 -hia p -pwdn ppp %%~S > run.out 
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Undefine authorizing index %%~S"
    %TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 -pwdp ppp %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Clear platform auth %%~S"
    %TPM_EXE_PATH%hierarchychangeauth -hi p -pwda ppp %%~S > run.out
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
echo "Write Lock"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    echo "NV Define Space with write define"
    %TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 +at wd > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Read Public, unwritten Name"
    %TPM_EXE_PATH%nvreadpublic -ha 01000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV write %%~S"
    %TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if policies/aaa %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV read %%~S"
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 16 %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Write lock %%~S"
    %TPM_EXE_PATH%nvwritelock -ha 01000000 -pwdn nnn %%~S > run.out  
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV write %%~S - should fail"
    %TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if policies/aaa %%~S > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "NV read %%~S"
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 16 %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Undefine Space"
    %TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
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
echo "Read Lock"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    echo "NV Define Space with read stclear"
    %TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 +at rst > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Read Public, unwritten Name"
    %TPM_EXE_PATH%nvreadpublic -ha 01000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV write %%~S"
    %TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if policies/aaa %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV read %%~S"
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 16 %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

     echo "Read lock %%~S"
    %TPM_EXE_PATH%nvreadlock -ha 01000000 -pwdn nnn %%~S > run.out 
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV write %%~S"
    %TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if policies/aaa %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV read %%~S - should fail"
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 16 %%~S > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "NV Undefine Space"
    %TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
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
echo "Global Lock"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    echo "NV Define Space 01000000 with global lock"
    %TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 +at gl > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Define Space 01000001 with global lock"
    %TPM_EXE_PATH%nvdefinespace -hi o -ha 01000001 -pwdn nnn -sz 16 +at gl > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV write 01000000 %%~S"
    %TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if policies/aaa %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV write 01000001 %%~S"
    %TPM_EXE_PATH%nvwrite -ha 01000001 -pwdn nnn -if policies/aaa %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV global lock"
    %TPM_EXE_PATH%nvglobalwritelock -hia p > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Read Public, 01000000, locked"
    %TPM_EXE_PATH%nvreadpublic -ha 01000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Read Public, 01000001, locked"
    %TPM_EXE_PATH%nvreadpublic -ha 01000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV write 01000000 %%~S - should fail"
    %TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if policies/aaa %%~S > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "NV write 01000001 %%~S - should fail"
    %TPM_EXE_PATH%nvwrite -ha 01000001 -pwdn nnn -if policies/aaa %%~S > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "NV read 01000000 %%~S"
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 16 %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV read 01000001 %%~S"
    %TPM_EXE_PATH%nvread -ha 01000001 -pwdn nnn -sz 16 %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Undefine Space 01000000"
    %TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Undefine Space 01000001"
    %TPM_EXE_PATH%nvundefinespace -hi p -ha 01000001 > run.out
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
echo "NV Change Authorization"
echo ""

REM policy is policycommandcode + policyauthvalue
REM aa 83 a5 98 d9 3a 56 c9 ca 6f ea 7c 3f fc 4e 10 
REM 63 57 ff 6d 93 e1 1a 9b 4a c2 b6 aa e1 2b a0 de 

echo "NV Define Space with POLICY_DELETE and no policy - should fail"
%TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 +at pold > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Start an HMAC session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    echo "NV Define Space 0100000"
    %TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 -pol policies/policyccnvchangeauth-auth.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Read Public, unwritten Name"
    %TPM_EXE_PATH%nvreadpublic -ha 01000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV write %%~S"
    %TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if policies/aaa %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV read %%~S"
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 16 %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Start a policy session"
    %TPM_EXE_PATH%startauthsession -se p > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Policy command code"    
    %TPM_EXE_PATH%policycommandcode -ha 03000001 -cc 0000013b > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Policy authvalue"    
    %TPM_EXE_PATH%policyauthvalue -ha 03000001 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Change authorization"
    %TPM_EXE_PATH%nvchangeauth -ha 01000000 -pwdo nnn -pwdn xxx -se0 03000001 1 > run.out 
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV write %%~S, old auth - should fail"
    %TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn nnn -if policies/aaa %%~S > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "NV read %%~S, old auth - should fail"
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn nnn -sz 3 %%~S > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "NV write %%~S"
    %TPM_EXE_PATH%nvwrite -ha 01000000 -pwdn xxx -if policies/aaa %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV read %%~S"
    %TPM_EXE_PATH%nvread -ha 01000000 -pwdn xxx -sz 3 %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "NV Undefine Space"
    %TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Flush the auth session"
    %TPM_EXE_PATH%flushcontext -ha 03000001 > run.out
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
echo "NV Change Authorization with bind"
echo ""

echo "NV Define Space 0100000"
%TPM_EXE_PATH%nvdefinespace -hi o -ha 01000000 -pwdn nnn -sz 16 -pol policies/policyccnvchangeauth-auth.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start an HMAC session, bind to NV index"
%TPM_EXE_PATH%startauthsession -se h -bi 01000000 -pwdb nnn > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy command code"    
%TPM_EXE_PATH%policycommandcode -ha 03000001 -cc 0000013b > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Policy authvalue"    
%TPM_EXE_PATH%policyauthvalue -ha 03000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Change authorization"
%TPM_EXE_PATH%nvchangeauth -ha 01000000 -pwdo nnn -pwdn xxx -se0 03000001 1 > run.out 
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "NV Undefine Space"
%TPM_EXE_PATH%nvundefinespace -hi p -ha 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 03000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "NV Undefine space special"
echo ""

REM policy is policy command code + policy password

echo "Start a policy session"
%TPM_EXE_PATH%startauthsession -se p > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%P in (policyauthvalue policypassword) do (

    echo "NV Define Space 0100000"
    %TPM_EXE_PATH%nvdefinespace -hi p -ha 01000000 -pwdn nnn -sz 16 +at pold -pol policies/policyccundefinespacespecial-auth.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Undefine space special - should fail"
    %TPM_EXE_PATH%nvundefinespacespecial -ha 01000000 -pwdn nnn > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "Undefine space special - should fail"
    %TPM_EXE_PATH%nvundefinespacespecial -ha 01000000 -se0 03000000 1 -pwdn nnn > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "Policy command code, NV undefine space special"
    %TPM_EXE_PATH%policycommandcode -ha 03000000 -cc 11f > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Undefine space special - should fail"
    %TPM_EXE_PATH%nvundefinespacespecial -ha 01000000 -se0 03000000 1 -pwdn nnn > run.out
    IF !ERRORLEVEL! EQU 0 (
       exit /B 1
    )

    echo "Policy %%P"
    %TPM_EXE_PATH%%%P -ha 03000000 > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

    echo "Undefine space special"
    %TPM_EXE_PATH%nvundefinespacespecial -ha 01000000 -se0 03000000 1 -pwdn nnn > run.out
    IF !ERRORLEVEL! NEQ 0 (
       exit /B 1
    )

)

echo "Flush the session"
%TPM_EXE_PATH%flushcontext -ha 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

exit /B 0

REM getcapability  -cap 1 -pr 80000000
REM getcapability  -cap 1 -pr 02000000
REM getcapability  -cap 1 -pr 01000000
