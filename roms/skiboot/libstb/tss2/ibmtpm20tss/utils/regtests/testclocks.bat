REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #		$Id: testclocks.bat 1292 2018-08-01 17:27:24Z kgoldman $	#
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
echo "Clocks"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

for %%S in ("" "-se0 02000000 1") do (

    echo "Read Clock"
    %TPM_EXE_PATH%readclock -oclock tmpclk.bin > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "Clock set, time 0 %%~S - should fail"
    %TPM_EXE_PATH%clockset -iclock tmpclk.bin %%~S > run.out
    IF !ERRORLEVEL! EQU 0 (
        exit /B 1
    )

    echo "Clock set, time plus 20 sec %%~S"
    %TPM_EXE_PATH%clockset -iclock tmpclk.bin -addsec 20 %%~S > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    for %%A in (-3 0 3) do (

	echo "Clock rate adjust %%A %%~S"
	%TPM_EXE_PATH%clockrateadjust -adj %%A %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

    )

    for %%A in (-4 4) do (

	echo "Clock rate adjust %%A %%~S - should fail"
	%TPM_EXE_PATH%clockrateadjust -adj %%A %%~S > run.out
    	IF !ERRORLEVEL! EQU 0 (
       	    exit /B 1
    	)

    )

)

echo "Flush the auth session"
%TPM_EXE_PATH%flushcontext -ha 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rm -f tmpclk.bin

exit /B 0

