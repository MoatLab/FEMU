REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #										#
REM # (c) Copyright IBM Corporation 2018 - 2020					#
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
echo "Keyed hash HMAC key"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM session 02000000
REM loaded HMAC key 80000001
REM primary HMAC key 80000001
REM sequence object 80000002

for %%H in (%ITERATE_ALGS%) do (

    for %%S in ("" "-se0 02000000 1") do (

    	echo "Load the %%H keyed hash key under the primary key"
    	%TPM_EXE_PATH%load -hp 80000000 -ipr khpriv%%H.bin -ipu khpub%%H.bin -pwdp sto > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)

	echo "HMAC %%H using the keyed hash key, message from file %%~S"
	%TPM_EXE_PATH%hmac -hk 80000001 -if msg.bin -os sig.bin -pwdk khk -halg %%H %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "HMAC %%H start using the keyed hash key %%~S"
	%TPM_EXE_PATH%hmacstart -hk 80000001 -pwdk khk -pwda aaa %%~S -halg %%H > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "HMAC %%H sequence update %%~S"
	%TPM_EXE_PATH%sequenceupdate -hs 80000002 -pwds aaa -if msg.bin %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "HMAC %%H sequence complete %%~S"
	%TPM_EXE_PATH%sequencecomplete -hs 80000002 -pwds aaa -of tmp.bin %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Verify the HMAC %%H using the two methods"
	diff sig.bin tmp.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "HMAC %%H using the keyed hash key, message from command line %%~S"
	%TPM_EXE_PATH%hmac -hk 80000001 -ic 1234567890123456 -os sig.bin -pwdk khk -halg %%H %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Verify the HMAC %%H using the two methods"
	diff sig.bin tmp.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Flush the %%H HMAC key"
	%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Create primary HMAC key - %%H"
	%TPM_EXE_PATH%createprimary -kh -halg %%H -pwdk khp > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "HMAC %%H using the keyed hash primary key %%~S"
	%TPM_EXE_PATH%hmac -hk 80000001 -if msg.bin -os sig.bin -pwdk khp -halg %%H %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "HMAC %%H start using the keyed hash primary key %%~S"
	%TPM_EXE_PATH%hmacstart -hk 80000001 -pwdk khp -pwda aaa %%~S -halg %%H > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "HMAC %%H sequence update %%~S"
	%TPM_EXE_PATH%sequenceupdate -hs 80000002 -pwds aaa -if msg.bin %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "HMAC %%H sequence complete %%~S"
	%TPM_EXE_PATH%sequencecomplete -hs 80000002 -pwds aaa -of tmp.bin %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Verify the HMAC %%H using the two methods"
	diff sig.bin tmp.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Flush the %%H primary HMAC key"
	%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)
    )
)

echo ""
echo "Hash"
echo ""

for %%H in (%ITERATE_ALGS%) do (

    for %%S in ("" "-se0 02000000 1") do (

	echo "Hash %%H in one call, data from file"
	%TPM_EXE_PATH%hash -hi p -halg %%H -if policies/aaa -oh tmp.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Verify the hash %%H"
	diff tmp.bin policies/%%Haaa.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Hash %%H in one cal, data on command linel"
	%TPM_EXE_PATH%hash -hi p -halg %%H -ic aaa -oh tmp.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Verify the hash %%H"
	diff tmp.bin policies/%%Haaa.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Hash %%H sequence start"
	%TPM_EXE_PATH%hashsequencestart -halg %%H -pwda aaa > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Hash %%H sequence update %%~S"
	%TPM_EXE_PATH%sequenceupdate -hs 80000001 -pwds aaa -if policies/aaa %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Hash %%H sequence complete %%~S"
	%TPM_EXE_PATH%sequencecomplete -hi p -hs 80000001 -pwds aaa -of tmp.bin %%~S > run.out
	IF !ERRORLEVEL! NEQ 0 (
	   exit /B 1
	)

	echo "Verify the %%H hash"
	diff tmp.bin policies/%%Haaa.bin > run.out
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

REM getcapability -cap 1 -pr 80000000
REM getcapability -cap 1 -pr 02000000

echo ""
echo "Sign with ticket"
echo ""

echo "Load the signing key under the primary key"
%TPM_EXE_PATH%load -hp 80000000 -ipr signrsa2048rpriv.bin -ipu signrsa2048rpub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Hash and create ticket"
%TPM_EXE_PATH%hash -hi p -halg sha256 -if msg.bin -oh sig.bin -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest with a restricted signing key and no ticket - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Sign a digest with a restricted signing key and ticket"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if msg.bin -tk tkt.bin -os sig.bin -pwdk sig  > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Hash and create null ticket, msg with TPM_GENERATED"
%TPM_EXE_PATH%hash -hi p -halg sha256 -if policies/msgtpmgen.bin -oh sig.bin -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest with a restricted signing key and ticket - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if msg.bin -tk tkt.bin -os sig.bin -pwdk sig  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Hash sequence start"
%TPM_EXE_PATH%hashsequencestart -halg sha256 -pwda aaa > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Hash sequence update "
%TPM_EXE_PATH%sequenceupdate -hs 80000002 -pwds aaa -if msg.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Hash sequence complete"
%TPM_EXE_PATH%sequencecomplete -hi p -hs 80000002 -pwds aaa -of tmp.bin -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest with a restricted signing key and no ticket - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -halg  sha256 -if msg.bin -os sig.bin -pwdk sig  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Sign a digest with a restricted signing key and ticket"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if msg.bin -tk tkt.bin -os sig.bin -pwdk sig  > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Hash sequence start"
%TPM_EXE_PATH%hashsequencestart -halg sha256 -pwda aaa -halg sha256 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Hash sequence update, msg with TPM_GENERATED"
%TPM_EXE_PATH%sequenceupdate -hs 80000002 -pwds aaa -if policies/msgtpmgen.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Hash sequence complete"
%TPM_EXE_PATH%sequencecomplete -hi p -hs 80000002 -pwds aaa -of tmp.bin -tk tkt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Sign a digest with a restricted signing key and ticket - should fail"
%TPM_EXE_PATH%sign -hk 80000001 -halg sha256 -if msg.bin -tk tkt.bin -os sig.bin -pwdk sig  > run.out
IF !ERRORLEVEL! EQU 0 (
   exit /B 1
)

echo "Flush the signing key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

exit /B 0

REM getcapability -cap 1 -pr 80000000
REM getcapability -cap 1 -pr 02000000

