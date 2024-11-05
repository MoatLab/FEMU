REM #############################################################################
REM										#
REM			TPM2 regression test					#
REM			     Written by Ken Goldman				#
REM		       IBM Thomas J. Watson Research Center			#
REM										#
REM (c) Copyright IBM Corporation 2015 - 2019					#
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

REM #
REM # for pcrextend
REM #
REM 
REM # extend of aaa + 0 pad to digest length using pcrextend, use resettable PCR 16
REM 
REM # sha1extaaa0.bin
REM # 1d 47 f6 8a ce d5 15 f7 79 73 71 b5 54 e3 2d 47 
REM # 98 1a a0 a0 
REM 
REM # sha256extaaa0.bin
REM # c2 11 97 64 d1 16 13 bf 07 b7 e2 04 c3 5f 93 73 
REM # 2b 4a e3 36 b4 35 4e bc 16 e8 d0 c3 96 3e be bb 
REM 
REM # sha384extaaa0.bin
REM # 29 29 63 e3 1c 34 c2 72 bd ea 27 15 40 94 af 92 
REM # 50 ad 97 d9 e7 44 6b 83 6d 3a 73 7c 90 ca 47 df 
REM # 2c 39 90 21 ce dd 00 85 3e f0 84 97 c5 a4 23 84 
REM 
REM # sha512extaaa0.bin
REM # 7f e1 e4 cf 01 52 93 13 6b f1 30 18 30 39 b6 a6 
REM # 46 ea 00 8b 75 af d0 f8 46 6a 9b fe 53 1a f8 ad 
REM # a8 67 a6 58 28 cf ce 48 60 77 52 9e 54 f1 83 0a 
REM # a4 9a b7 80 56 2b ae a4 9c 67 a8 73 34 ff e7 78 
REM 
REM #
REM # for pcrevent
REM #
REM 
REM # first hash using hash -ic aaa -ns
REM # then extend using policymaker
REM 
REM # sha1 of aaa
REM # 7e240de74fb1ed08fa08d38063f6a6a91462a815
REM # extend
REM # ab 53 c7 ec 3f fe fe 21 9e 9d 89 da f1 8e 16 55 
REM # 3e 23 8e a6 
REM 
REM # sha256 of aaa
REM # 9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0
REM # extend
REM # df 81 1e 9d 19 a0 d3 3d e6 7b b1 c7 26 a6 20 5c 
REM # d0 a2 eb 0f 61 b7 c9 ee 91 66 eb cf dc 17 db ab 
REM 
REM # sha384 of aaa
REM # 8e07e5bdd64aa37536c1f257a6b44963cc327b7d7dcb2cb47a22073d33414462bfa184487cf372ce0a19dfc83f8336d8
REM # extend of that
REM # 61 bc 70 39 e2 94 87 c2 17 b0 b1 46 10 5d 64 e6 
REM # ad 32 a6 d5 c2 5b 45 01 a7 4b bc a7 7f cc 24 25 
REM # 36 ca 1a 40 f9 36 44 f0 d8 b0 98 ea a6 50 97 4d 
REM 
REM # sha512 of aaa
REM # d6f644b19812e97b5d871658d6d3400ecd4787faeb9b8990c1e7608288664be77257104a58d033bcf1a0e0945ff06468ebe53e2dff36e248424c7273117dac09 
REM # extend of that (using policymaker)
REM # cb 7f be b3 1c 29 61 24 4c 9c 47 80 84 0d b4 3a 
REM # 76 3f ba 96 ef c1 d9 52 f4 e3 e0 2c 06 8a 31 8a 
REM # e5 3f a0 a7 a1 74 e8 23 e3 07 1a cd c6 52 6f b6 
REM # 77 6d 07 0f 36 47 27 4d a6 29 db c9 10 a7 6c 2a 
REM 
REM # all these variables are related
REM 
REM # bank algorithm test pattern is

set BANKS=^
    "sha1"			^
    "sha256"			^
    "sha384"			^
    "sha512"			^
    "sha1   sha256"		^
    "sha1   sha384"		^
    "sha1   sha512"		^
    "sha256 sha384"		^
    "sha256 sha512"		^
    "sha384 sha512"		^
    "sha1   sha256 sha384"	^
    "sha1   sha256 sha512"	^
    "sha1   sha384 sha512"	^
    "sha256 sha384 sha512"	^
    "sha1   sha256 sha384 sha512"

REM # bank extend algorithm test pattern is

set EXTEND=^
    "-halg sha1"				^
    "-halg sha256"				^
    "-halg sha384"				^
    "-halg sha512"				^
    "-halg sha1   -halg sha256"			^
    "-halg sha1   -halg sha384"			^
    "-halg sha1   -halg sha512"			^
    "-halg sha256 -halg sha384"			^
    "-halg sha256 -halg sha512"			^
    "-halg sha384 -halg sha512"			^
    "-halg sha1   -halg sha256 -halg sha384"	^
    "-halg sha1   -halg sha256 -halg sha512"	^
    "-halg sha1   -halg sha384 -halg sha512"	^
    "-halg sha256 -halg sha384 -halg sha512"	^
    "-halg sha1   -halg sha256 -halg sha384 -halg sha512"

REM # bank event file test pattern is

set EVENT=^
    "-of1 tmpsha1.bin"						^
    "-of2 tmpsha256.bin"					^
    "-of3 tmpsha384.bin"					^
    "-of5 tmpsha512.bin"					^
    "-of1 tmpsha1.bin   -of2 tmpsha256.bin"			^
    "-of1 tmpsha1.bin   -of3 tmpsha384.bin"			^
    "-of1 tmpsha1.bin   -of5 tmpsha512.bin"			^
    "-of2 tmpsha256.bin -of3 tmpsha384.bin"			^
    "-of2 tmpsha256.bin -of5 tmpsha512.bin"			^
    "-of3 tmpsha384.bin -of5 tmpsha512.bin"			^
    "-of1 tmpsha1.bin   -of2 tmpsha256.bin -of3 tmpsha384.bin"	^
    "-of1 tmpsha1.bin   -of2 tmpsha256.bin -of5 tmpsha512.bin"	^
    "-of1 tmpsha1.bin   -of3 tmpsha384.bin -of5 tmpsha512.bin"	^
    "-of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin"	^
    "-of1 tmpsha1.bin   -of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin"
)

REM # assuming starts with starts with sha1 sha256 sha384 sha512

set ALLOC=^
    "-sha256 -sha384 -sha512"		^
    "-sha1   +sha256"			^
    "-sha256 +sha384"			^
    "-sha384 +sha512"			^
    "+sha1   +sha256 -sha512"		^
    "-sha256 +sha384"			^
    "-sha384 +sha512"			^
    "-sha1   +sha256 +sha384 -sha512"	^
    "-sha384 +sha512"			^
    "-sha256 +sha384"			^
    "+sha1   +sha256 -sha512"		^
    "-sha384 +sha512"			^
    "-sha256 +sha384"			^
    "-sha1   +sha256"			^
    "+sha1"
)

REM i is iterator over PCR bank allocation patterns
set i=0
for %%a in (!BANKS!) do set /A i+=1 & set BANKS[!i!]=%%~a
set i=0
for %%a in (!EXTEND!) do set /A i+=1 & set EXTEND[!i!]=%%~a
set i=0
for %%a in (!EVENT!) do set /A i+=1 & set EVENT[!i!]=%%~a
set i=0
for %%a in (!ALLOC!) do set /A i+=1 & set ALLOC[!i!]=%%~a
set L=!i!

for /L %%i in (1,1,!L!) do (

    echo ""
    echo "pcrallocate !BANKS[%%i]!"
    echo ""
    %TPM_EXE_PATH%pcrallocate !ALLOC[%%i]! > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
    )

    echo "powerup"
    %TPM_EXE_PATH%powerup > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
    )

    echo "startup"
    %TPM_EXE_PATH%startup > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
    )

    echo "display PCR banks"
    %TPM_EXE_PATH%getcapability -cap 5 > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
    )
    
    echo ""
    echo "PCR Extend"
    echo ""

    echo "PCR Reset"
    %TPM_EXE_PATH%pcrreset -ha 16 > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
      )

    echo "PCR Extend !EXTEND[%%i]!"
    %TPM_EXE_PATH%pcrextend -ha 16 !EXTEND[%%i]! -if policies/aaa > run.out
    IF !ERRORLEVEL! NEQ 0 (
      exit /B 1
      )

    for %%H in (!BANKS[%%i]!) do (

    	echo "PCR Read %%H"
    	%TPM_EXE_PATH%pcrread -ha 16 -halg %%H -of tmp.bin > run.out
    	IF !ERRORLEVEL! NEQ 0 (
      	    exit /B 1
      	)

    	echo "Verify the read data %%H"
    	diff policies/%%Hextaaa0.bin tmp.bin > run.out
    	IF !ERRORLEVEL! NEQ 0 (
      	    exit /B 1
      	)
    )

    echo ""
    echo "PCR Event"
    echo ""

    echo "PCR Reset"
    %TPM_EXE_PATH%pcrreset -ha 16 > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    echo "PCR Event !EVENT[%%i]!"
    %TPM_EXE_PATH%pcrevent -ha 16 -if policies/aaa !EVENT[%%i]! > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    for %%H in (!BANKS[%%i]!) do (

    	echo "Verify Digest %%H"
    	diff policies/%%Haaa.bin tmp%%H.bin > run.out > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "PCR Read %%H"
	%TPM_EXE_PATH%pcrread -ha 16 -halg %%H -of tmp%%H.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Verify Digest %%H"
	diff policies/%%Hexthaaa.bin tmp%%H.bin > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)
    )

    echo ""
    echo "Event Sequence Complete"
    echo ""

    echo "PCR Reset"
    %TPM_EXE_PATH%pcrreset -ha 16 > run.out
        IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Event sequence start, alg null"
    %TPM_EXE_PATH%hashsequencestart -halg null -pwda aaa > run.out
        IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    echo "Event Sequence Complete"
    %TPM_EXE_PATH%eventsequencecomplete -hs 80000000 -pwds aaa -ha 16 -if policies/aaa !EVENT[%%i]! > run.out
        IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
    )

    for %%H in (!BANKS[%%i]!) do (

    	echo "Verify Digest %%H"
	diff policies/%%Haaa.bin tmp%%H.bin > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)
	
	echo "PCR Read %%H"
	%TPM_EXE_PATH%pcrread -ha 16 -halg %%H -of tmp%%H.bin > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

	echo "Verify Digest %%H"
	diff policies/%%Hexthaaa.bin tmp%%H.bin > run.out
	    IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

    )

)

echo "PCR Reset"
%TPM_EXE_PATH%pcrreset -ha 16 > run.out
IF !ERRORLEVEL! NEQ 0 (
  exit /B 1
)

REM # recreate the primary key that was flushed on the powerup

echo "Create a platform primary storage key"
%TPM_EXE_PATH%createprimary -hi p -pwdk sto -pol policies/zerosha256.bin -tk pritk.bin -ch prich.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

exit /B 0
