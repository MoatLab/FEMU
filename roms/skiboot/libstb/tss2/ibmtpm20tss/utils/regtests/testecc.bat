REM #############################################################################
REM #										#
REM #			TPM2 regression test					#
REM #			     Written by Ken Goldman				#
REM #		       IBM Thomas J. Watson Research Center			#
REM #										#
REM # (c) Copyright IBM Corporation 2015 - 2019.				#
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
echo "ECC Ephemeral"
echo ""

echo ""
echo "ECC Parameters and Ephemeral"
echo ""

for %%C in (bnp256 nistp256 nistp384) do (

    echo "ECC Parameters for curve %%C"
    %TPM_EXE_PATH%eccparameters -cv %%C > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )

    for %%A in (-si -sir) do (

	echo "Create %%A for curve %%C"
	%TPM_EXE_PATH%create -hp 80000000 -pwdp sto %%A -ecc %%C > run.out
	IF !ERRORLEVEL! NEQ 0 (
	    exit /B 1
	)

    )

    echo "EC Ephemeral for curve %%C"
    %TPM_EXE_PATH%ecephemeral -ecc %%C > run.out
    IF !ERRORLEVEL! NEQ 0 (
        exit /B 1
    )
)

echo ""
echo "ECC Commit"
echo ""

echo "Start an HMAC auth session"
%TPM_EXE_PATH%startauthsession -se h > run.out
IF !ERRORLEVEL! NEQ 0 (
    exit /B 1
)

for %%K in ("-dau" "-dar") do (

    for %%S in ("" "-se0 02000000 1") do (

	echo "Create a %%~K ECDAA signing key under the primary key"
	%TPM_EXE_PATH%create -hp 80000000 -ecc bnp256 %%~K -nalg sha256 -halg sha256 -kt f -kt p -opr tmprpriv.bin -opu tmprpub.bin -pwdp sto -pwdk siga > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)

	echo "Load the signing key 80000001 under the primary key 80000000"
	%TPM_EXE_PATH%load -hp 80000000 -ipr tmprpriv.bin -ipu tmprpub.bin -pwdp sto > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)

    	REM %TPM_EXE_PATH%getcapability -cap 1 -pr 80000001
    	
    	REM The trick with commit is first use - empty ECC point and no s2 and y2 parameters
    	REM which means no P1, no s2 and no y2. 
    	REM and output the result and get the efile.bin
    	REM feed back the point in efile.bin as the new p1 because it is on the curve.
	
    	REM There is no test case for s2 and y2. To construct a y2 requires using Cipolla's algorithm.
	REM example of normal command    
    	REM %TPM_EXE_PATH%commit -hk 80000001 -pt p1.bin -s2 s2.bin -y2 y2_a.bin -Kf kfile.bin -Lf lfile.bin -Ef efile.bin -pwdk siga > run.out
	
	echo "Create new point E, based on point-multiply of TPM's commit random scalar and Generator point %%~S"
	%TPM_EXE_PATH%commit -hk 80000001 -Ef efile.bin -pwdk siga  %%~S > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)

        REM copy efile as new p1 - for hash operation
        cp efile.bin p1.bin

        REM We have a point on the curve - in efile.bin.  Use E as P1 and feed it back in
		
	REM All this does is simulate the commit that the FIDO alliance wants to
	REM use in its TPM Join operation.
		
	echo "Create new point E, based on point-multiply of TPM's commit random scalar and input point %%~S"
	%TPM_EXE_PATH%commit -hk 80000001 -pt p1.bin -Ef efile.bin -cf counterfile.bin -pwdk siga %%~S > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)

        cat efile.bin p1.bin tmprpub.bin > hashinput.bin

        echo "Hash the E, P1, and Q to create the ticket to use in signing"
        %TPM_EXE_PATH%hash -hi p -halg sha256 -if hashinput.bin -oh outhash.bin -tk tfile.bin > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)
        
        echo "Sign the hash of the points made from commit"
        %TPM_EXE_PATH%sign -hk 80000001 -pwdk siga -salg ecc -scheme ecdaa -cf counterfile.bin -if hashinput.bin -os sig.bin -tk tfile.bin > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)
        
	echo "Flush the signing key"
	%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)
    )
)

REM save old counterfile for off nominal error check
cp counterfile.bin counterfileold.bin


for %%K in ("-dau" "-dar") do (
    for %%S in ("" "-se0 02000000 1") do (

        echo "Create a %%~K ECDAA signing primary key"
        %TPM_EXE_PATH%createprimary -ecc bnp256 %%~K -nalg sha256 -halg sha256 -kt f -kt p -opu tmprpub.bin -pwdk siga > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)
        
        REM %TPM_EXE_PATH%getcapability -cap 1 -pr 80000001
        
        REM The trick with commit is first use - empty ECC point and no s2 and y2 parameters
        REM which means no P1, no s2 and no y2. 
        REM and output the result and get the efile.bin
        REM feed back the point in efile.bin as the new p1 because it is on the curve.
        
        REM There is no test case for s2 and y2. To construct a y2 requires using Cipolla's algorithm.
        REM example of normal command    
        REM %TPM_EXE_PATH%commit -hk 80000001 -pt p1.bin -s2 s2.bin -y2 y2_a.bin -Kf kfile.bin -Lf lfile.bin -Ef efile.bin -cf counterfile.bin -pwdk siga > run.out
        
        echo "Create new point E, based on point-multiply of TPM's commit random scalar and Generator point %%~S"
        %TPM_EXE_PATH%commit -hk 80000001 -Ef efile.bin -cf counterfile.bin -pwdk siga %%~S > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)
        
	REM copy efile as new p1 - for hash operation
        cp efile.bin p1.bin
       
        REM We have a point on the curve - in efile.bin.  Use E as P1 and feed it back in
        
        REM All this does is simulate the commit that the FIDO alliance wants to
        REM use in its TPM Join operation.
        
        echo "Create new point E, based on point-multiply of TPM's commit random scalar and input point %%~S"
        %TPM_EXE_PATH%commit -hk 80000001 -pt efile.bin -Ef efile.bin -pwdk siga %%~S > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)

        cat efile.bin p1.bin tmprpub.bin > hashinput.bin

        echo "Hash the E, P1, and Q to create the ticket to use in signing"
        %TPM_EXE_PATH%hash -hi p -halg sha256 -if hashinput.bin -oh outhash.bin -tk tfile.bin > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)

        echo "Check error case bad counter"
        %TPM_EXE_PATH%sign -hk 80000001 -pwdk siga -salg ecc -scheme ecdaa -cf counterfileold.bin -if hashinput.bin -os sig.bin -tk tfile.bin  > run.out
    	IF !ERRORLEVEL! EQU 0 (
           exit /B 1
    	)

        echo "Sign the hash of the points made from commit"
        %TPM_EXE_PATH%sign -hk 80000001 -pwdk siga -salg ecc -scheme ecdaa -cf counterfile.bin -if hashinput.bin -os sig.bin -tk tfile.bin  > run.out
    	IF !ERRORLEVEL! NEQ 0 (
           exit /B 1
    	)

        echo "Flush the signing key"
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
echo "ECC zgen2phase"
echo ""

echo "ECC Parameters for curve nistp256"
%TPM_EXE_PATH%eccparameters -cv nistp256 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM This is just a script for a B "remote" side to create a static key
REM pair and ephemeral for use in demonstrating (on the local side) a
REM two-phase operation involving ecephemeral and zgen2phase

echo "Create decryption key for curve nistp256"
%TPM_EXE_PATH%create -hp 80000000 -pwdp sto -den -ecc nistp256 -opu QsBpub.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "EC Ephemeral for curve nistp256"
%TPM_EXE_PATH%ecephemeral -ecc nistp256 -oq QeBpt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

REM local side
REM 
REM scp or cp the QsBpub.bin and QeBpt.bin from the B side over to the
REM A side. This assumes QsBpub is a TPM2B_PUBLIC from a create command
REM on B side.  QeBpt is already in TPM2B_ECC_POINT form since it was
REM created by ecephemeral on B side QsBpub.bin is presumed in a form
REM produced by a create commamnd using another TPM

echo "Create decryption key for curve nistp256"
%TPM_EXE_PATH%create -hp 80000000 -pwdp sto -den -ecc nistp256 -opr QsApriv.bin -opu QsApub.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Load the decryption key under the primary key, 80000001"
%TPM_EXE_PATH%load -hp 80000000 -ipr QsApriv.bin -ipu QsApub.bin -pwdp sto > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "EC Ephemeral for curve nistp256"
%TPM_EXE_PATH%ecephemeral -ecc nistp256 -oq QeApt.bin -cf counter.bin  > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Convert public raw to TPM2B_ECC_POINT"
%TPM_EXE_PATH%tpmpublic2eccpoint -ipu QsBpub.bin -pt QsBpt.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Execute zgen2phase for curve nistp256"
%TPM_EXE_PATH%zgen2phase -hk 80000001 -scheme ecdh -qsb QsBpt.bin -qeb QeBpt.bin -cf counter.bin > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Flush the key"
%TPM_EXE_PATH%flushcontext -ha 80000001 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

rm -rf efile.bin
rm -rf tmprpub.bin
rm -rf tmprpriv.bin
rm -rf counterfile.bin
rm -rf counterfileold.bin
rm -rf p1.bin
rm -rf hashinput.bin
rm -rf outhash.bin
rm -rf sig.bin
rm -rf tfile.bin

rm -rf QsBpub.bin
rm -rf QeBpt.bin
rm -rf QsApriv.bin
rm -rf QsApub.bin
rm -rf QeApt.bin
rm -rf counter.bin
rm -rf QsBpt.bin

REM %TPM_EXE_PATH%getcapability -cap 1 -pr 80000000
REM %TPM_EXE_PATH%getcapability -cap 1 -pr 02000000
exit /B 0
