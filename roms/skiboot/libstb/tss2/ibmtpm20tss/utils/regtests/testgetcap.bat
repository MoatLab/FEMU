#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2019                                            #
# 										#
# All rights reserved.								#
# 										#
# Redistribution and use in source and binary forms, with or without		#
# modification, are permitted provided that the following conditions are	#
# met:										#
# 										#
# Redistributions of source code must retain the above copyright notice,	#
# this list of conditions and the following disclaimer.				#
# 										#
# Redistributions in binary form must reproduce the above copyright		#
# notice, this list of conditions and the following disclaimer in the		#
# documentation and/or other materials provided with the distribution.		#
# 										#
# Neither the names of the IBM Corporation nor the names of its			#
# contributors may be used to endorse or promote products derived from		#
# this software without specific prior written permission.			#
# 										#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		#
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		#
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR		#
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		#
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	#
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		#
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,		#
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY		#
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		#
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE		#
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		#
#										#
#################################################################################

setlocal enableDelayedExpansion

# used for the name in policy authorize

echo ""
echo "Get Capability"
echo ""

echo "Get Capability TPM_CAP_ALGS"
%TPM_EXE_PATH%getcapability -cap 0 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo ""
echo "Get Capability TPM_CAP_HANDLES"
echo ""

echo "TPM_HT_PCR"
%TPM_EXE_PATH%getcapability -cap 1 -pr 00000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "TPM_HT_NV_INDEX"
%TPM_EXE_PATH%getcapability -cap 1 -pr 01000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "TPM_HT_LOADED_SESSION"
%TPM_EXE_PATH%getcapability -cap 1 -pr 02000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
				  
echo "TPM_HT_SAVED_SESSION"			  
%TPM_EXE_PATH%getcapability -cap 1 -pr 03000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
				  
echo "TPM_HT_PERMANENT"			  
%TPM_EXE_PATH%getcapability -cap 1 -pr 40000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
				  
echo "TPM_HT_TRANSIENT"			  
%TPM_EXE_PATH%getcapability -cap 1 -pr 80000000  > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
				  
echo "TPM_HT_PERSISTENT"			  
%TPM_EXE_PATH%getcapability -cap 1 -pr 81000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
				  
echo "Get Capability TPM_CAP_COMMANDS"
%TPM_EXE_PATH%getcapability -cap 2 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
				  
echo "Get Capability TPM_CAP_PP_COMMANDS"
%TPM_EXE_PATH%getcapability -cap 3 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
				  
echo "Get Capability TPM_CAP_AUDIT_COMMANDS"
%TPM_EXE_PATH%getcapability -cap 4 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)

echo "Get Capability TPM_CAP_PCRS"
%TPM_EXE_PATH%getcapability -cap 5 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
				  
echo ""
echo "Get Capability TPM_CAP_TPM_PROPERTIES"
echo ""

echo "Get Capability TPM_CAP_TPM_PROPERTIES 100"
%TPM_EXE_PATH%getcapability -cap 6 -pr 100 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
				  
echo "Get Capability TPM_CAP_TPM_PROPERTIES 200"
%TPM_EXE_PATH%getcapability -cap 6 -pr 200 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
				  
echo "Get Capability TPM_CAP_PCR_PROPERTIES "
%TPM_EXE_PATH%getcapability -cap 7 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
				  
echo "Get Capability TPM_CAP_ECC_CURVES"
%TPM_EXE_PATH%getcapability -cap 8 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
				  
echo "Get Capability TPM_CAP_AUTH_POLICIES"
%TPM_EXE_PATH%getcapability -cap 9 -pr 40000000 > run.out
IF !ERRORLEVEL! NEQ 0 (
   exit /B 1
)
				  
exit /B 0
