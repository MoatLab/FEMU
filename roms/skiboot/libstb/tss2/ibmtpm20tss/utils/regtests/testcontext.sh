#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2015 - 2020					#
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

echo ""
echo "Context"
echo ""

echo ""
echo "Basic Context"
echo ""

echo "Start an HMAC auth session"
${PREFIX}startauthsession -se h > run.out
checkSuccess $?

echo "Load the signing key under the primary key"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto -se0 02000000 1 > run.out
checkSuccess $?

echo "Sign a digest"
${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 1 > run.out
checkSuccess $?

echo "Verify the signature"
${PREFIX}verifysignature -hk 80000001 -halg sha256 -if msg.bin -is sig.bin > run.out
checkSuccess $?

echo "Save context for the key"
${PREFIX}contextsave -ha 80000001 -of tmp.bin > run.out
checkSuccess $?

echo "Sign to verify that the original key is not flushed"
${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 1 > run.out
checkSuccess $?

echo "Flush the original key"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Sign with original key  - should fail"
${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 1 > run.out
checkFailure $?

echo "Load context"
${PREFIX}contextload -if tmp.bin > run.out
checkSuccess $?

echo "Sign with the loaded context"
${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 1 > run.out
checkSuccess $?

echo "Save context for the session"
${PREFIX}contextsave -ha 02000000 -of tmp.bin > run.out
checkSuccess $?

echo "Sign with the saved session context - should fail"
${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 1 > run.out
checkFailure $?

echo "Load context for the session"
${PREFIX}contextload -if tmp.bin > run.out
checkSuccess $?

echo "Sign with the saved session context"
${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 1 > run.out
checkSuccess $?

echo "Flush the loaded context"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the session"
${PREFIX}flushcontext -ha 02000000 > run.out
checkSuccess $?

echo ""
echo "Context Public Key for Salt"
echo ""

echo "Load the storage key at 80000001"
${PREFIX}load -hp 80000000 -ipr storersa2048priv.bin -ipu storersa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Save context for the storage key at 80000001"
${PREFIX}contextsave -ha 80000001 -of tmp.bin > run.out
checkSuccess $?

echo "Load context at 80000002"
${PREFIX}contextload -if tmp.bin > run.out
checkSuccess $?

echo "Flush the original key at 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Start an HMAC auth session at 02000000 using the storage key 80000002 salt"
${PREFIX}startauthsession -se h -hs 80000002 > run.out
checkSuccess $?

echo "Load the signing key under the primary key at 80000001"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Sign a digest"
${PREFIX}sign -hk 80000001 -halg sha256 -if msg.bin -os sig.bin -pwdk sig -se0 02000000 0 > run.out
checkSuccess $?

echo "Flush the signing key at 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?

echo "Flush the salt key at 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo ""
echo "Context Primary Key"
echo ""

echo "Save context for the primary key at 80000000"
${PREFIX}contextsave -ha 80000000 -of tmp.bin > run.out
checkSuccess $?

echo "Load context primary key at 80000001"
${PREFIX}contextload -if tmp.bin > run.out
checkSuccess $?

echo "Load the signing key at 80000002 under the primary key at 80000001"
${PREFIX}load -hp 80000000 -ipr signrsa2048priv.bin -ipu signrsa2048pub.bin -pwdp sto > run.out
checkSuccess $?

echo "Flush the signing key at 80000002"
${PREFIX}flushcontext -ha 80000002 > run.out
checkSuccess $?

echo "Flush the primary key at 80000001"
${PREFIX}flushcontext -ha 80000001 > run.out
checkSuccess $?



# ${PREFIX}getcapability  -cap 1 -pr 80000000
# ${PREFIX}getcapability  -cap 1 -pr 02000000
