#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2015 - 2019					#
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

#
# for pcrextend
#

# extend of aaa + 0 pad to digest length using pcrextend, use resettable PCR 16

# sha1extaaa0.bin
# 1d 47 f6 8a ce d5 15 f7 79 73 71 b5 54 e3 2d 47 
# 98 1a a0 a0 

# sha256extaaa0.bin
# c2 11 97 64 d1 16 13 bf 07 b7 e2 04 c3 5f 93 73 
# 2b 4a e3 36 b4 35 4e bc 16 e8 d0 c3 96 3e be bb 

# sha384extaaa0.bin
# 29 29 63 e3 1c 34 c2 72 bd ea 27 15 40 94 af 92 
# 50 ad 97 d9 e7 44 6b 83 6d 3a 73 7c 90 ca 47 df 
# 2c 39 90 21 ce dd 00 85 3e f0 84 97 c5 a4 23 84 

# sha512extaaa0.bin
# 7f e1 e4 cf 01 52 93 13 6b f1 30 18 30 39 b6 a6 
# 46 ea 00 8b 75 af d0 f8 46 6a 9b fe 53 1a f8 ad 
# a8 67 a6 58 28 cf ce 48 60 77 52 9e 54 f1 83 0a 
# a4 9a b7 80 56 2b ae a4 9c 67 a8 73 34 ff e7 78 

#
# for pcrevent
#

# first hash using hash -ic aaa -ns
# then extend using policymaker

# sha1 of aaa
# 7e240de74fb1ed08fa08d38063f6a6a91462a815
# extend
# ab 53 c7 ec 3f fe fe 21 9e 9d 89 da f1 8e 16 55 
# 3e 23 8e a6 

# sha256 of aaa
# 9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0
# extend
# df 81 1e 9d 19 a0 d3 3d e6 7b b1 c7 26 a6 20 5c 
# d0 a2 eb 0f 61 b7 c9 ee 91 66 eb cf dc 17 db ab 

# sha384 of aaa
# 8e07e5bdd64aa37536c1f257a6b44963cc327b7d7dcb2cb47a22073d33414462bfa184487cf372ce0a19dfc83f8336d8
# extend of that
# 61 bc 70 39 e2 94 87 c2 17 b0 b1 46 10 5d 64 e6 
# ad 32 a6 d5 c2 5b 45 01 a7 4b bc a7 7f cc 24 25 
# 36 ca 1a 40 f9 36 44 f0 d8 b0 98 ea a6 50 97 4d 

# sha512 of aaa
# d6f644b19812e97b5d871658d6d3400ecd4787faeb9b8990c1e7608288664be77257104a58d033bcf1a0e0945ff06468ebe53e2dff36e248424c7273117dac09 
# extend of that (using policymaker)
# cb 7f be b3 1c 29 61 24 4c 9c 47 80 84 0d b4 3a 
# 76 3f ba 96 ef c1 d9 52 f4 e3 e0 2c 06 8a 31 8a 
# e5 3f a0 a7 a1 74 e8 23 e3 07 1a cd c6 52 6f b6 
# 77 6d 07 0f 36 47 27 4d a6 29 db c9 10 a7 6c 2a 

# all these variables are related

# bank algorithm test pattern is

BANKS=( \
    "sha1"			\
    "sha256"			\
    "sha384"			\
    "sha512"			\
    "sha1   sha256"		\
    "sha1   sha384"		\
    "sha1   sha512"		\
    "sha256 sha384"		\
    "sha256 sha512"		\
    "sha384 sha512"		\
    "sha1   sha256 sha384"	\
    "sha1   sha256 sha512"	\
    "sha1   sha384 sha512"	\
    "sha256 sha384 sha512"	\
    "sha1   sha256 sha384 sha512"
)

# bank extend algorithm test pattern is

EXTEND=( \
    "-halg sha1"			\
    "-halg sha256"			\
    "-halg sha384"			\
    "-halg sha512"			\
    "-halg sha1   -halg sha256"		\
    "-halg sha1   -halg sha384"		\
    "-halg sha1   -halg sha512"		\
    "-halg sha256 -halg sha384"		\
    "-halg sha256 -halg sha512"		\
    "-halg sha384 -halg sha512"		\
    "-halg sha1   -halg sha256 -halg sha384"	
    "-halg sha1   -halg sha256 -halg sha512"	\
    "-halg sha1   -halg sha384 -halg sha512"	\
    "-halg sha256 -halg sha384 -halg sha512"	\
    "-halg sha1   -halg sha256 -halg sha384 -halg sha512"	\
)

# bank event file test pattern is

EVENT=( \
    "-of1 tmpsha1.bin"			\
    "-of2 tmpsha256.bin"			\
    "-of3 tmpsha384.bin"			\
    "-of5 tmpsha512.bin"			\
    "-of1 tmpsha1.bin   -of2 tmpsha256.bin"		\
    "-of1 tmpsha1.bin   -of3 tmpsha384.bin"		\
    "-of1 tmpsha1.bin   -of5 tmpsha512.bin"		\
    "-of2 tmpsha256.bin -of3 tmpsha384.bin"		\
    "-of2 tmpsha256.bin -of5 tmpsha512.bin"		\
    "-of3 tmpsha384.bin -of5 tmpsha512.bin"		\
    "-of1 tmpsha1.bin   -of2 tmpsha256.bin -of3 tmpsha384.bin"	\
    "-of1 tmpsha1.bin   -of2 tmpsha256.bin -of5 tmpsha512.bin"	\
    "-of1 tmpsha1.bin   -of3 tmpsha384.bin -of5 tmpsha512.bin"	\
    "-of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin"	\
    "-of1 tmpsha1.bin   -of2 tmpsha256.bin -of3 tmpsha384.bin -of5 tmpsha512.bin"
)

# assuming starts with starts with sha1 sha256 sha384 sha512

ALLOC=( \
    "-sha256 -sha384 -sha512"		\
    "-sha1   +sha256"			\
    "-sha256 +sha384"			\
    "-sha384 +sha512"			\
    "+sha1   +sha256 -sha512"		\
    "-sha256 +sha384"			\
    "-sha384 +sha512"			\
    "-sha1   +sha256 +sha384 -sha512"	\
    "-sha384 +sha512"			\
    "-sha256 +sha384"			\
    "+sha1   +sha256 -sha512"		\
    "-sha384 +sha512"			\
    "-sha256 +sha384"			\
    "-sha1   +sha256"			\
    "+sha1"
)

# i is iterator over PCR bank allocation patterns
for ((i = 0 ; i < 15 ; i++))
do
    echo ""
    echo "pcrallocate ${BANKS[i]}"
    echo ""
    ${PREFIX}pcrallocate ${ALLOC[i]} > run.out
    checkSuccess $?

    echo "powerup"
    ${PREFIX}powerup > run.out
    checkSuccess $?

    echo "startup"
    ${PREFIX}startup > run.out
    checkSuccess $?

    echo "display PCR banks"
    ${PREFIX}getcapability -cap 5 > run.out
    checkSuccess $?
    
    echo ""
    echo "PCR Extend"
    echo ""

    echo "PCR Reset banks ${BANKS[i]}"
    ${PREFIX}pcrreset -ha 16 > run.out
    checkSuccess $?

    echo "PCR Extend ${EXTEND[i]}"
    ${PREFIX}pcrextend -ha 16 ${EXTEND[i]} -if policies/aaa > run.out
    checkSuccess $?

    for HALG in ${BANKS[i]}
    do
    
	echo "PCR Read ${HALG}"
	${PREFIX}pcrread -ha 16 -halg ${HALG} -of tmp.bin > run.out
	checkSuccess $?

	echo "Verify the read data ${HALG}"
	diff policies/${HALG}extaaa0.bin tmp.bin > run.out
	checkSuccess $?

    done
    
    echo ""
    echo "PCR Event"
    echo ""

    echo "PCR Reset"
    ${PREFIX}pcrreset -ha 16 > run.out
    checkSuccess $?

    echo "PCR Event ${EVENT[i]}"
    ${PREFIX}pcrevent -ha 16 -if policies/aaa ${EVENT[i]} > run.out
    checkSuccess $?

    for HALG in ${BANKS[i]}
    do

    	echo "Verify Digest ${HALG}"
    	diff policies/${HALG}aaa.bin tmp${HALG}.bin > run.out
    	checkSuccess $?

    	echo "PCR Read ${HALG}"
    	${PREFIX}pcrread -ha 16 -halg ${HALG} -of tmp${HALG}.bin > run.out
    	checkSuccess $?

    	echo "Verify Digest ${HALG}"
    	diff policies/${HALG}exthaaa.bin tmp${HALG}.bin > run.out
    	checkSuccess $?

    done

    echo ""
    echo "Event Sequence Complete"
    echo ""

    echo "PCR Reset"
    ${PREFIX}pcrreset -ha 16 > run.out
    checkSuccess $?

    echo "Event sequence start, alg null"
    ${PREFIX}hashsequencestart -halg null -pwda aaa > run.out
    checkSuccess $?

    echo "Event Sequence Complete"
    ${PREFIX}eventsequencecomplete -hs 80000000 -pwds aaa -ha 16 -if policies/aaa ${EVENT[i]} > run.out
    checkSuccess $?

    for HALG in ${BANKS[i]}
    do

	echo "Verify Digest ${HALG}"
	diff policies/${HALG}aaa.bin tmp${HALG}.bin > run.out
	checkSuccess $?
	
	echo "PCR Read ${HALG}"
	${PREFIX}pcrread -ha 16 -halg ${HALG} -of tmp${HALG}.bin > run.out
	checkSuccess $?

	echo "Verify Digest ${HALG}"
	diff policies/${HALG}exthaaa.bin tmp${HALG}.bin > run.out
	checkSuccess $?

    done

done

echo "PCR Reset"
${PREFIX}pcrreset -ha 16 > run.out
checkSuccess $?

# recreate the primary key that was flushed on the powerup

initprimary
