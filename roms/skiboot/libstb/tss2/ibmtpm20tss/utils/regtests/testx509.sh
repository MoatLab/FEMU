#!/bin/bash
#

#################################################################################
#										#
#			TPM2 regression test					#
#			     Written by Ken Goldman				#
#		       IBM Thomas J. Watson Research Center			#
#										#
# (c) Copyright IBM Corporation 2019 - 2020					#
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

# The mbedtls port does not support TPM2_CertifyX509 yet */

if [ ${CRYPTOLIBRARY} == "openssl" ]; then

echo ""
echo "TPM2_CertifyX509"
echo ""

# basic test

# sign${SKEY[i]}rpriv.bin is a restricted signing key
# sign${SKEY[i]}priv.bin is an unrestricted signing key

SALG=(rsa ecc)
SKEY=(rsa2048 ecc)

for ((i = 0 ; i < 2 ; i++))
do

    echo "Load the ${SALG[i]} issuer key 80000001 under the primary key"
    ${PREFIX}load -hp 80000000 -ipr sign${SKEY[i]}rpriv.bin -ipu sign${SKEY[i]}rpub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Load the ${SALG[i]} subject key 80000002 under the primary key"
    ${PREFIX}load -hp 80000000 -ipr sign${SKEY[i]}priv.bin -ipu sign${SKEY[i]}pub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Signing Key Self Certify CA Root ${SALG[i]}"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000001 -halg sha256 -pwdk sig -pwdo sig -opc tmppart1.bin -os tmpsig1.bin -oa tmpadd1.bin -otbs tmptbs1.bin -ocert tmpx5091.bin -salg ${SALG[i]} -sub -v -iob 00050472 > run.out
    checkSuccess $?


    # dumpasn1 -a -l -d     tmpx509i.bin > tmpx509i1.dump
    # dumpasn1 -a -l -d -hh tmpx509i.bin > tmpx509i1.dumphh
    # dumpasn1 -a -l -d     tmppart1.bin > tmppart1.dump
    # dumpasn1 -a -l -d -hh tmppart1.bin > tmppart1.dumphh
    # dumpasn1 -a -l -d     tmpadd1.bin  > tmpadd1.dump
    # dumpasn1 -a -l -d -hh tmpadd1.bin  > tmpadd1.dumphh
    # dumpasn1 -a -l -d     tmpx5091.bin > tmpx5091.dump
    # dumpasn1 -a -l -d -hh tmpx5091.bin > tmpx5091.dumphh
    # openssl x509 -text -inform der -in tmpx5091.bin -noout > tmpx5091.txt

    echo "Convert issuer X509 DER to PEM"
    openssl x509 -inform der -in tmpx5091.bin -out tmpx5091.pem > run.out 2>&1
    echo " INFO:"

    echo "Verify ${SALG[i]} self signed issuer root" 
    echo -n " INFO: "
    openssl verify -CAfile tmpx5091.pem tmpx5091.pem > run.out 2>&1

    echo "Signing Key Certify ${SALG[i]}"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -iob 00040472 > run.out
    checkSuccess $?

    # dumpasn1 -a -l -d     tmpx509i.bin > tmpx509i2.dump
    # dumpasn1 -a -l -d -hh tmpx509i.bin > tmpx509i2.dumphh
    # dumpasn1 -a -l -d     tmppart2.bin > tmppart2.dump
    # dumpasn1 -a -l -d -hh tmppart2.bin > tmppart2.dumphhe 
    # dumpasn1 -a -l -d     tmpadd2.bin  > tmpadd2.dump
    # dumpasn1 -a -l -d -hh tmpadd2.bin  > tmpadd2.dumphh
    # dumpasn1 -a -l -d     tmpx5092.bin > tmpx5092.dump
    # dumpasn1 -a -l -d -hh tmpx5092.bin > tmpx5092.dumphh
    # openssl x509 -text -inform der -in tmpx5092.bin -noout > tmpx5092.txt

    echo "Convert subject X509 DER to PEM"
    openssl x509 -inform der -in tmpx5092.bin -out tmpx5092.pem > run.out 2>&1
    echo " INFO:"

    echo "Verify ${SALG[i]} subject against issuer" 
    echo -n " INFO: "
    openssl verify -CAfile tmpx5091.pem tmpx5092.pem > run.out 2>&1


    echo "Signing Key Certify ${SALG[i]} with bad OID"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -iob ffffffff > run.out
    checkFailure $?

# bad der, test bits for 250 bytes
# better to get size from tmppart2.bin

    # for bit in {0..2}
    # do
    # 	echo "Signing Key Certify ${SALG[i]} testing bit $bit"
    # 	${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -bit $bit > run.out
    # 	checkSuccess0 $?
    # done

    echo "Flush the root CA issuer signing key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Flush the subject signing key"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

done

# bad extensions for key type

echo ""
echo "TPM2_CertifyX509 Key Usage Extension for fixedTPM signing key"
echo ""

for ((i = 0 ; i < 2 ; i++))
do

    echo "Load the ${SALG[i]} issuer key 80000001 under the primary key"
    ${PREFIX}load -hp 80000000 -ipr sign${SKEY[i]}rpriv.bin -ipu sign${SKEY[i]}rpub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Load the ${SALG[i]} subject key 80000002 under the primary key"
    ${PREFIX}load -hp 80000000 -ipr sign${SKEY[i]}priv.bin -ipu sign${SKEY[i]}pub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} digitalSignature"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,digitalSignature > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} nonRepudiation"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,nonRepudiation > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} keyEncipherment"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,keyEncipherment > run.out
    checkFailure $?

   echo "Signing Key Certify ${SALG[i]} dataEncipherment"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,dataEncipherment > run.out
    checkFailure $?

    echo "Signing Key Certify ${SALG[i]} keyAgreement"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,keyAgreement > run.out
    checkFailure $?

    echo "Signing Key Certify ${SALG[i]} keyCertSign"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,keyCertSign > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} cRLSign"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,cRLSign > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} encipherOnly"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,encipherOnly > run.out
    checkFailure $?

    echo "Signing Key Certify ${SALG[i]} decipherOnly"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,decipherOnly > run.out
    checkFailure $?

    echo "Flush the root CA issuer signing key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Flush the subject signing key"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

done

echo ""
echo "TPM2_CertifyX509 Key Usage Extension for not fixedTPM signing key"
echo ""

for ((i = 0 ; i < 2 ; i++))
do

    echo "Load the ${SALG[i]} issuer key 80000001 under the primary key"
    ${PREFIX}load -hp 80000000 -ipr sign${SKEY[i]}nfpriv.bin -ipu sign${SKEY[i]}nfpub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Load the ${SALG[i]} subject key 80000002 under the primary key"
    ${PREFIX}load -hp 80000000 -ipr sign${SKEY[i]}nfpriv.bin -ipu sign${SKEY[i]}nfpub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} digitalSignature"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,digitalSignature > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} nonRepudiation"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,nonRepudiation > run.out
    checkFailure $?

    echo "Signing Key Certify ${SALG[i]} keyEncipherment"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SAL[i]} -ku critical,keyEncipherment > run.out
    checkFailure $?

   echo "Signing Key Certify ${SALG[i]} dataEncipherment"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,dataEncipherment > run.out
    checkFailure $?

    echo "Signing Key Certify ${SALG[i]} keyAgreement"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,keyAgreement > run.out
    checkFailure $?

    echo "Signing Key Certify ${SALG[i]} keyCertSign"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,keyCertSign > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} cRLSign"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,cRLSign > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} encipherOnly"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,encipherOnly > run.out
    checkFailure $?

    echo "Signing Key Certify ${SALG[i]} decipherOnly"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sig -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,decipherOnly > run.out
    checkFailure $?

    echo "Flush the root CA issuer signing key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Flush the subject signing key"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

done

echo ""
echo "TPM2_CertifyX509 Key Usage Extension for fixedTpm restricted encryption key"
echo ""

for ((i = 0 ; i < 2 ; i++))
do

    echo "Load the ${SALG[i]} issuer key 80000001 under the primary key"
    ${PREFIX}load -hp 80000000 -ipr sign${SKEY[i]}rpriv.bin -ipu sign${SKEY[i]}rpub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Load the ${SALG[i]} subject key 80000002 under the primary key"
    ${PREFIX}load -hp 80000000 -ipr store${SKEY[i]}priv.bin -ipu store${SKEY[i]}pub.bin -pwdp sto > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} digitalSignature"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sto -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,digitalSignature > run.out
    checkFailure $?

    echo "Signing Key Certify ${SALG[i]} nonRepudiation"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sto -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,nonRepudiation > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} keyEncipherment"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sto -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,keyEncipherment > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} dataEncipherment"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sto -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,dataEncipherment > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} keyAgreement"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sto -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,keyAgreement > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} keyCertSign"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sto -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,keyCertSign > run.out
    checkFailure $?

    echo "Signing Key Certify ${SALG[i]} cRLSign"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sto -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,cRLSign > run.out
    checkFailure $?

    echo "Signing Key Certify ${SALG[i]} encipherOnly"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sto -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,encipherOnly > run.out
    checkSuccess $?

    echo "Signing Key Certify ${SALG[i]} decipherOnly"
    ${PREFIX}certifyx509 -hk 80000001 -ho 80000002 -halg sha256 -pwdk sig -pwdo sto -opc tmppart2.bin -os tmpsig2.bin -oa tmpadd2.bin -otbs tmptbs2.bin -ocert tmpx5092.bin -salg ${SALG[i]} -ku critical,decipherOnly > run.out
    checkSuccess $?

    echo "Flush the root CA issuer signing key"
    ${PREFIX}flushcontext -ha 80000001 > run.out
    checkSuccess $?

    echo "Flush the subject signing key"
    ${PREFIX}flushcontext -ha 80000002 > run.out
    checkSuccess $?

done

# cleanup

rm -r tmppart1.bin
rm -r tmpadd1.bin
rm -r tmptbs1.bin
rm -r tmpsig1.bin
rm -r tmpx5091.bin
rm -r tmpx5091.pem
rm -r tmpx5092.pem
rm -r tmpx509i.bin
rm -r tmppart2.bin
rm -r tmpadd2.bin
rm -r tmptbs2.bin
rm -r tmpsig2.bin
rm -r tmpx5092.bin

# openssl only
fi
