/********************************************************************************/
/*										*/
/*			OpenSSL Crypto Utilities				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2018 - 2020.					*/
/*										*/
/* All rights reserved.								*/
/* 										*/
/* Redistribution and use in source and binary forms, with or without		*/
/* modification, are permitted provided that the following conditions are	*/
/* met:										*/
/* 										*/
/* Redistributions of source code must retain the above copyright notice,	*/
/* this list of conditions and the following disclaimer.			*/
/* 										*/
/* Redistributions in binary form must reproduce the above copyright		*/
/* notice, this list of conditions and the following disclaimer in the		*/
/* documentation and/or other materials provided with the distribution.		*/
/* 										*/
/* Neither the names of the IBM Corporation nor the names of its		*/
/* contributors may be used to endorse or promote products derived from		*/
/* this software without specific prior written permission.			*/
/* 										*/
/* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS		*/
/* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT		*/
/* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR	*/
/* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT		*/
/* HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,	*/
/* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT		*/
/* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,	*/
/* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY	*/
/* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT		*/
/* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE	*/
/* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.		*/
/********************************************************************************/

/* These functions are worthwhile sample code that probably (judgment call) do not belong in the TSS
   library.

   They abstract out crypto library functions.

   They show how to convert public or private EC or RSA among PEM format <-> EVP format <-> EC_KEY
   or RSA format <-> binary arrays <-> TPM format TPM2B_PRIVATE, TPM2B_SENSITIVE, TPM2B_PUBLIC
   usable for loadexternal or import.

   There are functions to convert public keys from TPM <-> RSA, ECC <-> PEM, and to verify a TPM
   signature using a PEM format public key.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

#ifndef TPM_TSS_NORSA
#include <openssl/rsa.h>
#endif /* TPM_TSS_NORSA */
#include <openssl/objects.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#ifndef TPM_TSS_NOECC
#include <openssl/ec.h>
#endif

#ifndef TPM_TSS_NOFILE
#include <ibmtss/tssfile.h>
#endif
#include <ibmtss/tssutils.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/Implementation.h>

#include "objecttemplates.h"
#include "cryptoutils.h"

/* verbose tracing flag shared by command line utilities */

int tssUtilsVerbose;

/* openssl compatibility functions, during the transition from 1.0.1, 1.0.2, 1.1.0, 1.1.1.  Some
   structures were made opaque, with gettters and setters.  Some parameters were made const.  Some
   function names changed. */

/* Some functions add const to parameters as of openssl 1.1.0 */

/* These functions are only required for OpenSSL 1.0.  OpenSSL 1.1 has them, and the structures are
   opaque. */

#if OPENSSL_VERSION_NUMBER < 0x10100000

int ECDSA_SIG_set0(ECDSA_SIG *sig, BIGNUM *r, BIGNUM *s)
{
    if (r == NULL || s == NULL)
	return 0;
    BN_clear_free(sig->r);
    BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;
    return 1;
}

void ECDSA_SIG_get0(const ECDSA_SIG *sig, const BIGNUM **pr, const BIGNUM **ps)
{
    if (pr != NULL) {
	*pr = sig->r;
    }
    if (ps != NULL) {
	*ps = sig->s;
    }
    return;
}

const X509_ALGOR *X509_get0_tbs_sigalg(const X509 *x)
{
    return x->cert_info->signature;
}

void RSA_get0_key(const RSA *rsaKey,
		  const BIGNUM **n,
		  const BIGNUM **e,
		  const BIGNUM **d)
{
    if (n != NULL) {
	*n = rsaKey->n;
    }
    if (e != NULL) {
	*e = rsaKey->e;
    }
    if (d != NULL) {
	*d = rsaKey->d;
    }
    return;
}

void RSA_get0_factors(const RSA *rsaKey,
		      const BIGNUM **p,
		      const BIGNUM **q)
{
    if (p != NULL) {
	*p = rsaKey->p;
    }
    if (q != NULL) {
	*q = rsaKey->q;
    }
    return;
}

#endif	/* pre openssl 1.1 */

/* These functions are only required for OpenSSL 1.0.1 OpenSSL 1.0.2 has them, and the structures
   are opaque.   In 1.1.0, the parameters became const.  */

#if OPENSSL_VERSION_NUMBER < 0x10002000

void X509_get0_signature(OSSLCONST ASN1_BIT_STRING **psig,
                         OSSLCONST X509_ALGOR **palg, const X509 *x)
{
    *psig = x->signature;
    *palg = x->sig_alg;
    return;
}

#endif	/* pre openssl 1.0.2 */

#ifndef TPM_TSS_NOFILE

/* getCryptoLibrary() returns a string indicating the underlying crypto library.

   It can be used for programs that must account for library differences.
*/

void getCryptoLibrary(const char **name)
{
    *name = "openssl";
    return;
}
    
/* convertPemToEvpPrivKey() converts a PEM key file to an openssl EVP_PKEY key pair */

TPM_RC convertPemToEvpPrivKey(EVP_PKEY **evpPkey,		/* freed by caller */
			      const char *pemKeyFilename,
			      const char *password)
{
    TPM_RC 	rc = 0;
    FILE 	*pemKeyFile = NULL;

    if (rc == 0) {
	rc = TSS_File_Open(&pemKeyFile, pemKeyFilename, "rb"); 	/* closed @2 */
    }
    if (rc == 0) {
	*evpPkey = PEM_read_PrivateKey(pemKeyFile, NULL, NULL, (void *)password);
	if (*evpPkey == NULL) {
	    printf("convertPemToEvpPrivKey: Error reading key file %s\n", pemKeyFilename);
	    rc = EXIT_FAILURE;
	}
    }
    if (pemKeyFile != NULL) {
	fclose(pemKeyFile);			/* @2 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE

/* convertPemToEvpPubKey() converts a PEM public key file to an openssl EVP_PKEY public key */

TPM_RC convertPemToEvpPubKey(EVP_PKEY **evpPkey,		/* freed by caller */
			     const char *pemKeyFilename)
{
    TPM_RC 	rc = 0;
    FILE 	*pemKeyFile = NULL;

    if (rc == 0) {
	rc = TSS_File_Open(&pemKeyFile, pemKeyFilename, "rb"); 	/* closed @2 */
    }
    if (rc == 0) {
	*evpPkey = PEM_read_PUBKEY(pemKeyFile, NULL, NULL, NULL);
	if (*evpPkey == NULL) {
	    printf("convertPemToEvpPubKey: Error reading key file %s\n", pemKeyFilename);
	    rc = EXIT_FAILURE;
	}
    }
    if (pemKeyFile != NULL) {
	fclose(pemKeyFile);			/* @2 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE

/* convertPemToRsaPrivKey() converts a PEM format keypair file to a library specific RSA key
   token.

   The return is void because the structure is opaque to the caller.  This accomodates other crypto
   libraries.

   rsaKey is an RSA structure 
*/

TPM_RC convertPemToRsaPrivKey(void **rsaKey,		/* freed by caller */
			      const char *pemKeyFilename,
			      const char *password)
{
    TPM_RC 	rc = 0;
    FILE 	*pemKeyFile = NULL;

    if (rc == 0) {
	rc = TSS_File_Open(&pemKeyFile, pemKeyFilename, "rb"); 	/* closed @1 */
    }
    if (rc == 0) {
	*rsaKey = (void *)PEM_read_RSAPrivateKey(pemKeyFile, NULL, NULL, (void *)password);
	if (*rsaKey == NULL) {
	    printf("convertPemToRsaPrivKey: Error in OpenSSL PEM_read_RSAPrivateKey()\n");
	    rc = EXIT_FAILURE;
	}
    }
    if (pemKeyFile != NULL) {
	fclose(pemKeyFile);			/* @1 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOECC

/* convertEvpPkeyToEckey retrieves the EC_KEY key token from the EVP_PKEY */

TPM_RC convertEvpPkeyToEckey(EC_KEY **ecKey,		/* freed by caller */
			     EVP_PKEY *evpPkey)
{
    TPM_RC 	rc = 0;
    
    if (rc == 0) {
	*ecKey = EVP_PKEY_get1_EC_KEY(evpPkey);
	if (*ecKey == NULL) {
	    printf("convertEvpPkeyToEckey: Error extracting EC key from EVP_PKEY\n");
	    rc = EXIT_FAILURE;
	}
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

/* convertEvpPkeyToRsakey() retrieves the RSA key token from the EVP_PKEY */

TPM_RC convertEvpPkeyToRsakey(RSA **rsaKey,		/* freed by caller */
			      EVP_PKEY *evpPkey)
{
    TPM_RC 	rc = 0;
    
    if (rc == 0) {
	*rsaKey = EVP_PKEY_get1_RSA(evpPkey);
	if (*rsaKey == NULL) {
	    printf("convertEvpPkeyToRsakey: EVP_PKEY_get1_RSA failed\n");  
	    rc = EXIT_FAILURE;
	}
    }
    return rc;
}

#ifndef TPM_TSS_NOECC

/* convertEcKeyToPrivateKeyBin() converts an OpenSSL EC_KEY to a binary array

   FIXME  Only supports NIST P256 curve.
*/

TPM_RC convertEcKeyToPrivateKeyBin(int 		*privateKeyBytes,
				   uint8_t 	**privateKeyBin,	/* freed by caller */
				   const EC_KEY *ecKey)
{
    TPM_RC 		rc = 0;
    const EC_GROUP 	*ecGroup = NULL;
    int			nid;
    const BIGNUM 	*privateKeyBn = NULL;
    int 		bnBytes;
    
    /* get the group from the key */
    if (rc == 0) {   
	ecGroup = EC_KEY_get0_group(ecKey);
	if (ecGroup == NULL) {
	    printf("convertEcKeyToPrivateKeyBin: Error extracting EC group from EC key\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* and then the curve from the group */
    if (rc == 0) {
	nid = EC_GROUP_get_curve_name(ecGroup);
	/* map NID to size of private key */
	switch (nid) {
	  case NID_X9_62_prime256v1:
	    *privateKeyBytes = 32;
	    break;
	  default:
	    printf("convertEcKeyToPrivateKeyBin: Error, curve NID %u not supported\n", nid);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* get the ECC private key as a BIGNUM from the EC_KEY */
    if (rc == 0) {
	privateKeyBn = EC_KEY_get0_private_key(ecKey);
    }
    /* sanity check the BN size against the curve */
    if (rc == 0) {
	bnBytes = BN_num_bytes(privateKeyBn);
	if (bnBytes > *privateKeyBytes) {
	    printf("convertEcKeyToPrivateKeyBin: Error, private key %d bytes too large for curve\n",
		   bnBytes);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* allocate a buffer for the private key array  based on the curve */
    if (rc == 0) {
	rc = TSS_Malloc(privateKeyBin, *privateKeyBytes);
    }
    /* convert the private key bignum to binary */
    if (rc == 0) {
	/* TPM rev 116 required the ECC private key to be zero padded in the duplicate parameter of
	   import */
	memset(*privateKeyBin, 0, *privateKeyBytes - bnBytes);
	BN_bn2bin(privateKeyBn, (*privateKeyBin) + (*privateKeyBytes - bnBytes));
	if (tssUtilsVerbose) TSS_PrintAll("convertEcKeyToPrivateKeyBin:", *privateKeyBin, *privateKeyBytes);
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

/* convertRsaKeyToPrivateKeyBin() converts an OpenSSL RSA key token private prime p to a binary
   array */

TPM_RC convertRsaKeyToPrivateKeyBin(int 	*privateKeyBytes,
				    uint8_t 	**privateKeyBin,	/* freed by caller */
				    const RSA	*rsaKey)
{
    TPM_RC 		rc = 0;
    const BIGNUM 	*p = NULL;
    const BIGNUM 	*q;

    /* get the private primes */
    if (rc == 0) {
	rc = getRsaKeyParts(NULL, NULL, NULL, &p, &q, rsaKey);
    }
    /* allocate a buffer for the private key array */
    if (rc == 0) {
	*privateKeyBytes = BN_num_bytes(p);
	rc = TSS_Malloc(privateKeyBin, *privateKeyBytes);
    }
    /* convert the private key bignum to binary */
    if (rc == 0) {
	BN_bn2bin(p, *privateKeyBin);
    }    
    return rc;
}


#ifndef TPM_TSS_NOECC

/* convertEcKeyToPublicKeyBin() converts an OpenSSL EC_KEY public key token to a binary array */

TPM_RC convertEcKeyToPublicKeyBin(int 		*modulusBytes,
				  uint8_t 	**modulusBin,	/* freed by caller */
				  const EC_KEY 	*ecKey)
{
    TPM_RC 		rc = 0;
    const EC_POINT 	*ecPoint = NULL;
    const EC_GROUP 	*ecGroup = NULL;

    if (rc == 0) {
	ecPoint = EC_KEY_get0_public_key(ecKey);
	if (ecPoint == NULL) {
	    printf("convertEcKeyToPublicKeyBin: Error extracting EC point from EC public key\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {   
	ecGroup = EC_KEY_get0_group(ecKey);
	if (ecGroup == NULL) {
	    printf("convertEcKeyToPublicKeyBin: Error extracting EC group from EC public key\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* get the public modulus */
    if (rc == 0) {   
	*modulusBytes = EC_POINT_point2oct(ecGroup, ecPoint,
					   POINT_CONVERSION_UNCOMPRESSED,
					   NULL, 0, NULL);
    }
    if (rc == 0) {   
	rc = TSS_Malloc(modulusBin, *modulusBytes);
    }
    if (rc == 0) {
	EC_POINT_point2oct(ecGroup, ecPoint,
			   POINT_CONVERSION_UNCOMPRESSED,
			   *modulusBin, *modulusBytes, NULL);
	if (tssUtilsVerbose) TSS_PrintAll("convertEcKeyToPublicKeyBin:", *modulusBin, *modulusBytes);
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

/* convertRsaKeyToPublicKeyBin() converts from an openssl RSA key token to a public modulus */

TPM_RC convertRsaKeyToPublicKeyBin(int 		*modulusBytes,
				   uint8_t 	**modulusBin,	/* freed by caller */
				   void 	*rsaKey)
{
    TPM_RC 		rc = 0;
    const BIGNUM 	*n = NULL;
    const BIGNUM 	*e;
    const BIGNUM 	*d;

    /* get the public modulus from the RSA key token */
    if (rc == 0) {
	rc = getRsaKeyParts(&n, &e, &d, NULL, NULL, rsaKey);
    }
    if (rc == 0) {
	*modulusBytes = BN_num_bytes(n);
    }
    if (rc == 0) {   
	rc = TSS_Malloc(modulusBin, *modulusBytes);
    }
    if (rc == 0) {
	BN_bn2bin(n, *modulusBin);
    }
    return rc;
}

#ifdef TPM_TPM20

#ifndef TPM_TSS_NOECC

/* convertEcPrivateKeyBinToPrivate() converts an EC 'privateKeyBin' to either a
   TPM2B_PRIVATE or a TPM2B_SENSITIVE

*/

TPM_RC convertEcPrivateKeyBinToPrivate(TPM2B_PRIVATE 	*objectPrivate,
				       TPM2B_SENSITIVE 	*objectSensitive,
				       int 		privateKeyBytes,
				       uint8_t 		*privateKeyBin,
				       const char 	*password)
{
    TPM_RC 		rc = 0;
    TPMT_SENSITIVE	tSensitive;
    TPM2B_SENSITIVE	bSensitive;

    if (rc == 0) {
	if (((objectPrivate == NULL) && (objectSensitive == NULL)) ||
	    ((objectPrivate != NULL) && (objectSensitive != NULL))) {
	    printf("convertEcPrivateKeyBinToPrivate: Only one result supported\n");
	    rc = EXIT_FAILURE;
	}
    }
    /* In some cases, the sensitive data is not encrypted and the integrity value is not present.
       When an integrity value is not needed, it is not present and it is not represented by an
       Empty Buffer.

       In this case, the TPM2B_PRIVATE will just be a marshaled TPM2B_SENSITIVE, which is a
       marshaled TPMT_SENSITIVE */	

    /* construct TPMT_SENSITIVE	*/
    if (rc == 0) {
	/* This shall be the same as the type parameter of the associated public area. */
	tSensitive.sensitiveType = TPM_ALG_ECC;
	tSensitive.seedValue.b.size = 0;
	/* key password converted to TPM2B */
	rc = TSS_TPM2B_StringCopy(&tSensitive.authValue.b, password,
				  sizeof(tSensitive.authValue.t.buffer));
    }
    if (rc == 0) {
	if (privateKeyBytes > 32) {	/* hard code NISTP256 */
	    printf("convertEcPrivateKeyBinToPrivate: Error, private key size %u not 32\n",
		   privateKeyBytes);
	    rc = EXIT_FAILURE;
	}
    }
    if (rc == 0) {
	tSensitive.sensitive.ecc.t.size = privateKeyBytes;
	memcpy(tSensitive.sensitive.ecc.t.buffer, privateKeyBin, privateKeyBytes);
    }
    /* FIXME common code for EC and RSA */
    /* marshal the TPMT_SENSITIVE into a TPM2B_SENSITIVE */	
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    uint32_t size = sizeof(bSensitive.t.sensitiveArea);	/* max size */
	    uint8_t *buffer = bSensitive.b.buffer;		/* pointer that can move */
	    bSensitive.t.size = 0;				/* required before marshaling */
	    rc = TSS_TPMT_SENSITIVE_Marshalu(&tSensitive,
					    &bSensitive.b.size,	/* marshaled size */
					    &buffer,		/* marshal here */
					    &size);		/* max size */
	}
	else {	/* return TPM2B_SENSITIVE */
	    objectSensitive->t.sensitiveArea = tSensitive;
	}	
    }
    /* marshal the TPM2B_SENSITIVE (as a TPM2B_PRIVATE, see above) into a TPM2B_PRIVATE */
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    uint32_t size = sizeof(objectPrivate->t.buffer);	/* max size */
	    uint8_t *buffer = objectPrivate->t.buffer;		/* pointer that can move */
	    objectPrivate->t.size = 0;				/* required before marshaling */
	    rc = TSS_TPM2B_PRIVATE_Marshalu((TPM2B_PRIVATE *)&bSensitive,
					   &objectPrivate->t.size,	/* marshaled size */
					   &buffer,		/* marshal here */
					   &size);		/* max size */
	}
    }
    return rc;
}

#endif 	/* TPM_TSS_NOECC */
#endif 	/* TPM_TPM20 */

#ifdef TPM_TPM20

/* convertRsaPrivateKeyBinToPrivate() converts an RSA prime 'privateKeyBin' to either a
   TPM2B_PRIVATE or a TPM2B_SENSITIVE

*/

TPM_RC convertRsaPrivateKeyBinToPrivate(TPM2B_PRIVATE 	*objectPrivate,
					TPM2B_SENSITIVE *objectSensitive,
					int 		privateKeyBytes,
					uint8_t 	*privateKeyBin,
					const char 	*password)
{
    TPM_RC 		rc = 0;
    TPMT_SENSITIVE	tSensitive;
    TPM2B_SENSITIVE	bSensitive;

    if (rc == 0) {
	if (((objectPrivate == NULL) && (objectSensitive == NULL)) ||
	    ((objectPrivate != NULL) && (objectSensitive != NULL))) {
	    printf("convertRsaPrivateKeyBinToPrivate: Only one result supported\n");
	    rc = EXIT_FAILURE;
	}
    }
    /* In some cases, the sensitive data is not encrypted and the integrity value is not present.
       When an integrity value is not needed, it is not present and it is not represented by an
       Empty Buffer.

       In this case, the TPM2B_PRIVATE will just be a marshaled TPM2B_SENSITIVE, which is a
       marshaled TPMT_SENSITIVE */	

    /* construct TPMT_SENSITIVE	*/
    if (rc == 0) {
	/* This shall be the same as the type parameter of the associated public area. */
	tSensitive.sensitiveType = TPM_ALG_RSA;
	/* generate a seed for storage keys */
	tSensitive.seedValue.b.size = 32; 	/* FIXME hard coded seed length */
	rc = TSS_RandBytes(tSensitive.seedValue.b.buffer, tSensitive.seedValue.b.size);
    }
    /* key password converted to TPM2B */
    if (rc == 0) {
	rc = TSS_TPM2B_StringCopy(&tSensitive.authValue.b, password,
				  sizeof(tSensitive.authValue.t.buffer));
    }
    if (rc == 0) {
	if ((size_t)privateKeyBytes > sizeof(tSensitive.sensitive.rsa.t.buffer)) {
	    printf("convertRsaPrivateKeyBinToPrivate: "
		   "Error, private key modulus %d greater than %lu\n",
		   privateKeyBytes, (unsigned long)sizeof(tSensitive.sensitive.rsa.t.buffer));
	    rc = EXIT_FAILURE;
	}
    }
    if (rc == 0) {
	tSensitive.sensitive.rsa.t.size = privateKeyBytes;
	memcpy(tSensitive.sensitive.rsa.t.buffer, privateKeyBin, privateKeyBytes);
    }
    /* FIXME common code for EC and RSA */
    /* marshal the TPMT_SENSITIVE into a TPM2B_SENSITIVE */	
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    uint32_t size = sizeof(bSensitive.t.sensitiveArea);	/* max size */
	    uint8_t *buffer = bSensitive.b.buffer;		/* pointer that can move */
	    bSensitive.t.size = 0;				/* required before marshaling */
	    rc = TSS_TPMT_SENSITIVE_Marshalu(&tSensitive,
					    &bSensitive.b.size,	/* marshaled size */
					    &buffer,		/* marshal here */
					    &size);		/* max size */
	}
	else {	/* return TPM2B_SENSITIVE */
	    objectSensitive->t.sensitiveArea = tSensitive;
	}	
    }
    /* marshal the TPM2B_SENSITIVE (as a TPM2B_PRIVATE, see above) into a TPM2B_PRIVATE */
    if (rc == 0) {
	if (objectPrivate != NULL) {
	    uint32_t size = sizeof(objectPrivate->t.buffer);	/* max size */
	    uint8_t *buffer = objectPrivate->t.buffer;		/* pointer that can move */
	    objectPrivate->t.size = 0;				/* required before marshaling */
	    rc = TSS_TPM2B_PRIVATE_Marshalu((TPM2B_PRIVATE *)&bSensitive,
					   &objectPrivate->t.size,	/* marshaled size */
					   &buffer,		/* marshal here */
					   &size);		/* max size */
	}
    }
    return rc;
}

#endif /* TPM_TPM20 */

#ifndef TPM_TSS_NOECC

/* convertEcPublicKeyBinToPublic() converts an EC modulus and other parameters to a TPM2B_PUBLIC

   FIXME  Only supports NIST P256 curve.
*/

TPM_RC convertEcPublicKeyBinToPublic(TPM2B_PUBLIC 		*objectPublic,
				     int			keyType,
				     TPMI_ALG_SIG_SCHEME 	scheme,
				     TPMI_ALG_HASH 		nalg,
				     TPMI_ALG_HASH		halg,
				     TPMI_ECC_CURVE 		curveID,
				     int 			modulusBytes,
				     uint8_t 			*modulusBin)
{
    TPM_RC 		rc = 0;

    scheme = scheme;	/* scheme parameter not supported yet */
    if (rc == 0) {
	if (modulusBytes != 65) {	/* 1 for compression + 32 + 32 */
	    printf("convertEcPublicKeyBinToPublic: public modulus expected 65 bytes, actual %u\n",
		   modulusBytes);
	    rc = EXIT_FAILURE;
	}
    }
    if (rc == 0) {
	/* Table 184 - Definition of TPMT_PUBLIC Structure */
	objectPublic->publicArea.type = TPM_ALG_ECC;
	objectPublic->publicArea.nameAlg = nalg;
	objectPublic->publicArea.objectAttributes.val = TPMA_OBJECT_NODA;
	objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	switch (keyType) {
	  case TYPE_SI:
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
	    objectPublic->publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDSA;
	    break;
	  case TYPE_ST:		/* for public part only */
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
	    objectPublic->publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	    break;
	  case TYPE_DEN:	/* for public and private part */
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    objectPublic->publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	    objectPublic->publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_NULL;
	    objectPublic->publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_ECDH;
	    break;
	}
	objectPublic->publicArea.authPolicy.t.size = 0;
	/* Table 152 - Definition of TPMU_ASYM_SCHEME Union */
	objectPublic->publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg = halg;
	objectPublic->publicArea.parameters.eccDetail.curveID = curveID;	
	objectPublic->publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
	objectPublic->publicArea.parameters.eccDetail.kdf.details.mgf1.hashAlg = halg;

	objectPublic->publicArea.unique.ecc.x.t.size = 32;	
	memcpy(objectPublic->publicArea.unique.ecc.x.t.buffer, modulusBin +1, 32);	

	objectPublic->publicArea.unique.ecc.y.t.size = 32;	
	memcpy(objectPublic->publicArea.unique.ecc.y.t.buffer, modulusBin +33, 32);	
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

/* convertRsaPublicKeyBinToPublic() converts a public modulus to a TPM2B_PUBLIC structure. */

TPM_RC convertRsaPublicKeyBinToPublic(TPM2B_PUBLIC 		*objectPublic,
				      int			keyType,
				      TPMI_ALG_SIG_SCHEME 	scheme,
				      TPMI_ALG_HASH 		nalg,
				      TPMI_ALG_HASH		halg,
				      int 			modulusBytes,
				      uint8_t 			*modulusBin)
{
    TPM_RC 		rc = 0;

    if (rc == 0) {
	if ((size_t)modulusBytes > sizeof(objectPublic->publicArea.unique.rsa.t.buffer)) {
	    printf("convertRsaPublicKeyBinToPublic: Error, "
		   "public key modulus %d greater than %lu\n", modulusBytes,
		   (unsigned long)sizeof(objectPublic->publicArea.unique.rsa.t.buffer));
	    rc = EXIT_FAILURE;
	}
    }
    if (rc == 0) {
	/* Table 184 - Definition of TPMT_PUBLIC Structure */
	objectPublic->publicArea.type = TPM_ALG_RSA;
	objectPublic->publicArea.nameAlg = nalg;
	objectPublic->publicArea.objectAttributes.val = TPMA_OBJECT_NODA;
	objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_USERWITHAUTH;
	switch (keyType) {
	  case TYPE_SI:
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_SIGN;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	    break;
	  case TYPE_ST:		/* for public part only */
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_RESTRICTED;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
	    break;
	  case TYPE_DEN:	/* for public and private part */
	    objectPublic->publicArea.objectAttributes.val |= TPMA_OBJECT_DECRYPT;
	    objectPublic->publicArea.objectAttributes.val &= ~TPMA_OBJECT_RESTRICTED;
	    objectPublic->publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_NULL;
	    break;
	}
	objectPublic->publicArea.authPolicy.t.size = 0;
	/* Table 182 - Definition of TPMU_PUBLIC_PARMS Union <IN/OUT, S> */
	objectPublic->publicArea.parameters.rsaDetail.scheme.scheme = scheme;
	objectPublic->publicArea.parameters.rsaDetail.scheme.details.rsassa.hashAlg = halg;
	objectPublic->publicArea.parameters.rsaDetail.keyBits = modulusBytes * 8;	
	objectPublic->publicArea.parameters.rsaDetail.exponent = 0;

	objectPublic->publicArea.unique.rsa.t.size = modulusBytes;
	memcpy(objectPublic->publicArea.unique.rsa.t.buffer, modulusBin, modulusBytes);
    }
    return rc;
}

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcKeyToPrivate() converts an openssl EC_KEY to token to either a TPM2B_PRIVATE or
   TPM2B_SENSITIVE
*/

TPM_RC convertEcKeyToPrivate(TPM2B_PRIVATE 	*objectPrivate,
			     TPM2B_SENSITIVE 	*objectSensitive,
			     EC_KEY 		*ecKey,
			     const char 	*password)
{
    TPM_RC 	rc = 0;
    int 	privateKeyBytes;
    uint8_t 	*privateKeyBin = NULL;
    
    /* convert an openssl EC_KEY token to a binary array */
    if (rc == 0) {
	rc = convertEcKeyToPrivateKeyBin(&privateKeyBytes,
					 &privateKeyBin,	/* freed @1 */
					 ecKey);
    }
    if (rc == 0) {
	rc = convertEcPrivateKeyBinToPrivate(objectPrivate,
					     objectSensitive,
					     privateKeyBytes,
					     privateKeyBin,
					     password);
    }
    free(privateKeyBin);		/* @1 */
    return rc;
}

#endif	/* TPM_TSS_NOECC */

/* convertRsaKeyToPrivate() converts an openssl RSA key token to either a TPM2B_PRIVATE or
   TPM2B_SENSITIVE
*/

TPM_RC convertRsaKeyToPrivate(TPM2B_PRIVATE 	*objectPrivate,
			      TPM2B_SENSITIVE 	*objectSensitive,
			      RSA 		*rsaKey,
			      const char 	*password)
{
    TPM_RC 	rc = 0;
    int 	privateKeyBytes;
    uint8_t 	*privateKeyBin = NULL;

    /* convert an openssl RSA key token private prime p to a binary array */
    if (rc == 0) {
	rc = convertRsaKeyToPrivateKeyBin(&privateKeyBytes,
					  &privateKeyBin,	/* freed @1 */
					  rsaKey);
    }
    /* convert an RSA prime 'privateKeyBin' to either a TPM2B_PRIVATE or a TPM2B_SENSITIVE */
    if (rc == 0) {
	rc = convertRsaPrivateKeyBinToPrivate(objectPrivate,
					      objectSensitive,
					      privateKeyBytes,
					      privateKeyBin,
					      password);
    }
    free(privateKeyBin);		/* @1 */
    return rc;
}

#ifndef TPM_TSS_NOECC

/* convertEcKeyToPublic() converts an EC_KEY to a TPM2B_PUBLIC */

TPM_RC convertEcKeyToPublic(TPM2B_PUBLIC 		*objectPublic,
			    int				keyType,
			    TPMI_ALG_SIG_SCHEME 	scheme,
			    TPMI_ALG_HASH 		nalg,
			    TPMI_ALG_HASH		halg,
			    EC_KEY 			*ecKey)
{
    TPM_RC 		rc = 0;
    int 		modulusBytes;
    uint8_t 		*modulusBin = NULL;
    TPMI_ECC_CURVE	curveID;
    
    if (rc == 0) {
	rc = convertEcKeyToPublicKeyBin(&modulusBytes,
					&modulusBin,		/* freed @1 */
					ecKey);
    }
    if (rc == 0) {
	rc = getEcCurve(&curveID, ecKey);
    }
    if (rc == 0) {
	rc = convertEcPublicKeyBinToPublic(objectPublic,
					   keyType,
					   scheme,
					   nalg,
					   halg,
					   curveID,
					   modulusBytes,
					   modulusBin);
    }
    free(modulusBin);		/* @1 */
    return rc;
}

#endif	/* TPM_TSS_NOECC */

/* convertRsaKeyToPublic() converts from an openssl RSA key token to a TPM2B_PUBLIC */

TPM_RC convertRsaKeyToPublic(TPM2B_PUBLIC 		*objectPublic,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     void 			*rsaKey)
{
    TPM_RC 		rc = 0;
    int 		modulusBytes;
    uint8_t 		*modulusBin = NULL;
    
    /* openssl RSA key token to a public modulus */
    if (rc == 0) {
	rc = convertRsaKeyToPublicKeyBin(&modulusBytes,
					 &modulusBin,		/* freed @1 */
					 rsaKey);
    }
    /* public modulus to TPM2B_PUBLIC */
    if (rc == 0) {
	rc = convertRsaPublicKeyBinToPublic(objectPublic,
					    keyType,
					    scheme,
					    nalg,
					    halg,
					    modulusBytes,
					    modulusBin);
    }
    free(modulusBin);		/* @1 */
    return rc;
}

#endif

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcPemToKeyPair() converts a PEM file to a TPM2B_PUBLIC and TPM2B_PRIVATE */

TPM_RC convertEcPemToKeyPair(TPM2B_PUBLIC 		*objectPublic,
			     TPM2B_PRIVATE 		*objectPrivate,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     const char 		*pemKeyFilename,
			     const char 		*password)
{
    TPM_RC 	rc = 0;
    EVP_PKEY 	*evpPkey = NULL;
    EC_KEY 	*ecKey = NULL;

    /* convert a PEM file to an openssl EVP_PKEY */
    if (rc == 0) {
	rc = convertPemToEvpPrivKey(&evpPkey,		/* freed @1 */
				    pemKeyFilename,
				    password);
    }
    if (rc == 0) {
	rc = convertEvpPkeyToEckey(&ecKey,		/* freed @2 */
				   evpPkey);
    }
    if (rc == 0) {
	rc = convertEcKeyToPrivate(objectPrivate,	/* TPM2B_PRIVATE */
				   NULL,		/* TPM2B_SENSITIVE */
				   ecKey,
				   password);
    }
    if (rc == 0) {
	rc = convertEcKeyToPublic(objectPublic,
				  keyType,
				  scheme,
				  nalg,
				  halg,
				  ecKey);
    }
    EC_KEY_free(ecKey);   		/* @2 */
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif
#endif

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcPemToPublic() converts an ECC P256 signing public key in PEM format to a
   TPM2B_PUBLIC */

TPM_RC convertEcPemToPublic(TPM2B_PUBLIC 	*objectPublic,
			    int			keyType,
			    TPMI_ALG_SIG_SCHEME scheme,
			    TPMI_ALG_HASH 	nalg,
			    TPMI_ALG_HASH	halg,
			    const char		*pemKeyFilename)
{
    TPM_RC	rc = 0;
    EVP_PKEY  	*evpPkey = NULL;
    EC_KEY 	*ecKey = NULL;

    if (rc == 0) {
	rc = convertPemToEvpPubKey(&evpPkey,		/* freed @1 */
				   pemKeyFilename);
    }
    if (rc == 0) {
	rc = convertEvpPkeyToEckey(&ecKey,		/* freed @2 */
				   evpPkey);
    }
    if (rc == 0) {
	rc = convertEcKeyToPublic(objectPublic,
				  keyType,
				  scheme,
				  nalg,
				  halg,
				  ecKey);
    }
    if (ecKey != NULL) {
	EC_KEY_free(ecKey);   		/* @2 */
    }
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif
#endif

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NORSA

/* convertRsaPemToKeyPair() converts an RSA PEM file to a TPM2B_PUBLIC and TPM2B_PRIVATE */

TPM_RC convertRsaPemToKeyPair(TPM2B_PUBLIC 		*objectPublic,
			      TPM2B_PRIVATE 		*objectPrivate,
			      int			keyType,
			      TPMI_ALG_SIG_SCHEME 	scheme,
			      TPMI_ALG_HASH 		nalg,
			      TPMI_ALG_HASH		halg,
			      const char 		*pemKeyFilename,
			      const char 		*password)
{
    TPM_RC 	rc = 0;
    EVP_PKEY 	*evpPkey = NULL;
    RSA		*rsaKey = NULL;
    
    if (rc == 0) {
	rc = convertPemToEvpPrivKey(&evpPkey,		/* freed @1 */
				    pemKeyFilename,
				    password);
    }
    if (rc == 0) {
	rc = convertEvpPkeyToRsakey(&rsaKey,		/* freed @2 */
				    evpPkey);
    }
    if (rc == 0) {
	rc = convertRsaKeyToPrivate(objectPrivate,	/* TPM2B_PRIVATE */
				    NULL,		/* TPM2B_SENSITIVE */
				    rsaKey,
				    password);
    }
    if (rc == 0) {
	rc = convertRsaKeyToPublic(objectPublic,
				   keyType,
				   scheme,
				   nalg,
				   halg,
				   rsaKey);
    }
    TSS_RsaFree(rsaKey);		/* @2 */
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

#endif /* TPM_TSS_NORSA */
#endif /* TPM_TPM20 */
#endif /* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcDerToKeyPair() converts an EC keypair stored in DER to a TPM2B_PUBLIC and
   TPM2B_SENSITIVE.  Useful for LoadExternal.

*/

TPM_RC convertEcDerToKeyPair(TPM2B_PUBLIC 		*objectPublic,
			     TPM2B_SENSITIVE 		*objectSensitive,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     const char			*derKeyFilename,
			     const char 		*password)
{
    TPM_RC		rc = 0;
    EC_KEY		*ecKey = NULL;
    unsigned char	*derBuffer = NULL;
    size_t		derSize;

    /* read the DER file */
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&derBuffer,     	/* freed @1 */
				     &derSize,
				     derKeyFilename); 
    }    
    if (rc == 0) {
	const unsigned char *tmpPtr = derBuffer;	/* because pointer moves */
	ecKey = d2i_ECPrivateKey(NULL, &tmpPtr, derSize);	/* freed @2 */
	if (ecKey == NULL) {
	    printf("convertEcDerToKeyPair: could not convert key to EC_KEY\n");
	    rc = TPM_RC_VALUE;
	}
    }
    if (rc == 0) {
	rc = convertEcKeyToPrivate(NULL,		/* TPM2B_PRIVATE */
				   objectSensitive,	/* TPM2B_SENSITIVE */
				   ecKey,
				   password);
    }	
    if (rc == 0) {
	rc = convertEcKeyToPublic(objectPublic,
				  keyType,
				  scheme,
				  nalg,
				  halg,
				  ecKey);
    }
    free(derBuffer);		/* @1 */
    if (ecKey != NULL) {
	EC_KEY_free(ecKey);		/* @2 */
    }
    return rc;
}

/* convertEcDerToPublic() converts an EC public key stored in DER to a TPM2B_PUBLIC.  Useful to
   calculate a Name.

*/

TPM_RC convertEcDerToPublic(TPM2B_PUBLIC 		*objectPublic,
			    int				keyType,
			    TPMI_ALG_SIG_SCHEME 	scheme,
			    TPMI_ALG_HASH 		nalg,
			    TPMI_ALG_HASH		halg,
			    const char			*derKeyFilename)
{
    TPM_RC		rc = 0;
    EVP_PKEY 		*evpPkey = NULL;
    EC_KEY		*ecKey = NULL;
    unsigned char	*derBuffer = NULL;
    size_t		derSize;

    /* read the DER file */
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&derBuffer,     	/* freed @1 */
				     &derSize,
				     derKeyFilename); 
    }    
    if (rc == 0) {
	const unsigned char *tmpPtr = derBuffer;	/* because pointer moves */
	evpPkey = d2i_PUBKEY(NULL, &tmpPtr, derSize);	/* freed @2 */
	if (evpPkey == NULL) {
	    printf("convertEcDerToPublic: could not convert key to EVP_PKEY\n");
	    rc = TPM_RC_VALUE;
	}
    }
    if (rc == 0) {
	rc = convertEvpPkeyToEckey(&ecKey,		/* freed @3 */
				   evpPkey);
    }
    if (rc == 0) {
	rc = convertEcKeyToPublic(objectPublic,
				  keyType,
				  scheme,
				  nalg,
				  halg,
				  ecKey);
    }
    free(derBuffer);			/* @1 */
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    if (ecKey != NULL) {
	EC_KEY_free(ecKey);		/* @2 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif
#endif

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
#ifndef TPM_TSS_NORSA

/* convertRsaDerToKeyPair() converts an RSA keypair stored in DER to a TPM2B_PUBLIC and
   TPM2B_SENSITIVE.  Useful for LoadExternal.

*/

TPM_RC convertRsaDerToKeyPair(TPM2B_PUBLIC 		*objectPublic,
			      TPM2B_SENSITIVE 		*objectSensitive,
			      int			keyType,
			      TPMI_ALG_SIG_SCHEME 	scheme,
			      TPMI_ALG_HASH 		nalg,
			      TPMI_ALG_HASH		halg,
			      const char		*derKeyFilename,
			      const char 		*password)
{
    TPM_RC		rc = 0;
    RSA 		*rsaKey = NULL;
    unsigned char	*derBuffer = NULL;
    size_t		derSize;

    /* read the DER file */
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&derBuffer,     	/* freed @1 */
				     &derSize,
				     derKeyFilename); 
    }    
    if (rc == 0) {
	const unsigned char *tmpPtr = derBuffer;	/* because pointer moves */
	rsaKey = d2i_RSAPrivateKey(NULL, &tmpPtr, derSize);	/* freed @2 */
	if (rsaKey == NULL) {
	    printf("convertRsaDerToKeyPair: could not convert key to RSA\n");
	    rc = TPM_RC_VALUE;
	}
    }
    if (rc == 0) {
	rc = convertRsaKeyToPrivate(NULL,		/* TPM2B_PRIVATE */
				    objectSensitive,	/* TPM2B_SENSITIVE */
				    rsaKey,
				    password);	
    }	
    if (rc == 0) {
	rc = convertRsaKeyToPublic(objectPublic,
				   keyType,
				   scheme,
				   nalg,
				   halg,
				   rsaKey);
    }
    free(derBuffer);			/* @1 */
    TSS_RsaFree(rsaKey);		/* @2 */
    return rc;
}

/* convertRsaDerToPublic() converts an RSA public key stored in DER to a TPM2B_PUBLIC.  Useful to
   calculate a Name.

*/

TPM_RC convertRsaDerToPublic(TPM2B_PUBLIC 		*objectPublic,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     const char			*derKeyFilename)
{
    TPM_RC		rc = 0;
    RSA 		*rsaKey = NULL;
    unsigned char	*derBuffer = NULL;
    size_t		derSize;

    /* read the DER file */
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&derBuffer,     	/* freed @1 */
				     &derSize,
				     derKeyFilename); 
    }    
    if (rc == 0) {
	const unsigned char *tmpPtr = derBuffer;	/* because pointer moves */
	rsaKey = d2i_RSA_PUBKEY(NULL, &tmpPtr, derSize);	/* freed @2 */
	if (rsaKey == NULL) {
	    printf("convertRsaDerToPublic: could not convert key to RSA\n");
	    rc = TPM_RC_VALUE;
	}
    }
    if (rc == 0) {
	rc = convertRsaKeyToPublic(objectPublic,
				   keyType,
				   scheme,
				   nalg,
				   halg,
				   rsaKey);
    }
    free(derBuffer);			/* @1 */
    TSS_RsaFree(rsaKey);		/* @2 */
    return rc;
}

#endif /* TPM_TSS_NORSA */
#endif /* TPM_TPM20 */
#endif /* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20

/* convertRsaPemToPublic() converts an RSA public key in PEM format to a TPM2B_PUBLIC */

TPM_RC convertRsaPemToPublic(TPM2B_PUBLIC 		*objectPublic,
			     int			keyType,
			     TPMI_ALG_SIG_SCHEME 	scheme,
			     TPMI_ALG_HASH 		nalg,
			     TPMI_ALG_HASH		halg,
			     const char 		*pemKeyFilename)
{
    TPM_RC	rc = 0;
    EVP_PKEY 	*evpPkey = NULL;
    RSA		*rsaKey = NULL;

    if (rc == 0) {
	rc = convertPemToEvpPubKey(&evpPkey,		/* freed @1 */
				   pemKeyFilename);
    }
    if (rc == 0) {
	rc = convertEvpPkeyToRsakey(&rsaKey,		/* freed @2 */
				    evpPkey);
    }
    if (rc == 0) {
	rc = convertRsaKeyToPublic(objectPublic,
				   keyType,
				   scheme,
				   nalg,
				   halg,
				   rsaKey);
    }
    RSA_free(rsaKey);			/* @2 */ 
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

#endif
#endif

/* getRsaKeyParts() gets the RSA key parts from an OpenSSL RSA key token.

   If n is not NULL, returns n, e, and d.  If p is not NULL, returns p and q.
*/

TPM_RC getRsaKeyParts(const BIGNUM **n,
		     const BIGNUM **e,
		     const BIGNUM **d,
		     const BIGNUM **p,
		     const BIGNUM **q,
		     const RSA *rsaKey)
{
    TPM_RC  	rc = 0;
    if (n != NULL) {
	RSA_get0_key(rsaKey, n, e, d);
    }
    if (p != NULL) {
	RSA_get0_factors(rsaKey, p, q);
    }
    return rc;
}

/* returns the type (EVP_PKEY_RSA or EVP_PKEY_EC) of the EVP_PKEY.

 */

int getRsaPubkeyAlgorithm(EVP_PKEY *pkey)
{
    int 			pkeyType;	/* RSA or EC */
    pkeyType = EVP_PKEY_base_id(pkey);
    return pkeyType;
}

#ifndef TPM_TSS_NOFILE

/* convertPublicToPEM() saves a PEM format public key from a TPM2B_PUBLIC
   
*/

TPM_RC convertPublicToPEM(const TPM2B_PUBLIC *public,
			  const char *pemFilename)
{
    TPM_RC 	rc = 0;
    EVP_PKEY 	*evpPubkey = NULL;          	/* OpenSSL public key, EVP format */

    /* convert TPM2B_PUBLIC to EVP_PKEY */
    if (rc == 0) {
	switch (public->publicArea.type) {
#ifndef TPM_TSS_NORSA
	  case TPM_ALG_RSA:
	    rc = convertRsaPublicToEvpPubKey(&evpPubkey,	/* freed @1 */
					     &public->publicArea.unique.rsa);
	    break;
#endif /* TPM_TSS_NORSA */
#ifndef TPM_TSS_NOECC
	  case TPM_ALG_ECC:
	    rc = convertEcPublicToEvpPubKey(&evpPubkey,		/* freed @1 */
					    &public->publicArea.unique.ecc);
	    break;
#endif	/* TPM_TSS_NOECC */
	  default:
	    printf("convertPublicToPEM: Unknown publicArea.type %04hx unsupported\n",
		   public->publicArea.type);
	    rc = TSS_RC_NOT_IMPLEMENTED;
	    break;
	}
    }
    /* write the openssl structure in PEM format */
    if (rc == 0) {
	rc = convertEvpPubkeyToPem(evpPubkey,
				   pemFilename);

    }
    if (evpPubkey != NULL) {
	EVP_PKEY_free(evpPubkey);		/* @1 */
    }
    return rc;
}

#endif /* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NORSA

/* convertRsaPublicToEvpPubKey() converts an RSA TPM2B_PUBLIC to a EVP_PKEY.

*/

TPM_RC convertRsaPublicToEvpPubKey(EVP_PKEY **evpPubkey,	/* freed by caller */
				   const TPM2B_PUBLIC_KEY_RSA *tpm2bRsa)
{
    TPM_RC 	rc = 0;
    int		irc;
    RSA		*rsaPubKey = NULL;
    
    if (rc == 0) {
	*evpPubkey = EVP_PKEY_new();
	if (*evpPubkey == NULL) {
	    printf("convertRsaPublicToEvpPubKey: EVP_PKEY failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* TPM to RSA token */
    if (rc == 0) {
	/* public exponent */
	unsigned char earr[3] = {0x01, 0x00, 0x01};
	rc = TSS_RSAGeneratePublicTokenI
	     ((void **)&rsaPubKey,			/* freed as part of EVP_PKEY  */
	      tpm2bRsa->t.buffer,  		/* public modulus */
	      tpm2bRsa->t.size,
	      earr,      			/* public exponent */
	      sizeof(earr));
    }
    /* RSA token to EVP */
    if (rc == 0) {
	irc  = EVP_PKEY_assign_RSA(*evpPubkey, rsaPubKey);
	if (irc == 0) {
	    TSS_RsaFree(rsaPubKey);	/* because not assigned tp EVP_PKEY */
	    printf("convertRsaPublicToEvpPubKey: EVP_PKEY_assign_RSA failed\n");
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    return rc;
}

#endif /* TPM_TSS_NORSA */

#ifndef TPM_TSS_NOECC

/* convertEcPublicToEvpPubKey() converts an EC TPMS_ECC_POINT to an EVP_PKEY.
 */

TPM_RC convertEcPublicToEvpPubKey(EVP_PKEY **evpPubkey,		/* freed by caller */
				  const TPMS_ECC_POINT *tpmsEccPoint)
{
    TPM_RC 	rc = 0;
    int		irc;
    EC_GROUP 	*ecGroup = NULL;
    EC_KEY 	*ecKey = NULL;
    BIGNUM 	*x = NULL;		/* freed @2 */
    BIGNUM 	*y = NULL;		/* freed @3 */
    
    if (rc == 0) {
	ecKey = EC_KEY_new();		/* freed @1 */
	if (ecKey == NULL) {
	    printf("convertEcPublicToEvpPubKey: Error creating EC_KEY\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	ecGroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);	/* freed @4 */
	if (ecGroup == NULL) {
	    printf("convertEcPublicToEvpPubKey: Error in EC_GROUP_new_by_curve_name\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	/* returns void */
	EC_GROUP_set_asn1_flag(ecGroup, OPENSSL_EC_NAMED_CURVE);
    }
    /* assign curve to EC_KEY */
    if (rc == 0) {
	irc = EC_KEY_set_group(ecKey, ecGroup);
	if (irc != 1) {
	    printf("convertEcPublicToEvpPubKey: Error in EC_KEY_set_group\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	rc = convertBin2Bn(&x,				/* freed @2 */
			   tpmsEccPoint->x.t.buffer,
			   tpmsEccPoint->x.t.size);	
    }
    if (rc == 0) {
	rc = convertBin2Bn(&y,				/* freed @3 */
			   tpmsEccPoint->y.t.buffer,
			   tpmsEccPoint->y.t.size);
    }
    if (rc == 0) {
	irc = EC_KEY_set_public_key_affine_coordinates(ecKey, x, y);
	if (irc != 1) {
	    printf("convertEcPublicToEvpPubKey: "
		   "Error converting public key from X Y to EC_KEY format\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	*evpPubkey = EVP_PKEY_new();		/* freed by caller */
	if (*evpPubkey == NULL) {
	    printf("convertEcPublicToEvpPubKey: EVP_PKEY failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	irc = EVP_PKEY_set1_EC_KEY(*evpPubkey, ecKey);
	if (irc != 1) {
	    printf("convertEcPublicToEvpPubKey: "
		   "Error converting public key from EC to EVP format\n");
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (ecGroup != NULL) {
	EC_GROUP_free(ecGroup);	/* @4 */
    }
    if (ecKey != NULL) {
	EC_KEY_free(ecKey);	/* @1 */
    }
    if (x != NULL) {
	BN_free(x);		/* @2 */
    }
    if (y != NULL) {
	BN_free(y);		/* @3 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

#ifndef TPM_TSS_NOFILE

TPM_RC convertEvpPubkeyToPem(EVP_PKEY *evpPubkey,
			     const char *pemFilename)
{
    TPM_RC 	rc = 0;
    int		irc;
    FILE 	*pemFile = NULL; 
    
    if (rc == 0) {
	pemFile = fopen(pemFilename, "wb");	/* close @1 */
	if (pemFile == NULL) {
	    printf("convertEvpPubkeyToPem: Unable to open PEM file %s for write\n", pemFilename);
	    rc = TSS_RC_FILE_OPEN;
	}
    }
    if (rc == 0) {
	irc = PEM_write_PUBKEY(pemFile, evpPubkey);
	if (irc == 0) {
	    printf("convertEvpPubkeyToPem: Unable to write PEM file %s\n", pemFilename);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    if (pemFile != NULL) {
	fclose(pemFile);			/* @1 */
    }
    return rc;
}

#endif
#ifndef TPM_TSS_NOFILE

/* verifySignatureFromPem() verifies the signature 'tSignature' against the digest 'message' using
   the public key in the PEM format file 'pemFilename'.

*/

TPM_RC verifySignatureFromPem(unsigned char *message,
			      unsigned int messageSize,
			      TPMT_SIGNATURE *tSignature,
			      TPMI_ALG_HASH halg,
			      const char *pemFilename)
{
    TPM_RC 		rc = 0;
    EVP_PKEY 		*evpPkey = NULL;        /* OpenSSL public key, EVP format */
    
    /* read the public key from PEM format */
    if (rc == 0) {
	rc = convertPemToEvpPubKey(&evpPkey,		/* freed @1*/
				   pemFilename);
    }
    /* RSA or EC */
    if (rc == 0) {
	switch(tSignature->sigAlg) {
#ifndef TPM_TSS_NORSA
	  case TPM_ALG_RSASSA:
	  case TPM_ALG_RSAPSS:
	    rc = verifyRSASignatureFromEvpPubKey(message,
						 messageSize,
						 tSignature,
						 halg,
						 evpPkey);
	    break;
#else
	    halg = halg;
#endif /* TPM_TSS_NORSA */
#ifndef TPM_TSS_NOECC
	  case TPM_ALG_ECDSA:
	    rc = verifyEcSignatureFromEvpPubKey(message,
						messageSize,
						tSignature,
						evpPkey);
	    break;
#endif	/* TPM_TSS_NOECC */
	  default:
	    printf("verifySignatureFromPem: Unknown signature algorithm %04x\n", tSignature->sigAlg);
	    rc = TSS_RC_BAD_SIGNATURE_ALGORITHM;
	}
    }
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

#endif

#ifndef TPM_TSS_NORSA

/* verifyRSASignatureFromEvpPubKey() verifies the signature 'tSignature' against the digest
   'message' using the RSA public key in evpPkey.

*/

TPM_RC verifyRSASignatureFromEvpPubKey(unsigned char *message,
				       unsigned int messageSize,
				       TPMT_SIGNATURE *tSignature,
				       TPMI_ALG_HASH halg,
				       EVP_PKEY *evpPkey)
{
    TPM_RC 		rc = 0;
    RSA 		*rsaPubKey = NULL;	/* OpenSSL public key, RSA format */
    
    /* construct the RSA key token */
    if (rc == 0) {
	rsaPubKey = EVP_PKEY_get1_RSA(evpPkey);	/* freed @1 */
	if (rsaPubKey == NULL) {
	    printf("verifyRSASignatureFromEvpPubKey: EVP_PKEY_get1_RSA failed\n");
	    rc = TSS_RC_RSA_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	rc = verifyRSASignatureFromRSA(message,
				       messageSize,
				       tSignature,
				       halg,
				       rsaPubKey);
    }
    TSS_RsaFree(rsaPubKey);          	/* @1 */
    return rc;
}

/* signRSAFromRSA() signs digest to signature, using th4 RSA key rsaKey. */

TPM_RC signRSAFromRSA(uint8_t *signature, size_t *signatureLength,
		      size_t signatureSize,
		      const uint8_t *digest, size_t digestLength,
		      TPMI_ALG_HASH hashAlg,
		      void *rsaKey)
{
    TPM_RC 		rc = 0;
    int			irc;
    int			nid;			/* openssl hash algorithm */
    
    /* map the hash algorithm to the openssl NID */
    if (rc == 0) {
	switch (hashAlg) {
	  case TPM_ALG_SHA1:
	    nid = NID_sha1;
	    break;
	  case TPM_ALG_SHA256:
	    nid = NID_sha256;
	    break;
	  case TPM_ALG_SHA384:
	    nid = NID_sha384;
	    break;
	  case TPM_ALG_SHA512:
	    nid = NID_sha512;
	    break;
	  default:
	    printf("signRSAFromRSA: Error, hash algorithm %04hx unsupported\n", hashAlg);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    /* validate that the length of the resulting signature will fit in the
       signature array */
    if (rc == 0) {
	unsigned int keySize = RSA_size(rsaKey);
	if (keySize > signatureSize) {
	    printf("signRSAFromRSA: Error, private key length %u > signature buffer %u\n",
		   keySize, (unsigned int)signatureSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    if (rc == 0) {
	unsigned int siglen;
	irc = RSA_sign(nid,
		       digest, digestLength,
		       signature, &siglen,
		       rsaKey);
	*signatureLength = siglen;
	if (irc != 1) {
	    printf("signRSAFromRSA: Error in OpenSSL RSA_sign()\n");
	    rc = TSS_RC_RSA_SIGNATURE;
	}
    }
    return rc;
}

/* verifyRSASignatureFromRSA() verifies the signature 'tSignature' against the digest 'message'
   using the RSA public key in the OpenSSL RSA format.

   Supports RSASSA and RSAPSS schemes.
*/

TPM_RC verifyRSASignatureFromRSA(unsigned char *message,
				 unsigned int messageSize,
				 TPMT_SIGNATURE *tSignature,
				 TPMI_ALG_HASH halg,
				 void *rsaPubKey)
{
    TPM_RC 		rc = 0;
    int			irc;
    int 		nid = 0;	/* initialized these two to suppress false gcc -O3
					   warnings */
    const EVP_MD 	*md = NULL;
    /* map from hash algorithm to openssl nid */
    if (rc == 0) {
	switch (halg) {
	  case TPM_ALG_SHA1:
	    nid = NID_sha1;
	    md = EVP_sha1();
	    break;
	  case TPM_ALG_SHA256:
	    nid = NID_sha256;
	    md = EVP_sha256();
	    break;
	  case TPM_ALG_SHA384:
	    nid = NID_sha384;
	    md = EVP_sha384();
	    break;
	  case TPM_ALG_SHA512:
	    nid = NID_sha512;
	    md = EVP_sha512();
	    break;
	  default:
	    printf("verifyRSASignatureFromRSA: Unknown hash algorithm %04x\n", halg);
	    rc = TSS_RC_BAD_HASH_ALGORITHM;
	}
    }
    /* verify the signature */
    if (tSignature->sigAlg == TPM_ALG_RSASSA) {
	if (rc == 0) {
	    irc = RSA_verify(nid,
			     message, messageSize,
			     tSignature->signature.rsassa.sig.t.buffer,
			     tSignature->signature.rsassa.sig.t.size,
			     rsaPubKey);
	    if (irc != 1) {
		printf("verifyRSASignatureFromRSA: Bad signature\n");
		rc = TSS_RC_RSA_SIGNATURE;
	    }
	}
    }
    else if (tSignature->sigAlg == TPM_ALG_RSAPSS) {
	uint8_t decryptedSig[sizeof(tSignature->signature.rsapss.sig.t.buffer)];
	if (rc == 0) {
	    irc = RSA_public_decrypt(tSignature->signature.rsapss.sig.t.size,
				     tSignature->signature.rsapss.sig.t.buffer,
				     decryptedSig,
				     rsaPubKey,
				     RSA_NO_PADDING);
	    if (irc == -1) {
		printf("verifyRSASignatureFromRSA: RSAPSS Bad signature\n");
		rc = TSS_RC_RSA_SIGNATURE;
	    }
	}
	if (rc == 0) {
	    irc = RSA_verify_PKCS1_PSS(rsaPubKey,
				       message,
				       md,
				       decryptedSig,
				       -2); /* salt length recovered from signature*/
	    if (irc != 1) {
		printf("verifyRSASignatureFromRSA: RSAPSS Bad signature\n");
		rc = TSS_RC_RSA_SIGNATURE;
	    }
	}
    }
    else {
	printf("verifyRSASignatureFromRSA: Bad signature scheme %04x\n",
	       tSignature->sigAlg);
    }
    return rc;
}

#endif /* TPM_TSS_NORSA */

#ifndef TPM_TSS_NOECC

/* verifyEcSignatureFromEvpPubKey() verifies the signature 'tSignature' against the digest 'message'
   using the EC public key in evpPkey.

*/

TPM_RC verifyEcSignatureFromEvpPubKey(unsigned char *message,
				      unsigned int messageSize,
				      TPMT_SIGNATURE *tSignature,
				      EVP_PKEY *evpPkey)
{
    TPM_RC 		rc = 0;
    int			irc;
    EC_KEY 		*ecKey = NULL;
    BIGNUM 		*r = NULL;
    BIGNUM 		*s = NULL;
    ECDSA_SIG 		*ecdsaSig = NULL;

    /* construct the EC key token */
    if (rc == 0) {
	ecKey = EVP_PKEY_get1_EC_KEY(evpPkey);	/* freed @1 */
	if (ecKey == NULL) {
	    printf("verifyEcSignatureFromEvpPubKey: EVP_PKEY_get1_EC_KEY failed\n");  
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* construct the ECDSA_SIG signature token */
    if (rc == 0) {
	rc = convertBin2Bn(&r,			/* freed @2 */
			   tSignature->signature.ecdsa.signatureR.t.buffer,
			   tSignature->signature.ecdsa.signatureR.t.size);
    }	
    if (rc == 0) {
	rc = convertBin2Bn(&s,			/* freed @2 */
			   tSignature->signature.ecdsa.signatureS.t.buffer,
			   tSignature->signature.ecdsa.signatureS.t.size);
    }
    /* ECDSA_SIG_new() allocates an empty ECDSA_SIG structure.  */
    if (rc == 0) {
	ecdsaSig = ECDSA_SIG_new(); 		/* freed @2 */
	if (ecdsaSig == NULL) {
	    printf("verifyEcSignatureFromEvpPubKey: Error creating ECDSA_SIG_new\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	int irc = ECDSA_SIG_set0(ecdsaSig, r, s);	
	if (irc != 1) {
            printf("verifyEcSignatureFromEvpPubKey: Error in ECDSA_SIG_set0()\n");
            rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    /* verify the signature */
    if (rc == 0) {
	irc = ECDSA_do_verify(message, messageSize, 
			      ecdsaSig, ecKey);
	if (irc != 1) {		/* quote signature did not verify */
	    printf("verifyEcSignatureFromEvpPubKey: Bad signature\n");
	    rc = TSS_RC_EC_SIGNATURE;
	}
    }
    if (ecKey != NULL) {
	EC_KEY_free(ecKey);		/* @1 */
    }
    /* if the ECDSA_SIG was allocated correctly, r and s are implicitly freed */
    if (ecdsaSig != NULL) {
	ECDSA_SIG_free(ecdsaSig);	/* @2 */
    }
    /* if not, explicitly free */
    else {
	if (r != NULL) BN_free(r);	/* @2 */
	if (s != NULL) BN_free(s);	/* @2 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

#ifndef TPM_TSS_NOFILE

/* verifySignatureFromHmacKey() verifies the signature (MAC) against the digest 'message'
   using the HMAC key in raw binary format.
*/

TPM_RC verifySignatureFromHmacKey(unsigned char *message,
				  unsigned int messageSize,
				  TPMT_SIGNATURE *tSignature,
				  TPMI_ALG_HASH halg,
				  const char *hmacKeyFilename)
{
    TPM_RC 		rc = 0;
    TPM2B_KEY 		hmacKey;
    uint32_t 		sizeInBytes;
    
    /* read the HMAC key */
    if (rc == 0) {
	rc = TSS_File_Read2B(&hmacKey.b,
			     sizeof(hmacKey.t.buffer),
			     hmacKeyFilename);
    }
    if (rc == 0) {
	sizeInBytes = TSS_GetDigestSize(halg);
	rc = TSS_HMAC_Verify(&tSignature->signature.hmac,
			     &hmacKey,		/* input HMAC key */
			     sizeInBytes,
			     messageSize, message,
			     0, NULL);
    }
    return rc;
}

#endif /* TPM_TSS_NOFILE */

/* convertRsaBinToTSignature() converts an RSA binary signature to a TPMT_SIGNATURE */

TPM_RC convertRsaBinToTSignature(TPMT_SIGNATURE *tSignature,
				 TPMI_ALG_HASH halg,
				 uint8_t *signatureBin,
				 size_t signatureBinLen)
{
    TPM_RC rc = 0;

    tSignature->sigAlg = TPM_ALG_RSASSA;
    tSignature->signature.rsassa.hash = halg;
    tSignature->signature.rsassa.sig.t.size = (uint16_t)signatureBinLen;
    memcpy(&tSignature->signature.rsassa.sig.t.buffer, signatureBin, signatureBinLen);
    return rc;
}

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOECC

/* convertEcBinToTSignature() converts an EC binary signature to a TPMT_SIGNATURE */

TPM_RC convertEcBinToTSignature(TPMT_SIGNATURE *tSignature,
				TPMI_ALG_HASH halg,
				const uint8_t *signatureBin,
				size_t signatureBinLen)
{
    TPM_RC rc = 0;
    ECDSA_SIG 		*ecSig = NULL;
    int 		rBytes;
    int 		sBytes;
    const BIGNUM 	*pr = NULL;
    const BIGNUM 	*ps = NULL;
    
    if (rc == 0) {
	tSignature->sigAlg = TPM_ALG_ECDSA;
	tSignature->signature.ecdsa.hash = halg;
    }
    /* convert DER to ECDSA_SIG */
    if (rc == 0) {
	ecSig = d2i_ECDSA_SIG(NULL, &signatureBin, signatureBinLen);	/* freed @1 */
	if (ecSig == NULL) {
	    printf("convertEcBinToTSignature: could not convert signature to ECDSA_SIG\n");
	    rc = TPM_RC_VALUE;
	}
    }
    /* check that the signature size agrees with the currently hard coded P256 curve */
    if (rc == 0) {
	ECDSA_SIG_get0(ecSig, &pr, &ps);
	rBytes = BN_num_bytes(pr);
	sBytes = BN_num_bytes(ps);
	if ((rBytes > 32) ||
	    (sBytes > 32)) {
	    printf("convertEcBinToTSignature: signature rBytes %u or sBytes %u greater than 32\n",
		   rBytes, sBytes);
	    rc = TPM_RC_VALUE;
	}
    }
    /* extract the raw signature bytes from the openssl structure BIGNUMs */
    if (rc == 0) {
	tSignature->signature.ecdsa.signatureR.t.size = rBytes;
	tSignature->signature.ecdsa.signatureS.t.size = sBytes;

	BN_bn2bin(pr, (unsigned char *)&tSignature->signature.ecdsa.signatureR.t.buffer);
	BN_bn2bin(ps, (unsigned char *)&tSignature->signature.ecdsa.signatureS.t.buffer);
	if (tssUtilsVerbose) {
	    TSS_PrintAll("convertEcBinToTSignature: signature R",
			 tSignature->signature.ecdsa.signatureR.t.buffer,
			 tSignature->signature.ecdsa.signatureR.t.size);		
	    TSS_PrintAll("convertEcBinToTSignature: signature S",
			 tSignature->signature.ecdsa.signatureS.t.buffer,
			 tSignature->signature.ecdsa.signatureS.t.size);		
	}
    }
    if (ecSig != NULL) {
	ECDSA_SIG_free(ecSig);		/* @1 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

#ifndef TPM_TSS_NOECC

/* getEcCurve() gets the TCG algorithm ID curve associated with the openssl EC_KEY */

TPM_RC getEcCurve(TPMI_ECC_CURVE *curveID,
		  const EC_KEY *ecKey)
{
    TPM_RC 		rc = 0;
    const EC_GROUP 	*ecGroup;
    int			nid;
    
    if (rc == 0) {
	ecGroup = EC_KEY_get0_group(ecKey);
	nid = EC_GROUP_get_curve_name(ecGroup);	/* openssl NID */
	/* NID to TCG curve ID */
	switch (nid) {
	  case NID_X9_62_prime256v1:
	    *curveID = TPM_ECC_NIST_P256;
	    break;
	  default:
	    printf("getEcCurve: Error, curve NID %u not supported \n", nid);
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */
#endif

/* convertBin2Bn() wraps the openSSL function in an error handler

   Converts a char array to bignum
*/

TPM_RC convertBin2Bn(BIGNUM **bn,			/* freed by caller */
		     const unsigned char *bin,
		     unsigned int bytes)
{
    TPM_RC rc = 0;

    /* BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret);
    
       BN_bin2bn() converts the positive integer in big-endian form of length len at s into a BIGNUM
       and places it in ret. If ret is NULL, a new BIGNUM is created.

       BN_bin2bn() returns the BIGNUM, NULL on error.
    */
    if (rc == 0) {
        *bn = BN_bin2bn(bin, bytes, *bn);
        if (*bn == NULL) {
            printf("convertBin2Bn: Error in BN_bin2bn\n");
            rc = TSS_RC_BIGNUM;
        }
    }
    return rc;
}

