/********************************************************************************/
/*										*/
/*			     TSS Library Independent Crypto Support		*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2019.					*/
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/tsserror.h>

#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>

extern int tssVverbose;
extern int tssVerbose;

/* local prototypes */

static TPM_RC TSS_MGF1(unsigned char       	*mask,
		       uint32_t            	maskLen,
		       const unsigned char 	*mgfSeed,
		       uint16_t			mgfSeedlen,
		       TPMI_ALG_HASH 		halg);

/* TSS_HMAC_Generate() can be called directly to HMAC a list of streams.
   
   The ... arguments are a message list of the form
   int length, unsigned char *buffer
   terminated by a 0 length
*/

/* On call, digest->hashAlg is the desired hash algorithm */

TPM_RC TSS_HMAC_Generate(TPMT_HA *digest,		/* largest size of a digest */
			 const TPM2B_KEY *hmacKey,
			 ...)
{
    TPM_RC		rc = 0;
    va_list		ap;
    
    va_start(ap, hmacKey);
    rc = TSS_HMAC_Generate_valist(digest, hmacKey, ap);
    va_end(ap);
    return rc;
}

/* TSS_HMAC_Verify() can be called directly to check the HMAC of a list of streams.
   
   The ... arguments are a list of the form
   int length, unsigned char *buffer
   terminated by a 0 length

*/

TPM_RC TSS_HMAC_Verify(TPMT_HA *expect,
		       const TPM2B_KEY *hmacKey,
		       uint32_t sizeInBytes,
		       ...)
{
    TPM_RC		rc = 0;
    int			irc;
    va_list		ap;
    TPMT_HA 		actual;

    actual.hashAlg = expect->hashAlg;	/* algorithm for the HMAC calculation */
    va_start(ap, sizeInBytes);
    if (rc == 0) {
	rc = TSS_HMAC_Generate_valist(&actual, hmacKey, ap);
    }
    if (rc == 0) {
	irc = memcmp((uint8_t *)&expect->digest, &actual.digest, sizeInBytes);
	if (irc != 0) {
	    TSS_PrintAll("TSS_HMAC_Verify: calculated HMAC",
			 (uint8_t *)&actual.digest, sizeInBytes);
	    rc = TSS_RC_HMAC_VERIFY;
	}
    }
    va_end(ap);
    return rc;
}

/* TSS_KDFA() 11.4.9	Key Derivation Function

   As defined in SP800-108, the inner loop for building the key stream is:

   K(i) = HMAC (KI , [i]2 || Label || 00 || Context || [L]2) 
*/

TPM_RC TSS_KDFA(uint8_t		*keyStream,    	/* OUT: key buffer */
		TPM_ALG_ID	hashAlg,       	/* IN: hash algorithm used in HMAC */
		const TPM2B	*key,           /* IN: HMAC key */
		const char	*label,		/* IN: KDFa label, NUL terminated */
		const TPM2B	*contextU,      /* IN: context U */
		const TPM2B	*contextV,      /* IN: context V */
		uint32_t	sizeInBits)    	/* IN: size of generated key in bits */

{
    TPM_RC	rc = 0;
    uint32_t 	bytes = ((sizeInBits + 7) / 8);	/* bytes left to produce */
    uint8_t	*stream;
    uint32_t 	sizeInBitsNbo = htonl(sizeInBits);	/* KDFa L2 */
    uint16_t    bytesThisPass;			/* in one HMAC operation */
    uint32_t	counter;    			/* counter value */
    uint32_t 	counterNbo;			/* counter in big endian */
    TPMT_HA 	hmac;				/* hmac result for this pass */
    

    if (rc == 0) {
	hmac.hashAlg = hashAlg;			/* for TSS_HMAC_Generate() */
	bytesThisPass = TSS_GetDigestSize(hashAlg);	/* start with hashAlg sized chunks */
	if (bytesThisPass == 0) {
	    if (tssVerbose) printf("TSS_KDFA: KDFa failed\n");
	    rc = TSS_RC_KDFA_FAILED;
	}
    }
    /* Generate required bytes */
    for (stream = keyStream, counter = 1 ;	/* beginning of stream, KDFa counter starts at 1 */
	 (rc == 0) && bytes > 0 ;				/* bytes left to produce */
	 stream += bytesThisPass, bytes -= bytesThisPass, counter++) {

	/* last pass, can be less than hashAlg sized chunks */
	if (bytes < bytesThisPass) {
	    bytesThisPass = bytes;
	}
	counterNbo = htonl(counter);	/* counter for this pass in BE format */
	    
	rc = TSS_HMAC_Generate(&hmac,				/* largest size of an HMAC */
			       (const TPM2B_KEY *)key,
			       sizeof(uint32_t), &counterNbo,	/* KDFa i2 counter */
			       strlen(label) + 1, label,	/* KDFa label, use NUL as the KDFa
								   00 byte */
			       contextU->size, contextU->buffer,	/* KDFa Context */
			       contextV->size, contextV->buffer,	/* KDFa Context */
			       sizeof(uint32_t), &sizeInBitsNbo,	/* KDFa L2 */
			       0, NULL);
	memcpy(stream, &hmac.digest.tssmax, bytesThisPass);
    }
    return rc;
}

/* TSS_KDFE() 11.4.9.3	Key Derivation Function for ECDH

   Digest = Hash(counter || Z || Use || PartyUInfo || PartyVInfo || bits )

   where

   counter is initialized to 1 and incremented for each iteration
   
   Z is the X-coordinate of the product of a public (TPM) ECC key and 
   a different private ECC key
   
   Use is a NULL-terminated string that indicates the use of the key 
   ("DUPLICATE", "IDENTITY", "SECRET", etc)
   
   PartyUInfo is the X-coordinate of the public point of an ephemeral key
   
   PartyVInfo is the X-coordinate of the public point of the TPM key
   
   bits is a 32-bit value indicating the number of bits to be returned
*/

TPM_RC TSS_KDFE(uint8_t		*keyStream,    	/* OUT: key buffer */
		TPM_ALG_ID	hashAlg,       	/* IN: hash algorithm used */
		const TPM2B	*key,           /* IN: Z  */
		const char	*label,		/* IN: KDFe label, NUL terminated */
		const TPM2B	*contextU,      /* IN: context U */
		const TPM2B	*contextV,      /* IN: context V */
		uint32_t	sizeInBits)    	/* IN: size of generated key in bits */

{
    TPM_RC	rc = 0;
    uint32_t 	bytes = ((sizeInBits + 7) / 8);	/* bytes left to produce */
    uint8_t	*stream;
    uint16_t    bytesThisPass;			/* in one Hash operation */
    uint32_t	counter;    			/* counter value */
    uint32_t 	counterNbo;			/* counter in big endian */
    TPMT_HA 	digest;				/* result for this pass */
    
    if (rc == 0) {
	digest.hashAlg = hashAlg;			/* for TSS_Hash_Generate() */
	bytesThisPass = TSS_GetDigestSize(hashAlg);	/* start with hashAlg sized chunks */
	if (bytesThisPass == 0) {
	    if (tssVerbose) printf("TSS_KDFE: KDFe failed\n");
	    rc = TSS_RC_KDFE_FAILED;
	}
    }
    /* Generate required bytes */
    for (stream = keyStream, counter = 1 ;	/* beginning of stream, KDFe counter starts at 1 */
	 (rc == 0) && bytes > 0 ;				/* bytes left to produce */
	 stream += bytesThisPass, bytes -= bytesThisPass, counter++) {
	/* last pass, can be less than hashAlg sized chunks */
	if (bytes < bytesThisPass) {
	    bytesThisPass = bytes;
	}
	counterNbo = htonl(counter);	/* counter for this pass in BE format */
	    
	rc = TSS_Hash_Generate(&digest,				/* largest size of a digest */
			       sizeof(uint32_t), &counterNbo,	/* KDFe i2 counter */
			       key->size, key->buffer,
			       strlen(label) + 1, label,	/* KDFe label, use NUL as the KDFe
								   00 byte */
			       contextU->size, contextU->buffer,	/* KDFe Context */
			       contextV->size, contextV->buffer,	/* KDFe Context */
			       0, NULL);
	memcpy(stream, &digest.digest.tssmax, bytesThisPass);
    }
    return rc;
}

/* On call, digest->hashAlg is the desired hash algorithm

   ... is a list of int length, unsigned char *buffer pairs.

   length 0 is ignored, buffer NULL terminates list.
*/

TPM_RC TSS_Hash_Generate(TPMT_HA *digest,		/* largest size of a digest */
			 ...)
{
    TPM_RC	rc = 0;
    va_list	ap;
    va_start(ap, digest);
    rc = TSS_Hash_Generate_valist(digest, ap);
    va_end(ap);
    return rc;
}


/* TSS_GetDigestBlockSize() returns the digest block size in bytes based on the hash algorithm.

   Returns 0 for an unknown algorithm.
*/

/* NOTE: Marked as const function in header */

uint16_t TSS_GetDigestBlockSize(TPM_ALG_ID hashAlg)
{
    uint16_t size;
    
    switch (hashAlg) {
#ifdef TPM_ALG_SHA1
     case TPM_ALG_SHA1:
	size = SHA1_BLOCK_SIZE;
	break;
#endif
#ifdef TPM_ALG_SHA256	
      case TPM_ALG_SHA256:
	size = SHA256_BLOCK_SIZE;
	break;
#endif
#ifdef TPM_ALG_SHA384
     case TPM_ALG_SHA384:
	size = SHA384_BLOCK_SIZE;
	break;
#endif
#ifdef TPM_ALG_SHA512
      case TPM_ALG_SHA512:
	size = SHA512_BLOCK_SIZE;
	break;
#endif
#if 0
      case TPM_ALG_SM3_256:
	size = SM3_256_BLOCK_SIZE;
	break;
#endif
      default:
	size = 0;
    }
    return size;
}

/* TPM_MGF1() generates an MGF1 'array' of length 'arrayLen' from 'seed' of length 'seedlen'

   The openSSL DLL doesn't export MGF1 in Windows or Linux 1.0.0, so this version is created from
   scratch.
   
   Algorithm and comments (not the code) from:

   PKCS #1: RSA Cryptography Specifications Version 2.1 B.2.1 MGF1

   Prototype designed to be compatible with openSSL

   MGF1 is a Mask Generation Function based on a hash function.
   
   MGF1 (mgfSeed, maskLen)

   Options:     

   Hash hash function (hLen denotes the length in octets of the hash 
   function output)

   Input:
   
   mgfSeed         seed from which mask is generated, an octet string
   maskLen         intended length in octets of the mask, at most 2^32(hLen)

   Output:      
   mask            mask, an octet string of length l; or "mask too long"

   Error:          "mask too long'
*/

static TPM_RC TSS_MGF1(unsigned char       	*mask,
		       uint32_t            	maskLen,
		       const unsigned char 	*mgfSeed,
		       uint16_t			mgfSeedlen,
		       TPMI_ALG_HASH 		halg)
{
    TPM_RC 		rc = 0;
    unsigned char       counter[4];     /* 4 octets */
    uint32_t	        count;          /* counter as an integral type */
    uint32_t		outLen;
    TPMT_HA 		digest;
    uint16_t 		digestSize = TSS_GetDigestSize(halg);
    
    digest.hashAlg = halg;
    
#if 0
    if (rc == 0) {
        /* this is possible with arrayLen on a 64 bit architecture, comment to quiet beam */
        if ((maskLen / TPM_DIGEST_SIZE) > 0xffffffff) {        /* constant condition */
            if (tssVerbose)
		printf("TSS_MGF1: Error (fatal), Output length too large for 32 bit counter\n");
            rc = TPM_FAIL;              /* should never occur */
        }
    }
#endif
    /* 1.If l > 2^32(hLen), output "mask too long" and stop. */
    /* NOTE Checked by caller */
    /* 2. Let T be the empty octet string. */
    /* 3. For counter from 0 to [masklen/hLen] - 1, do the following: */
    for (count = 0, outLen = 0 ; (rc == 0) && (outLen < maskLen) ; count++) {
	/* a. Convert counter to an octet string C of length 4 octets - see Section 4.1 */
	/* C = I2OSP(counter, 4) NOTE Basically big endian */
        uint32_t count_n = htonl(count);
	memcpy(counter, &count_n, 4);
	/* b.Concatenate the hash of the seed mgfSeed and C to the octet string T: */
	/* T = T || Hash (mgfSeed || C) */
	/* If the entire digest is needed for the mask */
	if ((outLen + digestSize) < maskLen) {
	    rc = TSS_Hash_Generate(&digest,
				   mgfSeedlen, mgfSeed,
				   4, counter,
				   0, NULL);
	    memcpy(mask + outLen, &digest.digest, digestSize);
	    outLen += digestSize;
	}
	/* if the mask is not modulo TPM_DIGEST_SIZE, only part of the final digest is needed */
	else {
	    /* hash to a temporary digest variable */
	    rc = TSS_Hash_Generate(&digest,
				   mgfSeedlen, mgfSeed,
				   4, counter,
				   0, NULL);
	    /* copy what's needed */
	    memcpy(mask + outLen, &digest.digest, maskLen - outLen);
	    outLen = maskLen;           /* outLen = outLen + maskLen - outLen */
	}
    }
    /* 4.Output the leading l octets of T as the octet string mask. */
    return rc;
}

/*
  OAEP Padding 
*/

/* TSS_RSA_padding_add_PKCS1_OAEP() is a variation of the the openSSL function

   int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
   unsigned char *f, int fl, unsigned char *p, int pl);

   It is used because the openssl function is hard coded to SHA1.

   This function was independently written from the PKCS1 specification "9.1.1.1 Encoding
   Operation" and PKCS#1 v2.2, intended to be unencumbered by any license.


   | <-			  emLen					   -> |
   
                         |  lHash |    PS     | 01 |  Message	      |

                            SHA                       flen

                         |  db                                        |
			 |  dbMask                                    |
        |  seed          |

	   SHA
	   
        |  seedMask      | 
   | 00 |  maskSeed      |   maskedDB                                 |
*/

TPM_RC TSS_RSA_padding_add_PKCS1_OAEP(unsigned char *em, uint32_t emLen,
				      const unsigned char *from, uint32_t fLen,
				      const unsigned char *p,
				      int plen,
				      TPMI_ALG_HASH halg)	
{	
    TPM_RC		rc = 0;
    TPMT_HA 		lHash;
    unsigned char 	*db = NULL;		/* compiler false positive */
    
    unsigned char *dbMask = NULL;			/* freed @1 */
    unsigned char *seed = NULL;				/* freed @2 */
    unsigned char *maskedDb;
    unsigned char *seedMask = NULL;		/* compiler false positive */
    unsigned char *maskedSeed;

    uint16_t hlen = TSS_GetDigestSize(halg);
    
    /* 1.a. If the length of L is greater than the input limitation for */
    /* the hash function (2^61-1 octets for SHA-1) then output "parameter */
    /* string too long" and stop. */
    if (rc == 0) {
	if (plen > 0xffff) {
	    if (tssVerbose) printf("TSS_RSA_padding_add_PKCS1_OAEP: Error, "
				   "label %u too long\n", plen);
	    rc = TSS_RC_RSA_PADDING;
	}	    
    }
    /* 1.b. If ||M|| > emLen-2hLen-1 then output "message too long" and stop. */
    if (rc == 0) {
	if (emLen < ((2 * hlen) + 2 + fLen)) {
	    if (tssVerbose) printf("TSS_RSA_padding_add_PKCS1_OAEP: Error, "
				   "message length %u too large for encoded length %u\n",
				   fLen, emLen);
	    rc = TSS_RC_RSA_PADDING;
	}
    }
    /* 2.a. Let lHash = Hash(L), an octet string of length hLen. */
    if (rc == 0) {
	lHash.hashAlg = halg;
	rc = TSS_Hash_Generate(&lHash,
			       plen, p,
			       0, NULL);
    }
    if (rc == 0) {
	/* 2.b. Generate an octet string PS consisting of emLen-||M||-2hLen-2 zero octets. The
	   length of PS may be 0. */
	/* 2.c. Concatenate lHash, PS, a single octet of 0x01 the message M, to form a data block DB
	   as: DB = lHash || PS || 01 || M */
	/* NOTE Since db is eventually maskedDb, part of em, create directly in em */
	db = em + hlen + 1;
	memcpy(db, &lHash.digest, hlen);			/* lHash */
	/* PSlen = emlen - flen - (2 * hlen) - 2 */
	memset(db + hlen, 0,					/* PS */
	       emLen - fLen - (2 * hlen) - 2);
	/* position of 0x01 in db is
	   hlen + PSlen =
	   hlen + emlen - flen - (2 * hlen) - 2 = 
	   emlen - hlen - flen - 2 */
	db[emLen - fLen - hlen - 2] = 0x01;
	memcpy(db + emLen - fLen - hlen - 1, from, fLen);	/* M */
    }
    /* 2.d. Generate a random octet string seed of length hLen. */
    if (rc == 0) {
	rc = TSS_Malloc(&seed, hlen);
    }
    if (rc == 0) {
	rc = TSS_RandBytes(seed, hlen);
    }
    if (rc == 0) {
	rc = TSS_Malloc(&dbMask, emLen - hlen - 1);
    }
    if (rc == 0) {
	/* 2.e. Let dbMask = MGF(seed, emLen-hLen-1). */
	rc = TSS_MGF1(dbMask, emLen - hlen -1,	/* dbLen */
		      seed, hlen,
		      halg);
    }
    if (rc == 0) {
	/* 2.f. Let maskedDB = DB xor dbMask. */
	/* NOTE Since maskedDB is eventually em, XOR directly to em */
	maskedDb = em + hlen + 1;
	TSS_XOR(maskedDb, db, dbMask, emLen - hlen -1);
	/* 2.g. Let seedMask = MGF(maskedDB, hLen). */
	/* NOTE Since seedMask is eventually em, create directly to em */
	seedMask = em + 1;
	rc = TSS_MGF1(seedMask, hlen,
		      maskedDb, emLen - hlen - 1,
		      halg);
    }
    if (rc == 0) {
	/* 2.h. Let maskedSeed = seed xor seedMask. */
	/* NOTE Since maskedSeed is eventually em, create directly to em */
	maskedSeed = em + 1;
	TSS_XOR(maskedSeed, seed, seedMask, hlen);
	/* 2.i. 0x00, maskedSeed, and maskedDb to form EM */
	/* NOTE Created directly in em */
    }
    free(dbMask);		/* @1 */
    free(seed);			/* @2 */
    return rc;
}

/* TPM_XOR XOR's 'in1' and 'in2' of 'length', putting the result in 'out'

 */

void TSS_XOR(unsigned char *out,
	     const unsigned char *in1,
	     const unsigned char *in2,
	     size_t length)
{
    size_t i;
    
    for (i = 0 ; i < length ; i++) {
	out[i] = in1[i] ^ in2[i];
    }
    return;
}

/*
  AES
*/

#define TSS_AES_KEY_BITS 128

/* TSS_Sym_GetBlockSize() returns the block size for the symmetric algorithm.  Returns 0 on for an
   unknown algorithm.
*/

/* NOTE: Marked as const function in header */

uint16_t TSS_Sym_GetBlockSize(TPM_ALG_ID	symmetricAlg, 
			      uint16_t		keySizeInBits)
{
    keySizeInBits = keySizeInBits;
    
    switch (symmetricAlg) {
#ifdef TPM_ALG_AES
      case TPM_ALG_AES:
#endif
#ifdef TPM_ALG_SM4 /* Both AES and SM4 use the same block size */
      case TPM_ALG_SM4:
#endif
	return  16;
      default:
	return 0;
    }
    return 0;
}

