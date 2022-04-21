/********************************************************************************/
/*										*/
/*			   RSA_Decrypt						*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2020					*/
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

/* 

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscryptoh.h>

static void printRsaDecrypt(RSA_Decrypt_Out *out);
static TPM_RC getKeySize(TSS_CONTEXT 		*tssContext,
			 TPMI_RSA_KEY_BITS	*keyBits,
			 TPMI_DH_PCR		objectHandle);
static TPM_RC padData(uint8_t 		**buffer,
		      size_t		*padLength,
		      TPMI_ALG_HASH 	halg,
		      TPMI_RSA_KEY_BITS	keyBits);
static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    RSA_Decrypt_In 		in;
    RSA_Decrypt_Out 		out;
    TPMI_DH_OBJECT		keyHandle = 0;
    TPMI_RSA_KEY_BITS		keyBits;
    const char			*encryptFilename = NULL;
    const char			*decryptFilename = NULL;
    const char			*keyPassword = NULL;
    const char			*keyPasswordFilename = NULL;
    uint8_t			*keyPasswordBuffer = NULL;
    size_t 			keyPasswordBufferLength = 0;
    const char			*keyPasswordPtr = NULL;
    TPMI_ALG_HASH 		halg = TPM_ALG_NULL;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RH_NULL;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;
 
    uint16_t			written;
    size_t			length;			/* input data */
    uint8_t			*buffer = NULL;		/* for the free */

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x",&keyHandle);
	    }
	    else {
		printf("Missing parameter for -hk\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdk") == 0) {
	    i++;
	    if (i < argc) {
		keyPassword = argv[i];
	    }
	    else {
		printf("-pwdk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ipwdk") == 0) {
	    i++;
	    if (i < argc) {
		keyPasswordFilename = argv[i];
	    }
	    else {
		printf("-ipwdk option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-oid") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    halg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    halg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    halg = TPM_ALG_SHA384;
		}
		else if (strcmp(argv[i],"sha512") == 0) {
		    halg = TPM_ALG_SHA512;
		}
		else {
		    printf("Bad parameter %s for -oid\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-oid option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ie") == 0) {
	    i++;
	    if (i < argc) {
		encryptFilename = argv[i];
	    }
	    else {
		printf("-ie option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-od") == 0) {
	    i++;
	    if (i < argc) {
		decryptFilename = argv[i];
	    }
	    else {
		printf("-od option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se0") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle0);
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes0);
		if (sessionAttributes0 > 0xff) {
		    printf("Out of range session attributes for -se0\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se0\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se1") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle1);
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes1);
		if (sessionAttributes1 > 0xff) {
		    printf("Out of range session attributes for -se1\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se1\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-se2") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionHandle2);
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x", &sessionAttributes2);
		if (sessionAttributes2 > 0xff) {
		    printf("Out of range session attributes for -se2\n");
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -se2\n");
		printUsage();
	    }
	}
 	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    tssUtilsVerbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (keyHandle == 0) {
	printf("Missing handle parameter -hk\n");
	printUsage();
    }
    if (encryptFilename == NULL) {
	printf("Missing encrypted message -ie\n");
	printUsage();
    }
    if ((keyPassword != NULL) && (keyPasswordFilename != NULL)) {
	printf("Only one of -pwdk and -ipwdk can be specified\n");
	printUsage();
    }
    if (rc == 0) {
	/* use passsword from command line */
	if (keyPassword != NULL) {
	    keyPasswordPtr = keyPassword;
	}
	/* use password from file */
	else if (keyPasswordFilename != NULL) {
	    rc = TSS_File_ReadBinaryFile(&keyPasswordBuffer,     /* freed @2 */
					 &keyPasswordBufferLength,
					 keyPasswordFilename);
	    keyPasswordPtr = (const char *)keyPasswordBuffer;
	}
	/* empty password */
	else {
	    keyPasswordPtr = NULL;
	}
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* get the public modulus size for checks and padding */
    if (rc == 0) {
	rc = getKeySize(tssContext, &keyBits, keyHandle);
    }
    if (rc == 0) {
	rc = TSS_File_ReadBinaryFile(&buffer,     /* freed @1 */
				     &length,
				     encryptFilename);
    }
    if (rc == 0) {
	if (length > (keyBits / 8U)) {
	    printf("Input data too long %u\n", (unsigned int)length);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* if an OID was requested, treat the encryptFilename as a hash to be signed */
    if ((rc == 0) && (halg != TPM_ALG_NULL)) {
	rc = padData(&buffer,		/* realloced to fit */
		     &length,		/* resized for OID and pad */
		     halg,		/* gigest algorithm for size and OID */
		     keyBits);		/* RSA modulus length in bits */
    }
    if (rc == 0) {
	/* Handle of key that will perform rsa decrypt */
	in.keyHandle = keyHandle;

	/* Table 158 - Definition of {RSA} TPM2B_PUBLIC_KEY_RSA Structure */
	{
	    in.cipherText.t.size = (uint16_t)length;	/* cast safe, range tested above */
	    memcpy(in.cipherText.t.buffer, buffer, length);
	}
	/* padding scheme */
	{
	    /* Table 157 - Definition of {RSA} TPMT_RSA_DECRYPT Structure */
	    in.inScheme.scheme = TPM_ALG_NULL;
	}
	/* label */
	{
	    /* Table 73 - Definition of TPM2B_DATA Structure */
	    in.label.t.size = 0;
	}
    }
    free(buffer);		/* @1 */
    buffer = NULL;

    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_RSA_Decrypt,
			 sessionHandle0, keyPasswordPtr, sessionAttributes0,
			 sessionHandle1, NULL, sessionAttributes1,
			 sessionHandle2, NULL, sessionAttributes2,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if ((rc == 0) && (decryptFilename != NULL)) {
	rc = TSS_Structure_Marshal(&buffer,	/* freed @1 */
				   &written,
				   &out.message,
				   (MarshalFunction_t)TSS_TPM2B_PUBLIC_KEY_RSA_Marshalu);
    }
    if ((rc == 0) && (decryptFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(buffer + sizeof(uint16_t),
				      written - sizeof(uint16_t),
				      decryptFilename); 
    }    
    if (rc == 0) {
	if (tssUtilsVerbose) printRsaDecrypt(&out);
	if (tssUtilsVerbose) printf("rsadecrypt: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("rsadecrypt: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    free(buffer);		/* @1 */
    free(keyPasswordBuffer);	/* @2 */
    return rc;
}

/* padData() is used then the private key operation is a signing operation over a hash.  It takes a
   'buffer' of original 'length'.  The original length should match the hash algorithm digest size.

   buffer is realloc'ed to the key size, than then padded with the OID for the hash algorithm and
   the PKCS1 padding.
*/

static TPM_RC padData(uint8_t 			**buffer,
		      size_t			*padLength,
		      TPMI_ALG_HASH 		halg,
		      TPMI_RSA_KEY_BITS		keyBits)
{
    TPM_RC		rc = 0;
    uint16_t 		digestSize;
    const uint8_t	*oid;
    uint16_t		oidSize;
    const uint8_t	sha1Oid[] = {SHA1_DER};
    const uint8_t	sha256Oid[] = {SHA256_DER};
    const uint8_t	sha384Oid[] = {SHA384_DER};
    const uint8_t	sha512Oid[] = {SHA512_DER};
    
    /* check that the original buffer length matches the hash algorithm */
    if (rc == 0) {
	digestSize = TSS_GetDigestSize(halg);
	if (digestSize == 0) {
	    printf("padData: Unsupported hash algorithm %04x\n", halg);
	    rc = TPM_RC_HASH;
	}
    }
    if (rc == 0) {
	if (digestSize != *padLength) {
	    unsigned long pl = *padLength;
	    printf("paddata: hash algorithm length %u not equal data length %lu\n",
		   digestSize, pl);
	    rc = TPM_RC_VALUE;
	}
    }
    /* realloc the buffer to the key size in bytes */
    if (rc == 0) {
	*padLength = keyBits / 8;
	rc = TSS_Realloc(buffer, *padLength);
    }
    /* determine the OID */
    if (rc == 0) {
	switch (halg) {
	  case TPM_ALG_SHA1:
	    oid = sha1Oid;
	    oidSize = SHA1_DER_SIZE;
	    break;
	  case TPM_ALG_SHA256:
	    oid = sha256Oid;
	    oidSize = SHA256_DER_SIZE;
	    break;
	  case TPM_ALG_SHA384:
	    oid = sha384Oid;
	    oidSize = SHA384_DER_SIZE;
	    break;
	  case TPM_ALG_SHA512:
	    oid = sha512Oid;
	    oidSize = SHA512_DER_SIZE;
	    break;
	  default:
	    printf("padData: Unsupported hash algorithm %04x\n", halg);
	    rc = TPM_RC_HASH;
	}
    }
    if (rc == 0) {
	/* move the hash to the end */
	memmove(*buffer + *padLength - digestSize, *buffer, digestSize);
	/* prepend the OID */
	memcpy(*buffer + *padLength - digestSize - oidSize, oid, oidSize);
	/* prepend the PKCS1 pad */
	(*buffer)[0] = 0x00;
	(*buffer)[1] = 0x01;
	memset(&(*buffer)[2], 0xff, *padLength - 3 - oidSize - digestSize);
	(*buffer)[*padLength - oidSize - digestSize - 1] = 0x00;
	if (tssUtilsVerbose) TSS_PrintAll("padData: padded data", *buffer, *padLength);
    }
    return rc;
}

/* getKeySize() gets the key size in bits */

static TPM_RC getKeySize(TSS_CONTEXT 		*tssContext,
			 TPMI_RSA_KEY_BITS	*keyBits,
			 TPMI_DH_PCR		objectHandle)
{
    TPM_RC			rc = 0;
    ReadPublic_In 		in;
    ReadPublic_Out 		out;

    /* call TSS to execute the command */
    if (rc == 0) {
	in.objectHandle = objectHandle;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_ReadPublic,
			 TPM_RH_NULL, NULL, 0);
    }
    if (rc == 0) {
	*keyBits = out.outPublic.publicArea.parameters.rsaDetail.keyBits;
	if (tssUtilsVerbose) printf("getKeySize: size %u\n", *keyBits);
    }
    return rc;
}

static void printRsaDecrypt(RSA_Decrypt_Out *out)
{
    TSS_PrintAll("outData", out->message.t.buffer, out->message.t.size);
}

static void printUsage(void)
{
    printf("\n");
    printf("rsadecrypt\n");
    printf("\n");
    printf("Runs TPM2_RSA_Decrypt\n");
    printf("\n");
    printf("\t-hk\tkey handle\n");
    printf("\t[-pwdk\tpassword for key (default empty)[\n");
    printf("\t[-ipwdk\tpassword file for key, nul terminated (default empty)]\n");
    printf("\t-ie\tencrypt file name\n");
    printf("\t-od\tdecrypt file name (default do not save)\n");
    printf("\t[-oid\t(sha1, sha256, sha384 sha512)]\n");
    printf("\t\toptionally add OID and PKCS1 padding to the\n");
    printf("\t\tencrypt data (demo of signing with arbitrary OID)\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);	
}
