/********************************************************************************/
/*										*/
/*			EK Index Parsing Utilities (and more)			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2019.					*/
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

/* These functions are worthwhile sample code that probably (judgment call) do not belong in the
   TSS library.

   They started as code to manipulate EKs, EK templates, and EK certificates.

   Other useful X509 certificate crypto functions are migrating here.  Much of it is OpenSSL
   specific, but it also provides examples of how to port from OpenSSL 1.0 to 1.1.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

/* Windows 10 crypto API clashes with openssl */
#ifdef TPM_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tsscrypto.h>
#include <ibmtss/tssprint.h>
#include <ibmtss/Unmarshal_fp.h>

#include "cryptoutils.h"
#include "ekutils.h"

/* windows apparently uses _MAX_PATH in stdlib.h */
#ifndef PATH_MAX
#ifdef _MAX_PATH
#define PATH_MAX _MAX_PATH
#else
/* Debian/Hurd does not define MAX_PATH */
#define PATH_MAX 4096
#endif
#endif

/* The print flag is set by the caller, depending on whether it wants information displayed.

   tssUtilsVerbose is a global, used for verbose debug print

   Errors are always printed.
*/

extern int tssUtilsVerbose;

#ifdef TPM_TPM20

/* readNvBufferMax() determines the maximum NV read/write block size.  The limit is typically set by
   the TPM property TPM_PT_NV_BUFFER_MAX.  However, it's possible that a value could be larger than
   the TSS side structure MAX_NV_BUFFER_SIZE.
*/

TPM_RC readNvBufferMax(TSS_CONTEXT *tssContext,
		       uint32_t *nvBufferMax)
{
    TPM_RC			rc = 0;
    GetCapability_In 		in;
    GetCapability_Out		out;

    in.capability = TPM_CAP_TPM_PROPERTIES;
    in.property = TPM_PT_NV_BUFFER_MAX;
    in.propertyCount = 1;	/* ask for one property */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out, 
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_GetCapability,
			 TPM_RH_NULL, NULL, 0);
    }
    /* sanity check that the property name is correct (demo of how to parse the structure) */
    if (rc == 0) {
	if ((out.capabilityData.data.tpmProperties.count > 0) &&
	    (out.capabilityData.data.tpmProperties.tpmProperty[0].property ==
	     TPM_PT_NV_BUFFER_MAX)) {
	    *nvBufferMax = out.capabilityData.data.tpmProperties.tpmProperty[0].value;
	}
	else {
	    if (tssUtilsVerbose) printf("readNvBufferMax: wrong property returned: %08x\n",
		   out.capabilityData.data.tpmProperties.tpmProperty[0].property);
	    /* hard code a value for a back level HW TPM that does not implement
	       TPM_PT_NV_BUFFER_MAX yet */
	    *nvBufferMax = 512;
	}
	if (tssUtilsVerbose) printf("readNvBufferMax: TPM max read/write: %u\n", *nvBufferMax);
	/* in addition, the maximum TSS side structure MAX_NV_BUFFER_SIZE is accounted for.  The TSS
	   value is typically larger than the TPM value. */
	if (*nvBufferMax > MAX_NV_BUFFER_SIZE) {
	    *nvBufferMax = MAX_NV_BUFFER_SIZE;
	}
	if (tssUtilsVerbose) printf("readNvBufferMax: combined max read/write: %u\n", *nvBufferMax);
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("getcapability: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* getIndexSize() uses TPM2_NV_ReadPublic() to return the NV index size */

TPM_RC getIndexSize(TSS_CONTEXT *tssContext,
		    uint16_t *dataSize,
		    TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC			rc = 0;
    NV_ReadPublic_In 		in;
    NV_ReadPublic_Out		out;
    
    if (rc == 0) {
	/* if (tssUtilsVerbose) printf("getIndexSize: index %08x\n", nvIndex); */
	in.nvIndex = nvIndex;
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_NV_ReadPublic,
			 TPM_RH_NULL, NULL, 0);
	/* only print if verbose, since EK nonce and template index may not exist */
	if ((rc != 0) && tssUtilsVerbose) {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("nvreadpublic: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	}
    }
    if (rc == 0) {
	/* if (tssUtilsVerbose) printf("getIndexSize: size %u\n", out.nvPublic.t.nvPublic.dataSize); */
	*dataSize = out.nvPublic.nvPublic.dataSize;
    }
    return rc;
}

/* getIndexData() uses TPM2_NV_Read() to return the NV index contents.

   It assumes index authorization with an empty password
*/

TPM_RC getIndexData(TSS_CONTEXT *tssContext,
		    unsigned char **readBuffer,		/* freed by caller */
		    TPMI_RH_NV_INDEX nvIndex,
		    uint16_t readDataSize)		/* total size to read */
{
    TPM_RC			rc = 0;
    int				done = FALSE;
    uint32_t 			nvBufferMax;
    uint16_t 			bytesRead;			/* bytes read so far */
    NV_Read_In 			in;
    NV_Read_Out			out;
    
    /* data may have to be read in chunks.  Read the TPM_PT_NV_BUFFER_MAX, the chunk size */
    if (rc == 0) {
	rc = readNvBufferMax(tssContext,
			     &nvBufferMax);
    }    
    if (rc == 0) {
	if (tssUtilsVerbose) printf("getIndexData: index %08x\n", nvIndex);
	in.authHandle = nvIndex;	/* index authorization */
	in.nvIndex = nvIndex;
	in.offset = 0;			/* start at beginning */
	bytesRead = 0;			/* bytes read so far */
    }
    if (rc == 0) {
	rc = TSS_Malloc(readBuffer, readDataSize);
    }
    /* call TSS to execute the command */
    while ((rc == 0) && !done) {
	if (rc == 0) {
	    /* read a chunk */
	    in.offset = bytesRead;
	    if ((uint32_t)(readDataSize - bytesRead) < nvBufferMax) {
		in.size = readDataSize - bytesRead;	/* last chunk */
	    }
	    else {
		in.size = nvBufferMax;		/* next chunk */
	    }
	}
	if (rc == 0) {
	    rc = TSS_Execute(tssContext,
			     (RESPONSE_PARAMETERS *)&out,
			     (COMMAND_PARAMETERS *)&in,
			     NULL,
			     TPM_CC_NV_Read,
			     TPM_RS_PW, NULL, 0,
			     TPM_RH_NULL, NULL, 0);
	    if (rc != 0) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("nvread: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
	    }
	}
 	/* copy the results to the read buffer */
	if (rc == 0) {
	    memcpy(*readBuffer + bytesRead, out.data.b.buffer, out.data.b.size);
	    bytesRead += out.data.b.size;
	    if (bytesRead == readDataSize) {
		done = TRUE;
	    }
	}
    }
    return rc;
}

/* getIndexContents() uses TPM2_NV_ReadPublic() to get the NV index size, then uses TPM2_NV_Read()
   to read the entire contents.

*/

TPM_RC getIndexContents(TSS_CONTEXT *tssContext,
			unsigned char **readBuffer,		/* freed by caller */
			uint16_t *readBufferSize,		/* total size read */
			TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC			rc = 0;

    /* first read the public index size */
    if (rc == 0) {
	rc = getIndexSize(tssContext, readBufferSize, nvIndex);
    }
    /* read the entire index */
    if (rc == 0) {
	rc = getIndexData(tssContext,
			  readBuffer,			/* freed by caller */
			  nvIndex,
			  *readBufferSize);		/* total size to read */
    }
    return rc;
}

/* IWG (TCG Infrastructure Work Group) default EK primary key policy */

static const unsigned char iwgPolicy[] = {
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D, 0x46, 0xA5, 0xD7, 0x24,
    0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
};

/* RSA EK primary key IWG default template */

void getRsaTemplate(TPMT_PUBLIC *tpmtPublic)
{
    tpmtPublic->type = TPM_ALG_RSA;
    tpmtPublic->nameAlg = TPM_ALG_SHA256;
    tpmtPublic->objectAttributes.val = TPMA_OBJECT_FIXEDTPM |
				       TPMA_OBJECT_FIXEDPARENT |
				       TPMA_OBJECT_SENSITIVEDATAORIGIN |
				       TPMA_OBJECT_ADMINWITHPOLICY |
				       TPMA_OBJECT_RESTRICTED |
				       TPMA_OBJECT_DECRYPT;
    tpmtPublic->authPolicy.t.size = 32;
    memcpy(&tpmtPublic->authPolicy.t.buffer, iwgPolicy, 32);
    tpmtPublic->parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
    tpmtPublic->parameters.rsaDetail.symmetric.keyBits.aes = 128;
    tpmtPublic->parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
    tpmtPublic->parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
    tpmtPublic->parameters.rsaDetail.scheme.details.anySig.hashAlg = 0;
    tpmtPublic->parameters.rsaDetail.keyBits = 2048;
    tpmtPublic->parameters.rsaDetail.exponent = 0;
    tpmtPublic->unique.rsa.t.size = 256;
    memset(&tpmtPublic->unique.rsa.t.buffer, 0, 256);
    return;
}

/* ECC EK primary key IWG default template */

void getEccTemplate(TPMT_PUBLIC *tpmtPublic)
{
    tpmtPublic->type = TPM_ALG_ECC;
    tpmtPublic->nameAlg = TPM_ALG_SHA256;
    tpmtPublic->objectAttributes.val = TPMA_OBJECT_FIXEDTPM |
				       TPMA_OBJECT_FIXEDPARENT |
				       TPMA_OBJECT_SENSITIVEDATAORIGIN |
				       TPMA_OBJECT_ADMINWITHPOLICY |
				       TPMA_OBJECT_RESTRICTED |
				       TPMA_OBJECT_DECRYPT;
    tpmtPublic->authPolicy.t.size = sizeof(iwgPolicy);
    memcpy(tpmtPublic->authPolicy.t.buffer, iwgPolicy, sizeof(iwgPolicy));
    tpmtPublic->parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
    tpmtPublic->parameters.eccDetail.symmetric.keyBits.aes = 128;
    tpmtPublic->parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
    tpmtPublic->parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
    tpmtPublic->parameters.eccDetail.scheme.details.anySig.hashAlg = 0;
    tpmtPublic->parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
    tpmtPublic->parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;
    tpmtPublic->parameters.eccDetail.kdf.details.mgf1.hashAlg = 0;
    tpmtPublic->unique.ecc.x.t.size = 32;	
    memset(&tpmtPublic->unique.ecc.x.t.buffer, 0, 32);	
    tpmtPublic->unique.ecc.y.t.size = 32;	
    memset(&tpmtPublic->unique.ecc.y.t.buffer, 0, 32);	
    return;
}

/* getIndexX509Certificate() reads the X509 certificate from the nvIndex and converts the DER
   (binary) to OpenSSL X509 format

*/

TPM_RC getIndexX509Certificate(TSS_CONTEXT *tssContext,
			       void **certificate,		/* freed by caller */
			       TPMI_RH_NV_INDEX nvIndex)
{
    TPM_RC			rc = 0;
    unsigned char 		*certData = NULL; 		/* freed @1 */
    uint16_t 			certSize;

    /* read the certificate from NV to a DER stream */
    if (rc == 0) {
	rc = getIndexContents(tssContext,
			      &certData,
			      &certSize,
			      nvIndex);
    }
    /* unmarshal the DER stream to an OpenSSL X509 structure */
    if (rc == 0) {
	unsigned char 		*tmpData = NULL; 
	tmpData = certData;			/* tmp pointer because d2i moves the pointer */
	*certificate = d2i_X509(NULL,			/* freed by caller */
				 (const unsigned char **)&tmpData, certSize);
	if (*certificate == NULL) {
	    printf("getIndexX509Certificate: Could not parse X509 certificate\n");
	    rc = TPM_RC_INTEGRITY;
	}
    }
    free(certData);			/* @1 */
    return rc;
}

#endif	/* TPM20 */

#ifndef TPM_TSS_NOFILE
#ifndef TPM_TSS_NORSA

/* getPubkeyFromDerCertFile() gets an OpenSSL RSA public key token from a DER format X509
   certificate stored in a file.

   Returns both the OpenSSL X509 certificate token and RSA public key token.
*/

uint32_t getPubkeyFromDerCertFile(RSA  **rsaPkey,
				  X509 **x509,
				  const char *derCertificateFileName)
{
    uint32_t rc = 0;
    FILE *fp = NULL;

    /* open the file */
    if (rc == 0) {
	fp = fopen(derCertificateFileName, "rb");
	if (fp == NULL) {
	    printf("getPubkeyFromDerCertFile: Error opening %s\n", derCertificateFileName);
	    rc = TSS_RC_FILE_OPEN;
	}
    }
    /* read the file and convert the X509 DER to OpenSSL format */
    if (rc == 0) {
	*x509 = d2i_X509_fp(fp, NULL);
	if (*x509 == NULL) {
	    printf("getPubkeyFromDerCertFile: Error converting %s\n", derCertificateFileName);
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* extract the OpenSSL format public key from the X509 token */
    if (rc == 0) {
	rc = getPubKeyFromX509Cert(rsaPkey, *x509);
    }
    /* for debug, print the X509 certificate */
    if (rc == 0) {
	if (tssUtilsVerbose) X509_print_fp(stdout, *x509);
    }
    if (fp != NULL) {
	fclose(fp);
    }
    return rc;
}

#endif /* TPM_TSS_NORSA */
#endif /* TPM_TSS_NOFILE */

#ifndef TPM_TSS_NORSA

/* getPubKeyFromX509Cert() gets an OpenSSL RSA public key token from an OpenSSL X509 certificate
   token. */

uint32_t getPubKeyFromX509Cert(RSA  **rsaPkey,
			       X509 *x509)
{
    uint32_t rc = 0;
    EVP_PKEY *evpPkey = NULL;

    if (rc == 0) {
	evpPkey = X509_get_pubkey(x509);	/* freed @1 */
	if (evpPkey == NULL) {
	    printf("getPubKeyFromX509Cert: X509_get_pubkey failed\n");  
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	*rsaPkey = EVP_PKEY_get1_RSA(evpPkey);
	if (*rsaPkey == NULL) {
	    printf("getPubKeyFromX509Cert: EVP_PKEY_get1_RSA failed\n");  
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}
#endif /* TPM_TSS_NORSA */

#ifndef TPM_TSS_NOFILE

/* getRootCertificateFilenames() reads listFilename, which is a list of filenames.  The intent is
   that the filenames are a list of EK TPM vendor root certificates in PEM format.

   It accepts up to MAX_ROOTS filenames, which is a #define.

*/

TPM_RC getRootCertificateFilenames(char *rootFilename[],
				   unsigned int *rootFileCount,
				   const char *listFilename,
				   int print)
{
    TPM_RC		rc = 0;
    int			done = 0;
    FILE		*listFile = NULL;		/* closed @1 */

    *rootFileCount = 0;

    if (rc == 0) {
	listFile = fopen(listFilename, "rb");		/* closed @1 */
	if (listFile == NULL) {
	    printf("getRootCertificateFilenames: Error opening list file %s\n",
		   listFilename);  
	    rc = TSS_RC_FILE_OPEN;
	}
    }
    while ((rc == 0) && !done && (*rootFileCount < MAX_ROOTS)) {
	size_t rootFilenameLength;
	if (rc == 0) {
	    rootFilename[*rootFileCount] = malloc(PATH_MAX);
	    if (rootFilename[*rootFileCount] == NULL) {
		printf("getRootCertificateFilenames: Error allocating memory\n");
		rc = TSS_RC_OUT_OF_MEMORY;
	    }
	}
	if (rc == 0) {
	    char *tmpptr = fgets(rootFilename[*rootFileCount], PATH_MAX-1, listFile);
	    if (tmpptr == NULL) {	/* end of file */
		free(rootFilename[*rootFileCount]);	/* free malloced but unused entry */
		done = 1;
	    }
	}
	if ((rc == 0) && !done) {
	    rootFilenameLength = strlen(rootFilename[*rootFileCount]);
	    if (rootFilename[*rootFileCount][rootFilenameLength-1] != '\n') {
		printf("getRootCertificateFilenames: filename %s too long\n",
		       rootFilename[*rootFileCount]);
		rc = TSS_RC_OUT_OF_MEMORY;
		free(rootFilename[*rootFileCount]);	/* free malloced but bad entry */
		done = 1;
	    }
	}
	if ((rc == 0) && !done) {
	    rootFilename[*rootFileCount][rootFilenameLength-1] = '\0';	/* remove newline */
	    if (print) printf("getRootCertificateFilenames: Root file name %u\n%s\n",
			      *rootFileCount, rootFilename[*rootFileCount]);
	    (*rootFileCount)++;
	}
    }
    if (listFile != NULL) {
	fclose(listFile);		/* @1 */
    }
    return rc;
}

#endif

#ifndef TPM_TSS_NOFILE

/* getCaStore() creates an OpenSSL X509_STORE, populated by the root certificates in the
   rootFilename array.  Depending on the vendor, some certificates may be intermediate certificates.
   OpenSSL handles this internally by walking the chain back to the root.

   The caCert array is returned because it must be freed after the caStore is freed

   NOTE:  There is no TPM interaction.
*/ 

TPM_RC getCaStore(X509_STORE **caStore,		/* freed by caller */
		  X509 	*caCert[],		/* freed by caller */
		  const char *rootFilename[],
		  unsigned int rootFileCount)
{
    TPM_RC			rc = 0;
    FILE 			*caCertFile = NULL;		/* closed @1 */
    unsigned int 		i;

    if (rc == 0) {
	*caStore  = X509_STORE_new();
	if (*caStore == NULL) {
	    printf("getCaStore: X509_store_new failed\n");  
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    for (i = 0 ; (i < rootFileCount) && (rc == 0) ; i++) {
	/* read a root certificate from the file */
	caCertFile = fopen(rootFilename[i], "rb");	/* closed @1 */
	if (caCertFile == NULL) {
	    printf("getCaStore: Error opening CA root certificate file %s\n",
		   rootFilename[i]);  
	    rc = TSS_RC_FILE_OPEN;
	}
	/* convert the root certificate from PEM to X509 */
	if (rc == 0) {
	    caCert[i] = PEM_read_X509(caCertFile, NULL, NULL, NULL);	/* freed by caller */
	    if (caCert[i] == NULL) {
		printf("getCaStore: Error reading CA root certificate file %s\n",
		       rootFilename[i]);  
		rc = TSS_RC_FILE_READ;
	    } 
	}
	if ((rc == 0) && tssUtilsVerbose) {
	    X509_NAME *x509Name;
	    char *subject = NULL;
	    x509Name = X509_get_subject_name(caCert[i]);
	    subject = X509_NAME_oneline(x509Name, NULL, 0);
	    printf("getCaStore: subject %u: %s\n", i, subject);
	    OPENSSL_free(subject);
	}

	/* add the CA X509 certificate to the certificate store */
	if (rc == 0) {
	    X509_STORE_add_cert(*caStore, caCert[i]);    
	}
	if (caCertFile != NULL) {
	    fclose(caCertFile);		/* @1 */
	    caCertFile = NULL;
	}
    }
    return rc;
}

#endif

#ifndef TPM_TSS_NOFILE

/* verifyCertificate() verifies a certificate (typically an EK certificate against the root CA
   certificate (typically the TPM vendor CA certificate chain)

   The 'rootFileCount' root certificates are stored in the files whose paths are in the array
   'rootFilename'

*/

TPM_RC verifyCertificate(void *x509Certificate,
			 const char *rootFilename[],
			 unsigned int rootFileCount,
			 int print)
{
    TPM_RC			rc = 0;
    unsigned int		i;
    X509_STORE 			*caStore = NULL;	/* freed @1 */
    X509 			*caCert[MAX_ROOTS];	/* freed @2 */
    X509_STORE_CTX 		*verifyCtx = NULL;	/* freed @3 */

    for (i = 0 ; i < rootFileCount ; i++) {
	caCert[i] = NULL;    				/* for free @2 */
    }
    /* get the root CA certificate chain */
    if (rc == 0) {
	rc = getCaStore(&caStore,			/* freed @1 */
			caCert,				/* freed @2 */
			rootFilename,
			rootFileCount);
    }
    /* create the certificate verify context */
    if (rc == 0) {
	verifyCtx = X509_STORE_CTX_new();		/* freed @3 */
	if (verifyCtx == NULL) {
	    printf("verifyCertificate: X509_STORE_CTX_new failed\n");  
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* add the root certificate store and EK certificate to be verified to the verify context */
    if (rc == 0) {
	int irc = X509_STORE_CTX_init(verifyCtx,
				      caStore,		/* trusted certificates */
				      x509Certificate,	/* end entity certificate */
				      NULL);		/* untrusted (intermediate) certificates */
	if (irc != 1) {
	    printf("verifyCertificate: "
		   "Error in X509_STORE_CTX_init initializing verify context\n");  
	    rc = TSS_RC_RSA_SIGNATURE;
	}	    
    }
    /* walk the certificate chain */
    if (rc == 0) {
	int irc = X509_verify_cert(verifyCtx);
	if (irc != 1) {
	    printf("verifyCertificate: Error in X509_verify_cert verifying certificate\n");  
	    rc = TSS_RC_RSA_SIGNATURE;
	}
	else {
	    if (print) printf("EK certificate verified against the root\n");
	}
    }
    if (caStore != NULL) {
	X509_STORE_free(caStore);	/* @1 */
    }
    for (i = 0 ; i < rootFileCount ; i++) {
	X509_free(caCert[i]);	   	/* @2 */
    }
    if (verifyCtx != NULL) {
	X509_STORE_CTX_free(verifyCtx);	/* @3 */
    }
    return rc;
}

/* verifyKeyUsage() validates the key usage for an EK.

   If the EK has the decrypt attribute set, the keyEncipherment bit MUST be set for an RSA EK
   certificate; the keyAgreement bit MUST be set for an ECC EK certificate.
*/

TPM_RC verifyKeyUsage(X509 *ekX509Certificate,		/* X509 certificate */
		      int pkeyType,			/* RSA or ECC */
		      int print)
{
    TPM_RC		rc = 0;
    ASN1_BIT_STRING 	*keyUsage = NULL;
    uint8_t 		bitmap;
    int 		keyAgreement;		/* boolean flags */
    int 		keyEncipherment;
    
    if (rc == 0) {
	keyUsage = X509_get_ext_d2i(ekX509Certificate, NID_key_usage,	/* freed @1 */
				    NULL, NULL);
	if (keyUsage == NULL) {
	    printf("verifyKeyUsage: Cannot find key usage\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	if (keyUsage->length == 0) {
	    printf("verifyKeyUsage: Key usage length 0 bytes\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	bitmap = keyUsage->data[0];
	keyEncipherment = bitmap & (1<<5);		/* bit 2 little endian */
	keyAgreement = bitmap & (1<<3);			/* bit 4 little endian */
	if (keyEncipherment) {		/* bit 2 little endian */
	    if (print) printf("verifyKeyUsage: Key Encipherment\n");
	}
	if (keyAgreement) {		/* bit 4 little endian */
	    if (print) printf("verifyKeyUsage: Key Agreement\n");
	}
	if (pkeyType == EVP_PKEY_RSA) {
	    if (!keyEncipherment) {
		printf("ERROR: verifyKeyUsage: RSA Key usage %02x not Key Encipherment\n",
		       bitmap);
		rc = TSS_RC_X509_ERROR;
	    }
	}
	else if (pkeyType ==  EVP_PKEY_EC) {
	    /* ECC should be key agreement, but some HW TPMs use key encipherment */
	    if (!keyEncipherment && !keyAgreement) {
		printf("ERROR: verifyKeyUsage: ECC Key usage %02x not "
		       "Key agreement or key encipherment\n",
		       bitmap);
		rc = TSS_RC_X509_ERROR;
	    }
	}
	else {
	    printf("ERROR: verifyKeyUsage: Public key is not RSA or ECC\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (keyUsage != NULL) {
	ASN1_BIT_STRING_free(keyUsage);		/* @1 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOFILE */

#ifdef TPM_TPM20

/* processEKNonce()reads the EK nonce from NV and returns the contents and size */
   
TPM_RC processEKNonce(TSS_CONTEXT *tssContext,
		      unsigned char **nonce, 	/* freed by caller */
		      uint16_t *nonceSize,
		      TPMI_RH_NV_INDEX ekNonceIndex,
		      int print)
{
    TPM_RC			rc = 0;

    if (rc == 0) { 
	rc = getIndexContents(tssContext,
			      nonce,
			      nonceSize,
			      ekNonceIndex);
    }
    /* optional tracing */
    if (rc == 0) {
	if (print) TSS_PrintAll("EK Nonce: ", *nonce, *nonceSize);
    }
    return rc;
}

/* processEKTemplate() reads the EK template from NV and returns the unmarshaled TPMT_PUBLIC */

TPM_RC processEKTemplate(TSS_CONTEXT *tssContext,
			 TPMT_PUBLIC *tpmtPublic,
			 TPMI_RH_NV_INDEX ekTemplateIndex,
			 int print)
{
    TPM_RC			rc = 0;
    uint16_t 			dataSize;
    unsigned char 		*data = NULL; 		/* freed @1 */
    uint32_t 			tmpDataSize;
    unsigned char 		*tmpData = NULL; 

    if (rc == 0) {
	rc = getIndexContents(tssContext,
			      &data,
			      &dataSize,
			      ekTemplateIndex);
    }
    /* unmarshal the data stream */
    if (rc == 0) {
	tmpData = data;		/* temps because unmarshal moves the pointers */
	tmpDataSize = dataSize;
	rc = TSS_TPMT_PUBLIC_Unmarshalu(tpmtPublic, &tmpData, &tmpDataSize, YES);
    }
    /* optional tracing */
    if (rc == 0) {
	if (print) TSS_TPMT_PUBLIC_Print(tpmtPublic, 0);
    }
    free(data);   			/* @1 */
    return rc;
}

/* processEKCertificate() reads the EK certificate from NV and returns an X509 certificate
   structure.  It also extracts and returns the public modulus.

   The return is void because the structure is opaque to the caller.  This accomodates other crypto
   libraries.

   ekCertificate is an X509 structure.
*/
    
TPM_RC processEKCertificate(TSS_CONTEXT *tssContext,
			    void **ekCertificate,	/* freed by caller */
			    uint8_t **modulusBin,	/* freed by caller */
			    int *modulusBytes,
			    TPMI_RH_NV_INDEX ekCertIndex,
			    int print)
{
    TPM_RC			rc = 0;

    /* read the EK X509 certificate from NV and convert the DER (binary) to OpenSSL X509 format */
    if (rc == 0) {
	rc = getIndexX509Certificate(tssContext,
				     ekCertificate,	/* freed by caller */
				     ekCertIndex);
	if (rc != 0) {
	    printf("No EK certificate\n");
	}
    }
    /* extract the public modulus from the X509 structure */
    if (rc == 0) {
	rc = convertCertificatePubKey(modulusBin,	/* freed by caller */
				      modulusBytes,
				      *ekCertificate,
				      ekCertIndex,
				      print);
    }
    return rc;
}

#endif	/* TPM20 */

/* convertX509ToDer() serializes the openSSL X509 structure to a DER certificate

 */

TPM_RC convertX509ToDer(uint32_t *certLength,
			unsigned char **certificate,	/* output, freed by caller */
			X509 *x509Certificate)		/* input */
{
    TPM_RC 		rc = 0;		/* general return code */
    int			irc;

    /* sanity check for memory leak */
    if (rc == 0) {
	if (*certificate != NULL) {
	    printf("ERROR: convertX509ToDer: Error, certificate not NULL at entry\n");
	    rc = TSS_RC_X509_ERROR;
	}	
    }
    if (rc == 0) {
	irc = i2d_X509(x509Certificate, NULL);
	if (irc < 0) {
	    printf("ERROR: convertX509ToDer: Error in certificate serialization i2d_X509()\n");
	    rc = TSS_RC_X509_ERROR;
	}
	else {
	    *certLength = irc; 
	}
    }
    if (rc == 0) {
	rc = TSS_Malloc(certificate, *certLength);
    }
    /* convert the X509 structure to binary (internal to DER format) */
    if (rc == 0) {
	unsigned char *tmpptr = *certificate;
	if (tssUtilsVerbose) printf("convertX509ToDer: Serializing certificate\n");
	irc = i2d_X509(x509Certificate, &tmpptr);
	if (irc < 0) {
	    printf("ERROR: convertX509ToDer: Error in certificate serialization i2d_X509()\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    return rc;
}

#ifndef TPM_TSS_NOECC

/* convertX509ToEc extracts the public key from an X509 structure to an openssl EC_KEY structure

 */

TPM_RC convertX509ToEc(EC_KEY **ecKey,	/* freed by caller */
		       X509 *x509)
{
    TPM_RC rc = 0;
    EVP_PKEY *evpPkey = NULL;

    if (tssUtilsVerbose) printf("convertX509ToEc: Entry\n\n");
    if (rc == 0) {
	evpPkey = X509_get_pubkey(x509);	/* freed @1 */
	if (evpPkey == NULL) {
	    printf("ERROR: convertX509ToEc: X509_get_pubkey failed\n");  
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (rc == 0) {
	*ecKey = EVP_PKEY_get1_EC_KEY(evpPkey);
	if (*ecKey == NULL) {
	    printf("ERROR: convertX509ToEc: EVP_PKEY_get1_EC_KEY failed\n");  
	    rc = TSS_RC_EC_KEY_CONVERT;
	}
    }
    if (evpPkey != NULL) {
	EVP_PKEY_free(evpPkey);		/* @1 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

/* convertCertificatePubKey() returns the public modulus from an openssl X509 certificate
   structure.  ekCertIndex determines whether the algorithm is RSA or ECC.

   If print is true, prints the EK certificate

   The return is void because the structure is opaque to the caller.  This accomodates other crypto
   libraries.

   ekCertificate is an X509 structure.
*/

TPM_RC convertCertificatePubKey(uint8_t **modulusBin,	/* freed by caller */
				int *modulusBytes,
				void *ekCertificate,
				TPMI_RH_NV_INDEX ekCertIndex,
				int print)
{
    TPM_RC			rc = 0;
    EVP_PKEY 			*pkey = NULL;
    int 			pkeyType;	/* RSA or EC */
    
    /* use openssl to print the X509 certificate */
#ifndef TPM_TSS_NOFILE		/* stdout is a file descriptor */
    if (rc == 0) {
	if (print) X509_print_fp(stdout, ekCertificate);
    }
#endif
    /* extract the public key */
    if (rc == 0) {
	pkey = X509_get_pubkey(ekCertificate);		/* freed @2 */
	if (pkey == NULL) {
#ifndef TPM_TSS_NORSA
	    if (tssUtilsVerbose) printf("convertCertificatePubKey: "
				"Could not extract public key from X509 certificate, "
				"may be TPM 1.2\n");
	    /* if the conversion failed, this may be a TPM 1.2 certificate with a non-standard TCG
	       algorithm.  Try a different method to get the public modulus. */
	    rc = convertCertificatePubKey12(modulusBin,	/* freed by caller */
					    modulusBytes,
					    ekCertificate);
#else	    
	    printf("convertCertificatePubKey12: Could not extract X509_PUBKEY public key "
		   "from X509 certificate\n");
	    rc =  TPM_RC_INTEGRITY;
#endif /* TPM_TSS_NORSA */

	}
	else {
	    if (rc == 0) {
		pkeyType = getRsaPubkeyAlgorithm(pkey);
	    }
	    switch (ekCertIndex) {
#ifndef TPM_TSS_NORSA
	      case EK_CERT_RSA_INDEX:
		  {
		      RSA *rsaKey = NULL;
		      /* check that the public key algorithm matches the ekCertIndex algorithm */
		      if (rc == 0) {
			  if (pkeyType != EVP_PKEY_RSA) {
			      printf("convertCertificatePubKey: "
				     "Public key from X509 certificate is not RSA\n");
			      rc = TPM_RC_INTEGRITY;
			  }
		      }
		      /* convert the public key to OpenSSL structure */
		      if (rc == 0) {
			  rsaKey = EVP_PKEY_get1_RSA(pkey);		/* freed @3 */
			  if (rsaKey == NULL) {
			      printf("convertCertificatePubKey: Could not extract RSA public key "
				     "from X509 certificate\n");
			      rc = TPM_RC_INTEGRITY;
			  }
		      }
		      if (rc == 0) {
			  rc = convertRsaKeyToPublicKeyBin(modulusBytes,
							   modulusBin,	/* freed by caller */
							   rsaKey);
		      }
		      if (rc == 0) {
			  if (print) TSS_PrintAll("Certificate public key:",
						  *modulusBin, *modulusBytes);
		      }    
		      RSA_free(rsaKey);   		/* @3 */
		  }
		  break;
#endif /* TPM_TSS_NORSA */
#ifndef TPM_TSS_NOECC
	      case EK_CERT_EC_INDEX:
		  {
		      EC_KEY *ecKey = NULL;
		      /* check that the public key algorithm matches the ekCertIndex algorithm */
		      if (rc == 0) {
			  if (pkeyType != EVP_PKEY_EC) {
			      printf("convertCertificatePubKey: "
				     "Public key from X509 certificate is not EC\n");
			      rc = TPM_RC_INTEGRITY;
			  }
		      }
		      /* convert the public key to OpenSSL structure */
		      if (rc == 0) {
			  ecKey = EVP_PKEY_get1_EC_KEY(pkey);		/* freed @3 */
			  if (ecKey == NULL) {
			      printf("convertCertificatePubKey: Could not extract EC public key "
				     "from X509 certificate\n");
			      rc = TPM_RC_INTEGRITY;
			  }
		      }
		      if (rc == 0) {
			  rc = convertEcKeyToPublicKeyBin(modulusBytes,
							  modulusBin,	/* freed by caller */
							  ecKey);
		      }
		      if (rc == 0) {
			  if (print) TSS_PrintAll("Certificate public key:",
						  *modulusBin, *modulusBytes);
		      }
		      EC_KEY_free(ecKey);   		/* @3 */
		  }
		  break;
#endif	/* TPM_TSS_NOECC */
	      default:
		printf("convertCertificatePubKey: "
		       "ekCertIndex %08x (asymmetric algorithm) not supported\n", ekCertIndex);
		rc = TPM_RC_INTEGRITY;
		break;
	    }
	}
	EVP_PKEY_free(pkey);   		/* @2 */
    }
    return rc;
}

#ifndef TPM_TSS_NORSA

TPM_RC convertCertificatePubKey12(uint8_t **modulusBin,	/* freed by caller */
				  int *modulusBytes,
				  X509 *ekCertificate)
{
    TPM_RC		rc = 0;
    int			irc;
    X509_PUBKEY 	*pubkey = NULL;
    ASN1_OBJECT 	*ppkalg = NULL;			/* ignore OID */
    const unsigned char *pk = NULL;			/* do not free */
    int 		ppklen;
    X509_ALGOR 		*palg = NULL;			/* algorithm identifier for public key */
    RSA 		*rsaKey = NULL;

    /* get internal pointer to the public key in the certificate */
    if (rc == 0) {
	pubkey = X509_get_X509_PUBKEY(ekCertificate);	/* do not free */
	if (pubkey == NULL) {
	    printf("convertCertificatePubKey12: Could not extract X509_PUBKEY public key "
		   "from X509 certificate\n");
	    rc = TPM_RC_INTEGRITY;
	}
    }
    /* get the public key parameters, as a byte stream pk */
    if (rc == 0) {
	irc = X509_PUBKEY_get0_param(&ppkalg,
				     &pk, &ppklen,	/* internal, don't free */
				     &palg, pubkey);
	if (irc != 1) {
	    printf("convertCertificatePubKey12: Could not extract public key parameters "
		   "from X509 certificate\n");
	    rc = TPM_RC_INTEGRITY;
	}
    }
    if (rc == 0) {
	const unsigned char *tmppk = pk;	/* because d2i moves the pointer */
	rsaKey = d2i_RSAPublicKey(NULL, &tmppk, ppklen);	/* freed @1 */
	if (rsaKey == NULL) {
	    printf("convertCertificatePubKey12: Could not convert to RSA structure\n");
	    rc = TPM_RC_INTEGRITY;
	}
    }
    if (rc == 0) {
	rc = convertRsaKeyToPublicKeyBin(modulusBytes,
					 modulusBin,	/* freed by caller */
					 rsaKey);
	TSS_PrintAll("convertCertificatePubKey12", *modulusBin, *modulusBytes);
    }
    if (rsaKey != NULL) {
	RSA_free(rsaKey);		/* @1 */
    }
    return rc;
}

#endif /* TPM_TSS_NORSA */

#ifndef TPM_TSS_NOFILE		/* stdout is a file descriptor */

TPM_RC convertX509PemToDer(uint32_t *certLength,
			    unsigned char **certificate,	/* output, freed by caller */
			    const char *pemCertificateFilename)
{
    TPM_RC rc = 0;
    X509 	*x509Certificate = NULL;

    if (rc == 0) {
	rc = convertPemToX509(&x509Certificate,		/* freed @1 */
			      pemCertificateFilename);
    }
    if (rc == 0) {
	rc = convertX509ToDer(certLength,
			      certificate,		/* output, freed by caller */
			      x509Certificate);		/* input */
    }
    if (x509Certificate != NULL) {
	X509_free(x509Certificate);	/* @1 */
    }
    return rc;
}

#endif

#ifndef TPM_TSS_NOFILE

/* convertPemToX509() reads a PEM file and converts it to an OpenSSL X509 structure

 */

uint32_t convertPemToX509(X509 **x509,				/* freed by caller */
			  const char *pemCertificateFilename)
{
    uint32_t 	rc = 0;
    int		irc;
    FILE 	*pemCertificateFile = NULL;

    if (tssUtilsVerbose) printf("convertPemToX509: Reading PEM certificate file %s\n",
			pemCertificateFilename);
    if (rc == 0) {
	pemCertificateFile = fopen(pemCertificateFilename, "r");
	if (pemCertificateFile == NULL) {
	    printf("convertPemToX509: Cannot open PEM file %s\n", pemCertificateFilename);
	    rc = TSS_RC_FILE_OPEN;
	}
    }
    /* convert the platform certificate from PEM to DER */
    if (rc == 0) {
	*x509 = PEM_read_X509(pemCertificateFile , NULL, NULL, NULL);	/* freed @1 */
	if (*x509 == NULL) {
	    printf("convertPemToX509: Cannot parse PEM certificate file %s\n",
		   pemCertificateFilename);
	    rc = TSS_RC_FILE_READ;
	}
    }
    /* for debug */
    if ((rc == 0) && tssUtilsVerbose) {
	irc = X509_print_fp(stdout, *x509);
	if (irc != 1) {
	    printf("ERROR: convertPemToX509: Error in certificate print X509_print_fp()\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (pemCertificateFile != NULL) {
	fclose(pemCertificateFile);		/* @1 */
    }
    return rc;
}

#endif

/* convertDerToX509() converts a DER stream to an OpenSSL X509 structure

   The return is void because the structure is opaque to the caller.  This accomodates other crypto
   libraries.
*/

uint32_t convertDerToX509(void **x509Certificate,			/* freed by caller */
			  uint16_t readLength,
			  const unsigned char *readBuffer)
{
    uint32_t 	rc = 0;
    *x509Certificate = d2i_X509(NULL,					/* freed by caller */
				&readBuffer, readLength);
    if (*x509Certificate == NULL) {
	printf("convertDerToX509: Could not parse X509 certificate\n");
	rc = TSS_RC_X509_ERROR;
    }
    return rc;
}

/* x509FreeStructure() is the library specific free structure.

   The parameter is void because the structure is opaque to the caller.  This accomodates other
   crypto libraries.
*/

void x509FreeStructure(void *x509)
{
    if (x509 != NULL) {
	X509_free(x509);
    }
    return;
}

/* x509PrintStructure() prints the structure to stdout

   The parameter is void because the structure is opaque to the caller.  This accomodates other
   crypto libraries.
*/

void x509PrintStructure(void *x509)
{
    X509_print_fp(stdout, x509);
    return;
}

/* convertPemMemToX509() converts an in-memory PEM format X509 certificate to an openssl X509
   structure.

*/

uint32_t convertPemMemToX509(X509 **x509,		/* freed by caller */
			     const char *pemCertificate)
{
    uint32_t rc = 0;
    BIO *bio = NULL;
    int pemLength;
    int writeLen = 0;

    if (tssUtilsVerbose) printf("convertPemMemToX509: pemCertificate\n%s\n", pemCertificate);  
    /* create a BIO that uses an in-memory buffer */
    if (rc == 0) {
	bio = BIO_new(BIO_s_mem());		/* freed @1 */
	if (bio == NULL) {
	    printf("convertPemMemToX509: BIO_new failed\n");  
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* write the PEM from memory to BIO */
    if (rc == 0) {
	pemLength = strlen(pemCertificate);
	writeLen = BIO_write(bio, pemCertificate, pemLength);
	if (writeLen != pemLength) {
	    printf("convertPemMemToX509: BIO_write failed\n");  
	    rc = TPM_RC_INTEGRITY;
	}
    }
    /* convert the properly formatted PEM to X509 structure */
    if (rc == 0) {
	*x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (*x509 == NULL) {
	    printf("convertPemMemToX509: PEM_read_bio_X509 failed\n");
	    rc = TPM_RC_INTEGRITY;
	}
    }
    /* for debug */
#ifndef TPM_TSS_NOFILE		/* stdout is a file descriptor */
    if (rc == 0) {
	if (tssUtilsVerbose) X509_print_fp(stdout, *x509);
    }
#endif
    if (bio != NULL) {
	BIO_free(bio);			/* @1 */
    }
    return rc;
}

#ifndef TPM_TSS_NOFILE

/* convertX509ToPem() writes an OpenSSL X509 structure to a PEM format file

   The return is void because the structure is opaque to the caller.  This accomodates other crypto
   libraries.
 
   For OpenSSL, the type is X509*
*/

TPM_RC convertX509ToPem(const char *pemFilename,
			void *x509)
{
    TPM_RC 	rc = 0;
    int		irc;
    FILE 	*pemFile = NULL;

    if (tssUtilsVerbose) printf("convertX509ToPem: Writing PEM certificate file %s\n",
			pemFilename);
    if (rc == 0) {
	pemFile = fopen(pemFilename, "w");	/* close @1 */
	if (pemFile == NULL) {
	    printf("convertX509ToPem: Cannot open PEM file %s\n", pemFilename);
	    rc = TSS_RC_FILE_OPEN;
	}
    }
    if (rc == 0) {
	irc = PEM_write_X509(pemFile, x509);
	if (irc == 0) {
	    printf("convertX509ToPem: Unable to write PEM file %s\n", pemFilename);
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    if (pemFile != NULL) {
	fclose(pemFile);	/* @1 */
    }
    return rc;
}

#endif

/* convertX509ToPemMem() converts an OpenSSL X509 structure to PEM format in memory */

TPM_RC convertX509ToPemMem(char **pemString,	/* freed by caller */
			   X509 *x509)
{
    TPM_RC 		rc = 0;		/* general return code */
    int			irc;
    char 		*data = NULL;
    long 		length;
    
    /* create a BIO that uses an in-memory buffer */
    BIO *bio = NULL;
    if (rc == 0) {
	bio = BIO_new(BIO_s_mem());		/* freed @1 */
	if (bio == NULL) {
	    printf("convertX509ToPemMem: BIO_new failed\n");  
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* convert X509 to PEM and write the PEM to memory */
    if (rc == 0) {
	irc = PEM_write_bio_X509(bio, x509);
	if (irc != 1) {
	    printf("convertX509ToPemMem: PEM_write_bio_X509 failed\n");
	    rc = TSS_RC_FILE_WRITE;
	}
    }
    if (rc == 0) {
	length = BIO_get_mem_data(bio, &data);
	*pemString = malloc(length+1);
	if (*pemString == NULL) {
	    printf("ERROR: convertX509ToPemMem: Cannot malloc %lu\n", length);  
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
	else {
	    (*pemString)[length] = '\0';
	}
    }
    if (rc == 0) {
	irc = BIO_read(bio, *pemString, length);
 	if (irc <= 0) {
	    printf("ERROR: convertX509ToPemMem: BIO_read failed\n");
	    rc = TSS_RC_FILE_READ;
	}
    }
    if (bio != NULL) {
	BIO_free(bio);			/* @1 */
    }
    return rc;
}

/* convertX509ToString() converts an OpenSSL X509 structure to a human readable string */

TPM_RC convertX509ToString(char **x509String,	/* freed by caller */
			     X509 *x509)
{
    TPM_RC 	rc = 0;
    int		irc;
    char 	*data = NULL;
    long 	length;

    /* create a BIO that uses an in-memory buffer */
    BIO *bio = NULL;
    if (rc == 0) {
	bio = BIO_new(BIO_s_mem());		/* freed @1 */
	if (bio == NULL) {
	    printf("convertX509ToString: BIO_new failed\n");  
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* write the string to memory */
    if (rc == 0) {
	irc = X509_print(bio, x509);
	if (irc != 1) {
	    printf("convertX509ToString X509_print failed\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	length = BIO_get_mem_data(bio, &data);
	*x509String = malloc(length+1);
	if (*x509String == NULL) {
	    printf("convertX509ToString: Cannot malloc %lu\n", length);  
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
	else {
	    (*x509String)[length] = '\0';
	}
    }
    if (rc == 0) {
	irc = BIO_read(bio, *x509String, length);
 	if (irc <= 0) {
	    printf("convertX509ToString BIO_read failed\n");
	    rc = TSS_RC_FILE_READ;
	}
    }
    if (bio != NULL) {
	BIO_free(bio);			/* @1 */
    }
    return rc;
}

/*
  Certificate Creation
*/

/* These are the names inserted into the certificates.  If changed, the entries also change.  At run
   time, the mapping from key to nid is done once and used repeatedly.  */
    
CertificateName certificateName[] = {
    { "countryName",			NID_undef},	/* 0 */
    { "stateOrProvinceName",		NID_undef},	/* 1 */
    { "localityName",			NID_undef},	/* 2 */
    { "organizationName",		NID_undef},	/* 3 */
    { "organizationalUnitName",		NID_undef},	/* 4 */
    { "commonName",			NID_undef},	/* 5 */
    { "emailAddress",			NID_undef},	/* 6 */
};

TPM_RC calculateNid(void)
{
    TPM_RC rc = 0;
    size_t 	i;

    for (i=0 ; (i < sizeof(certificateName)/sizeof(CertificateName)) && (rc == 0) ; i++) {
	certificateName[i].nid = OBJ_txt2nid(certificateName[i].key);	/* look up the NID for the
									   field */
	if (certificateName[i].nid == NID_undef) {
	    printf("calculateNid: Error finding nid for %s\n", certificateName[i].key);
	    rc = TSS_RC_X509_ERROR;
	}
    }
    return rc;
}

/* createCertificate() constructs a certificate from the issuer and subject.  The public key to be
   certified is tpmtPublic.

   It signs the certificate using the CA key in caKeyFileName protected by the password
   caKeyPassword.  The CA signing key algorithm caKeyAlg is RSA or ECC.

   The certificate is returned as a DER encoded array 'certificate', a PEM string, and a formatted
   string.

*/

TPM_RC createCertificate(char **x509CertString,		/* freed by caller */
			 char **pemCertString,		/* freed by caller */
			 uint32_t *certLength,		/* output, certificate length */
			 unsigned char **certificate,	/* output, freed by caller */
			 TPMT_PUBLIC *tpmtPublic,	/* key to be certified */	
			 const char *caKeyFileName,
			 size_t issuerEntriesSize,
			 char **issuerEntries,
			 size_t subjectEntriesSize,
			 char **subjectEntries,
			 const char *caKeyPassword)
{
    TPM_RC 		rc = 0;
    X509 		*x509Certificate = NULL;
    uint16_t 		publicKeyLength;
    const unsigned char *publicKey = NULL;
    
    /* allocate memory for the X509 structure */
    if (rc == 0) {
	x509Certificate = X509_new();		/* freed @2 */
	if (x509Certificate == NULL) {
	    printf("createCertificate: Error in X509_new\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* hash unique field to create serial number */
    if (rc == 0) {
	if (tpmtPublic->type == TPM_ALG_RSA) {
	    publicKeyLength = tpmtPublic->unique.rsa.t.size;
	    publicKey = tpmtPublic->unique.rsa.t.buffer;
	}
	else if (tpmtPublic->type == TPM_ALG_ECC) {
	    publicKeyLength = tpmtPublic->unique.ecc.x.t.size;
	    publicKey = tpmtPublic->unique.ecc.x.t.buffer;
	}
	else {
	    printf("createCertificate: public key algorithm %04x not supported\n",
		   tpmtPublic->type);
	    rc = TSS_RC_BAD_SIGNATURE_ALGORITHM;
	}
    }    
    /* fill in basic X509 information - version, serial, validity, issuer, subject */
    if (rc == 0) {
	rc = startCertificate(x509Certificate,
			      publicKeyLength, publicKey,
			      issuerEntriesSize, issuerEntries,
			      subjectEntriesSize, subjectEntries);
    }
    /* If the EK has the decrypt attribute set, the keyEncipherment bit MUST be set for an RSA EK
       certificate; the keyAgreement bit MUST be set for an ECC EK certificate. */
    if (rc == 0) {
	if (tpmtPublic->type == TPM_ALG_RSA) {
	    rc = addCertExtension(x509Certificate, NID_key_usage, "critical,keyEncipherment");
	}
	if (tpmtPublic->type == TPM_ALG_ECC) {
	    rc = addCertExtension(x509Certificate, NID_key_usage, "critical,keyAgreement");
	}
    }
    /* add the TPM public key to be certified */
    if (rc == 0) {
	switch (tpmtPublic->type) {
#ifndef TPM_TSS_NORSA
	  case TPM_ALG_RSA:
	    rc = addCertKeyRsa(x509Certificate, &tpmtPublic->unique.rsa);
	    break;
#endif /* TPM_TSS_NORSA */
#ifndef TPM_TSS_NOECC
	  case TPM_ALG_ECC:
	    rc = addCertKeyEcc(x509Certificate, &tpmtPublic->unique.ecc);
	    break;
#endif	/* TPM_TSS_NOECC */
	  default:
	    printf("createCertificate: public key algorithm %04x not supported\n",
		   tpmtPublic->type);
	    rc = TSS_RC_BAD_SIGNATURE_ALGORITHM;
	}
    }
    /* sign the certificate with the root CA key */
    if (rc == 0) {
	rc = addCertSignatureRoot(x509Certificate, caKeyFileName, caKeyPassword);
    }
    if (rc == 0) {
	rc = convertX509ToDer(certLength, certificate,	/* freed by caller */
			      x509Certificate);		/* in */
    }
    if (rc == 0) {
	rc = convertX509ToPemMem(pemCertString,		/* freed by caller */
				 x509Certificate);
    }
    if (rc == 0) {
	rc = convertX509ToString(x509CertString,	/* freed by caller */
				 x509Certificate);
    }
    X509_free(x509Certificate);		/* @2 */
    return rc;
}

/* Certificate duration period is hard coded to 20 years */

#define CERT_DURATION (60 * 60 * 24 * ((365 * 20) + 2))		/* +2 for leap years */

/* startCertificate() fills in basic X509 information, such as:
   version
   serial number
   issuer
   validity
   subject
*/

TPM_RC startCertificate(X509 *x509Certificate,	/* X509 certificate to be generated */
			uint16_t keyLength,
			const unsigned char *keyBuffer,	/* key to be certified */
			size_t issuerEntriesSize,
			char **issuerEntries,		/* certificate issuer */
			size_t subjectEntriesSize,
			char **subjectEntries)		/* certificate subject */
{
    TPM_RC 		rc = 0;			/* general return code */
    int			irc;			/* integer return code */
    ASN1_TIME 		*arc;			/* return code */
    ASN1_INTEGER 	*x509Serial;		/* certificate serial number in ASN1 */
    BIGNUM 		*x509SerialBN;		/* certificate serial number as a BIGNUM */
    unsigned char 	x509Serialbin[SHA1_DIGEST_SIZE]; /* certificate serial number in binary */
    X509_NAME 		*x509IssuerName;	/* composite issuer name, key/value pairs */
    X509_NAME 		*x509SubjectName;	/* composite subject name, key/value pairs */

    x509IssuerName = NULL;	/* freed @1 */
    x509SubjectName = NULL;	/* freed @2 */
    x509SerialBN = NULL;	/* freed @3 */ 

    /* add certificate version X509 v3 */
    if (rc == 0) {
	irc = X509_set_version(x509Certificate, 2L);	/* value 2 == v3 */
	if (irc != 1) {
	    printf("startCertificate: Error in X509_set_version\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /*
      add certificate serial number
    */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("startCertificate: Adding certificate serial number\n");
	/* to create a unique serial number, hash the key to be certified */
	SHA1(keyBuffer, keyLength, x509Serialbin);
	/* convert the SHA1 digest to a BIGNUM */
	x509SerialBN = BN_bin2bn(x509Serialbin, SHA1_DIGEST_SIZE, x509SerialBN);
	if (x509SerialBN == NULL) {
	    printf("startCertificate: Error in serial number BN_bin2bn\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	/* get the serial number structure member, can't fail */
	x509Serial = X509_get_serialNumber(x509Certificate);
	/* convert the BIGNUM to ASN1 and add to X509 certificate */
	x509Serial = BN_to_ASN1_INTEGER(x509SerialBN, x509Serial);
	if (x509Serial == NULL) {
	    printf("startCertificate: Error setting certificate serial number\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* add issuer */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("startCertificate: Adding certificate issuer\n");
	rc = createX509Name(&x509IssuerName,
			    issuerEntriesSize,
			    issuerEntries);
    }
    if (rc == 0) {
	irc = X509_set_issuer_name(x509Certificate, x509IssuerName);
	if (irc != 1) {
	    printf("startCertificate: Error setting certificate issuer\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* add validity */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("startCertificate: Adding certificate validity\n");
    }
    if (rc == 0) {
	/* can't fail, just returns a structure member */
	ASN1_TIME *notBefore = X509_get_notBefore(x509Certificate);
	arc = X509_gmtime_adj(notBefore ,0L);			/* set to today */
	if (arc == NULL) {
	    printf("startCertificate: Error setting notBefore time\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	/* can't fail, just returns a structure member */
	ASN1_TIME *notAfter = X509_get_notAfter(x509Certificate);
	arc = X509_gmtime_adj(notAfter, CERT_DURATION);		/* set to duration */
	if (arc == NULL) {
	    printf("startCertificate: Error setting notAfter time\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* add subject */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("startCertificate: Adding certificate subject\n");
	rc = createX509Name(&x509SubjectName,
			    subjectEntriesSize,
			    subjectEntries);
    }
    if (rc == 0) {
	irc = X509_set_subject_name(x509Certificate, x509SubjectName);
	if (irc != 1) {
	    printf("startCertificate: Error setting certificate subject\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* cleanup */
    X509_NAME_free(x509IssuerName);		/* @1 */
    X509_NAME_free(x509SubjectName);		/* @2 */
    BN_free(x509SerialBN);			/* @3 */
    return rc;
}

/* createX509Name() create an X509 name (issuer or subject) from a pointer to issuer or subject
   entries

*/

TPM_RC createX509Name(X509_NAME **x509Name,
		      size_t entriesSize,
		      char **entries)
{
    TPM_RC 		rc = 0;		/* general return code */
    int			irc;		/* integer return code */
    size_t  		i;
    X509_NAME_ENTRY 	*nameEntry;		/* single field of the name */

    nameEntry = NULL;

    /* Precalculate the openssl nids, into global table */
    if (rc == 0) {
	rc = calculateNid();
    }
    if (rc == 0) {
	*x509Name = X509_NAME_new();
	if (*x509Name == NULL) {
	    printf("createX509Name: Error in X509_NAME_new()\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    for (i=0 ; (i < entriesSize) && (rc == 0) ; i++) {
	if ((rc == 0) && (entries[i] != NULL)) {
	    nameEntry =
		X509_NAME_ENTRY_create_by_NID(NULL,		/* caller creates object */
					      certificateName[i].nid,
					      MBSTRING_ASC,	/* character encoding */
					      (unsigned char *)entries[i],	/* to add */
					      -1);		/* length, -1 is C string */

	    if (nameEntry == NULL) {
		printf("createX509Name: Error creating entry for %s\n",
		       certificateName[i].key);
		rc = TSS_RC_X509_ERROR;
	    }
	}
	if ((rc == 0) && (entries[i] != NULL)) {
	    irc = X509_NAME_add_entry(*x509Name,	/* add to issuer */
				      nameEntry,	/* add the entry */
				      -1,		/* location - append */	
				      0);		/* set - not multivalued */
	    if (irc != 1) {
		printf("createX509Name: Error adding entry for %s\n",
		       certificateName[i].key);
		rc = TSS_RC_X509_ERROR;
	    }
	}
	X509_NAME_ENTRY_free(nameEntry);	/* callee checks for NULL */
	nameEntry = NULL;
    }
    return rc;
}

/* addCertExtension() adds the extension type 'nid' to the X509 certificate

 */ 

TPM_RC addCertExtension(X509 *x509Certificate, int nid, const char *value)
{
    TPM_RC 		rc = 0;
    X509_EXTENSION 	*extension = NULL;	/* freed @1 */

    if (rc == 0) {
#if OPENSSL_VERSION_NUMBER < 0x10100000
	/* the cast is required for the older openssl 1.0 API */
	extension = X509V3_EXT_conf_nid(NULL, NULL,	/* freed @1 */
					nid, (char *)value);
#else
	extension = X509V3_EXT_conf_nid(NULL, NULL,	/* freed @1 */
					nid, value);
#endif
	if (extension == NULL) {
	    printf("addCertExtension: Error creating nid %i extension %s\n",
		   nid, value);
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	int irc = X509_add_ext(x509Certificate,		/* the certificate */
			       extension,		/* the extension to add */
			       -1);			/* location - append */
	if (irc != 1) {
	    printf("addCertExtension: Error adding nid %i extension %s\n",
		   nid, value);
	}
    }
    if (extension != NULL) {
	X509_EXTENSION_free(extension);		/* @1 */
    }
    return rc;
}
 
#ifndef TPM_TSS_NORSA

/* addCertKeyRsa() adds the TPM RSA public key (the key to be certified) to the openssl X509
   certificate

*/

TPM_RC addCertKeyRsa(X509 *x509Certificate,
		     const TPM2B_PUBLIC_KEY_RSA *tpm2bRsa)	/* key to be certified */
{
    TPM_RC 		rc = 0;		/* general return code */
    int			irc;		/* integer return code */
    EVP_PKEY 		*evpPubkey = NULL;	/* EVP format public key to be certified */

    if (tssUtilsVerbose) printf("addCertKeyRsa: add public key to certificate\n");
    /* convert from TPM key data format to openSSL RSA type */
    if (rc == 0) {
	rc = convertRsaPublicToEvpPubKey(&evpPubkey,	/* freed @1 */
					 tpm2bRsa);
    }
    /* add the public key to the certificate */
    if (rc == 0) {
	irc = X509_set_pubkey(x509Certificate, evpPubkey);
	if (irc != 1) {
	    printf("addCertKeyRsa: Error adding public key to certificate\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* cleanup */
    if (evpPubkey != NULL) {
	EVP_PKEY_free(evpPubkey);	/* @1 */
    }
    return rc;
}

#endif /* TPM_TSS_NORSA */

#ifndef TPM_TSS_NOECC

/* addCertKeyEcc() adds the TPM ECC public key (the key to be certified) to the openssl X509
   certificate

*/

TPM_RC addCertKeyEcc(X509 *x509Certificate,
		     const TPMS_ECC_POINT *tpmsEccPoint)
{
    TPM_RC 		rc = 0;			/* general return code */
    int			irc;
    EVP_PKEY 		*evpPubkey = NULL;	/* EVP format public key to be certified */

    /* convert EC TPMS_ECC_POINT to an EVP_PKEY */
    if (rc == 0) {
	rc = convertEcPublicToEvpPubKey(&evpPubkey,		/* freed @1 */
					tpmsEccPoint);
    }
    /* add the public key to the certificate */
    if (rc == 0) {
	irc = X509_set_pubkey(x509Certificate, evpPubkey);
	if (irc != 1) {
	    printf("addCertKeyEcc: Error adding public key to certificate\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* cleanup */
    if (evpPubkey != NULL) {
	EVP_PKEY_free(evpPubkey);	/* @1 */
    }
    return rc;
}

#endif	/* TPM_TSS_NOECC */

/* addCertSignatureRoot() uses the openSSL root key to sign the X509 certificate.

   As a sanity check, it verifies the certificate.
*/

TPM_RC addCertSignatureRoot(X509 *x509Certificate,	/* certificate to be signed */
			    const char *caKeyFileName,	/* openSSL root CA key password */
			    const char *caKeyPassword)
{
    TPM_RC 		rc = 0;		/* general return code */
    int			irc;		/* integer return code */
    FILE 		*fp = NULL;
    /* signing key */
    const EVP_MD	*digest = NULL;		/* signature digest algorithm */
    EVP_PKEY 		*evpSignkey;		/* EVP format */

    evpSignkey = NULL;		/* freed @1 */

    /* open the CA signing key file */
    if (rc == 0) {
	fp = fopen(caKeyFileName,"r");
	if (fp == NULL) {
	    printf("addCertSignatureRoot: Error, Cannot open %s\n", caKeyFileName);
	    rc = TSS_RC_FILE_OPEN;
	}
    }
    /* convert the CA signing key from PEM to EVP_PKEY format */
    if (rc == 0) {
	evpSignkey = PEM_read_PrivateKey(fp, NULL, NULL, (void *)caKeyPassword);	
	if (evpSignkey == NULL) {
	    printf("addCertSignatureRoot: Error calling PEM_read_PrivateKey() from %s\n",
		   caKeyFileName);
	    rc = TSS_RC_FILE_READ;
	}
    }
    /* close the CA signing key file */
    if (fp != NULL) { 
	fclose(fp);
    }
    /* set the certificate signature digest algorithm */
    if (rc == 0) {
	digest = EVP_sha256();	/* no error return */
    }
    /* sign the certificate with the root CA signing key */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("addCertSignatureRoot: Signing the certificate\n");
	irc = X509_sign(x509Certificate, evpSignkey, digest);
	if (irc == 0) {	/* returns signature size, 0 on error */
	    printf("addCertSignature: Error signing certificate\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* verify the signature */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("addCertSignatureRoot: Verifying the certificate\n");
	irc = X509_verify(x509Certificate, evpSignkey);
	if (irc != 1) {
	    printf("addCertSignatureRoot: Error verifying certificate\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* cleanup */
    if (evpSignkey != NULL) {
	EVP_PKEY_free(evpSignkey);	/* @1 */
    }
    return rc;
}

#ifdef TPM_TPM20

/* processRoot() validates the certificate at ekCertIndex against the root CA certificates at
   rootFilename.
 */

#ifndef TPM_TSS_NOFILE

TPM_RC processRoot(TSS_CONTEXT *tssContext,
		   TPMI_RH_NV_INDEX ekCertIndex,
		   const char *rootFilename[],
		   unsigned int rootFileCount,
		   int print)
{
    TPM_RC	rc = 0;
    void	*ekCertificate = NULL;		/* freed @1 */

    /* read the EK X509 certificate from NV */
    if (rc == 0) {
	rc = getIndexX509Certificate(tssContext,
				     &ekCertificate,	/* freed @1 */
				     ekCertIndex);
	if (rc != 0) {
	    printf("processRoot: No EK certificate\n");  
	}
    }
    if (rc == 0) {
	rc = verifyCertificate(ekCertificate,
			       rootFilename,
			       rootFileCount,
			       print);
	if (rc != 0) {
	    printf("processRoot: EK certificate did not verify\n");
	}
    }
    if (ekCertificate != NULL) {
	X509_free(ekCertificate);   	/* @1 */
    }
    return rc;
}

#endif

/* processCreatePrimary() combines the EK nonce and EK template from NV to form the
   createprimary input.  It creates the primary key.

   ekCertIndex determines whether an RSA or ECC key is created.
   
   If nonce is NULL, the default IWG templates are used.  If nonce is non-NULL, the nonce and
   tpmtPublicIn are used.

   After returning the TPMT_PUBLIC, flushes the primary key unless noFlush is TRUE.  If noFlush is
   FALSE, returns the loaded handle, else returns TPM_RH_NULL.
*/

TPM_RC processCreatePrimary(TSS_CONTEXT *tssContext,
			    TPM_HANDLE *keyHandle,		/* primary key handle */
			    TPMI_RH_NV_INDEX ekCertIndex,
			    unsigned char *nonce,
			    uint16_t nonceSize,
			    TPMT_PUBLIC *tpmtPublicIn,		/* template */
			    TPMT_PUBLIC *tpmtPublicOut,		/* primary key */
			    unsigned int noFlush,	/* TRUE - don't flush the primary key */
			    int print)
{
    TPM_RC			rc = 0;
    CreatePrimary_In 		inCreatePrimary;
    CreatePrimary_Out 		outCreatePrimary;

    /* sanity check nonce size (should never happen on HW TPM) */
    if ((rc == 0) && (nonce != NULL)) {
	if (ekCertIndex == EK_CERT_RSA_INDEX) {			/* RSA primary key */
	    if (nonceSize > 256) {
		printf("processCreatePrimary: RSA NV nonce size %u > 256\n", nonceSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
	else {							/* EC primary key */
	    if (nonceSize > 32) {
		printf("processCreatePrimary: EC NV nonce size %u > 32\n", nonceSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }    
    /* set up the createprimary in parameters */
    if (rc == 0) {
	inCreatePrimary.primaryHandle = TPM_RH_ENDORSEMENT;
	inCreatePrimary.inSensitive.sensitive.userAuth.t.size = 0;
	inCreatePrimary.inSensitive.sensitive.data.t.size = 0;
	/* creation data */
	inCreatePrimary.outsideInfo.t.size = 0;
	inCreatePrimary.creationPCR.count = 0;
    }
    /* construct the template from the NV template and nonce */
    if ((rc == 0) && (nonce != NULL)) {
	inCreatePrimary.inPublic.publicArea = *tpmtPublicIn;
	if (ekCertIndex == EK_CERT_RSA_INDEX) {			/* RSA primary key */
	    /* unique field is 256 bytes */
	    inCreatePrimary.inPublic.publicArea.unique.rsa.t.size = 256;
	    /* first part is nonce */
	    memcpy(inCreatePrimary.inPublic.publicArea.unique.rsa.t.buffer, nonce, nonceSize);
	    /* padded with zeros */
	    memset(inCreatePrimary.inPublic.publicArea.unique.rsa.t.buffer + nonceSize, 0,
		   256 - nonceSize);
	}
	else {							/* EC primary key */
	    /* unique field is X and Y points */
	    /* X gets nonce and pad */
	    inCreatePrimary.inPublic.publicArea.unique.ecc.x.t.size = 32;
	    memcpy(inCreatePrimary.inPublic.publicArea.unique.ecc.x.t.buffer, nonce, nonceSize);
	    memset(inCreatePrimary.inPublic.publicArea.unique.ecc.x.t.buffer + nonceSize, 0,
		   32 - nonceSize);
	    /* Y gets zeros */
	    inCreatePrimary.inPublic.publicArea.unique.ecc.y.t.size = 32;
	    memset(inCreatePrimary.inPublic.publicArea.unique.ecc.y.t.buffer, 0, 32);
	}
    }
    /* construct the template from the default IWG template */
    if ((rc == 0) && (nonce == NULL)) {
	if (ekCertIndex == EK_CERT_RSA_INDEX) {			/* RSA primary key */
	    getRsaTemplate(&inCreatePrimary.inPublic.publicArea);
	}
	else {							/* EC primary key */
	    getEccTemplate(&inCreatePrimary.inPublic.publicArea);
	}
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&outCreatePrimary,
			 (COMMAND_PARAMETERS *)&inCreatePrimary,
			 NULL,
			 TPM_CC_CreatePrimary,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc != 0) {
	    const char *msg;
	    const char *submsg;
	    const char *num;
	    printf("createprimary: failed, rc %08x\n", rc);
	    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	    printf("%s%s%s\n", msg, submsg, num);
	}
    }
    /* return the primary key */
    if (rc == 0) {
	*tpmtPublicOut = outCreatePrimary.outPublic.publicArea;
    }
    /* flush the primary key */
    if (rc == 0) {
	if (!noFlush) {		/* flush the primary key */
	    FlushContext_In 		inFlushContext;
	    *keyHandle = TPM_RH_NULL;	    
	    inFlushContext.flushHandle = outCreatePrimary.objectHandle;
	    rc = TSS_Execute(tssContext,
			     NULL, 
			     (COMMAND_PARAMETERS *)&inFlushContext,
			     NULL,
			     TPM_CC_FlushContext,
			     TPM_RH_NULL, NULL, 0);
	    if (rc != 0) {
		const char *msg;
		const char *submsg;
		const char *num;
		printf("flushcontext: failed, rc %08x\n", rc);
		TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
		printf("%s%s%s\n", msg, submsg, num);
	    }
	}
	else {	/* not flushed, return the handle */
	    *keyHandle = outCreatePrimary.objectHandle;
	}
    }	    
    /* trace the public key */
    if (rc == 0) {
	if (ekCertIndex == EK_CERT_RSA_INDEX) {
	    if (print) TSS_PrintAll("createprimary: RSA public key",
				    outCreatePrimary.outPublic.publicArea.unique.rsa.t.buffer,
				    outCreatePrimary.outPublic.publicArea.unique.rsa.t.size);
	}
	else {
	    if (print) TSS_PrintAll("createprimary: ECC public key x",
				    outCreatePrimary.outPublic.publicArea.unique.ecc.x.t.buffer,
				    outCreatePrimary.outPublic.publicArea.unique.ecc.x.t.size);
	    if (print) TSS_PrintAll("createprimary: ECC public key y",
				    outCreatePrimary.outPublic.publicArea.unique.ecc.y.t.buffer,
				    outCreatePrimary.outPublic.publicArea.unique.ecc.y.t.size);
	}
    }
    return rc;
}

/* processValidatePrimary() compares the public key in the EK certificate to the public key output
   of createprimary.  */

TPM_RC processValidatePrimary(uint8_t *publicKeyBin,		/* from certificate */
			      int publicKeyBytes,
			      TPMT_PUBLIC *tpmtPublic,		/* primary key */
			      TPMI_RH_NV_INDEX ekCertIndex,
			      int print)
{
    TPM_RC			rc = 0;

    print = print;
    /* compare the X509 certificate public key to the createprimary public key */
    switch (ekCertIndex) {
#ifndef TPM_TSS_NORSA
      case EK_CERT_RSA_INDEX:
	  {
	      int irc;
	      /* RSA just has a public modulus */
	      if (rc == 0) {
		  if (tpmtPublic->unique.rsa.t.size != publicKeyBytes) {
		      printf("processValidatePrimary: "
			     "X509 certificate key length %u does not match output of createprimary %u\n",
			     publicKeyBytes,
			     tpmtPublic->unique.rsa.t.size);
		      rc = TPM_RC_INTEGRITY;
		  }
	      }
	      if (rc == 0) {
		  irc = memcmp(publicKeyBin,
			       tpmtPublic->unique.rsa.t.buffer,
			       publicKeyBytes);
		  if (irc != 0) {
		      printf("processValidatePrimary: "
			     "Public key from X509 certificate does not match output of createprimary\n");
		      rc = TPM_RC_INTEGRITY;
		  }
	      }
	  }
	  break;
#endif /* TPM_TSS_NORSA */
#ifndef TPM_TSS_NOECC
      case EK_CERT_EC_INDEX:
	  {
	      int irc;
	      /* ECC has X and Y points */
	      /* compression algorithm is the extra byte at the beginning of the certificate */
	      if (rc == 0) {
		  if (tpmtPublic->unique.ecc.x.t.size +
		      tpmtPublic->unique.ecc.y.t.size + 1
		      != publicKeyBytes) {
		      printf("processValidatePrimary: "
			     "X509 certificate key length %u does not match "
			     "output of createprimary x %u +y %u\n",
			     publicKeyBytes,
			     tpmtPublic->unique.ecc.x.t.size,
			     tpmtPublic->unique.ecc.y.t.size);
		      rc = TPM_RC_INTEGRITY;
		  }
	      }
	      /* check X */
	      if (rc == 0) {
		  irc = memcmp(publicKeyBin +1,
			       tpmtPublic->unique.ecc.x.t.buffer,
			       tpmtPublic->unique.ecc.x.t.size);
		  if (irc != 0) {
		      printf("processValidatePrimary: "
			     "Public key X from X509 certificate does not match "
			     "output of createprimary\n");
		      rc = TPM_RC_INTEGRITY;
		  }
	      }
	      /* check Y */
	      if (rc == 0) {
		  irc = memcmp(publicKeyBin + 1 + tpmtPublic->unique.ecc.x.t.size,
			       tpmtPublic->unique.ecc.y.t.buffer,
			       tpmtPublic->unique.ecc.y.t.size);
		  if (irc != 0) {
		      printf("processValidatePrimary: "
			     "Public key Y from X509 certificate does not match "
			     "output of createprimary\n");
		      rc = TPM_RC_INTEGRITY;
		  }
	      }	
	  }
	  break;
#endif /* TPM_TSS_NOECC */
      default:
	printf("processValidatePrimary: "
	       "ekCertIndex %08x (asymmetric algorithm) not supported\n", ekCertIndex);
	rc = TPM_RC_INTEGRITY;
	break;
    }
    if (rc == 0) {
	if (print) printf("processValidatePrimary: "
			  "Public key from X509 certificate matches output of createprimary\n");
    }
    return rc;
}

/* processPrimary() reads the EK nonce and EK template from NV.  It combines them to form the
   createprimary input.  It creates the primary key.

   It reads the EK certificate from NV.  It extracts the public key.

   Finally, it compares the public key in the certificate to the public key output of createprimary.
*/

TPM_RC processPrimary(TSS_CONTEXT *tssContext,
		      TPM_HANDLE *keyHandle,		/* primary key handle */
		      TPMI_RH_NV_INDEX ekCertIndex,
		      TPMI_RH_NV_INDEX ekNonceIndex, 
		      TPMI_RH_NV_INDEX ekTemplateIndex,
		      unsigned int noFlush,		/* TRUE - don't flush the primary key */
		      int print)
{
    TPM_RC			rc = 0;
    void 			*ekCertificate = NULL;
    unsigned char 		*nonce = NULL;
    uint16_t 			nonceSize;
    TPMT_PUBLIC 		tpmtPublicIn;		/* template */
    TPMT_PUBLIC 		tpmtPublicOut;		/* primary key */
    uint8_t 			*publicKeyBin = NULL;	/* from certificate */
    int				publicKeyBytes;
    int 			validate = FALSE;	/* validate the certificate */

    /* get the EK nonce */
    if (rc == 0) {
	rc = processEKNonce(tssContext, &nonce, &nonceSize, ekNonceIndex, print); /* freed @1 */
	if ((rc & 0xff) == TPM_RC_HANDLE) {
	    if (print) printf("processPrimary: EK nonce not found, use default template\n");
	    rc = 0;
	}
    }
    if (rc == 0) {
	/* if the nonce was found, get the EK template */
	if (nonce != NULL) {
	    rc = processEKTemplate(tssContext, &tpmtPublicIn, ekTemplateIndex, print);
	}
    }
    /* create the primary key */
    if (rc == 0) {
	rc = processCreatePrimary(tssContext,
				  keyHandle,
				  ekCertIndex,
				  nonce, nonceSize,		/* EK nonce, can be NULL */
				  &tpmtPublicIn,		/* template */
				  &tpmtPublicOut,		/* primary key */
				  noFlush,
				  print);
    }
    /* validate against the certificate if the algorithm is compiled in */
    if (rc == 0) {
#ifndef TPM_TSS_NORSA
	if (ekCertIndex == EK_CERT_RSA_INDEX) {
	    validate = TRUE;
	}
#endif /* TPM_TSS_NORSA */
#ifndef TPM_TSS_NOECC
	if (ekCertIndex == EK_CERT_EC_INDEX) {
	    validate = TRUE;
	}
#endif	/* TPM_TSS_NOECC */
    }
    /* get the EK certificate */
    if ((rc == 0) && validate) {
	rc = processEKCertificate(tssContext,
				  &ekCertificate,			/* freed @2 */
				  &publicKeyBin, &publicKeyBytes,	/* freed @3 */
				  ekCertIndex,
				  print);
    }
    /* compare the public key in the EK certificate to the public key output */
    if ((rc == 0) && validate) {
	rc = processValidatePrimary(publicKeyBin,	/* certificate */
				    publicKeyBytes,
				    &tpmtPublicOut,	/* primary key */
				    ekCertIndex,
				    print);
    }
    if ((rc == 0) && validate) {
	if (print) printf("Public key from X509 certificate matches output of createprimary\n");
    } 
    free(nonce);			/* @1 */
    if (ekCertificate != NULL) {
	X509_free(ekCertificate);   	/* @2 */
    }
    free(publicKeyBin);			/* @3 */
    return rc;
}

#endif	/* TPM20 */

