/********************************************************************************/
/*										*/
/*		TPM 2.0 Attestation - Client EK and EK certificate  		*/
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

/* This program provisions an EK certificate.  It is required only for a SW TPM, which does not, of
   course, come with a certificate.

   NOTE This is a one time operation unless the EPS is changed, typically through the TSS regression
   test.  I suggest saving the NVChip file.

   Steps implemented:

   Create a primary key using the default IWG template
   
   Create a certificate using the CA key cakey.pem

   Create NV Index if not already provisioned.

   Write the certificate to NV.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* Windows 10 crypto API clashes with openssl */
#ifdef TPM_WINDOWS
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#endif

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tsscrypto.h>
#include "ekutils.h"

/* local function prototypes */

static void printUsage(void);

static TPM_RC defineEKCertIndex(TSS_CONTEXT *tssContext,
				uint32_t certLength,	
				TPMI_RH_NV_INDEX nvIndex,
				const char *platformPassword);
static TPM_RC storeEkCertificate(TSS_CONTEXT *tssContext,
				 uint32_t certLength,
				 unsigned char *certificate,	
				 TPMI_RH_NV_INDEX nvIndex,
				 const char *platformPassword);

int vverbose = 0;
extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    int 		rc = 0;
    int			i;    /* argc iterator */
    TSS_CONTEXT 	*tssContext = NULL;
    int			noFlush = FALSE;
    const char		*certificateFilename = NULL;
    TPMI_RH_NV_INDEX	ekCertIndex = EK_CERT_RSA_INDEX;
    /* the CA for endorsement key certificates */
    const char 		*caKeyFileName = NULL;
    const char 		*caKeyPassword = "";
    const char		*platformPassword = NULL; 
    TPMT_PUBLIC 	tpmtPublicOut;		/* primary key public part */
    char 		*x509CertString = NULL;
    char 		*pemCertString = NULL;
    uint32_t 		certLength;
    unsigned char 	*certificate = NULL;

    /* FIXME may be better from command line or config file */
    char *subjectEntries[] = {
	"US",		/* 0 country */
	"NY",		/* 1 state */
	"Yorktown",	/* 2 locality*/
	"IBM",		/* 3 organization */
	NULL,		/* 4 organization unit */
	"IBM's SW TPM",	/* 5 common name */
	NULL		/* 6 email */
    };
    /* FIXME should come from root certificate, cacert.pem, cacertec.pem */
    char *rootIssuerEntriesRsa[] = {
	"US"			,
	"NY"			,
	"Yorktown"		,
	"IBM"			,
	NULL			,
	"EK CA"			,
	NULL	
    };
    char *rootIssuerEntriesEc[] = {
	"US"			,
	"NY"			,
	"Yorktown"		,
	"IBM"			,
	NULL			,
	"EK EC CA"		,
	NULL	
    };
    /* default RSA */
    char 		**issuerEntries = rootIssuerEntriesRsa;
    size_t		issuerEntriesSize = sizeof(rootIssuerEntriesRsa)/sizeof(char *);

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-noflush") == 0) {
	    noFlush = TRUE;
	}
	else if (strcmp(argv[i],"-of") == 0) {
	    i++;
	    if (i < argc) {
		certificateFilename = argv[i];
	    }
	    else {
		printf("-of option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-alg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"rsa") == 0) {
		    ekCertIndex = EK_CERT_RSA_INDEX;
		}
		else if (strcmp(argv[i],"ecc") == 0) {
		    ekCertIndex = EK_CERT_EC_INDEX;
		}
		else {
		    printf("Bad parameter %s for -alg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-alg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-caalg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"rsa") == 0) {
		    issuerEntries = rootIssuerEntriesRsa;
		    issuerEntriesSize = sizeof(rootIssuerEntriesRsa)/sizeof(char *);
		}
		else if (strcmp(argv[i],"ec") == 0) {
		    issuerEntries = rootIssuerEntriesEc;
		    issuerEntriesSize = sizeof(rootIssuerEntriesEc)/sizeof(char *);
		}
		else {
		    printf("Bad parameter %s for -caalg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-alg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-cakey") == 0) {
	    i++;
	    if (i < argc) {
		caKeyFileName = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -cakey\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-capwd") == 0) {
	    i++;
	    if (i < argc) {
		caKeyPassword = argv[i];
	    }
	    else {
		printf("ERROR: Missing parameter for -capwd\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdp") == 0) {
	    i++;
	    if (i < argc) {
		platformPassword = argv[i];
	    }
	    else {
		printf("-pwdp option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-h") == 0) {
	    printUsage();
	}
	else if (strcmp(argv[i],"-v") == 0) {
	    tssUtilsVerbose = 1;
	}
	else if (strcmp(argv[i],"-vv") == 0) {
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");	/* trace entire TSS */
	    tssUtilsVerbose = 1;
	    vverbose = 1;
	}
	else {
 	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (caKeyFileName == NULL) {
	printf("ERROR: Missing -cakey\n");
	printUsage();
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* create a primary EK using the default IWG template */
    if (rc == 0) {
	TPM_HANDLE keyHandle;
	rc = processCreatePrimary(tssContext,
				  &keyHandle,
				  ekCertIndex,		/* RSA or EC */
				  NULL, 0,		/* EK nonce, can be NULL */
				  NULL,			/* template */
				  &tpmtPublicOut,	/* primary key */
				  noFlush,
				  tssUtilsVerbose);		/* print errors */
    }
    /* create the EK certificate from the EK public key, using the above issuer and subject */
    if (rc == 0) {
	rc = createCertificate(&x509CertString,			/* freed @3 */
			       &pemCertString,			/* freed @2 */
			       &certLength,
			       &certificate,			/* output, freed @1 */
			       &tpmtPublicOut,			/* public key to be certified */
			       caKeyFileName,			/* CA signing key */
			       issuerEntriesSize,
			       issuerEntries,			/* certificate issuer */
			       sizeof(subjectEntries)/sizeof(char *),
			       subjectEntries,			/* certificate subject */
			       caKeyPassword);			/* CA signing key password */
    }
    /* If the NV index is not defined, define it */
    if (rc == 0) {
	rc = defineEKCertIndex(tssContext,
			       certLength,	
			       ekCertIndex,
			       platformPassword);
    }
    /* store the EK certificate in NV */
    if (rc == 0) {
	rc = storeEkCertificate(tssContext,
				certLength, certificate,	
				ekCertIndex,
				platformPassword);
    }
    /* optionally store the certificate in DER format */
    if ((rc == 0) && (certificateFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(certificate, certLength, certificateFilename);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    free(certificate);			/* @1 */
    free(pemCertString);		/* @2 */
    free(x509CertString);		/* @3 */
    return rc;
}

/* defineEKCertIndex() defines the EK certificate index if it is not already defined */

static TPM_RC defineEKCertIndex(TSS_CONTEXT *tssContext,
				uint32_t certLength,	
				TPMI_RH_NV_INDEX nvIndex,
				const char *platformPassword)
{
    TPM_RC 		rc = 0;
    NV_ReadPublic_In 	nvReadPublicIn;
    NV_ReadPublic_Out	nvReadPublicOut;
    NV_DefineSpace_In 	nvDefineSpaceIn;
    
    /* read metadata to make sure the index is there, the size is sufficient, and get the Name */
    if (tssUtilsVerbose) printf("defineEKCertIndex: certificate length %u\n", certLength);
    if (rc == 0) {
	nvReadPublicIn.nvIndex = nvIndex;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&nvReadPublicOut,
			 (COMMAND_PARAMETERS *)&nvReadPublicIn,
			 NULL,
			 TPM_CC_NV_ReadPublic,
			 TPM_RH_NULL, NULL, 0);
    }
    /* if already defined, check the size */
    if (rc == 0) {
	if (tssUtilsVerbose) printf("defineEKCertIndex: defined data size %u\n",
			    nvReadPublicOut.nvPublic.nvPublic.dataSize);
	if (nvReadPublicOut.nvPublic.nvPublic.dataSize < certLength) {
	    printf("defineEKCertIndex: data size %u insufficient for certificate %u\n",
		   nvReadPublicOut.nvPublic.nvPublic.dataSize, certLength);
	    rc = EXIT_FAILURE;
	}
    }
    else if ((rc & 0xff) == TPM_RC_HANDLE) {
	rc = 0;		/* not an error yet, define the index for the EK certificate */
	nvDefineSpaceIn.authHandle = TPM_RH_PLATFORM;
	nvDefineSpaceIn.auth.b.size = 0;					/* empty auth */
	nvDefineSpaceIn.publicInfo.nvPublic.authPolicy.t.size = 0;		/* empty policy */
	nvDefineSpaceIn.publicInfo.nvPublic.nvIndex = nvIndex;	/* handle of the data area */
	nvDefineSpaceIn.publicInfo.nvPublic.nameAlg = TPM_ALG_SHA256; 	/* name hash algorithm */
	nvDefineSpaceIn.publicInfo.nvPublic.attributes.val = 0;
	/* PC Client specification */
	nvDefineSpaceIn.publicInfo.nvPublic.attributes.val |= TPMA_NVA_ORDINARY;
	nvDefineSpaceIn.publicInfo.nvPublic.attributes.val |= TPMA_NVA_PLATFORMCREATE;
	nvDefineSpaceIn.publicInfo.nvPublic.attributes.val |= TPMA_NVA_AUTHREAD;
	nvDefineSpaceIn.publicInfo.nvPublic.attributes.val |= TPMA_NVA_NO_DA;
	nvDefineSpaceIn.publicInfo.nvPublic.attributes.val |= TPMA_NVA_PPWRITE;
	/* required for Microsoft Windows certification test */
	nvDefineSpaceIn.publicInfo.nvPublic.attributes.val |= TPMA_NVA_OWNERREAD; 
	if (certLength < 1000) {
	    nvDefineSpaceIn.publicInfo.nvPublic.dataSize = 1000;		/* minimum size */
	}
	else {
	    nvDefineSpaceIn.publicInfo.nvPublic.dataSize = certLength;
	}
	/* call TSS to execute the command */
	if (rc == 0) {
	    rc = TSS_Execute(tssContext,
			     NULL,
			     (COMMAND_PARAMETERS *)&nvDefineSpaceIn,
			     NULL,
			     TPM_CC_NV_DefineSpace,
			     TPM_RS_PW, platformPassword, 0,
			     TPM_RH_NULL, NULL, 0);
	}
    }
    if (rc != 0) {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("defineEKCertIndex: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	printf("ERROR: defineEKCertIndex: requires certificate min length %u at index %08x\n",
	       certLength, nvIndex);
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* storeEkCertificate() writes the EK certificate at the specified NV index.  It does not define the
   NV index.  */

static TPM_RC storeEkCertificate(TSS_CONTEXT *tssContext,
				 uint32_t certLength,
				 unsigned char *certificate,	
				 TPMI_RH_NV_INDEX nvIndex,
				 const char *platformPassword)
{
    TPM_RC 		rc = 0;
    NV_Write_In 	nvWriteIn;
    uint32_t 		nvBufferMax;		/* max write in one chunk */
    uint16_t 		bytesWritten;		/* bytes written so far */
    int			done = FALSE;

    if (rc == 0) {
	rc = readNvBufferMax(tssContext,
			     &nvBufferMax);
    }    
    if (rc == 0) {
	if (tssUtilsVerbose) printf("storeEkCertificate: writing %u bytes to %08x\n",
			    certLength, nvIndex);
	nvWriteIn.authHandle = TPM_RH_PLATFORM;  
	nvWriteIn.nvIndex = nvIndex;
	nvWriteIn.offset = 0;
	bytesWritten = 0;	/* bytes written so far */
    }
    while ((rc == 0) && !done) {
	uint16_t writeBytes;		/* bytes to write in this pass */
	if (rc == 0) {
	    nvWriteIn.offset = bytesWritten;
	    if ((uint32_t)(certLength - bytesWritten) < nvBufferMax) {
		writeBytes = certLength - bytesWritten;	/* last chunk */
	    }
	    else {
		writeBytes = nvBufferMax;	/* next chunk */
	    }
	    rc = TSS_TPM2B_Create(&nvWriteIn.data.b, certificate + bytesWritten, writeBytes,
				  sizeof(nvWriteIn.data.t.buffer));
	}
	if (rc == 0) {
	    rc = TSS_Execute(tssContext,
			     NULL,
			     (COMMAND_PARAMETERS *)&nvWriteIn,
			     NULL,
			     TPM_CC_NV_Write,
			     TPM_RS_PW, platformPassword, 0,
			     TPM_RH_NULL, NULL, 0);
	}
	if (rc == 0) {
	    bytesWritten += writeBytes;
	    if (bytesWritten == certLength) {
		done = TRUE;
	    }
	}
    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("storeEkCertificate: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("storeEkCertificate: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	if (rc == TSS_RC_FILE_OPEN) {
	    printf("Possible cause: missing nvreadpublic before nvwrite\n");
	}
	rc = EXIT_FAILURE;
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("createekcert\n");
    printf("\n");
    printf("Provisions an EK certificate, using the default IWG template\n");
    printf("E.g.,\n");
    printf("\n");
    printf("Usage: createekcert -alg rsa -cakey cakey.pem    -capwd rrrr -v\n");
    printf("or:    createekcert -alg ecc -cakey cakeyecc.pem -capwd rrrr -caalg ec -v\n");
    printf("\n");
    printf("\t[-pwdp\t\tplatform hierarchy password (default empty)]\n");
    printf("\t-cakey\t\tCA PEM key file name\n");
    printf("\t[-capwd\t\tCA PEM key password (default empty)]\n");
    printf("\t[-caalg\t\tCA key algorithm (rsa or ec) (default rsa)]\n");
    printf("\t[-alg\t\t(rsa or ecc certificate) (default rsa)]\n");
    printf("\t[-noflush\tdo not flush the primary key]\n");
    printf("\t[-of\t\tDER certificate output file name]\n");
    printf("\n");
    printf("Currently:\n");
    printf("\n");
    printf("\tCertificate issuer, subject, and validity are hard coded.\n");
    exit(1);	
}
