/********************************************************************************/
/*										*/
/*			     IWG EK Index Parsing				*/
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

/* This demo application shows the EK createprimary process.

   It reads the EK template at 01c00004 (RSA) 01c0000c (EC)

   It reads the EK nonce at 01c00003 (RSA) 01c0000b (EC)

   It constructs an EK createprimary input and runs the command

   It reads the EK certificate at 01c00002 (RSA) 01c0000a (EC) 

   It compares the public key from the createprimary to that of the certificate.

   If validates the EK certificate against the TPM vendor root CA certificate.

   To validate certificate against the root, it must be in a file in PEM format.  The root typically
   comes from the TPM vendor in DER (binary) format.  Convert using openssl, approximately:

   > openssl x509 -inform der -outform pem -in certificate.der -out certificate.pem

   This is a one time operation.
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
#include <ibmtss/Unmarshal_fp.h>

#include "ekutils.h"

/* local function prototypes */

static void printUsage(void);

/* possible utility commands */

#define EKTemplateType		1
#define EKNonceType		2
#define EKCertType		3
#define CreateprimaryType	4

#define AlgRSA			1
#define AlgEC			2

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    unsigned int		ui;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    int				inputType = 0;
    const char 			*listFilename = NULL;
    unsigned int		inputCount = 0;
    unsigned int		algType = 0;
    /* initialized to suppress false gcc -O3 warning */
    TPMI_RH_NV_INDEX		ekCertIndex = 0;
    TPMI_RH_NV_INDEX		ekNonceIndex = 0;
    TPMI_RH_NV_INDEX		ekTemplateIndex = 0;
    TPMT_PUBLIC 		tpmtPublic;
    char			*rootFilename[MAX_ROOTS];
    unsigned int		rootFileCount = 0;
    unsigned char 		*nonce = NULL; 		/* freed @1 */
    uint16_t 			nonceSize;
    void 			*ekCertificate = NULL;
    uint8_t 			*modulusBin = NULL;
    int				modulusBytes;
    unsigned int 		noFlush = 0;		/* default flush after validation */
    TPM_HANDLE 			keyHandle;		/* primary key handle */
    
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* for free */
    for (i = 0 ; i < MAX_ROOTS ; i++) {
	rootFilename[i] = NULL;
    }
    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-te") == 0) {
	    inputType = EKTemplateType;
	    inputCount++;
	}
	else if (strcmp(argv[i],"-no") == 0) {
	    inputType = EKNonceType;
	    inputCount++;
	}
	else if (strcmp(argv[i],"-ce") == 0) {
	    inputType = EKCertType;
	    inputCount++;
	}
	else if (strcmp(argv[i],"-cp") == 0) {
	    inputType = CreateprimaryType;
	    inputCount++;
	}
	else if (strcmp(argv[i],"-root") == 0) {
	    i++;
	    if (i < argc) {
		listFilename = argv[i];
	    }
	    else {
		printf("-root option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-alg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"rsa") == 0) {
		    algType = AlgRSA;
		    ekCertIndex = EK_CERT_RSA_INDEX;
		    ekNonceIndex = EK_NONCE_RSA_INDEX;
		    ekTemplateIndex = EK_TEMPLATE_RSA_INDEX;
		}
		else if (strcmp(argv[i],"ecc") == 0) {
		    algType = AlgEC;
		    ekCertIndex = EK_CERT_EC_INDEX;
		    ekNonceIndex = EK_NONCE_EC_INDEX;
		    ekTemplateIndex = EK_TEMPLATE_EC_INDEX;
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
	else if (strcmp(argv[i],"-noflush") == 0) {
	    noFlush = 1;
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
    if (inputCount > 1) {
	printf("Only one of -te, -no, -ce can be specified\n");
	printUsage();
    }
    if ((inputCount == 0) && (listFilename == NULL)) {
	printf("Nothing to do\n");
	printUsage();
    }
    if (algType == 0) {
	printf("-alg must be specified\n");
	printUsage();
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    if (rc == 0) {
	switch (inputType) {
	  case EKTemplateType:
	    rc = processEKTemplate(tssContext, &tpmtPublic, ekTemplateIndex, TRUE);
	    if (rc != 0) {
		printf("No EK template\n");
	    }
	    break;
	  case EKNonceType:
	    rc = processEKNonce(tssContext, &nonce, &nonceSize, ekNonceIndex, TRUE);
	    if (rc != 0) {
		printf("No EK nonce\n");
	    }
	    break;
	  case EKCertType:
	    rc = processEKCertificate(tssContext,
				      &ekCertificate,			/* freed @2 */
				      &modulusBin, &modulusBytes,	/* freed @3 */
				      ekCertIndex,
				      TRUE);		/* print the EK certificate */
	    break;
	  case CreateprimaryType:
	    rc = processPrimary(tssContext, &keyHandle,
				ekCertIndex, ekNonceIndex, ekTemplateIndex,
				noFlush, TRUE);
	    break;
	}
    }
    if (listFilename != NULL) {
	if (rc == 0) {
	    rc = getRootCertificateFilenames(rootFilename,	/* freed @4 */
					     &rootFileCount,
					     listFilename,
					     tssUtilsVerbose);
	}
	if (rc == 0) {
	    rc = processRoot(tssContext,
			     ekCertIndex,
			     (const char **)rootFilename,
			     rootFileCount,
			     TRUE); 
	}
    }
    if ((rc == 0) && noFlush && (inputType == CreateprimaryType)) {
	printf("Primary key Handle %08x\n", keyHandle);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    free(nonce);			/* @1 */
    x509FreeStructure(ekCertificate);  	/* @2 */
    free(modulusBin);			/* @3 */
    for (ui = 0 ; ui < rootFileCount ; ui++) {
	free(rootFilename[ui]);		/* @4 */
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("createek\n");
    printf("\n");
    printf("Parses and prints the various EK NV indexes specified by the IWG\n");
    printf("Creates a primary key based on the EK NV indexes\n");
    printf("\n");
    printf("\t-te\tprint EK Template \n");
    printf("\t-no\tprint EK nonce \n");
    printf("\t-ce\tprint EK certificate \n");
    printf("\t-cp\tCreatePrimary using the EK template and EK nonce.\n");
    printf("\t\tValidate the EK against the EK certificate\n");
    printf("\t[-noflush\tDo not flush the primary key after validation]\n");
    printf("\t[-root\tfilename - validate EK certificate against the root]\n");
    printf("\t\tfilename contains a list of PEM format CA root certificate\n"
	   "\t\tfilenames, one per line.\n");
    printf("\t\tThe list may contain up to %u certificates.\n", MAX_ROOTS);
    printf("\t-alg (rsa or ecc) \n");
    exit(1);	
}
