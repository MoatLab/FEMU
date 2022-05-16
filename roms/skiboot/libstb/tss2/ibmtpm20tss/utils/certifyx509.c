/********************************************************************************/
/*										*/
/*			    CertifyX509						*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2019.						*/
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

/* CertifyX509 exercises the TPM2_CertifyX509 command.  It:

   - Creates a partialCertificate parameter
   - Runs the TPM2_CertifyX509 command
   - Reconstructs the X509 certificate from the addedToCertificate and signature outputs
*/

/* mbedtls does not support this utility */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "cryptoutils.h"

#ifndef TPM_TSS_MBEDTLS

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tssfile.h>

/* NOTE: This is currently openssl only. */
#include <ekutils.h>

static void printUsage(void);

TPM_RC createPartialCertificate(X509 *x509Certificate,
				uint8_t *partialCertificateDer,
				uint16_t *partialCertificateDerLength,
				size_t partialCertificateDerSize,
				const char *keyUsage,
				uint32_t tpmaObject,
				int addTpmaObject,
				int subeqiss);
TPM_RC convertCertToPartialCert(uint16_t *partialCertificateDerLength,
				uint8_t *partialCertificateDer,
				uint16_t certificateDerLength,
				uint8_t *certificateDer);
TPM_RC reformCertificate(X509 *x509Certificate,
			 int useRsa,
			 TPM2B_MAX_BUFFER *addedToCertificate,
			 TPMT_SIGNATURE *tSignature);
TPM_RC addSerialNumber(X509 		*x509Certificate,
		       unsigned char *tmpAddedToCert,
		       uint16_t *tmpAddedToCertIndex);
TPM_RC addPubKeyRsa(X509 		*x509Certificate,
		    unsigned char 	*tmpAddedToCert,
		    uint16_t 		*tmpAddedToCertIndex);
TPM_RC addSignatureRsa(X509 		*x509Certificate,
		       TPMT_SIGNATURE 	*tSignature);
TPM_RC addSignatureEcc(X509 		*x509Certificate,
		       TPMT_SIGNATURE 	*signature);
TPM_RC addPubKeyEcc(X509 		*x509Certificate,
		    unsigned char 	*tmpAddedToCert,
		    uint16_t 		*tmpAddedToCertIndex);
TPM_RC addCertExtensionTpmaOid(X509 *x509Certificate,
			       uint32_t tpmaObject);

TPM_RC getDataLength(uint8_t type,
		     uint16_t *wrapperLength,
		     uint16_t *dataLength,
		     uint16_t *certificateDerIndex,
		     uint8_t *certificateDer);

TPM_RC skipSequence(uint16_t *certificateDerIndex, uint8_t *certificateDer);
TPM_RC skipBitString(uint16_t *dataLength,
		     uint16_t *certificateDerIndex, uint8_t *certificateDer);

TPM_RC copyType(uint8_t type,
		uint16_t *partialCertificateDerLength, uint8_t *partialCertificateDer,
		uint16_t *certificateDerIndex, uint8_t *certificateDer);

TPM_RC getInteger(uint16_t *integerLength, unsigned char *integerStream,
		  uint16_t *certificateDerIndex, unsigned char *certificateDer);
TPM_RC prependSequence(uint16_t *partialCertificateDerLength, uint8_t *partialCertificateDer);

int verbose = FALSE;

/* FIXME
   length checks
*/

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    CertifyX509_In 		in;
    CertifyX509_Out 		out;
    TPMI_DH_OBJECT		objectHandle = 0;
    TPMI_DH_OBJECT		signHandle = 0;
    TPMI_ALG_HASH		halg = TPM_ALG_SHA256;
    unsigned int 		bit = 0;
    int 			testBit = FALSE;
    const char			*keyPassword = NULL; 
    const char			*objectPassword = NULL; 
    const char			*outPartialCertificateFilename = NULL;
    const char			*outCertificateFilename = NULL;
    const char			*addedToCertificateFilename = NULL;
    const char			*tbsDigestFilename = NULL;
    const char			*signatureFilename = NULL;

    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RS_PW;
    unsigned int		sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle1 = TPM_RS_PW;
    unsigned int		sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION    	sessionHandle2 = TPM_RH_NULL;
    unsigned int		sessionAttributes2 = 0;

    int				useRsa = 1;
    int				subeqiss = FALSE;	/* TRUE: subject = issuer */
    const char 			*keyUsage = "critical,digitalSignature,keyCertSign,cRLSign";
    uint32_t			tpmaObject = 0;
    int				addTpmaObject = FALSE;
    X509 			*x509Certificate = NULL;
    unsigned char 		*x509Der = NULL;
    uint32_t 			x509DerLength = 0;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ho") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x",&objectHandle);
	    }
	    else {
		printf("Missing parameter for -ho\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pwdo") == 0) {
	    i++;
	    if (i < argc) {
		objectPassword = argv[i];
	    }
	    else {
		printf("-pwdo option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-hk") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%x",&signHandle);
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
	else if (strcmp(argv[i],"-halg") == 0) {
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
		    printf("Bad parameter %s for -halg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-halg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-salg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"rsa") == 0) {
		    useRsa = 1;
		}
		else if (strcmp(argv[i],"ecc") == 0) {
		    useRsa = 0;
		}
		else {
		    printf("Bad parameter %s for -salg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-salg option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ku") == 0) {
	    i++;
	    if (i < argc) {
		keyUsage = argv[i];
	    }
	    else {
		printf("-ku option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-iob") == 0) {
	    i++;
	    if (i < argc) {
		addTpmaObject = TRUE;
		sscanf(argv[i], "%x", &tpmaObject);
	    }
	    else {
		printf("-iob option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-sub") == 0) {
	    subeqiss = TRUE;
	}
	else if (strcmp(argv[i],"-opc") == 0) {
	    i++;
	    if (i < argc) {
		outPartialCertificateFilename = argv[i];
	    }
	    else {
		printf("-opc option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ocert") == 0) {
	    i++;
	    if (i < argc) {
		outCertificateFilename = argv[i];
	    }
	    else {
		printf("-ocert option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-oa") == 0) {
	    i++;
	    if (i < argc) {
		addedToCertificateFilename = argv[i];
	    }
	    else {
		printf("-oa option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-otbs") == 0) {
	    i++;
	    if (i < argc) {
		tbsDigestFilename = argv[i];
	    }
	    else {
		printf("-otbs option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-os") == 0) {
	    i++;
	    if (i < argc) {
		signatureFilename = argv[i];
	    }
	    else {
		printf("-os option needs a value\n");
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
	    verbose = TRUE;
	    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "2");
	}
	else {
	    printf("\n%s is not a valid option\n", argv[i]);
	    printUsage();
	}
    }
    if (objectHandle == 0) {
	printf("Missing object handle parameter -ho\n");
	printUsage();
    }
    if (signHandle == 0) {
	printf("Missing sign handle parameter -hk\n");
	printUsage();
    }
    if (rc == 0) {
	/* Handle of the object to be certified */
	in.objectHandle = objectHandle;
	/* Handle of key that will perform certifying */
	in.signHandle = signHandle;
	if (useRsa) {
	    /* Table 145 - Definition of TPMT_SIG_SCHEME Structure */
	    in.inScheme.scheme = TPM_ALG_RSASSA;	
	    /* Table 144 - Definition of TPMU_SIG_SCHEME Union <IN/OUT, S> */
	    /* Table 142 - Definition of {RSA} Types for RSA Signature Schemes */
	    /* Table 135 - Definition of TPMS_SCHEME_HASH Structure */
	    in.inScheme.details.rsassa.hashAlg = halg;
	}
	else {	/* ecc */
	    in.inScheme.scheme = TPM_ALG_ECDSA;	
	    in.inScheme.details.ecdsa.hashAlg = halg;
	}
	in.reserved.t.size = 0;
    }
    /* initialize a new, empty X509 structure.  It will first be used to form the partialCertificate
       command parameter, and then be used to reform the certificate from the response
       parameters. */
    if (rc == 0) {
	x509Certificate = X509_new();				/* freed @1 */
	if (x509Certificate == NULL) {
	    printf("main: Error in X509_new\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    /* form partial certificate */
    if (rc == 0) {
	rc = createPartialCertificate(x509Certificate,
				      in.partialCertificate.t.buffer,
				      &in.partialCertificate.b.size,
				      sizeof(in.partialCertificate.t.buffer),
				      keyUsage,
				      tpmaObject,
				      addTpmaObject,
				      subeqiss);
    }
    if ((rc == 0) && (testBit)) {
	unsigned int bitInByte = bit % 8;
	unsigned int byteInDer = bit / 8;
	if (byteInDer <= in.partialCertificate.b.size) {
	    if (verbose) {
		printf("main: Testing byte %u bit %u\n", byteInDer, bitInByte);
		printf("main: Byte was %02x\n", in.partialCertificate.t.buffer[byteInDer]);
	    }		
	    in.partialCertificate.t.buffer[byteInDer] ^= (1 << bitInByte);
	    if (verbose) printf("main: Byte is %02x\n", in.partialCertificate.t.buffer[byteInDer]);
	}
	else {
	    printf("Bad -bit parameter, byte %u, DER length %u\n",
		   byteInDer, in.partialCertificate.b.size);
	    rc = TSS_RC_BAD_PROPERTY;
	}
    }
    /* for debug, or stop here for sample of how to create the partialCertificate parameter */
    if (rc == 0) {
	if (outPartialCertificateFilename != NULL) {
	    rc = TSS_File_WriteBinaryFile(in.partialCertificate.b.buffer,
					  in.partialCertificate.b.size,
					  outPartialCertificateFilename);
	}
    }
    /* Start a TSS context */
    if (rc == 0) {
	rc = TSS_Create(&tssContext);
    }
    /* call TSS to execute the command */
    if (rc == 0) {
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_CertifyX509,
			 sessionHandle0, objectPassword, sessionAttributes0,
			 sessionHandle1, keyPassword, sessionAttributes1,
			 sessionHandle2, NULL, sessionAttributes2,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    if (rc != 0) {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("certifyx509: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    /* write response parameters for debug */
    if ((rc == 0) && (addedToCertificateFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(out.addedToCertificate.t.buffer,
				      out.addedToCertificate.t.size,
				      addedToCertificateFilename);
    }
    if ((rc == 0) && (tbsDigestFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(out.tbsDigest.t.buffer,
				      out.tbsDigest.t.size,
				      tbsDigestFilename);
    }
    if ((rc == 0) && (signatureFilename != NULL)) {
	rc = TSS_File_WriteStructure(&out.signature,
				     (MarshalFunction_t)TSS_TPMT_SIGNATURE_Marshalu,
				     signatureFilename);
    }
    if (rc == 0) {
	if (verbose) TSS_TPMT_SIGNATURE_Print(&out.signature, 0);
    }
    /* reform the signed certificate from the original input plus the response parameters */
    if (rc == 0) {
	rc = reformCertificate(x509Certificate,
			       useRsa,
			       &out.addedToCertificate,
			       &out.signature);
    }
    if (rc == 0) {
	if (verbose) X509_print_fp(stdout, x509Certificate);	/* for debug */
	rc = convertX509ToDer(&x509DerLength,
			      &x509Der,				/* freed @2 */
			      x509Certificate);
    }
    if ((rc == 0) && (outCertificateFilename != NULL)) {
	rc = TSS_File_WriteBinaryFile(x509Der, x509DerLength,
				      outCertificateFilename);
    }
    if (x509Certificate != NULL) {
	X509_free(x509Certificate);			/* @1 */
    }
    free(x509Der);					/* @2 */		
    return rc;
}

/* example of a 20 year validity */
#define CERT_DURATION (60 * 60 * 24 * ((365 * 20) + 5))		/* +5 for leap years */

/* in this test, the issuer and subject are the same, making a self signed certificate.  This is
   simply so that openssl can be used to verify the certificate signature.
 */

char *issuerEntries[] = {
    "US"			,
    "NY"			,
    "Yorktown"			,
    "IBM"			,
    NULL			,
    "CA"			,
    NULL	
};

char *subjectEntries[] = {
    "US"			,
    "NY"			,
    "Yorktown"			,
    "IBM"			,
    NULL			,
    "Subject"			,
    NULL	
};

/* createPartialCertificate() forms the partialCertificate DER.  It starts with an empty X509
   structure and adds the needed parameters.  Then (in a total hack), converts the X509 structure to
   DER, parses the DER field by field, and outputs just the fields required for the
   partialCertificate parameter.

   subeqiss FALSE: subject name is independent of issuer name
   subeqiss TRUE:  subject name is the same as the issuer name
*/

TPM_RC createPartialCertificate(X509 *x509Certificate,			/* input / output */
				uint8_t *partialCertificateDer,		/* output */
				uint16_t *partialCertificateDerLength,
				size_t partialCertificateDerSize,
				const char *keyUsage,
				uint32_t tpmaObject,
				int addTpmaObject,
				int subeqiss)				/* subject variation */
{
    TPM_RC 	rc = 0;
    int		irc;
    ASN1_TIME	*arc;			/* return code */

    X509_NAME 	*x509IssuerName = NULL;	/* composite issuer name, key/value pairs */
    X509_NAME 	*x509SubjectName = NULL;/* composite subject name, key/value pairs */
    size_t	issuerEntriesSize = sizeof(issuerEntries)/sizeof(char *);
    size_t	subjectEntriesSize = sizeof(subjectEntries)/sizeof(char *);
  
    uint32_t 	certificateDerLength = 0;
    uint8_t 	*certificateDer = NULL;

    partialCertificateDerSize = partialCertificateDerSize;	/* FIXME needs size check */

    /* add certificate version X509 v3 */
    if (rc == 0) {
	irc = X509_set_version(x509Certificate, 2L);	/* value 2 == v3 */
	if (irc != 1) {
	    printf("createPartialCertificate: Error in X509_set_version\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* add issuer */
    if (rc == 0) {
	if (verbose) printf("createPartialCertificate: Adding issuer, size %lu\n",
				(unsigned long)issuerEntriesSize);
	rc = createX509Name(&x509IssuerName,
			    issuerEntriesSize,
			    issuerEntries);
    }
    if (rc == 0) {
	irc = X509_set_issuer_name(x509Certificate, x509IssuerName);
	if (irc != 1) {
	    printf("createPartialCertificate: Error setting issuer\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* add validity */
    if (rc == 0) {
	/* can't fail, just returns a structure member */
	ASN1_TIME *notBefore = X509_get_notBefore(x509Certificate);
	arc = X509_gmtime_adj(notBefore ,0L);			/* set to today */
	if (arc == NULL) {
	    printf("createPartialCertificate: Error setting notBefore time\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	/* can't fail, just returns a structure member */
	ASN1_TIME *notAfter = X509_get_notAfter(x509Certificate);
	arc = X509_gmtime_adj(notAfter, CERT_DURATION);		/* set to duration */
	if (arc == NULL) {
	    printf("createPartialCertificate: Error setting notAfter time\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* add subject */
    if (rc == 0) {
	/* normal case */
	if (!subeqiss) {
	    if (verbose) printf("createPartialCertificate: Adding subject, size %lu\n",
				(unsigned long)subjectEntriesSize);
	    rc = createX509Name(&x509SubjectName,
				subjectEntriesSize,
				subjectEntries);
	}
	/* special case, self signed CA, make the subject the same as the issuer */
	else {
	    if (verbose) printf("createPartialCertificate: Adding subject (issuer), size %lu\n",
				(unsigned long)issuerEntriesSize);
	    rc = createX509Name(&x509SubjectName,
				issuerEntriesSize,
				issuerEntries);
	}
    }
    if (rc == 0) {
	irc = X509_set_subject_name(x509Certificate, x509SubjectName);
	if (irc != 1) {
	    printf("createPartialCertificate: Error setting subject\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* add some certificate extensions, requires corresponding bits in subject key */
    if (rc == 0) {
	if (verbose) printf("createPartialCertificate: Adding extensions\n");
	rc = addCertExtension(x509Certificate,
			      NID_key_usage, keyUsage);
    }
    /* optional TPMA_OBJECT extension */
    /* From TCG OID registry tcg-tpmaObject 2.23.133.10.1.1.1  */
    if (rc == 0) {
	if (addTpmaObject) {
	    rc = addCertExtensionTpmaOid(x509Certificate, tpmaObject);
	}
    }
    /* convertX509ToDer() serializes the openSSL X509 structure to a DER certificate stream */
    if (rc == 0) {
	rc = convertX509ToDer(&certificateDerLength,
			      &certificateDer,		/* freed @4 */
			      x509Certificate);		/* input */
    }
    /* for debug.  The structure is incomplete and so will trace with errors */
    if (rc == 0) {
	if (verbose) printf("createPartialCertificate: Trace preliminary certificate\n");
	if (verbose) X509_print_fp(stdout, x509Certificate);
    }
#if 1
    /* for debug.  Use dumpasn1 to view the incomplete certificate */
    if (rc == 0) {
	rc = TSS_File_WriteBinaryFile(certificateDer, certificateDerLength , "tmpx509i.bin");
    }
#endif
    /* extract the partialCertificate DER from the X509 DER */
    if (rc == 0) {
	rc = convertCertToPartialCert(partialCertificateDerLength,
				      partialCertificateDer,	/* output partial */
				      certificateDerLength,
				      certificateDer);		/* input X509 */
    }
    free(certificateDer);	/* @4 */
    return rc;
}

/* addCertExtension() adds the tpmaObject extension oid to the X509 certificate

 */ 

TPM_RC addCertExtensionTpmaOid(X509 *x509Certificate, uint32_t tpmaObject)
{
    TPM_RC 		rc = 0;
    X509_EXTENSION 	*extension = NULL;	/* freed @1 */


    uint8_t tpmaObjectOid[] = {0x06, 0x07, 0x67, 0x81, 0x05, 0x0A, 0x01, 0x01, 0x01};
    const uint8_t *tmpOidPtr;

    /* BIT STRING 0x03 length 5 no padding 0, 4 dummy bytes of TPMA_OBJECT */
    uint8_t tpmaObjectData[] = {0x03, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00};
    ASN1_OBJECT *object = NULL;
    ASN1_OCTET_STRING *osData = NULL; 
    uint8_t *tmpOdPtr;
    uint32_t tpmaObjectNbo = htonl(tpmaObject);

    if (rc == 0) {
	tmpOidPtr = tpmaObjectOid; 
	object = d2i_ASN1_OBJECT(NULL, &tmpOidPtr, sizeof(tpmaObjectOid));	/* freed @2 */
	if (object ==  NULL) {
	    printf("d2i_ASN1_OBJECT failed\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	osData = ASN1_OCTET_STRING_new();	/* freed @3 */
	if (osData == NULL) {
	    printf("d2i_ASN1_OCTET_STRING failed\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	tmpOdPtr = tpmaObjectData;
	memcpy(tmpOdPtr + 3, &tpmaObjectNbo, sizeof(uint32_t));
	ASN1_OCTET_STRING_set(osData, tmpOdPtr, sizeof (tpmaObjectData));
    }
    if (rc == 0) {
	extension = X509_EXTENSION_create_by_OBJ(NULL,		/* freed @1 */
						 object,
						 0,			/* int crit */
						 osData);
	if (extension == NULL) {
	    printf("X509_EXTENSION_create_by_OBJ failed\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (rc == 0) {
	int irc = X509_add_ext(x509Certificate,	/* the certificate */
			       extension,		/* the extension to add */
			       -1);			/* location - append */
	if (irc != 1) {
	    printf("addCertExtension: Error adding oid to extension\n");
	}
    }
    if (extension != NULL) {
	X509_EXTENSION_free(extension);	/* @1 */
    }
    if (object != NULL) {
	ASN1_OBJECT_free(object);		/* @2 */
    }
    if (osData != NULL) {
	ASN1_OCTET_STRING_free(osData);	/* @3 */
    }
    return rc;
}


/* convertCertToPartialCert() extracts the partialCertificate DER from the X509 DER

   It assumes that the input is well formed and has exactly the fields required.
*/

TPM_RC convertCertToPartialCert(uint16_t *partialCertificateDerLength,
				  uint8_t *partialCertificateDer,
				  uint16_t certificateDerLength,
				  uint8_t *certificateDer)
{
    TPM_RC 	rc = 0;
    uint16_t 	certificateDerIndex = 0;	/* index into the DER input */
    
    
    certificateDerLength = certificateDerLength; 	/* FIXME for future error checking */
    *partialCertificateDerLength = 0;			/* updates on each call */
    
    /* skip the outer SEQUENCE wrapper */
    if (rc == 0) {
	if (verbose) printf("convertCertToPartialCert: Skip outer SEQUENCE wrapper\n");
	rc = skipSequence(&certificateDerIndex, certificateDer);
    }
    /* skip the inner SEQUENCE wrapper, will be back filled with the total length */
    if (rc == 0) {
	if (verbose) printf("convertCertToPartialCert: Skip inner SEQUENCE wrapper\n");
	rc = skipSequence(&certificateDerIndex, certificateDer);
    }
    /* skip the a3 wrapping the version */
    if (rc == 0) {
	if (verbose) printf("convertCertToPartialCert: Skip a3 version wrapper\n");
	rc = copyType(0xa0, NULL, NULL, 		/* NULL says to skip */
		      &certificateDerIndex, certificateDer);
    }
    /* skip the integer (version) */
    if (rc == 0) {
	if (verbose) printf("convertCertToPartialCert: Skip version\n");
	rc = copyType(0x02, NULL, NULL, 		/* NULL says to skip */
		      &certificateDerIndex, certificateDer);
    }
    /* skip the sequence (serial number) */
    if (rc == 0) {
	if (verbose) printf("convertCertToPartialCert: Skip serial number\n");
	rc = copyType(0x30, NULL, NULL, 		/* NULL says to skip */
		      &certificateDerIndex, certificateDer);
    }
    /* copy the next SEQUENCE, issuer */
    if (rc == 0) {
	if (verbose) printf("convertCertToPartialCert: Copy issuer\n");
	rc = copyType(0x30, partialCertificateDerLength, partialCertificateDer,
		      &certificateDerIndex, certificateDer);
    }
    /* copy the next SEQUENCE, validity */
    if (rc == 0) {
	if (verbose) printf("convertCertToPartialCert: Copy validity\n");
	rc = copyType(0x30, partialCertificateDerLength, partialCertificateDer,
		      &certificateDerIndex, certificateDer);
    }
    /* copy the next SEQUENCE, subject */
    if (rc == 0) {
	if (verbose) printf("convertCertToPartialCert: Copy subject\n");
	rc = copyType(0x30, partialCertificateDerLength, partialCertificateDer,
		      &certificateDerIndex, certificateDer);
    }
    /* skip the SEQUENCE (public key) */
    if (rc == 0) {
	if (verbose) printf("convertCertToPartialCert: Skip public key\n");
	rc = copyType(0x30, NULL, NULL, 		/* NULL says to skip */
		      &certificateDerIndex, certificateDer);
    }
    /* copy the a3 and encapsulating sequence */
    if (rc == 0) {
	if (verbose) printf("convertCertToPartialCert: Copy a3 extensions\n");
	rc = copyType(0xa3, partialCertificateDerLength, partialCertificateDer,
		      &certificateDerIndex, certificateDer);
    }
    /* shift and back fill the sequence length */
    if (rc == 0) {
	rc = prependSequence(partialCertificateDerLength, partialCertificateDer);
    }
    return rc;
}

/* reformCertificate() starts with the X509 certificate used as the input partialCertificate
   parameter plus a few fields like the version.  It adds the output addedToCertificate and
   signature values to reform the X509 certificate that the TPM signed.
*/

TPM_RC reformCertificate(X509 *x509Certificate,
			 int useRsa,
			 TPM2B_MAX_BUFFER *addedToCertificate,
			 TPMT_SIGNATURE *tSignature)
{
    TPM_RC 		rc = 0;
    unsigned char 	*tmpAddedToCert = NULL;
    /* size_t 		tmpAddedToCertLength = 0; FIXME better to sanity check length */

    /* the index increments, so this function must parse the addedToCertificate in its order */
    uint16_t 		tmpAddedToCertIndex = 0;

    tmpAddedToCert = addedToCertificate->t.buffer;
    /* tmpAddedToCertLength = addedToCertificate->t.size; */

    /* add serial number */
    if (rc == 0) {
	rc = addSerialNumber(x509Certificate,
			     tmpAddedToCert,
			     &tmpAddedToCertIndex);
    }
    if (useRsa) {
	/* add public key algorithm and public key */
	if (rc == 0) {
	    rc = addPubKeyRsa(x509Certificate,
			      tmpAddedToCert,
			      &tmpAddedToCertIndex);
	}
	/* add certificate signature */
	if (rc == 0) {
	    rc = addSignatureRsa(x509Certificate, tSignature);
	}
    }
    else {
	/* add public key  */
	if (rc == 0) {
	    rc = addPubKeyEcc(x509Certificate,
			      tmpAddedToCert,
			      &tmpAddedToCertIndex);
	}
	/* add certificate signature */
	if (rc == 0) {
	    rc = addSignatureEcc(x509Certificate, tSignature);
	}
    }
    return rc;
}

/* addSerialNumber() is the first call from reforming the certificate. tmpAddedToCertIndex will be
   0.

   After the call, tmpAddedToCertIndex will point after the serial number.
*/

TPM_RC addSerialNumber(X509 		*x509Certificate,
			 unsigned char 	*tmpAddedToCert,
			 uint16_t 	*tmpAddedToCertIndex)
{
    TPM_RC 		rc = 0;
    ASN1_INTEGER 	*x509Serial;		/* certificate serial number in ASN1 */
    BIGNUM 		*x509SerialBN;		/* certificate serial number as a BIGNUM */
    unsigned char 	x509SerialBin[1048]; 	/* certificate serial number in binary */
    uint16_t 		integerLength = 0;

    /* FIXME check the size */

    x509SerialBN = NULL;

    /* skip outer sequence */
    if (rc == 0) {
	rc = skipSequence(tmpAddedToCertIndex, tmpAddedToCert);
    }
    /* skip version */
    if (rc == 0) {
	rc = copyType(0xa0, NULL, NULL, 		/* NULL says to skip */
		      tmpAddedToCertIndex, tmpAddedToCert);
    }
    /* get integer serial number from addedToCertificate */
    if (rc == 0) {
	rc = getInteger(&integerLength, x509SerialBin,
			tmpAddedToCertIndex, tmpAddedToCert);
    }
    /* convert the integer stream to a BIGNUM */
    if (rc == 0) {
	x509SerialBN = BN_bin2bn(x509SerialBin, integerLength, x509SerialBN); 	/* freed @1 */
	if (x509SerialBN == NULL) {
	    printf("addSerialNumber: Error in serial number BN_bin2bn\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* add it into the final certificate */
    if (rc == 0) {
	/* get the serial number structure member, can't fail */
	x509Serial = X509_get_serialNumber(x509Certificate);
	/* convert the BIGNUM to ASN1 and add to X509 certificate */
	x509Serial = BN_to_ASN1_INTEGER(x509SerialBN, x509Serial);
	if (x509Serial == NULL) {
	    printf("addSerialNumber: Error setting certificate serial number\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    if (x509SerialBN != NULL) BN_clear_free(x509SerialBN );		/* @1 */
    return rc;
}

/* addPubKeyRsa() adds the public key to the certificate. tmpAddedToCertIndex must point to the
   public key.
 */

TPM_RC addPubKeyRsa(X509 		*x509Certificate,
		    unsigned char 	*tmpAddedToCert,
		    uint16_t 		*tmpAddedToCertIndex)
{
    TPM_RC 			rc = 0;
    TPM2B_PUBLIC_KEY_RSA 	tpm2bRsa;
    uint16_t 			dataLength;

    /* skip the SEQUENCE with the Signature Algorithm object identifier */
    if (rc == 0) {
	rc = copyType(0x30, NULL, NULL, 		/* NULL says to skip */
		      tmpAddedToCertIndex, tmpAddedToCert);
    }
    /* skip the SEQUENCE wrapper for the Subject Public Key Info */
    if (rc == 0) {
	rc = skipSequence(tmpAddedToCertIndex, tmpAddedToCert);
    }
    /* skip the SEQUENCE Public Key Algorithm */
    if (rc == 0) {
	rc = copyType(0x30, NULL, NULL, 		/* NULL says to skip */
		      tmpAddedToCertIndex, tmpAddedToCert);
    }
    /* skip the BIT STRING intoduction to the public key */
    if (rc == 0) {
	rc = skipBitString(&dataLength, tmpAddedToCertIndex, tmpAddedToCert);
    }
    /* skip the SEQUENCE wrapper for the public key */
    if (rc == 0) {
	rc = skipSequence(tmpAddedToCertIndex, tmpAddedToCert);
    }
    /* get the integer public modulus FIXME missing length check */
    if (rc == 0) {
	rc = getInteger(&tpm2bRsa.t.size, tpm2bRsa.t.buffer,
			tmpAddedToCertIndex, tmpAddedToCert);
    }
    if (rc == 0) {
	rc = addCertKeyRsa(x509Certificate,
			   &tpm2bRsa);	/* certified public key */
    }
    /* skip the INTEGER public exponent - should not matter since it's the last item */
    /* FIXME test for 010001 */
    if (rc == 0) {
	uint16_t dummy;
	rc = getInteger(&dummy, NULL,
			tmpAddedToCertIndex, tmpAddedToCert);
    }
    return rc;
}

/* addPubKeyEcc() adds the public key to the certificate. tmpAddedToCertIndex must point to the
   public key.
*/


TPM_RC addPubKeyEcc(X509 		*x509Certificate,
		    unsigned char 	*tmpAddedToCert,
		    uint16_t 		*tmpAddedToCertIndex)
{
    TPM_RC 		rc = 0;
    uint16_t 		dataLength;
    TPMS_ECC_POINT 	tpmsEccPoint;

    /* skip the SEQUENCE with the Signature Algorithm object identifier ecdsaWithSHA256 */
    if (rc == 0) {
	rc = copyType(0x30, NULL, NULL, 		/* NULL says to skip */
		      tmpAddedToCertIndex, tmpAddedToCert);
    }
    /* skip the SEQUENCE wrapper for the Subject Public Key Info */
    if (rc == 0) {
	rc = skipSequence(tmpAddedToCertIndex, tmpAddedToCert);
    }
    /* skip the SEQUENCE Public Key Algorithm */
    if (rc == 0) {
	rc = copyType(0x30, NULL, NULL, 		/* NULL says to skip */
		      tmpAddedToCertIndex, tmpAddedToCert);
    }
    /* skip the BIT STRING intoduction to the public key */
    if (rc == 0) {
	rc = skipBitString(&dataLength, tmpAddedToCertIndex, tmpAddedToCert);
    }
    /* the next bytes are the 04, x and y */
    if (rc == 0) {

	/* FIXME check that dataLength is 65 */

	*tmpAddedToCertIndex += 1;	/* skip the 0x04 compression byte */

	tpmsEccPoint.x.t.size = 32;	
	memcpy(tpmsEccPoint.x.t.buffer, tmpAddedToCert +  *tmpAddedToCertIndex, 32);	
	*tmpAddedToCertIndex += 32;

	tpmsEccPoint.y.t.size = 32;	
	memcpy(tpmsEccPoint.y.t.buffer, tmpAddedToCert +  *tmpAddedToCertIndex, 32);	
	*tmpAddedToCertIndex += 32;

	rc = addCertKeyEcc(x509Certificate, &tpmsEccPoint);
    }
    return rc;
}

/* addSignatureRsa() copies the TPMT_SIGNATURE output of the TPM2_CertifyX509 command to the X509
   certificate.
 */

TPM_RC addSignatureRsa(X509 		*x509Certificate,
		       TPMT_SIGNATURE 	*tSignature)
{
    TPM_RC 		rc = 0;
    int 		irc;
    X509_ALGOR 		*signatureAlgorithm = NULL;
    X509_ALGOR 		*certSignatureAlgorithm = NULL;
    ASN1_BIT_STRING 	*asn1Signature = NULL;
    
    /* FIXME check sign length */
    
    if (rc == 0) {
	certSignatureAlgorithm = (X509_ALGOR *)X509_get0_tbs_sigalg(x509Certificate);
	X509_get0_signature((OSSLCONST ASN1_BIT_STRING**)&asn1Signature,
			    (OSSLCONST X509_ALGOR **)&signatureAlgorithm,
			    x509Certificate);
    }
    /* set the algorithm in the top level structure */
    if (rc == 0) {
	X509_ALGOR_set0(signatureAlgorithm,
			OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL, NULL);
    }
    /* set the algorithm in the to be signed structure */
    if (rc == 0) {
	X509_ALGOR_set0(certSignatureAlgorithm,
			OBJ_nid2obj(NID_sha256WithRSAEncryption), V_ASN1_NULL, NULL);
    }
    /* ASN1_BIT_STRING x509Certificate->signature contains a BIT STRING with the RSA signature */
    if (rc == 0) {
	irc = ASN1_BIT_STRING_set(asn1Signature,
				  tSignature->signature.rsassa.sig.t.buffer,
				  tSignature->signature.rsassa.sig.t.size);
	asn1Signature->flags &= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
	asn1Signature->flags |= ASN1_STRING_FLAG_BITS_LEFT;
	if (irc == 0) {
	    printf("addSignatureRsa: Error in ASN1_BIT_STRING_set for signature\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    return rc;
}

/* addSignatureEcc() copies the TPMT_SIGNATURE output of the TPM2_CertifyX509 command to the X509
   certificate.
*/

TPM_RC addSignatureEcc(X509 		*x509Certificate,
		       TPMT_SIGNATURE 	*tSignature)
{
    TPM_RC 		rc = 0;
    int 		irc;
    X509_ALGOR 		*signatureAlgorithm = NULL;
    X509_ALGOR 		*certSignatureAlgorithm = NULL;
    ASN1_BIT_STRING 	*asn1Signature = NULL;
    BIGNUM 		*rSig = NULL;
    BIGNUM 		*sSig = NULL;
    ECDSA_SIG 		*ecdsaSig = NULL;
    unsigned char 	*ecdsaSigBin = NULL;
    int 		ecdsaSigBinLength;

    /* FIXME check sign length */
    
    if (rc == 0) {
	certSignatureAlgorithm = (X509_ALGOR *)X509_get0_tbs_sigalg(x509Certificate);
	X509_get0_signature((OSSLCONST ASN1_BIT_STRING**)&asn1Signature,
			    (OSSLCONST X509_ALGOR **)&signatureAlgorithm,
			    x509Certificate);
    }
    /* set the algorithm in the top level structure */
    if (rc == 0) {
	X509_ALGOR_set0(signatureAlgorithm,
			OBJ_nid2obj(NID_ecdsa_with_SHA256), V_ASN1_UNDEF, NULL);
    }
    /* set the algorithm in the to be signed structure */
    if (rc == 0) {
	X509_ALGOR_set0(certSignatureAlgorithm,
			OBJ_nid2obj(NID_ecdsa_with_SHA256), V_ASN1_UNDEF, NULL);
    }
    /* ASN1_BIT_STRING x509Certificate->signature contains a sequence with two INTEGER, R and S */
    /* construct DER and then ASN1_BIT_STRING_set into X509 */
    if (rc == 0) {
	rSig = BN_new();
	if (rSig == NULL) {
	    printf("addSignatureEcc: BN_new() failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	sSig = BN_new();
	if (sSig == NULL) {
	    printf("addSignatureEcc: BN_new() failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
        rSig = BN_bin2bn(tSignature->signature.ecdsa.signatureR.b.buffer,
			 tSignature->signature.ecdsa.signatureR.b.size, rSig);
        if (rSig == NULL) {
            printf("addSignatureEcc: Error in BN_bin2bn\n");
            rc = TSS_RC_BIGNUM;
        }
    }
    if (rc == 0) {
        sSig = BN_bin2bn(tSignature->signature.ecdsa.signatureS.b.buffer,
			 tSignature->signature.ecdsa.signatureS.b.size, sSig);
        if (sSig == NULL) {
            printf("addSignatureEcc: Error in BN_bin2bn\n");
            rc = TSS_RC_BIGNUM;
        }
    }
    if (rc == 0) {
	ecdsaSig = ECDSA_SIG_new();		/* freed @1 */
	if (ecdsaSig == NULL) {
	    printf("addSignatureEcc: ECDSA_SIG_new() failed\n");
	    rc = TSS_RC_OUT_OF_MEMORY;
	}
    }
    if (rc == 0) {
	irc = ECDSA_SIG_set0(ecdsaSig, rSig, sSig);
	if (irc != 1) {
	    printf("addSignatureEcc: Error in ECDSA_SIG_set0\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* serialize the signature to DER */
    if (rc == 0) {
	ecdsaSigBinLength = i2d_ECDSA_SIG(ecdsaSig, &ecdsaSigBin);	/* freed @2 */
	if (ecdsaSigBinLength < 0) {
	    printf("addSignatureEcc: Error in signature serialization i2d_ECDSA_SIG()\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* add the DER signature to the certificate */
    if (rc == 0) {
	irc = ASN1_BIT_STRING_set(asn1Signature,
				  ecdsaSigBin,
				  ecdsaSigBinLength);
	asn1Signature->flags&= ~(ASN1_STRING_FLAG_BITS_LEFT|0x07);
	asn1Signature->flags|=ASN1_STRING_FLAG_BITS_LEFT;
	if (irc == 0) {
	    printf("addSignatureEcc: Error in ASN1_BIT_STRING_set for signature\n");
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* freed by ECDSA_SIG_free */
    if (ecdsaSig == NULL) {
	BN_free(rSig);
	BN_free(sSig);
    }
    ECDSA_SIG_free(ecdsaSig);		/* @1 */
    OPENSSL_free(ecdsaSigBin);		/* @2 */
    return rc;
}

/* getDataLength() checks the type, gets the length of the wrapper and following data */

TPM_RC getDataLength(uint8_t type,			/* expected type */
		       uint16_t *wrapperLength,		/* wrapper */
		       uint16_t *dataLength,		/* data */
		       uint16_t *certificateDerIndex,
		       uint8_t *certificateDer)
{
    TPM_RC 	rc = 0;
    uint32_t	i = 0;
    uint16_t	lengthLength = 0;	/* number of length bytes */

    /* validate the wrapper type */
    if (rc == 0) {
	if (certificateDer[*certificateDerIndex] != type) {
	    printf("getDataLength: index %u expect %02x actual %02x\n",
		   *certificateDerIndex, type, certificateDer[*certificateDerIndex]);
	    rc = TSS_RC_X509_ERROR;
	}
    }
    /* get the length */
    if (rc == 0) {
	/* long form length starts with the 'length of the length' */
	if ((certificateDer[*certificateDerIndex + 1] & 0x80)) {
	    lengthLength = certificateDer[*certificateDerIndex + 1] & 0x7f;
	    if (lengthLength <= sizeof(*dataLength)) {

		*dataLength = 0;
		for (i = 0 ; i < lengthLength ; i++) {
		    *dataLength <<= (i * 8);
		    *dataLength += certificateDer[*certificateDerIndex + 2 + i];
		}
	    }
	    else {
		printf("getDataLength: lengthLength %u too large for uint16_t\n", lengthLength);
		rc = TSS_RC_X509_ERROR;
	    }
	}
	/* short form length is in byte following type */
	else {
	    *dataLength = certificateDer[*certificateDerIndex + 1] & 0x7f;
	}
    }
    if (rc == 0) {
	*wrapperLength = 2 + lengthLength;
	if (verbose) printf("getDataLength: wrapperLength %u dataLength %u\n",
			    *wrapperLength, *dataLength);
    }
    return rc;
}

/* skipSequence() moves the certificateDerIndex past the SEQUENCE and its length.  I.e., it just
   skips the wrapper, not the contents
*/

TPM_RC skipSequence(uint16_t *certificateDerIndex, uint8_t *certificateDer)
{
    TPM_RC 	rc = 0;
    uint16_t 	wrapperLength;
    uint16_t 	dataLength;

    if (rc == 0) {
	rc = getDataLength(0x30,		/* variable length SEQUENCE */
			   &wrapperLength,
			   &dataLength,
			   certificateDerIndex, certificateDer);
    }
    if (rc == 0) {
	*certificateDerIndex += wrapperLength;
    }
    return rc;
}

/* skipBitString() moves the certificateDerIndex past the BIT STRING, its length, and its padding,
   not the contents
*/

TPM_RC skipBitString(uint16_t *dataLength,
		     uint16_t *certificateDerIndex, uint8_t *certificateDer)
{
    TPM_RC 	rc = 0;
    uint16_t 	wrapperLength;

    if (rc == 0) {
	rc = getDataLength(0x03,		/* BIT STRING */
			   &wrapperLength,  
			   dataLength,
			   certificateDerIndex, certificateDer);
    }
    if (rc == 0) {
	*certificateDerIndex += wrapperLength;
	*certificateDerIndex += 1;	/* BIT STRING padding */
    }
    return rc;
}

/* copyType() copies the type at certificateDerIndex to partialCertificateDer.

   certificateDerIndex and partialCertificateDerLength are updated
*/

TPM_RC copyType(uint8_t type,			/* expected type */
		  uint16_t *partialCertificateDerLength, uint8_t *partialCertificateDer,
		  uint16_t *certificateDerIndex, uint8_t *certificateDer)
{
    TPM_RC 	rc = 0;
    uint16_t 	wrapperLength = 0;
    uint16_t 	dataLength = 0;

    if (rc == 0) {
	rc = getDataLength(type,
			   &wrapperLength,  
			   &dataLength,
			   certificateDerIndex, certificateDer);
    }
    if (rc == 0) {
	if (partialCertificateDer != NULL) {
	    memcpy(partialCertificateDer + *partialCertificateDerLength,
		   &(certificateDer[*certificateDerIndex]),
		   wrapperLength + dataLength);
	    *partialCertificateDerLength += wrapperLength + dataLength;
	}
	*certificateDerIndex += wrapperLength + dataLength;
    }
    return rc;
}

/* getInteger() copies the INTEGER data (not including the wrapper) to integerStream.

   certificateDerIndex is updated.
*/

TPM_RC getInteger(uint16_t *integerDataLength, unsigned char *integerStream,
		    uint16_t *certificateDerIndex, unsigned char *certificateDer)
{
    TPM_RC 	rc = 0;
    uint16_t 	wrapperLength = 0;

    if (rc == 0) {
	rc = getDataLength(0x02,		/* INTEGER */
			   &wrapperLength,  
			   integerDataLength,
			   certificateDerIndex, certificateDer);
    }
    if (rc == 0) {
	if (integerStream != NULL) {
	    memcpy(integerStream,
		   certificateDer + *certificateDerIndex + wrapperLength,
		   *integerDataLength);
	}
	*certificateDerIndex += wrapperLength + *integerDataLength;
    }
    return rc;
}

/* prependSequence() shifts the DER down and back fills the SEQUENCE and length */

TPM_RC prependSequence(uint16_t *partialCertificateDerLength, uint8_t *partialCertificateDer)
{
    TPM_RC 	rc = 0;
    uint16_t	prefixLength;
    uint16_t	lengthLength = 0;
    uint16_t	i = 0;

    if (verbose) printf("prependSequence: total length %u %04x\n",
			*partialCertificateDerLength, *partialCertificateDerLength);
    /* calculate the number of prepended bytes */
    if (rc == 0) {
	/* long form length when greater than 7f */
	if ((*partialCertificateDerLength) > 0x7f) {
	    lengthLength = (*partialCertificateDerLength / 0x100) + 1;	/* +1 to round up */
	    prefixLength = 2 + lengthLength;	/* SEQUENCE + length of length + length bytes */
	}
	/* short form length when up to 7f */
	else {
	    prefixLength = 2;	/* SEQUENCE + length byte */
	}
    }
    /* shift the partialCertificateDer down by prefix length */
    if (rc == 0) {
	memmove(partialCertificateDer + prefixLength,
		partialCertificateDer,
		*partialCertificateDerLength);
    }
    /* construct the prefix */
    if (rc == 0) {
	partialCertificateDer[0] = 0x30; 	/* SEQUENCE */
	/* long form length */
	if (lengthLength > 0) {
	    partialCertificateDer[1] = 0x80 + lengthLength; 	/* byte 1 bit 7 set for long form */
	    for (i = 0 ; i < lengthLength ; i++) {		/* start at byte 2 */
		partialCertificateDer[2 + i] =			/* add length bytes */
		    (*partialCertificateDerLength >> ((lengthLength - i - 1) * 8)) & 0xff;
	    }
	}
	/* short form length */
	else {
	    /* just length for short form, cast safe bacause of above test */
	    partialCertificateDer[1] = (uint8_t)*partialCertificateDerLength;
	}
	*partialCertificateDerLength += prefixLength;	/* adjust the total length of the DER */
    }
    return rc;
}

static void printUsage(void)
{
    printf("\n");
    printf("certifyx509\n");
    printf("\n");
    printf("Runs TPM2_Certifyx509\n");
    printf("\n");
    printf("\t-ho\tobject handle\n");
    printf("\t[-pwdo\tpassword for object (default empty)]\n");
    printf("\t-hk\tcertifying key handle\n");
    printf("\t[-pwdk\tpassword for key (default empty)]\n");
    printf("\t[-halg\t(sha1, sha256, sha384 sha512) (default sha256)]\n");
    printf("\t[-salg\tsignature algorithm (rsa, ecc) (default rsa)]\n");

    printf("\t[-ku\tX509 key usage - string - comma separated, no spaces]\n");
    printf("\t[-iob\tTPMA_OBJECT - 4 byte hex]\n");
    printf("\t\te.g. sign: critical,digitalSignature,keyCertSign,cRLSign (default)\n");
    printf("\t\te.g. decrypt: critical,dataEncipherment,keyAgreement,encipherOnly,decipherOnly\n");
    printf("\t\te.g. fixedTPM: critical,nonRepudiation\n");
    printf("\t\te.g. parent (restrict decrypt): critical,keyEncipherment\n");
    
    printf("\t[-bit\tbit in partialCertificate to toggle]\n");
    printf("\t[-sub\tsubject same as issuer for self signed (root) certificate]\n");
    printf("\t[-opc\tpartial certificate file name (default do not save)]\n");
    printf("\t[-oa\taddedToCertificate file name (default do not save)]\n");
    printf("\t[-otbs\tsigned tbsDigest file name (default do not save)]\n");
    printf("\t[-os\tsignature file name (default do not save)]\n");
    printf("\t[-ocert\t reconstructed certificate file name (default do not save)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1);	
}

#endif	/* TPM_TSS_MBEDTLS */

#ifdef TPM_TSS_MBEDTLS

int verbose;

int main(int argc, char *argv[])
{
    argc = argc;
    argv = argv;
    printf("certifyx509 not supported with mbedtls yet\n");
    return 0;
}

#endif	/* TPM_TSS_MBEDTLS */
