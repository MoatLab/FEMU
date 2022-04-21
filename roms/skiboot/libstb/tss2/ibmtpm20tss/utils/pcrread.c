/********************************************************************************/
/*										*/
/*			   PCR_Read 						*/
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

/* 

 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#ifdef TPM_POSIX
#include <netinet/in.h>
#endif
#ifdef TPM_WINDOWS
#include <winsock2.h>
#endif

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tssresponsecode.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsscryptoh.h>

static void printPcrRead(PCR_Read_Out *out);
static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC			rc = 0;
    int				i;    /* argc iterator */
    TSS_CONTEXT			*tssContext = NULL;
    PCR_Read_In 		in;
    PCR_Read_Out 		out;
    TPMI_DH_PCR 		pcrHandle = IMPLEMENTATION_PCR;
    const char 			*datafilename = NULL;
    TPMI_ALG_HASH		ahalg = TPM_ALG_SHA256;
    uint32_t 			sizeInBytes = 0;	/* initialized to suppress false gcc -O3
							   warning */
    const char 			*sadfilename = NULL;
    int				noSpace = FALSE;
    TPMI_SH_AUTH_SESSION    	sessionHandle0 = TPM_RH_NULL;
    unsigned int		sessionAttributes0 = 0;
   
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    in.pcrSelectionIn.count = 0xffffffff;

    /* command line argument defaults */
    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-ha") == 0) {
	    i++;
	    if (i < argc) {
		sscanf(argv[i],"%u", &pcrHandle);
	    }
	    else {
		printf("Missing parameter for -ha\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-halg") == 0) {
	    if (in.pcrSelectionIn.count == 0xffffffff) {
		in.pcrSelectionIn.count = 1;
	    }
	    else {
		in.pcrSelectionIn.count++;
	    }
	    if (in.pcrSelectionIn.count > HASH_COUNT) {
		printf("Too many -halg specifiers, %u permitted\n", HASH_COUNT);
		printUsage();
	    }
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    in.pcrSelectionIn.pcrSelections[in.pcrSelectionIn.count-1].hash = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    in.pcrSelectionIn.pcrSelections[in.pcrSelectionIn.count-1].hash = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    in.pcrSelectionIn.pcrSelections[in.pcrSelectionIn.count-1].hash = TPM_ALG_SHA384;
		}
		else if (strcmp(argv[i],"sha512") == 0) {
		    in.pcrSelectionIn.pcrSelections[in.pcrSelectionIn.count-1].hash = TPM_ALG_SHA512;
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
	else if (strcmp(argv[i],"-ahalg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    ahalg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    ahalg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    ahalg = TPM_ALG_SHA384;
		}
		else if (strcmp(argv[i],"sha512") == 0) {
		    ahalg = TPM_ALG_SHA512;
		}
		else {
		    printf("Bad parameter %s for -ahalg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("-halg option needs a value\n");
		printUsage();
	    }
	}
 	else if (strcmp(argv[i], "-of")  == 0) {
	    i++;
	    if (i < argc) {
		datafilename = argv[i];
	    } else {
		printf("-of option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-iosad")  == 0) {
	    i++;
	    if (i < argc) {
		sadfilename = argv[i];
	    } else {
		printf("-iosad option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-ns") == 0) {
	    noSpace = TRUE;
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
    if (pcrHandle >= IMPLEMENTATION_PCR) {
	printf("Missing or bad PCR handle parameter -ha\n");
	printUsage();
    }
    /* handle default hash algorithm */
    if (in.pcrSelectionIn.count == 0xffffffff) {	/* if none specified */
	in.pcrSelectionIn.count = 1;
	in.pcrSelectionIn.pcrSelections[0].hash = TPM_ALG_SHA256;
    }
    if (rc == 0) {
	uint16_t c;
	/* Table 102 - Definition of TPML_PCR_SELECTION Structure */
	/* Table 85 - Definition of TPMS_PCR_SELECTION Structure */
	for (c = 0 ; c < in.pcrSelectionIn.count ; c++) {
	    in.pcrSelectionIn.pcrSelections[c].sizeofSelect = 3;
	    in.pcrSelectionIn.pcrSelections[c].pcrSelect[0] = 0;
	    in.pcrSelectionIn.pcrSelections[c].pcrSelect[1] = 0;
	    in.pcrSelectionIn.pcrSelections[c].pcrSelect[2] = 0;
	    in.pcrSelectionIn.pcrSelections[c].pcrSelect[pcrHandle / 8] = 1 << (pcrHandle % 8);
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
			 TPM_CC_PCR_Read,
			 sessionHandle0, NULL, sessionAttributes0,
			 TPM_RH_NULL, NULL, 0);
    }
    {
	TPM_RC rc1 = TSS_Delete(tssContext);
	if (rc == 0) {
	    rc = rc1;
	}
    }
    /* first hash algorithm, in binary */
    if (rc != 0) {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("pcrread: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    if ((rc == 0) && (datafilename != NULL) && (out.pcrValues.count != 0)) {
	rc = TSS_File_WriteBinaryFile(out.pcrValues.digests[0].t.buffer,
				      out.pcrValues.digests[0].t.size,
				      datafilename);
    }
    /* auth session hash algorithm for cpHash and rpHash */
    if (rc == 0) {
        sizeInBytes = TSS_GetDigestSize(ahalg);
    }
    /* option to output cpHash and rpHash to test session audit of PCR Read */
    if (sadfilename != NULL) {
	TPMT_HA 	cpHash;
	uint8_t 	cpBuffer [MAX_COMMAND_SIZE];
	uint16_t 	cpBufferSize = 0;
	TPMT_HA 	rpHash;
	uint8_t 	rpBuffer [MAX_RESPONSE_SIZE];
	uint16_t 	rpBufferSize = 0;
	uint8_t 	*tmpptr;
	uint32_t 	tmpsize;
	TPMT_HA 	sessionDigest;
	uint8_t		*sessionDigestData = NULL;
	size_t		sessionDigestSize;
	/* calculate cpHash from CC || parameters */
	if (rc == 0) {
	    tmpptr = cpBuffer;
	    tmpsize = sizeof(cpBuffer);
	    rc = TSS_TPML_PCR_SELECTION_Marshalu(&in.pcrSelectionIn,
						 &cpBufferSize, &tmpptr, &tmpsize);
	}
	if (rc == 0) {
	    TPM_CC commandCode = TPM_CC_PCR_Read;
	    TPM_CC commandCodeNbo = htonl(commandCode);
	    cpHash.hashAlg = ahalg;
	    rc = TSS_Hash_Generate(&cpHash,		/* largest size of a digest */
				   sizeof(TPM_CC), &commandCodeNbo,
				   cpBufferSize, cpBuffer,
				   0, NULL);
	}
	if ((rc == 0) && tssUtilsVerbose) {
#if 0
	    TSS_PrintAll("cpBuffer", cpBuffer, cpBufferSize);
	    TSS_PrintAll("cpHash", (uint8_t *)&cpHash.digest, sizeInBytes);
#endif
	}
	/* calculate rpHash from RC || CC || parameters */
	if (rc == 0) {
	    tmpptr = rpBuffer;
	    tmpsize = sizeof(rpBuffer);
	    rc = TSS_UINT32_Marshalu(&out.pcrUpdateCounter,
				     &rpBufferSize, &tmpptr, &tmpsize);
	}
	if (rc == 0) {
	    rc = TSS_TPML_PCR_SELECTION_Marshalu(&out.pcrSelectionOut,
						 &rpBufferSize, &tmpptr, &tmpsize);
	}
	if (rc == 0) {
	    rc = TSS_TPML_DIGEST_Marshalu(&out.pcrValues,
					  &rpBufferSize, &tmpptr, &tmpsize);
	}
	if (rc == 0) {
	    TPM_CC 		commandCode = TPM_CC_PCR_Read;
	    TPM_CC 		commandCodeNbo = htonl(commandCode);
	    rpHash.hashAlg = ahalg;
	    rc = TSS_Hash_Generate(&rpHash,			/* largest size of a digest */
				   sizeof(TPM_RC), &rc,	/* RC is always 0, no need to endian
							   convert */
				   sizeof(TPM_CC), &commandCodeNbo,
				   rpBufferSize, rpBuffer,
				   0, NULL);
	}
	if ((rc == 0) && tssUtilsVerbose) {
#if 0
	    TSS_PrintAll("rpBuffer", rpBuffer, rpBufferSize);
	    TSS_PrintAll("rpHash", (uint8_t *)&rpHash.digest, sizeInBytes);
#endif
	}
	/* read the original session digest, must be initialized to all zero */
	if (rc == 0) {
	    rc = TSS_File_ReadBinaryFile(&sessionDigestData,	/* freed @1 */
					 &sessionDigestSize,
					 sadfilename);
	}
	/* sanity check the size against the session digest hash algorithm */
	if (rc == 0) {
	    if (sizeInBytes != sessionDigestSize) {
		printf("pcrread: -ahalg size %u does not match digest size %u from %s\n",
		       (unsigned int)sizeInBytes, (unsigned int)sessionDigestSize, sadfilename);
	    }
	}
	/* extend cpHash and rpHash */
	if (rc == 0) {
	    sessionDigest.hashAlg = ahalg;
	    rc = TSS_Hash_Generate(&sessionDigest,
				   sizeInBytes, sessionDigestData, 
				   sizeInBytes, (uint8_t *)&cpHash.digest,
				   sizeInBytes, (uint8_t *)&rpHash.digest,
				   0, NULL);
	}
	if ((rc == 0) && tssUtilsVerbose) {
	    TSS_PrintAll("Session digest old", sessionDigestData, sizeInBytes);
	    TSS_PrintAll("Session digest new", (uint8_t *)&sessionDigest.digest, sizeInBytes);
	}
	if (rc == 0) {
	    /* write back the result */
	    rc = TSS_File_WriteBinaryFile((uint8_t *)&sessionDigest.digest,
					  sizeInBytes,
					  sadfilename);
	}
	free(sessionDigestData);	/* @1 */
    }
    if (rc == 0) {
	/* machine readable format */
	if (noSpace) {
	    uint32_t count;
	    /* TPM can return count 0 if the requested algorithm is not allocated */
	    if (out.pcrValues.count != 0) {
		for (count = 0 ; count < out.pcrValues.count ; count++) {
		    uint32_t bp;
		    for (bp = 0 ; bp < out.pcrValues.digests[count].t.size ; bp++) {
			printf("%02x", out.pcrValues.digests[count].t.buffer[bp]);
		    }
		    printf("\n");
		}
	    }
	    else {
		printf("count %u\n", out.pcrValues.count);
	    }
	}
	/* human readable format, all hash algorithms */
	else {
	    printPcrRead(&out);
	    if (tssUtilsVerbose) printf("pcrread: success\n");
	}
    }
    return rc;
}

static void printPcrRead(PCR_Read_Out *out)
{
    uint32_t	i;
    
    /* Table 99 - Definition of TPML_DIGEST Structure */
    printf("count %u pcrUpdateCounter %u \n", out->pcrValues.count, out->pcrUpdateCounter);
    for (i = 0 ; i < out->pcrValues.count ; i++) {
	TSS_PrintAll("digest", out->pcrValues.digests[i].t.buffer, out->pcrValues.digests[i].t.size);
    }
    return;
}

static void printUsage(void)
{
    printf("\n");
    printf("pcrread\n");
    printf("\n");
    printf("Runs TPM2_PCR_Read\n");
    printf("\n");
    printf("\t-ha\tpcr handle\n");
    printf("\t-halg\t(sha1, sha256, sha384, sha512) (default sha256)\n");
    printf("\t\t-halg may be specified more than once\n");
    printf("\t[-of\tdata file for first algorithm specified, in binary]\n");
    printf("\t[-ahalg\t to extend session audit digest for testing (sha1, sha256, sha384, sha512) (default sha256)]\n");
    printf("\t[-iosad\t file for session audit digest testing]\n");
    printf("\t[-ns\tno space, no text, no newlines]\n");
    printf("\t\tUsed for scripting policy construction\n");
    printf("\n");
    printf("\t-se0 session handle / attributes (default NULL)\n");
    printf("\t01\tcontinue\n");
    printf("\t80\taudit\n");
    exit(1);	
}
