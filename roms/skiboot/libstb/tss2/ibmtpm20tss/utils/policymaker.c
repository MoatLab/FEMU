/********************************************************************************/
/*										*/
/*			   policymaker						*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2019					*/
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
   policymaker calculates a TPM2 policy hash

   Inputs are:

   a hash algorithm
   a file with lines in hexascii, to be extended into the policy digest, big endian

   NOTE: Empty lines (lines with just a newline character) are permitted and cause a double hash.
   This is useful for e.g. TPM2_PolicySigned when the policyRef is empty.

   Outputs are:

   if specified, a file with a binary digest
   if specified, a print of the hash

   Example input: policy command code with a command code of NV write

   0000016c00000137

   TPM2_PolicyCounterTimer is handled as a special case, where there is a double hash.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssutils.h>
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>

static void printUsage(void);
static int Format_FromHexascii(unsigned char *binary,
			       const char *string,
			       size_t length);
static int Format_ByteFromHexascii(unsigned char *byte,
				   const char *string);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC		rc = 0;
    int			i;    			/* argc iterator */
    char 		*prc = NULL;		/* pointer return code */
    const char 		*inFilename = NULL;
    const char 		*outFilename = NULL;
    int			pr = FALSE;
    int			nz = FALSE;
    int			noSpace = FALSE;
    TPMT_HA 		digest;
    /* initialized to suppress false gcc -O3 warning */
    uint32_t           	sizeInBytes = 0;	/* hash algorithm mapped to size */
    uint32_t           	startSizeInBytes = 0;	/* starting buffer for extend */
    FILE 		*inFile = NULL;
    FILE 		*outFile = NULL;

    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;
    
    /* command line defaults */
    digest.hashAlg = TPM_ALG_SHA256;

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
	if (strcmp(argv[i],"-halg") == 0) {
	    i++;
	    if (i < argc) {
		if (strcmp(argv[i],"sha1") == 0) {
		    digest.hashAlg = TPM_ALG_SHA1;
		}
		else if (strcmp(argv[i],"sha256") == 0) {
		    digest.hashAlg = TPM_ALG_SHA256;
		}
		else if (strcmp(argv[i],"sha384") == 0) {
		    digest.hashAlg = TPM_ALG_SHA384;
		}
		else if (strcmp(argv[i],"sha512") == 0) {
		    digest.hashAlg = TPM_ALG_SHA512;
		}
		else {
		    printf("Bad parameter %s for -halg\n", argv[i]);
		    printUsage();
		}
	    }
	    else {
		printf("Missing parameter for -hi\n");
		printUsage();
	    }
	    
	}
	else if (strcmp(argv[i],"-if") == 0) {
	    i++;
	    if (i < argc) {
		inFilename = argv[i];
	    }
	    else {
		printf("-if option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-of") == 0) {
	    i++;
	    if (i < argc) {
		outFilename = argv[i];
	    }
	    else {
		printf("-of option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i],"-pr") == 0) {
	    pr = TRUE;
	}
	else if (strcmp(argv[i],"-nz") == 0) {
	    nz = TRUE;
	}
	else if (strcmp(argv[i],"-ns") == 0) {
	    noSpace = TRUE;
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
    if (inFilename == NULL) {
	printf("Missing input file parameter -if\n");
	printUsage();
    }
    /* open the input file */
    if (rc == 0) {
	inFile = fopen(inFilename, "r");
	if (inFile == NULL) {
	    printf("Error opening %s for %s, %s\n", inFilename, "r", strerror(errno));
	    rc = EXIT_FAILURE;
	}
    }
    if (rc == 0) {
	sizeInBytes = TSS_GetDigestSize(digest.hashAlg);
	/* startauthsession sets session digest to zero */
	if (!nz) {
	    startSizeInBytes = sizeInBytes;
	    memset((uint8_t *)&digest.digest, 0, sizeInBytes);
	}
	else {	/* nz TRUE, start with empty buffer */
	    startSizeInBytes = 0;
	}
    }
    /* iterate through each line */
    do {
	char 		lineString[10240];		/* returned line in hex ascii */
	unsigned char 	lineBinary[5120];		/* returned line in binary */
	size_t		lineLength;			

	if (rc == 0) {
	    prc = fgets(lineString, sizeof(lineString), inFile);
	}
	if (prc != NULL) {
	    /* convert hex ascii to binary */ 
	    if (rc == 0) {
		lineLength = strlen(lineString);
		rc = Format_FromHexascii(lineBinary,
					 lineString, lineLength/2);
	    }
	    if (rc == 0) {
		/* not TPM2_PolicyCounterTimer */
		if (memcmp(lineString, "0000016d", 8) != 0) {
		    /* hash extend digest.digest with line */
		    if (rc == 0) {
			rc = TSS_Hash_Generate(&digest,
					       startSizeInBytes, (uint8_t *)&digest.digest,
					       lineLength /2, lineBinary,
					       0, NULL);
		    }
		}
		/* TPM2_PolicyCounterTimer is a special case - double hash */
		else {
		    TPMT_HA	args;
		    args.hashAlg = digest.hashAlg;
		    if (rc == 0) {
			/* args is a hash of the arguments excluding the command code */
			rc = TSS_Hash_Generate(&args,
					       (lineLength /2) -4, lineBinary +4,
					       0, NULL);
		    }
		    if (rc == 0) {
			uint8_t commandCode[] = {0x00, 0x00, 0x01, 0x6d};
			rc = TSS_Hash_Generate(&digest,
					       startSizeInBytes, (uint8_t *)&digest.digest,
					       sizeof(commandCode), commandCode,
					       startSizeInBytes, (uint8_t *)&args.digest,
					       0, NULL);
		    }
		}
	    }
	    if (rc == 0) {
		if (tssUtilsVerbose) TSS_PrintAll("intermediate policy digest",
					  (uint8_t *)&digest.digest, sizeInBytes);
	    }
	}
    }
    while ((rc == 0) && (prc != NULL));

    if ((rc == 0) && pr) {
	TSS_PrintAll("policy digest", (uint8_t *)&digest.digest, sizeInBytes);
    }
    if ((rc == 0) && noSpace) {
	unsigned int b;
	printf("policy digest:\n");
	for (b = 0 ; b < sizeInBytes ; b++) {
	    printf("%02x", *(((uint8_t *)&digest.digest) + b));
	}
	printf("\n");
    }
    /* open the output file */
    if ((rc == 0) && (outFilename != NULL)) {
	outFile = fopen(outFilename, "wb");
	if (outFile == NULL) {
	    printf("Error opening %s for %s, %s\n", outFilename , "W", strerror(errno));
	    rc = EXIT_FAILURE;
	}
    }
    if ((rc == 0) && (outFilename != NULL)) {
	fwrite((uint8_t *)&digest.digest, 1, sizeInBytes, outFile);
    }
    if (inFile != NULL) {
	fclose(inFile);
    }
    if (outFile != NULL) {
	fclose(outFile);
    }
    if (rc != 0) {
	rc = EXIT_FAILURE;
    }
    return rc;
}

/* Format_FromHexAscii() converts 'string' in hex ascii to 'binary' of 'length'

   It assumes that the string has enough bytes to accommodate the length.
*/

static int Format_FromHexascii(unsigned char *binary,
			       const char *string,
			       size_t length)
{
    int 	rc = 0;
    size_t	i;

    for (i = 0 ; (rc == 0) && (i < length) ; i++) {
	rc = Format_ByteFromHexascii(binary + i,
				     string + (i * 2));
	
    }
    return rc;
}

/* Format_ByteFromHexAscii() converts two bytes of hex ascii to one byte of binary
 */

static int Format_ByteFromHexascii(unsigned char *byte,
				   const char *string)
{
    int 	rc = 0;
    size_t	i;
    char	c;
    *byte 	= 0;
    
    for (i = 0 ; (rc == 0) && (i < 2) ; i++) {
	(*byte) <<= 4;		/* big endian, shift up the nibble */
	c = *(string + i);	/* extract the next character from the string */

	if ((c >= '0') && (c <= '9')) {
	    *byte += c - '0';
	}
	else if ((c >= 'a') && (c <= 'f')) {
	    *byte += c + 10 - 'a';
	}
	else if ((c >= 'A') && (c <= 'F')) {
	    *byte += c + 10 - 'A';
	}
	else {
	    printf("Format_ByteFromHexascii: "
		   "Error: Line has non hex ascii character: %02x %c\n", c, c);
	    rc = EXIT_FAILURE;
	}
    }
    return rc;
}


static void printUsage(void)
{
    printf("\n");
    printf("policymaker\n");
    printf("\n");
    printf("\t[-halg\thash algorithm (sha1 sha256 sha384 sha512) (default sha256)]\n");
    printf("\t[-nz\tdo not extend starting with zeros, just hash the last line]\n");
    printf("\t-if\tinput policy statements in hex ascii\n");
    printf("\t[-of\toutput file - policy hash in binary]\n");
    printf("\t[-pr\tstdout - policy hash in hex ascii]\n");
    printf("\t[-ns\tadditionally print policy hash in hex ascii on one line]\n");
    printf("\t\tUseful to paste into policy OR\n");
    printf("\n");
    exit(1);	
}
