/********************************************************************************/
/*										*/
/*			    ZGen_2Phase						*/
/*	     		Written by Ken Goldman 					*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2017 - 2019					*/
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
#include <ibmtss/Unmarshal_fp.h>

static void printUsage(void);

extern int tssUtilsVerbose;

int main(int argc, char *argv[])
{
    TPM_RC 			rc = 0;
    int 			i;    /* argc iterator */
    TSS_CONTEXT 		*tssContext = NULL;
    ZGen_2Phase_In   		in;
    ZGen_2Phase_Out   		out;
    TPMI_DH_OBJECT      	keyHandle = 0;
    const char          	*qsbFilename = NULL;
    const char          	*qebFilename = NULL;
    const char                  *counterFilename = NULL;
    const char       		*z1Filename = NULL;
    const char          	*z2Filename = NULL;
    const char          	*keyPassword = NULL;
    TPMI_SH_AUTH_SESSION        sessionHandle0 = TPM_RS_PW;
    unsigned int                sessionAttributes0 = 0;
    TPMI_SH_AUTH_SESSION        sessionHandle1 = TPM_RH_NULL;
    unsigned int                sessionAttributes1 = 0;
    TPMI_SH_AUTH_SESSION        sessionHandle2 = TPM_RH_NULL;
    unsigned int                sessionAttributes2 = 0;
 
    setvbuf(stdout, 0, _IONBF, 0);      /* output may be going through pipe to log file */
    TSS_SetProperty(NULL, TPM_TRACE_LEVEL, "1");
    tssUtilsVerbose = FALSE;

    /* command line argument defaults */
    in.inScheme = TPM_ALG_ECDH;

    for (i=1 ; (i<argc) && (rc == 0) ; i++) {
        if (strcmp(argv[i], "-hk") == 0) {
            i++;
            if (i < argc) {
                sscanf(argv[i],"%x", &keyHandle);
            }
            else {
                printf("Missing parameter for -hk\n");
                printUsage();
            }
        }
        else if (strcmp(argv[i],"-qsb") == 0) {
            i++;
            if (i < argc) {
                qsbFilename = argv[i];
            }
            else {
                printf("-s2 option needs a value\n");
                printUsage();
            }
        }
        else if (strcmp(argv[i],"-qeb") == 0) {
            i++;
            if (i < argc) {
                qebFilename = argv[i];
            }
            else {
                printf("-qeb option needs a value\n");
                printUsage();
            }
        }
	else if (strcmp(argv[i],"-scheme") == 0) {
            i++;
	    if (i < argc) {
		if (strcmp(argv[i],"ecdh") == 0) {
		    in.inScheme = TPM_ALG_ECDH;
		}
#if 0
		else if (strcmp(argv[i],"ecmqv") == 0) {
		    in.inScheme = TPM_ALG_ECMQV;
		}
#endif
		else if (strcmp(argv[i],"sm2") == 0) {
		    in.inScheme = TPM_ALG_SM2;
		}
		else {
		    printf("Bad parameter %s for -scheme\n", argv[i]);
		    printUsage();
		}
	    }
        }
        else if (strcmp(argv[i], "-cf")  == 0) {
	    i++;
	    if (i < argc) {
		counterFilename = argv[i];
	    } else {
		printf("-cf option needs a value\n");
		printUsage();
	    }
	}
	else if (strcmp(argv[i], "-z1")  == 0) {
	    i++;
	    if (i < argc) {
		z1Filename = argv[i];
	    } else {
		printf("-z1 option needs a value\n");
		printUsage();
	    }	
	}
	else if (strcmp(argv[i], "-z2")  == 0) {
	    i++;
	    if (i < argc) {
                z2Filename = argv[i];
	    } else {
		printf("-z2 option needs a value\n");
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
    if (qsbFilename == NULL) {
	printf("Missing handle parameter -qsb\n");
	printUsage();
    }	
    if (qebFilename == NULL) {
	printf("Missing handle parameter -qeb\n");
	printUsage();
    }	
    if (counterFilename == NULL) {
	printf("Missing handle parameter -cf\n");
	printUsage();
    }	
    if (rc == 0) {
	in.keyA = keyHandle;
    }
    if (rc == 0) {
	rc = TSS_File_ReadStructure(&in.inQsB,
				    (UnmarshalFunction_t)TSS_TPM2B_ECC_POINT_Unmarshalu,
				    qsbFilename);
    }
    if (rc == 0) {
	rc = TSS_File_ReadStructure(&in.inQeB,
				    (UnmarshalFunction_t)TSS_TPM2B_ECC_POINT_Unmarshalu,
				    qebFilename);
    }
    if (rc == 0) {
	rc = TSS_File_ReadStructure(&in.counter, 
				    (UnmarshalFunction_t)TSS_UINT16_Unmarshalu,
				    counterFilename);
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
			 TPM_CC_ZGen_2Phase,
                         sessionHandle0, keyPassword, sessionAttributes0,
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
    if ((rc == 0) && (z1Filename != NULL)) {
	rc = TSS_File_WriteStructure(&out.outZ1,
				     (MarshalFunction_t)TSS_TPM2B_ECC_POINT_Marshalu,
				     z1Filename);


    }
    if ((rc == 0) && (z2Filename != NULL)) {
	rc = TSS_File_WriteStructure(&out.outZ2,
				     (MarshalFunction_t)TSS_TPM2B_ECC_POINT_Marshalu,
				     z2Filename);


    }
    if (rc == 0) {
	if (tssUtilsVerbose) printf("zgen2phase: success\n");
    }
    else {
	const char *msg;
	const char *submsg;
	const char *num;
	printf("zgen2phase: failed, rc %08x\n", rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	printf("%s%s%s\n", msg, submsg, num);
	rc = EXIT_FAILURE;
    }
    return rc;
}


static void printUsage(void)
{
    printf("\n");
    printf("zgen2phase\n");
    printf("\n");
    printf("Runs TPM2_ZGen_2Phase\n");
    printf("\n");
    printf("\t-hk\tunrestricted decryption key handle\n");
    printf("\t[-pwdk\tpassword for key (default empty)]\n");
    printf("\t-qsb\tQsB point input file name\n");
    printf("\t-qeb\tQeB point input file name\n");
    printf("\t-cf\tcounter file name\n");
    printf("\t[-scheme\t(default ecdh)]\n");
    printf("\t\tecdh\n");
    printf("\t\tecmqv\n");
    printf("\t\tsm2\n");
    printf("\t[-z1\tZ1 output data file name (default do not save)]\n");
    printf("\t[-z2\tZ2 output data file name (default do not save)]\n");
    printf("\n");
    printf("\t-se[0-2] session handle / attributes (default PWAP)\n");
    printf("\t01\tcontinue\n");
    printf("\t20\tcommand decrypt\n");
    printf("\t40\tresponse encrypt\n");
    exit(1); 
}



