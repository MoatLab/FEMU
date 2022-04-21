/********************************************************************************/
/*										*/
/*			Return Code Hex to String     				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: returncode.c 1290 2018-08-01 14:45:24Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015 - 2017.					*/
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ibmtss/tss.h>
#include <ibmtss/tssresponsecode.h>

static void printUsage(void);

int main(int argc, char *argv[])
{
    TPM_RC rc;
    const char *msg;
    const char *submsg;
    const char *num;

    if (argc < 2) {
	printf("returncode: needs argument\n");
	return EXIT_FAILURE;
    }
    if (strcmp(argv[1], "-h") == 0) {
	printUsage();
    }	    

    rc = strtoul(argv[1], NULL, 16);
    TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
    printf("%s%s%s\n", msg, submsg, num);
    return 0;
}

static void printUsage(void)
{
    printf("\n");
    printf("Usage: returncode hex-number\n");
    printf("\n");
    printf("Returns the TPM_RC name and text for the return code\n");
    printf("\n");
    exit(1);	
}
