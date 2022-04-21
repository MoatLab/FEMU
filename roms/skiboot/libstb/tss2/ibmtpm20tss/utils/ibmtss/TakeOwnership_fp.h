/********************************************************************************/
/*										*/
/*			    TPM 1.2 TakeOwnership				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: TakeOwnership_fp.h 1257 2018-06-27 20:52:08Z kgoldman $	*/
/*										*/
/* (c) Copyright IBM Corporation 2018.						*/
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

#ifndef TAKEOWNERSHIP_FP_H
#define TAKEOWNERSHIP_FP_H

#include <ibmtss/tpmtypes12.h>
#include <ibmtss/tpmstructures12.h>

#include <ibmtss/Implementation.h>

typedef struct {
    TPM_PROTOCOL_ID protocolID;
    uint32_t encOwnerAuthSize;
    uint8_t encOwnerAuth[MAX_RSA_KEY_BYTES];
    uint32_t encSrkAuthSize;
    uint8_t encSrkAuth[MAX_RSA_KEY_BYTES];
    TPM_KEY12 srkParams;
} TakeOwnership_In;  

typedef struct {
    TPM_KEY12 srkPub;
} TakeOwnership_Out;  

TPM_RC
TPM2_TakeOwnership(
		   TakeOwnership_In *in,            // IN: input parameter buffer
		   TakeOwnership_Out *out           // OUT: output parameter buffer
		   );

#endif
