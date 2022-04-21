/********************************************************************************/
/*										*/
/*		     	TPM2 Nuvoton Proprietary Commands			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*	      $Id: tssntc.c 1285 2018-07-27 18:33:41Z kgoldman $		*/
/*										*/
/* (c) Copyright IBM Corporation 2015, 2017					*/
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

#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tssprint.h>
#include "tssntc.h"

/* Marshal and Unmarshal Functions */

TPM_RC
TSS_NTC2_CFG_STRUCT_Unmarshalu(NTC2_CFG_STRUCT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    /* assumes that the NTC2_CFG_STRUCT structure are all uint8_t so that there are no endian
       issues */
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_Array_Unmarshalu((BYTE *)target, sizeof(NTC2_CFG_STRUCT), buffer, size);
    }
    return rc;
}
    
TPM_RC
TSS_NTC2_CFG_STRUCT_Marshal(NTC2_CFG_STRUCT *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_Array_Marshalu((BYTE *)source, sizeof(NTC2_CFG_STRUCT), written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_NTC2_PreConfig_In_Unmarshalu(NTC2_PreConfig_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[])
{
    TPM_RC rc = TPM_RC_SUCCESS;
    handles = handles;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_NTC2_CFG_STRUCT_Unmarshalu(&target->preConfig, buffer, size);	
	if (rc != TPM_RC_SUCCESS) {	
	    rc += RC_NTC2_PreConfig_preConfig;
	}
    }
    return rc;
}

TPM_RC
TSS_NTC2_PreConfig_In_Marshalu(NTC2_PreConfig_In *source, uint16_t *written, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_NTC2_CFG_STRUCT_Marshal(&source->preConfig, written, buffer, size);
    }
    return rc;
}

TPM_RC
TSS_NTC2_GetConfig_Out_Unmarshalu(NTC2_GetConfig_Out *target, TPM_ST tag, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    tag = tag;
    
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_NTC2_CFG_STRUCT_Unmarshalu(&target->preConfig, buffer, size);
    }
    return rc;
}

/* These functions are deprecated.  They were adapted from the TPM side, but the signed size
   caused static analysis tool warnings. */
    
TPM_RC
NTC2_CFG_STRUCT_Unmarshal(NTC2_CFG_STRUCT *target, BYTE **buffer, INT32 *size)
{
    return TSS_NTC2_CFG_STRUCT_Unmarshalu(target, buffer, (uint32_t *)size);
}
TPM_RC
NTC2_PreConfig_In_Unmarshal(NTC2_PreConfig_In *target, BYTE **buffer, INT32 *size, TPM_HANDLE handles[])
{
    return TSS_NTC2_PreConfig_In_Unmarshalu(target, buffer, (uint32_t *)size, handles);
}
TPM_RC
TSS_NTC2_GetConfig_Out_Unmarshal(NTC2_GetConfig_Out *target, TPM_ST tag, BYTE **buffer, INT32 *size)
{
    return TSS_NTC2_GetConfig_Out_Unmarshalu(target, tag, buffer, (uint32_t *)size);
}
