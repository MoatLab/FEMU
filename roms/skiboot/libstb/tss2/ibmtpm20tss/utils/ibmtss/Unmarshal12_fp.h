/********************************************************************************/
/*										*/
/*			     Parameter Unmarshaling				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Unmarshal12_fp.h 1285 2018-07-27 18:33:41Z kgoldman $	*/
/*										*/
/* (c) Copyright IBM Corporation 2018						*/
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

#ifndef UNMARSHAL12_FP_H
#define UNMARSHAL12_FP_H

#include "TPM_Types.h"
#include "tpmtypes12.h"
#include <ibmtss/tpmstructures12.h>

#ifdef __cplusplus
extern "C" {
#endif

    TPM_RC
    TSS_TPM_STARTUP_TYPE_Unmarshalu(TPM_STARTUP_TYPE *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_VERSION_Unmarshalu(TPM_VERSION *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_TAG_Unmarshalu(TPM_TAG *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_PCR_SELECTION_Unmarshalu(TPM_PCR_SELECTION *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM4B_TPM_PCR_INFO_LONG_Unmarshalu(TPM_PCR_INFO_LONG *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_PCR_INFO_LONG_Unmarshalu(TPM_PCR_INFO_LONG *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_PCR_INFO_SHORT_Unmarshalu(TPM_PCR_INFO_SHORT *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_SYMMETRIC_KEY_Unmarshalu(TPM_SYMMETRIC_KEY *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_RSA_KEY_PARMS_Unmarshalu(TPM_RSA_KEY_PARMS *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPMU_PARMS_Unmarshalu(TPMU_PARMS *target, BYTE **buffer, uint32_t *size, uint32_t selector);
    TPM_RC
    TSS_TPM4B_TPMU_PARMS_Unmarshalu(TPMU_PARMS *target, BYTE **buffer, uint32_t *size, uint32_t selector);
    TPM_RC
    TSS_TPM_KEY_PARMS_Unmarshalu(TPM_KEY_PARMS *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_KEY12_Unmarshalu(TPM_KEY12 *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_STORE_PUBKEY_Unmarshalu(TPM_STORE_PUBKEY *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_PUBKEY_Unmarshalu(TPM_PUBKEY *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_NV_ATTRIBUTES_Unmarshalu(TPM_NV_ATTRIBUTES *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_NV_DATA_PUBLIC_Unmarshalu(TPM_NV_DATA_PUBLIC *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_CAP_VERSION_INFO_Unmarshalu(TPM_CAP_VERSION_INFO *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_DA_INFO_Unmarshalu(TPM_DA_INFO *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_DA_INFO_LIMITED_Unmarshalu(TPM_DA_INFO_LIMITED *target, BYTE **buffer, uint32_t *size);
    TPM_RC
    TSS_TPM_DA_ACTION_TYPE_Unmarshalu(TPM_DA_ACTION_TYPE *target, BYTE **buffer, uint32_t *size);

#endif
