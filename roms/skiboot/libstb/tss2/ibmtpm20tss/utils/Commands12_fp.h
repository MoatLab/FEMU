/********************************************************************************/
/*                                                                              */
/*                              	                                        */
/*                           Written by Ken Goldman                             */
/*                     IBM Thomas J. Watson Research Center                     */
/*            $Id: Commands12_fp.h 1257 2018-06-27 20:52:08Z kgoldman $         */
/*                                                                              */
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

#ifndef COMMANDS12_FP_H
#define COMMANDS12_FP_H

#include <ibmtss/TPM_Types.h>
#include <ibmtss/Parameters12.h>

TPM_RC
ActivateIdentity_In_Unmarshal(ActivateIdentity_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
CreateEndorsementKeyPair_In_Unmarshal(CreateEndorsementKeyPair_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
CreateWrapKey_In_Unmarshal(CreateWrapKey_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
Extend_In_Unmarshal(Extend_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
FlushSpecific_In_Unmarshal(FlushSpecific_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
GetCapability12_In_Unmarshal(GetCapability12_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
LoadKey2_In_Unmarshal(LoadKey2_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
MakeIdentity_In_Unmarshal(MakeIdentity_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
NV_DefineSpace12_In_Unmarshal(NV_DefineSpace12_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
NV_ReadValueAuth_In_Unmarshal(NV_ReadValueAuth_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
NV_ReadValue_In_Unmarshal(NV_ReadValue_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
NV_WriteValue_In_Unmarshal(NV_WriteValue_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
NV_WriteValueAuth_In_Unmarshal(NV_WriteValueAuth_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
OSAP_In_Unmarshal(OSAP_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
OwnerSetDisable_In_Unmarshal(OwnerSetDisable_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
OwnerReadInternalPub_In_Unmarshal(OwnerReadInternalPub_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
PcrRead12_In_Unmarshal(PcrRead12_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
PCR_Reset12_In_Unmarshal(PCR_Reset12_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
ReadPubek_In_Unmarshal(ReadPubek_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
Quote2_In_Unmarshal(Quote2_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
Sign12_In_Unmarshal(Sign12_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
Startup12_In_Unmarshal(Startup12_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);
TPM_RC
TakeOwnership_In_Unmarshal(TakeOwnership_In *target, BYTE **buffer, uint32_t *size, TPM_HANDLE handles[]);

#endif
