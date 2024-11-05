/********************************************************************************/
/*										*/
/*		     	TPM2 Measurement Log Common Routines			*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*										*/
/* (c) Copyright IBM Corporation 2016 - 2020.					*/
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

#ifndef EVENTLIB_H
#define EVENTLIB_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ibmtss/TPM_Types.h>

#define TCG_EVENT_LEN_MAX	0x10000

#define EV_PREBOOT_CERT	  			0x00
#define EV_POST_CODE				0x01
#define	EV_UNUSED				0x02
#define EV_NO_ACTION				0x03
#define EV_SEPARATOR				0x04
#define EV_ACTION				0x05
#define EV_EVENT_TAG				0x06
#define EV_S_CRTM_CONTENTS			0x07
#define EV_S_CRTM_VERSION			0x08
#define EV_CPU_MICROCODE			0x09
#define EV_PLATFORM_CONFIG_FLAGS		0x0A
#define EV_TABLE_OF_DEVICES			0x0B
#define EV_COMPACT_HASH				0x0C
#define EV_IPL					0x0D
#define EV_IPL_PARTITION_DATA			0x0E
#define EV_NONHOST_CODE				0x0F
#define EV_NONHOST_CONFIG			0x10
#define EV_NONHOST_INFO				0x11
#define EV_OMIT_BOOT_DEVICE_EVENTS		0x12
#define EV_EFI_EVENT_BASE			0x80000000
#define EV_EFI_VARIABLE_DRIVER_CONFIG		0x80000001
#define EV_EFI_VARIABLE_BOOT			0x80000002
#define EV_EFI_BOOT_SERVICES_APPLICATION	0x80000003
#define EV_EFI_BOOT_SERVICES_DRIVER		0x80000004
#define EV_EFI_RUNTIME_SERVICES_DRIVER		0x80000005
#define EV_EFI_GPT_EVENT			0x80000006
#define EV_EFI_ACTION				0x80000007
#define EV_EFI_PLATFORM_FIRMWARE_BLOB		0x80000008
#define EV_EFI_HANDOFF_TABLES			0x80000009
#define EV_EFI_HCRTM_EVENT			0x80000010 
#define EV_EFI_VARIABLE_AUTHORITY		0x800000E0

/* PCR 0-7 are the BIOS / UEFI / firmware / pre-OS PCRs, set to 10 because a Lenovo TPM 1.2 firmware
   extends PCR 0-9 */
#define TPM_BIOS_PCR	10

/* TCG_PCR_EVENT is the TPM 1.2 SHA-1 event log entry format.  It is defined in the TCG PC Client
   Specific Implementation Specification for Conventional BIOS, where it is called
   TCG_PCClientPCREventStruc.  In the PFP, it's called TCG_PCClientPCREvent.

   I renamed it to be consistent with the TPM 2.0 naming.
 */

typedef struct tdTCG_PCR_EVENT {
    uint32_t pcrIndex;
    uint32_t eventType;	
    uint8_t digest[SHA1_DIGEST_SIZE];
    uint32_t eventDataSize;
    uint8_t event[TCG_EVENT_LEN_MAX];				
} TCG_PCR_EVENT;

/* TCG_PCR_EVENT2 is the TPM 2.0 hash agile event log entry format.  It is defined in the PFP - TCG
   PC Client Platform Firmware Profile Specification.

 */

typedef struct tdTCG_PCR_EVENT2 {
    uint32_t 		pcrIndex;
    uint32_t 		eventType;
    TPML_DIGEST_VALUES	digests;
    uint32_t 		eventSize; 
    uint8_t 		event[TCG_EVENT_LEN_MAX];				
} TCG_PCR_EVENT2;

/* TCG_EfiSpecIdEventAlgorithmSize is a hash agile mapping of algorithmId to digestSize. It is part
   of the first event log entry.  It permits a parser to unmarshal an event log that contains hash
   algorithms that are unknown to the parser.  */
		
typedef struct tdTCG_EfiSpecIdEventAlgorithmSize {
    uint16_t      algorithmId;
    uint16_t      digestSize;
} TCG_EfiSpecIdEventAlgorithmSize;

/* TCG_EfiSpecIDEvent is the event field of the first TCG_PCR_EVENT entry in a hash agile TPM 2.0
   format log.

   NOTE: If vendorInfo is ever changed to less than 0xff, unmarshal needs a range check on
   vendorInfoSize.
*/

typedef struct tdTCG_EfiSpecIdEvent {
    uint8_t					signature[16];  
    uint32_t					platformClass;
    uint8_t					specVersionMinor;
    uint8_t					specVersionMajor;
    uint8_t					specErrata;
    uint8_t					uintnSize;
    uint32_t					numberOfAlgorithms;
    TCG_EfiSpecIdEventAlgorithmSize		digestSizes[HASH_COUNT];
    uint8_t					vendorInfoSize;
    uint8_t 					vendorInfo[0xff]; 
} TCG_EfiSpecIDEvent;

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TPM_TSS_NOFILE
    int TSS_EVENT_Line_Read(TCG_PCR_EVENT *event,
			    int *endOfFile,
			    FILE *inFile);

#endif /* TPM_TSS_NOFILE */
    TPM_RC TSS_EVENT_Line_Marshal(TCG_PCR_EVENT *source,
				  uint16_t *written, uint8_t **buffer, uint32_t *size);
    
    TPM_RC TSS_EVENT_Line_Unmarshal(TCG_PCR_EVENT *event, BYTE **buffer, uint32_t *size);

    TPM_RC TSS_EVENT_Line_LE_Unmarshal(TCG_PCR_EVENT *target, BYTE **buffer, uint32_t *size);

#ifndef TPM_TSS_NOCRYPTO                                                         

    TPM_RC TSS_EVENT_PCR_Extend(TPMT_HA pcrs[IMPLEMENTATION_PCR],
				TCG_PCR_EVENT *event);
#endif /* TPM_TSS_NOCRYPTO */    

    void TSS_EVENT_Line_Trace(TCG_PCR_EVENT *event);

#ifndef TPM_TSS_NOFILE
    int TSS_EVENT2_Line_Read(TCG_PCR_EVENT2 *event2,
			     int *endOfFile,
			     FILE *inFile);

#endif /* TPM_TSS_NOFILE */
    TPM_RC TSS_EVENT2_Line_Marshal(TCG_PCR_EVENT2 *source, uint16_t *written,
				   uint8_t **buffer, uint32_t *size);

    TPM_RC TSS_EVENT2_Line_LE_Marshal(TCG_PCR_EVENT2 *source, uint16_t *written,
				   uint8_t **buffer, uint32_t *size);


    TPM_RC TSS_EVENT2_Line_Unmarshal(TCG_PCR_EVENT2 *target, BYTE **buffer, uint32_t *size);

    TPM_RC TSS_EVENT2_Line_LE_Unmarshal(TCG_PCR_EVENT2 *target, BYTE **buffer, uint32_t *size);


#ifndef TPM_TSS_NOCRYPTO
    TPM_RC TSS_EVENT2_PCR_Extend(TPMT_HA pcrs[HASH_COUNT][IMPLEMENTATION_PCR],
				 TCG_PCR_EVENT2 *event2);
#endif

    void TSS_EVENT2_Line_Trace(TCG_PCR_EVENT2 *event);

    TPM_RC TSS_SpecIdEvent_Unmarshal(TCG_EfiSpecIDEvent *specIdEvent,
				     uint32_t eventSize,
				     uint8_t *event);

    void TSS_SpecIdEvent_Trace(TCG_EfiSpecIDEvent *specIdEvent);

    const char *TSS_EVENT_EventTypeToString(uint32_t eventType);

    TPM_RC TSS_UINT32LE_Marshal(const UINT32 *source, uint16_t *written,
                                BYTE **buffer, uint32_t *size);

    TPM_RC TSS_UINT16LE_Marshalu(const UINT16 *source, uint16_t *written,
                                 BYTE **buffer, uint32_t *size);

#ifdef __cplusplus
}
#endif

#endif
