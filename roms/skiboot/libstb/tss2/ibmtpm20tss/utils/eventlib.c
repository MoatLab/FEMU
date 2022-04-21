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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ibmtss/tssprint.h>
#include <ibmtss/Unmarshal_fp.h>
#include <ibmtss/tssmarshal.h>
#include <ibmtss/tsserror.h>
#ifndef TPM_TSS_NOCRYPTO
#include <ibmtss/tsscryptoh.h>
#include <ibmtss/tsscrypto.h>
#endif /* TPM_TSS_NOCRYPTO */
#include <ibmtss/tssutils.h>

#include "eventlib.h"

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20
static uint16_t Uint16_Convert(uint16_t in);
#endif
static uint32_t Uint32_Convert(uint32_t in);
#endif /* TPM_TSS_NOFILE */
static TPM_RC UINT16LE_Unmarshal(uint16_t *target, BYTE **buffer, uint32_t *size);
static TPM_RC UINT32LE_Unmarshal(uint32_t *target, BYTE **buffer, uint32_t *size);

static void TSS_EVENT_EventType_Trace(uint32_t eventType);
static TPM_RC TSS_SpecIdEventAlgorithmSize_Unmarshal(TCG_EfiSpecIdEventAlgorithmSize *algSize,
						     uint8_t **buffer,
						     uint32_t *size);
static void TSS_SpecIdEventAlgorithmSize_Trace(TCG_EfiSpecIdEventAlgorithmSize *algSize);
static TPM_RC TSS_TPML_DIGEST_VALUES_LE_Unmarshalu(TPML_DIGEST_VALUES *target,
						   BYTE **buffer,
						   uint32_t *size);
static TPM_RC TSS_TPMT_HA_LE_Unmarshalu(TPMT_HA *target, BYTE **buffer,
					uint32_t *size, BOOL allowNull);
static TPM_RC TSS_TPMI_ALG_HASH_LE_Unmarshalu(TPMI_ALG_HASH *target,
					      BYTE **buffer, uint32_t *size,
					      BOOL allowNull);
static TPM_RC TSS_TPM_ALG_ID_LE_Unmarshalu(TPM_ALG_ID *target,
					   BYTE **buffer, uint32_t *size);
static TPM_RC TSS_TPMT_HA_LE_Marshalu(const TPMT_HA *source, uint16_t *written,
				      BYTE **buffer, uint32_t *size);
static TPM_RC TSS_TPML_DIGEST_VALUES_LE_Marshalu(const TPML_DIGEST_VALUES *source,
						 uint16_t *written, BYTE **buffer,
						 uint32_t *size);

/* TSS_EVENT_Line_Read() reads a TPM 1.2 SHA-1 event line from a binary file inFile.

 */

#ifndef TPM_TSS_NOFILE
int TSS_EVENT_Line_Read(TCG_PCR_EVENT *event,
			int *endOfFile,
			FILE *inFile)
{
    int rc = 0;
    size_t readSize;
    *endOfFile = FALSE;

    /* read the PCR index */
    if (rc == 0) {
	readSize = fread(&(event->pcrIndex),
			 sizeof(((TCG_PCR_EVENT *)NULL)->pcrIndex), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("TSS_EVENT_Line_Read: Error, could not read pcrIndex, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->pcrIndex = Uint32_Convert(event->pcrIndex);
    }
    /* read the event type */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->eventType),
			 sizeof(((TCG_PCR_EVENT *)NULL)->eventType), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT_Line_Read: Error, could not read eventType, returned %lu\n",
		   (unsigned long) readSize);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->eventType = Uint32_Convert(event->eventType);
    }
    /* read the digest */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->digest),
			 sizeof(((TCG_PCR_EVENT *)NULL)->digest), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT_Line_Read: Error, could not read digest, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read the event data size */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->eventDataSize),
			 sizeof(((TCG_PCR_EVENT *)NULL)->eventDataSize), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT_Line_Read: Error, could not read event data size, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->eventDataSize = Uint32_Convert(event->eventDataSize);
    }
    /* bounds check the event data length */
    if (!*endOfFile && (rc == 0)) {
	if (event->eventDataSize > sizeof(((TCG_PCR_EVENT *)NULL)->event)) {
	    printf("TSS_EVENT_Line_Read: Error, event data length too big: %u\n",
		   event->eventDataSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read the event */
    if (!*endOfFile && (rc == 0)) {
	memset(event->event , 0, sizeof(((TCG_PCR_EVENT *)NULL)->event));
	readSize = fread(&(event->event),
			 event->eventDataSize, 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT_Line_Read: Error, could not read event, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    return rc;
}

#endif /* TPM_TSS_NOFILE */

/* TSS_EVENT_Line_Marshal() marshals a TCG_PCR_EVENT structure */

TPM_RC TSS_EVENT_Line_Marshal(TCG_PCR_EVENT *source,
			      uint16_t *written, uint8_t **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->pcrIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->eventType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->digest, SHA1_DIGEST_SIZE, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->eventDataSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu(source->event, source->eventDataSize, written, buffer, size);
    }
    return rc;
}

/* TSS_EVENT_Line_Unmarshal() unmarshals a TCG_PCR_EVENT2 structure

 */

TPM_RC TSS_EVENT_Line_Unmarshal(TCG_PCR_EVENT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->pcrIndex, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->eventType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->digest, SHA1_DIGEST_SIZE, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->eventDataSize, buffer, size);
    }
    if (rc == 0) {
	if (target->eventDataSize > sizeof(target->event)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->event, target->eventDataSize, buffer, size);
    }
    return rc;
}

/*
 * TSS_EVENT_Line_LE_Unmarshal() Unmarshal LE buffer into a target TCG_PCR_EVENT
*/
TPM_RC TSS_EVENT_Line_LE_Unmarshal(TCG_PCR_EVENT *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = UINT32LE_Unmarshal(&target->pcrIndex, buffer, size);
    }
    if (rc == 0) {
	rc = UINT32LE_Unmarshal(&target->eventType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->digest, SHA1_DIGEST_SIZE, buffer, size);
    }
    if (rc == 0) {
	rc = UINT32LE_Unmarshal(&target->eventDataSize, buffer, size);
    }
    if (rc == 0) {
	if (target->eventDataSize > sizeof(target->event)) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->event, target->eventDataSize, buffer, size);
    }
    return rc;
}

#ifndef TPM_TSS_NOCRYPTO
/* TSS_EVENT_PCR_Extend() extends PCR digest with the digest from the TCG_PCR_EVENT event log
   entry.
*/

TPM_RC TSS_EVENT_PCR_Extend(TPMT_HA pcrs[IMPLEMENTATION_PCR],
			    TCG_PCR_EVENT *event)
{
    TPM_RC 		rc = 0;
    
    /* validate PCR number */
    if (rc == 0) {
	if (event->pcrIndex >= IMPLEMENTATION_PCR) {
	    printf("ERROR: TSS_EVENT_PCR_Extend: PCR number %u out of range\n", event->pcrIndex);
	    rc = TSS_RC_BAD_PROPERTY_VALUE;
	}
    }
    /* process each event hash algorithm */
    if (rc == 0) {
	pcrs[event->pcrIndex].hashAlg = TPM_ALG_SHA1;	/* should already be initialized */
	if (rc == 0) {
	    rc = TSS_Hash_Generate(&pcrs[event->pcrIndex],
				   SHA1_DIGEST_SIZE, (uint8_t *)&pcrs[event->pcrIndex].digest,
				   SHA1_DIGEST_SIZE, &event->digest,
				   0, NULL);
	}
    }
    return rc;
}
#endif /* TPM_TSS_NOCRYPTO */

void TSS_EVENT_Line_Trace(TCG_PCR_EVENT *event)
{
    printf("TSS_EVENT_Line_Trace: PCR index %u\n", event->pcrIndex);
    TSS_EVENT_EventType_Trace(event->eventType);
    TSS_PrintAll("TSS_EVENT_Line_Trace: PCR",
		 event->digest, sizeof(((TCG_PCR_EVENT *)NULL)->digest));
    TSS_PrintAll("TSS_EVENT_Line_Trace: event",
		 event->event, event->eventDataSize);
    if (event->eventType == EV_IPL) {	/* this event appears to be printable strings */
	printf(" %.*s\n", event->eventDataSize, event->event);
    }
    return;
}

/* TSS_SpecIdEvent_Unmarshal() unmarshals the TCG_EfiSpecIDEvent structure.

   The size and buffer are not moved, since this is the only structure in the event.
*/

TPM_RC TSS_SpecIdEvent_Unmarshal(TCG_EfiSpecIDEvent *specIdEvent,
				 uint32_t eventSize,
				 uint8_t *event)
{
    TPM_RC	rc = 0;
    uint32_t	size = eventSize;	/* copy, because size and buffer are not moved */
    uint8_t	*buffer = event;
    uint32_t 	i;

    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(specIdEvent->signature, sizeof(specIdEvent->signature),
			     &buffer, &size);
    }
    if (rc == 0) {
	rc = UINT32LE_Unmarshal(&(specIdEvent->platformClass), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->specVersionMinor), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->specVersionMajor), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->specErrata), &buffer, &size);
    }
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->uintnSize), &buffer, &size);
    }
    if (rc == 0) {
	rc = UINT32LE_Unmarshal(&(specIdEvent->numberOfAlgorithms), &buffer, &size);
    }
    for (i = 0 ; (rc == 0) && (i < specIdEvent->numberOfAlgorithms) ; i++) {
	rc = TSS_SpecIdEventAlgorithmSize_Unmarshal(&(specIdEvent->digestSizes[i]),
						    &buffer, &size);
    }	    
    if (rc == 0) {
	rc = TSS_UINT8_Unmarshalu(&(specIdEvent->vendorInfoSize), &buffer, &size);
    }
#if 0	/* NOTE: Can never fail because vendorInfoSize is uint8_t and vendorInfo is 0xff bytes */
    if (rc == 0) {
	if (specIdEvent->vendorInfoSize > sizeof(specIdEvent->vendorInfo)) {
	    rc = TPM_RC_SIZE;
	}
    }    
#endif
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu(specIdEvent->vendorInfo, specIdEvent->vendorInfoSize,
			     &buffer, &size);
    }
    return rc;
}

/* TSS_SpecIdEventAlgorithmSize_Unmarshal() unmarshals the TCG_EfiSpecIdEventAlgorithmSize
   structure */

static TPM_RC TSS_SpecIdEventAlgorithmSize_Unmarshal(TCG_EfiSpecIdEventAlgorithmSize *algSize,
						     uint8_t **buffer,
						     uint32_t *size)
{
    TPM_RC	rc = 0;

    if (rc == 0) {
	rc = UINT16LE_Unmarshal(&(algSize->algorithmId), buffer, size);
    }
    if (rc == 0) {
	rc = UINT16LE_Unmarshal(&(algSize->digestSize), buffer, size);
    } 
    if (rc == 0) {
	uint16_t mappedDigestSize = TSS_GetDigestSize(algSize->algorithmId);
	if (mappedDigestSize != 0) {
	    if (mappedDigestSize != algSize->digestSize) {
		printf("TSS_SpecIdEventAlgorithmSize_Unmarshal: "
		       "Error, inconsistent digest size, algorithm %04x size %u\n",
		       algSize->algorithmId, algSize->digestSize);
		rc = TSS_RC_BAD_PROPERTY_VALUE;
	    }
	}
    }
    return rc;
}

void TSS_SpecIdEvent_Trace(TCG_EfiSpecIDEvent *specIdEvent)
{
    uint32_t 	i;

    /* normal case */
    if (specIdEvent->signature[15] == '\0')  {
	printf("TSS_SpecIdEvent_Trace: signature: %s\n", specIdEvent->signature);
    }
    /* error case */
    else {
	TSS_PrintAll("TSS_SpecIdEvent_Trace: signature",
		     specIdEvent->signature, sizeof(specIdEvent->signature));
    }
    printf("TSS_SpecIdEvent_Trace: platformClass %08x\n", specIdEvent->platformClass);
    printf("TSS_SpecIdEvent_Trace: specVersionMinor %02x\n", specIdEvent->specVersionMinor);
    printf("TSS_SpecIdEvent_Trace: specVersionMajor %02x\n", specIdEvent->specVersionMajor);
    printf("TSS_SpecIdEvent_Trace: specErrata %02x\n", specIdEvent->specErrata);
    printf("TSS_SpecIdEvent_Trace: uintnSize %02x\n", specIdEvent->uintnSize);
    printf("TSS_SpecIdEvent_Trace: numberOfAlgorithms %u\n", specIdEvent->numberOfAlgorithms);
    for (i = 0 ; (i < specIdEvent->numberOfAlgorithms) ; i++) {
	TSS_SpecIdEventAlgorithmSize_Trace(&(specIdEvent->digestSizes[i]));
    }
    /* try for a printable string */
    if (specIdEvent->vendorInfo[specIdEvent->vendorInfoSize-1] == '\0')  {
	printf("TSS_SpecIdEvent_Trace: vendorInfo: %s\n", specIdEvent->vendorInfo);
    }
    /* if not, trace the bytes */
    else {
	TSS_PrintAll("TSS_SpecIdEvent_Trace: vendorInfo",
		     specIdEvent->vendorInfo, specIdEvent->vendorInfoSize);
    }
    return;
}

static void TSS_SpecIdEventAlgorithmSize_Trace(TCG_EfiSpecIdEventAlgorithmSize *algSize)
{
    printf("TSS_SpecIdEventAlgorithmSize_Trace: algorithmId %04x\n", algSize->algorithmId);
    printf("TSS_SpecIdEventAlgorithmSize_Trace: digestSize %u\n", algSize->digestSize);
    return;
}

#ifdef TPM_TPM20
#ifndef TPM_TSS_NOFILE

/* TSS_EVENT2_Line_Read() reads a TPM2 event line from a binary file inFile.

*/

int TSS_EVENT2_Line_Read(TCG_PCR_EVENT2 *event,
			 int *endOfFile,
			 FILE *inFile)
{
    int rc = 0;
    size_t readSize;
    uint32_t maxCount; 
    uint32_t count;

    *endOfFile = FALSE;
    /* read the PCR index */
    if (rc == 0) {
	readSize = fread(&(event->pcrIndex),
			 sizeof(((TCG_PCR_EVENT2 *)NULL)->pcrIndex), 1, inFile);
	if (readSize != 1) {
	    if (feof(inFile)) {
		*endOfFile = TRUE;
	    }
	    else {
		printf("TSS_EVENT2_Line_Read: Error, could not read pcrIndex, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->pcrIndex = Uint32_Convert(event->pcrIndex);
    }
    /* read the event type */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->eventType),
			 sizeof(((TCG_PCR_EVENT2 *)NULL)->eventType), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT2_Line_Read: Error, could not read eventType, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->eventType = Uint32_Convert(event->eventType);
    }
    /* read the TPML_DIGEST_VALUES count */
    if (!*endOfFile && (rc == 0)) {
	maxCount = sizeof((TPML_DIGEST_VALUES *)NULL)->digests / sizeof(TPMT_HA);
	readSize = fread(&(event->digests.count),
			 sizeof(((TPML_DIGEST_VALUES *)NULL)->count), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT2_Line_Read: Error, could not read digest count, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->digests.count = Uint32_Convert(event->digests.count);
    }
    /* range check the digest count */
    if (!*endOfFile && (rc == 0)) {
	if (event->digests.count > maxCount) {
	    printf("TSS_EVENT2_Line_Read: Error, digest count %u is greater than structure %u\n",
		   event->digests.count, maxCount);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
	else if (event->digests.count == 0) {
	    printf("TSS_EVENT2_Line_Read: Error, digest count is zero\n");
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read all the TPMT_HA, loop through all the digest algorithms */
    for (count = 0 ; !*endOfFile && (count < event->digests.count) ; count++) {
	uint16_t digestSize;
	/* read the digest algorithm */
	if (rc == 0) {
	    readSize = fread(&(event->digests.digests[count].hashAlg),
			     sizeof((TPMT_HA *)NULL)->hashAlg, 1, inFile);
	    if (readSize != 1) {
		printf("TSS_EVENT2_Line_Read: "
		       "Error, could not read digest algorithm, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
	/* do the endian conversion of the hash algorithm from stream to uint16_t */
	if (rc == 0) {
	    event->digests.digests[count].hashAlg =
		Uint16_Convert(event->digests.digests[count].hashAlg);
	}
	/* map from the digest algorithm to the digest length */
	if (rc == 0) {
	    digestSize = TSS_GetDigestSize(event->digests.digests[count].hashAlg);
	    if (digestSize == 0) {
		printf("TSS_EVENT2_Line_Read: Error, unknown digest algorithm %04x*\n",
		       event->digests.digests[count].hashAlg);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
	/* read the digest */
	if (rc == 0) {
	    readSize = fread((uint8_t *)&(event->digests.digests[count].digest),
			     digestSize, 1, inFile);
	    if (readSize != 1) {
		printf("TSS_EVENT2_Line_Read: Error, could not read digest, returned %lu\n",
		       (unsigned long)readSize);
		rc = TSS_RC_INSUFFICIENT_BUFFER;
	    }
	}
    }
    /* read the event size */
    if (!*endOfFile && (rc == 0)) {
	readSize = fread(&(event->eventSize),
			 sizeof(((TCG_PCR_EVENT2 *)NULL)->eventSize), 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT2_Line_Read: Error, could not read event size, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* do the endian conversion from stream to uint32_t */
    if (!*endOfFile && (rc == 0)) {
	event->eventSize = Uint32_Convert(event->eventSize);
    }
    /* bounds check the event size */
    if (!*endOfFile && (rc == 0)) {
	if (event->eventSize > sizeof(((TCG_PCR_EVENT2 *)NULL)->event)) {
	    printf("TSS_EVENT2_Line_Read: Error, event size too big: %u\n",
		   event->eventSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    /* read the event */
    if (!*endOfFile && (event->eventSize > 0) && (rc == 0)) {
	memset(event->event , 0, sizeof(((TCG_PCR_EVENT2 *)NULL)->event));
	readSize = fread(&(event->event),
			 event->eventSize, 1, inFile);
	if (readSize != 1) {
	    printf("TSS_EVENT2_Line_Read: Error, could not read event, returned %lu\n",
		   (unsigned long)readSize);
	    rc = TSS_RC_INSUFFICIENT_BUFFER;
	}
    }
    return rc;
}
#endif /* TPM_TSS_NOFILE */

/* TSS_EVENT2_Line_Marshal() marshals a TCG_PCR_EVENT2 structure */

TPM_RC TSS_EVENT2_Line_Marshal(TCG_PCR_EVENT2 *source,
			       uint16_t *written, uint8_t **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->pcrIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->eventType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_Marshalu(&source->digests, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Marshalu(&source->eventSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu((uint8_t *)source->event, source->eventSize, written, buffer, size);
    }
    return rc;
}

/*
 * TSS_EVENT2_Line_LE_Marshal() Marshals a TSS_EVENT2 structure from HBO into LE
 * and saves to buffer.
 */
TPM_RC TSS_EVENT2_Line_LE_Marshal(TCG_PCR_EVENT2 *source, uint16_t *written,
				  uint8_t **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32LE_Marshal(&source->pcrIndex, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Marshal(&source->eventType, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_LE_Marshalu(&source->digests, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32LE_Marshal(&source->eventSize, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_Array_Marshalu((uint8_t *)source->event, source->eventSize, written, buffer, size);
    }
    return rc;
}

/* TSS_EVENT2_Line_Unmarshal() unmarshals a TCG_PCR_EVENT2 structure */


TPM_RC TSS_EVENT2_Line_Unmarshal(TCG_PCR_EVENT2 *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->pcrIndex, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->eventType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_Unmarshalu(&target->digests, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_UINT32_Unmarshalu(&target->eventSize, buffer, size);
    }
    if (rc == 0) {
	if (target->eventSize > sizeof(target->event)) {
	    rc = TPM_RC_SIZE;
	}
    }    
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->event, target->eventSize, buffer, size);
    }
    return rc;
}

/*
 * TSS_EVENT2_Line_LE_Unmarshal() Unmarshals an LE eventlog buffer and save to
 * the target TCG_PCR_EVENT2
 */
TPM_RC TSS_EVENT2_Line_LE_Unmarshal(TCG_PCR_EVENT2 *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;

    if (rc == 0) {
	rc = UINT32LE_Unmarshal(&target->pcrIndex, buffer, size);
    }
    if (rc == 0) {
	rc = UINT32LE_Unmarshal(&target->eventType, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPML_DIGEST_VALUES_LE_Unmarshalu(&target->digests, buffer, size);
    }
    if (rc == 0) {
	rc = UINT32LE_Unmarshal(&target->eventSize, buffer, size);
    }
    if (rc == 0) {
	if (target->eventSize > sizeof(target->event)) {
	    rc = TPM_RC_SIZE;
	}
    }
    if (rc == 0) {
	rc = TSS_Array_Unmarshalu((uint8_t *)target->event, target->eventSize, buffer, size);
    }
    return rc;
}

#ifndef TPM_TSS_NOCRYPTO
/* TSS_EVENT2_PCR_Extend() extends PCR digests with the digest from the TCG_PCR_EVENT2 event log
   entry.
*/

TPM_RC TSS_EVENT2_PCR_Extend(TPMT_HA pcrs[HASH_COUNT][IMPLEMENTATION_PCR],
			     TCG_PCR_EVENT2 *event2)
{
    TPM_RC 		rc = 0;
    uint32_t 		i;		/* iterator though hash algorithms */
    uint32_t 		bankNum = 0;	/* iterator though PCR hash banks */
    
    /* validate PCR number */
    if (rc == 0) {
	if (event2->pcrIndex >= IMPLEMENTATION_PCR) {
	    printf("ERROR: TSS_EVENT2_PCR_Extend: PCR number %u out of range\n", event2->pcrIndex);
	    rc = 1;
	}
    }
    /* validate event count */
    if (rc == 0) {
	uint32_t maxCount = sizeof(((TPML_DIGEST_VALUES *)NULL)->digests) / sizeof(TPMT_HA);
	if (event2->digests.count > maxCount) {
	    printf("ERROR: TSS_EVENT2_PCR_Extend: PCR count %u out of range, max %u\n",
		   event2->digests.count, maxCount);
	    rc = 1;
	}	    
    }
    /* process each event hash algorithm */
    for (i = 0; (rc == 0) && (i < event2->digests.count) ; i++) {
	/* find the matching PCR bank */
	for (bankNum = 0 ; (rc == 0) && (bankNum < event2->digests.count) ; bankNum++) {
	    if (pcrs[bankNum][0].hashAlg == event2->digests.digests[i].hashAlg) {

		uint16_t digestSize;
		if (rc == 0) {
		    digestSize = TSS_GetDigestSize(event2->digests.digests[i].hashAlg);
		    if (digestSize == 0) {
			printf("ERROR: TSS_EVENT2_PCR_Extend: hash algorithm %04hx unknown\n",
			       event2->digests.digests[i].hashAlg);
			rc = 1;
		    }
		}
		if (rc == 0) {
		    rc = TSS_Hash_Generate(&pcrs[bankNum][event2->pcrIndex],
					   digestSize,
					   (uint8_t *)&pcrs[bankNum][event2->pcrIndex].digest,
					   digestSize,
					   &event2->digests.digests[i].digest,
					   0, NULL);
		}
	    }
	}
    }
    return rc;
}
#endif /* TPM_TSS_NOCRYPTO */
#endif	/* TPM_TPM20 */

#ifndef TPM_TSS_NOFILE
#ifdef TPM_TPM20

/* Uint16_Convert() converts a little endian uint16_t (from an input stream) to host byte order
 */

static uint16_t Uint16_Convert(uint16_t in)
{
    uint16_t out = 0;
    unsigned char *inb = (unsigned char *)&in;
    
    /* little endian input */
    out = (inb[0] <<  0) |
	  (inb[1] <<  8);
    return out;
}

#endif

/* Uint32_Convert() converts a little endian uint32_t (from an input stream) to host byte order
 */

static uint32_t Uint32_Convert(uint32_t in)
{
    uint32_t out = 0;
    unsigned char *inb = (unsigned char *)&in;
    
    /* little endian input */
    out = (inb[0] <<  0) |
	  (inb[1] <<  8) |
	  (inb[2] << 16) |
	  (inb[3] << 24);
    return out;
}
#endif /* TPM_TSS_NOFILE */

/* UINT16LE_Unmarshal() unmarshals a little endian 2-byte array from buffer into a HBO uint16_t */

static TPM_RC
UINT16LE_Unmarshal(uint16_t *target, BYTE **buffer, uint32_t *size)
{
    if (*size < sizeof(uint16_t)) {
	return TPM_RC_INSUFFICIENT;
    }
    *target = ((uint16_t)((*buffer)[0]) <<  0) |
	      ((uint16_t)((*buffer)[1]) <<  8);
    *buffer += sizeof(uint16_t);
    *size -= sizeof(uint16_t);
    return TPM_RC_SUCCESS;
}

/* UINT32LE_Unmarshal() unmarshals a little endian 4-byte array from buffer into a HBO uint32_t */

static TPM_RC
UINT32LE_Unmarshal(uint32_t *target, BYTE **buffer, uint32_t *size)
{
    if (*size < sizeof(uint32_t)) {
	return TPM_RC_INSUFFICIENT;
    }
    *target = ((uint32_t)((*buffer)[0]) <<  0) |
	      ((uint32_t)((*buffer)[1]) <<  8) |
	      ((uint32_t)((*buffer)[2]) << 16) |
	      ((uint32_t)((*buffer)[3]) << 24);
    *buffer += sizeof(uint32_t);
    *size -= sizeof(uint32_t);
    return TPM_RC_SUCCESS;
}


void TSS_EVENT2_Line_Trace(TCG_PCR_EVENT2 *event)
{
    uint32_t count;
    uint16_t digestSize;
    printf("TSS_EVENT2_Line_Trace: PCR index %u\n", event->pcrIndex);
    TSS_EVENT_EventType_Trace(event->eventType);
    printf("TSS_EVENT2_Line_Trace: digest count %u\n", event->digests.count);
    for (count = 0 ; count < event->digests.count ; count++) {
	printf("TSS_EVENT2_Line_Trace: digest %u algorithm %04x\n",
	       count, event->digests.digests[count].hashAlg);
	digestSize = TSS_GetDigestSize(event->digests.digests[count].hashAlg);
	TSS_PrintAll("TSS_EVENT2_Line_Trace: PCR",
		     (uint8_t *)&event->digests.digests[count].digest, digestSize);
    }
    TSS_PrintAll("TSS_EVENT2_Line_Trace: event",
		 event->event, event->eventSize);
    return;
}

/* tables to map eventType to text */

typedef struct {
    uint32_t eventType;
    const char *text;
} EVENT_TYPE_TABLE;

const EVENT_TYPE_TABLE eventTypeTable [] = {
    {EV_PREBOOT_CERT, "EV_PREBOOT_CERT"},
    {EV_POST_CODE, "EV_POST_CODE"},
    {EV_UNUSED, "EV_UNUSED"},
    {EV_NO_ACTION, "EV_NO_ACTION"},
    {EV_SEPARATOR, "EV_SEPARATOR"},
    {EV_ACTION, "EV_ACTION"},
    {EV_EVENT_TAG, "EV_EVENT_TAG"},
    {EV_S_CRTM_CONTENTS, "EV_S_CRTM_CONTENTS"},
    {EV_S_CRTM_VERSION, "EV_S_CRTM_VERSION"},
    {EV_CPU_MICROCODE, "EV_CPU_MICROCODE"},
    {EV_PLATFORM_CONFIG_FLAGS, "EV_PLATFORM_CONFIG_FLAGS"},
    {EV_TABLE_OF_DEVICES, "EV_TABLE_OF_DEVICES"},
    {EV_COMPACT_HASH, "EV_COMPACT_HASH"},
    {EV_IPL, "EV_IPL"},
    {EV_IPL_PARTITION_DATA, "EV_IPL_PARTITION_DATA"},
    {EV_NONHOST_CODE, "EV_NONHOST_CODE"},
    {EV_NONHOST_CONFIG, "EV_NONHOST_CONFIG"},
    {EV_NONHOST_INFO, "EV_NONHOST_INFO"},
    {EV_OMIT_BOOT_DEVICE_EVENTS, "EV_OMIT_BOOT_DEVICE_EVENTS"},
    {EV_EFI_EVENT_BASE, "EV_EFI_EVENT_BASE"},
    {EV_EFI_VARIABLE_DRIVER_CONFIG, "EV_EFI_VARIABLE_DRIVER_CONFIG"},
    {EV_EFI_VARIABLE_BOOT, "EV_EFI_VARIABLE_BOOT"},
    {EV_EFI_BOOT_SERVICES_APPLICATION, "EV_EFI_BOOT_SERVICES_APPLICATION"},
    {EV_EFI_BOOT_SERVICES_DRIVER, "EV_EFI_BOOT_SERVICES_DRIVER"},
    {EV_EFI_RUNTIME_SERVICES_DRIVER, "EV_EFI_RUNTIME_SERVICES_DRIVER"},
    {EV_EFI_GPT_EVENT, "EV_EFI_GPT_EVENT"},
    {EV_EFI_ACTION, "EV_EFI_ACTION"},
    {EV_EFI_PLATFORM_FIRMWARE_BLOB, "EV_EFI_PLATFORM_FIRMWARE_BLOB"},
    {EV_EFI_HANDOFF_TABLES, "EV_EFI_HANDOFF_TABLES"},
    {EV_EFI_HCRTM_EVENT, "EV_EFI_HCRTM_EVENT"},
    {EV_EFI_VARIABLE_AUTHORITY, "EV_EFI_VARIABLE_AUTHORITY"}
};

static void TSS_EVENT_EventType_Trace(uint32_t eventType)
{
    size_t i;

    for (i = 0 ; i < sizeof(eventTypeTable) / sizeof(EVENT_TYPE_TABLE) ; i++) {
	if (eventTypeTable[i].eventType == eventType) {
	    printf("TSS_EVENT_EventType_Trace: %08x %s\n",
		   eventTypeTable[i].eventType, eventTypeTable[i].text);
	    return;
	}
    }
    printf("TSS_EVENT_EventType_Trace: %08x Unknown\n", eventType);
    return;
}

const char *TSS_EVENT_EventTypeToString(uint32_t eventType)
{
    const char *crc = NULL;
    size_t i;

    for (i = 0 ; i < sizeof(eventTypeTable) / sizeof(EVENT_TYPE_TABLE) ; i++) {
	if (eventTypeTable[i].eventType == eventType) {
	    crc = eventTypeTable[i].text;
	}
    }
    if (crc == NULL) {
	crc = "Unknown event type";
    }
    return crc;
}

/*
 * TSS_TPML_DIGEST_VALUES_LE_Unmarshalu() Unmarshals TPML_DIGEST_VALUES struct
 * from a LE buffer into HBO data structure. This is similar to
 * TSS_TPML_DIGEST_VALUES_Unmarshalu but it unrmarshals TPML_DIGEST_VALUES's
 * count  and the digests array members from LE instead of HBO.
 */

static TPM_RC
TSS_TPML_DIGEST_VALUES_LE_Unmarshalu(TPML_DIGEST_VALUES *target, BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    uint32_t i;
    if (rc == TPM_RC_SUCCESS) {
	rc = UINT32LE_Unmarshal(&target->count, buffer, size);
    }
    if (rc == TPM_RC_SUCCESS) {
	if (target->count > HASH_COUNT) {
	    rc = TPM_RC_SIZE;
	}
    }
    for (i = 0 ; (rc == TPM_RC_SUCCESS) && (i < target->count) ; i++) {
	rc = TSS_TPMT_HA_LE_Unmarshalu(&target->digests[i], buffer, size, NO);
    }
    return rc;
}

/*
 * TSS_TPMT_HA_LE_Unmarshalu() Unmarshals a TPMT_HA data from LE to HBO. This is
 * similar to TSS_TPMT_HA_Unmarshalu but differs specificaly for unmarshalling
 * hashAlg member from LE instead of from HBO.
 */
static TPM_RC
TSS_TPMT_HA_LE_Unmarshalu(TPMT_HA *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMI_ALG_HASH_LE_Unmarshalu(&target->hashAlg, buffer, size, allowNull);
    }
    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPMU_HA_Unmarshalu(&target->digest, buffer, size, target->hashAlg);
    }
    return rc;
}

/*
 * TSS_TPMI_ALG_HASH_LE_Unmarshalu() Unmarshals TPMI_ALG_HASH from a LE buffer
 * into HBO data structure. This is similar to TSS_TPMI_ALG_HASH_Unmarshalu but
 * unmarshals TPMI_ALG_HASH from LE instead of HBO.
 */
static TPM_RC
TSS_TPMI_ALG_HASH_LE_Unmarshalu(TPMI_ALG_HASH *target, BYTE **buffer, uint32_t *size, BOOL allowNull)
{
    TPM_RC rc = TPM_RC_SUCCESS;
    allowNull = allowNull;

    if (rc == TPM_RC_SUCCESS) {
	rc = TSS_TPM_ALG_ID_LE_Unmarshalu(target, buffer, size);
    }
    return rc;
}

/*
 * TSS_TPM_ALG_ID_LE_Unmarshalu() Unrmarshals TPM_ALG_ID from LE buffer. This is
 * simlar to TSS_TPM_ALG_ID_Unmarshalu but unmarshals from LE instead of HBO.
 */
static TPM_RC
TSS_TPM_ALG_ID_LE_Unmarshalu(TPM_ALG_ID *target, BYTE **buffer,
                                 uint32_t *size)
{
    TPM_RC rc = TPM_RC_SUCCESS;

    if (rc == TPM_RC_SUCCESS) {
	rc = UINT16LE_Unmarshal(target, buffer, size);
    }
    return rc;
}

/* TSS_TPML_DIGEST_VALUES_LE_Marshalu() Similar to TSS_TPML_DIGEST_VALUES_Marshalu
 * for TSS EVENT2 this marshals count to buffer in LE endianess.
 */
static TPM_RC
TSS_TPML_DIGEST_VALUES_LE_Marshalu(const TPML_DIGEST_VALUES *source,
                                       uint16_t *written, BYTE **buffer,
                                       uint32_t *size)
{
    TPM_RC rc = 0;
    uint32_t i;

    if (rc == 0) {
	rc = TSS_UINT32LE_Marshal(&source->count, written, buffer, size);
    }
    for (i = 0 ; i < source->count ; i++) {
	if (rc == 0) {
	    rc = TSS_TPMT_HA_LE_Marshalu(&source->digests[i], written, buffer, size);
	}
    }
    return rc;
}

/* TSS_TPMT_HA_LE_Marshalu() Similar to TSS_TPMT_HA_Marshalu for TSS EVENT2,
 * this saves hashAlg attr as little endian into buffer.
 */
static TPM_RC
TSS_TPMT_HA_LE_Marshalu(const TPMT_HA *source, uint16_t *written,
			BYTE **buffer, uint32_t *size)
{
    TPM_RC rc = 0;
    if (rc == 0) {
	rc = TSS_UINT16LE_Marshalu(&source->hashAlg, written, buffer, size);
    }
    if (rc == 0) {
	rc = TSS_TPMU_HA_Marshalu(&source->digest, written, buffer, size,
                                  source->hashAlg);
    }
    return rc;
}

/*
 * TSS_UINT32LE_Marshal() Marshals uint32_t from HBO into LE in the given buffer.
 */
TPM_RC
TSS_UINT32LE_Marshal(const UINT32 *source, uint16_t *written, BYTE **buffer,
                 uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
        if ((size == NULL) || (*size >= sizeof(uint32_t))) {
            (*buffer)[0] = (BYTE)((*source >> 0) &  0xff);
            (*buffer)[1] = (BYTE)((*source >> 8) & 0xff);
            (*buffer)[2] = (BYTE)((*source >> 16) & 0xff);
            (*buffer)[3] = (BYTE)((*source >> 24) & 0xff);

            *buffer += sizeof(uint32_t);
            if (size != NULL) {
                *size -= sizeof(uint32_t);
            }
        }
        else {
            rc = TSS_RC_INSUFFICIENT_BUFFER;
        }
    }
    *written += sizeof(uint32_t);
    return rc;
}

/*
 * UINT16LE_Marshal() Marshals uint16_t from HBO into LE in the given buffer.
 */

TPM_RC
TSS_UINT16LE_Marshalu(const UINT16 *source, uint16_t *written, BYTE **buffer,
                      uint32_t *size)
{
    TPM_RC rc = 0;
    if (buffer != NULL) {
        if ((size == NULL) || (*size >= sizeof(uint16_t))) {
	    (*buffer)[0] = (BYTE)((*source >> 0) & 0xff);
	    (*buffer)[1] = (BYTE)((*source >> 8) & 0xff);

            *buffer += sizeof(uint16_t);

            if (size != NULL) {
                *size -= sizeof(uint16_t);
            }
        }
        else {
            rc = TSS_RC_INSUFFICIENT_BUFFER;
        }
    }
    *written += sizeof(uint16_t);
    return rc;
}
