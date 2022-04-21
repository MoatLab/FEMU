// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */

#include <skiboot.h>

#include <eventlog.h>
#include <eventlib.h>
#include <ibmtss/tssmarshal.h>


int load_eventlog(TpmLogMgr *logmgr, uint8_t *eventlog_ptr,
		  uint32_t eventlog_size)
{
	TCG_PCR_EVENT2 *event2 = NULL;
	TCG_PCR_EVENT *event = NULL;
	uint8_t *log_ptr, *ptr;
	uint32_t size;
	int rc = 0;

	event = zalloc(sizeof(TCG_PCR_EVENT));
	if(!event){
		rc = 1;
		goto cleanup;
	}

	event2 = zalloc(sizeof(TCG_PCR_EVENT2));
	if(!event2){
		rc = 1;
		goto cleanup;
	}

	logmgr->logMaxSize = eventlog_size;
	logmgr->eventLogInMem = eventlog_ptr;
	logmgr->logSize = 0;

	log_ptr = logmgr->eventLogInMem;
	size = sizeof(TCG_PCR_EVENT);

	//first event in the log is a header
	rc = TSS_EVENT_Line_LE_Unmarshal(event, &log_ptr, &size);
	if(rc)
	{
		prlog(PR_INFO, "Couldn't read event log header event, rc=%d",
		      rc);
		rc = 1;
		goto cleanup;
	}
	//now iterate through all events
	ptr = log_ptr;
	do {
		size = sizeof(TCG_PCR_EVENT2);
		rc = TSS_EVENT2_Line_LE_Unmarshal(event2, &ptr, &size);
		/* something went wrong in parsing (invalid values) or
		 * digest.count is 0 - which doesn't make sense - we stop.
		 */
		if (rc || event2->digests.count == 0 )
			break;
		log_ptr = ptr;
	} while(1);
	logmgr->logSize = log_ptr - logmgr->eventLogInMem;
	logmgr->newEventPtr = log_ptr;

cleanup:
	free(event);
	free(event2);
	return rc;
}

int add_to_eventlog(TpmLogMgr *logmgr, TCG_PCR_EVENT2 *event)
{
	uint32_t size = sizeof(TCG_PCR_EVENT2), rc = 0;
	uint16_t written = 0, ev_size =0;

	/* Calling Marshal function with a NULL buffer to obtain the event size.
	 * It's a well known and safe pattern used in TSS code.
	 * Then check if an event that larger will fit in evenlog buffer, and
	 * only after success here marshal it to eventlog buffer pointed by
	 * logmgr->newEventPtr.
	 */
	TSS_EVENT2_Line_LE_Marshal(event, &ev_size, NULL, &size);
	if(logmgr->logSize + ev_size > logmgr->logMaxSize){
		return 1;
	}
	rc = TSS_EVENT2_Line_LE_Marshal(event, &written,
				     &(logmgr->newEventPtr), &size);
	if(rc)
		return rc;
	logmgr->logSize += ev_size;

	return rc;
}

int build_event(TCG_PCR_EVENT2 *event, TPMI_DH_PCR pcrHandle,
		TPMI_ALG_HASH *hashes, uint8_t hashes_len,
		const uint8_t **digests, uint32_t event_type,
		const char* logmsg, uint32_t logmsg_len)
{
       uint16_t alg_digest_size;
       uint32_t size;

	memset(event, 0, sizeof(TCG_PCR_EVENT2));
	event->pcrIndex = pcrHandle;
	event->eventType = event_type;
	event->digests.count = hashes_len;

	size = sizeof(TPMI_ALG_HASH);
	for (int i=0; i < event->digests.count; i++){
		event->digests.digests[i].hashAlg = hashes[i];

		TSS_TPMI_ALG_HASH_Marshalu(hashes+i, &alg_digest_size, NULL, &size);

		if (alg_digest_size == 0)
			return 1;
		memcpy(&(event->digests.digests[i].digest), digests[i],
		       strlen(digests[i]) > alg_digest_size ?
				strlen(digests[i]) : alg_digest_size);

	}

	event->eventSize = logmsg_len;
	memset(&(event->event), 0, sizeof(event->event));
	memcpy(&(event->event), logmsg,
	       event->eventSize > TCG_EVENT_LEN_MAX ?
			TCG_EVENT_LEN_MAX - 1: event->eventSize);
	return 0;
}
