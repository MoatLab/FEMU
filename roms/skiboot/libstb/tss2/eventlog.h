// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2020 IBM Corp. */

#ifndef __EVENTLOG_H
#define __EVENTLOG_H

#include <ibmtss/TPM_Types.h>
#include <eventlib.h>

#define MAX_TPM_LOG_MSG 128
#define MAX_VENDOR_INFO_LEN 255

struct _TpmLogMgr
{
	uint32_t logSize;
	uint32_t logMaxSize;
	uint8_t* newEventPtr;
	uint8_t* eventLogInMem;
};
typedef struct _TpmLogMgr TpmLogMgr;


int load_eventlog(TpmLogMgr *logmgr, uint8_t* eventlog_ptr,
		  uint32_t eventlog_size);
int add_to_eventlog(TpmLogMgr *logmgr, TCG_PCR_EVENT2 *event);
int build_event(TCG_PCR_EVENT2 *event, TPMI_DH_PCR pcrHandle,
                TPMI_ALG_HASH *hashes, uint8_t hashes_len,
		const uint8_t **digests, uint32_t event_type,
		const char* logmsg, uint32_t logmsg_len);
#endif //__EVENTLOG_H
