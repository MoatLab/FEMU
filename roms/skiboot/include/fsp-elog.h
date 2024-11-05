// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2016 IBM Corp. */

#include <opal.h>
#include <errorlog.h>
#include <pel.h>
#ifndef __ELOG_H
#define __ELOG_H

#define ELOG_TYPE_PEL			0
#define MAX_RETRIES			3

/* Following variables are used to indicate state of the
 * head log entry which is being fetched from FSP/OPAL and
 * these variables are not overwritten until next log is
 * retrieved from FSP/OPAL.
 */
enum elog_head_state {
	ELOG_STATE_FETCHING,    /*In the process of reading log from FSP. */
	ELOG_STATE_FETCHED_DATA,/* Indicates reading log is completed */
	ELOG_STATE_HOST_INFO,	/* Host read log info */
	ELOG_STATE_NONE,        /* Indicates to fetch next log */
	ELOG_STATE_REJECTED,    /* resend all pending logs to linux */
};

/* Generate src from opal reason code (src_comp) */
#define generate_src_from_comp(src_comp)  (OPAL_SRC_TYPE_ERROR << 24 | \
				OPAL_FAILING_SUBSYSTEM << 16 | src_comp)

int elog_fsp_commit(struct errorlog *buf) __warn_unused_result;

bool opal_elog_info(__be64 *opal_elog_id, __be64 *opal_elog_size) __warn_unused_result;

bool opal_elog_read(void *buffer, uint64_t opal_elog_size,
						uint64_t opal_elog_id) __warn_unused_result;

bool opal_elog_ack(uint64_t ack_id) __warn_unused_result;

void opal_resend_pending_logs(void);

void elog_set_head_state(bool opal_logs, enum elog_head_state state);

#endif /* __ELOG_H */
