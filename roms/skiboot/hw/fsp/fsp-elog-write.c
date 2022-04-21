// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * This code will enable generation and pushing of error log from Sapphire
 * to FSP.
 * Critical events from Sapphire that needs to be reported will be pushed
 * on to FSP after converting the error log to Platform Error Log(PEL) format.
 * This is termed as write action to FSP.
 *
 * Copyright 2013-2016 IBM Corp.
 */

#include <cpu.h>
#include <errno.h>
#include <fsp.h>
#include <fsp-elog.h>
#include <lock.h>
#include <opal-api.h>
#include <pel.h>
#include <pool.h>
#include <skiboot.h>
#include <timebase.h>

static LIST_HEAD(elog_write_to_fsp_pending);
static LIST_HEAD(elog_write_to_host_pending);
static LIST_HEAD(elog_write_to_host_processed);

static struct lock elog_write_lock = LOCK_UNLOCKED;
static struct lock elog_panic_write_lock = LOCK_UNLOCKED;
static struct lock elog_write_to_host_lock = LOCK_UNLOCKED;

#define ELOG_WRITE_TO_FSP_BUFFER_SIZE	0x00004000
/* Log buffer to copy OPAL log for write to FSP. */
static void *elog_write_to_fsp_buffer;

#define ELOG_PANIC_WRITE_BUFFER_SIZE	0x00004000
static void *elog_panic_write_buffer;

#define ELOG_WRITE_TO_HOST_BUFFER_SIZE	0x00004000
static void *elog_write_to_host_buffer;

static uint32_t elog_write_retries;

/* Manipulate this only with write_lock held */
static uint32_t elog_plid_fsp_commit = -1;
static enum elog_head_state elog_write_to_host_head_state = ELOG_STATE_NONE;

/* Need forward declaration because of circular dependency */
static int opal_send_elog_to_fsp(void);

static void remove_elog_head_entry(void)
{
	struct errorlog *head, *entry;

	lock(&elog_write_lock);
	if (!list_empty(&elog_write_to_fsp_pending)) {
		head = list_top(&elog_write_to_fsp_pending,
					struct errorlog, link);
		if (head->plid == elog_plid_fsp_commit) {
			entry = list_pop(&elog_write_to_fsp_pending,
					struct errorlog, link);
			opal_elog_complete(entry,
					elog_write_retries < MAX_RETRIES);
			/* Reset the counter */
			elog_plid_fsp_commit = -1;
		}
	}

	elog_write_retries = 0;
	unlock(&elog_write_lock);
}

static void opal_fsp_write_complete(struct fsp_msg *read_msg)
{
	uint8_t val;

	val = (read_msg->resp->word1 >> 8) & 0xff;
	fsp_freemsg(read_msg);

	switch (val) {
	case FSP_STATUS_SUCCESS:
		remove_elog_head_entry();
		break;
	default:
		if (elog_write_retries++ >= MAX_RETRIES) {
			remove_elog_head_entry();
			prerror("ELOG: Error in writing to FSP (0x%x)!\n", val);
		}

		break;
	}

	if (opal_send_elog_to_fsp() != OPAL_SUCCESS)
		prerror("ELOG: Error sending elog to FSP !\n");
}

/* Write PEL format hex dump of the log to FSP */
static int64_t fsp_opal_elog_write(size_t opal_elog_size)
{
	struct fsp_msg *elog_msg;

	elog_msg = fsp_mkmsg(FSP_CMD_CREATE_ERRLOG, 3, opal_elog_size,
						 0, PSI_DMA_ERRLOG_WRITE_BUF);
	if (!elog_msg) {
		prerror("ELOG: Failed to create message for WRITE to FSP\n");
		return OPAL_INTERNAL_ERROR;
	}

	if (fsp_queue_msg(elog_msg, opal_fsp_write_complete)) {
		fsp_freemsg(elog_msg);
		elog_msg = NULL;
		prerror("FSP: Error queueing elog update\n");
		return OPAL_INTERNAL_ERROR;
	}

	return OPAL_SUCCESS;
}

/* This should be called with elog_write_to_host_lock lock */
static inline void fsp_elog_write_set_head_state(enum elog_head_state state)
{
	elog_set_head_state(true, state);
	elog_write_to_host_head_state = state;
}

bool opal_elog_info(__be64 *opal_elog_id, __be64 *opal_elog_size)
{
	struct errorlog *head;
	bool rc = false;

	lock(&elog_write_to_host_lock);
	if (elog_write_to_host_head_state == ELOG_STATE_FETCHED_DATA) {
		head = list_top(&elog_write_to_host_pending,
					struct errorlog, link);
		if (!head) {
			/**
			 * @fwts-label ElogListInconsistent
			 * @fwts-advice Bug in interaction between FSP and
			 * OPAL. The state maintained by OPAL didn't match
			 * what the FSP sent.
			 */
			prlog(PR_ERR,
			      "%s: Inconsistent internal list state !\n",
			      __func__);
			fsp_elog_write_set_head_state(ELOG_STATE_NONE);
		} else {
			*opal_elog_id = cpu_to_be64(head->plid);
			*opal_elog_size = cpu_to_be64(head->log_size);
			fsp_elog_write_set_head_state(ELOG_STATE_HOST_INFO);
			rc = true;
		}
	}

	unlock(&elog_write_to_host_lock);
	return rc;
}

static void opal_commit_elog_in_host(void)
{
	struct errorlog *buf;

	lock(&elog_write_to_host_lock);
	if (!list_empty(&elog_write_to_host_pending) &&
			(elog_write_to_host_head_state == ELOG_STATE_NONE)) {
		buf = list_top(&elog_write_to_host_pending,
				struct errorlog, link);
		buf->log_size = create_pel_log(buf,
					(char *)elog_write_to_host_buffer,
					ELOG_WRITE_TO_HOST_BUFFER_SIZE);
		fsp_elog_write_set_head_state(ELOG_STATE_FETCHED_DATA);
	}

	unlock(&elog_write_to_host_lock);
}

bool opal_elog_read(void *buffer, uint64_t opal_elog_size,
		    uint64_t opal_elog_id)
{
	struct errorlog *log_data;
	bool rc = false;

	lock(&elog_write_to_host_lock);
	if (elog_write_to_host_head_state == ELOG_STATE_HOST_INFO) {
		log_data = list_top(&elog_write_to_host_pending,
					struct errorlog, link);
		if (!log_data) {
			fsp_elog_write_set_head_state(ELOG_STATE_NONE);
			unlock(&elog_write_to_host_lock);
			return rc;
		}

		if ((opal_elog_id != log_data->plid) &&
		    (opal_elog_size != log_data->log_size)) {
			unlock(&elog_write_to_host_lock);
			return rc;
		}

		memcpy(buffer, elog_write_to_host_buffer, opal_elog_size);
		list_del(&log_data->link);
		list_add(&elog_write_to_host_processed, &log_data->link);
		fsp_elog_write_set_head_state(ELOG_STATE_NONE);
		rc = true;
	}

	unlock(&elog_write_to_host_lock);
	opal_commit_elog_in_host();
	return rc;
}

bool opal_elog_ack(uint64_t ack_id)
{
	bool rc = false;
	struct errorlog *log_data;
	struct errorlog *record, *next_record;

	lock(&elog_write_to_host_lock);
	if (!list_empty(&elog_write_to_host_processed)) {
		list_for_each_safe(&elog_write_to_host_processed, record,
						next_record, link) {
			if (record->plid != ack_id)
				continue;

			list_del(&record->link);
			opal_elog_complete(record, true);
			rc = true;
		}
	}

	if ((!rc) && (!list_empty(&elog_write_to_host_pending))) {
		log_data = list_top(&elog_write_to_host_pending,
						struct errorlog, link);
		if (ack_id == log_data->plid)
			fsp_elog_write_set_head_state(ELOG_STATE_NONE);

		list_for_each_safe(&elog_write_to_host_pending, record,
						next_record, link) {
			if (record->plid != ack_id)
				continue;

			list_del(&record->link);
			opal_elog_complete(record, true);
			rc = true;
			unlock(&elog_write_to_host_lock);
			opal_commit_elog_in_host();
			return rc;
		}
	}

	unlock(&elog_write_to_host_lock);
	return rc;
}

void opal_resend_pending_logs(void)
{
	struct errorlog *record;

	lock(&elog_write_to_host_lock);
	while (!list_empty(&elog_write_to_host_processed)) {
		record = list_pop(&elog_write_to_host_processed,
					struct errorlog, link);
		list_add_tail(&elog_write_to_host_pending, &record->link);
	}

	fsp_elog_write_set_head_state(ELOG_STATE_NONE);
	unlock(&elog_write_to_host_lock);
	opal_commit_elog_in_host();
}

static inline u64 get_elog_timeout(void)
{
	return (mftb() + secs_to_tb(ERRORLOG_TIMEOUT_INTERVAL));
}

static int opal_send_elog_to_fsp(void)
{
	struct errorlog *head;
	int rc = OPAL_SUCCESS;

	/*
	 * Convert entry to PEL and push it down to FSP.
	 * Then we wait for the ack from FSP.
	 */
	lock(&elog_write_lock);
	if (!list_empty(&elog_write_to_fsp_pending)) {
		head = list_top(&elog_write_to_fsp_pending,
					 struct errorlog, link);
		/* Error needs to be committed, update the time out value */
		head->elog_timeout = get_elog_timeout();

		elog_plid_fsp_commit = head->plid;
		head->log_size = create_pel_log(head,
					(char *)elog_write_to_fsp_buffer,
					ELOG_WRITE_TO_FSP_BUFFER_SIZE);
		rc = fsp_opal_elog_write(head->log_size);
		unlock(&elog_write_lock);
		return rc;
	}

	unlock(&elog_write_lock);
	return rc;
}

static int opal_push_logs_sync_to_fsp(struct errorlog *buf)
{
	struct fsp_msg *elog_msg;
	int opal_elog_size = 0;
	int rc = OPAL_SUCCESS;

	lock(&elog_panic_write_lock);

	/* Error needs to be committed, update the time out value */
	buf->elog_timeout = get_elog_timeout();

	opal_elog_size = create_pel_log(buf,
					(char *)elog_panic_write_buffer,
					ELOG_PANIC_WRITE_BUFFER_SIZE);

	elog_msg = fsp_mkmsg(FSP_CMD_CREATE_ERRLOG, 3, opal_elog_size,
					0, PSI_DMA_ELOG_PANIC_WRITE_BUF);
	if (!elog_msg) {
		prerror("ELOG: PLID: 0x%x Failed to create message for WRITE "
							"to FSP\n", buf->plid);
		unlock(&elog_panic_write_lock);
		opal_elog_complete(buf, false);
		return OPAL_INTERNAL_ERROR;
	}

	if (fsp_sync_msg(elog_msg, false)) {
		fsp_freemsg(elog_msg);
		rc = OPAL_INTERNAL_ERROR;
	} else {
		rc = (elog_msg->resp->word1 >> 8) & 0xff;
		fsp_freemsg(elog_msg);
	}

	unlock(&elog_panic_write_lock);
	if (rc != OPAL_SUCCESS)
		opal_elog_complete(buf, false);
	else
		opal_elog_complete(buf, true);

	return rc;
}

int elog_fsp_commit(struct errorlog *buf)
{
	int rc = OPAL_SUCCESS;

	if (buf->event_severity == OPAL_ERROR_PANIC) {
		rc = opal_push_logs_sync_to_fsp(buf);
		return rc;
	}

	lock(&elog_write_lock);
	if (list_empty(&elog_write_to_fsp_pending)) {
		list_add_tail(&elog_write_to_fsp_pending, &buf->link);
		unlock(&elog_write_lock);
		rc = opal_send_elog_to_fsp();
		return rc;
	}

	list_add_tail(&elog_write_to_fsp_pending, &buf->link);
	unlock(&elog_write_lock);
	return rc;
}

static void elog_append_write_to_host(struct errorlog *buf)
{
	lock(&elog_write_to_host_lock);
	if (list_empty(&elog_write_to_host_pending)) {
		list_add(&elog_write_to_host_pending, &buf->link);
		unlock(&elog_write_to_host_lock);
		opal_commit_elog_in_host();
	} else {
		list_add_tail(&elog_write_to_host_pending, &buf->link);
		unlock(&elog_write_to_host_lock);
	}
}

static void elog_timeout_poll(void *data __unused)
{
	uint64_t now;
	struct errorlog *head, *entry;

	lock(&elog_write_lock);
	if (list_empty(&elog_write_to_fsp_pending)) {
		unlock(&elog_write_lock);
		return;
	}

	head = list_top(&elog_write_to_fsp_pending, struct errorlog, link);
	now = mftb();
	if ((tb_compare(now, head->elog_timeout) == TB_AAFTERB) ||
			(tb_compare(now, head->elog_timeout) == TB_AEQUALB)) {
		entry = list_pop(&elog_write_to_fsp_pending,
				struct errorlog, link);
		unlock(&elog_write_lock);
		elog_append_write_to_host(entry);
	} else {
		unlock(&elog_write_lock);
	}
}

/* FSP elog init function */
void fsp_elog_write_init(void)
{
	if (!fsp_present())
		return;

	elog_panic_write_buffer = memalign(TCE_PSIZE,
					ELOG_PANIC_WRITE_BUFFER_SIZE);
	if (!elog_panic_write_buffer) {
		prerror("FSP: could not allocate ELOG_PANIC_WRITE_BUFFER!\n");
		return;
	}

	elog_write_to_fsp_buffer = memalign(TCE_PSIZE,
					ELOG_WRITE_TO_FSP_BUFFER_SIZE);
	if (!elog_write_to_fsp_buffer) {
		prerror("FSP: could not allocate ELOG_WRITE_BUFFER!\n");
		return;
	}

	elog_write_to_host_buffer = memalign(TCE_PSIZE,
					ELOG_WRITE_TO_HOST_BUFFER_SIZE);
	if (!elog_write_to_host_buffer) {
		prerror("FSP: could not allocate ELOG_WRITE_TO_HOST_BUFFER!\n");
		return;
	}

	/* Map TCEs */
	fsp_tce_map(PSI_DMA_ELOG_PANIC_WRITE_BUF, elog_panic_write_buffer,
					PSI_DMA_ELOG_PANIC_WRITE_BUF_SZ);

	fsp_tce_map(PSI_DMA_ERRLOG_WRITE_BUF, elog_write_to_fsp_buffer,
					PSI_DMA_ERRLOG_WRITE_BUF_SZ);

	elog_init();

	/* Add a poller */
	opal_add_poller(elog_timeout_poll, NULL);
}
