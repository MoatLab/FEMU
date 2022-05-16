// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * This code will enable retrieving of error log from FSP -> Sapphire in
 * sequence.
 * Here, FSP would send next log only when Sapphire sends a new log notification
 * response to FSP. On Completion of reading the log from FSP,
 * OPAL_EVENT_ERROR_LOG_AVAIL is signaled. This will remain raised until a call
 * to opal_elog_read() is made and OPAL_SUCCESS is returned. Upon which, the
 * operation is complete and the event is cleared. This is READ action from FSP.
 *
 * Copyright 2013-2017 IBM Corp.
 */

/*
 * Design of READ error log :
 * When we receive a new error log entry notification from FSP, we queue it into
 * the "pending" list. If the "pending" list is not empty, then we start
 * fetching log from FSP.
 *
 * When Linux reads a log entry, we dequeue it from the "pending" list and
 * enqueue it to another "processed" list. At this point, if the "pending"
 * list is not empty, we continue to fetch the next log.
 *
 * When Linux calls opal_resend_pending_logs(), we fetch the log corresponding
 * to the head of the pending list and move it to the processed list, and
 * continue this process until the pending list is empty. If the pending list
 * was empty earlier and is currently non-empty, we initiate an error log fetch.
 *
 * When Linux acks an error log, we remove it from processed list.
 */

#include <errno.h>
#include <fsp.h>
#include <fsp-elog.h>
#include <lock.h>
#include <opal-api.h>
#include <psi.h>
#include <skiboot.h>

/*
 * Maximum number of entries that are pre-allocated
 * to keep track of pending elogs to be fetched.
 */
#define ELOG_READ_MAX_RECORD		128

/* Structure to maintain log-id, log-size, pending and processed list. */
struct fsp_log_entry {
	uint32_t log_id;
	size_t log_size;
	struct list_node link;
};

static LIST_HEAD(elog_read_pending);
static LIST_HEAD(elog_read_processed);
static LIST_HEAD(elog_read_free);
/*
 * Lock is used to protect overwriting of processed and pending list
 * and also used while updating state of each log.
 */
static struct lock elog_read_lock = LOCK_UNLOCKED;

#define ELOG_READ_BUFFER_SIZE		0x00004000
/* Log buffer to copy FSP log for read */
static void *elog_read_buffer;
static uint32_t elog_head_id;	/* FSP entry ID */
static size_t elog_head_size;	/* Actual FSP log size */
static uint32_t elog_read_retries;	/* Bad response status count */

/* Initialize the state of the log */
static enum elog_head_state elog_read_from_fsp_head_state = ELOG_STATE_NONE;

static bool elog_enabled = false;

/* Need forward declaration because of circular dependency. */
static void fsp_elog_queue_fetch(void);

/*
 * Check the response message for mbox acknowledgement
 * command send to FSP.
 */
static void fsp_elog_ack_complete(struct fsp_msg *msg)
{
	uint8_t val;

	val = (msg->resp->word1 >> 8) & 0xff;
	if (val != 0)
		prerror("ELOG: Acknowledgement error\n");

	fsp_freemsg(msg);
}

/* Send error log PHYP acknowledgement to FSP with entry ID. */
static int64_t fsp_send_elog_ack(uint32_t log_id)
{
	struct fsp_msg *ack_msg;

	ack_msg = fsp_mkmsg(FSP_CMD_ERRLOG_PHYP_ACK, 1, log_id);
	if (!ack_msg) {
		prerror("ELOG: Failed to allocate ack message\n");
		return OPAL_INTERNAL_ERROR;
	}

	if (fsp_queue_msg(ack_msg, fsp_elog_ack_complete)) {
		fsp_freemsg(ack_msg);
		ack_msg = NULL;
		prerror("ELOG: Error queueing elog ack complete\n");
		return OPAL_INTERNAL_ERROR;
	}

	return OPAL_SUCCESS;
}

/* Retrieve error log from FSP with TCE for the data transfer. */
static void fsp_elog_check_and_fetch_head(void)
{
	lock(&elog_read_lock);
	if (elog_read_from_fsp_head_state != ELOG_STATE_NONE ||
			list_empty(&elog_read_pending)) {
		unlock(&elog_read_lock);
		return;
	}

	elog_read_retries = 0;
	/* Start fetching first entry from the pending list */
	fsp_elog_queue_fetch();
	unlock(&elog_read_lock);
}

void elog_set_head_state(bool opal_logs, enum elog_head_state state)
{
	static enum elog_head_state opal_logs_state = ELOG_STATE_NONE;
	static enum elog_head_state fsp_logs_state = ELOG_STATE_NONE;

	/* ELOG disabled */
	if (!elog_enabled)
		return;

	if (opal_logs)
		opal_logs_state = state;
	else
		fsp_logs_state = state;

	if (fsp_logs_state == ELOG_STATE_FETCHED_DATA ||
		opal_logs_state == ELOG_STATE_FETCHED_DATA)
		opal_update_pending_evt(OPAL_EVENT_ERROR_LOG_AVAIL,
					OPAL_EVENT_ERROR_LOG_AVAIL);
	else
		opal_update_pending_evt(OPAL_EVENT_ERROR_LOG_AVAIL, 0);
}

/* This function should be called with the lock held. */
static inline void fsp_elog_set_head_state(enum elog_head_state state)
{
	elog_set_head_state(false, state);
	elog_read_from_fsp_head_state = state;
}

/*
 * When, we try maximum time of fetching log from FSP
 * we call following function to delete log from the
 * pending list and update the state to fetch next log.
 *
 * This function should be called with the lock held.
 */
static void fsp_elog_fetch_failure(uint8_t fsp_status)
{
	struct fsp_log_entry *log_data;

	/* Read top list and delete the node */
	log_data = list_top(&elog_read_pending, struct fsp_log_entry, link);
	if (!log_data) {
		/**
		 * @fwts-label ElogFetchFailureInconsistent
		 * @fwts-advice Inconsistent state between OPAL and FSP
		 * in code path for handling failure of fetching error log
		 * from FSP. Likely a bug in interaction between FSP and OPAL.
		 */
		prlog(PR_ERR, "%s: Inconsistent internal list state !\n",
		      __func__);
	} else {
		list_del(&log_data->link);
		list_add(&elog_read_free, &log_data->link);
		prerror("ELOG: received invalid data: %x FSP status: 0x%x\n",
			log_data->log_id, fsp_status);
	}

	fsp_elog_set_head_state(ELOG_STATE_NONE);
}

/* Read response value from FSP for fetch sp data mbox command */
static void fsp_elog_read_complete(struct fsp_msg *read_msg)
{
	uint8_t val;

	lock(&elog_read_lock);
	val = (read_msg->resp->word1 >> 8) & 0xff;
	fsp_freemsg(read_msg);
	if (elog_read_from_fsp_head_state == ELOG_STATE_REJECTED) {
		fsp_elog_set_head_state(ELOG_STATE_NONE);
		goto elog_read_out;
	}

	switch (val) {
	case FSP_STATUS_SUCCESS:
		fsp_elog_set_head_state(ELOG_STATE_FETCHED_DATA);
		break;

	case FSP_STATUS_DMA_ERROR:
		if (elog_read_retries++ < MAX_RETRIES) {
			/*
			 * For a error response value from FSP, we try to
			 * send fetch sp data mbox command again for three
			 * times if response from FSP is still not valid
			 * we send generic error response to FSP.
			 */
			fsp_elog_queue_fetch();
			break;
		}

		fsp_elog_fetch_failure(val);
		break;

	default:
		fsp_elog_fetch_failure(val);
	}

elog_read_out:
	unlock(&elog_read_lock);

	/* Check if a new log needs fetching */
	fsp_elog_check_and_fetch_head();
}

/* Read error log from FSP through mbox commands */
static void fsp_elog_queue_fetch(void)
{
	int rc;
	uint8_t flags = 0;
	struct fsp_log_entry *entry;

	entry = list_top(&elog_read_pending, struct fsp_log_entry, link);
	if (!entry) {
		/**
		 * @fwts-label ElogQueueInconsistent
		 * @fwts-advice Bug in interaction between FSP and OPAL. We
		 * expected there to be a pending read from FSP but the list
		 * was empty.
		 */
		prlog(PR_ERR, "%s: Inconsistent internal list state !\n",
			__func__);
		fsp_elog_set_head_state(ELOG_STATE_NONE);
		return;
	}

	fsp_elog_set_head_state(ELOG_STATE_FETCHING);
	elog_head_id = entry->log_id;
	elog_head_size = entry->log_size;
	rc = fsp_fetch_data_queue(flags, FSP_DATASET_ERRLOG, elog_head_id,
				  0, (void *)PSI_DMA_ERRLOG_READ_BUF,
				  &elog_head_size, fsp_elog_read_complete);
	if (rc) {
		prerror("ELOG: failed to queue read message: %d\n", rc);
		fsp_elog_set_head_state(ELOG_STATE_NONE);
	}
}

/* OPAL interface for PowerNV to read log size and log ID from Sapphire. */
static int64_t fsp_opal_elog_info(__be64 *opal_elog_id,
				  __be64 *opal_elog_size, __be64 *elog_type)
{
	struct fsp_log_entry *log_data;

	/* Copy type of the error log */
	*elog_type = cpu_to_be64(ELOG_TYPE_PEL);

	/* Check if any OPAL log needs to be reported to the host */
	if (opal_elog_info(opal_elog_id, opal_elog_size))
		return OPAL_SUCCESS;

	lock(&elog_read_lock);
	if (elog_read_from_fsp_head_state != ELOG_STATE_FETCHED_DATA) {
		unlock(&elog_read_lock);
		return OPAL_WRONG_STATE;
	}

	log_data = list_top(&elog_read_pending, struct fsp_log_entry, link);
	if (!log_data) {
		/**
		 * @fwts-label ElogInfoInconsistentState
		 * @fwts-advice We expected there to be an entry in the list
		 * of error logs for the error log we're fetching information
		 * for. There wasn't. This means there's a bug.
		 */
		prlog(PR_ERR, "%s: Inconsistent internal list state !\n",
		      __func__);
		fsp_elog_set_head_state(ELOG_STATE_NONE);
		unlock(&elog_read_lock);
		return OPAL_WRONG_STATE;
	}

	*opal_elog_id = cpu_to_be64(log_data->log_id);
	*opal_elog_size = cpu_to_be64(log_data->log_size);
	fsp_elog_set_head_state(ELOG_STATE_HOST_INFO);
	unlock(&elog_read_lock);
	return OPAL_SUCCESS;
}

/* OPAL interface for PowerNV to read log from Sapphire. */
static int64_t fsp_opal_elog_read(void *buffer, uint64_t opal_elog_size,
				  uint64_t opal_elog_id)
{
	int size = opal_elog_size;
	struct fsp_log_entry *log_data;

	/* Check if any OPAL log needs to be reported to the PowerNV */
	if (opal_elog_read(buffer, opal_elog_size, opal_elog_id))
		return OPAL_SUCCESS;

	/*
	 * Read top entry from list.
	 * As we know always top record of the list is fetched from FSP
	 */
	lock(&elog_read_lock);
	if (elog_read_from_fsp_head_state != ELOG_STATE_HOST_INFO) {
		unlock(&elog_read_lock);
		return OPAL_WRONG_STATE;
	}

	log_data = list_top(&elog_read_pending, struct fsp_log_entry, link);
	if (!log_data) {
		/**
		 * @fwts-label ElogReadInconsistentState
		 * @fwts-advice Inconsistent state while reading error log
		 * from FSP. Bug in OPAL and FSP interaction.
		 */
		prlog(PR_ERR, "%s: Inconsistent internal list state !\n",
		      __func__);
		fsp_elog_set_head_state(ELOG_STATE_NONE);
		unlock(&elog_read_lock);
		return OPAL_WRONG_STATE;
	}

	/* Check log ID and then read log from buffer */
	if (opal_elog_id != log_data->log_id) {
		unlock(&elog_read_lock);
		return OPAL_PARAMETER;
	}

	/* Do not copy more than actual log size */
	if (opal_elog_size > log_data->log_size)
		size = log_data->log_size;

	memset(buffer, 0, opal_elog_size);
	memcpy(buffer, elog_read_buffer, size);

	/*
	 * Once log is read from linux move record from pending
	 * to processed list and delete record from pending list
	 * and change state of the log to fetch next record.
	 */
	list_del(&log_data->link);
	list_add(&elog_read_processed, &log_data->link);
	fsp_elog_set_head_state(ELOG_STATE_NONE);
	unlock(&elog_read_lock);

	/* Read error log from FSP */
	fsp_elog_check_and_fetch_head();

	return OPAL_SUCCESS;
}

/* Set state of the log head before fetching the log. */
static void elog_reject_head(void)
{
	if (elog_read_from_fsp_head_state == ELOG_STATE_FETCHING)
		fsp_elog_set_head_state(ELOG_STATE_REJECTED);
	else
		fsp_elog_set_head_state(ELOG_STATE_NONE);
}

/* OPAL interface for PowerNV to send ack to FSP with log ID */
static int64_t fsp_opal_elog_ack(uint64_t ack_id)
{
	int rc = 0;
	struct fsp_log_entry  *record, *next_record;

	if (opal_elog_ack(ack_id))
		return rc;

	/* Send acknowledgement to FSP */
	rc = fsp_send_elog_ack(ack_id);
	if (rc != OPAL_SUCCESS) {
		prerror("ELOG: failed to send acknowledgement: %d\n", rc);
		return rc;
	}

	lock(&elog_read_lock);
	list_for_each_safe(&elog_read_processed, record, next_record, link) {
		if (record->log_id != ack_id)
			continue;

		list_del(&record->link);
		list_add(&elog_read_free, &record->link);
		unlock(&elog_read_lock);
		return rc;
	}

	list_for_each_safe(&elog_read_pending, record, next_record, link) {
		if (record->log_id != ack_id)
			continue;
		/*
		 * It means PowerNV has sent ACK without reading actual data.
		 * Because of this elog_read_from_fsp_head_state may be
		 * stuck in wrong state (ELOG_STATE_HOST_INFO) and not able
		 * to send remaining ELOGs to PowerNV. Hence reset ELOG state
		 * and start sending remaining ELOGs.
		 */
		list_del(&record->link);
		list_add(&elog_read_free, &record->link);
		elog_reject_head();
		unlock(&elog_read_lock);
		fsp_elog_check_and_fetch_head();
		return rc;
	}

	unlock(&elog_read_lock);
	return OPAL_PARAMETER;
}

/*
 * Once Linux kexec's it ask to resend all logs which
 * are not acknowledged from Linux.
 */
static void fsp_opal_resend_pending_logs(void)
{
	struct fsp_log_entry  *entry;

	lock(&elog_read_lock);
	elog_enabled = true;
	unlock(&elog_read_lock);

	/* Check if any Sapphire logs are pending. */
	opal_resend_pending_logs();

	lock(&elog_read_lock);
	/*
	 * If processed list is not empty add all record from
	 * processed list to pending list at head of the list
	 * and delete records from processed list.
	 */
	while (!list_empty(&elog_read_processed)) {
		entry = list_pop(&elog_read_processed,
					 struct fsp_log_entry, link);
		list_add(&elog_read_pending, &entry->link);
	}

	unlock(&elog_read_lock);

	/* Read error log from FSP */
	elog_reject_head();
	fsp_elog_check_and_fetch_head();
}

/* Disable ELOG event flag until PowerNV is ready to receive event */
static bool opal_kexec_elog_notify(void *data __unused)
{
	lock(&elog_read_lock);
	elog_enabled = false;
	opal_update_pending_evt(OPAL_EVENT_ERROR_LOG_AVAIL, 0);
	unlock(&elog_read_lock);

	return true;
}

/* FSP elog notify function */
static bool fsp_elog_msg(uint32_t cmd_sub_mod, struct fsp_msg *msg)
{
	int rc = 0;
	struct fsp_log_entry  *record;
	uint32_t log_id;
	uint32_t log_size;

	if (cmd_sub_mod != FSP_CMD_ERRLOG_NOTIFICATION)
		return false;

	log_id = fsp_msg_get_data_word(msg, 0);
	log_size = fsp_msg_get_data_word(msg, 1);

	prlog(PR_TRACE, "ELOG: Notified of log 0x%08x (size: %d)\n",
	       log_id, log_size);

	/* Make sure we don't cross read buffer size */
	if (log_size > ELOG_READ_BUFFER_SIZE) {
		log_size = ELOG_READ_BUFFER_SIZE;
		printf("ELOG: Truncated log (0x%08x) to 0x%x\n",
		       log_id, log_size);
	}

	/* Take a lock until we take out the node from elog_read_free */
	lock(&elog_read_lock);
	if (!list_empty(&elog_read_free)) {
		/* Create a new entry in the pending list. */
		record = list_pop(&elog_read_free, struct fsp_log_entry, link);
		record->log_id = log_id;
		record->log_size = log_size;
		list_add_tail(&elog_read_pending, &record->link);
		unlock(&elog_read_lock);

		/* Send response back to FSP for a new elog notify message. */
		rc = fsp_queue_msg(fsp_mkmsg(FSP_RSP_ERRLOG_NOTIFICATION,
					1, log_id), fsp_freemsg);
		if (rc)
			prerror("ELOG: Failed to queue errlog notification"
				" response: %d\n", rc);

		/* Read error log from FSP */
		fsp_elog_check_and_fetch_head();

	} else {
		prlog(PR_TRACE, "ELOG: Log entry 0x%08x discarded\n", log_id);

		/* Unlock if elog_read_free is empty. */
		unlock(&elog_read_lock);

		rc = fsp_queue_msg(fsp_mkmsg(FSP_RSP_ERRLOG_NOTIFICATION,
					     1, log_id), fsp_freemsg);
		if (rc)
			prerror("ELOG: Failed to queue errlog notification"
				" response: %d\n", rc);

		/*
		 * If list is full with max record then we send discarded by
		 * phyp (condition full) ack to FSP.
		 *
		 * At some point in the future, we'll get notified again.
		 * This is largely up to FSP as to when they tell us about
		 * the log again.
		 */
		rc = fsp_queue_msg(fsp_mkmsg(FSP_CMD_ERRLOG_PHYP_ACK | 0x02,
				1, log_id), fsp_freemsg);
		if (rc)
			prerror("ELOG: Failed to queue errlog ack"
				" response: %d\n", rc);
	}

	return true;
}

static struct fsp_client fsp_get_elog_notify = {
	.message = fsp_elog_msg,
};

/* Pre-allocate memory for reading error log from FSP */
static int init_elog_read_free_list(uint32_t num_entries)
{
	struct fsp_log_entry *entry;
	int i;

	entry = zalloc(sizeof(struct fsp_log_entry) * num_entries);
	if (!entry)
		goto out_err;

	for (i = 0; i < num_entries; ++i) {
		list_add_tail(&elog_read_free, &entry->link);
		entry++;
	}

	return 0;

out_err:
	return -ENOMEM;
}

/* FSP elog read init function */
void fsp_elog_read_init(void)
{
	int val = 0;

	if (!fsp_present())
		return;

	elog_read_buffer = memalign(TCE_PSIZE, ELOG_READ_BUFFER_SIZE);
	if (!elog_read_buffer) {
		prerror("FSP: could not allocate FSP ELOG_READ_BUFFER!\n");
		return;
	}

	/* Map TCEs */
	fsp_tce_map(PSI_DMA_ERRLOG_READ_BUF, elog_read_buffer,
					PSI_DMA_ERRLOG_READ_BUF_SZ);

	/* Pre allocate memory for 128 record */
	val = init_elog_read_free_list(ELOG_READ_MAX_RECORD);
	if (val != 0)
		return;

	/* Register error log class D2 */
	fsp_register_client(&fsp_get_elog_notify, FSP_MCLASS_ERR_LOG);

	/* Register for sync on PowerNV reboot call */
	opal_add_host_sync_notifier(opal_kexec_elog_notify, NULL);

	/* Register OPAL interface */
	opal_register(OPAL_ELOG_READ, fsp_opal_elog_read, 3);
	opal_register(OPAL_ELOG_ACK, fsp_opal_elog_ack, 1);
	opal_register(OPAL_ELOG_RESEND, fsp_opal_resend_pending_logs, 0);
	opal_register(OPAL_ELOG_SIZE, fsp_opal_elog_info, 3);
}
