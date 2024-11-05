// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Dump support:
 *  We get dump notification from different sources:
 *   - During system initialization via HDAT
 *   - During FSP reset/reload (FipS dump)
 *   - Dump available notification MBOX command (0xCE, 0x78, 0x00)
 *
 *  To avoid complications, we keep list of dumps in a list and fetch
 *  them serially.
 *
 * Dump retrieve process:
 *   - Once we get notification from FSP we enqueue the dump ID and notify
 *     Linux via OPAL event notification.
 *   - Linux reads dump info and allocates required memory to fetch the dump
 *     and makes dump read call.
 *   - Sapphire fetches dump data from FSP.
 *   - Linux writes dump to disk and sends acknowledgement.
 *   - Sapphire acknowledges FSP.
 *
 * Copyright 2013-2015 IBM Corp.
 */

#include <fsp.h>
#include <psi.h>
#include <lock.h>
#include <device.h>
#include <skiboot.h>
#include <errorlog.h>
#include <opal-api.h>

/*
 * Max outstanding dumps to retrieve
 *
 * Note:
 *  Dumps are serialized. We don't get notification for second
 *  dump of given type until we acknowledge first one. But we
 *  may get notification for different dump type. And our dump
 *  retrieval code is serialized. Hence we use list to keep
 *  track of outstanding dumps to be retrieved.
 */
#define MAX_DUMP_RECORD		0x04

/* Max retry */
#define FIPS_DUMP_MAX_RETRY	0x03

/* Dump type */
#define DUMP_TYPE_FSP		0x01
#define DUMP_TYPE_SYS		0x02
#define DUMP_TYPE_SMA		0x03

/* Dump fetch size */
#define DUMP_FETCH_SIZE_FSP	0x500000
#define DUMP_FETCH_SIZE_SYS	0x400000
#define DUMP_FETCH_SIZE_RES	0x200000

/* Params for Fips dump */
#define FSP_DUMP_TOOL_TYPE	"SYS "
#define FSP_DUMP_CLIENT_ID	"SAPPHIRE_CLIENT"

enum dump_state {
	DUMP_STATE_ABSENT,	/* No FSP dump */
	DUMP_STATE_NONE,	/* No dump to retrieve */
	DUMP_STATE_NOTIFY,	/* Notified Linux */
	DUMP_STATE_FETCHING,	/* Dump retrieval is in progress */
	DUMP_STATE_FETCH,	/* Dump retrieve complete */
	DUMP_STATE_PARTIAL,	/* Partial read */
	DUMP_STATE_ABORTING,	/* Aborting due to kexec */
};

/* Pending dump list */
struct dump_record {
	uint8_t	 type;
	uint32_t id;
	uint32_t size;
	struct list_node link;
};

/* List definations */
static LIST_HEAD(dump_pending);
static LIST_HEAD(dump_free);

/* Dump retrieve state */
static enum dump_state dump_state = DUMP_STATE_NONE;

/* Dump buffer SG list */
static struct opal_sg_list *dump_data;
static struct dump_record *dump_entry;
static int64_t dump_offset;
static size_t fetch_remain;

/* FipS dump retry count */
static int retry_cnt;

/* Protect list and dump retrieve state */
static struct lock dump_lock = LOCK_UNLOCKED;

/* Forward declaration */
static int64_t fsp_opal_dump_init(uint8_t dump_type);
static int64_t fsp_dump_read(void);

DEFINE_LOG_ENTRY(OPAL_RC_DUMP_INIT, OPAL_PLATFORM_ERR_EVT, OPAL_DUMP,
		 OPAL_PLATFORM_FIRMWARE,
		 OPAL_PREDICTIVE_ERR_FAULT_RECTIFY_REBOOT,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_DUMP_LIST, OPAL_PLATFORM_ERR_EVT, OPAL_DUMP,
		 OPAL_PLATFORM_FIRMWARE,
		 OPAL_INFO,
		 OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_DUMP_ACK, OPAL_PLATFORM_ERR_EVT, OPAL_DUMP,
		 OPAL_PLATFORM_FIRMWARE, OPAL_INFO,
		 OPAL_NA);

/*
 * Helper functions
 */
static inline void update_dump_state(enum dump_state state)
{
	dump_state = state;
}

static int64_t check_dump_state(void)
{
	switch (dump_state) {
	case DUMP_STATE_ABSENT:
		return OPAL_HARDWARE;
	case DUMP_STATE_NONE:
	case DUMP_STATE_NOTIFY:
		/* During dump fetch, notify is wrong state */
		return OPAL_WRONG_STATE;
	case DUMP_STATE_FETCHING:
	case DUMP_STATE_ABORTING:
		return OPAL_BUSY_EVENT;
	case DUMP_STATE_FETCH:
		return OPAL_SUCCESS;
	case DUMP_STATE_PARTIAL:
		return OPAL_PARTIAL;
	}
	return OPAL_SUCCESS;
}

static inline void dump_tce_map(uint32_t tce_offset,
				void *buffer, uint32_t size)
{
	uint32_t tlen = ALIGN_UP(size, TCE_PSIZE);
	fsp_tce_map(PSI_DMA_DUMP_DATA + tce_offset, buffer, tlen);
}

static inline void dump_tce_unmap(uint32_t size)
{
	fsp_tce_unmap(PSI_DMA_DUMP_DATA, size);
}

/*
 * Returns Data set ID for the given dump type
 */
static inline uint16_t get_dump_data_set_id(uint8_t type)
{
	switch (type) {
	case DUMP_TYPE_FSP:
		return FSP_DATASET_SP_DUMP;
	case DUMP_TYPE_SYS:
		return FSP_DATASET_HW_DUMP;
	default:
		break;
	}
	return OPAL_INTERNAL_ERROR;
}

/*
 * Returns max data we can fetch from FSP fetch data call
 */
static inline int64_t get_dump_fetch_max_size(uint8_t type)
{
	switch (type) {
	case DUMP_TYPE_FSP:
		return DUMP_FETCH_SIZE_FSP;
	case DUMP_TYPE_SYS:
		return DUMP_FETCH_SIZE_SYS;
	default:
		break;
	}
	return OPAL_INTERNAL_ERROR;
}

/*
 * Get dump record from pending list
 */
static inline struct dump_record *get_dump_rec_from_list(uint32_t id)
{
	struct dump_record *record;

	list_for_each(&dump_pending, record, link) {
		if (record->id == id)
			return record;
	}
	return NULL;
}

/*
 * New dump available notification to Linux
 */
static void update_opal_dump_notify(void)
{
	/*
	 * Wait until current dump retrieval to complete
	 * before notifying again.
	 */
	if (dump_state != DUMP_STATE_NONE)
		return;

	 /* More dump's to retrieve */
	if (!list_empty(&dump_pending)) {
		update_dump_state(DUMP_STATE_NOTIFY);
		opal_update_pending_evt(OPAL_EVENT_DUMP_AVAIL,
					OPAL_EVENT_DUMP_AVAIL);
	}
}

static int64_t remove_dump_id_from_list(uint32_t dump_id)
{
	struct dump_record *record, *nxt_record;
	int rc = OPAL_SUCCESS;
	bool found = false;

	/* Remove record from pending list */
	list_for_each_safe(&dump_pending, record, nxt_record, link) {
		if (record->id != dump_id)
			continue;

		found = true;
		list_del(&record->link);
		list_add(&dump_free, &record->link);
		break;
	}

	/*
	 * Continue update_opal_dump_notify even if it fails
	 * to remove ID. So that we can resend notification
	 * for the same dump ID to Linux.
	 */
	if (!found) { /* List corrupted? */
		log_simple_error(&e_info(OPAL_RC_DUMP_LIST),
				 "DUMP: ID 0x%x not found in list!\n",
				 dump_id);
		rc = OPAL_PARAMETER;
	}

	/* Update state */
	update_dump_state(DUMP_STATE_NONE);
	/* Notify next available dump to retrieve */
	update_opal_dump_notify();

	return rc;
}

static int64_t add_dump_id_to_list(uint8_t dump_type,
				   uint32_t dump_id, uint32_t dump_size)
{
	struct dump_record *record;
	int rc = OPAL_SUCCESS;

	lock(&dump_lock);

	rc = check_dump_state();
	if (rc == OPAL_HARDWARE)
		goto out;

	/* List is full ? */
	if (list_empty(&dump_free)) {
		printf("DUMP: Dump ID 0x%x is not queued.\n", dump_id);
		rc = OPAL_RESOURCE;
		goto out;
	}

	/* Already queued? */
	record = get_dump_rec_from_list(dump_id);
	if (record) {
		rc = OPAL_SUCCESS;
		goto out;
	}

	/* Add to list */
	record = list_pop(&dump_free, struct dump_record, link);
	record->type = dump_type;
	record->id = dump_id;
	record->size = dump_size;
	list_add_tail(&dump_pending, &record->link);

	/* OPAL notification */
	update_opal_dump_notify();
	rc = OPAL_SUCCESS;

out:
	unlock(&dump_lock);
	return rc;
}

static void dump_init_complete(struct fsp_msg *msg)
{
	uint8_t status = (msg->resp->word1 >> 8) & 0xff;

	printf("DUMP: FipS dump init status = 0x%x\n", status);
	fsp_freemsg(msg);

	switch (status) {
	case FSP_STATUS_SUCCESS:
		printf("DUMP: Initiated FipS dump.\n");
		break;
	case FSP_STATUS_BUSY: /* Retry, if FSP is busy */
		if (retry_cnt++ < FIPS_DUMP_MAX_RETRY)
			if (fsp_opal_dump_init(DUMP_TYPE_FSP) == OPAL_SUCCESS)
				return;
		break;
	default:
		break;
	}
	/* Reset max retry count */
	retry_cnt = 0;
}

/*
 * Initiate new FipS dump
 */
static int64_t fsp_opal_dump_init(uint8_t dump_type)
{
	struct fsp_msg *msg;
	int rc = OPAL_SUCCESS;
	uint32_t *tool_type = (void *)FSP_DUMP_TOOL_TYPE;
	uint32_t *client_id = (void *)FSP_DUMP_CLIENT_ID;

	/* Only FipS dump generate request is supported */
	if (dump_type != DUMP_TYPE_FSP)
		return OPAL_PARAMETER;

	msg = fsp_mkmsg(FSP_CMD_FSP_DUMP_INIT, 6, *tool_type,
			sizeof(FSP_DUMP_CLIENT_ID), *client_id,
			*(client_id + 1), *(client_id + 2), *(client_id + 3));

	if (!msg) {
		log_simple_error(&e_info(OPAL_RC_DUMP_INIT),
				 "DUMP: Message allocation failed.\n");
		rc = OPAL_INTERNAL_ERROR;
	} else if (fsp_queue_msg(msg, dump_init_complete)) {
		log_simple_error(&e_info(OPAL_RC_DUMP_INIT),
			"DUMP: Failed to queue FipS dump init request.\n");
		fsp_freemsg(msg);
		rc = OPAL_INTERNAL_ERROR;
	}

	return rc;
}

/*
 * OPAL interface to send dump information to Linux.
 */
static int64_t fsp_opal_dump_info2(__be32 *dump_id, __be32 *dump_size,
				   __be32 *dump_type)
{
	struct dump_record *record;
	int rc = OPAL_SUCCESS;

	lock(&dump_lock);

	/* Clear notification */
	opal_update_pending_evt(OPAL_EVENT_DUMP_AVAIL, 0);

	record = list_top(&dump_pending, struct dump_record, link);
	if (!record) { /* List corrupted? */
		update_dump_state(DUMP_STATE_NONE);
		rc = OPAL_INTERNAL_ERROR;
		goto out;
	}
	*dump_id = cpu_to_be32(record->id);
	*dump_size = cpu_to_be32(record->size);
	*dump_type = cpu_to_be32(record->type);

out:
	unlock(&dump_lock);
	return rc;
}

static int64_t fsp_opal_dump_info(__be32 *dump_id, __be32 *dump_size)
{
	__be32 dump_type;
	return fsp_opal_dump_info2(dump_id, dump_size, &dump_type);
}

static int64_t validate_dump_sglist(struct opal_sg_list *list,
				    int64_t *size)
{
	struct opal_sg_list *sg;
	struct opal_sg_entry *prev_entry, *entry;
	int length, num_entries, i;

	prev_entry = NULL;
	*size = 0;
	for (sg = list; sg; sg = (struct opal_sg_list*)be64_to_cpu(sg->next)) {
		length = be64_to_cpu(sg->length) - 16;
		num_entries = length / sizeof(struct opal_sg_entry);
		if (num_entries <= 0)
			return OPAL_PARAMETER;

		for (i = 0; i < num_entries; i++) {
			entry = &sg->entry[i];
			*size += be64_to_cpu(entry->length);

			/* All entries must be aligned */
			if (((uint64_t)be64_to_cpu(entry->data)) & 0xfff)
				return OPAL_PARAMETER;

			/* All non-terminal entries size must be aligned */
			if (prev_entry && (be64_to_cpu(prev_entry->length) & 0xfff))
				return OPAL_PARAMETER;

			prev_entry = entry;
		}
	}
	return OPAL_SUCCESS;
}

/*
 * Map dump buffer to TCE buffer
 */
static int64_t map_dump_buffer(void)
{
	struct opal_sg_list *sg;
	struct opal_sg_entry *entry;
	int64_t fetch_max;
	int length, num_entries, i;
	int buf_off, fetch_off, tce_off, sg_off;
	bool last = false;

	/* FSP fetch max size */
	fetch_max = get_dump_fetch_max_size(dump_entry->type);
	if (fetch_max > (dump_entry->size - dump_offset))
		fetch_remain = dump_entry->size - dump_offset;
	else
		fetch_remain = fetch_max;

	/* offsets */
	fetch_off = fetch_remain;
	tce_off = sg_off = 0;

	for (sg = dump_data; sg; sg = (struct opal_sg_list*)be64_to_cpu(sg->next)) {
		num_entries = (be64_to_cpu(sg->length) - 16) /
					sizeof(struct opal_sg_entry);
		if (num_entries <= 0)
			return OPAL_PARAMETER;

		for (i = 0; i < num_entries; i++) {
			entry = &sg->entry[i];

			/* Continue until we get offset */
			if ((sg_off + be64_to_cpu(entry->length)) < dump_offset) {
				sg_off += be64_to_cpu(entry->length);
				continue;
			}

			/*
			 * SG list entry size can be more than 4k.
			 * Map only required pages, instead of
			 * mapping entire entry.
			 */
			if (!tce_off) {
				buf_off = (dump_offset - sg_off) & ~0xfff;
				length = be64_to_cpu(entry->length) - buf_off;
			} else {
				buf_off = 0;
				length = be64_to_cpu(entry->length);
			}

			/* Adjust length for last mapping */
			if (fetch_off <= length) {
				length = fetch_off;
				last = true;
			}

			/* Adjust offset */
			sg_off += be64_to_cpu(entry->length);
			fetch_off -= length;

			/* TCE mapping */
			dump_tce_map(tce_off, (void*)(be64_to_cpu(entry->data) + buf_off), length);
			tce_off += length;

			/* TCE mapping complete */
			if (last)
				return OPAL_SUCCESS;
		}
	} /* outer loop */
	return OPAL_PARAMETER;
}

static void dump_read_complete(struct fsp_msg *msg)
{
	void *buffer;
	size_t length, offset;
	int rc;
	uint32_t dump_id;
	uint16_t id;
	uint8_t flags, status;
	bool compl = false;

	status = (msg->resp->word1 >> 8) & 0xff;
	flags = (fsp_msg_get_data_word(msg, 0) >> 16) & 0xff;
	id = fsp_msg_get_data_word(msg, 0) & 0xffff;
	dump_id = fsp_msg_get_data_word(msg, 1);
	offset = fsp_msg_get_data_word(msg->resp, 1);
	length = fsp_msg_get_data_word(msg->resp, 2);

	fsp_freemsg(msg);

	lock(&dump_lock);

	if (dump_state == DUMP_STATE_ABORTING) {
		printf("DUMP: Fetch dump aborted, ID = 0x%x\n", dump_id);
		dump_tce_unmap(PSI_DMA_DUMP_DATA_SIZE);
		update_dump_state(DUMP_STATE_NONE);
		goto bail;
	}

	switch (status) {
	case FSP_STATUS_SUCCESS: /* Fetch next dump block */
		if (dump_offset < dump_entry->size) {
			dump_tce_unmap(PSI_DMA_DUMP_DATA_SIZE);
			rc = fsp_dump_read();
			if (rc == OPAL_SUCCESS)
				goto bail;
		} else { /* Dump read complete */
			compl = true;
		}
		break;
	case FSP_STATUS_MORE_DATA:	/* More data to read */
		offset += length;
		buffer = (void *)PSI_DMA_DUMP_DATA + offset;
		fetch_remain -= length;

		rc = fsp_fetch_data_queue(flags, id, dump_id, offset, buffer,
					  &fetch_remain, dump_read_complete);
		if (rc == OPAL_SUCCESS)
			goto bail;
		break;
	default:
		break;
	}

	dump_tce_unmap(PSI_DMA_DUMP_DATA_SIZE);

	/* Update state */
	if (compl) {
		printf("DUMP: Fetch dump success. ID = 0x%x\n", dump_id);
		update_dump_state(DUMP_STATE_FETCH);
	} else {
		printf("DUMP: Fetch dump partial. ID = 0x%x\n", dump_id);
		update_dump_state(DUMP_STATE_PARTIAL);
	}
 bail:
	unlock(&dump_lock);
}

/*
 * Fetch dump data from FSP
 */
static int64_t fsp_dump_read(void)
{
	int64_t rc;
	uint16_t data_set;
	uint8_t flags = 0x00;

	/* Get data set ID */
	data_set = get_dump_data_set_id(dump_entry->type);

	/* Map TCE buffer */
	rc = map_dump_buffer();
	if (rc != OPAL_SUCCESS) {
		printf("DUMP: TCE mapping failed\n");
		return rc;
	}

	printf("DUMP: Fetch Dump. ID = %02x, sub ID = %08x, len = %ld\n",
	       data_set, dump_entry->id, fetch_remain);

	/* Fetch data */
	rc = fsp_fetch_data_queue(flags, data_set, dump_entry->id,
				  dump_offset, (void *)PSI_DMA_DUMP_DATA,
				  &fetch_remain, dump_read_complete);

	/* Adjust dump fetch offset */
	dump_offset += fetch_remain;

	return rc;
}

static int64_t fsp_opal_dump_read(uint32_t dump_id,
				  struct opal_sg_list *list)
{
	struct dump_record *record;
	int64_t rc, size;

	lock(&dump_lock);

	/* Check state */
	if (dump_state != DUMP_STATE_NOTIFY) {
		rc = check_dump_state();
		goto out;
	}

	/* Validate dump ID */
	record = get_dump_rec_from_list(dump_id);
	if (!record) { /* List corrupted? */
		rc = OPAL_INTERNAL_ERROR;
		goto out;
	}

	/* Validate dump buffer and size */
	rc = validate_dump_sglist(list, &size);
	if (rc != OPAL_SUCCESS) {
		printf("DUMP: SG list validation failed\n");
		goto out;
	}

	if (size < record->size) { /* Insuffient buffer */
		printf("DUMP: Insufficient buffer\n");
		rc = OPAL_PARAMETER;
		goto out;
	}

	/* Update state */
	update_dump_state(DUMP_STATE_FETCHING);

	/* Fetch dump data */
	dump_entry = record;
	dump_data = list;
	dump_offset = 0;
	rc = fsp_dump_read();
	if (rc != OPAL_SUCCESS)
		goto out;

	/* Check status after initiating fetch data */
	rc = check_dump_state();

out:
	unlock(&dump_lock);
	return rc;
}

static void dump_ack_complete(struct fsp_msg *msg)
{
	uint8_t status = (msg->resp->word1 >> 8) & 0xff;

	if (status)
		log_simple_error(&e_info(OPAL_RC_DUMP_ACK),
				 "DUMP: ACK failed for ID: 0x%x\n",
				 fsp_msg_get_data_word(msg, 0));
	else
		printf("DUMP: ACKed dump ID: 0x%x\n", fsp_msg_get_data_word(msg, 0));

	fsp_freemsg(msg);
}

/*
 * Acknowledge dump
 */
static int64_t fsp_opal_dump_ack(uint32_t dump_id)
{
	struct dump_record *record;
	struct fsp_msg *msg;
	int rc;
	uint32_t cmd;
	uint8_t dump_type = 0;

	/* Get dump type */
	lock(&dump_lock);
	record = get_dump_rec_from_list(dump_id);
	if (record)
		dump_type = record->type;

	/*
	 * Next available dump in pending list will be of different
	 * type. Hence we don't need to wait for ack complete.
	 *
	 * Note:
	 *   This allows us to proceed even if we fail to ACK.
	 *   In the worst case we may get notification for the
	 *   same dump again, which is probably better than
	 *   looping forever.
	 */
	rc = remove_dump_id_from_list(dump_id);
	if (rc != OPAL_SUCCESS) /* Invalid dump id */
		goto out;

	/* Adjust mod value */
	cmd = FSP_CMD_ACK_DUMP | (dump_type & 0xff);
	msg = fsp_mkmsg(cmd, 1, dump_id);
	if (!msg) {
		log_simple_error(&e_info(OPAL_RC_DUMP_ACK),
				 "DUMP: Message allocation failed.!\n");
		rc = OPAL_INTERNAL_ERROR;
	} else if (fsp_queue_msg(msg, dump_ack_complete)) {
		log_simple_error(&e_info(OPAL_RC_DUMP_ACK),
			"DUMP: Failed to queue dump ack message.\n");
		fsp_freemsg(msg);
		rc = OPAL_INTERNAL_ERROR;
	}
out:
	unlock(&dump_lock);
	return rc;
}

/* Resend dump available notification */
static int64_t fsp_opal_dump_resend_notification(void)
{
	lock(&dump_lock);

	if (dump_state != DUMP_STATE_ABSENT)
		update_dump_state(DUMP_STATE_NONE);

	update_opal_dump_notify();

	unlock(&dump_lock);

	return OPAL_SUCCESS;
}

/*
 * Handle FSP R/R event.
 */
static bool fsp_dump_retrieve_rr(uint32_t cmd_sub_mod,
				 struct fsp_msg *msg __unused)
{
	switch (cmd_sub_mod) {
	case FSP_RESET_START:
		lock(&dump_lock);
		/* Reset dump state */
		if (dump_state == DUMP_STATE_FETCHING)
			update_dump_state(DUMP_STATE_ABORTING);
		unlock(&dump_lock);
		return true;
	case FSP_RELOAD_COMPLETE:
		lock(&dump_lock);

		/* Reset TCE mapping */
		dump_tce_unmap(PSI_DMA_DUMP_DATA_SIZE);

		/* Reset dump state */
		update_dump_state(DUMP_STATE_NONE);

		/*
		 * For now keeping R/R handler simple. In the worst case
		 * we may endup resending dump available notification for
		 * same dump ID twice to Linux.
		 */
		update_opal_dump_notify();
		unlock(&dump_lock);
		return true;
	}
	return false;
}

/*
 * Handle host kexec'ing scenarios
 */
static bool opal_kexec_dump_notify(void *data __unused)
{
	bool ready = true;

	lock(&dump_lock);

	/* Dump retrieve is in progress? */
	if (dump_state == DUMP_STATE_FETCHING)
		dump_state = DUMP_STATE_ABORTING;

	/* Not yet safe to kexec */
	if (dump_state == DUMP_STATE_ABORTING)
		ready = false;

	unlock(&dump_lock);

	return ready;
}

/*
 * FipS dump notification
 */
void fsp_fips_dump_notify(uint32_t dump_id, uint32_t dump_size)
{
	printf("DUMP: FipS dump available. ID = 0x%x [size: %d bytes]\n",
	       dump_id, dump_size);
	add_dump_id_to_list(DUMP_TYPE_FSP, dump_id, dump_size);
}

/*
 * System/Platform dump notification
 */
static bool fsp_sys_dump_notify(uint32_t cmd_sub_mod, struct fsp_msg *msg)
{
	/*
	 * Though spec says mod 00 is deprecated we still
	 * seems to get mod 00 notification (at least on
	 * P7 machine).
	 */
	if (cmd_sub_mod != FSP_RSP_SYS_DUMP &&
	    cmd_sub_mod != FSP_RSP_SYS_DUMP_OLD)
		return false;

	printf("DUMP: Platform dump available. ID = 0x%x [size: %d bytes]\n",
	       fsp_msg_get_data_word(msg, 0), fsp_msg_get_data_word(msg, 1));

	add_dump_id_to_list(DUMP_TYPE_SYS,
			    fsp_msg_get_data_word(msg, 0),
			    fsp_msg_get_data_word(msg, 1));
	return true;
}

/*
 * If platform dump available during IPL time, then we
 * get notification via HDAT. Check for DT for the dump
 * presence.
 */
static void check_ipl_sys_dump(void)
{
	struct dt_node *dump_node, *opal_node;
	uint32_t dump_id, dump_size;

	if (proc_gen >= proc_gen_p9) {
		opal_node = dt_find_by_path(dt_root, "ibm,opal");
		if (!opal_node)
			return;
		dump_node = dt_find_by_path(opal_node, "dump");
		if (dump_node) {
			if (dt_find_property(dump_node, "mpipl-boot"))
				return;
		}
	}

	dump_node = dt_find_by_path(dt_root, "ipl-params/platform-dump");
	if (!dump_node)
		return;

	if (!dt_find_property(dump_node, "dump-id"))
		return;

	dump_id = dt_prop_get_u32(dump_node, "dump-id");
	dump_size = (uint32_t)dt_prop_get_u64(dump_node, "total-size");

	printf("DUMP: Platform dump present during IPL.\n");
	printf("      ID = 0x%x [size: %d bytes]\n", dump_id, dump_size);

	add_dump_id_to_list(DUMP_TYPE_SYS, dump_id, dump_size);
}

/*
 * Allocate and initialize dump list
 */
static int init_dump_free_list(void)
{
	struct dump_record *entry;
	int i;

	entry = zalloc(sizeof(struct dump_record) * MAX_DUMP_RECORD);
	if (!entry) {
		log_simple_error(&e_info(OPAL_RC_DUMP_INIT),
				 "DUMP: Out of memory\n");
		return -ENOMEM;
	}

	for (i = 0; i < MAX_DUMP_RECORD; i++) {
		list_add_tail(&dump_free, &entry->link);
		entry++;
	}
	return 0;
}

static struct fsp_client fsp_sys_dump_client = {
	.message = fsp_sys_dump_notify,
};

static struct fsp_client fsp_dump_client_rr = {
	.message = fsp_dump_retrieve_rr,
};

void fsp_dump_init(void)
{
	if (!fsp_present()) {
		update_dump_state(DUMP_STATE_ABSENT);
		return;
	}

	/* Initialize list */
	if (init_dump_free_list() != 0) {
		update_dump_state(DUMP_STATE_ABSENT);
		return;
	}

	/* Register for Class CE */
	fsp_register_client(&fsp_sys_dump_client, FSP_MCLASS_SERVICE);
	/* Register for Class AA (FSP R/R) */
	fsp_register_client(&fsp_dump_client_rr, FSP_MCLASS_RR_EVENT);

	/* Register for sync on host reboot call */
	opal_add_host_sync_notifier(opal_kexec_dump_notify, NULL);

	/* OPAL interface */
	opal_register(OPAL_DUMP_INIT, fsp_opal_dump_init, 1);
	opal_register(OPAL_DUMP_INFO, fsp_opal_dump_info, 2);
	opal_register(OPAL_DUMP_INFO2, fsp_opal_dump_info2, 3);
	opal_register(OPAL_DUMP_READ, fsp_opal_dump_read, 2);
	opal_register(OPAL_DUMP_ACK, fsp_opal_dump_ack, 1);
	opal_register(OPAL_DUMP_RESEND, fsp_opal_dump_resend_notification, 0);

	/* Check for platform dump presence during IPL time */
	check_ipl_sys_dump();
}
