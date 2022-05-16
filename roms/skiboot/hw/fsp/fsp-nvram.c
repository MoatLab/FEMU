// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Read/Write NVRAM from/to FSP
 *
 * Copyright 2013-2017 IBM Corp.
 */

#include <skiboot.h>
#include <fsp.h>
#include <opal.h>
#include <lock.h>
#include <device.h>
#include <errorlog.h>

/*
 * The FSP NVRAM API operates in "blocks" of 4K. It is entirely exposed
 * to the OS via the OPAL APIs.
 *
 * In order to avoid dealing with complicated read/modify/write state
 * machines (and added issues related to FSP failover in the middle)
 * we keep a memory copy of the entire nvram which we load at boot
 * time. We save only modified blocks.
 *
 * To limit the amount of memory used by the nvram image, we limit
 * how much nvram we support to NVRAM_SIZE. Additionally, this limit
 * of 1M is the maximum that the CHRP/PAPR nvram partition format
 * supports for a partition entry.
 *
 * (Q: should we save the whole thing in case of FSP failover ?)
 *
 * The nvram is expected to comply with the CHRP/PAPR defined format,
 * and specifically contain a System partition (ID 0x70) named "common"
 * with configuration variables for the bootloader and a FW private
 * partition for future use by skiboot.
 *
 * If the partition layout appears broken or lacks one of the above
 * partitions, we reformat the entire nvram at boot time.
 *
 * We do not exploit the ability of the FSP to store a checksum. This
 * is documented as possibly going away. The CHRP format for nvram
 * that Linux uses has its own (though weak) checksum mechanism already
 *
 */

#define NVRAM_BLKSIZE	0x1000

struct nvram_triplet {
	__be64		dma_addr;
	__be32		blk_offset;
	__be32		blk_count;
} __packed;

#define NVRAM_FLAG_CLEAR_WPEND	0x80000000

enum nvram_state {
	NVRAM_STATE_CLOSED,
	NVRAM_STATE_OPENING,
	NVRAM_STATE_BROKEN,
	NVRAM_STATE_OPEN,
	NVRAM_STATE_ABSENT,
};

static void *fsp_nvram_image;
static uint32_t fsp_nvram_size;
static struct lock fsp_nvram_lock = LOCK_UNLOCKED;
static struct fsp_msg *fsp_nvram_msg;
static uint32_t fsp_nvram_dirty_start;
static uint32_t fsp_nvram_dirty_end;
static bool fsp_nvram_was_read;
static struct nvram_triplet fsp_nvram_triplet __align(0x1000);
static enum nvram_state fsp_nvram_state = NVRAM_STATE_CLOSED;

DEFINE_LOG_ENTRY(OPAL_RC_NVRAM_INIT, OPAL_PLATFORM_ERR_EVT , OPAL_NVRAM,
		OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_NVRAM_OPEN, OPAL_PLATFORM_ERR_EVT, OPAL_NVRAM,
		OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_NVRAM_SIZE, OPAL_PLATFORM_ERR_EVT, OPAL_NVRAM,
		OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_NVRAM_READ, OPAL_PLATFORM_ERR_EVT, OPAL_NVRAM,
		OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

DEFINE_LOG_ENTRY(OPAL_RC_NVRAM_WRITE, OPAL_PLATFORM_ERR_EVT, OPAL_NVRAM,
		OPAL_MISC_SUBSYSTEM, OPAL_PREDICTIVE_ERR_GENERAL,
		OPAL_NA);

static void fsp_nvram_send_write(void);

static void fsp_nvram_wr_complete(struct fsp_msg *msg)
{
	struct fsp_msg *resp = msg->resp;
	uint8_t rc;

	lock(&fsp_nvram_lock);
	fsp_nvram_msg = NULL;

	/* Check for various errors. If an error occurred,
	 * we generally assume the nvram is completely dirty
	 * but we won't trigger a new write until we get
	 * either a new attempt at writing, or an FSP reset
	 * reload (TODO)
	 */
	if (!resp || resp->state != fsp_msg_response)
		goto fail_dirty;
	rc = (msg->word1 >> 8) & 0xff;
	switch(rc) {
	case 0:
	case 0x44:
		/* Sync to secondary required... XXX */
	case 0x45:
		break;
	case 0xef:
		/* Sync to secondary failed, let's ignore that for now,
		 * maybe when (if) we handle redundant FSPs ...
		 */
		prerror("FSP: NVRAM sync to secondary failed\n");
		break;
	default:
		log_simple_error(&e_info(OPAL_RC_NVRAM_WRITE),
			"FSP: NVRAM write return error 0x%02x\n", rc);
		goto fail_dirty;
	}
	fsp_freemsg(msg);
	if (fsp_nvram_dirty_start <= fsp_nvram_dirty_end)
		fsp_nvram_send_write();
	unlock(&fsp_nvram_lock);
	return;
 fail_dirty:
	fsp_nvram_dirty_start = 0;
	fsp_nvram_dirty_end = fsp_nvram_size - 1;
	fsp_freemsg(msg);
	unlock(&fsp_nvram_lock);
}

static void fsp_nvram_send_write(void)
{
	uint32_t start = fsp_nvram_dirty_start;
	uint32_t end = fsp_nvram_dirty_end;
	uint32_t count;

	if (start > end || fsp_nvram_state != NVRAM_STATE_OPEN)
		return;
	count = (end - start) / NVRAM_BLKSIZE + 1;
	fsp_nvram_triplet.dma_addr = cpu_to_be64(PSI_DMA_NVRAM_BODY + start);
	fsp_nvram_triplet.blk_offset = cpu_to_be32(start / NVRAM_BLKSIZE);
	fsp_nvram_triplet.blk_count = cpu_to_be32(count);
	fsp_nvram_msg = fsp_mkmsg(FSP_CMD_WRITE_VNVRAM, 6,
				  0, PSI_DMA_NVRAM_TRIPL, 1,
				  NVRAM_FLAG_CLEAR_WPEND, 0, 0);
	if (fsp_queue_msg(fsp_nvram_msg, fsp_nvram_wr_complete)) {
		fsp_freemsg(fsp_nvram_msg);
		fsp_nvram_msg = NULL;
		log_simple_error(&e_info(OPAL_RC_NVRAM_WRITE),
				"FSP: Error queueing nvram update\n");
		return;
	}
	fsp_nvram_dirty_start = fsp_nvram_size;
	fsp_nvram_dirty_end = 0;
}

static void fsp_nvram_rd_complete(struct fsp_msg *msg)
{
	int64_t rc;

	lock(&fsp_nvram_lock);

	/* Read complete, check status. What to do if the read fails ?
	 *
	 * Well, there could be various reasons such as an FSP reboot
	 * at the wrong time, but there is really not much we can do
	 * so for now I'll just mark the nvram as closed, and we'll
	 * attempt a re-open and re-read whenever the OS tries to
	 * access it
	 */
	rc = (msg->resp->word1 >> 8) & 0xff;
	fsp_nvram_msg = NULL;
	fsp_freemsg(msg);
	if (rc) {
		prerror("FSP: NVRAM read failed, will try again later\n");
		fsp_nvram_state = NVRAM_STATE_CLOSED;
	} else {
		/* nvram was read once, no need to do it ever again */
		fsp_nvram_was_read = true;
		fsp_nvram_state = NVRAM_STATE_OPEN;

		/* XXX Here we should look for nvram settings that concern
		 * us such as guest kernel arguments etc...
		 */
	}
	unlock(&fsp_nvram_lock);
	nvram_read_complete(fsp_nvram_state == NVRAM_STATE_OPEN);
	if (fsp_nvram_state != NVRAM_STATE_OPEN)
		log_simple_error(&e_info(OPAL_RC_NVRAM_INIT),
		"FSP: NVRAM not read, skipping init\n");
}

static void fsp_nvram_send_read(void)
{
	fsp_nvram_msg = fsp_mkmsg(FSP_CMD_READ_VNVRAM, 4,
				  0, PSI_DMA_NVRAM_BODY, 0,
				  fsp_nvram_size / NVRAM_BLKSIZE);
	if (fsp_queue_msg(fsp_nvram_msg, fsp_nvram_rd_complete)) {
		/* If the nvram read fails to queue, we mark ourselves
		 * closed. Shouldn't have happened anyway. Not much else
		 * we can do.
		 */
		fsp_nvram_state = NVRAM_STATE_CLOSED;
		fsp_freemsg(fsp_nvram_msg);
		fsp_nvram_msg = NULL;
		log_simple_error(&e_info(OPAL_RC_NVRAM_READ),
				"FSP: Error queueing nvram read\n");
		return;
	}
}

static void fsp_nvram_open_complete(struct fsp_msg *msg)
{
	int8_t rc;

	lock(&fsp_nvram_lock);

	/* Open complete, check status */
	rc = (msg->resp->word1 >> 8) & 0xff;
	fsp_nvram_msg = NULL;
	fsp_freemsg(msg);
	if (rc) {
		log_simple_error(&e_info(OPAL_RC_NVRAM_OPEN),
			"FSP: NVRAM open failed, FSP error 0x%02x\n", rc);
		goto failed;
	}
	if (fsp_nvram_was_read)
		fsp_nvram_state = NVRAM_STATE_OPEN;
	else
		fsp_nvram_send_read();
	unlock(&fsp_nvram_lock);
	return;
 failed:
	fsp_nvram_state = NVRAM_STATE_CLOSED;
	unlock(&fsp_nvram_lock);
}

static void fsp_nvram_send_open(void)
{
	printf("FSP NVRAM: Opening nvram...\n");
	fsp_nvram_msg = fsp_mkmsg(FSP_CMD_OPEN_VNVRAM, 1, fsp_nvram_size);
	assert(fsp_nvram_msg);
	fsp_nvram_state = NVRAM_STATE_OPENING;
	if (!fsp_queue_msg(fsp_nvram_msg, fsp_nvram_open_complete))
		return;

	prerror("FSP NVRAM: Failed to queue nvram open message\n");
	fsp_freemsg(fsp_nvram_msg);
	fsp_nvram_msg = NULL;
	fsp_nvram_state = NVRAM_STATE_CLOSED;
}

static bool fsp_nvram_get_size(uint32_t *out_size)
{
	struct fsp_msg *msg;
	int rc, size;

	msg = fsp_mkmsg(FSP_CMD_GET_VNVRAM_SIZE, 0);
	assert(msg);

	rc = fsp_sync_msg(msg, false);
	size = msg->resp ? fsp_msg_get_data_word(msg->resp, 0) : 0;
	fsp_freemsg(msg);
	if (rc || size == 0) {
		log_simple_error(&e_info(OPAL_RC_NVRAM_SIZE),
			"FSP: Error %d nvram size reported is %d\n", rc, size);
		fsp_nvram_state = NVRAM_STATE_BROKEN;
		return false;
	}
	printf("FSP: NVRAM file size from FSP is %d bytes\n", size);
	*out_size = size;
	return true;
}

static bool fsp_nvram_msg_rr(u32 cmd_sub_mod, struct fsp_msg *msg)
{
	assert(msg == NULL);

	switch (cmd_sub_mod) {
	case FSP_RESET_START:
		printf("FSP: Closing NVRAM on account of FSP Reset\n");
		fsp_nvram_state = NVRAM_STATE_CLOSED;
		return true;
	case FSP_RELOAD_COMPLETE:
		printf("FSP: Reopening NVRAM of FSP Reload complete\n");
		lock(&fsp_nvram_lock);
		fsp_nvram_send_open();
		unlock(&fsp_nvram_lock);
		return true;
	}
	return false;
}

static struct fsp_client fsp_nvram_client_rr = {
	.message = fsp_nvram_msg_rr,
};

static bool fsp_vnvram_msg(u32 cmd_sub_mod, struct fsp_msg *msg __unused)
{
	u32 cmd;
	struct fsp_msg *resp;

	switch (cmd_sub_mod) {
	case FSP_CMD_GET_VNV_STATS:
		prlog(PR_DEBUG,
		      "FSP NVRAM: Get vNVRAM statistics not supported\n");
		cmd = FSP_RSP_GET_VNV_STATS | FSP_STATUS_INVALID_SUBCMD;
		break;
	case FSP_CMD_FREE_VNV_STATS:
		prlog(PR_DEBUG,
		      "FSP NVRAM: Free vNVRAM statistics buffer not supported\n");
		cmd = FSP_RSP_FREE_VNV_STATS | FSP_STATUS_INVALID_SUBCMD;
		break;
	default:
		return false;
	}

	resp = fsp_mkmsg(cmd, 0);
	if (!resp) {
		prerror("FSP NVRAM: Failed to allocate resp message\n");
		return false;
	}
	if (fsp_queue_msg(resp, fsp_freemsg)) {
		prerror("FSP NVRAM: Failed to queue resp message\n");
		fsp_freemsg(resp);
		return false;
	}
	return true;
}

static struct fsp_client fsp_vnvram_client = {
	.message = fsp_vnvram_msg,
};

int fsp_nvram_info(uint32_t *total_size)
{
	if (!fsp_present()) {
		fsp_nvram_state = NVRAM_STATE_ABSENT;
		return OPAL_HARDWARE;
	}

	if (!fsp_nvram_get_size(total_size))
		return OPAL_HARDWARE;
	return OPAL_SUCCESS;
}

int fsp_nvram_start_read(void *dst, uint32_t src, uint32_t len)
{
	/* We are currently limited to fully aligned transfers */
	assert((((uint64_t)dst) & 0xfff) == 0);
	assert(dst);

	/* Currently don't support src!=0 */
	assert(src == 0);

	if (!fsp_present())
		return -ENODEV;

	op_display(OP_LOG, OP_MOD_INIT, 0x0007);

	lock(&fsp_nvram_lock);

	/* Store image info */
	fsp_nvram_image = dst;
	fsp_nvram_size = len;

	/* Mark nvram as not dirty */
	fsp_nvram_dirty_start = len;
	fsp_nvram_dirty_end = 0;

	/* Map TCEs */
	fsp_tce_map(PSI_DMA_NVRAM_TRIPL, &fsp_nvram_triplet,
		    PSI_DMA_NVRAM_TRIPL_SZ);
	fsp_tce_map(PSI_DMA_NVRAM_BODY, dst, PSI_DMA_NVRAM_BODY_SZ);

	/* Register for the reset/reload event */
	fsp_register_client(&fsp_nvram_client_rr, FSP_MCLASS_RR_EVENT);

	/* Register for virtual NVRAM interface events */
	fsp_register_client(&fsp_vnvram_client, FSP_MCLASS_VIRTUAL_NVRAM);

	/* Open and load the nvram from the FSP */
	fsp_nvram_send_open();

	unlock(&fsp_nvram_lock);

	return 0;
}

int fsp_nvram_write(uint32_t offset, void *src, uint32_t size)
{
	uint64_t end = offset + size - 1;

	/* We only support writing from the original image */
	if (src != fsp_nvram_image + offset)
		return OPAL_HARDWARE;

	offset &= ~(NVRAM_BLKSIZE - 1);
	end &= ~(NVRAM_BLKSIZE - 1);

	lock(&fsp_nvram_lock);
	/* If the nvram is closed, try re-opening */
	if (fsp_nvram_state == NVRAM_STATE_CLOSED)
		fsp_nvram_send_open();
	if (fsp_nvram_dirty_start > offset)
		fsp_nvram_dirty_start = offset;
	if (fsp_nvram_dirty_end < end)
		fsp_nvram_dirty_end = end;
	if (!fsp_nvram_msg && fsp_nvram_state == NVRAM_STATE_OPEN)
		fsp_nvram_send_write();
	unlock(&fsp_nvram_lock);

	return 0;
}
