// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2018-2019 IBM Corp. */

#define pr_fmt(fmt) "HIOMAP: " fmt

#include <hiomap.h>
#include <inttypes.h>
#include <ipmi.h>
#include <lpc.h>
#include <mem_region-malloc.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <ccan/container_of/container_of.h>

#include "errors.h"
#include "ipmi-hiomap.h"

#define CMD_OP_HIOMAP_EVENT	0x0f

struct ipmi_hiomap_result {
	struct ipmi_hiomap *ctx;
	int16_t cc;
};

#define RESULT_INIT(_name, _ctx) struct ipmi_hiomap_result _name = { _ctx, -1 }

static inline uint32_t blocks_to_bytes(struct ipmi_hiomap *ctx, uint16_t blocks)
{
	return blocks << ctx->block_size_shift;
}

static inline uint16_t bytes_to_blocks(struct ipmi_hiomap *ctx, uint32_t bytes)
{
	return bytes >> ctx->block_size_shift;
}

static inline uint16_t bytes_to_blocks_align_up(struct ipmi_hiomap *ctx,
						uint32_t pos, uint32_t len)
{
	uint32_t block_size = 1 << ctx->block_size_shift;
	uint32_t delta = pos & (block_size - 1);
	uint32_t aligned = ALIGN_UP((len + delta), block_size);
	uint32_t blocks = aligned >> ctx->block_size_shift;
	/* Our protocol can handle block count < sizeof(u16) */
	uint32_t mask = ((1 << 16) - 1);

	assert(!(blocks & ~mask));

	return blocks & mask;
}

/* Call under ctx->lock */
static int hiomap_protocol_ready(struct ipmi_hiomap *ctx)
{
	if (!(ctx->bmc_state & HIOMAP_E_DAEMON_READY))
		return FLASH_ERR_DEVICE_GONE;
	if (ctx->bmc_state & HIOMAP_E_FLASH_LOST)
		return FLASH_ERR_AGAIN;

	return 0;
}

static int hiomap_queue_msg_sync(struct ipmi_hiomap *ctx, struct ipmi_msg *msg)
{
	int rc;

	/*
	 * There's an unavoidable TOCTOU race here with the BMC sending an
	 * event saying it's no-longer available right after we test but before
	 * we call into the IPMI stack to send the message.
	 * hiomap_queue_msg_sync() exists to capture the race in a single
	 * location.
	 */
	lock(&ctx->lock);
	rc = hiomap_protocol_ready(ctx);
	unlock(&ctx->lock);
	if (rc) {
		ipmi_free_msg(msg);
		return rc;
	}

	ipmi_queue_msg_sync(msg);

	return 0;
}

/* Call under ctx->lock */
static int hiomap_window_valid(struct ipmi_hiomap *ctx, uint64_t pos,
			        uint64_t len)
{
	if (ctx->bmc_state & HIOMAP_E_FLASH_LOST)
		return FLASH_ERR_AGAIN;
	if (ctx->bmc_state & HIOMAP_E_PROTOCOL_RESET)
		return FLASH_ERR_AGAIN;
	if (ctx->bmc_state & HIOMAP_E_WINDOW_RESET)
		return FLASH_ERR_AGAIN;
	if (ctx->window_state == closed_window)
		return FLASH_ERR_PARM_ERROR;
	if (pos < ctx->current.cur_pos)
		return FLASH_ERR_PARM_ERROR;
	if ((pos + len) > (ctx->current.cur_pos + ctx->current.size))
		return FLASH_ERR_PARM_ERROR;

	return 0;
}

static void ipmi_hiomap_cmd_cb(struct ipmi_msg *msg)
{
	struct ipmi_hiomap_result *res = msg->user_data;
	struct ipmi_hiomap *ctx = res->ctx;

	res->cc = msg->cc;
	if (msg->cc != IPMI_CC_NO_ERROR) {
		ipmi_free_msg(msg);
		return;
	}

	/* We at least need the command and sequence */
	if (msg->resp_size < 2) {
		prerror("Illegal response size: %u\n", msg->resp_size);
		res->cc = IPMI_ERR_UNSPECIFIED;
		ipmi_free_msg(msg);
		return;
	}

	if (msg->data[1] != ctx->seq) {
		prerror("Unmatched sequence number: wanted %u got %u\n",
			ctx->seq, msg->data[1]);
		res->cc = IPMI_ERR_UNSPECIFIED;
		ipmi_free_msg(msg);
		return;
	}

	switch (msg->data[0]) {
	case HIOMAP_C_GET_INFO:
	{
		struct hiomap_v2_info *parms;

		if (msg->resp_size != 6) {
			prerror("%u: Unexpected response size: %u\n", msg->data[0],
				msg->resp_size);
			res->cc = IPMI_ERR_UNSPECIFIED;
			break;
		}

		ctx->version = msg->data[2];
		if (ctx->version < 2) {
			prerror("Failed to negotiate protocol v2 or higher: %d\n",
				ctx->version);
			res->cc = IPMI_ERR_UNSPECIFIED;
			break;
		}

		parms = (struct hiomap_v2_info *)&msg->data[3];
		ctx->block_size_shift = parms->block_size_shift;
		ctx->timeout = le16_to_cpu(parms->timeout);
		break;
	}
	case HIOMAP_C_GET_FLASH_INFO:
	{
		struct hiomap_v2_flash_info *parms;

		if (msg->resp_size != 6) {
			prerror("%u: Unexpected response size: %u\n", msg->data[0],
				msg->resp_size);
			res->cc = IPMI_ERR_UNSPECIFIED;
			break;
		}

		parms = (struct hiomap_v2_flash_info *)&msg->data[2];
		ctx->total_size =
			blocks_to_bytes(ctx, le16_to_cpu(parms->total_size));
		ctx->erase_granule =
			blocks_to_bytes(ctx, le16_to_cpu(parms->erase_granule));
		break;
	}
	case HIOMAP_C_CREATE_READ_WINDOW:
	case HIOMAP_C_CREATE_WRITE_WINDOW:
	{
		struct hiomap_v2_create_window *parms;

		if (msg->resp_size != 8) {
			prerror("%u: Unexpected response size: %u\n", msg->data[0],
				msg->resp_size);
			res->cc = IPMI_ERR_UNSPECIFIED;
			break;
		}

		parms = (struct hiomap_v2_create_window *)&msg->data[2];

		ctx->current.lpc_addr =
			blocks_to_bytes(ctx, le16_to_cpu(parms->lpc_addr));
		ctx->current.size =
			blocks_to_bytes(ctx, le16_to_cpu(parms->size));
		ctx->current.cur_pos =
			blocks_to_bytes(ctx, le16_to_cpu(parms->offset));

		lock(&ctx->lock);
		if (msg->data[0] == HIOMAP_C_CREATE_READ_WINDOW)
			ctx->window_state = read_window;
		else
			ctx->window_state = write_window;
		unlock(&ctx->lock);

		break;
	}
	case HIOMAP_C_MARK_DIRTY:
	case HIOMAP_C_FLUSH:
	case HIOMAP_C_ACK:
	case HIOMAP_C_ERASE:
	case HIOMAP_C_RESET:
		if (msg->resp_size != 2) {
			prerror("%u: Unexpected response size: %u\n", msg->data[0],
				msg->resp_size);
			res->cc = IPMI_ERR_UNSPECIFIED;
			break;
		}
		break;
	default:
		prlog(PR_WARNING, "Unimplemented command handler: %u\n",
		      msg->data[0]);
		break;
	};
	ipmi_free_msg(msg);
}

static void hiomap_init(struct ipmi_hiomap *ctx)
{
	/*
	 * Speculatively mark the daemon as available so we attempt to perform
	 * the handshake without immediately bailing out.
	 */
	lock(&ctx->lock);
	ctx->bmc_state = HIOMAP_E_DAEMON_READY;
	unlock(&ctx->lock);
}

static int hiomap_get_info(struct ipmi_hiomap *ctx)
{
	RESULT_INIT(res, ctx);
	unsigned char req[3];
	struct ipmi_msg *msg;
	int rc;

	/* Negotiate protocol version 2 */
	req[0] = HIOMAP_C_GET_INFO;
	req[1] = ++ctx->seq;
	req[2] = HIOMAP_V2;

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req), 6);

	rc = hiomap_queue_msg_sync(ctx, msg);
	if (rc)
		return rc;

	if (res.cc != IPMI_CC_NO_ERROR) {
		prerror("%s failed: %d\n", __func__, res.cc);
		return FLASH_ERR_PARM_ERROR; /* XXX: Find something better? */
	}

	return 0;
}

static int hiomap_get_flash_info(struct ipmi_hiomap *ctx)
{
	RESULT_INIT(res, ctx);
	unsigned char req[2];
	struct ipmi_msg *msg;
	int rc;

	req[0] = HIOMAP_C_GET_FLASH_INFO;
	req[1] = ++ctx->seq;
	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req), 2 + 2 + 2);

	rc = hiomap_queue_msg_sync(ctx, msg);
	if (rc)
		return rc;

	if (res.cc != IPMI_CC_NO_ERROR) {
		prerror("%s failed: %d\n", __func__, res.cc);
		return FLASH_ERR_PARM_ERROR; /* XXX: Find something better? */
	}

	return 0;
}

static int hiomap_window_move(struct ipmi_hiomap *ctx, uint8_t command,
			      uint64_t pos, uint64_t len, uint64_t *size)
{
	enum lpc_window_state want_state;
	struct hiomap_v2_range *range;
	RESULT_INIT(res, ctx);
	unsigned char req[6];
	struct ipmi_msg *msg;
	bool valid_state;
	bool is_read;
	int rc;

	is_read = (command == HIOMAP_C_CREATE_READ_WINDOW);
	want_state = is_read ? read_window : write_window;

	lock(&ctx->lock);

	valid_state = want_state == ctx->window_state;
	rc = hiomap_window_valid(ctx, pos, len);
	if (valid_state && !rc) {
		unlock(&ctx->lock);
		*size = len;
		return 0;
	}

	ctx->window_state = closed_window;

	unlock(&ctx->lock);

	req[0] = command;
	req[1] = ++ctx->seq;

	range = (struct hiomap_v2_range *)&req[2];
	range->offset = cpu_to_le16(bytes_to_blocks(ctx, pos));
	range->size = cpu_to_le16(bytes_to_blocks_align_up(ctx, pos, len));

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req),
			 2 + 2 + 2 + 2);

	rc = hiomap_queue_msg_sync(ctx, msg);
	if (rc)
		return rc;

	if (res.cc != IPMI_CC_NO_ERROR) {
		prlog(PR_INFO, "%s failed: %d\n", __func__, res.cc);
		return FLASH_ERR_PARM_ERROR; /* XXX: Find something better? */
	}

	lock(&ctx->lock);
	*size = len;
	/* Is length past the end of the window? */
	if ((pos + len) > (ctx->current.cur_pos + ctx->current.size))
		/* Adjust size to meet current window */
		*size = (ctx->current.cur_pos + ctx->current.size) - pos;

	if (len != 0 && *size == 0) {
		unlock(&ctx->lock);
		prerror("Invalid window properties: len: %"PRIu64", size: %"PRIu64"\n",
			len, *size);
		return FLASH_ERR_PARM_ERROR;
	}

	prlog(PR_DEBUG, "Opened %s window from 0x%x for %u bytes at 0x%x\n",
	      (command == HIOMAP_C_CREATE_READ_WINDOW) ? "read" : "write",
	      ctx->current.cur_pos, ctx->current.size, ctx->current.lpc_addr);

	unlock(&ctx->lock);

	return 0;
}

static int hiomap_mark_dirty(struct ipmi_hiomap *ctx, uint64_t offset,
			      uint64_t size)
{
	struct hiomap_v2_range *range;
	enum lpc_window_state state;
	RESULT_INIT(res, ctx);
	unsigned char req[6];
	struct ipmi_msg *msg;
	uint32_t pos;
	int rc;

	lock(&ctx->lock);
	state = ctx->window_state;
	unlock(&ctx->lock);

	if (state != write_window)
		return FLASH_ERR_PARM_ERROR;

	req[0] = HIOMAP_C_MARK_DIRTY;
	req[1] = ++ctx->seq;

	pos = offset - ctx->current.cur_pos;
	range = (struct hiomap_v2_range *)&req[2];
	range->offset = cpu_to_le16(bytes_to_blocks(ctx, pos));
	range->size = cpu_to_le16(bytes_to_blocks_align_up(ctx, pos, size));

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req), 2);

	rc = hiomap_queue_msg_sync(ctx, msg);
	if (rc)
		return rc;

	if (res.cc != IPMI_CC_NO_ERROR) {
		prerror("%s failed: %d\n", __func__, res.cc);
		return FLASH_ERR_PARM_ERROR;
	}

	prlog(PR_DEBUG, "Marked flash dirty at 0x%" PRIx64 " for %" PRIu64 "\n",
	      offset, size);

	return 0;
}

static int hiomap_flush(struct ipmi_hiomap *ctx)
{
	enum lpc_window_state state;
	RESULT_INIT(res, ctx);
	unsigned char req[2];
	struct ipmi_msg *msg;
	int rc;

	lock(&ctx->lock);
	state = ctx->window_state;
	unlock(&ctx->lock);

	if (state != write_window)
		return FLASH_ERR_PARM_ERROR;

	req[0] = HIOMAP_C_FLUSH;
	req[1] = ++ctx->seq;

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req), 2);

	rc = hiomap_queue_msg_sync(ctx, msg);
	if (rc)
		return rc;

	if (res.cc != IPMI_CC_NO_ERROR) {
		prerror("%s failed: %d\n", __func__, res.cc);
		return FLASH_ERR_PARM_ERROR;
	}

	prlog(PR_DEBUG, "Flushed writes\n");

	return 0;
}

static int hiomap_ack(struct ipmi_hiomap *ctx, uint8_t ack)
{
	RESULT_INIT(res, ctx);
	unsigned char req[3];
	struct ipmi_msg *msg;
	int rc;

	req[0] = HIOMAP_C_ACK;
	req[1] = ++ctx->seq;
	req[2] = ack;

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req), 2);

	rc = hiomap_queue_msg_sync(ctx, msg);
	if (rc)
		return rc;

	if (res.cc != IPMI_CC_NO_ERROR) {
		prlog(PR_DEBUG, "%s failed: %d\n", __func__, res.cc);
		return FLASH_ERR_PARM_ERROR;
	}

	prlog(PR_DEBUG, "Acked events: 0x%x\n", ack);

	return 0;
}

static int hiomap_erase(struct ipmi_hiomap *ctx, uint64_t offset,
			 uint64_t size)
{
	struct hiomap_v2_range *range;
	enum lpc_window_state state;
	RESULT_INIT(res, ctx);
	unsigned char req[6];
	struct ipmi_msg *msg;
	uint32_t pos;
	int rc;

	lock(&ctx->lock);
	state = ctx->window_state;
	unlock(&ctx->lock);

	if (state != write_window)
		return FLASH_ERR_PARM_ERROR;

	req[0] = HIOMAP_C_ERASE;
	req[1] = ++ctx->seq;

	pos = offset - ctx->current.cur_pos;
	range = (struct hiomap_v2_range *)&req[2];
	range->offset = cpu_to_le16(bytes_to_blocks(ctx, pos));
	range->size = cpu_to_le16(bytes_to_blocks_align_up(ctx, pos, size));

	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req), 2);
	rc = hiomap_queue_msg_sync(ctx, msg);
	if (rc)
		return rc;

	if (res.cc != IPMI_CC_NO_ERROR) {
		prerror("%s failed: %d\n", __func__, res.cc);
		return FLASH_ERR_PARM_ERROR;
	}

	prlog(PR_DEBUG, "Erased flash at 0x%" PRIx64 " for %" PRIu64 "\n",
	      offset, size);

	return 0;
}

static bool hiomap_reset(struct ipmi_hiomap *ctx)
{
	RESULT_INIT(res, ctx);
	unsigned char req[2];
	struct ipmi_msg *msg;

	prlog(PR_NOTICE, "Reset\n");

	req[0] = HIOMAP_C_RESET;
	req[1] = ++ctx->seq;
	msg = ipmi_mkmsg(IPMI_DEFAULT_INTERFACE,
		         bmc_platform->sw->ipmi_oem_hiomap_cmd,
			 ipmi_hiomap_cmd_cb, &res, req, sizeof(req), 2);
	ipmi_queue_msg_sync(msg);

	if (res.cc != IPMI_CC_NO_ERROR) {
		prlog(PR_ERR, "%s failed: %d\n", __func__, res.cc);
		return false;
	}

	return true;
}

static void hiomap_event(uint8_t events, void *context)
{
	struct ipmi_hiomap *ctx = context;

	prlog(PR_DEBUG, "Received events: 0x%x\n", events);

	lock(&ctx->lock);
	ctx->bmc_state = events | (ctx->bmc_state & HIOMAP_E_ACK_MASK);
	unlock(&ctx->lock);
}

static int lpc_window_read(struct ipmi_hiomap *ctx, uint32_t pos,
			   void *buf, uint32_t len)
{
	uint32_t off = ctx->current.lpc_addr + (pos - ctx->current.cur_pos);
	int rc;

	if ((ctx->current.lpc_addr + ctx->current.size) < (off + len))
		return FLASH_ERR_PARM_ERROR;

	prlog(PR_TRACE, "Reading at 0x%08x for 0x%08x offset: 0x%08x\n",
	      pos, len, off);

	while(len) {
		uint32_t chunk;
		uint32_t dat;

		/* XXX: make this read until it's aligned */
		if (len > 3 && !(off & 3)) {
			rc = lpc_read(OPAL_LPC_FW, off, &dat, 4);
			if (!rc) {
				/*
				 * lpc_read swaps to CPU endian but it's not
				 * really a 32-bit value, so convert back.
				 */
				*(__be32 *)buf = cpu_to_be32(dat);
			}
			chunk = 4;
		} else {
			rc = lpc_read(OPAL_LPC_FW, off, &dat, 1);
			if (!rc)
				*(uint8_t *)buf = dat;
			chunk = 1;
		}
		if (rc) {
			prlog(PR_ERR, "lpc_read failure %d to FW 0x%08x\n", rc, off);
			return rc;
		}
		len -= chunk;
		off += chunk;
		buf += chunk;
	}

	return 0;
}

static int lpc_window_write(struct ipmi_hiomap *ctx, uint32_t pos,
			    const void *buf, uint32_t len)
{
	uint32_t off = ctx->current.lpc_addr + (pos - ctx->current.cur_pos);
	enum lpc_window_state state;
	int rc;

	lock(&ctx->lock);
	state = ctx->window_state;
	unlock(&ctx->lock);

	if (state != write_window)
		return FLASH_ERR_PARM_ERROR;

	if ((ctx->current.lpc_addr + ctx->current.size) < (off + len))
		return FLASH_ERR_PARM_ERROR;

	prlog(PR_TRACE, "Writing at 0x%08x for 0x%08x offset: 0x%08x\n",
	      pos, len, off);

	while(len) {
		uint32_t chunk;

		if (len > 3 && !(off & 3)) {
			/* endian swap: see lpc_window_read */
			uint32_t dat = be32_to_cpu(*(__be32 *)buf);

			rc = lpc_write(OPAL_LPC_FW, off, dat, 4);
			chunk = 4;
		} else {
			uint8_t dat = *(uint8_t *)buf;

			rc = lpc_write(OPAL_LPC_FW, off, dat, 1);
			chunk = 1;
		}
		if (rc) {
			prlog(PR_ERR, "lpc_write failure %d to FW 0x%08x\n", rc, off);
			return rc;
		}
		len -= chunk;
		off += chunk;
		buf += chunk;
	}

	return 0;
}

/* Best-effort asynchronous event handling by blocklevel callbacks */
static int ipmi_hiomap_handle_events(struct ipmi_hiomap *ctx)
{
	uint8_t status;
	int rc;

	lock(&ctx->lock);

	status = ctx->bmc_state;

	/*
	 * Immediately clear the ackable events to make sure we don't race to
	 * clear them after dropping the lock, as we may lose protocol or
	 * window state if a race materialises. In the event of a failure where
	 * we haven't completed the recovery, the state we mask out below gets
	 * OR'ed back in to avoid losing it.
	 */
	ctx->bmc_state &= ~HIOMAP_E_ACK_MASK;

	/*
	 * We won't be attempting to restore window state -
	 * ipmi_hiomap_handle_events() is followed by hiomap_window_move() in
	 * all cases. Attempting restoration after HIOMAP_E_PROTOCOL_RESET or
	 * HIOMAP_E_WINDOW_RESET can be wasteful if we immediately shift the
	 * window elsewhere, and if it does not need to be shifted with respect
	 * to the subsequent request then hiomap_window_move() will handle
	 * re-opening it from the closed state.
	 *
	 * Therefore it is enough to mark the window as closed to consider it
	 * recovered.
	 */
	if (status & (HIOMAP_E_PROTOCOL_RESET | HIOMAP_E_WINDOW_RESET))
		ctx->window_state = closed_window;

	unlock(&ctx->lock);

	/*
	 * If there's anything to acknowledge, do so in the one request to
	 * minimise overhead. By sending the ACK prior to performing the
	 * protocol recovery we ensure that even with coalesced resets we still
	 * end up in the recovered state and not unknowingly stuck in a reset
	 * state. We may receive reset events after the ACK but prior to the
	 * recovery procedures being run, but this just means that we will
	 * needlessly perform recovery on the following invocation of
	 * ipmi_hiomap_handle_events(). If the reset event is a
	 * HIOMAP_E_WINDOW_RESET it is enough that the window is already marked
	 * as closed above - future accesses will force it to be re-opened and
	 * the BMC's cache must be valid if opening the window is successful.
	 */
	if (status & HIOMAP_E_ACK_MASK) {
		/* ACK is unversioned, can send it if the daemon is ready */
		rc = hiomap_ack(ctx, status & HIOMAP_E_ACK_MASK);
		if (rc) {
			prlog(PR_DEBUG, "Failed to ack events: 0x%x\n",
			      status & HIOMAP_E_ACK_MASK);
			goto restore;
		}
	}

	if (status & HIOMAP_E_PROTOCOL_RESET) {
		prlog(PR_INFO, "Protocol was reset\n");

		rc = hiomap_get_info(ctx);
		if (rc) {
			prerror("Failure to renegotiate after protocol reset\n");
			goto restore;
		}

		rc = hiomap_get_flash_info(ctx);
		if (rc) {
			prerror("Failure to fetch flash info after protocol reset\n");
			goto restore;
		}

		prlog(PR_INFO, "Restored state after protocol reset\n");
	}

	/*
	 * As there's no change to the protocol on HIOMAP_E_WINDOW_RESET we
	 * simply need to open a window to recover, which as mentioned above is
	 * handled by hiomap_window_move() after our cleanup here.
	 */

	return 0;

restore:
	/*
	 * Conservatively restore the events to the un-acked state to avoid
	 * losing events due to races. It might cause us to restore state more
	 * than necessary, but never less than necessary.
	 */
	lock(&ctx->lock);
	ctx->bmc_state |= (status & HIOMAP_E_ACK_MASK);
	unlock(&ctx->lock);

	return rc;
}

static int ipmi_hiomap_read(struct blocklevel_device *bl, uint64_t pos,
			    void *buf, uint64_t len)
{
	struct ipmi_hiomap *ctx;
	uint64_t size;
	int rc = 0;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || len > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	ctx = container_of(bl, struct ipmi_hiomap, bl);

	rc = ipmi_hiomap_handle_events(ctx);
	if (rc)
		return rc;

	prlog(PR_TRACE, "Flash read at %#" PRIx64 " for %#" PRIx64 "\n", pos,
	      len);
	while (len > 0) {
		/* Move window and get a new size to read */
		rc = hiomap_window_move(ctx, HIOMAP_C_CREATE_READ_WINDOW, pos,
				        len, &size);
		if (rc)
			return rc;

		/* Perform the read for this window */
		rc = lpc_window_read(ctx, pos, buf, size);
		if (rc)
			return rc;

		/* Check we can trust what we read */
		lock(&ctx->lock);
		rc = hiomap_window_valid(ctx, pos, size);
		unlock(&ctx->lock);
		if (rc)
			return rc;

		len -= size;
		pos += size;
		buf += size;
	}
	return rc;

}

static int ipmi_hiomap_write(struct blocklevel_device *bl, uint64_t pos,
			     const void *buf, uint64_t len)
{
	struct ipmi_hiomap *ctx;
	uint64_t size;
	int rc = 0;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || len > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	ctx = container_of(bl, struct ipmi_hiomap, bl);

	rc = ipmi_hiomap_handle_events(ctx);
	if (rc)
		return rc;

	prlog(PR_TRACE, "Flash write at %#" PRIx64 " for %#" PRIx64 "\n", pos,
	      len);
	while (len > 0) {
		/* Move window and get a new size to read */
		rc = hiomap_window_move(ctx, HIOMAP_C_CREATE_WRITE_WINDOW, pos,
				        len, &size);
		if (rc)
			return rc;

		/* Perform the write for this window */
		rc = lpc_window_write(ctx, pos, buf, size);
		if (rc)
			return rc;

		/*
		 * Unlike ipmi_hiomap_read() we don't explicitly test if the
		 * window is still valid after completing the LPC accesses as
		 * the following hiomap_mark_dirty() will implicitly check for
		 * us. In the case of a read operation there's no requirement
		 * that a command that validates window state follows, so the
		 * read implementation explicitly performs a check.
		 */

		rc = hiomap_mark_dirty(ctx, pos, size);
		if (rc)
			return rc;

		/*
		 * The BMC *should* flush if the window is implicitly closed,
		 * but do an explicit flush here to be sure.
		 *
		 * XXX: Removing this could improve performance
		 */
		rc = hiomap_flush(ctx);
		if (rc)
			return rc;

		len -= size;
		pos += size;
		buf += size;
	}
	return rc;
}

static int ipmi_hiomap_erase(struct blocklevel_device *bl, uint64_t pos,
			     uint64_t len)
{
	struct ipmi_hiomap *ctx;
	int rc;

	/* LPC is only 32bit */
	if (pos > UINT_MAX || len > UINT_MAX)
		return FLASH_ERR_PARM_ERROR;

	ctx = container_of(bl, struct ipmi_hiomap, bl);

	rc = ipmi_hiomap_handle_events(ctx);
	if (rc)
		return rc;

	prlog(PR_TRACE, "Flash erase at 0x%08x for 0x%08x\n", (u32) pos,
	      (u32) len);
	while (len > 0) {
		uint64_t size;

		/* Move window and get a new size to erase */
		rc = hiomap_window_move(ctx, HIOMAP_C_CREATE_WRITE_WINDOW, pos,
				        len, &size);
		if (rc)
			return rc;

		rc = hiomap_erase(ctx, pos, size);
		if (rc)
			return rc;

		/*
		 * Flush directly, don't mark that region dirty otherwise it
		 * isn't clear if a write happened there or not
		 */
		rc = hiomap_flush(ctx);
		if (rc)
			return rc;

		len -= size;
		pos += size;
	}

	return 0;
}

static int ipmi_hiomap_get_flash_info(struct blocklevel_device *bl,
				      const char **name, uint64_t *total_size,
				      uint32_t *erase_granule)
{
	struct ipmi_hiomap *ctx;
	int rc;

	ctx = container_of(bl, struct ipmi_hiomap, bl);

	rc = ipmi_hiomap_handle_events(ctx);
	if (rc)
		return rc;

	rc = hiomap_get_flash_info(ctx);
	if (rc)
		return rc;

	ctx->bl.erase_mask = ctx->erase_granule - 1;

	if (name)
		*name = NULL;
	if (total_size)
		*total_size = ctx->total_size;
	if (erase_granule)
		*erase_granule = ctx->erase_granule;

	return 0;
}

int ipmi_hiomap_init(struct blocklevel_device **bl)
{
	struct ipmi_hiomap *ctx;
	int rc;

	if (!bmc_platform->sw->ipmi_oem_hiomap_cmd)
		/* FIXME: Find a better error code */
		return FLASH_ERR_DEVICE_GONE;

	if (!bl)
		return FLASH_ERR_PARM_ERROR;

	*bl = NULL;

	ctx = zalloc(sizeof(struct ipmi_hiomap));
	if (!ctx)
		return FLASH_ERR_MALLOC_FAILED;

	init_lock(&ctx->lock);

	ctx->bl.read = &ipmi_hiomap_read;
	ctx->bl.write = &ipmi_hiomap_write;
	ctx->bl.erase = &ipmi_hiomap_erase;
	ctx->bl.get_info = &ipmi_hiomap_get_flash_info;
	ctx->bl.exit = &ipmi_hiomap_exit;

	hiomap_init(ctx);

	/* Ack all pending ack-able events to avoid spurious failures */
	rc = hiomap_ack(ctx, HIOMAP_E_ACK_MASK);
	if (rc) {
		prlog(PR_DEBUG, "Failed to ack events: 0x%x\n",
		      HIOMAP_E_ACK_MASK);
		goto err;
	}

	rc = ipmi_sel_register(CMD_OP_HIOMAP_EVENT, hiomap_event, ctx);
	if (rc < 0)
		goto err;

	/* Negotiate protocol behaviour */
	rc = hiomap_get_info(ctx);
	if (rc) {
		prerror("Failed to get hiomap parameters: %d\n", rc);
		goto err;
	}

	/* Grab the flash parameters */
	rc = hiomap_get_flash_info(ctx);
	if (rc) {
		prerror("Failed to get flash parameters: %d\n", rc);
		goto err;
	}

	prlog(PR_NOTICE, "Negotiated hiomap protocol v%u\n", ctx->version);
	prlog(PR_NOTICE, "Block size is %uKiB\n",
	      1 << (ctx->block_size_shift - 10));
	prlog(PR_NOTICE, "BMC suggested flash timeout of %us\n", ctx->timeout);
	prlog(PR_NOTICE, "Flash size is %uMiB\n", ctx->total_size >> 20);
	prlog(PR_NOTICE, "Erase granule size is %uKiB\n",
	      ctx->erase_granule >> 10);

	ctx->bl.keep_alive = 0;

	*bl = &(ctx->bl);

	return 0;

err:
	free(ctx);

	return rc;
}

bool ipmi_hiomap_exit(struct blocklevel_device *bl)
{
	bool status = true;

	struct ipmi_hiomap *ctx;
	if (bl) {
		ctx = container_of(bl, struct ipmi_hiomap, bl);
		status = hiomap_reset(ctx);
		free(ctx);
	}

	return status;
}
