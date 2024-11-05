// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017 IBM Corp. */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <inttypes.h>

#include <sys/mman.h> /* for mprotect() */

#define pr_fmt(fmt) "MBOX-SERVER: " fmt
#include "skiboot.h"
#include "opal-api.h"

#include "mbox-server.h"
#include "stubs.h"

#define ERASE_GRANULE 0x100

#define LPC_BLOCKS 256

#define __unused          __attribute__((unused))

enum win_type {
	WIN_CLOSED,
	WIN_READ,
	WIN_WRITE
};

typedef void (*mbox_data_cb)(struct bmc_mbox_msg *msg, void *priv);
typedef void (*mbox_attn_cb)(uint8_t reg, void *priv);

struct {
	mbox_data_cb fn;
	void *cb_data;
	struct bmc_mbox_msg *msg;
	mbox_attn_cb attn;
	void *cb_attn;
} mbox_data;

static struct {
	int api;
	bool reset;

	void *lpc_base;
	size_t lpc_size;

	uint8_t attn_reg;

	uint32_t block_shift;
	uint32_t erase_granule;

	uint16_t def_read_win;  /* default window size in blocks */
	uint16_t def_write_win;

	uint16_t max_read_win; /* max window size in blocks */
	uint16_t max_write_win;

	enum win_type win_type;
	uint32_t win_base;
	uint32_t win_size;
	bool win_dirty;
} server_state;


static bool check_window(uint32_t pos, uint32_t size)
{
	/* If size is zero then all is well */
	if (size == 0)
		return true;

	if (server_state.api == 1) {
		/*
		 * Can actually be stricter in v1 because pos is relative to
		 * flash not window
		 */
		if (pos < server_state.win_base ||
				pos + size > server_state.win_base + server_state.win_size) {
			fprintf(stderr, "pos: 0x%08x size: 0x%08x aren't in active window\n",
					pos, size);
			fprintf(stderr, "window pos: 0x%08x window size: 0x%08x\n",
					server_state.win_base, server_state.win_size);
			return false;
		}
	} else {
		if (pos + size > server_state.win_base + server_state.win_size)
			return false;
	}
	return true;
}

/* skiboot test stubs */
int64_t lpc_read(enum OpalLPCAddressType __unused addr_type, uint32_t addr,
		 uint32_t *data, uint32_t sz);
int64_t lpc_read(enum OpalLPCAddressType __unused addr_type, uint32_t addr,
		 uint32_t *data, uint32_t sz)
{
	/* Let it read from a write window... Spec says it ok! */
	if (!check_window(addr, sz) || server_state.win_type == WIN_CLOSED)
		return 1;

	switch (sz) {
	case 1:
		*(uint8_t *)data = *(uint8_t *)(server_state.lpc_base + addr);
		break;
	case 2:
		*(uint16_t *)data = be16_to_cpu(*(uint16_t *)(server_state.lpc_base + addr));
		break;
	case 4:
		*(uint32_t *)data = be32_to_cpu(*(uint32_t *)(server_state.lpc_base + addr));
		break;
	default:
		prerror("Invalid data size %d\n", sz);
		return 1;
	}
	return 0;
}

int64_t lpc_write(enum OpalLPCAddressType __unused addr_type, uint32_t addr,
		  uint32_t data, uint32_t sz);
int64_t lpc_write(enum OpalLPCAddressType __unused addr_type, uint32_t addr,
		  uint32_t data, uint32_t sz)
{
	if (!check_window(addr, sz) || server_state.win_type != WIN_WRITE)
		return 1;
	switch (sz) {
	case 1:
		*(uint8_t *)(server_state.lpc_base + addr) = data;
		break;
	case 2:
		*(uint16_t *)(server_state.lpc_base + addr) = cpu_to_be16(data);
		break;
	case 4:
		*(uint32_t *)(server_state.lpc_base + addr) = cpu_to_be32(data);
		break;
	default:
		prerror("Invalid data size %d\n", sz);
		return 1;
	}
	return 0;
}

int bmc_mbox_register_attn(mbox_attn_cb handler, void *drv_data)
{
	mbox_data.attn = handler;
	mbox_data.cb_attn = drv_data;

	return 0;
}

uint8_t bmc_mbox_get_attn_reg(void)
{
	return server_state.attn_reg;
}

int bmc_mbox_register_callback(mbox_data_cb handler, void *drv_data)
{
	mbox_data.fn = handler;
	mbox_data.cb_data = drv_data;

	return 0;
}

static int close_window(bool check)
{
	/*
	 * This isn't strictly prohibited and some daemons let you close
	 * windows even if none are open.
	 * I've made the test fail because closing with no windows open is
	 * a sign that something 'interesting' has happened.
	 * You should investigate why
	 *
	 * If check is false it is because we just want to do the logic
	 * because open window has been called - you can open a window
	 * over a closed window obviously
	 */
	if (check && server_state.win_type == WIN_CLOSED)
		return MBOX_R_PARAM_ERROR;

	server_state.win_type = WIN_CLOSED;
	mprotect(server_state.lpc_base, server_state.lpc_size, PROT_NONE);

	return MBOX_R_SUCCESS;
}

static int do_dirty(uint32_t pos, uint32_t size)
{
	pos <<= server_state.block_shift;
	if (server_state.api > 1)
		size <<= server_state.block_shift;
	if (!check_window(pos, size)) {
		prlog(PR_ERR, "Trying to dirty not in open window range\n");
		return MBOX_R_PARAM_ERROR;
	}
	if (server_state.win_type != WIN_WRITE) {
		prlog(PR_ERR, "Trying to dirty not write window\n");
		return MBOX_R_PARAM_ERROR;
	}

	/* Thats about all actually */
	return MBOX_R_SUCCESS;
}

void check_timers(bool __unused unused)
{
	/* now that we've handled the message, holla-back */
	if (mbox_data.msg) {
		mbox_data.fn(mbox_data.msg, mbox_data.cb_data);
		mbox_data.msg = NULL;
	}
}

static int open_window(struct bmc_mbox_msg *msg, bool write, u32 offset, u32 size)
{
	int max_size = server_state.max_read_win << server_state.block_shift;
	//int win_size = server_state.def_read_win;
	enum win_type type = WIN_READ;
	int prot = PROT_READ;

	assert(server_state.win_type == WIN_CLOSED);

	/* Shift params up */
	offset <<= server_state.block_shift;
	size <<= server_state.block_shift;

	if (!size || server_state.api == 1)
		size = server_state.def_read_win << server_state.block_shift;

	if (write) {
		max_size = server_state.max_write_win << server_state.block_shift;
		//win_size = server_state.def_write_win;
		prot |= PROT_WRITE;
		type = WIN_WRITE;
		/* Use the default size if zero size is set */
		if (!size || server_state.api == 1)
			size = server_state.def_write_win << server_state.block_shift;
	}


	prlog(PR_INFO, "Opening range %#.8x, %#.8x for %s\n",
			offset, offset + size - 1, write ? "writing" : "reading");

	/* XXX: Document this behaviour */
	if ((size + offset) > server_state.lpc_size) {
		prlog(PR_INFO, "tried to open beyond end of flash\n");
		return MBOX_R_PARAM_ERROR;
	}

	/* XXX: should we do this before or after checking for errors?
	 * 	Doing it afterwards ensures consistency between
	 * 	implementations
	 */
	if (server_state.api == 2)
		size = MIN(size, max_size);

	mprotect(server_state.lpc_base + offset, size, prot);
	server_state.win_type = type;
	server_state.win_base = offset;
	server_state.win_size = size;

	memset(msg->args, 0, sizeof(msg->args));
	bmc_put_u16(msg, 0, offset >> server_state.block_shift);
	if (server_state.api == 1) {
		/*
		 * Put nonsense in here because v1 mbox-flash shouldn't know about it.
		 * If v1 mbox-flash does read this, 0xffff should trigger a big mistake.
		 */
		bmc_put_u16(msg, 2, 0xffff >> server_state.block_shift);
		bmc_put_u16(msg, 4, 0xffff >> server_state.block_shift);
	} else {
		bmc_put_u16(msg, 2, size >> server_state.block_shift);
		bmc_put_u16(msg, 4, offset >> server_state.block_shift);
	}
	return MBOX_R_SUCCESS;
}

int bmc_mbox_enqueue(struct bmc_mbox_msg *msg,
		unsigned int __unused timeout_sec)
{
	/*
	 * FIXME: should we be using the same storage for message
	 *        and response?
	 */
	int rc = MBOX_R_SUCCESS;
	uint32_t start, size;

	if (server_state.reset && msg->command != MBOX_C_GET_MBOX_INFO &&
				msg->command != MBOX_C_BMC_EVENT_ACK) {
		/*
		 * Real daemons should return an error, but for testing we'll
		 * be a bit more strict
		 */
		prlog(PR_EMERG, "Server was in reset state - illegal command %d\n",
			msg->command);
		exit(1);
	}

	switch (msg->command) {
		case MBOX_C_RESET_STATE:
			prlog(PR_INFO, "RESET_STATE\n");
			server_state.win_type = WIN_CLOSED;
			rc = open_window(msg, false, 0, LPC_BLOCKS);
			memset(msg->args, 0, sizeof(msg->args));
			break;

		case MBOX_C_GET_MBOX_INFO:
			prlog(PR_INFO, "GET_MBOX_INFO version = %d, block_shift = %d\n",
					server_state.api, server_state.block_shift);
			msg->args[0] = server_state.api;
			if (server_state.api == 1) {
				prlog(PR_INFO, "\tread_size = 0x%08x, write_size = 0x%08x\n",
						server_state.def_read_win, server_state.def_write_win);
				bmc_put_u16(msg, 1, server_state.def_read_win);
				bmc_put_u16(msg, 3, server_state.def_write_win);
				msg->args[5] = 0xff; /* If v1 reads this, 0xff will force the mistake */
			} else {
				msg->args[5] = server_state.block_shift;
			}
			server_state.reset = false;
			break;

		case MBOX_C_GET_FLASH_INFO:
			prlog(PR_INFO, "GET_FLASH_INFO: size: 0x%" PRIu64 ", erase: 0x%08x\n",
					server_state.lpc_size, server_state.erase_granule);
			if (server_state.api == 1) {
				bmc_put_u32(msg, 0, server_state.lpc_size);
				bmc_put_u32(msg, 4, server_state.erase_granule);
			} else {
				bmc_put_u16(msg, 0, server_state.lpc_size >> server_state.block_shift);
				bmc_put_u16(msg, 2, server_state.erase_granule >> server_state.block_shift);
			}
			break;

		case MBOX_C_CREATE_READ_WINDOW:
			start = bmc_get_u16(msg, 0);
			size = bmc_get_u16(msg, 2);
			prlog(PR_INFO, "CREATE_READ_WINDOW: pos: 0x%08x, len: 0x%08x\n", start, size);
			rc = close_window(false);
			if (rc != MBOX_R_SUCCESS)
				break;
			rc = open_window(msg, false, start, size);
			break;

		case MBOX_C_CLOSE_WINDOW:
			rc = close_window(true);
			break;

		case MBOX_C_CREATE_WRITE_WINDOW:
			start = bmc_get_u16(msg, 0);
			size = bmc_get_u16(msg, 2);
			prlog(PR_INFO, "CREATE_WRITE_WINDOW: pos: 0x%08x, len: 0x%08x\n", start, size);
			rc = close_window(false);
			if (rc != MBOX_R_SUCCESS)
				break;
			rc = open_window(msg, true, start, size);
			break;

		/* TODO: make these do something */
		case MBOX_C_WRITE_FLUSH:
			prlog(PR_INFO, "WRITE_FLUSH\n");
			/*
			 * This behaviour isn't strictly illegal however it could
			 * be a sign of bad behaviour
			 */
			if (server_state.api > 1 && !server_state.win_dirty) {
				prlog(PR_EMERG, "Version >1 called FLUSH without a previous DIRTY\n");
				exit (1);
			}
			server_state.win_dirty = false;
			if (server_state.api > 1)
				break;

			/* This is only done on V1 */
			start = bmc_get_u16(msg, 0);
			if (server_state.api == 1)
				size = bmc_get_u32(msg, 2);
			else
				size = bmc_get_u16(msg, 2);
			prlog(PR_INFO, "\tpos: 0x%08x len: 0x%08x\n", start, size);
			rc = do_dirty(start, size);
			break;
		case MBOX_C_MARK_WRITE_DIRTY:
			start = bmc_get_u16(msg, 0);
			if (server_state.api == 1)
				size = bmc_get_u32(msg, 2);
			else
				size = bmc_get_u16(msg, 2);
			prlog(PR_INFO, "MARK_WRITE_DIRTY: pos: 0x%08x, len: %08x\n", start, size);
			server_state.win_dirty = true;
			rc = do_dirty(start, size);
			break;
		case MBOX_C_BMC_EVENT_ACK:
			/*
			 * Clear any BMC notifier flags. Don't clear the server
			 * reset state here, it is a permitted command but only
			 * GET_INFO should clear it.
			 *
			 * Make sure that msg->args[0] is only acking bits we told
			 * it about, in server_state.attn_reg. The caveat is that
			 * it could NOT ack some bits...
			 */
			prlog(PR_INFO, "BMC_EVENT_ACK 0x%02x\n", msg->args[0]);
			if ((msg->args[0] | server_state.attn_reg) != server_state.attn_reg) {
				prlog(PR_EMERG, "Tried to ack bits we didn't say!\n");
				exit(1);
			}
			msg->bmc &= ~msg->args[0];
			server_state.attn_reg &= ~msg->args[0];
			break;
		case MBOX_C_MARK_WRITE_ERASED:
			start = bmc_get_u16(msg, 0) << server_state.block_shift;
			size = bmc_get_u16(msg, 2) << server_state.block_shift;
			/* If we've negotiated v1 this should never be called */
			if (server_state.api == 1) {
				prlog(PR_EMERG, "Version 1 protocol called a V2 only command\n");
				exit(1);
			}
			/*
			 * This will likely result in flush (but not
			 * dirty) being called. This is the point.
			 */
			server_state.win_dirty = true;
			/* This should really be done when they call flush */
			memset(server_state.lpc_base + server_state.win_base + start, 0xff, size);
			break;
		default:
			prlog(PR_EMERG, "Got unknown command code from mbox: %d\n", msg->command);
	}

	prerror("command response = %d\n", rc);
	msg->response = rc;

	mbox_data.msg = msg;

	return 0;
}

int mbox_server_memcmp(int off, const void *buf, size_t len)
{
	return memcmp(server_state.lpc_base + off, buf, len);
}

void mbox_server_memset(int c)
{
	memset(server_state.lpc_base, c, server_state.lpc_size);
}

uint32_t mbox_server_total_size(void)
{
	/* Not actually but for this server we don't differentiate */
	return server_state.lpc_size;
}

uint32_t mbox_server_erase_granule(void)
{
	return server_state.erase_granule;
}

int mbox_server_version(void)
{
	return server_state.api;
}

int mbox_server_reset(unsigned int version, uint8_t block_shift)
{
	if (version > 3)
		return 1;

	server_state.api = version;
	if (block_shift)
		server_state.block_shift = block_shift;
	if (server_state.erase_granule < (1 << server_state.block_shift))
		server_state.erase_granule = 1 << server_state.block_shift;
	server_state.lpc_size = LPC_BLOCKS * (1 << server_state.block_shift);
	free(server_state.lpc_base);
	server_state.lpc_base = malloc(server_state.lpc_size);
	server_state.attn_reg = MBOX_ATTN_BMC_REBOOT | MBOX_ATTN_BMC_DAEMON_READY;
	server_state.win_type = WIN_CLOSED;
	server_state.reset = true;
	mbox_data.attn(MBOX_ATTN_BMC_REBOOT, mbox_data.cb_attn);

	return 0;
}

int mbox_server_init(void)
{
	server_state.api = 1;
	server_state.reset = true;

	/* We're always ready! */
	server_state.attn_reg = MBOX_ATTN_BMC_DAEMON_READY;

	/* setup server */
	server_state.block_shift = 12;
	server_state.erase_granule = 0x1000;
	server_state.lpc_size = LPC_BLOCKS * (1 << server_state.block_shift);
	server_state.lpc_base = malloc(server_state.lpc_size);

	server_state.def_read_win = 1; /* These are in units of block shift "= 1 is 4K" */
	server_state.def_write_win = 1; /* These are in units of block shift "= 1 is 4K" */

	server_state.max_read_win = LPC_BLOCKS;
	server_state.max_write_win = LPC_BLOCKS;
	server_state.win_type = WIN_CLOSED;

	return 0;
}

void mbox_server_destroy(void)
{
	free(server_state.lpc_base);
}
