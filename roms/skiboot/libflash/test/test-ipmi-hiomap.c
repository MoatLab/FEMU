// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2018-2019 IBM Corp. */

#include <assert.h>
#include <ccan/container_of/container_of.h>
#include <libflash/blocklevel.h>
#include <lock.h>
#include <lpc.h>
#include <hiomap.h>
#include <ipmi.h>
#include <opal-api.h>
#include <platform.h>
#include <stdio.h>
#include <stdlib.h>

#include "../ipmi-hiomap.h"
#include "../errors.h"

/* Stub for blocklevel debug macros */
bool libflash_debug;

const struct bmc_sw_config bmc_sw_hiomap = {
	.ipmi_oem_hiomap_cmd         = IPMI_CODE(0x3a, 0x5a),
};

const struct bmc_platform _bmc_platform = {
	.name = "generic:hiomap",
	.sw = &bmc_sw_hiomap,
};

enum scenario_event_type {
	scenario_sentinel = 0,
	scenario_event_p,
	scenario_cmd,
	scenario_sel,
	scenario_delay,
};

struct scenario_cmd_data {
	uint8_t cmd;
	uint8_t seq;
	uint8_t args[13];
} __attribute__((packed));

struct scenario_cmd {
	struct scenario_cmd_data req;
	struct scenario_cmd_data resp;
	uint8_t cc;
	size_t resp_size;
};

struct scenario_sel {
	uint8_t bmc_state;
};

struct scenario_event {
	enum scenario_event_type type;
	union {
		const struct scenario_event *p;
		struct scenario_cmd c;
		struct scenario_sel s;
	};
};

#define SCENARIO_SENTINEL { .type = scenario_sentinel }

struct ipmi_sel {
	void (*fn)(uint8_t data, void *context);
	void *context;
};

struct ipmi_msg_ctx {
	const struct scenario_event *scenario;
	const struct scenario_event *cursor;

	struct ipmi_sel sel;

	struct ipmi_msg msg;
};

struct ipmi_msg_ctx ipmi_msg_ctx;

const struct bmc_platform *bmc_platform = &_bmc_platform;

static void scenario_enter(const struct scenario_event *scenario)
{
	ipmi_msg_ctx.scenario = scenario;
	ipmi_msg_ctx.cursor = scenario;
}

static void scenario_advance(void)
{
	struct ipmi_msg_ctx *ctx = &ipmi_msg_ctx;

	assert(ctx->cursor->type == scenario_delay);
	ctx->cursor++;

	/* Deliver all the undelayed, scheduled SELs */
	while (ctx->cursor->type == scenario_sel) {
		ctx->sel.fn(ctx->cursor->s.bmc_state, ctx->sel.context);
		ctx->cursor++;
	}
}

static void scenario_exit(void)
{
	if (ipmi_msg_ctx.cursor->type != scenario_sentinel) {
		ptrdiff_t d = ipmi_msg_ctx.cursor - ipmi_msg_ctx.scenario;
		printf("%s: Exiting on event %tu with event type %d \n",
		       __func__, d, ipmi_msg_ctx.cursor->type);
		assert(false);
	}
}

void ipmi_init_msg(struct ipmi_msg *msg, int interface __attribute__((unused)),
		   uint32_t code, void (*complete)(struct ipmi_msg *),
		   void *user_data, size_t req_size, size_t resp_size)
{
	msg->backend = NULL;
	msg->cmd = IPMI_CMD(code);
	msg->netfn = IPMI_NETFN(code) << 2;
	msg->req_size = req_size;
	msg->resp_size = resp_size;
	msg->complete = complete;
	msg->user_data = user_data;
}

struct ipmi_msg *ipmi_mkmsg(int interface __attribute__((unused)),
			    uint32_t code, void (*complete)(struct ipmi_msg *),
			    void *user_data, void *req_data, size_t req_size,
			    size_t resp_size)
{
	struct ipmi_msg *msg = &ipmi_msg_ctx.msg;

	ipmi_init_msg(msg, 0 /* some bogus value */, code, complete, user_data,
		      req_size, resp_size);

	msg->data = malloc(req_size > resp_size ? req_size : resp_size);
	if (req_data)
		memcpy(msg->data, req_data, req_size);

	return msg;
}

void ipmi_free_msg(struct ipmi_msg *msg __attribute__((unused)))
{
	if (msg)
		free(msg->data);
}

void ipmi_queue_msg_sync(struct ipmi_msg *msg)
{
	struct ipmi_msg_ctx *ctx = container_of(msg, struct ipmi_msg_ctx, msg);
	const struct scenario_cmd *cmd;

	if (ctx->cursor->type == scenario_cmd) {
		cmd = &ctx->cursor->c;
	} else if (ctx->cursor->type == scenario_event_p) {
		assert(ctx->cursor->p->type == scenario_cmd);
		cmd = &ctx->cursor->p->c;
	} else {
		printf("Got unexpected request:\n");
		for (ssize_t i = 0; i < msg->req_size; i++)
			printf("msg->data[%zd]: 0x%02x\n", i, msg->data[i]);
		assert(false);
	}

	assert((msg->netfn >> 2) == 0x3a);
	assert(msg->cmd == 0x5a);
	assert(msg->req_size >= 2);

	if (memcmp(msg->data, &cmd->req, msg->req_size)) {
		printf("Comparing received vs expected message\n");
		for (ssize_t i = 0; i < msg->req_size; i++) {
			printf("msg->data[%zd]: 0x%02x, cmd->req[%zd]: 0x%02x\n",
			       i, msg->data[i], i, ((uint8_t *)(&cmd->req))[i]);
		}
		assert(false);
	}

	msg->cc = cmd->cc;
	memcpy(msg->data, &cmd->resp, msg->resp_size);

	if (cmd->resp_size)
		msg->resp_size = cmd->resp_size;

	msg->complete(msg);

	ctx->cursor++;

	/* Deliver all the scheduled SELs */
	while (ctx->cursor->type == scenario_sel) {
		ctx->sel.fn(ctx->cursor->s.bmc_state, ctx->sel.context);
		ctx->cursor++;
	}
}

int ipmi_sel_register(uint8_t oem_cmd __attribute__((unused)),
		      void (*fn)(uint8_t data, void *context),
		      void *context)
{
	ipmi_msg_ctx.sel.fn = fn;
	ipmi_msg_ctx.sel.context = context;

	return 0;
}

int64_t lpc_write(enum OpalLPCAddressType addr_type __attribute__((unused)),
		  uint32_t addr __attribute__((unused)),
		  uint32_t data __attribute__((unused)),
		  uint32_t sz)
{
	assert(sz != 0);
	return 0;
}

int64_t lpc_read(enum OpalLPCAddressType addr_type __attribute__((unused)),
		 uint32_t addr __attribute__((unused)), uint32_t *data,
		 uint32_t sz)
{
	memset(data, 0xaa, sz);

	return 0;
}

static bool lpc_read_success(const uint8_t *buf, size_t len)
{
	if (len < 64) {
		while (len--)
			if (*buf++ != 0xaa)
				return false;
		return true;
	}

	for (int i = 0; i < 64; i++)
		if (buf[i] != 0xaa)
			return false;

	return !memcmp(buf, buf + 64, len - 64);
}

/* Commonly used messages */

static const struct scenario_event hiomap_ack_call = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_ACK,
			.seq = 1,
			.args = {
				[0] = HIOMAP_E_ACK_MASK,
			},
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_ACK,
			.seq = 1,
		},
	},
};

static const struct scenario_event hiomap_get_info_call = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_GET_INFO,
			.seq = 2,
			.args = {
				[0] = HIOMAP_V2,
			},
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_GET_INFO,
			.seq = 2,
			.args = {
				[0] = HIOMAP_V2,
				[1] = 12,
				[2] = 8, [3] = 0,
			},
		},
	},
};

static const struct scenario_event hiomap_get_flash_info_call = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_GET_FLASH_INFO,
			.seq = 3,
			.args = {
			},
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_GET_FLASH_INFO,
			.seq = 3,
			.args = {
				[0] = 0x00, [1] = 0x20,
				[2] = 0x01, [3] = 0x00,
			},
		},
	},
};

static const struct scenario_event
hiomap_create_read_window_qs0l1_rs0l1_call = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_CREATE_READ_WINDOW,
			.seq = 4,
			.args = {
				[0] = 0x00, [1] = 0x00,
				[2] = 0x01, [3] = 0x00,
			},
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_CREATE_READ_WINDOW,
			.seq = 4,
			.args = {
				[0] = 0xff, [1] = 0x0f,
				[2] = 0x01, [3] = 0x00,
				[4] = 0x00, [5] = 0x00,
			},
		},
	},
};

static const struct scenario_event
hiomap_create_read_window_qs0l2_rs0l1_call = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_CREATE_READ_WINDOW,
			.seq = 4,
			.args = {
				[0] = 0x00, [1] = 0x00,
				[2] = 0x02, [3] = 0x00,
			},
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_CREATE_READ_WINDOW,
			.seq = 4,
			.args = {
				[0] = 0xff, [1] = 0x0f,
				[2] = 0x01, [3] = 0x00,
				[4] = 0x00, [5] = 0x00,
			},
		},
	},
};

static const struct scenario_event
hiomap_create_write_window_qs0l1_rs0l1_call = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
			.seq = 4,
			.args = {
				[0] = 0x00, [1] = 0x00,
				[2] = 0x01, [3] = 0x00,
			},
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
			.seq = 4,
			.args = {
				[0] = 0xff, [1] = 0x0f,
				[2] = 0x01, [3] = 0x00,
				[4] = 0x00, [5] = 0x00,
			},
		},
	},
};

static const struct scenario_event hiomap_mark_dirty_qs0l1_call = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_MARK_DIRTY,
			.seq = 5,
			.args = {
				[0] = 0x00, [1] = 0x00,
				[2] = 0x01, [3] = 0x00,
			},
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_MARK_DIRTY,
			.seq = 5,
		},
	},
};

static const struct scenario_event
hiomap_create_write_window_qs0l2_rs0l1_call = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
			.seq = 4,
			.args = {
				[0] = 0x00, [1] = 0x00,
				[2] = 0x02, [3] = 0x00,
			},
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
			.seq = 4,
			.args = {
				[0] = 0xff, [1] = 0x0f,
				[2] = 0x01, [3] = 0x00,
				[4] = 0x00, [5] = 0x00,
			},
		},
	},
};

static const struct scenario_event hiomap_flush_call = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_FLUSH,
			.seq = 6,
		},
		.resp = {
			.cmd = HIOMAP_C_FLUSH,
			.seq = 6,
		},
	},
};

static const struct scenario_event
hiomap_create_write_window_qs1l1_rs1l1_call = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
			.seq = 7,
			.args = {
				[0] = 0x01, [1] = 0x00,
				[2] = 0x01, [3] = 0x00,
			},
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
			.seq = 7,
			.args = {
				[0] = 0xfe, [1] = 0x0f,
				[2] = 0x01, [3] = 0x00,
				[4] = 0x01, [5] = 0x00,
			},
		},
	},
};

static const struct scenario_event hiomap_erase_qs0l1_call = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_ERASE,
			.seq = 5,
			.args = {
				[0] = 0x00, [1] = 0x00,
				[2] = 0x01, [3] = 0x00,
			},
		},
		.resp = {
			.cmd = HIOMAP_C_ERASE,
			.seq = 5,
		},
	},
};

static const struct scenario_event hiomap_reset_call_seq_4 = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_RESET,
			.seq = 4,
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_RESET,
			.seq = 4,
		},
	},
};

static const struct scenario_event hiomap_reset_call_seq_5 = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_RESET,
			.seq = 5,
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_RESET,
			.seq = 5,
		},
	},
};

static const struct scenario_event hiomap_reset_call_seq_6 = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_RESET,
			.seq = 6,
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_RESET,
			.seq = 6,
		},
	},
};

static const struct scenario_event hiomap_reset_call_seq_7 = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_RESET,
			.seq = 7,
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_RESET,
			.seq = 7,
		},
	},
};

static const struct scenario_event hiomap_reset_call_seq_9 = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_RESET,
			.seq = 9,
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_RESET,
			.seq = 9,
		},
	},
};

static const struct scenario_event hiomap_reset_call_seq_a = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_RESET,
			.seq = 0xa,
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_RESET,
			.seq = 0xa,
		},
	},
};

static const struct scenario_event scenario_hiomap_init[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_4, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_init(void)
{
	struct blocklevel_device *bl;

	scenario_enter(scenario_hiomap_init);
	assert(!ipmi_hiomap_init(&bl));
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event scenario_hiomap_event_daemon_ready[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{ .type = scenario_sel, .s = { .bmc_state = HIOMAP_E_DAEMON_READY } },
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_4, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_event_daemon_ready(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;

	scenario_enter(scenario_hiomap_event_daemon_ready);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	assert(ctx->bmc_state == HIOMAP_E_DAEMON_READY);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event scenario_hiomap_event_daemon_stopped[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{ .type = scenario_sel, .s = { .bmc_state = HIOMAP_E_DAEMON_READY } },
	{ .type = scenario_sel, .s = { .bmc_state = HIOMAP_E_PROTOCOL_RESET } },
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_4, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_event_daemon_stopped(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;

	scenario_enter(scenario_hiomap_event_daemon_stopped);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	assert(ctx->bmc_state == HIOMAP_E_PROTOCOL_RESET);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event scenario_hiomap_event_daemon_restarted[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{ .type = scenario_sel, .s = { .bmc_state = HIOMAP_E_DAEMON_READY } },
	{ .type = scenario_sel, .s = { .bmc_state = HIOMAP_E_PROTOCOL_RESET } },
	{ .type = scenario_sel, .s = { .bmc_state = HIOMAP_E_DAEMON_READY } },
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_4, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_event_daemon_restarted(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;

	scenario_enter(scenario_hiomap_event_daemon_restarted);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	assert(ctx->bmc_state == (HIOMAP_E_DAEMON_READY | HIOMAP_E_PROTOCOL_RESET));
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_event_daemon_lost_flash_control[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{ .type = scenario_sel, .s = { .bmc_state = HIOMAP_E_DAEMON_READY } },
	{
		.type = scenario_sel,
		.s = {
			.bmc_state = (HIOMAP_E_DAEMON_READY
					| HIOMAP_E_FLASH_LOST),
		}
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_5, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_event_daemon_lost_flash_control(void)
{
	struct blocklevel_device *bl;
	size_t len = 2 * (1 << 12);
	void *buf;

	buf = malloc(len);
	assert(buf);

	scenario_enter(scenario_hiomap_event_daemon_lost_flash_control);
	assert(!ipmi_hiomap_init(&bl));
	assert(bl->read(bl, 0, buf, len) == FLASH_ERR_AGAIN);
	ipmi_hiomap_exit(bl);
	scenario_exit();

	free(buf);
}

static const struct scenario_event
scenario_hiomap_event_daemon_regained_flash_control_dirty[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{ .type = scenario_sel, .s = { .bmc_state = HIOMAP_E_DAEMON_READY } },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 4,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x02, [3] = 0x00,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 4,
				.args = {
					[0] = 0xfe, [1] = 0x0f,
					[2] = 0x02, [3] = 0x00,
					[4] = 0x00, [5] = 0x00,
				},
			},
		},
	},
	{
		.type = scenario_delay
	},
	{
		.type = scenario_sel,
		.s = {
			.bmc_state = (HIOMAP_E_DAEMON_READY
					| HIOMAP_E_FLASH_LOST),
		}
	},
	{
		.type = scenario_sel,
		.s = {
			.bmc_state = (HIOMAP_E_DAEMON_READY
					| HIOMAP_E_WINDOW_RESET),
		}
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ACK,
				.seq = 5,
				.args = { [0] = HIOMAP_E_WINDOW_RESET },
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_ACK,
				.seq = 5,
			}
		}
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 6,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x02, [3] = 0x00,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 6,
				.args = {
					[0] = 0xfe, [1] = 0x0f,
					[2] = 0x02, [3] = 0x00,
					[4] = 0x00, [5] = 0x00,
				},
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_7, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_event_daemon_regained_flash_control_dirty(void)
{
	struct blocklevel_device *bl;
	size_t len = 2 * (1 << 12);
	void *buf;

	buf = malloc(len);
	assert(buf);

	scenario_enter(scenario_hiomap_event_daemon_regained_flash_control_dirty);
	assert(!ipmi_hiomap_init(&bl));
	assert(!bl->read(bl, 0, buf, len));
	scenario_advance();
	assert(!bl->read(bl, 0, buf, len));
	ipmi_hiomap_exit(bl);
	scenario_exit();

	free(buf);
}

static const struct scenario_event scenario_hiomap_protocol_reset_recovery[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{ .type = scenario_sel, .s = { .bmc_state = HIOMAP_E_DAEMON_READY } },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 4,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x02, [3] = 0x00,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 4,
				.args = {
					[0] = 0xfe, [1] = 0x0f,
					[2] = 0x02, [3] = 0x00,
					[4] = 0x00, [5] = 0x00,
				},
			},
		},
	},
	{
		.type = scenario_delay
	},
	{
		.type = scenario_sel,
		.s = { .bmc_state = HIOMAP_E_PROTOCOL_RESET, }
	},
	{
		.type = scenario_sel,
		.s = { .bmc_state = HIOMAP_E_DAEMON_READY, }
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ACK,
				.seq = 5,
				.args = { [0] = HIOMAP_E_PROTOCOL_RESET },
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_ACK,
				.seq = 5,
			}
		}
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 6,
				.args = {
					[0] = HIOMAP_V2,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 6,
				.args = {
					[0] = HIOMAP_V2,
					[1] = 12,
					[2] = 8, [3] = 0,
				},
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 7,
				.args = {
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 7,
				.args = {
					[0] = 0x00, [1] = 0x20,
					[2] = 0x01, [3] = 0x00,
				},
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 8,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x02, [3] = 0x00,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 8,
				.args = {
					[0] = 0xfe, [1] = 0x0f,
					[2] = 0x02, [3] = 0x00,
					[4] = 0x00, [5] = 0x00,
				},
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_9, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_reset_recovery(void)
{
	struct blocklevel_device *bl;
	size_t len = 2 * (1 << 12);
	void *buf;

	buf = malloc(len);
	assert(buf);

	scenario_enter(scenario_hiomap_protocol_reset_recovery);
	assert(!ipmi_hiomap_init(&bl));
	assert(!bl->read(bl, 0, buf, len));
	scenario_advance();
	assert(!bl->read(bl, 0, buf, len));
	ipmi_hiomap_exit(bl);
	scenario_exit();

	free(buf);
}

static const struct scenario_event
scenario_hiomap_protocol_read_one_block[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_read_window_qs0l1_rs0l1_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_5, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_read_one_block(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	uint8_t *buf;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_read_one_block);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(!bl->read(bl, 0, buf, len));
	assert(lpc_read_success(buf, len));
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static void test_hiomap_protocol_read_one_byte(void)
{
	struct blocklevel_device *bl;
	uint8_t *buf;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_read_one_block);
	assert(!ipmi_hiomap_init(&bl));
	len = 1;
	buf = calloc(1, len);
	assert(buf);
	assert(!bl->read(bl, 0, buf, len));
	assert(lpc_read_success(buf, len));
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_read_two_blocks[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_read_window_qs0l2_rs0l1_call,
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 5,
				.args = {
					[0] = 0x01, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 5,
				.args = {
					[0] = 0xfe, [1] = 0x0f,
					[2] = 0x01, [3] = 0x00,
					[4] = 0x01, [5] = 0x00,
				},
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_6, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_read_two_blocks(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	uint8_t *buf;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_read_two_blocks);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 2 * (1 << ctx->block_size_shift);
	buf = calloc(1, len);
	assert(buf);
	assert(!bl->read(bl, 0, buf, len));
	assert(lpc_read_success(buf, len));
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static void test_hiomap_protocol_read_1block_1byte(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	uint8_t *buf;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_read_two_blocks);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = (1 << ctx->block_size_shift) + 1;
	buf = calloc(1, len);
	assert(buf);
	assert(!bl->read(bl, 0, buf, len));
	assert(lpc_read_success(buf, len));
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_read_one_block_twice[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_read_window_qs0l1_rs0l1_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_5, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_read_one_block_twice(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	uint8_t *buf;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_read_one_block_twice);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(!bl->read(bl, 0, buf, len));
	assert(!bl->read(bl, 0, buf, len));
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_event_before_action[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_sel,
		.s = {
			.bmc_state = HIOMAP_E_DAEMON_READY |
					HIOMAP_E_FLASH_LOST,
		}
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_5, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_event_before_read(void)
{
	struct blocklevel_device *bl;
	char buf;
	int rc;

	scenario_enter(scenario_hiomap_protocol_event_before_action);
	assert(!ipmi_hiomap_init(&bl));
	rc = bl->read(bl, 0, &buf, sizeof(buf));
	assert(rc == FLASH_ERR_AGAIN);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_event_during_read[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_read_window_qs0l1_rs0l1_call,
	},
	{
		.type = scenario_sel,
		.s = {
			.bmc_state = HIOMAP_E_DAEMON_READY |
					HIOMAP_E_FLASH_LOST,
		}
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_5, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_event_during_read(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	uint8_t *buf;
	size_t len;
	int rc;

	scenario_enter(scenario_hiomap_protocol_event_during_read);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	rc = bl->read(bl, 0, buf, len);
	assert(rc == FLASH_ERR_AGAIN);
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_write_one_block[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_mark_dirty_qs0l1_call, },
	{ .type = scenario_event_p, .p = &hiomap_flush_call, },
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_7, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_write_one_block(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	uint8_t *buf;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_write_one_block);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(!bl->write(bl, 0, buf, len));
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static void test_hiomap_protocol_write_one_byte(void)
{
	struct blocklevel_device *bl;
	uint8_t *buf;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_write_one_block);
	assert(!ipmi_hiomap_init(&bl));
	len = 1;
	buf = calloc(1, len);
	assert(buf);
	assert(!bl->write(bl, 0, buf, len));
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_write_two_blocks[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l2_rs0l1_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_mark_dirty_qs0l1_call, },
	{ .type = scenario_event_p, .p = &hiomap_flush_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs1l1_rs1l1_call,
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_MARK_DIRTY,
				.seq = 8,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.resp = {
				.cmd = HIOMAP_C_MARK_DIRTY,
				.seq = 8,
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 9,
			},
			.resp = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 9,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_a, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_write_two_blocks(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	uint8_t *buf;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_write_two_blocks);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 2 * (1 << ctx->block_size_shift);
	buf = calloc(1, len);
	assert(buf);
	assert(!bl->write(bl, 0, buf, len));
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static void test_hiomap_protocol_write_1block_1byte(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	uint8_t *buf;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_write_two_blocks);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len =  (1 << ctx->block_size_shift) + 1;
	buf = calloc(1, len);
	assert(buf);
	assert(!bl->write(bl, 0, buf, len));
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_write_one_block_twice[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_mark_dirty_qs0l1_call, },
	{ .type = scenario_event_p, .p = &hiomap_flush_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_MARK_DIRTY,
				.seq = 7,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.resp = {
				.cmd = HIOMAP_C_MARK_DIRTY,
				.seq = 7,
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 8,
			},
			.resp = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 8,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_9, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_write_one_block_twice(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	uint8_t *buf;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_write_one_block_twice);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(!bl->write(bl, 0, buf, len));
	assert(!bl->write(bl, 0, buf, len));
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static void test_hiomap_protocol_event_before_write(void)
{
	struct blocklevel_device *bl;
	char buf;
	int rc;

	scenario_enter(scenario_hiomap_protocol_event_before_action);
	assert(!ipmi_hiomap_init(&bl));
	rc = bl->write(bl, 0, &buf, sizeof(buf));
	assert(rc == FLASH_ERR_AGAIN);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_event_during_write[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{
		.type = scenario_sel,
		.s = {
			.bmc_state = HIOMAP_E_DAEMON_READY |
					HIOMAP_E_FLASH_LOST,
		}
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_6, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_event_during_write(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	char *buf;
	int rc;

	scenario_enter(scenario_hiomap_protocol_event_during_write);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	rc = bl->write(bl, 0, buf, len);
	free(buf);
	assert(rc == FLASH_ERR_AGAIN);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_erase_one_block[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{
		.type = scenario_event_p,
		.p = &hiomap_erase_qs0l1_call,
	},
	{
		.type = scenario_event_p,
		.p = &hiomap_flush_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_7, },
	SCENARIO_SENTINEL,
};

static const struct scenario_event
scenario_hiomap_protocol_erase_two_blocks[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l2_rs0l1_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_erase_qs0l1_call, },
	{ .type = scenario_event_p, .p = &hiomap_flush_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs1l1_rs1l1_call,
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 8,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.resp = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 8,
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 9,
			},
			.resp = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 9,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_a, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_erase_two_blocks(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_erase_two_blocks);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 2 * (1 << ctx->block_size_shift);
	assert(!bl->erase(bl, 0, len));
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_erase_one_block_twice[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_erase_qs0l1_call, },
	{ .type = scenario_event_p, .p = &hiomap_flush_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 7,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.resp = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 7,
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 8,
			},
			.resp = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 8,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_9, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_erase_one_block_twice(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_erase_one_block_twice);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	assert(!bl->erase(bl, 0, len));
	assert(!bl->erase(bl, 0, len));
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static void test_hiomap_protocol_erase_one_block(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_erase_one_block);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	assert(!bl->erase(bl, 0, len));
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static void test_hiomap_protocol_event_before_erase(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	int rc;

	scenario_enter(scenario_hiomap_protocol_event_before_action);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	rc = bl->erase(bl, 0, len);
	assert(rc == FLASH_ERR_AGAIN);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_event_during_erase[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{
		.type = scenario_sel,
		.s = {
			.bmc_state = HIOMAP_E_DAEMON_READY |
					HIOMAP_E_FLASH_LOST,
		}
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_6, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_event_during_erase(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	int rc;

	scenario_enter(scenario_hiomap_protocol_event_during_erase);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	rc = bl->erase(bl, 0, len);
	assert(rc == FLASH_ERR_AGAIN);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event scenario_hiomap_protocol_bad_sequence[] = {
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ACK,
				.seq = 1,
				.args = {
					[0] = HIOMAP_E_ACK_MASK,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_ACK,
				.seq = 0,
			},
		},
	},
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_bad_sequence(void)
{
	struct blocklevel_device *bl;

	scenario_enter(scenario_hiomap_protocol_bad_sequence);
	assert(ipmi_hiomap_init(&bl) > 0);
	scenario_exit();
}

static const struct scenario_event scenario_hiomap_protocol_action_error[] = {
	{
		.type = scenario_cmd,
		.c = {
			/* Ack is legitimate, but we'll pretend it's invalid */
			.req = {
				.cmd = HIOMAP_C_ACK,
				.seq = 1,
				.args = { [0] = 0x3 },
			},
			.cc = IPMI_INVALID_COMMAND_ERR,
			.resp = {
				.cmd = HIOMAP_C_ACK,
				.seq = 1,
			},
		},
	},
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_action_error(void)
{
	struct blocklevel_device *bl;

	scenario_enter(scenario_hiomap_protocol_action_error);
	assert(ipmi_hiomap_init(&bl) > 0);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_get_flash_info[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 4,
				.args = {
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 4,
				.args = {
					[0] = 0x00, [1] = 0x20,
					[2] = 0x01, [3] = 0x00,
				},
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_5, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_get_flash_info(void)
{
	struct blocklevel_device *bl;
	const char *name;
	uint32_t granule;
	uint64_t size;

	scenario_enter(scenario_hiomap_protocol_get_flash_info);
	assert(!ipmi_hiomap_init(&bl));
	assert(!bl->get_info(bl, &name, &size, &granule));
	assert(!name);
	assert(size == (32 * 1024 * 1024));
	assert(granule == (4 * 1024));
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_persistent_error[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{ .type = scenario_sel, .s = { .bmc_state = HIOMAP_E_PROTOCOL_RESET } },
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_6, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_persistent_error(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	char buf;
	int rc;

	scenario_enter(scenario_hiomap_protocol_persistent_error);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	assert(ctx->bmc_state == HIOMAP_E_PROTOCOL_RESET);
	rc = bl->read(bl, 0, &buf, sizeof(buf));
	assert(rc == FLASH_ERR_DEVICE_GONE);
	rc = bl->read(bl, 0, &buf, sizeof(buf));
	assert(rc == FLASH_ERR_DEVICE_GONE);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_get_info_error[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 2,
				.args = {
					[0] = HIOMAP_V2,
				},
			},
			.cc = IPMI_INVALID_COMMAND_ERR,
		},
	},
	SCENARIO_SENTINEL,
};

static void test_hiomap_get_info_error(void)
{
	struct blocklevel_device *bl;

	scenario_enter(scenario_hiomap_get_info_error);
	assert(ipmi_hiomap_init(&bl) > 0);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_get_flash_info_error[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 3,
				.args = {
					[0] = HIOMAP_V2,
				},
			},
			.cc = IPMI_INVALID_COMMAND_ERR,
		},
	},
	SCENARIO_SENTINEL,
};

static void test_hiomap_get_flash_info_error(void)
{
	struct blocklevel_device *bl;

	scenario_enter(scenario_hiomap_get_flash_info_error);
	assert(ipmi_hiomap_init(&bl) > 0);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_create_read_window_error[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 4,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.cc = IPMI_INVALID_COMMAND_ERR,
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_5, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_create_read_window_error(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	void *buf;

	scenario_enter(scenario_hiomap_create_read_window_error);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(bl->read(bl, 0, buf, len) > 0);
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_create_write_window_error[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
				.seq = 4,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.cc = IPMI_INVALID_COMMAND_ERR,
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_5, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_create_write_window_error(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	void *buf;

	scenario_enter(scenario_hiomap_create_write_window_error);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(bl->write(bl, 0, buf, len) > 0);
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event scenario_hiomap_mark_dirty_error[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_MARK_DIRTY,
				.seq = 5,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.cc = IPMI_INVALID_COMMAND_ERR,
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_6, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_mark_dirty_error(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	void *buf;

	scenario_enter(scenario_hiomap_mark_dirty_error);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(bl->write(bl, 0, buf, len) > 0);
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event scenario_hiomap_flush_error[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_mark_dirty_qs0l1_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 6,
			},
			.cc = IPMI_INVALID_COMMAND_ERR,
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_7, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_flush_error(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	void *buf;

	scenario_enter(scenario_hiomap_flush_error);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(bl->write(bl, 0, buf, len) > 0);
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static void test_hiomap_ack_error(void)
{
	/* Same thing at the moment */
	test_hiomap_protocol_action_error();
}

static const struct scenario_event scenario_hiomap_erase_error[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 5,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.cc = IPMI_INVALID_COMMAND_ERR,
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_6, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_erase_error(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;

	scenario_enter(scenario_hiomap_erase_error);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	assert(bl->erase(bl, 0, len) > 0);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event scenario_hiomap_ack_malformed_small[] = {
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ACK,
				.seq = 1,
				.args = { [0] = 0x3 },
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp_size = 1
		},
	},
	SCENARIO_SENTINEL,
};

static void test_hiomap_ack_malformed_small(void)
{
	struct blocklevel_device *bl;

	scenario_enter(scenario_hiomap_ack_malformed_small);
	assert(ipmi_hiomap_init(&bl) > 0);
	scenario_exit();
}

static const struct scenario_event scenario_hiomap_ack_malformed_large[] = {
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ACK,
				.seq = 1,
				.args = { [0] = 0x3 },
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp_size = 3,
			.resp = {
				.cmd = HIOMAP_C_ACK,
				.seq = 1,
			},
		},
	},
	SCENARIO_SENTINEL,
};

static void test_hiomap_ack_malformed_large(void)
{
	struct blocklevel_device *bl;

	scenario_enter(scenario_hiomap_ack_malformed_large);
	assert(ipmi_hiomap_init(&bl) > 0);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_get_info_malformed_small[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 2,
				.args = { [0] = 0x2 },
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp_size = 7,
			.resp = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 2,
			},
		},
	},
	SCENARIO_SENTINEL,
};

static void test_hiomap_get_info_malformed_small(void)
{
	struct blocklevel_device *bl;

	scenario_enter(scenario_hiomap_get_info_malformed_small);
	assert(ipmi_hiomap_init(&bl) > 0);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_get_info_malformed_large[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 2,
				.args = { [0] = 0x2 },
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp_size = 9,
			.resp = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 2,
			},
		},
	},
	SCENARIO_SENTINEL,
};

static void test_hiomap_get_info_malformed_large(void)
{
	struct blocklevel_device *bl;

	scenario_enter(scenario_hiomap_get_info_malformed_large);
	assert(ipmi_hiomap_init(&bl) > 0);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_get_flash_info_malformed_small[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 3,
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp_size = 5,
			.resp = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 3,
			},
		},
	},
	SCENARIO_SENTINEL,
};

static void test_hiomap_get_flash_info_malformed_small(void)
{
	struct blocklevel_device *bl;

	scenario_enter(scenario_hiomap_get_flash_info_malformed_small);
	assert(ipmi_hiomap_init(&bl) > 0);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_get_flash_info_malformed_large[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 3,
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp_size = 7,
			.resp = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 3,
			},
		},
	},
	SCENARIO_SENTINEL,
};

static void test_hiomap_get_flash_info_malformed_large(void)
{
	struct blocklevel_device *bl;

	scenario_enter(scenario_hiomap_get_flash_info_malformed_large);
	assert(ipmi_hiomap_init(&bl) > 0);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_create_read_window_malformed_small[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 4,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp_size = 7,
			.resp = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 4,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_5, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_create_read_window_malformed_small(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	void *buf;

	scenario_enter(scenario_hiomap_create_read_window_malformed_small);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(bl->read(bl, 0, buf, len) > 0);
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();

}

static const struct scenario_event
scenario_hiomap_create_read_window_malformed_large[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 4,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp_size = 9,
			.resp = {
				.cmd = HIOMAP_C_CREATE_READ_WINDOW,
				.seq = 4,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_5, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_create_read_window_malformed_large(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	void *buf;

	scenario_enter(scenario_hiomap_create_read_window_malformed_large);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(bl->read(bl, 0, buf, len) > 0);
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_create_write_window_malformed_small[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
				.seq = 4,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp_size = 7,
			.resp = {
				.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
				.seq = 4,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_5, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_create_write_window_malformed_small(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	void *buf;

	scenario_enter(scenario_hiomap_create_write_window_malformed_small);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(bl->write(bl, 0, buf, len) > 0);
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();

}

static const struct scenario_event
scenario_hiomap_create_write_window_malformed_large[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
				.seq = 4,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp_size = 9,
			.resp = {
				.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
				.seq = 4,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_5, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_create_write_window_malformed_large(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	void *buf;

	scenario_enter(scenario_hiomap_create_write_window_malformed_large);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(bl->write(bl, 0, buf, len) > 0);
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_mark_dirty_malformed_small[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_MARK_DIRTY,
				.seq = 5,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.resp_size = 1,
			.resp = {
				.cmd = HIOMAP_C_MARK_DIRTY,
				.seq = 5,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_6, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_mark_dirty_malformed_small(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	void *buf;

	scenario_enter(scenario_hiomap_mark_dirty_malformed_small);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(bl->write(bl, 0, buf, len) > 0);
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();

}

static const struct scenario_event
scenario_hiomap_mark_dirty_malformed_large[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_MARK_DIRTY,
				.seq = 5,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.resp_size = 3,
			.resp = {
				.cmd = HIOMAP_C_MARK_DIRTY,
				.seq = 5,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_6, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_mark_dirty_malformed_large(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	void *buf;

	scenario_enter(scenario_hiomap_mark_dirty_malformed_large);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(bl->write(bl, 0, buf, len) > 0);
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_flush_malformed_small[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_mark_dirty_qs0l1_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 6,
			},
			.resp_size = 1,
			.resp = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 6,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_7, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_flush_malformed_small(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	void *buf;

	scenario_enter(scenario_hiomap_flush_malformed_small);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(bl->write(bl, 0, buf, len) > 0);
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();

}

static const struct scenario_event
scenario_hiomap_flush_malformed_large[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_mark_dirty_qs0l1_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 6,
			},
			.resp_size = 3,
			.resp = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 6,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_7, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_flush_malformed_large(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;
	void *buf;

	scenario_enter(scenario_hiomap_flush_malformed_large);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	buf = calloc(1, len);
	assert(buf);
	assert(bl->write(bl, 0, buf, len) > 0);
	free(buf);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_erase_malformed_small[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 5,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.resp_size = 1,
			.resp = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 5,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_6, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_erase_malformed_small(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;

	scenario_enter(scenario_hiomap_erase_malformed_small);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	assert(bl->erase(bl, 0, len) > 0);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_erase_malformed_large[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 5,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.resp_size = 3,
			.resp = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 5,
			},
		},
	},
	{ .type = scenario_event_p, .p = &hiomap_reset_call_seq_6, },
	SCENARIO_SENTINEL,
};

static void test_hiomap_erase_malformed_large(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;

	scenario_enter(scenario_hiomap_erase_malformed_large);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	assert(bl->erase(bl, 0, len) > 0);
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

/* Common recovery calls */

static const struct scenario_event hiomap_recovery_ack_call = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_ACK,
			.seq = 7,
			.args = {
				[0] = HIOMAP_E_PROTOCOL_RESET,
			},
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_ACK,
			.seq = 7,
		},
	},
};

static const struct scenario_event hiomap_recovery_get_info_call = {
	.type = scenario_cmd,
	.c = {
		.req = {
			.cmd = HIOMAP_C_GET_INFO,
			.seq = 8,
			.args = {
				[0] = HIOMAP_V2,
			},
		},
		.cc = IPMI_CC_NO_ERROR,
		.resp = {
			.cmd = HIOMAP_C_GET_INFO,
			.seq = 8,
			.args = {
				[0] = HIOMAP_V2,
				[1] = 12,
				[2] = 8, [3] = 0,
			},
		},
	},
};

static const struct scenario_event
scenario_hiomap_protocol_recovery_failure_ack[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_erase_qs0l1_call, },
	{ .type = scenario_event_p, .p = &hiomap_flush_call, },
	{ .type = scenario_delay },
	{
		.type = scenario_sel,
		.s = {
			.bmc_state = HIOMAP_E_DAEMON_READY |
					HIOMAP_E_PROTOCOL_RESET
		}
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ACK,
				.seq = 7,
				.args = {
					[0] = HIOMAP_E_PROTOCOL_RESET,
				},
			},
			.cc = IPMI_ERR_UNSPECIFIED,
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ACK,
				.seq = 8,
				.args = {
					[0] = HIOMAP_E_PROTOCOL_RESET,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_ACK,
				.seq = 8,
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 9,
				.args = {
					[0] = HIOMAP_V2,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 9,
				.args = {
					[0] = HIOMAP_V2,
					[1] = 12,
					[2] = 8, [3] = 0,
				},
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 10,
				.args = {
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 10,
				.args = {
					[0] = 0x00, [1] = 0x20,
					[2] = 0x01, [3] = 0x00,
				},
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
				.seq = 11,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
				.seq = 11,
				.args = {
					[0] = 0xff, [1] = 0x0f,
					[2] = 0x01, [3] = 0x00,
					[4] = 0x00, [5] = 0x00,
				},
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 12,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.resp = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 12,
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 13,
			},
			.resp = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 13,
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_RESET,
				.seq = 14,
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_RESET,
				.seq = 14,
			},
		},
	},
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_recovery_failure_ack(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_recovery_failure_ack);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	/*
	 * We're erasing the same block 3 times - it's irrelevant, we're just
	 * trying to manipulate window state
	 */
	assert(!bl->erase(bl, 0, len));
	scenario_advance();
	assert(bl->erase(bl, 0, len) > 0);
	assert(!bl->erase(bl, 0, len));
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_recovery_failure_get_info[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_erase_qs0l1_call, },
	{ .type = scenario_event_p, .p = &hiomap_flush_call, },
	{ .type = scenario_delay },
	{
		.type = scenario_sel,
		.s = {
			.bmc_state = HIOMAP_E_DAEMON_READY |
					HIOMAP_E_PROTOCOL_RESET
		}
	},
	{ .type = scenario_event_p, .p = &hiomap_recovery_ack_call, },
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 8,
				.args = {
					[0] = HIOMAP_V2,
				},
			},
			.cc = IPMI_ERR_UNSPECIFIED,
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ACK,
				.seq = 9,
				.args = {
					[0] = HIOMAP_E_PROTOCOL_RESET,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_ACK,
				.seq = 9,
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 10,
				.args = {
					[0] = HIOMAP_V2,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 10,
				.args = {
					[0] = HIOMAP_V2,
					[1] = 12,
					[2] = 8, [3] = 0,
				},
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 11,
				.args = {
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 11,
				.args = {
					[0] = 0x00, [1] = 0x20,
					[2] = 0x01, [3] = 0x00,
				},
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
				.seq = 12,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
				.seq = 12,
				.args = {
					[0] = 0xff, [1] = 0x0f,
					[2] = 0x01, [3] = 0x00,
					[4] = 0x00, [5] = 0x00,
				},
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 13,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.resp = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 13,
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 14,
			},
			.resp = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 14,
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_RESET,
				.seq = 15,
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_RESET,
				.seq = 15,
			},
		},
	},
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_recovery_failure_get_info(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_recovery_failure_get_info);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	/*
	 * We're erasing the same block 3 times - it's irrelevant, we're just
	 * trying to manipulate window state
	 */
	assert(!bl->erase(bl, 0, len));
	scenario_advance();
	assert(bl->erase(bl, 0, len) > 0);
	assert(!bl->erase(bl, 0, len));
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

static const struct scenario_event
scenario_hiomap_protocol_recovery_failure_get_flash_info[] = {
	{ .type = scenario_event_p, .p = &hiomap_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_info_call, },
	{ .type = scenario_event_p, .p = &hiomap_get_flash_info_call, },
	{
		.type = scenario_event_p,
		.p = &hiomap_create_write_window_qs0l1_rs0l1_call,
	},
	{ .type = scenario_event_p, .p = &hiomap_erase_qs0l1_call, },
	{ .type = scenario_event_p, .p = &hiomap_flush_call, },
	{ .type = scenario_delay },
	{
		.type = scenario_sel,
		.s = {
			.bmc_state = HIOMAP_E_DAEMON_READY |
					HIOMAP_E_PROTOCOL_RESET
		}
	},
	{ .type = scenario_event_p, .p = &hiomap_recovery_ack_call, },
	{ .type = scenario_event_p, .p = &hiomap_recovery_get_info_call},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 9,
			},
			.cc = IPMI_ERR_UNSPECIFIED,
		},

	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ACK,
				.seq = 10,
				.args = {
					[0] = HIOMAP_E_PROTOCOL_RESET,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_ACK,
				.seq = 10,
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 11,
				.args = {
					[0] = HIOMAP_V2,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_GET_INFO,
				.seq = 11,
				.args = {
					[0] = HIOMAP_V2,
					[1] = 12,
					[2] = 8, [3] = 0,
				},
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 12,
				.args = {
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_GET_FLASH_INFO,
				.seq = 12,
				.args = {
					[0] = 0x00, [1] = 0x20,
					[2] = 0x01, [3] = 0x00,
				},
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
				.seq = 13,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_CREATE_WRITE_WINDOW,
				.seq = 13,
				.args = {
					[0] = 0xff, [1] = 0x0f,
					[2] = 0x01, [3] = 0x00,
					[4] = 0x00, [5] = 0x00,
				},
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 14,
				.args = {
					[0] = 0x00, [1] = 0x00,
					[2] = 0x01, [3] = 0x00,
				},
			},
			.resp = {
				.cmd = HIOMAP_C_ERASE,
				.seq = 14,
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 15,
			},
			.resp = {
				.cmd = HIOMAP_C_FLUSH,
				.seq = 15,
			},
		},
	},
	{
		.type = scenario_cmd,
		.c = {
			.req = {
				.cmd = HIOMAP_C_RESET,
				.seq = 16,
			},
			.cc = IPMI_CC_NO_ERROR,
			.resp = {
				.cmd = HIOMAP_C_RESET,
				.seq = 16,
			},
		},
	},
	SCENARIO_SENTINEL,
};

static void test_hiomap_protocol_recovery_failure_get_flash_info(void)
{
	struct blocklevel_device *bl;
	struct ipmi_hiomap *ctx;
	size_t len;

	scenario_enter(scenario_hiomap_protocol_recovery_failure_get_flash_info);
	assert(!ipmi_hiomap_init(&bl));
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	/*
	 * We're erasing the same block 3 times - it's irrelevant, we're just
	 * trying to manipulate window state
	 */
	assert(!bl->erase(bl, 0, len));
	scenario_advance();
	ctx = container_of(bl, struct ipmi_hiomap, bl);
	len = 1 << ctx->block_size_shift;
	assert(bl->erase(bl, 0, len) > 0);
	assert(!bl->erase(bl, 0, len));
	ipmi_hiomap_exit(bl);
	scenario_exit();
}

struct test_case {
	const char *name;
	void (*fn)(void);
};

#define TEST_CASE(x) { #x, x }

struct test_case test_cases[] = {
	TEST_CASE(test_hiomap_init),
	TEST_CASE(test_hiomap_event_daemon_ready),
	TEST_CASE(test_hiomap_event_daemon_stopped),
	TEST_CASE(test_hiomap_event_daemon_restarted),
	TEST_CASE(test_hiomap_event_daemon_lost_flash_control),
	TEST_CASE(test_hiomap_event_daemon_regained_flash_control_dirty),
	TEST_CASE(test_hiomap_protocol_reset_recovery),
	TEST_CASE(test_hiomap_protocol_read_one_block),
	TEST_CASE(test_hiomap_protocol_read_one_byte),
	TEST_CASE(test_hiomap_protocol_read_two_blocks),
	TEST_CASE(test_hiomap_protocol_read_1block_1byte),
	TEST_CASE(test_hiomap_protocol_read_one_block_twice),
	TEST_CASE(test_hiomap_protocol_event_before_read),
	TEST_CASE(test_hiomap_protocol_event_during_read),
	TEST_CASE(test_hiomap_protocol_write_one_block),
	TEST_CASE(test_hiomap_protocol_write_one_byte),
	TEST_CASE(test_hiomap_protocol_write_two_blocks),
	TEST_CASE(test_hiomap_protocol_write_1block_1byte),
	TEST_CASE(test_hiomap_protocol_write_one_block_twice),
	TEST_CASE(test_hiomap_protocol_event_before_write),
	TEST_CASE(test_hiomap_protocol_event_during_write),
	TEST_CASE(test_hiomap_protocol_erase_one_block),
	TEST_CASE(test_hiomap_protocol_erase_two_blocks),
	TEST_CASE(test_hiomap_protocol_erase_one_block_twice),
	TEST_CASE(test_hiomap_protocol_event_before_erase),
	TEST_CASE(test_hiomap_protocol_event_during_erase),
	TEST_CASE(test_hiomap_protocol_bad_sequence),
	TEST_CASE(test_hiomap_protocol_action_error),
	TEST_CASE(test_hiomap_protocol_persistent_error),
	TEST_CASE(test_hiomap_protocol_get_flash_info),
	TEST_CASE(test_hiomap_get_info_error),
	TEST_CASE(test_hiomap_get_flash_info_error),
	TEST_CASE(test_hiomap_create_read_window_error),
	TEST_CASE(test_hiomap_create_write_window_error),
	TEST_CASE(test_hiomap_mark_dirty_error),
	TEST_CASE(test_hiomap_flush_error),
	TEST_CASE(test_hiomap_ack_error),
	TEST_CASE(test_hiomap_erase_error),
	TEST_CASE(test_hiomap_ack_malformed_small),
	TEST_CASE(test_hiomap_ack_malformed_large),
	TEST_CASE(test_hiomap_get_info_malformed_small),
	TEST_CASE(test_hiomap_get_info_malformed_large),
	TEST_CASE(test_hiomap_get_flash_info_malformed_small),
	TEST_CASE(test_hiomap_get_flash_info_malformed_large),
	TEST_CASE(test_hiomap_create_read_window_malformed_small),
	TEST_CASE(test_hiomap_create_read_window_malformed_large),
	TEST_CASE(test_hiomap_create_write_window_malformed_small),
	TEST_CASE(test_hiomap_create_write_window_malformed_large),
	TEST_CASE(test_hiomap_mark_dirty_malformed_small),
	TEST_CASE(test_hiomap_mark_dirty_malformed_large),
	TEST_CASE(test_hiomap_flush_malformed_small),
	TEST_CASE(test_hiomap_flush_malformed_large),
	TEST_CASE(test_hiomap_erase_malformed_small),
	TEST_CASE(test_hiomap_erase_malformed_large),
	TEST_CASE(test_hiomap_protocol_recovery_failure_ack),
	TEST_CASE(test_hiomap_protocol_recovery_failure_get_info),
	TEST_CASE(test_hiomap_protocol_recovery_failure_get_flash_info),
	{ NULL, NULL },
};

int main(void)
{
	struct test_case *tc = &test_cases[0];

	do {
		printf("%s\n", tc->name);
		tc->fn();
		printf("\n");
	} while ((++tc)->fn);

	return 0;
}
