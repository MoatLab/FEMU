/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#if HAVE_ENDIAN_H
#include <endian.h>
#endif

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define pr_fmt(x) "astlpc: " x

#include "container_of.h"
#include "crc32.h"
#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-astlpc.h"
#include "range.h"

#ifdef MCTP_HAVE_FILEIO

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/aspeed-lpc-ctrl.h>

/* kernel interface */
static const char *kcs_path = "/dev/mctp0";
static const char *lpc_path = "/dev/aspeed-lpc-ctrl";

#endif

enum mctp_astlpc_cmd {
	cmd_initialise = 0x00,
	cmd_tx_begin = 0x01,
	cmd_rx_complete = 0x02,
	cmd_dummy_value = 0xff,
};

enum mctp_astlpc_buffer_state {
	/*
	 * Prior to "Channel Ready" we mark the buffers as "idle" to catch illegal accesses. In this
	 * state neither side is considered the owner of the buffer.
	 *
	 * Upon "Channel Ready", each side transitions the buffers from the initial "idle" state
	 * to the following target states:
	 *
	 * Tx buffer: "acquired"
	 * Rx buffer: "released"
	 */
	buffer_state_idle,

	/*
	 * Beyond initialisation by "Channel Ready", buffers are in the "acquired" state once:
	 *
	 * 1. We dequeue a control command transferring the buffer to our ownership out of the KCS
	 *    interface, and
	 * 2. We are yet to complete all of our required accesses to the buffer
	 *
	 * * The Tx buffer enters the "acquired" state when we dequeue the "Rx Complete" command
	 * * The Rx buffer enters the "acquired" state when we dequeue the "Tx Begin" command
	 *
	 * It is a failure of implementation if it's possible for both sides to simultaneously
	 * consider a buffer as "acquired".
	 */
	buffer_state_acquired,

	/*
	 * Buffers are in the "prepared" state when:
	 *
	 * 1. We have completed all of our required accesses (read or write) for the buffer, and
	 * 2. We have not yet successfully enqueued the control command to hand off ownership
	 */
	buffer_state_prepared,

	/*
	 * Beyond initialisation by "Channel Ready", buffers are in the "released" state once:
	 *
	 * 1. We successfully enqueue the control command transferring ownership to the remote
	 *    side in to the KCS interface
	 *
	 * * The Tx buffer enters the "released" state when we enqueue the "Tx Begin" command
	 * * The Rx buffer enters the "released" state when we enqueue the "Rx Complete" command
	 *
	 * It may be the case that both sides simultaneously consider a buffer to be in the
	 * "released" state. However, if this is true, it must also be true that a buffer ownership
	 * transfer command has been enqueued in the KCS interface and is yet to be dequeued.
	 */
	buffer_state_released,
};

struct mctp_astlpc_buffer {
	uint32_t offset;
	uint32_t size;
	enum mctp_astlpc_buffer_state state;
};

struct mctp_astlpc_layout {
	struct mctp_astlpc_buffer rx;
	struct mctp_astlpc_buffer tx;
};

struct mctp_astlpc_protocol {
	uint16_t version;
	uint32_t (*packet_size)(uint32_t body);
	uint32_t (*body_size)(uint32_t packet);
	void (*pktbuf_protect)(struct mctp_pktbuf *pkt);
	bool (*pktbuf_validate)(struct mctp_pktbuf *pkt);
};

struct mctp_binding_astlpc {
	struct mctp_binding binding;

	void *lpc_map;
	struct mctp_astlpc_layout layout;

	uint8_t mode;
	uint32_t requested_mtu;

	const struct mctp_astlpc_protocol *proto;

	/* direct ops data */
	struct mctp_binding_astlpc_ops ops;
	void *ops_data;

	/* fileio ops data */
	int kcs_fd;
	uint8_t kcs_status;
};

#define binding_to_astlpc(b)                                                   \
	container_of(b, struct mctp_binding_astlpc, binding)

#define astlpc_prlog(ctx, lvl, fmt, ...)                                       \
	do {                                                                   \
		bool __bmc = ((ctx)->mode == MCTP_BINDING_ASTLPC_MODE_BMC);    \
		mctp_prlog(lvl, pr_fmt("%s: " fmt), __bmc ? "bmc" : "host",    \
			   ##__VA_ARGS__);                                     \
	} while (0)

#define astlpc_prerr(ctx, fmt, ...)                                            \
	astlpc_prlog(ctx, MCTP_LOG_ERR, fmt, ##__VA_ARGS__)
#define astlpc_prwarn(ctx, fmt, ...)                                           \
	astlpc_prlog(ctx, MCTP_LOG_WARNING, fmt, ##__VA_ARGS__)
#define astlpc_prinfo(ctx, fmt, ...)                                           \
	astlpc_prlog(ctx, MCTP_LOG_INFO, fmt, ##__VA_ARGS__)
#define astlpc_prdebug(ctx, fmt, ...)                                          \
	astlpc_prlog(ctx, MCTP_LOG_DEBUG, fmt, ##__VA_ARGS__)

/* clang-format off */
#define ASTLPC_MCTP_MAGIC	0x4d435450
#define ASTLPC_VER_BAD	0
#define ASTLPC_VER_MIN	1

/* Support testing of new binding protocols */
#ifndef ASTLPC_VER_CUR
#define ASTLPC_VER_CUR	3
#endif
/* clang-format on */

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

static uint32_t astlpc_packet_size_v1(uint32_t body)
{
	assert((body + 4) > body);

	return body + 4;
}

static uint32_t astlpc_body_size_v1(uint32_t packet)
{
	assert((packet - 4) < packet);

	return packet - 4;
}

void astlpc_pktbuf_protect_v1(struct mctp_pktbuf *pkt)
{
	(void)pkt;
}

bool astlpc_pktbuf_validate_v1(struct mctp_pktbuf *pkt)
{
	(void)pkt;
	return true;
}

static uint32_t astlpc_packet_size_v3(uint32_t body)
{
	assert((body + 4 + 4) > body);

	return body + 4 + 4;
}

static uint32_t astlpc_body_size_v3(uint32_t packet)
{
	assert((packet - 4 - 4) < packet);

	return packet - 4 - 4;
}

void astlpc_pktbuf_protect_v3(struct mctp_pktbuf *pkt)
{
	uint32_t code;

	code = htobe32(crc32(mctp_pktbuf_hdr(pkt), mctp_pktbuf_size(pkt)));
	mctp_prdebug("%s: 0x%" PRIx32, __func__, code);
	mctp_pktbuf_push(pkt, &code, 4);
}

bool astlpc_pktbuf_validate_v3(struct mctp_pktbuf *pkt)
{
	uint32_t code;
	void *check;

	code = be32toh(crc32(mctp_pktbuf_hdr(pkt), mctp_pktbuf_size(pkt) - 4));
	mctp_prdebug("%s: 0x%" PRIx32, __func__, code);
	check = mctp_pktbuf_pop(pkt, 4);
	return check && !memcmp(&code, check, 4);
}

static const struct mctp_astlpc_protocol astlpc_protocol_version[] = {
	[0] = {
		.version = 0,
		.packet_size = NULL,
		.body_size = NULL,
		.pktbuf_protect = NULL,
		.pktbuf_validate = NULL,
	},
	[1] = {
		.version = 1,
		.packet_size = astlpc_packet_size_v1,
		.body_size = astlpc_body_size_v1,
		.pktbuf_protect = astlpc_pktbuf_protect_v1,
		.pktbuf_validate = astlpc_pktbuf_validate_v1,
	},
	[2] = {
		.version = 2,
		.packet_size = astlpc_packet_size_v1,
		.body_size = astlpc_body_size_v1,
		.pktbuf_protect = astlpc_pktbuf_protect_v1,
		.pktbuf_validate = astlpc_pktbuf_validate_v1,
	},
	[3] = {
		.version = 3,
		.packet_size = astlpc_packet_size_v3,
		.body_size = astlpc_body_size_v3,
		.pktbuf_protect = astlpc_pktbuf_protect_v3,
		.pktbuf_validate = astlpc_pktbuf_validate_v3,
	},
};

struct mctp_lpcmap_hdr {
	uint32_t magic;

	uint16_t bmc_ver_min;
	uint16_t bmc_ver_cur;
	uint16_t host_ver_min;
	uint16_t host_ver_cur;
	uint16_t negotiated_ver;
	uint16_t pad0;

	struct {
		uint32_t rx_offset;
		uint32_t rx_size;
		uint32_t tx_offset;
		uint32_t tx_size;
	} layout;
} __attribute__((packed));

static const uint32_t control_size = 0x100;

#define LPC_WIN_SIZE (1 * 1024 * 1024)

#define KCS_STATUS_BMC_READY	  0x80
#define KCS_STATUS_CHANNEL_ACTIVE 0x40
#define KCS_STATUS_IBF		  0x02
#define KCS_STATUS_OBF		  0x01

static inline int mctp_astlpc_kcs_write(struct mctp_binding_astlpc *astlpc,
					enum mctp_binding_astlpc_kcs_reg reg,
					uint8_t val)
{
	return astlpc->ops.kcs_write(astlpc->ops_data, reg, val);
}

static inline int mctp_astlpc_kcs_read(struct mctp_binding_astlpc *astlpc,
				       enum mctp_binding_astlpc_kcs_reg reg,
				       uint8_t *val)
{
	return astlpc->ops.kcs_read(astlpc->ops_data, reg, val);
}

static inline int mctp_astlpc_lpc_write(struct mctp_binding_astlpc *astlpc,
					const void *buf, long offset,
					size_t len)
{
	astlpc_prdebug(astlpc, "%s: %zu bytes to 0x%lx", __func__, len, offset);

	assert(offset >= 0);

	/* Indirect access */
	if (astlpc->ops.lpc_write) {
		void *data = astlpc->ops_data;

		return astlpc->ops.lpc_write(data, buf, offset, len);
	}

	/* Direct mapping */
	assert(astlpc->lpc_map);
	memcpy(&((char *)astlpc->lpc_map)[offset], buf, len);

	return 0;
}

static inline int mctp_astlpc_lpc_read(struct mctp_binding_astlpc *astlpc,
				       void *buf, long offset, size_t len)
{
	astlpc_prdebug(astlpc, "%s: %zu bytes from 0x%lx", __func__, len,
		       offset);

	assert(offset >= 0);

	/* Indirect access */
	if (astlpc->ops.lpc_read) {
		void *data = astlpc->ops_data;

		return astlpc->ops.lpc_read(data, buf, offset, len);
	}

	/* Direct mapping */
	assert(astlpc->lpc_map);
	memcpy(buf, &((char *)astlpc->lpc_map)[offset], len);

	return 0;
}

static int mctp_astlpc_kcs_set_status(struct mctp_binding_astlpc *astlpc,
				      uint8_t status)
{
	uint8_t data;
	int rc;

	/* Since we're setting the status register, we want the other endpoint
	 * to be interrupted. However, some hardware may only raise a host-side
	 * interrupt on an ODR event.
	 * So, write a dummy value of 0xff to ODR, which will ensure that an
	 * interrupt is triggered, and can be ignored by the host.
	 */
	data = cmd_dummy_value;

	rc = mctp_astlpc_kcs_write(astlpc, MCTP_ASTLPC_KCS_REG_STATUS, status);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS status write failed");
		return -1;
	}

	rc = mctp_astlpc_kcs_write(astlpc, MCTP_ASTLPC_KCS_REG_DATA, data);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS dummy data write failed");
		return -1;
	}

	return 0;
}

static int mctp_astlpc_layout_read(struct mctp_binding_astlpc *astlpc,
				   struct mctp_astlpc_layout *layout)
{
	struct mctp_lpcmap_hdr hdr;
	int rc;

	rc = mctp_astlpc_lpc_read(astlpc, &hdr, 0, sizeof(hdr));
	if (rc < 0)
		return rc;

	/* Flip the buffers as the names are defined in terms of the host */
	if (astlpc->mode == MCTP_BINDING_ASTLPC_MODE_BMC) {
		layout->rx.offset = be32toh(hdr.layout.tx_offset);
		layout->rx.size = be32toh(hdr.layout.tx_size);
		layout->tx.offset = be32toh(hdr.layout.rx_offset);
		layout->tx.size = be32toh(hdr.layout.rx_size);
	} else {
		assert(astlpc->mode == MCTP_BINDING_ASTLPC_MODE_HOST);

		layout->rx.offset = be32toh(hdr.layout.rx_offset);
		layout->rx.size = be32toh(hdr.layout.rx_size);
		layout->tx.offset = be32toh(hdr.layout.tx_offset);
		layout->tx.size = be32toh(hdr.layout.tx_size);
	}

	return 0;
}

static int mctp_astlpc_layout_write(struct mctp_binding_astlpc *astlpc,
				    struct mctp_astlpc_layout *layout)
{
	uint32_t rx_size_be;

	if (astlpc->mode == MCTP_BINDING_ASTLPC_MODE_BMC) {
		struct mctp_lpcmap_hdr hdr;

		/*
		 * Flip the buffers as the names are defined in terms of the
		 * host
		 */
		hdr.layout.rx_offset = htobe32(layout->tx.offset);
		hdr.layout.rx_size = htobe32(layout->tx.size);
		hdr.layout.tx_offset = htobe32(layout->rx.offset);
		hdr.layout.tx_size = htobe32(layout->rx.size);

		return mctp_astlpc_lpc_write(astlpc, &hdr.layout,
					     offsetof(struct mctp_lpcmap_hdr,
						      layout),
					     sizeof(hdr.layout));
	}

	assert(astlpc->mode == MCTP_BINDING_ASTLPC_MODE_HOST);

	/*
	 * As of v2 we only need to write rx_size - the offsets are controlled
	 * by the BMC, as is the BMC's rx_size (host tx_size).
	 */
	rx_size_be = htobe32(layout->rx.size);
	return mctp_astlpc_lpc_write(astlpc, &rx_size_be,
				     offsetof(struct mctp_lpcmap_hdr,
					      layout.rx_size),
				     sizeof(rx_size_be));
}

static bool
mctp_astlpc_buffer_validate(const struct mctp_binding_astlpc *astlpc,
			    const struct mctp_astlpc_buffer *buf,
			    const char *name)
{
	/* Check for overflow */
	if (buf->offset + buf->size < buf->offset) {
		mctp_prerr(
			"%s packet buffer parameters overflow: offset: 0x%" PRIx32
			", size: %" PRIu32,
			name, buf->offset, buf->size);
		return false;
	}

	/* Check that the buffers are contained within the allocated space */
	if (buf->offset + buf->size > LPC_WIN_SIZE) {
		mctp_prerr(
			"%s packet buffer parameters exceed %uM window size: offset: 0x%" PRIx32
			", size: %" PRIu32,
			name, (LPC_WIN_SIZE / (1024 * 1024)), buf->offset,
			buf->size);
		return false;
	}

	/* Check that the baseline transmission unit is supported */
	if (buf->size <
	    astlpc->proto->packet_size(MCTP_PACKET_SIZE(MCTP_BTU))) {
		mctp_prerr(
			"%s packet buffer too small: Require %" PRIu32
			" bytes to support the %u byte baseline transmission unit, found %" PRIu32,
			name,
			astlpc->proto->packet_size(MCTP_PACKET_SIZE(MCTP_BTU)),
			MCTP_BTU, buf->size);
		return false;
	}

	/* Check for overlap with the control space */
	if (buf->offset < control_size) {
		mctp_prerr(
			"%s packet buffer overlaps control region {0x%" PRIx32
			", %" PRIu32 "}: Rx {0x%" PRIx32 ", %" PRIu32 "}",
			name, 0U, control_size, buf->offset, buf->size);
		return false;
	}

	return true;
}

static bool
mctp_astlpc_layout_validate(const struct mctp_binding_astlpc *astlpc,
			    const struct mctp_astlpc_layout *layout)
{
	const struct mctp_astlpc_buffer *rx = &layout->rx;
	const struct mctp_astlpc_buffer *tx = &layout->tx;
	bool rx_valid, tx_valid;

	rx_valid = mctp_astlpc_buffer_validate(astlpc, rx, "Rx");
	tx_valid = mctp_astlpc_buffer_validate(astlpc, tx, "Tx");

	if (!(rx_valid && tx_valid))
		return false;

	/* Check that the buffers are disjoint */
	if ((rx->offset <= tx->offset && rx->offset + rx->size > tx->offset) ||
	    (tx->offset <= rx->offset && tx->offset + tx->size > rx->offset)) {
		mctp_prerr("Rx and Tx packet buffers overlap: Rx {0x%" PRIx32
			   ", %" PRIu32 "}, Tx {0x%" PRIx32 ", %" PRIu32 "}",
			   rx->offset, rx->size, tx->offset, tx->size);
		return false;
	}

	return true;
}

static int mctp_astlpc_init_bmc(struct mctp_binding_astlpc *astlpc)
{
	struct mctp_lpcmap_hdr hdr = { 0 };
	uint8_t status;
	uint32_t sz;

	/*
	 * The largest buffer size is half of the allocated MCTP space
	 * excluding the control space.
	 */
	sz = ((LPC_WIN_SIZE - control_size) / 2);

	/*
	 * Trim the MTU to a multiple of 16 to meet the requirements of 12.17
	 * Query Hop in DSP0236 v1.3.0.
	 */
	sz = MCTP_BODY_SIZE(astlpc->proto->body_size(sz));
	sz &= ~0xfUL;
	sz = astlpc->proto->packet_size(MCTP_PACKET_SIZE(sz));

	if (astlpc->requested_mtu) {
		uint32_t rpkt, rmtu;

		rmtu = astlpc->requested_mtu;
		rpkt = astlpc->proto->packet_size(MCTP_PACKET_SIZE(rmtu));
		sz = MIN(sz, rpkt);
	}

	/* Flip the buffers as the names are defined in terms of the host */
	astlpc->layout.tx.offset = control_size;
	astlpc->layout.tx.size = sz;
	astlpc->layout.rx.offset =
		astlpc->layout.tx.offset + astlpc->layout.tx.size;
	astlpc->layout.rx.size = sz;

	if (!mctp_astlpc_layout_validate(astlpc, &astlpc->layout)) {
		astlpc_prerr(astlpc, "Cannot support an MTU of %" PRIu32, sz);
		return -EINVAL;
	}

	hdr = (struct mctp_lpcmap_hdr){
		.magic = htobe32(ASTLPC_MCTP_MAGIC),
		.bmc_ver_min = htobe16(ASTLPC_VER_MIN),
		.bmc_ver_cur = htobe16(ASTLPC_VER_CUR),

		/* Flip the buffers back as we're now describing the host's
		 * configuration to the host */
		.layout.rx_offset = htobe32(astlpc->layout.tx.offset),
		.layout.rx_size = htobe32(astlpc->layout.tx.size),
		.layout.tx_offset = htobe32(astlpc->layout.rx.offset),
		.layout.tx_size = htobe32(astlpc->layout.rx.size),
	};

	mctp_astlpc_lpc_write(astlpc, &hdr, 0, sizeof(hdr));

	/*
	 * Set status indicating that the BMC is now active. Be explicit about
	 * clearing OBF; we're reinitialising the binding and so any previous
	 * buffer state is irrelevant.
	 */
	status = KCS_STATUS_BMC_READY & ~KCS_STATUS_OBF;
	return mctp_astlpc_kcs_set_status(astlpc, status);
}

static int mctp_binding_astlpc_start_bmc(struct mctp_binding *b)
{
	struct mctp_binding_astlpc *astlpc =
		container_of(b, struct mctp_binding_astlpc, binding);

	astlpc->proto = &astlpc_protocol_version[ASTLPC_VER_CUR];

	return mctp_astlpc_init_bmc(astlpc);
}

static bool mctp_astlpc_validate_version(uint16_t bmc_ver_min,
					 uint16_t bmc_ver_cur,
					 uint16_t host_ver_min,
					 uint16_t host_ver_cur)
{
	if (!(bmc_ver_min && bmc_ver_cur && host_ver_min && host_ver_cur)) {
		mctp_prerr("Invalid version present in [%" PRIu16 ", %" PRIu16
			   "], [%" PRIu16 ", %" PRIu16 "]",
			   bmc_ver_min, bmc_ver_cur, host_ver_min,
			   host_ver_cur);
		return false;
	} else if (bmc_ver_min > bmc_ver_cur) {
		mctp_prerr("Invalid bmc version range [%" PRIu16 ", %" PRIu16
			   "]",
			   bmc_ver_min, bmc_ver_cur);
		return false;
	} else if (host_ver_min > host_ver_cur) {
		mctp_prerr("Invalid host version range [%" PRIu16 ", %" PRIu16
			   "]",
			   host_ver_min, host_ver_cur);
		return false;
	} else if ((host_ver_cur < bmc_ver_min) ||
		   (host_ver_min > bmc_ver_cur)) {
		mctp_prerr(
			"Unable to satisfy version negotiation with ranges [%" PRIu16
			", %" PRIu16 "] and [%" PRIu16 ", %" PRIu16 "]",
			bmc_ver_min, bmc_ver_cur, host_ver_min, host_ver_cur);
		return false;
	}

	return true;
}

static int mctp_astlpc_negotiate_layout_host(struct mctp_binding_astlpc *astlpc)
{
	struct mctp_astlpc_layout layout;
	uint32_t rmtu;
	uint32_t sz;
	int rc;

	rc = mctp_astlpc_layout_read(astlpc, &layout);
	if (rc < 0)
		return rc;

	if (!mctp_astlpc_layout_validate(astlpc, &layout)) {
		astlpc_prerr(
			astlpc,
			"BMC provided invalid buffer layout: Rx {0x%" PRIx32
			", %" PRIu32 "}, Tx {0x%" PRIx32 ", %" PRIu32 "}",
			layout.rx.offset, layout.rx.size, layout.tx.offset,
			layout.tx.size);
		return -EINVAL;
	}

	astlpc_prinfo(astlpc, "Desire an MTU of %" PRIu32 " bytes",
		      astlpc->requested_mtu);

	rmtu = astlpc->requested_mtu;
	sz = astlpc->proto->packet_size(MCTP_PACKET_SIZE(rmtu));
	layout.rx.size = sz;

	if (!mctp_astlpc_layout_validate(astlpc, &layout)) {
		astlpc_prerr(
			astlpc,
			"Generated invalid buffer layout with size %" PRIu32
			": Rx {0x%" PRIx32 ", %" PRIu32 "}, Tx {0x%" PRIx32
			", %" PRIu32 "}",
			sz, layout.rx.offset, layout.rx.size, layout.tx.offset,
			layout.tx.size);
		return -EINVAL;
	}

	astlpc_prinfo(astlpc, "Requesting MTU of %" PRIu32 " bytes",
		      astlpc->requested_mtu);

	return mctp_astlpc_layout_write(astlpc, &layout);
}

static uint16_t mctp_astlpc_negotiate_version(uint16_t bmc_ver_min,
					      uint16_t bmc_ver_cur,
					      uint16_t host_ver_min,
					      uint16_t host_ver_cur)
{
	if (!mctp_astlpc_validate_version(bmc_ver_min, bmc_ver_cur,
					  host_ver_min, host_ver_cur))
		return ASTLPC_VER_BAD;

	if (bmc_ver_cur < host_ver_cur)
		return bmc_ver_cur;

	return host_ver_cur;
}

static int mctp_astlpc_init_host(struct mctp_binding_astlpc *astlpc)
{
	const uint16_t ver_min_be = htobe16(ASTLPC_VER_MIN);
	const uint16_t ver_cur_be = htobe16(ASTLPC_VER_CUR);
	uint16_t bmc_ver_min, bmc_ver_cur, negotiated;
	struct mctp_lpcmap_hdr hdr;
	uint8_t status;
	int rc;

	rc = mctp_astlpc_kcs_read(astlpc, MCTP_ASTLPC_KCS_REG_STATUS, &status);
	if (rc) {
		mctp_prwarn("KCS status read failed");
		return rc;
	}

	astlpc->kcs_status = status;

	if (!(status & KCS_STATUS_BMC_READY))
		return -EHOSTDOWN;

	mctp_astlpc_lpc_read(astlpc, &hdr, 0, sizeof(hdr));

	bmc_ver_min = be16toh(hdr.bmc_ver_min);
	bmc_ver_cur = be16toh(hdr.bmc_ver_cur);

	/* Calculate the expected value of negotiated_ver */
	negotiated = mctp_astlpc_negotiate_version(
		bmc_ver_min, bmc_ver_cur, ASTLPC_VER_MIN, ASTLPC_VER_CUR);
	if (!negotiated) {
		astlpc_prerr(astlpc, "Cannot negotiate with invalid versions");
		return -EINVAL;
	}

	/* Assign protocol ops so we can calculate the packet buffer sizes */
	assert(negotiated < ARRAY_SIZE(astlpc_protocol_version));
	astlpc->proto = &astlpc_protocol_version[negotiated];

	/* Negotiate packet buffers in v2 style if the BMC supports it */
	if (negotiated >= 2) {
		rc = mctp_astlpc_negotiate_layout_host(astlpc);
		if (rc < 0)
			return rc;
	}

	/* Advertise the host's supported protocol versions */
	mctp_astlpc_lpc_write(astlpc, &ver_min_be,
			      offsetof(struct mctp_lpcmap_hdr, host_ver_min),
			      sizeof(ver_min_be));

	mctp_astlpc_lpc_write(astlpc, &ver_cur_be,
			      offsetof(struct mctp_lpcmap_hdr, host_ver_cur),
			      sizeof(ver_cur_be));

	/* Send channel init command */
	rc = mctp_astlpc_kcs_write(astlpc, MCTP_ASTLPC_KCS_REG_DATA, 0x0);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS write failed");
	}

	/*
	 * Configure the host so `astlpc->proto->version == 0` holds until we
	 * receive a subsequent status update from the BMC. Until then,
	 * `astlpc->proto->version == 0` indicates that we're yet to complete
	 * the channel initialisation handshake.
	 *
	 * When the BMC provides a status update with KCS_STATUS_CHANNEL_ACTIVE
	 * set we will assign the appropriate protocol ops struct in accordance
	 * with `negotiated_ver`.
	 */
	astlpc->proto = &astlpc_protocol_version[ASTLPC_VER_BAD];

	return rc;
}

static int mctp_binding_astlpc_start_host(struct mctp_binding *b)
{
	struct mctp_binding_astlpc *astlpc =
		container_of(b, struct mctp_binding_astlpc, binding);

	return mctp_astlpc_init_host(astlpc);
}

static bool __mctp_astlpc_kcs_ready(struct mctp_binding_astlpc *astlpc,
				    uint8_t status, bool is_write)
{
	bool is_bmc;
	bool ready_state;
	uint8_t flag;

	is_bmc = (astlpc->mode == MCTP_BINDING_ASTLPC_MODE_BMC);
	flag = (is_bmc ^ is_write) ? KCS_STATUS_IBF : KCS_STATUS_OBF;
	ready_state = is_write ? 0 : 1;

	return !!(status & flag) == ready_state;
}

static inline bool
mctp_astlpc_kcs_read_ready(struct mctp_binding_astlpc *astlpc, uint8_t status)
{
	return __mctp_astlpc_kcs_ready(astlpc, status, false);
}

static inline bool
mctp_astlpc_kcs_write_ready(struct mctp_binding_astlpc *astlpc, uint8_t status)
{
	return __mctp_astlpc_kcs_ready(astlpc, status, true);
}

static int mctp_astlpc_kcs_send(struct mctp_binding_astlpc *astlpc,
				enum mctp_astlpc_cmd data)
{
	uint8_t status;
	int rc;

	rc = mctp_astlpc_kcs_read(astlpc, MCTP_ASTLPC_KCS_REG_STATUS, &status);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS status read failed");
		return -EIO;
	}
	if (!mctp_astlpc_kcs_write_ready(astlpc, status))
		return -EBUSY;

	rc = mctp_astlpc_kcs_write(astlpc, MCTP_ASTLPC_KCS_REG_DATA, data);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS data write failed");
		return -EIO;
	}

	return 0;
}

static int mctp_binding_astlpc_tx(struct mctp_binding *b,
				  struct mctp_pktbuf *pkt)
{
	struct mctp_binding_astlpc *astlpc = binding_to_astlpc(b);
	uint32_t len, len_be;
	struct mctp_hdr *hdr;
	int rc;

	hdr = mctp_pktbuf_hdr(pkt);
	len = mctp_pktbuf_size(pkt);

	astlpc_prdebug(astlpc,
		       "%s: Transmitting %" PRIu32
		       "-byte packet (%hhu, %hhu, 0x%hhx)",
		       __func__, len, hdr->src, hdr->dest, hdr->flags_seq_tag);

	if (len > astlpc->proto->body_size(astlpc->layout.tx.size)) {
		astlpc_prwarn(astlpc, "invalid TX len %" PRIu32 ": %" PRIu32,
			      len,
			      astlpc->proto->body_size(astlpc->layout.tx.size));
		return -EMSGSIZE;
	}

	mctp_binding_set_tx_enabled(b, false);

	len_be = htobe32(len);
	mctp_astlpc_lpc_write(astlpc, &len_be, astlpc->layout.tx.offset,
			      sizeof(len_be));

	astlpc->proto->pktbuf_protect(pkt);
	len = mctp_pktbuf_size(pkt);

	mctp_astlpc_lpc_write(astlpc, hdr, astlpc->layout.tx.offset + 4, len);

	astlpc->layout.tx.state = buffer_state_prepared;

	rc = mctp_astlpc_kcs_send(astlpc, cmd_tx_begin);
	if (!rc)
		astlpc->layout.tx.state = buffer_state_released;

	return rc == -EBUSY ? 0 : rc;
}

static uint32_t mctp_astlpc_calculate_mtu(struct mctp_binding_astlpc *astlpc,
					  struct mctp_astlpc_layout *layout)
{
	uint32_t low, high, limit, rpkt;

	/* Derive the largest MTU the BMC _can_ support */
	low = MIN(astlpc->layout.rx.offset, astlpc->layout.tx.offset);
	high = MAX(astlpc->layout.rx.offset, astlpc->layout.tx.offset);
	limit = high - low;

	/* Determine the largest MTU the BMC _wants_ to support */
	if (astlpc->requested_mtu) {
		uint32_t rmtu = astlpc->requested_mtu;

		rpkt = astlpc->proto->packet_size(MCTP_PACKET_SIZE(rmtu));
		limit = MIN(limit, rpkt);
	}

	/* Determine the accepted MTU, applied both directions by convention */
	rpkt = MIN(limit, layout->tx.size);
	return MCTP_BODY_SIZE(astlpc->proto->body_size(rpkt));
}

static int mctp_astlpc_negotiate_layout_bmc(struct mctp_binding_astlpc *astlpc)
{
	struct mctp_astlpc_layout proposed, pending;
	uint32_t sz, mtu;
	int rc;

	/* Do we have a valid protocol version? */
	if (!astlpc->proto->version)
		return -EINVAL;

	/* Extract the host's proposed layout */
	rc = mctp_astlpc_layout_read(astlpc, &proposed);
	if (rc < 0)
		return rc;

	/* Do we have a reasonable layout? */
	if (!mctp_astlpc_layout_validate(astlpc, &proposed))
		return -EINVAL;

	/* Negotiate the MTU */
	mtu = mctp_astlpc_calculate_mtu(astlpc, &proposed);
	sz = astlpc->proto->packet_size(MCTP_PACKET_SIZE(mtu));

	/*
	 * Use symmetric MTUs by convention and to pass constraints in rx/tx
	 * functions
	 */
	pending = astlpc->layout;
	pending.tx.size = sz;
	pending.rx.size = sz;

	if (mctp_astlpc_layout_validate(astlpc, &pending)) {
		/* We found a sensible Rx MTU, so honour it */
		astlpc->layout = pending;

		/* Enforce the negotiated MTU */
		rc = mctp_astlpc_layout_write(astlpc, &astlpc->layout);
		if (rc < 0)
			return rc;

		astlpc_prinfo(astlpc, "Negotiated an MTU of %" PRIu32 " bytes",
			      mtu);
	} else {
		astlpc_prwarn(astlpc, "MTU negotiation failed");
		return -EINVAL;
	}

	if (astlpc->proto->version >= 2)
		astlpc->binding.pkt_size = MCTP_PACKET_SIZE(mtu);

	return 0;
}

static void mctp_astlpc_init_channel(struct mctp_binding_astlpc *astlpc)
{
	uint16_t negotiated, negotiated_be;
	struct mctp_lpcmap_hdr hdr;
	uint8_t status;
	int rc;

	mctp_astlpc_lpc_read(astlpc, &hdr, 0, sizeof(hdr));

	/* Version negotiation */
	negotiated = mctp_astlpc_negotiate_version(ASTLPC_VER_MIN,
						   ASTLPC_VER_CUR,
						   be16toh(hdr.host_ver_min),
						   be16toh(hdr.host_ver_cur));

	/* MTU negotiation requires knowing which protocol we'll use */
	assert(negotiated < ARRAY_SIZE(astlpc_protocol_version));
	astlpc->proto = &astlpc_protocol_version[negotiated];

	/* Host Rx MTU negotiation: Failure terminates channel init */
	rc = mctp_astlpc_negotiate_layout_bmc(astlpc);
	if (rc < 0)
		negotiated = ASTLPC_VER_BAD;

	/* Populate the negotiated version */
	negotiated_be = htobe16(negotiated);
	mctp_astlpc_lpc_write(astlpc, &negotiated_be,
			      offsetof(struct mctp_lpcmap_hdr, negotiated_ver),
			      sizeof(negotiated_be));

	/* Track buffer ownership */
	astlpc->layout.tx.state = buffer_state_acquired;
	astlpc->layout.rx.state = buffer_state_released;

	/* Finalise the configuration */
	status = KCS_STATUS_BMC_READY | KCS_STATUS_OBF;
	if (negotiated > 0) {
		astlpc_prinfo(astlpc, "Negotiated binding version %" PRIu16,
			      negotiated);
		status |= KCS_STATUS_CHANNEL_ACTIVE;
	} else {
		astlpc_prerr(astlpc, "Failed to initialise channel");
	}

	mctp_astlpc_kcs_set_status(astlpc, status);

	mctp_binding_set_tx_enabled(&astlpc->binding,
				    status & KCS_STATUS_CHANNEL_ACTIVE);
}

static void mctp_astlpc_rx_start(struct mctp_binding_astlpc *astlpc)
{
	struct mctp_pktbuf *pkt;
	struct mctp_hdr *hdr;
	uint32_t body, packet;

	mctp_astlpc_lpc_read(astlpc, &body, astlpc->layout.rx.offset,
			     sizeof(body));
	body = be32toh(body);

	if (body > astlpc->proto->body_size(astlpc->layout.rx.size)) {
		astlpc_prwarn(astlpc, "invalid RX len 0x%x", body);
		return;
	}

	if ((size_t)body > astlpc->binding.pkt_size) {
		astlpc_prwarn(astlpc, "invalid RX len 0x%x", body);
		return;
	}

	/* Eliminate the medium-specific header that we just read */
	packet = astlpc->proto->packet_size(body) - 4;
	pkt = mctp_pktbuf_alloc(&astlpc->binding, packet);
	if (!pkt) {
		astlpc_prwarn(astlpc, "unable to allocate pktbuf len 0x%x",
			      packet);
		return;
	}

	/*
	 * Read payload and medium-specific trailer from immediately after the
	 * medium-specific header.
	 */
	mctp_astlpc_lpc_read(astlpc, mctp_pktbuf_hdr(pkt),
			     astlpc->layout.rx.offset + 4, packet);

	astlpc->layout.rx.state = buffer_state_prepared;

	/* Inform the other side of the MCTP interface that we have read
	 * the packet off the bus before handling the contents of the packet.
	 */
	if (!mctp_astlpc_kcs_send(astlpc, cmd_rx_complete))
		astlpc->layout.rx.state = buffer_state_released;

	hdr = mctp_pktbuf_hdr(pkt);
	if (hdr->ver != 1) {
		mctp_pktbuf_free(pkt);
		astlpc_prdebug(astlpc, "Dropped packet with invalid version");
		return;
	}

	/*
	 * v3 will validate the CRC32 in the medium-specific trailer and adjust
	 * the packet size accordingly. On older protocols validation is a no-op
	 * that always returns true.
	 */
	if (astlpc->proto->pktbuf_validate(pkt)) {
		mctp_bus_rx(&astlpc->binding, pkt);
	} else {
		/* TODO: Drop any associated assembly */
		mctp_pktbuf_free(pkt);
		astlpc_prdebug(astlpc, "Dropped corrupt packet");
	}
}

static void mctp_astlpc_tx_complete(struct mctp_binding_astlpc *astlpc)
{
	astlpc->layout.tx.state = buffer_state_acquired;
	mctp_binding_set_tx_enabled(&astlpc->binding, true);
}

static int mctp_astlpc_finalise_channel(struct mctp_binding_astlpc *astlpc)
{
	struct mctp_astlpc_layout layout;
	uint16_t negotiated;
	int rc;

	rc = mctp_astlpc_lpc_read(astlpc, &negotiated,
				  offsetof(struct mctp_lpcmap_hdr,
					   negotiated_ver),
				  sizeof(negotiated));
	if (rc < 0)
		return rc;

	negotiated = be16toh(negotiated);
	astlpc_prerr(astlpc, "Version negotiation got: %u", negotiated);

	if (negotiated == ASTLPC_VER_BAD || negotiated < ASTLPC_VER_MIN ||
	    negotiated > ASTLPC_VER_CUR) {
		astlpc_prerr(astlpc, "Failed to negotiate version, got: %u\n",
			     negotiated);
		return -EINVAL;
	}

	assert(negotiated < ARRAY_SIZE(astlpc_protocol_version));
	astlpc->proto = &astlpc_protocol_version[negotiated];

	rc = mctp_astlpc_layout_read(astlpc, &layout);
	if (rc < 0)
		return rc;

	if (!mctp_astlpc_layout_validate(astlpc, &layout)) {
		mctp_prerr("BMC proposed invalid buffer parameters");
		return -EINVAL;
	}

	astlpc->layout = layout;

	if (negotiated >= 2)
		astlpc->binding.pkt_size =
			astlpc->proto->body_size(astlpc->layout.tx.size);

	/* Track buffer ownership */
	astlpc->layout.tx.state = buffer_state_acquired;
	astlpc->layout.rx.state = buffer_state_released;

	return 0;
}

static int mctp_astlpc_update_channel(struct mctp_binding_astlpc *astlpc,
				      uint8_t status)
{
	uint8_t updated;
	int rc = 0;

	assert(astlpc->mode == MCTP_BINDING_ASTLPC_MODE_HOST);

	updated = astlpc->kcs_status ^ status;

	astlpc_prdebug(astlpc, "%s: status: 0x%x, update: 0x%x", __func__,
		       status, updated);

	if (updated & KCS_STATUS_BMC_READY) {
		if (status & KCS_STATUS_BMC_READY) {
			astlpc->kcs_status = status;
			return astlpc->binding.start(&astlpc->binding);
		} else {
			/* Shut down the channel */
			astlpc->layout.rx.state = buffer_state_idle;
			astlpc->layout.tx.state = buffer_state_idle;
			mctp_binding_set_tx_enabled(&astlpc->binding, false);
		}
	}

	if (astlpc->proto->version == 0 ||
	    updated & KCS_STATUS_CHANNEL_ACTIVE) {
		bool enable;

		astlpc->layout.rx.state = buffer_state_idle;
		astlpc->layout.tx.state = buffer_state_idle;
		rc = mctp_astlpc_finalise_channel(astlpc);
		enable = (status & KCS_STATUS_CHANNEL_ACTIVE) && rc == 0;
		mctp_binding_set_tx_enabled(&astlpc->binding, enable);
	}

	astlpc->kcs_status = status;

	return rc;
}

bool mctp_astlpc_tx_done(struct mctp_binding_astlpc *astlpc)
{
	return astlpc->layout.tx.state == buffer_state_acquired;
}

int mctp_astlpc_poll(struct mctp_binding_astlpc *astlpc)
{
	uint8_t status, data;
	int rc;

	if (astlpc->layout.rx.state == buffer_state_prepared)
		if (!mctp_astlpc_kcs_send(astlpc, cmd_rx_complete))
			astlpc->layout.rx.state = buffer_state_released;

	if (astlpc->layout.tx.state == buffer_state_prepared)
		if (!mctp_astlpc_kcs_send(astlpc, cmd_tx_begin))
			astlpc->layout.tx.state = buffer_state_released;

	rc = mctp_astlpc_kcs_read(astlpc, MCTP_ASTLPC_KCS_REG_STATUS, &status);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS read error");
		return -1;
	}

	astlpc_prdebug(astlpc, "%s: status: 0x%hhx", __func__, status);

	if (!mctp_astlpc_kcs_read_ready(astlpc, status))
		return 0;

	rc = mctp_astlpc_kcs_read(astlpc, MCTP_ASTLPC_KCS_REG_DATA, &data);
	if (rc) {
		astlpc_prwarn(astlpc, "KCS data read error");
		return -1;
	}

	astlpc_prdebug(astlpc, "%s: data: 0x%hhx", __func__, data);

	if (!astlpc->proto->version &&
	    !(data == cmd_initialise || data == cmd_dummy_value)) {
		astlpc_prwarn(astlpc, "Invalid message for binding state: 0x%x",
			      data);
		return 0;
	}

	switch (data) {
	case cmd_initialise:
		mctp_astlpc_init_channel(astlpc);
		break;
	case cmd_tx_begin:
		if (astlpc->layout.rx.state != buffer_state_released) {
			astlpc_prerr(
				astlpc,
				"Protocol error: Invalid Rx buffer state for event %d: %d\n",
				data, astlpc->layout.rx.state);
			return 0;
		}
		mctp_astlpc_rx_start(astlpc);
		break;
	case cmd_rx_complete:
		if (astlpc->layout.tx.state != buffer_state_released) {
			astlpc_prerr(
				astlpc,
				"Protocol error: Invalid Tx buffer state for event %d: %d\n",
				data, astlpc->layout.tx.state);
			return 0;
		}
		mctp_astlpc_tx_complete(astlpc);
		break;
	case cmd_dummy_value:
		/* No responsibilities for the BMC on 0xff */
		if (astlpc->mode == MCTP_BINDING_ASTLPC_MODE_HOST) {
			rc = mctp_astlpc_update_channel(astlpc, status);
			if (rc < 0)
				return rc;
		}
		break;
	default:
		astlpc_prwarn(astlpc, "unknown message 0x%x", data);
	}

	/* Handle silent loss of bmc-ready */
	if (astlpc->mode == MCTP_BINDING_ASTLPC_MODE_HOST) {
		if (!(status & KCS_STATUS_BMC_READY && data == cmd_dummy_value))
			return mctp_astlpc_update_channel(astlpc, status);
	}

	return rc;
}

/* allocate and basic initialisation */
static struct mctp_binding_astlpc *__mctp_astlpc_init(uint8_t mode,
						      uint32_t mtu)
{
	struct mctp_binding_astlpc *astlpc;

	assert((mode == MCTP_BINDING_ASTLPC_MODE_BMC) ||
	       (mode == MCTP_BINDING_ASTLPC_MODE_HOST));

	astlpc = __mctp_alloc(sizeof(*astlpc));
	if (!astlpc)
		return NULL;

	memset(astlpc, 0, sizeof(*astlpc));
	astlpc->mode = mode;
	astlpc->lpc_map = NULL;
	astlpc->layout.rx.state = buffer_state_idle;
	astlpc->layout.tx.state = buffer_state_idle;
	astlpc->requested_mtu = mtu;
	astlpc->binding.name = "astlpc";
	astlpc->binding.version = 1;
	astlpc->binding.pkt_size =
		MCTP_PACKET_SIZE(mtu > MCTP_BTU ? mtu : MCTP_BTU);
	astlpc->binding.pkt_header = 4;
	astlpc->binding.pkt_trailer = 4;
	astlpc->binding.tx = mctp_binding_astlpc_tx;
	if (mode == MCTP_BINDING_ASTLPC_MODE_BMC)
		astlpc->binding.start = mctp_binding_astlpc_start_bmc;
	else if (mode == MCTP_BINDING_ASTLPC_MODE_HOST)
		astlpc->binding.start = mctp_binding_astlpc_start_host;
	else {
		astlpc_prerr(astlpc, "%s: Invalid mode: %d\n", __func__, mode);
		__mctp_free(astlpc);
		return NULL;
	}

	return astlpc;
}

struct mctp_binding *mctp_binding_astlpc_core(struct mctp_binding_astlpc *b)
{
	return &b->binding;
}

struct mctp_binding_astlpc *
mctp_astlpc_init(uint8_t mode, uint32_t mtu, void *lpc_map,
		 const struct mctp_binding_astlpc_ops *ops, void *ops_data)
{
	struct mctp_binding_astlpc *astlpc;

	if (!(mode == MCTP_BINDING_ASTLPC_MODE_BMC ||
	      mode == MCTP_BINDING_ASTLPC_MODE_HOST)) {
		mctp_prerr("Unknown binding mode: %u", mode);
		return NULL;
	}

	astlpc = __mctp_astlpc_init(mode, mtu);
	if (!astlpc)
		return NULL;

	memcpy(&astlpc->ops, ops, sizeof(astlpc->ops));
	astlpc->ops_data = ops_data;
	astlpc->lpc_map = lpc_map;
	astlpc->mode = mode;

	return astlpc;
}

struct mctp_binding_astlpc *
mctp_astlpc_init_ops(const struct mctp_binding_astlpc_ops *ops, void *ops_data,
		     void *lpc_map)
{
	return mctp_astlpc_init(MCTP_BINDING_ASTLPC_MODE_BMC, MCTP_BTU, lpc_map,
				ops, ops_data);
}

void mctp_astlpc_destroy(struct mctp_binding_astlpc *astlpc)
{
	/* Clear channel-active and bmc-ready */
	if (astlpc->mode == MCTP_BINDING_ASTLPC_MODE_BMC)
		mctp_astlpc_kcs_set_status(astlpc, 0);
	__mctp_free(astlpc);
}

#ifdef MCTP_HAVE_FILEIO

static int mctp_astlpc_init_fileio_lpc(struct mctp_binding_astlpc *astlpc)
{
	struct aspeed_lpc_ctrl_mapping map = {
		.window_type = ASPEED_LPC_CTRL_WINDOW_MEMORY,
		.window_id = 0, /* There's only one */
		.flags = 0,
		.addr = 0,
		.offset = 0,
		.size = 0
	};
	void *lpc_map_base;
	int fd, rc;

	fd = open(lpc_path, O_RDWR | O_SYNC);
	if (fd < 0) {
		astlpc_prwarn(astlpc, "LPC open (%s) failed", lpc_path);
		return -1;
	}

	rc = ioctl(fd, ASPEED_LPC_CTRL_IOCTL_GET_SIZE, &map);
	if (rc) {
		astlpc_prwarn(astlpc, "LPC GET_SIZE failed");
		close(fd);
		return -1;
	}

	/*
	 * 🚨🚨🚨
	 *
	 * Decouple ourselves from hiomapd[1] (another user of the FW2AHB) by
	 * mapping the FW2AHB to the reserved memory here as well.
	 *
	 * It's not possible to use the MCTP ASTLPC binding on machines that
	 * need the FW2AHB bridge mapped anywhere except to the reserved memory
	 * (e.g. the host SPI NOR).
	 *
	 * [1] https://github.com/openbmc/hiomapd/
	 *
	 * 🚨🚨🚨
	 *
	 * The following calculation must align with what's going on in
	 * hiomapd's lpc.c so as not to disrupt its behaviour:
	 *
	 * https://github.com/openbmc/hiomapd/blob/5ff50e3cbd7702aefc185264e4adfb9952040575/lpc.c#L68
	 *
	 * 🚨🚨🚨
	 */

	/* Map the reserved memory at the top of the 28-bit LPC firmware address space */
	map.addr = 0x0FFFFFFF & -map.size;
	astlpc_prinfo(
		astlpc,
		"Configuring FW2AHB to map reserved memory at 0x%08x for 0x%x in the LPC FW cycle address-space",
		map.addr, map.size);

	rc = ioctl(fd, ASPEED_LPC_CTRL_IOCTL_MAP, &map);
	if (rc) {
		astlpc_prwarn(astlpc,
			      "Failed to map FW2AHB to reserved memory");
		close(fd);
		return -1;
	}

	/* Map the reserved memory into our address space */
	lpc_map_base =
		mmap(NULL, map.size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (lpc_map_base == MAP_FAILED) {
		astlpc_prwarn(astlpc, "LPC mmap failed");
		rc = -1;
	} else {
		astlpc->lpc_map = lpc_map_base + map.size - LPC_WIN_SIZE;
	}

	close(fd);

	return rc;
}

static int mctp_astlpc_init_fileio_kcs(struct mctp_binding_astlpc *astlpc)
{
	astlpc->kcs_fd = open(kcs_path, O_RDWR);
	if (astlpc->kcs_fd < 0)
		return -1;

	return 0;
}

static int __mctp_astlpc_fileio_kcs_read(void *arg,
					 enum mctp_binding_astlpc_kcs_reg reg,
					 uint8_t *val)
{
	struct mctp_binding_astlpc *astlpc = arg;
	off_t offset = reg;
	int rc;

	rc = pread(astlpc->kcs_fd, val, 1, offset);

	return rc == 1 ? 0 : -1;
}

static int __mctp_astlpc_fileio_kcs_write(void *arg,
					  enum mctp_binding_astlpc_kcs_reg reg,
					  uint8_t val)
{
	struct mctp_binding_astlpc *astlpc = arg;
	off_t offset = reg;
	int rc;

	rc = pwrite(astlpc->kcs_fd, &val, 1, offset);

	return rc == 1 ? 0 : -1;
}

int mctp_astlpc_init_pollfd(struct mctp_binding_astlpc *astlpc,
			    struct pollfd *pollfd)
{
	bool release;

	pollfd->fd = astlpc->kcs_fd;
	pollfd->events = 0;

	release = astlpc->layout.rx.state == buffer_state_prepared ||
		  astlpc->layout.tx.state == buffer_state_prepared;

	pollfd->events = release ? POLLOUT : POLLIN;

	return 0;
}

struct mctp_binding_astlpc *mctp_astlpc_init_fileio(void)
{
	struct mctp_binding_astlpc *astlpc;
	int rc;

	/*
	 * If we're doing file IO then we're very likely not running
	 * freestanding, so lets assume that we're on the BMC side.
	 *
	 * Requesting an MTU of 0 requests the largest possible MTU, whatever
	 * value that might take.
	 */
	astlpc = __mctp_astlpc_init(MCTP_BINDING_ASTLPC_MODE_BMC, 0);
	if (!astlpc)
		return NULL;

	/* Set internal operations for kcs. We use direct accesses to the lpc
	 * map area */
	astlpc->ops.kcs_read = __mctp_astlpc_fileio_kcs_read;
	astlpc->ops.kcs_write = __mctp_astlpc_fileio_kcs_write;
	astlpc->ops_data = astlpc;

	rc = mctp_astlpc_init_fileio_lpc(astlpc);
	if (rc) {
		free(astlpc);
		return NULL;
	}

	rc = mctp_astlpc_init_fileio_kcs(astlpc);
	if (rc) {
		free(astlpc);
		return NULL;
	}

	return astlpc;
}
#else
struct mctp_binding_astlpc *mctp_astlpc_init_fileio(void)
{
	mctp_prlog(MCTP_LOG_ERR, "%s: Missing support for file IO", __func__);
	return NULL;
}

int mctp_astlpc_init_pollfd(struct mctp_binding_astlpc *astlpc __unused,
			    struct pollfd *pollfd __unused)
{
	mctp_prlog(MCTP_LOG_ERR, "%s: Missing support for file IO", __func__);
	return -1;
}
#endif
