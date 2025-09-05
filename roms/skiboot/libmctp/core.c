/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#undef pr_fmt
#define pr_fmt(fmt) "core: " fmt

#include "libmctp.h"
#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-cmds.h"
#include "range.h"

/* Internal data structures */

struct mctp_bus {
	mctp_eid_t eid;
	struct mctp_binding *binding;
	enum mctp_bus_state state;

	struct mctp_pktbuf *tx_queue_head;
	struct mctp_pktbuf *tx_queue_tail;

	/* todo: routing */
};

struct mctp_msg_ctx {
	uint8_t src;
	uint8_t dest;
	uint8_t tag;
	uint8_t last_seq;
	void *buf;
	size_t buf_size;
	size_t buf_alloc_size;
	size_t fragment_size;
};

struct mctp {
	int n_busses;
	struct mctp_bus *busses;

	/* Message RX callback */
	mctp_rx_fn message_rx;
	void *message_rx_data;

	/* Packet capture callback */
	mctp_capture_fn capture;
	void *capture_data;

	/* Message reassembly.
	 * @todo: flexible context count
	 */
	struct mctp_msg_ctx msg_ctxs[16];

	enum {
		ROUTE_ENDPOINT,
		ROUTE_BRIDGE,
	} route_policy;
	size_t max_message_size;
};

#ifndef BUILD_ASSERT
#define BUILD_ASSERT(x)                                                        \
	do {                                                                   \
		(void)sizeof(char[0 - (!(x))]);                                \
	} while (0)
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

/* 64kb should be sufficient for a single message. Applications
 * requiring higher sizes can override by setting max_message_size.*/
#ifndef MCTP_MAX_MESSAGE_SIZE
#define MCTP_MAX_MESSAGE_SIZE 65536
#endif

static int mctp_message_tx_on_bus(struct mctp_bus *bus, mctp_eid_t src,
				  mctp_eid_t dest, bool tag_owner,
				  uint8_t msg_tag, void *msg, size_t msg_len);

struct mctp_pktbuf *mctp_pktbuf_alloc(struct mctp_binding *binding, size_t len)
{
	struct mctp_pktbuf *buf;
	size_t size;

	size = len + binding->pkt_header + binding->pkt_trailer;

	/* todo: pools */
	buf = __mctp_alloc(sizeof(*buf) + size);

	if (!buf)
		return NULL;

	buf->size = size;
	buf->start = binding->pkt_header;
	buf->end = buf->start + len;
	buf->mctp_hdr_off = buf->start;
	buf->next = NULL;

	return buf;
}

void mctp_pktbuf_free(struct mctp_pktbuf *pkt)
{
	__mctp_free(pkt);
}

struct mctp_hdr *mctp_pktbuf_hdr(struct mctp_pktbuf *pkt)
{
	return (struct mctp_hdr *)(pkt->data + pkt->mctp_hdr_off);
}

void *mctp_pktbuf_data(struct mctp_pktbuf *pkt)
{
	return pkt->data + pkt->mctp_hdr_off + sizeof(struct mctp_hdr);
}

size_t mctp_pktbuf_size(struct mctp_pktbuf *pkt)
{
	return pkt->end - pkt->start;
}

void *mctp_pktbuf_alloc_start(struct mctp_pktbuf *pkt, size_t size)
{
	assert(size <= pkt->start);
	pkt->start -= size;
	return pkt->data + pkt->start;
}

void *mctp_pktbuf_alloc_end(struct mctp_pktbuf *pkt, size_t size)
{
	void *buf;

	assert(size <= (pkt->size - pkt->end));
	buf = pkt->data + pkt->end;
	pkt->end += size;
	return buf;
}

int mctp_pktbuf_push(struct mctp_pktbuf *pkt, void *data, size_t len)
{
	void *p;

	if (pkt->end + len > pkt->size)
		return -1;

	p = pkt->data + pkt->end;

	pkt->end += len;
	memcpy(p, data, len);

	return 0;
}

void *mctp_pktbuf_pop(struct mctp_pktbuf *pkt, size_t len)
{
	if (len > mctp_pktbuf_size(pkt))
		return NULL;

	pkt->end -= len;
	return pkt->data + pkt->end;
}

/* Message reassembly */
static struct mctp_msg_ctx *mctp_msg_ctx_lookup(struct mctp *mctp, uint8_t src,
						uint8_t dest, uint8_t tag)
{
	unsigned int i;

	/* @todo: better lookup, if we add support for more outstanding
	 * message contexts */
	for (i = 0; i < ARRAY_SIZE(mctp->msg_ctxs); i++) {
		struct mctp_msg_ctx *ctx = &mctp->msg_ctxs[i];
		if (ctx->src == src && ctx->dest == dest && ctx->tag == tag)
			return ctx;
	}

	return NULL;
}

static struct mctp_msg_ctx *mctp_msg_ctx_create(struct mctp *mctp, uint8_t src,
						uint8_t dest, uint8_t tag)
{
	struct mctp_msg_ctx *ctx = NULL;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(mctp->msg_ctxs); i++) {
		struct mctp_msg_ctx *tmp = &mctp->msg_ctxs[i];
		if (!tmp->src) {
			ctx = tmp;
			break;
		}
	}

	if (!ctx)
		return NULL;

	ctx->src = src;
	ctx->dest = dest;
	ctx->tag = tag;
	ctx->buf_size = 0;

	return ctx;
}

static void mctp_msg_ctx_drop(struct mctp_msg_ctx *ctx)
{
	ctx->src = 0;
}

static void mctp_msg_ctx_reset(struct mctp_msg_ctx *ctx)
{
	ctx->buf_size = 0;
	ctx->fragment_size = 0;
}

static int mctp_msg_ctx_add_pkt(struct mctp_msg_ctx *ctx,
				struct mctp_pktbuf *pkt, size_t max_size)
{
	size_t len;

	len = mctp_pktbuf_size(pkt) - sizeof(struct mctp_hdr);

	if (len + ctx->buf_size < ctx->buf_size) {
		return -1;
	}

	if (ctx->buf_size + len > ctx->buf_alloc_size) {
		size_t new_alloc_size;
		void *lbuf;

		/* @todo: finer-grained allocation */
		if (!ctx->buf_alloc_size) {
			new_alloc_size = MAX(len, 4096UL);
		} else {
			new_alloc_size = MAX(ctx->buf_alloc_size * 2,
					     len + ctx->buf_size);
		}

		/* Don't allow heap to grow beyond a limit */
		if (new_alloc_size > max_size)
			return -1;

		lbuf = __mctp_realloc(ctx->buf, new_alloc_size);
		if (lbuf) {
			ctx->buf = lbuf;
			ctx->buf_alloc_size = new_alloc_size;
		} else {
			__mctp_free(ctx->buf);
			return -1;
		}
	}

	memcpy((uint8_t *)ctx->buf + ctx->buf_size, mctp_pktbuf_data(pkt), len);
	ctx->buf_size += len;

	return 0;
}

/* Core API functions */
struct mctp *mctp_init(void)
{
	struct mctp *mctp;

	mctp = __mctp_alloc(sizeof(*mctp));

	if (!mctp)
		return NULL;

	memset(mctp, 0, sizeof(*mctp));
	mctp->max_message_size = MCTP_MAX_MESSAGE_SIZE;

	return mctp;
}

void mctp_set_max_message_size(struct mctp *mctp, size_t message_size)
{
	mctp->max_message_size = message_size;
}

void mctp_set_capture_handler(struct mctp *mctp, mctp_capture_fn fn, void *user)
{
	mctp->capture = fn;
	mctp->capture_data = user;
}

static void mctp_bus_destroy(struct mctp_bus *bus)
{
	while (bus->tx_queue_head) {
		struct mctp_pktbuf *curr = bus->tx_queue_head;

		bus->tx_queue_head = curr->next;
		mctp_pktbuf_free(curr);
	}
}

void mctp_destroy(struct mctp *mctp)
{
	size_t i;

	/* Cleanup message assembly contexts */
	BUILD_ASSERT(ARRAY_SIZE(mctp->msg_ctxs) < SIZE_MAX);
	for (i = 0; i < ARRAY_SIZE(mctp->msg_ctxs); i++) {
		struct mctp_msg_ctx *tmp = &mctp->msg_ctxs[i];
		if (tmp->buf)
			__mctp_free(tmp->buf);
	}

	while (mctp->n_busses--)
		mctp_bus_destroy(&mctp->busses[mctp->n_busses]);

	__mctp_free(mctp->busses);
	__mctp_free(mctp);
}

int mctp_set_rx_all(struct mctp *mctp, mctp_rx_fn fn, void *data)
{
	mctp->message_rx = fn;
	mctp->message_rx_data = data;
	return 0;
}

static struct mctp_bus *find_bus_for_eid(struct mctp *mctp, mctp_eid_t dest
					 __attribute__((unused)))
{
	if (mctp->n_busses == 0)
		return NULL;

	/* for now, just use the first bus. For full routing support,
	 * we will need a table of neighbours */
	return &mctp->busses[0];
}

int mctp_register_bus(struct mctp *mctp, struct mctp_binding *binding,
		      mctp_eid_t eid)
{
	int rc = 0;

	/* todo: multiple busses */
	assert(mctp->n_busses == 0);
	mctp->n_busses = 1;

	mctp->busses = __mctp_alloc(sizeof(struct mctp_bus));
	if (!mctp->busses)
		return -ENOMEM;

	memset(mctp->busses, 0, sizeof(struct mctp_bus));
	mctp->busses[0].binding = binding;
	mctp->busses[0].eid = eid;
	binding->bus = &mctp->busses[0];
	binding->mctp = mctp;
	mctp->route_policy = ROUTE_ENDPOINT;

	if (binding->start) {
		rc = binding->start(binding);
		if (rc < 0) {
			mctp_prerr("Failed to start binding: %d", rc);
			binding->bus = NULL;
			__mctp_free(mctp->busses);
			mctp->busses = NULL;
			mctp->n_busses = 0;
		}
	}

	return rc;
}

void mctp_unregister_bus(struct mctp *mctp, struct mctp_binding *binding)
{
	/*
	 * We only support one bus right now; once the call completes we will
	 * have no more busses
	 */
	mctp->n_busses = 0;
	binding->mctp = NULL;
	binding->bus = NULL;
	free(mctp->busses);
}

int mctp_bridge_busses(struct mctp *mctp, struct mctp_binding *b1,
		       struct mctp_binding *b2)
{
	int rc = 0;

	assert(mctp->n_busses == 0);
	mctp->busses = __mctp_alloc(2 * sizeof(struct mctp_bus));
	if (!mctp->busses)
		return -ENOMEM;
	memset(mctp->busses, 0, 2 * sizeof(struct mctp_bus));
	mctp->n_busses = 2;
	mctp->busses[0].binding = b1;
	b1->bus = &mctp->busses[0];
	b1->mctp = mctp;
	mctp->busses[1].binding = b2;
	b2->bus = &mctp->busses[1];
	b2->mctp = mctp;

	mctp->route_policy = ROUTE_BRIDGE;

	if (b1->start) {
		rc = b1->start(b1);
		if (rc < 0) {
			mctp_prerr("Failed to start bridged bus %s: %d",
				   b1->name, rc);
			goto done;
		}
	}

	if (b2->start) {
		rc = b2->start(b2);
		if (rc < 0) {
			mctp_prerr("Failed to start bridged bus %s: %d",
				   b2->name, rc);
			goto done;
		}
	}

done:
	return rc;
}

static inline bool mctp_ctrl_cmd_is_transport(struct mctp_ctrl_msg_hdr *hdr)
{
	return ((hdr->command_code >= MCTP_CTRL_CMD_FIRST_TRANSPORT) &&
		(hdr->command_code <= MCTP_CTRL_CMD_LAST_TRANSPORT));
}

static bool mctp_ctrl_handle_msg(struct mctp_bus *bus, mctp_eid_t src,
				 uint8_t msg_tag, bool tag_owner, void *buffer,
				 size_t length)
{
	struct mctp_ctrl_msg_hdr *msg_hdr = buffer;

	/*
	 * Control message is received. If a transport control message handler
	 * is provided, it will called. If there is no dedicated handler, this
	 * function returns false and data can be handled by the generic
	 * message handler. The transport control message handler will be
	 * provided with messages in the command range 0xF0 - 0xFF.
	 */
	if (mctp_ctrl_cmd_is_transport(msg_hdr)) {
		if (bus->binding->control_rx != NULL) {
			/* MCTP bus binding handler */
			bus->binding->control_rx(src, msg_tag, tag_owner,
						 bus->binding->control_rx_data,
						 buffer, length);
			return true;
		}
	}

	/*
	 * Command was not handled, due to lack of specific callback.
	 * It will be passed to regular message_rx handler.
	 */
	return false;
}

static inline bool mctp_rx_dest_is_local(struct mctp_bus *bus, mctp_eid_t dest)
{
	return dest == bus->eid || dest == MCTP_EID_NULL ||
	       dest == MCTP_EID_BROADCAST;
}

static inline bool mctp_ctrl_cmd_is_request(struct mctp_ctrl_msg_hdr *hdr)
{
	return hdr->ic_msg_type == MCTP_CTRL_HDR_MSG_TYPE &&
	       hdr->rq_dgram_inst & MCTP_CTRL_HDR_FLAG_REQUEST;
}

/*
 * Receive the complete MCTP message and route it.
 * Asserts:
 *     'buf' is not NULL.
 */
static void mctp_rx(struct mctp *mctp, struct mctp_bus *bus, mctp_eid_t src,
		    mctp_eid_t dest, bool tag_owner, uint8_t msg_tag, void *buf,
		    size_t len)
{
	assert(buf != NULL);

	if (mctp->route_policy == ROUTE_ENDPOINT &&
	    mctp_rx_dest_is_local(bus, dest)) {
		/* Handle MCTP Control Messages: */
		if (len >= sizeof(struct mctp_ctrl_msg_hdr)) {
			struct mctp_ctrl_msg_hdr *msg_hdr = buf;

			/*
			 * Identify if this is a control request message.
			 * See DSP0236 v1.3.0 sec. 11.5.
			 */
			if (mctp_ctrl_cmd_is_request(msg_hdr)) {
				bool handled;
				handled = mctp_ctrl_handle_msg(
					bus, src, msg_tag, tag_owner, buf, len);
				if (handled)
					return;
			}
		}

		if (mctp->message_rx)
			mctp->message_rx(src, tag_owner, msg_tag,
					 mctp->message_rx_data, buf, len);
	}

	if (mctp->route_policy == ROUTE_BRIDGE) {
		int i;

		for (i = 0; i < mctp->n_busses; i++) {
			struct mctp_bus *dest_bus = &mctp->busses[i];
			if (dest_bus == bus)
				continue;

			mctp_message_tx_on_bus(dest_bus, src, dest, tag_owner,
					       msg_tag, buf, len);
		}
	}
}

void mctp_bus_rx(struct mctp_binding *binding, struct mctp_pktbuf *pkt)
{
	struct mctp_bus *bus = binding->bus;
	struct mctp *mctp = binding->mctp;
	uint8_t flags, exp_seq, seq, tag;
	struct mctp_msg_ctx *ctx;
	struct mctp_hdr *hdr;
	bool tag_owner;
	size_t len;
	void *p;
	int rc;

	assert(bus);

	/* Drop packet if it was smaller than mctp hdr size */
	if (mctp_pktbuf_size(pkt) <= sizeof(struct mctp_hdr))
		goto out;

	if (mctp->capture)
		mctp->capture(pkt, MCTP_MESSAGE_CAPTURE_INCOMING,
			      mctp->capture_data);

	hdr = mctp_pktbuf_hdr(pkt);

	/* small optimisation: don't bother reassembly if we're going to
	 * drop the packet in mctp_rx anyway */
	if (mctp->route_policy == ROUTE_ENDPOINT && hdr->dest != bus->eid)
		goto out;

	flags = hdr->flags_seq_tag & (MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM);
	tag = (hdr->flags_seq_tag >> MCTP_HDR_TAG_SHIFT) & MCTP_HDR_TAG_MASK;
	seq = (hdr->flags_seq_tag >> MCTP_HDR_SEQ_SHIFT) & MCTP_HDR_SEQ_MASK;
	tag_owner = (hdr->flags_seq_tag >> MCTP_HDR_TO_SHIFT) &
		    MCTP_HDR_TO_MASK;

	switch (flags) {
	case MCTP_HDR_FLAG_SOM | MCTP_HDR_FLAG_EOM:
		/* single-packet message - send straight up to rx function,
		 * no need to create a message context */
		len = pkt->end - pkt->mctp_hdr_off - sizeof(struct mctp_hdr);
		p = pkt->data + pkt->mctp_hdr_off + sizeof(struct mctp_hdr);
		mctp_rx(mctp, bus, hdr->src, hdr->dest, tag_owner, tag, p, len);
		break;

	case MCTP_HDR_FLAG_SOM:
		/* start of a new message - start the new context for
		 * future message reception. If an existing context is
		 * already present, drop it. */
		ctx = mctp_msg_ctx_lookup(mctp, hdr->src, hdr->dest, tag);
		if (ctx) {
			mctp_msg_ctx_reset(ctx);
		} else {
			ctx = mctp_msg_ctx_create(mctp, hdr->src, hdr->dest,
						  tag);
			/* If context creation fails due to exhaution of contexts we
			* can support, drop the packet */
			if (!ctx) {
				mctp_prdebug("Context buffers exhausted.");
				goto out;
			}
		}

		/* Save the fragment size, subsequent middle fragments
		 * should of the same size */
		ctx->fragment_size = mctp_pktbuf_size(pkt);

		rc = mctp_msg_ctx_add_pkt(ctx, pkt, mctp->max_message_size);
		if (rc) {
			mctp_msg_ctx_drop(ctx);
		} else {
			ctx->last_seq = seq;
		}

		break;

	case MCTP_HDR_FLAG_EOM:
		ctx = mctp_msg_ctx_lookup(mctp, hdr->src, hdr->dest, tag);
		if (!ctx)
			goto out;

		exp_seq = (ctx->last_seq + 1) % 4;

		if (exp_seq != seq) {
			mctp_prdebug(
				"Sequence number %d does not match expected %d",
				seq, exp_seq);
			mctp_msg_ctx_drop(ctx);
			goto out;
		}

		len = mctp_pktbuf_size(pkt);

		if (len > ctx->fragment_size) {
			mctp_prdebug("Unexpected fragment size. Expected"
				     " less than %zu, received = %zu",
				     ctx->fragment_size, len);
			mctp_msg_ctx_drop(ctx);
			goto out;
		}

		rc = mctp_msg_ctx_add_pkt(ctx, pkt, mctp->max_message_size);
		if (!rc)
			mctp_rx(mctp, bus, ctx->src, ctx->dest, tag_owner, tag,
				ctx->buf, ctx->buf_size);

		mctp_msg_ctx_drop(ctx);
		break;

	case 0:
		/* Neither SOM nor EOM */
		ctx = mctp_msg_ctx_lookup(mctp, hdr->src, hdr->dest, tag);
		if (!ctx)
			goto out;

		exp_seq = (ctx->last_seq + 1) % 4;
		if (exp_seq != seq) {
			mctp_prdebug(
				"Sequence number %d does not match expected %d",
				seq, exp_seq);
			mctp_msg_ctx_drop(ctx);
			goto out;
		}

		len = mctp_pktbuf_size(pkt);

		if (len != ctx->fragment_size) {
			mctp_prdebug("Unexpected fragment size. Expected = %zu "
				     "received = %zu",
				     ctx->fragment_size, len);
			mctp_msg_ctx_drop(ctx);
			goto out;
		}

		rc = mctp_msg_ctx_add_pkt(ctx, pkt, mctp->max_message_size);
		if (rc) {
			mctp_msg_ctx_drop(ctx);
			goto out;
		}
		ctx->last_seq = seq;

		break;
	}
out:
	mctp_pktbuf_free(pkt);
}

static int mctp_packet_tx(struct mctp_bus *bus, struct mctp_pktbuf *pkt)
{
	struct mctp *mctp = bus->binding->mctp;

	if (bus->state != mctp_bus_state_tx_enabled)
		return -1;

	if (mctp->capture)
		mctp->capture(pkt, MCTP_MESSAGE_CAPTURE_OUTGOING,
			      mctp->capture_data);

	return bus->binding->tx(bus->binding, pkt);
}

static void mctp_send_tx_queue(struct mctp_bus *bus)
{
	struct mctp_pktbuf *pkt;

	while ((pkt = bus->tx_queue_head)) {
		int rc;

		rc = mctp_packet_tx(bus, pkt);
		switch (rc) {
		/* If transmission succeded, or */
		case 0:
		/* If the packet is somehow too large */
		case -EMSGSIZE:
			/* Drop the packet */
			bus->tx_queue_head = pkt->next;
			mctp_pktbuf_free(pkt);
			break;

		/* If the binding was busy, or */
		case -EBUSY:
		/* Some other unknown error occurred */
		default:
			/* Make sure the tail pointer is consistent and retry later */
			goto cleanup_tail;
		};
	}

cleanup_tail:
	if (!bus->tx_queue_head)
		bus->tx_queue_tail = NULL;
}

void mctp_binding_set_tx_enabled(struct mctp_binding *binding, bool enable)
{
	struct mctp_bus *bus = binding->bus;

	switch (bus->state) {
	case mctp_bus_state_constructed:
		if (!enable)
			return;

		if (binding->pkt_size < MCTP_PACKET_SIZE(MCTP_BTU)) {
			mctp_prerr(
				"Cannot start %s binding with invalid MTU: %zu",
				binding->name,
				MCTP_BODY_SIZE(binding->pkt_size));
			return;
		}

		bus->state = mctp_bus_state_tx_enabled;
		mctp_prinfo("%s binding started", binding->name);
		return;
	case mctp_bus_state_tx_enabled:
		if (enable)
			return;

		bus->state = mctp_bus_state_tx_disabled;
		mctp_prdebug("%s binding Tx disabled", binding->name);
		return;
	case mctp_bus_state_tx_disabled:
		if (!enable)
			return;

		bus->state = mctp_bus_state_tx_enabled;
		mctp_prdebug("%s binding Tx enabled", binding->name);
		mctp_send_tx_queue(bus);
		return;
	}
}

enum mctp_bus_state mctp_bus_get_state(struct mctp_bus *bus)
{
	return bus->state;
}

static int mctp_message_tx_on_bus(struct mctp_bus *bus, mctp_eid_t src,
				  mctp_eid_t dest, bool tag_owner,
				  uint8_t msg_tag, void *msg, size_t msg_len)
{
	size_t max_payload_len, payload_len, p;
	struct mctp_pktbuf *pkt;
	struct mctp_hdr *hdr;
	int i;

	if (bus->state == mctp_bus_state_constructed)
		return -ENXIO;

	if ((msg_tag & MCTP_HDR_TAG_MASK) != msg_tag)
		return -EINVAL;

	max_payload_len = MCTP_BODY_SIZE(bus->binding->pkt_size);

	{
		const bool valid_mtu = max_payload_len >= MCTP_BTU;
		assert(valid_mtu);
		if (!valid_mtu)
			return -EINVAL;
	}

	mctp_prdebug(
		"%s: Generating packets for transmission of %zu byte message from %hhu to %hhu",
		__func__, msg_len, src, dest);

	/* queue up packets, each of max MCTP_MTU size */
	for (p = 0, i = 0; p < msg_len; i++) {
		payload_len = msg_len - p;
		if (payload_len > max_payload_len)
			payload_len = max_payload_len;

		pkt = mctp_pktbuf_alloc(bus->binding,
					payload_len + sizeof(*hdr));
		hdr = mctp_pktbuf_hdr(pkt);

		hdr->ver = bus->binding->version & 0xf;
		hdr->dest = dest;
		hdr->src = src;
		hdr->flags_seq_tag = (tag_owner << MCTP_HDR_TO_SHIFT) |
				     (msg_tag << MCTP_HDR_TAG_SHIFT);

		if (i == 0)
			hdr->flags_seq_tag |= MCTP_HDR_FLAG_SOM;
		if (p + payload_len >= msg_len)
			hdr->flags_seq_tag |= MCTP_HDR_FLAG_EOM;
		hdr->flags_seq_tag |= (i & MCTP_HDR_SEQ_MASK)
				      << MCTP_HDR_SEQ_SHIFT;

		memcpy(mctp_pktbuf_data(pkt), (uint8_t *)msg + p, payload_len);

		/* add to tx queue */
		if (bus->tx_queue_tail)
			bus->tx_queue_tail->next = pkt;
		else
			bus->tx_queue_head = pkt;
		bus->tx_queue_tail = pkt;

		p += payload_len;
	}

	mctp_prdebug("%s: Enqueued %d packets", __func__, i);

	mctp_send_tx_queue(bus);

	return 0;
}

int mctp_message_tx(struct mctp *mctp, mctp_eid_t eid, bool tag_owner,
		    uint8_t msg_tag, void *msg, size_t msg_len)
{
	struct mctp_bus *bus;

	/* TODO: Protect against same tag being used across
	 * different callers */
	if ((msg_tag & MCTP_HDR_TAG_MASK) != msg_tag) {
		mctp_prerr("Incorrect message tag %u passed.", msg_tag);
		return -EINVAL;
	}

	bus = find_bus_for_eid(mctp, eid);
	if (!bus)
		return 0;

	return mctp_message_tx_on_bus(bus, bus->eid, eid, tag_owner, msg_tag,
				      msg, msg_len);
}
