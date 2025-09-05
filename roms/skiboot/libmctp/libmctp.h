/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#ifndef _LIBMCTP_H
#define _LIBMCTP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

typedef uint8_t mctp_eid_t;

/* Special Endpoint ID values */
#define MCTP_EID_NULL	   0
#define MCTP_EID_BROADCAST 0xff

/* MCTP packet definitions */
struct mctp_hdr {
	uint8_t ver;
	uint8_t dest;
	uint8_t src;
	uint8_t flags_seq_tag;
};

/* Definitions for flags_seq_tag field */
#define MCTP_HDR_FLAG_SOM  (1 << 7)
#define MCTP_HDR_FLAG_EOM  (1 << 6)
#define MCTP_HDR_FLAG_TO   (1 << 3)
#define MCTP_HDR_TO_SHIFT  (3)
#define MCTP_HDR_TO_MASK   (1)
#define MCTP_HDR_SEQ_SHIFT (4)
#define MCTP_HDR_SEQ_MASK  (0x3)
#define MCTP_HDR_TAG_SHIFT (0)
#define MCTP_HDR_TAG_MASK  (0x7)

#define MCTP_MESSAGE_TO_SRC	      true
#define MCTP_MESSAGE_TO_DST	      false
#define MCTP_MESSAGE_CAPTURE_OUTGOING true
#define MCTP_MESSAGE_CAPTURE_INCOMING false

/* Baseline Transmission Unit and packet size */
#define MCTP_BTU	       64
#define MCTP_PACKET_SIZE(unit) ((unit) + sizeof(struct mctp_hdr))
#define MCTP_BODY_SIZE(unit)   ((unit) - sizeof(struct mctp_hdr))

/* packet buffers */

struct mctp_pktbuf {
	size_t start, end, size;
	size_t mctp_hdr_off;
	struct mctp_pktbuf *next;
	unsigned char data[];
};

struct mctp_binding;

struct mctp_pktbuf *mctp_pktbuf_alloc(struct mctp_binding *hw, size_t len);
void mctp_pktbuf_free(struct mctp_pktbuf *pkt);
struct mctp_hdr *mctp_pktbuf_hdr(struct mctp_pktbuf *pkt);
void *mctp_pktbuf_data(struct mctp_pktbuf *pkt);
size_t mctp_pktbuf_size(struct mctp_pktbuf *pkt);
void *mctp_pktbuf_alloc_start(struct mctp_pktbuf *pkt, size_t size);
void *mctp_pktbuf_alloc_end(struct mctp_pktbuf *pkt, size_t size);
int mctp_pktbuf_push(struct mctp_pktbuf *pkt, void *data, size_t len);
void *mctp_pktbuf_pop(struct mctp_pktbuf *pkt, size_t len);

/* MCTP core */
struct mctp;
struct mctp_bus;

struct mctp *mctp_init(void);
void mctp_set_max_message_size(struct mctp *mctp, size_t message_size);
typedef void (*mctp_capture_fn)(struct mctp_pktbuf *pkt, bool outgoing,
				void *user);
void mctp_set_capture_handler(struct mctp *mctp, mctp_capture_fn fn,
			      void *user);
void mctp_destroy(struct mctp *mctp);

/* Register a binding to the MCTP core, and creates a bus (populating
 * binding->bus).
 *
 * If this function is called, the MCTP stack is initialised as an 'endpoint',
 * and will deliver local packets to a RX callback - see `mctp_set_rx_all()`
 * below.
 */
int mctp_register_bus(struct mctp *mctp, struct mctp_binding *binding,
		      mctp_eid_t eid);

void mctp_unregister_bus(struct mctp *mctp, struct mctp_binding *binding);

/* Create a simple bidirectional bridge between busses.
 *
 * In this mode, the MCTP stack is initialised as a bridge. There is no EID
 * defined, so no packets are considered local. Instead, all messages from one
 * binding are forwarded to the other.
 */
int mctp_bridge_busses(struct mctp *mctp, struct mctp_binding *b1,
		       struct mctp_binding *b2);

typedef void (*mctp_rx_fn)(uint8_t src_eid, bool tag_owner, uint8_t msg_tag,
			   void *data, void *msg, size_t len);

int mctp_set_rx_all(struct mctp *mctp, mctp_rx_fn fn, void *data);

int mctp_message_tx(struct mctp *mctp, mctp_eid_t eid, bool tag_owner,
		    uint8_t msg_tag, void *msg, size_t msg_len);

/* hardware bindings */

/**
 * @tx: Binding function to transmit one packet on the interface
 *      Return:
 *      * 0 - Success, pktbuf can be released
 *	* -EMSGSIZE - Packet exceeds binding MTU, pktbuf must be dropped
 *	* -EBUSY - Packet unable to be transmitted, pktbuf must be retained
 */
struct mctp_binding {
	const char *name;
	uint8_t version;
	struct mctp_bus *bus;
	struct mctp *mctp;
	size_t pkt_size;
	size_t pkt_header;
	size_t pkt_trailer;
	int (*start)(struct mctp_binding *binding);
	int (*tx)(struct mctp_binding *binding, struct mctp_pktbuf *pkt);
	mctp_rx_fn control_rx;
	void *control_rx_data;
};

enum mctp_bus_state {
        mctp_bus_state_constructed = 0,
        mctp_bus_state_tx_enabled,
        mctp_bus_state_tx_disabled,
};

void mctp_binding_set_tx_enabled(struct mctp_binding *binding, bool enable);


enum mctp_bus_state mctp_bus_get_state(struct mctp_bus *bus);

/*
 * Receive a packet from binding to core. Takes ownership of pkt, free()-ing it
 * after use.
 */
void mctp_bus_rx(struct mctp_binding *binding, struct mctp_pktbuf *pkt);

/* environment-specific allocation */
void mctp_set_alloc_ops(void *(*alloc)(size_t), void (*free)(void *),
			void *(realloc)(void *, size_t));

/* environment-specific logging */

void mctp_set_log_stdio(int level);
void mctp_set_log_syslog(void);
void mctp_set_log_custom(void (*fn)(int, const char *, va_list));

/* these should match the syslog-standard LOG_* definitions, for
 * easier use with syslog */
#define MCTP_LOG_ERR	 3
#define MCTP_LOG_WARNING 4
#define MCTP_LOG_NOTICE	 5
#define MCTP_LOG_INFO	 6
#define MCTP_LOG_DEBUG	 7

#ifdef __cplusplus
}
#endif

#endif /* _LIBMCTP_H */
