#ifndef _VIRTIO_NET_H_
# define _VIRTIO_NET_H_

/* The feature bitmap for virtio net */
#define VIRTIO_NET_F_CSUM       0       /* Host handles pkts w/ partial csum */
#define VIRTIO_NET_F_GUEST_CSUM 1       /* Guest handles pkts w/ partial csum */
#define VIRTIO_NET_F_MTU        3       /* Initial MTU advice */
#define VIRTIO_NET_F_MAC        5       /* Host has given MAC address. */
#define VIRTIO_NET_F_GSO        6       /* Host handles pkts w/ any GSO type */
#define VIRTIO_NET_F_GUEST_TSO4 7       /* Guest can handle TSOv4 in. */
#define VIRTIO_NET_F_GUEST_TSO6 8       /* Guest can handle TSOv6 in. */
#define VIRTIO_NET_F_GUEST_ECN  9       /* Guest can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_GUEST_UFO  10      /* Guest can handle UFO in. */
#define VIRTIO_NET_F_HOST_TSO4  11      /* Host can handle TSOv4 in. */
#define VIRTIO_NET_F_HOST_TSO6  12      /* Host can handle TSOv6 in. */
#define VIRTIO_NET_F_HOST_ECN   13      /* Host can handle TSO[6] w/ ECN in. */
#define VIRTIO_NET_F_HOST_UFO   14      /* Host can handle UFO in. */
#define VIRTIO_NET_F_MRG_RXBUF  15      /* Driver can merge receive buffers. */
#define VIRTIO_NET_F_STATUS     16      /* Configuration status field is available. */
#define VIRTIO_NET_F_CTRL_VQ    17      /* Control channel is available. */
#define VIRTIO_NET_F_CTRL_RX    18      /* Control channel RX mode support. */
#define VIRTIO_NET_F_CTRL_VLAN  19      /* Control channel VLAN filtering. */
#define VIRTIO_NET_F_GUEST_ANNOUNCE 21  /* Driver can send gratuitous packets. */

struct virtio_net_config
{
   /* The config defining mac address (if VIRTIO_NET_F_MAC) */
   u8 mac[6];
   /* See VIRTIO_NET_F_STATUS and VIRTIO_NET_S_* above */
   u16 status;
   /* Maximum number of each of transmit and receive queues;
    * see VIRTIO_NET_F_MQ and VIRTIO_NET_CTRL_MQ.
    * Legal values are between 1 and 0x8000
    */
   u16 max_virtqueue_pairs;
   /* Default maximum transmit unit advice */
   u16 mtu;
} __attribute__((packed));

/* This is the first element of the scatter-gather list.  If you don't
 * specify GSO or CSUM features, you can simply ignore the header. */

struct virtio_net_hdr
{
#define VIRTIO_NET_HDR_F_NEEDS_CSUM     1       // Use csum_start, csum_offset
   uint8_t flags;
#define VIRTIO_NET_HDR_GSO_NONE         0       // Not a GSO frame
#define VIRTIO_NET_HDR_GSO_TCPV4        1       // GSO frame, IPv4 TCP (TSO)
/* FIXME: Do we need this?  If they said they can handle ECN, do they care? */
#define VIRTIO_NET_HDR_GSO_TCPV4_ECN    2       // GSO frame, IPv4 TCP w/ ECN
#define VIRTIO_NET_HDR_GSO_UDP          3       // GSO frame, IPv4 UDP (UFO)
#define VIRTIO_NET_HDR_GSO_TCPV6        4       // GSO frame, IPv6 TCP
#define VIRTIO_NET_HDR_GSO_ECN          0x80    // TCP has ECN set
   uint8_t gso_type;
   uint16_t hdr_len;
   uint16_t gso_size;
   uint16_t csum_start;
   uint16_t csum_offset;
};

/* Virtio 1.0 version of the first element of the scatter-gather list. */
struct virtio_net_hdr_modern
{
   struct virtio_net_hdr legacy;

   /* Used only if VIRTIO_NET_F_MRG_RXBUF: */
   uint16_t num_buffers;
};

#endif /* _VIRTIO_NET_H_ */
