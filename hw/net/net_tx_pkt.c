/*
 * QEMU TX packets abstractions
 *
 * Copyright (c) 2012 Ravello Systems LTD (http://ravellosystems.com)
 *
 * Developed by Daynix Computing LTD (http://www.daynix.com)
 *
 * Authors:
 * Dmitry Fleytman <dmitry@daynix.com>
 * Tamir Shomer <tamirs@daynix.com>
 * Yan Vugenfirer <yan@daynix.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"
#include "net_tx_pkt.h"
#include "net/eth.h"
#include "net/checksum.h"
#include "net/tap.h"
#include "net/net.h"
#include "hw/pci/pci.h"

enum {
    NET_TX_PKT_VHDR_FRAG = 0,
    NET_TX_PKT_L2HDR_FRAG,
    NET_TX_PKT_L3HDR_FRAG,
    NET_TX_PKT_PL_START_FRAG
};

/* TX packet private context */
struct NetTxPkt {
    PCIDevice *pci_dev;

    struct virtio_net_hdr virt_hdr;
    bool has_virt_hdr;

    struct iovec *raw;
    uint32_t raw_frags;
    uint32_t max_raw_frags;

    struct iovec *vec;

    uint8_t l2_hdr[ETH_MAX_L2_HDR_LEN];
    uint8_t l3_hdr[ETH_MAX_IP_DGRAM_LEN];

    uint32_t payload_len;

    uint32_t payload_frags;
    uint32_t max_payload_frags;

    uint16_t hdr_len;
    eth_pkt_types_e packet_type;
    uint8_t l4proto;

    bool is_loopback;
};

void net_tx_pkt_init(struct NetTxPkt **pkt, PCIDevice *pci_dev,
    uint32_t max_frags, bool has_virt_hdr)
{
    struct NetTxPkt *p = g_malloc0(sizeof *p);

    p->pci_dev = pci_dev;

    p->vec = g_new(struct iovec, max_frags + NET_TX_PKT_PL_START_FRAG);

    p->raw = g_new(struct iovec, max_frags);

    p->max_payload_frags = max_frags;
    p->max_raw_frags = max_frags;
    p->has_virt_hdr = has_virt_hdr;
    p->vec[NET_TX_PKT_VHDR_FRAG].iov_base = &p->virt_hdr;
    p->vec[NET_TX_PKT_VHDR_FRAG].iov_len =
        p->has_virt_hdr ? sizeof p->virt_hdr : 0;
    p->vec[NET_TX_PKT_L2HDR_FRAG].iov_base = &p->l2_hdr;
    p->vec[NET_TX_PKT_L3HDR_FRAG].iov_base = &p->l3_hdr;

    *pkt = p;
}

void net_tx_pkt_uninit(struct NetTxPkt *pkt)
{
    if (pkt) {
        g_free(pkt->vec);
        g_free(pkt->raw);
        g_free(pkt);
    }
}

void net_tx_pkt_update_ip_hdr_checksum(struct NetTxPkt *pkt)
{
    uint16_t csum;
    assert(pkt);
    struct ip_header *ip_hdr;
    ip_hdr = pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_base;

    ip_hdr->ip_len = cpu_to_be16(pkt->payload_len +
        pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_len);

    ip_hdr->ip_sum = 0;
    csum = net_raw_checksum((uint8_t *)ip_hdr,
        pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_len);
    ip_hdr->ip_sum = cpu_to_be16(csum);
}

void net_tx_pkt_update_ip_checksums(struct NetTxPkt *pkt)
{
    uint16_t csum;
    uint32_t cntr, cso;
    assert(pkt);
    uint8_t gso_type = pkt->virt_hdr.gso_type & ~VIRTIO_NET_HDR_GSO_ECN;
    void *ip_hdr = pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_base;

    if (pkt->payload_len + pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_len >
        ETH_MAX_IP_DGRAM_LEN) {
        return;
    }

    if (gso_type == VIRTIO_NET_HDR_GSO_TCPV4 ||
        gso_type == VIRTIO_NET_HDR_GSO_UDP) {
        /* Calculate IP header checksum */
        net_tx_pkt_update_ip_hdr_checksum(pkt);

        /* Calculate IP pseudo header checksum */
        cntr = eth_calc_ip4_pseudo_hdr_csum(ip_hdr, pkt->payload_len, &cso);
        csum = cpu_to_be16(~net_checksum_finish(cntr));
    } else if (gso_type == VIRTIO_NET_HDR_GSO_TCPV6) {
        /* Calculate IP pseudo header checksum */
        cntr = eth_calc_ip6_pseudo_hdr_csum(ip_hdr, pkt->payload_len,
                                            IP_PROTO_TCP, &cso);
        csum = cpu_to_be16(~net_checksum_finish(cntr));
    } else {
        return;
    }

    iov_from_buf(&pkt->vec[NET_TX_PKT_PL_START_FRAG], pkt->payload_frags,
                 pkt->virt_hdr.csum_offset, &csum, sizeof(csum));
}

static void net_tx_pkt_calculate_hdr_len(struct NetTxPkt *pkt)
{
    pkt->hdr_len = pkt->vec[NET_TX_PKT_L2HDR_FRAG].iov_len +
        pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_len;
}

static bool net_tx_pkt_parse_headers(struct NetTxPkt *pkt)
{
    struct iovec *l2_hdr, *l3_hdr;
    size_t bytes_read;
    size_t full_ip6hdr_len;
    uint16_t l3_proto;

    assert(pkt);

    l2_hdr = &pkt->vec[NET_TX_PKT_L2HDR_FRAG];
    l3_hdr = &pkt->vec[NET_TX_PKT_L3HDR_FRAG];

    bytes_read = iov_to_buf(pkt->raw, pkt->raw_frags, 0, l2_hdr->iov_base,
                            ETH_MAX_L2_HDR_LEN);
    if (bytes_read < sizeof(struct eth_header)) {
        l2_hdr->iov_len = 0;
        return false;
    }

    l2_hdr->iov_len = sizeof(struct eth_header);
    switch (be16_to_cpu(PKT_GET_ETH_HDR(l2_hdr->iov_base)->h_proto)) {
    case ETH_P_VLAN:
        l2_hdr->iov_len += sizeof(struct vlan_header);
        break;
    case ETH_P_DVLAN:
        l2_hdr->iov_len += 2 * sizeof(struct vlan_header);
        break;
    }

    if (bytes_read < l2_hdr->iov_len) {
        l2_hdr->iov_len = 0;
        l3_hdr->iov_len = 0;
        pkt->packet_type = ETH_PKT_UCAST;
        return false;
    } else {
        l2_hdr->iov_len = ETH_MAX_L2_HDR_LEN;
        l2_hdr->iov_len = eth_get_l2_hdr_length(l2_hdr->iov_base);
        pkt->packet_type = get_eth_packet_type(l2_hdr->iov_base);
    }

    l3_proto = eth_get_l3_proto(l2_hdr, 1, l2_hdr->iov_len);

    switch (l3_proto) {
    case ETH_P_IP:
        bytes_read = iov_to_buf(pkt->raw, pkt->raw_frags, l2_hdr->iov_len,
                                l3_hdr->iov_base, sizeof(struct ip_header));

        if (bytes_read < sizeof(struct ip_header)) {
            l3_hdr->iov_len = 0;
            return false;
        }

        l3_hdr->iov_len = IP_HDR_GET_LEN(l3_hdr->iov_base);

        if (l3_hdr->iov_len < sizeof(struct ip_header)) {
            l3_hdr->iov_len = 0;
            return false;
        }

        pkt->l4proto = IP_HDR_GET_P(l3_hdr->iov_base);

        if (IP_HDR_GET_LEN(l3_hdr->iov_base) != sizeof(struct ip_header)) {
            /* copy optional IPv4 header data if any*/
            bytes_read = iov_to_buf(pkt->raw, pkt->raw_frags,
                                    l2_hdr->iov_len + sizeof(struct ip_header),
                                    l3_hdr->iov_base + sizeof(struct ip_header),
                                    l3_hdr->iov_len - sizeof(struct ip_header));
            if (bytes_read < l3_hdr->iov_len - sizeof(struct ip_header)) {
                l3_hdr->iov_len = 0;
                return false;
            }
        }

        break;

    case ETH_P_IPV6:
    {
        eth_ip6_hdr_info hdrinfo;

        if (!eth_parse_ipv6_hdr(pkt->raw, pkt->raw_frags, l2_hdr->iov_len,
                                &hdrinfo)) {
            l3_hdr->iov_len = 0;
            return false;
        }

        pkt->l4proto = hdrinfo.l4proto;
        full_ip6hdr_len = hdrinfo.full_hdr_len;

        if (full_ip6hdr_len > ETH_MAX_IP_DGRAM_LEN) {
            l3_hdr->iov_len = 0;
            return false;
        }

        bytes_read = iov_to_buf(pkt->raw, pkt->raw_frags, l2_hdr->iov_len,
                                l3_hdr->iov_base, full_ip6hdr_len);

        if (bytes_read < full_ip6hdr_len) {
            l3_hdr->iov_len = 0;
            return false;
        } else {
            l3_hdr->iov_len = full_ip6hdr_len;
        }
        break;
    }
    default:
        l3_hdr->iov_len = 0;
        break;
    }

    net_tx_pkt_calculate_hdr_len(pkt);
    return true;
}

static void net_tx_pkt_rebuild_payload(struct NetTxPkt *pkt)
{
    pkt->payload_len = iov_size(pkt->raw, pkt->raw_frags) - pkt->hdr_len;
    pkt->payload_frags = iov_copy(&pkt->vec[NET_TX_PKT_PL_START_FRAG],
                                pkt->max_payload_frags,
                                pkt->raw, pkt->raw_frags,
                                pkt->hdr_len, pkt->payload_len);
}

bool net_tx_pkt_parse(struct NetTxPkt *pkt)
{
    if (net_tx_pkt_parse_headers(pkt)) {
        net_tx_pkt_rebuild_payload(pkt);
        return true;
    } else {
        return false;
    }
}

struct virtio_net_hdr *net_tx_pkt_get_vhdr(struct NetTxPkt *pkt)
{
    assert(pkt);
    return &pkt->virt_hdr;
}

static uint8_t net_tx_pkt_get_gso_type(struct NetTxPkt *pkt,
                                          bool tso_enable)
{
    uint8_t rc = VIRTIO_NET_HDR_GSO_NONE;
    uint16_t l3_proto;

    l3_proto = eth_get_l3_proto(&pkt->vec[NET_TX_PKT_L2HDR_FRAG], 1,
        pkt->vec[NET_TX_PKT_L2HDR_FRAG].iov_len);

    if (!tso_enable) {
        goto func_exit;
    }

    rc = eth_get_gso_type(l3_proto, pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_base,
                          pkt->l4proto);

func_exit:
    return rc;
}

void net_tx_pkt_build_vheader(struct NetTxPkt *pkt, bool tso_enable,
    bool csum_enable, uint32_t gso_size)
{
    struct tcp_hdr l4hdr;
    assert(pkt);

    /* csum has to be enabled if tso is. */
    assert(csum_enable || !tso_enable);

    pkt->virt_hdr.gso_type = net_tx_pkt_get_gso_type(pkt, tso_enable);

    switch (pkt->virt_hdr.gso_type & ~VIRTIO_NET_HDR_GSO_ECN) {
    case VIRTIO_NET_HDR_GSO_NONE:
        pkt->virt_hdr.hdr_len = 0;
        pkt->virt_hdr.gso_size = 0;
        break;

    case VIRTIO_NET_HDR_GSO_UDP:
        pkt->virt_hdr.gso_size = gso_size;
        pkt->virt_hdr.hdr_len = pkt->hdr_len + sizeof(struct udp_header);
        break;

    case VIRTIO_NET_HDR_GSO_TCPV4:
    case VIRTIO_NET_HDR_GSO_TCPV6:
        iov_to_buf(&pkt->vec[NET_TX_PKT_PL_START_FRAG], pkt->payload_frags,
                   0, &l4hdr, sizeof(l4hdr));
        pkt->virt_hdr.hdr_len = pkt->hdr_len + l4hdr.th_off * sizeof(uint32_t);
        pkt->virt_hdr.gso_size = gso_size;
        break;

    default:
        g_assert_not_reached();
    }

    if (csum_enable) {
        switch (pkt->l4proto) {
        case IP_PROTO_TCP:
            pkt->virt_hdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
            pkt->virt_hdr.csum_start = pkt->hdr_len;
            pkt->virt_hdr.csum_offset = offsetof(struct tcp_hdr, th_sum);
            break;
        case IP_PROTO_UDP:
            pkt->virt_hdr.flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
            pkt->virt_hdr.csum_start = pkt->hdr_len;
            pkt->virt_hdr.csum_offset = offsetof(struct udp_hdr, uh_sum);
            break;
        default:
            break;
        }
    }
}

void net_tx_pkt_setup_vlan_header_ex(struct NetTxPkt *pkt,
    uint16_t vlan, uint16_t vlan_ethtype)
{
    bool is_new;
    assert(pkt);

    eth_setup_vlan_headers_ex(pkt->vec[NET_TX_PKT_L2HDR_FRAG].iov_base,
        vlan, vlan_ethtype, &is_new);

    /* update l2hdrlen */
    if (is_new) {
        pkt->hdr_len += sizeof(struct vlan_header);
        pkt->vec[NET_TX_PKT_L2HDR_FRAG].iov_len +=
            sizeof(struct vlan_header);
    }
}

bool net_tx_pkt_add_raw_fragment(struct NetTxPkt *pkt, hwaddr pa,
    size_t len)
{
    hwaddr mapped_len = 0;
    struct iovec *ventry;
    assert(pkt);

    if (pkt->raw_frags >= pkt->max_raw_frags) {
        return false;
    }

    if (!len) {
        return true;
     }

    ventry = &pkt->raw[pkt->raw_frags];
    mapped_len = len;

    ventry->iov_base = pci_dma_map(pkt->pci_dev, pa,
                                   &mapped_len, DMA_DIRECTION_TO_DEVICE);

    if ((ventry->iov_base != NULL) && (len == mapped_len)) {
        ventry->iov_len = mapped_len;
        pkt->raw_frags++;
        return true;
    } else {
        return false;
    }
}

bool net_tx_pkt_has_fragments(struct NetTxPkt *pkt)
{
    return pkt->raw_frags > 0;
}

eth_pkt_types_e net_tx_pkt_get_packet_type(struct NetTxPkt *pkt)
{
    assert(pkt);

    return pkt->packet_type;
}

size_t net_tx_pkt_get_total_len(struct NetTxPkt *pkt)
{
    assert(pkt);

    return pkt->hdr_len + pkt->payload_len;
}

void net_tx_pkt_dump(struct NetTxPkt *pkt)
{
#ifdef NET_TX_PKT_DEBUG
    assert(pkt);

    printf("TX PKT: hdr_len: %d, pkt_type: 0x%X, l2hdr_len: %lu, "
        "l3hdr_len: %lu, payload_len: %u\n", pkt->hdr_len, pkt->packet_type,
        pkt->vec[NET_TX_PKT_L2HDR_FRAG].iov_len,
        pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_len, pkt->payload_len);
#endif
}

void net_tx_pkt_reset(struct NetTxPkt *pkt)
{
    int i;

    /* no assert, as reset can be called before tx_pkt_init */
    if (!pkt) {
        return;
    }

    memset(&pkt->virt_hdr, 0, sizeof(pkt->virt_hdr));

    assert(pkt->vec);

    pkt->payload_len = 0;
    pkt->payload_frags = 0;

    assert(pkt->raw);
    for (i = 0; i < pkt->raw_frags; i++) {
        assert(pkt->raw[i].iov_base);
        pci_dma_unmap(pkt->pci_dev, pkt->raw[i].iov_base, pkt->raw[i].iov_len,
                      DMA_DIRECTION_TO_DEVICE, 0);
    }
    pkt->raw_frags = 0;

    pkt->hdr_len = 0;
    pkt->l4proto = 0;
}

static void net_tx_pkt_do_sw_csum(struct NetTxPkt *pkt)
{
    struct iovec *iov = &pkt->vec[NET_TX_PKT_L2HDR_FRAG];
    uint32_t csum_cntr;
    uint16_t csum = 0;
    uint32_t cso;
    /* num of iovec without vhdr */
    uint32_t iov_len = pkt->payload_frags + NET_TX_PKT_PL_START_FRAG - 1;
    uint16_t csl;
    size_t csum_offset = pkt->virt_hdr.csum_start + pkt->virt_hdr.csum_offset;
    uint16_t l3_proto = eth_get_l3_proto(iov, 1, iov->iov_len);

    /* Put zero to checksum field */
    iov_from_buf(iov, iov_len, csum_offset, &csum, sizeof csum);

    /* Calculate L4 TCP/UDP checksum */
    csl = pkt->payload_len;

    csum_cntr = 0;
    cso = 0;
    /* add pseudo header to csum */
    if (l3_proto == ETH_P_IP) {
        csum_cntr = eth_calc_ip4_pseudo_hdr_csum(
                pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_base,
                csl, &cso);
    } else if (l3_proto == ETH_P_IPV6) {
        csum_cntr = eth_calc_ip6_pseudo_hdr_csum(
                pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_base,
                csl, pkt->l4proto, &cso);
    }

    /* data checksum */
    csum_cntr +=
        net_checksum_add_iov(iov, iov_len, pkt->virt_hdr.csum_start, csl, cso);

    /* Put the checksum obtained into the packet */
    csum = cpu_to_be16(net_checksum_finish_nozero(csum_cntr));
    iov_from_buf(iov, iov_len, csum_offset, &csum, sizeof csum);
}

enum {
    NET_TX_PKT_FRAGMENT_L2_HDR_POS = 0,
    NET_TX_PKT_FRAGMENT_L3_HDR_POS,
    NET_TX_PKT_FRAGMENT_HEADER_NUM
};

#define NET_MAX_FRAG_SG_LIST (64)

static size_t net_tx_pkt_fetch_fragment(struct NetTxPkt *pkt,
    int *src_idx, size_t *src_offset, struct iovec *dst, int *dst_idx)
{
    size_t fetched = 0;
    struct iovec *src = pkt->vec;

    *dst_idx = NET_TX_PKT_FRAGMENT_HEADER_NUM;

    while (fetched < IP_FRAG_ALIGN_SIZE(pkt->virt_hdr.gso_size)) {

        /* no more place in fragment iov */
        if (*dst_idx == NET_MAX_FRAG_SG_LIST) {
            break;
        }

        /* no more data in iovec */
        if (*src_idx == (pkt->payload_frags + NET_TX_PKT_PL_START_FRAG)) {
            break;
        }


        dst[*dst_idx].iov_base = src[*src_idx].iov_base + *src_offset;
        dst[*dst_idx].iov_len = MIN(src[*src_idx].iov_len - *src_offset,
            IP_FRAG_ALIGN_SIZE(pkt->virt_hdr.gso_size) - fetched);

        *src_offset += dst[*dst_idx].iov_len;
        fetched += dst[*dst_idx].iov_len;

        if (*src_offset == src[*src_idx].iov_len) {
            *src_offset = 0;
            (*src_idx)++;
        }

        (*dst_idx)++;
    }

    return fetched;
}

static inline void net_tx_pkt_sendv(struct NetTxPkt *pkt,
    NetClientState *nc, const struct iovec *iov, int iov_cnt)
{
    if (pkt->is_loopback) {
        nc->info->receive_iov(nc, iov, iov_cnt);
    } else {
        qemu_sendv_packet(nc, iov, iov_cnt);
    }
}

static bool net_tx_pkt_do_sw_fragmentation(struct NetTxPkt *pkt,
    NetClientState *nc)
{
    struct iovec fragment[NET_MAX_FRAG_SG_LIST];
    size_t fragment_len = 0;
    bool more_frags = false;

    /* some pointers for shorter code */
    void *l2_iov_base, *l3_iov_base;
    size_t l2_iov_len, l3_iov_len;
    int src_idx =  NET_TX_PKT_PL_START_FRAG, dst_idx;
    size_t src_offset = 0;
    size_t fragment_offset = 0;

    l2_iov_base = pkt->vec[NET_TX_PKT_L2HDR_FRAG].iov_base;
    l2_iov_len = pkt->vec[NET_TX_PKT_L2HDR_FRAG].iov_len;
    l3_iov_base = pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_base;
    l3_iov_len = pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_len;

    /* Copy headers */
    fragment[NET_TX_PKT_FRAGMENT_L2_HDR_POS].iov_base = l2_iov_base;
    fragment[NET_TX_PKT_FRAGMENT_L2_HDR_POS].iov_len = l2_iov_len;
    fragment[NET_TX_PKT_FRAGMENT_L3_HDR_POS].iov_base = l3_iov_base;
    fragment[NET_TX_PKT_FRAGMENT_L3_HDR_POS].iov_len = l3_iov_len;


    /* Put as much data as possible and send */
    do {
        fragment_len = net_tx_pkt_fetch_fragment(pkt, &src_idx, &src_offset,
            fragment, &dst_idx);

        more_frags = (fragment_offset + fragment_len < pkt->payload_len);

        eth_setup_ip4_fragmentation(l2_iov_base, l2_iov_len, l3_iov_base,
            l3_iov_len, fragment_len, fragment_offset, more_frags);

        eth_fix_ip4_checksum(l3_iov_base, l3_iov_len);

        net_tx_pkt_sendv(pkt, nc, fragment, dst_idx);

        fragment_offset += fragment_len;

    } while (fragment_len && more_frags);

    return true;
}

bool net_tx_pkt_send(struct NetTxPkt *pkt, NetClientState *nc)
{
    assert(pkt);

    if (!pkt->has_virt_hdr &&
        pkt->virt_hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
        net_tx_pkt_do_sw_csum(pkt);
    }

    /*
     * Since underlying infrastructure does not support IP datagrams longer
     * than 64K we should drop such packets and don't even try to send
     */
    if (VIRTIO_NET_HDR_GSO_NONE != pkt->virt_hdr.gso_type) {
        if (pkt->payload_len >
            ETH_MAX_IP_DGRAM_LEN -
            pkt->vec[NET_TX_PKT_L3HDR_FRAG].iov_len) {
            return false;
        }
    }

    if (pkt->has_virt_hdr ||
        pkt->virt_hdr.gso_type == VIRTIO_NET_HDR_GSO_NONE) {
        net_tx_pkt_fix_ip6_payload_len(pkt);
        net_tx_pkt_sendv(pkt, nc, pkt->vec,
            pkt->payload_frags + NET_TX_PKT_PL_START_FRAG);
        return true;
    }

    return net_tx_pkt_do_sw_fragmentation(pkt, nc);
}

bool net_tx_pkt_send_loopback(struct NetTxPkt *pkt, NetClientState *nc)
{
    bool res;

    pkt->is_loopback = true;
    res = net_tx_pkt_send(pkt, nc);
    pkt->is_loopback = false;

    return res;
}

void net_tx_pkt_fix_ip6_payload_len(struct NetTxPkt *pkt)
{
    struct iovec *l2 = &pkt->vec[NET_TX_PKT_L2HDR_FRAG];
    if (eth_get_l3_proto(l2, 1, l2->iov_len) == ETH_P_IPV6) {
        struct ip6_header *ip6 = (struct ip6_header *) pkt->l3_hdr;
        /*
         * TODO: if qemu would support >64K packets - add jumbo option check
         * something like that:
         * 'if (ip6->ip6_plen == 0 && !has_jumbo_option(ip6)) {'
         */
        if (ip6->ip6_plen == 0) {
            if (pkt->payload_len <= ETH_MAX_IP_DGRAM_LEN) {
                ip6->ip6_plen = htons(pkt->payload_len);
            }
            /*
             * TODO: if qemu would support >64K packets
             * add jumbo option for packets greater then 65,535 bytes
             */
        }
    }
}
