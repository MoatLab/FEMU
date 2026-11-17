/*
 * FreeBSD sockio.h definitions for ioctl(2) emulation
 *
 * Copyright (c) 2015 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef OS_IOCTL_SOCKIO_H
#define OS_IOCTL_SOCKIO_H

/* See sys/sockio.h */
#define TARGET_SIOCSHIWAT       TARGET_IOW('s',  0, int32_t)
#define TARGET_SIOCGHIWAT       TARGET_IOR('s',  1, int32_t)
#define TARGET_SIOCSLOWAT       TARGET_IOW('s',  2, int32_t)
#define TARGET_SIOCGLOWAT       TARGET_IOR('s',  3, int32_t)
#define TARGET_SIOCATMARK       TARGET_IOR('s',  7, int32_t)
#define TARGET_SIOCSPGRP        TARGET_IOW('s',  8, int32_t)
#define TARGET_SIOCGPGRP        TARGET_IOR('s',  9, int32_t)

/* See net/if.h */
struct target_ifreq_buffer {
    abi_ulong  length;
    abi_ulong  buffer;
};

struct target_ifreq_nv_req {
    abi_uint   buf_length;     /* Total size of buffer */
    abi_uint   length;         /* Length of the filled part */
    abi_ulong  buffer;        /* Buffer itself, containing packed nv */
};

#define TARGET_IFNAMSIZ 16

struct target_ifreq {
    char    ifr_name[TARGET_IFNAMSIZ];
    union {
        struct  target_sockaddr ifru_addr;
        struct  target_sockaddr ifru_dstaddr;
        struct  target_sockaddr ifru_broadaddr;
        struct  target_ifreq_buffer ifru_buffer;
        abi_short   ifru_flags[2];
        abi_short   ifru_index;
        abi_int     ifru_jid;
        abi_int     ifru_metric;
        abi_int     ifru_mtu;
        abi_int     ifru_phys;
        abi_int     ifru_media;
        abi_ulong   ifru_data;
        abi_int     ifru_cap[2];
        uint32_t    ifru_fib;
        uint8_t     ifru_vlan_pcp;
        struct target_ifreq_nv_req ifru_nv;
    } ifr_ifru;
};


#define TARGET_SIOCSIFADDR      TARGET_IOW('i', 12, struct target_ifreq)
#define TARGET_SIOCGIFADDR      TARGET_IOWR('i', 33, struct target_ifreq)
#define TARGET_SIOCSIFDSTADDR   TARGET_IOW('i', 14, struct target_ifreq)
#define TARGET_SIOCGIFDSTADDR   TARGET_IOWR('i', 34, struct target_ifreq)
#define TARGET_SIOCSIFFLAGS     TARGET_IOW('i', 16, struct target_ifreq)
#define TARGET_SIOCGIFFLAGS     TARGET_IOWR('i', 17, struct target_ifreq)
#define TARGET_SIOCGIFBRDADDR   TARGET_IOWR('i', 35, struct target_ifreq)
#define TARGET_SIOCSIFBRDADDR   TARGET_IOW('i', 19, struct target_ifreq)
#define TARGET_SIOCGIFNETMASK   TARGET_IOWR('i', 37, struct target_ifreq)
#define TARGET_SIOCSIFNETMASK   TARGET_IOW('i', 22, struct target_ifreq)
#define TARGET_SIOCGIFMETRIC    TARGET_IOWR('i', 23, struct target_ifreq)
#define TARGET_SIOCSIFMETRIC    TARGET_IOW('i', 24, struct target_ifreq)
#define TARGET_SIOCDIFADDR      TARGET_IOW('i', 25, struct target_ifreq)
#define TARGET_SIOCSIFCAP       TARGET_IOW('i', 30, struct target_ifreq)
#define TARGET_SIOCGIFCAP       TARGET_IOWR('i', 31, struct target_ifreq)
#define TARGET_SIOCGIFINDEX     TARGET_IOWR('i', 32, struct target_ifreq)
#define TARGET_SIOCGIFMAC       TARGET_IOWR('i', 38, struct target_ifreq)
#define TARGET_SIOCSIFMAC       TARGET_IOW('i', 39, struct target_ifreq)
#define TARGET_SIOCSIFNAME      TARGET_IOW('i', 40, struct target_ifreq)
#define TARGET_SIOCSIFDESCR     TARGET_IOW('i', 41, struct target_ifreq)
#define TARGET_SIOCGIFDESCR     TARGET_IOWR('i', 42, struct target_ifreq)
#define TARGET_SIOCADDMULTI     TARGET_IOW('i', 49, struct target_ifreq)
#define TARGET_SIOCDELMULTI     TARGET_IOW('i', 50, struct target_ifreq)
#define TARGET_SIOCGIFMTU       TARGET_IOWR('i', 51, struct target_ifreq)
#define TARGET_SIOCSIFMTU       TARGET_IOW('i', 52, struct target_ifreq)
#define TARGET_SIOCGIFPHYS      TARGET_IOWR('i', 53, struct target_ifreq)
#define TARGET_SIOCSIFPHYS      TARGET_IOW('i', 54, struct target_ifreq)
#define TARGET_SIOCSIFMEDIA     TARGET_IOWR('i', 55, struct target_ifreq)
#define TARGET_SIOCSIFGENERIC   TARGET_IOW('i', 57, struct target_ifreq)
#define TARGET_SIOCGIFGENERIC   TARGET_IOWR('i', 58, struct target_ifreq)
#define TARGET_SIOCSIFLLADDR    TARGET_IOW('i', 60, struct target_ifreq)
#define TARGET_SIOCGIFPSRCADDR  TARGET_IOWR('i', 71, struct target_ifreq)
#define TARGET_SIOCGIFPDSTADDR  TARGET_IOWR('i', 72, struct target_ifreq)
#define TARGET_SIOCDIFPHYADDR   TARGET_IOW('i', 73, struct target_ifreq)
#define TARGET_SIOCGPRIVATE_0   TARGET_IOWR('i', 80, struct target_ifreq)
#define TARGET_SIOCGPRIVATE_1   TARGET_IOWR('i', 81, struct target_ifreq)
#define TARGET_SIOCSIFVNET      TARGET_IOWR('i', 90, struct target_ifreq)
#define TARGET_SIOCSIFRVNET     TARGET_IOWR('i', 91, struct target_ifreq)
#define TARGET_SIOCGIFFIB       TARGET_IOWR('i', 92, struct target_ifreq)
#define TARGET_SIOCSIFFIB       TARGET_IOW('i', 93, struct target_ifreq)
#define TARGET_SIOCGTUNFIB      TARGET_IOWR('i', 94, struct target_ifreq)
#define TARGET_SIOCIFCREATE     TARGET_IOWR('i', 122, struct target_ifreq)
#define TARGET_SIOCIFCREATE2    TARGET_IOWR('i', 124, struct target_ifreq)
#define TARGET_SIOCIFDESTROY    TARGET_IOW('i', 121, struct target_ifreq)

/* net/if_gre.h */
#define TARGET_GREGKEY          TARGET_IOWR('i', 107, struct target_ifreq)
#define TARGET_GREGOPTS         TARGET_IOWR('i', 109, struct target_ifreq)

/* net/if_gif.h */
#define TARGET_GIFGOPTS         TARGET_IOWR('i', 150, struct target_ifreq)

/* netinet/ip_carp.h */
#define TARGET_SIOCGVH          TARGET_IOWR('i', 246, struct target_ifreq)

/* net/if_pfsync.h */
#define TARGET_SIOCGETPFSYNC    TARGET_IOWR('i', 248, struct target_ifreq)


/* See net/if.h */
struct target_ifconf {
    int32_t ifc_len;
    union {
        abi_ulong   ifcu_buf;
        abi_ulong   ifcu_req;
    } ifc_ifcu;
};

#define TARGET_SIOCGIFCONF     TARGET_IOWR('i', 36, struct target_ifconf)

/* See net/if.h */
struct  target_ifdrv {
    char            ifd_name[TARGET_IFNAMSIZ];
    abi_ulong       ifd_cmd;
    abi_ulong       ifd_len;
    abi_ulong       ifd_data;
};

#define TARGET_SIOCSDRVSPEC    TARGET_IOW('i', 123, struct target_ifdrv)
#define TARGET_SIOCGDRVSPEC    TARGET_IOWR('i', 123, struct target_ifdrv)

/* See net/if.h */
struct target_ifg_req {
    union {
        char        ifgrqu_group[TARGET_IFNAMSIZ];
        char        ifgrqu_member[TARGET_IFNAMSIZ];
    } ifgrq_ifgrqu;
};

struct target_ifgroupreq {
    char            ifgr_name[TARGET_IFNAMSIZ];
    uint32_t        ifgr_len;
    union {
        char        ifgru_group[TARGET_IFNAMSIZ];
        abi_ulong   ifgru_groups;
    } ifgr_ifgru;
};

#define TARGET_SIOCGIFGROUP    TARGET_IOWR('i', 136, struct target_ifgroupreq)

struct target_ifmediareq {
    char        ifm_name[TARGET_IFNAMSIZ];
    int32_t     ifm_current;
    int32_t     ifm_mask;
    int32_t     ifm_status;
    int32_t     ifm_active;
    int32_t     ifm_count;
    abi_ulong   ifm_ulist;
};

#define TARGET_SIOCGIFMEDIA  TARGET_IOWR('i', 56, struct target_ifmediareq)
#define TARGET_SIOCGIFXMEDIA  TARGET_IOWR('i', 139, struct target_ifmediareq)

#define TARGET_IFSTATMAX    800
struct target_ifstat {
    char    ifs_name[TARGET_IFNAMSIZ];
    char    ascii[TARGET_IFSTATMAX + 1];
};

#define TARGET_SIOCGIFSTATUS TARGET_IOWR('i', 59, struct target_ifstat)

/* net80211/ieee80211_ioctl.h */
struct target_ieee80211req {
    char            i_name[TARGET_IFNAMSIZ];
    uint16_t        i_type;
    int16_t         i_val;
    uint16_t        i_len;
    abi_ulong       i_data;
};

#define TARGET_SIOCG80211 TARGET_IOWR('i', 235, struct target_ieee80211req)

/* net/if_lagg.h */
struct target_lacp_opreq {
    uint16_t        actor_prio;
    uint8_t         actor_mac[ETHER_ADDR_LEN];
    uint16_t        actor_key;
    uint16_t        actor_portprio;
    uint16_t        actor_portno;
    uint8_t         actor_state;
    uint16_t        partner_prio;
    uint8_t         partner_mac[ETHER_ADDR_LEN];
    uint16_t        partner_key;
    uint16_t        partner_portprio;
    uint16_t        partner_portno;
    uint8_t         partner_state;
};

struct target_lagg_reqport {
    char            rp_ifname[TARGET_IFNAMSIZ];
    char            rp_portname[TARGET_IFNAMSIZ];
    u_int32_t       rp_prio;
    u_int32_t       rp_flags;
    union {
        struct target_lacp_opreq rpsc_lacp;
    } rp_psc;
};
#define TARGET_SIOCGLAGGPORT TARGET_IOWR('i', 140, struct target_lagg_reqport)

struct target_lagg_reqall {
    char            ra_ifname[TARGET_IFNAMSIZ];
    abi_uint        ra_proto;

    abi_ulong       ra_size;
    abi_ulong       ra_port;
    abi_int         ra_ports;
    union {
        struct target_lacp_opreq rpsc_lacp;
    } ra_psc;
};
#define TARGET_SIOCGLAGG TARGET_IOWR('i', 143, struct target_lagg_reqall)

struct target_lagg_reqflags {
    char            rf_ifname[TARGET_IFNAMSIZ];
    uint32_t        rf_flags;
};
#define TARGET_SIOCGLAGGFLAGS TARGET_IOWR('i', 145, struct target_lagg_reqflags)

struct target_lagg_reqopts {
    char            ro_ifname[TARGET_IFNAMSIZ];
    abi_int         ro_opts;
    abi_uint        ro_count;
    abi_uint        ro_active;
    abi_uint        ro_flapping;
    abi_int         ro_flowid_shift;
    uint32_t        ro_bkt;
};
#define TARGET_SIOCGLAGGOPTS TARGET_IOWR('i', 152, struct target_lagg_reqopts)

#endif /* OS_IOCTL_SOCKIO_H */
