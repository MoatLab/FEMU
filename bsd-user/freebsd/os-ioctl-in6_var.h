/*
 * FreeBSD in6 definitions for ioctl(2) emulation
 *
 * Copyright (c) 2014-2015 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef BSD_USER_FREEBSD_OS_IOCTL_IN6_VAR_H
#define BSD_USER_FREEBSD_OS_IOCTL_IN6_VAR_H

#include "os-ioctl-sockio.h"

/*
 * see netinet6/in6_var.h
 * and see netinet/in6.h
 * XXX target_in6_addr and target_sockaddr_in6 should maybe go
 * somewhere else.
 */
struct target_in6_addr {
        union {
                uint8_t         __u6_addr8[16];
                uint16_t        __u6_addr16[8];
                uint32_t        __u6_addr32[4];
        } __u6_addr;
};

struct target_sockaddr_in6 {
        uint8_t         sin6_len;
        uint8_t         sin6_family;
        uint16_t        sin6_port;
        uint32_t        sin6_flowinfo;
        struct target_in6_addr sin6_addr;
        uint32_t        sin6_scope_id;
};

struct target_in6_addrlifetime {
        target_time_t ia6t_expire;
        target_time_t ia6t_preferred;
        u_int32_t ia6t_vltime;
        u_int32_t ia6t_pltime;
};

struct target_in6_ifstat {
        uint64_t ifs6_in_receive;
        uint64_t ifs6_in_hdrerr;
        uint64_t ifs6_in_toobig;
        uint64_t ifs6_in_noroute;
        uint64_t ifs6_in_addrerr;
        uint64_t ifs6_in_protounknown;

        uint64_t ifs6_in_truncated;
        uint64_t ifs6_in_discard;

        uint64_t ifs6_in_deliver;

        uint64_t ifs6_out_forward;

        uint64_t ifs6_out_request;

        uint64_t ifs6_out_discard;
        uint64_t ifs6_out_fragok;
        uint64_t ifs6_out_fragfail;
        uint64_t ifs6_out_fragcreat;

        uint64_t ifs6_reass_reqd;

        uint64_t ifs6_reass_ok;

        uint64_t ifs6_reass_fail;

        uint64_t ifs6_in_mcast;
        uint64_t ifs6_out_mcast;
};

struct target_icmp6_ifstat {
        uint64_t ifs6_in_msg;
        uint64_t ifs6_in_error;
        uint64_t ifs6_in_dstunreach;
        uint64_t ifs6_in_adminprohib;
        uint64_t ifs6_in_timeexceed;
        uint64_t ifs6_in_paramprob;
        uint64_t ifs6_in_pkttoobig;
        uint64_t ifs6_in_echo;
        uint64_t ifs6_in_echoreply;
        uint64_t ifs6_in_routersolicit;
        uint64_t ifs6_in_routeradvert;
        uint64_t ifs6_in_neighborsolicit;
        uint64_t ifs6_in_neighboradvert;
        uint64_t ifs6_in_redirect;
        uint64_t ifs6_in_mldquery;
        uint64_t ifs6_in_mldreport;
        uint64_t ifs6_in_mlddone;

        uint64_t ifs6_out_msg;
        uint64_t ifs6_out_error;
        uint64_t ifs6_out_dstunreach;
        uint64_t ifs6_out_adminprohib;
        uint64_t ifs6_out_timeexceed;
        uint64_t ifs6_out_paramprob;
        uint64_t ifs6_out_pkttoobig;
        uint64_t ifs6_out_echo;
        uint64_t ifs6_out_echoreply;
        uint64_t ifs6_out_routersolicit;
        uint64_t ifs6_out_routeradvert;
        uint64_t ifs6_out_neighborsolicit;
        uint64_t ifs6_out_neighboradvert;
        uint64_t ifs6_out_redirect;
        uint64_t ifs6_out_mldquery;
        uint64_t ifs6_out_mldreport;
        uint64_t ifs6_out_mlddone;
};

struct target_in6_ifreq {
        char ifr_name[TARGET_IFNAMSIZ];
        union {
                struct  target_sockaddr_in6 ifru_addr;
                struct  target_sockaddr_in6 ifru_dstaddr;
                abi_int     ifru_flags;
                abi_int     ifru_flags6;
                abi_int     ifru_metric;
                abi_ulong       ifru_data;
                struct target_in6_addrlifetime ifru_lifetime;
                struct target_in6_ifstat ifru_stat;
                struct target_icmp6_ifstat ifru_icmp6stat;
                u_int32_t ifru_scope_id[16];
        } ifr_ifru;
};

/* netinet6/nd6.h */
struct target_nd_ifinfo {
        uint32_t linkmtu;
        uint32_t maxmtu;
        uint32_t basereachable;
        uint32_t reachable;
        uint32_t retrans;
        uint32_t flags;
        int32_t  recalctm;
        uint8_t  chlim;
        uint8_t  initialized;
        uint8_t  randomseed0[8];
        uint8_t  randomseed1[8];
        uint8_t  randomid[8];
};

/* netinet6/nd6.h */
struct target_in6_ndireq {
    char ifname[TARGET_IFNAMSIZ];
    struct target_nd_ifinfo ndi;
};

struct  target_in6_ndifreq {
    char ifname[TARGET_IFNAMSIZ];
    abi_ulong ifindex;
};


#define TARGET_SIOCGIFDSTADDR_IN6 TARGET_IOWR('i', 34, struct target_in6_ifreq)
#define TARGET_SIOCGIFNETMASK_IN6 TARGET_IOWR('i', 37, struct target_in6_ifreq)

#define TARGET_SIOCDIFADDR_IN6 TARGET_IOW('i', 25, struct target_in6_ifreq)
#ifdef notyet
#define TARGET_OSIOCAIFADDR_IN6 TARGET_IOW('i', 26, struct target_oin6_aliasreq)
#define TARGET_SIOCAIFADDR_IN6 TARGET_IOW('i', 27, struct target_in6_aliasreq)

#define TARGET_SIOCSIFPHYADDR_IN6 TARGET_IOW('i', 70, \
                                             struct target_in6_aliasreq)
#endif
#define TARGET_SIOCGIFPSRCADDR_IN6 TARGET_IOWR('i', 71, struct target_in6_ifreq)
#define TARGET_SIOCGIFPDSTADDR_IN6 TARGET_IOWR('i', 72, struct target_in6_ifreq)

#define TARGET_SIOCGIFAFLAG_IN6 TARGET_IOWR('i', 73, struct target_in6_ifreq)

#ifdef notyet
#define TARGET_SIOCGDRLST_IN6 TARGET_IOWR('i', 74, struct target_in6_drlist)
#endif

#define TARGET_SIOCGIFINFO_IN6 TARGET_IOWR('i', 108, struct target_in6_ndireq)
#define TARGET_SIOCSIFINFO_IN6 TARGET_IOWR('i', 109, struct target_in6_ndireq)

#define TARGET_SIOCSNDFLUSH_IN6 TARGET_IOWR('i', 77, struct target_in6_ifreq)
#ifdef notyet
#define TARGET_SIOCGNBRINFO_IN6 TARGET_IOWR('i', 78, struct target_in6_nbrinfo)
#endif
#define TARGET_SIOCSPFXFLUSH_IN6 TARGET_IOWR('i', 79, struct target_in6_ifreq)
#define TARGET_SIOCSRTRFLUSH_IN6 TARGET_IOWR('i', 80, struct target_in6_ifreq)

#define TARGET_SIOCGIFALIFETIME_IN6 TARGET_IOWR('i', 81, \
                                                struct target_in6_ifreq)
#define TARGET_SIOCGIFSTAT_IN6 TARGET_IOWR('i', 83, struct target_in6_ifreq)
#define TARGET_SIOCGIFSTAT_ICMP6 TARGET_IOWR('i', 84, struct target_in6_ifreq)

#define TARGET_SIOCSDEFIFACE_IN6 TARGET_IOWR('i', 85, struct target_in6_ndifreq)
#define TARGET_SIOCGDEFIFACE_IN6 TARGET_IOWR('i', 86, struct target_in6_ndifreq)

#define TARGET_SIOCSIFINFO_FLAGS TARGET_IOWR('i', 87, struct target_in6_ndireq)

#define TARGET_SIOCSSCOPE6 TARGET_IOW('i', 88, struct target_in6_ifreq)
#define TARGET_SIOCGSCOPE6 TARGET_IOWR('i', 89, struct target_in6_ifreq)
#define TARGET_SIOCGSCOPE6DEF TARGET_IOWR('i', 90, struct target_in6_ifreq)

#ifdef notyet
#define TARGET_SIOCSIFPREFIX_IN6 TARGET_IOW('i', 100, \
                                            struct target_in6_prefixreq)
#define TARGET_SIOCGIFPREFIX_IN6 TARGET_IOWR('i', 101, \
                                             struct target_in6_prefixreq)
#define TARGET_SIOCDIFPREFIX_IN6 TARGET_IOW('i', 102, \
                                            struct target_in6_prefixreq)
#define TARGET_SIOCAIFPREFIX_IN6 TARGET_IOW('i', 103, \
                                            struct target_in6_rrenumreq)
#define TARGET_SIOCCIFPREFIX_IN6 TARGET_IOW('i', 104, \
                                            struct target_in6_rrenumreq)
#define TARGET_SIOCSGIFPREFIX_IN6 TARGET_IOW('i', 105, \
                                             struct target_in6_rrenumreq)

#define TARGET_SIOCGETSGCNT_IN6 TARGET_IOWR('u', 106, \
                                            struct target_sioc_sg_req6)
#define TARGET_SIOCGETMIFCNT_IN6 TARGET_IOWR('u', 107, \
                                             struct target_sioc_mif_req6)

#define TARGET_SIOCAADDRCTL_POLICY TARGET_IOW('u', 108, \
                                              struct target_in6_addrpolicy)
#define TARGET_SIOCDADDRCTL_POLICY TARGET_IOW('u', 109, \
                                              struct target_in6_addrpolicy)
#endif

#endif /* BSD_USER_FREEBSD_OS_IOCTL_IN6_VAR_H */
