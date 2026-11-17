/*
 * BSD ioctl(2) emulation
 *
 * Copyright (c) 2013-2015 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "qemu/osdep.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/disk.h>
#include <sys/ioccom.h>
#include <sys/ioctl.h>
#include <sys/sockio.h>
#include <sys/_termios.h>
#include <sys/ttycom.h>
#include <sys/filio.h>

#include <crypto/cryptodev.h>

#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_var.h>
#include <net/if_types.h>
#include <net/route.h>
#include <net/if_dl.h>
#include <net/if_gif.h>
#include <net/if_gre.h>
#include <net/if_lagg.h>
#include <net/if_media.h>
#include <net/pfvar.h>
#include <net/if_pfsync.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip_carp.h>
#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>
#include <net80211/ieee80211_ioctl.h>

#include <stdio.h>

#include "qemu.h"

#include "syscall_defs.h"
#include "bsd-ioctl.h"
#include "os-ioctl-cryptodev.h"
#include "os-ioctl-filio.h"
#include "os-ioctl-in6_var.h"
#include "os-ioctl-sockio.h"
#include "os-ioctl-ttycom.h"
#include "os-ioctl-disk.h"

static void target_to_host_termios(void *dst, const void *src)
{
    struct termios *host = dst;
    const struct target_termios *target = src;

    host->c_iflag = target_to_host_bitmask(tswap32(target->c_iflag), iflag_tbl);
    host->c_oflag = target_to_host_bitmask(tswap32(target->c_oflag), oflag_tbl);
    host->c_cflag = target_to_host_bitmask(tswap32(target->c_cflag), cflag_tbl);
    host->c_lflag = target_to_host_bitmask(tswap32(target->c_lflag), lflag_tbl);

    memset(host->c_cc, 0, sizeof(host->c_cc));
    host->c_cc[VEOF] = target->c_cc[TARGET_VEOF];
    host->c_cc[VEOL] = target->c_cc[TARGET_VEOL];
#ifdef VEOL2
    host->c_cc[VEOL2] = target->c_cc[TARGET_VEOL2];
#endif
    host->c_cc[VERASE] = target->c_cc[TARGET_VERASE];
#ifdef VWERASE
    host->c_cc[VWERASE] = target->c_cc[TARGET_VWERASE];
#endif
    host->c_cc[VKILL] = target->c_cc[TARGET_VKILL];
#ifdef VREPRINT
    host->c_cc[VREPRINT] = target->c_cc[TARGET_VREPRINT];
#endif
#ifdef VERASE2
    host->c_cc[VERASE2] = target->c_cc[TARGET_VERASE2];
#endif
    host->c_cc[VINTR] = target->c_cc[TARGET_VINTR];
    host->c_cc[VQUIT] = target->c_cc[TARGET_VQUIT];
    host->c_cc[VSUSP] = target->c_cc[TARGET_VSUSP];
#ifdef VDSUSP
    host->c_cc[VDSUSP] = target->c_cc[TARGET_VDSUSP];
#endif
    host->c_cc[VSTART] = target->c_cc[TARGET_VSTART];
    host->c_cc[VSTOP] = target->c_cc[TARGET_VSTOP];
#ifdef VLNEXT
    host->c_cc[VLNEXT] = target->c_cc[TARGET_VLNEXT];
#endif
#ifdef VDISCARD
    host->c_cc[VDISCARD] = target->c_cc[TARGET_VDISCARD];
#endif
    host->c_cc[VMIN] = target->c_cc[TARGET_VMIN];
    host->c_cc[VTIME] = target->c_cc[TARGET_VTIME];
#ifdef VSTATUS
    host->c_cc[VSTATUS] = target->c_cc[TARGET_VSTATUS];
#endif

    host->c_ispeed = tswap32(target->c_ispeed);
    host->c_ospeed = tswap32(target->c_ospeed);
}

static void host_to_target_termios(void *dst, const void *src)
{
    struct target_termios *target = dst;
    const struct termios *host = src;

    target->c_iflag = tswap32(host_to_target_bitmask(host->c_iflag, iflag_tbl));
    target->c_oflag = tswap32(host_to_target_bitmask(host->c_oflag, oflag_tbl));
    target->c_cflag = tswap32(host_to_target_bitmask(host->c_cflag, cflag_tbl));
    target->c_lflag = tswap32(host_to_target_bitmask(host->c_lflag, lflag_tbl));

    memset(target->c_cc, 0, sizeof(target->c_cc));
    target->c_cc[TARGET_VEOF] = host->c_cc[VEOF];
    target->c_cc[TARGET_VEOL] = host->c_cc[VEOL];
#ifdef VEOL2
    target->c_cc[TARGET_VEOL2] = host->c_cc[VEOL2];
#endif
    target->c_cc[TARGET_VERASE] = host->c_cc[VERASE];
#ifdef VWERASE
    target->c_cc[TARGET_VWERASE] = host->c_cc[VWERASE];
#endif
    target->c_cc[TARGET_VKILL] = host->c_cc[VKILL];
#ifdef VREPRINT
    target->c_cc[TARGET_VREPRINT] = host->c_cc[VREPRINT];
#endif
#ifdef VERASE2
    target->c_cc[TARGET_VERASE2] = host->c_cc[VERASE2];
#endif
    target->c_cc[TARGET_VINTR] = host->c_cc[VINTR];
    target->c_cc[TARGET_VQUIT] = host->c_cc[VQUIT];
    target->c_cc[TARGET_VSUSP] = host->c_cc[VSUSP];
#ifdef VDSUSP
    target->c_cc[TARGET_VDSUSP] = host->c_cc[VDSUSP];
#endif
    target->c_cc[TARGET_VSTART] = host->c_cc[VSTART];
    target->c_cc[TARGET_VSTOP] = host->c_cc[VSTOP];
#ifdef VLNEXT
    target->c_cc[TARGET_VLNEXT] = host->c_cc[VLNEXT];
#endif
#ifdef VDISCARD
    target->c_cc[TARGET_VDISCARD] = host->c_cc[VDISCARD];
#endif
    target->c_cc[TARGET_VMIN] = host->c_cc[VMIN];
    target->c_cc[TARGET_VTIME] = host->c_cc[VTIME];
#ifdef VSTATUS
    target->c_cc[TARGET_VSTATUS] = host->c_cc[VSTATUS];
#endif

    target->c_ispeed = tswap32(host->c_ispeed);
    target->c_ospeed = tswap32(host->c_ospeed);
}

static const StructEntry struct_termios_def = {
    .convert = { host_to_target_termios, target_to_host_termios },
    .size = { sizeof(struct target_termios), sizeof(struct termios) },
    .align = { __alignof__(struct target_termios),
        __alignof__(struct termios) },
};

/* ioctl structure type definitions */
#define STRUCT(name, ...) STRUCT_ ## name,
#define STRUCT_SPECIAL(name) STRUCT_ ## name,
enum {
#include "os-ioctl-types.h"
STRUCT_MAX
};
#undef STRUCT
#undef STRUCT_SPECIAL

#define STRUCT(name, ...) \
    static const argtype struct_ ## name ## _def[] = { __VA_ARGS__, TYPE_NULL };
#define STRUCT_SPECIAL(name)
#include "os-ioctl-types.h"
#undef STRUCT
#undef STRUCT_SPECIAL


struct IOCTLEntry;

typedef abi_long do_ioctl_fn(const struct IOCTLEntry *ie, uint8_t *buf_temp,
                int fd, abi_long cmd, abi_long arg);

struct IOCTLEntry {
    unsigned int target_cmd;
    unsigned int host_cmd;
    const char *name;
    int access;
    do_ioctl_fn *do_ioctl;
    const argtype arg_type[5];
};
typedef struct IOCTLEntry IOCTLEntry;

#define MAX_STRUCT_SIZE 4096

static abi_long do_ioctl_unsupported(__unused const IOCTLEntry *ie,
                                     __unused uint8_t *buf_temp,
                                     __unused int fd, __unused abi_long cmd,
                                     __unused abi_long arg);

static abi_long do_ioctl_in6_ifreq_sockaddr_int(const IOCTLEntry *ie,
        uint8_t *buf_temp, int fd, abi_long cmd, abi_long arg);

static IOCTLEntry ioctl_entries[] = {
#define IOC_    0x0000
#define IOC_R   0x0001
#define IOC_W   0x0002
#define IOC_RW  (IOC_R | IOC_W)
#define IOCTL(cmd, access, ...) \
    { TARGET_ ## cmd, cmd, #cmd, access, 0, { __VA_ARGS__ } },
#define IOCTL_SPECIAL(cmd, access, dofn, ...) \
    { TARGET_ ## cmd, cmd, #cmd, access, dofn, { __VA_ARGS__ } },
#define IOCTL_SPECIAL_UNIMPL(cmd, access, dofn, ...) \
    { TARGET_ ## cmd, 0, #cmd, access, dofn, { __VA_ARGS__ } },
#include "os-ioctl-cmds.h"
    { 0, 0 },
};

static void log_unsupported_ioctl(unsigned long cmd)
{
    gemu_log("cmd=0x%08lx dir=", cmd);
    switch (cmd & IOC_DIRMASK) {
    case IOC_VOID:
        gemu_log("VOID ");
        break;
    case IOC_OUT:
        gemu_log("OUT ");
        break;
    case IOC_IN:
        gemu_log("IN  ");
        break;
    case IOC_INOUT:
        gemu_log("INOUT");
        break;
    default:
        gemu_log("%01lx ???", (cmd & IOC_DIRMASK) >> 29);
        break;
    }
    gemu_log(" '%c' %3d %lu\n", (char)IOCGROUP(cmd), (int)(cmd & 0xff),
             IOCPARM_LEN(cmd));
}

static abi_long do_ioctl_unsupported(__unused const IOCTLEntry *ie,
                                     __unused uint8_t *buf_temp,
                                     __unused int fd, __unused abi_long cmd,
                                     __unused abi_long arg)
{
    return -TARGET_ENXIO;
}

static void target_to_host_sockaddr_in6(struct sockaddr_in6 *hsa_in6,
        struct target_sockaddr_in6 *tsa_in6)
{
    __get_user(hsa_in6->sin6_len, &tsa_in6->sin6_len);
    __get_user(hsa_in6->sin6_family, &tsa_in6->sin6_family);
    __get_user(hsa_in6->sin6_port, &tsa_in6->sin6_port);
    __get_user(hsa_in6->sin6_flowinfo, &tsa_in6->sin6_flowinfo);
    memcpy(&hsa_in6->sin6_addr, &tsa_in6->sin6_addr, 16);
    __get_user(hsa_in6->sin6_scope_id, &tsa_in6->sin6_scope_id);
}

/*
 * For ioctl()'s such as SIOCGIFAFLAG_IN6 and SIOCGIFALIFETIME_IN6 that
 * passes a struct sockaddr_in6 in and gets an int out using
 * struct in6_ifreq.
 */
static abi_long do_ioctl_in6_ifreq_sockaddr_int(const IOCTLEntry *ie,
        uint8_t *buf_temp, int fd, abi_long cmd, abi_long arg)
{
    abi_long ret;
    struct target_in6_ifreq *tin6ifreq;
    struct target_sockaddr_in6 *tsa_in6;
    struct in6_ifreq hin6ifreq;
    struct sockaddr_in6 *hsa_in6 = &hin6ifreq.ifr_ifru.ifru_addr;

    tin6ifreq = lock_user(VERIFY_WRITE, arg, sizeof(*tin6ifreq), 1);
    if (tin6ifreq == NULL) {
        return -TARGET_EFAULT;
    }
    memcpy(hin6ifreq.ifr_name, tin6ifreq->ifr_name, IFNAMSIZ);
    tsa_in6 = &tin6ifreq->ifr_ifru.ifru_addr;
    target_to_host_sockaddr_in6(hsa_in6, tsa_in6);

    ret = get_errno(safe_ioctl(fd, ie->host_cmd, &hin6ifreq));
    if (!is_error(ret)) {
        put_user_s32(hin6ifreq.ifr_ifru.ifru_flags6,
                arg + offsetof(struct target_in6_ifreq, ifr_ifru.ifru_flags6));
    }
    unlock_user(tin6ifreq, arg, sizeof(*tin6ifreq));

    return ret;
}

abi_long do_bsd_ioctl(int fd, abi_long cmd, abi_long arg)
{
    const IOCTLEntry *ie;
    const argtype *arg_type;
    abi_long ret;
    uint8_t buf_temp[MAX_STRUCT_SIZE];
    int target_size;
    void *argptr;

    ie = ioctl_entries;
    for (;;) {
        if (ie->target_cmd == 0) {
            gemu_log("QEMU unsupported ioctl: ");
            log_unsupported_ioctl(cmd);
            return -TARGET_ENOSYS;
        }
        if (ie->target_cmd == cmd) {
            break;
        }
        ie++;
    }
    arg_type = ie->arg_type;
#if defined(DEBUG)
    gemu_log("ioctl: cmd=0x%04lx (%s)\n", (long)cmd, ie->name);
#endif
    if (ie->do_ioctl) {
        return ie->do_ioctl(ie, buf_temp, fd, cmd, arg);
    }

    switch (arg_type[0]) {
    case TYPE_NULL:
        /* no argument */
        ret = get_errno(safe_ioctl(fd, ie->host_cmd));
        break;

    case TYPE_PTRVOID:
    case TYPE_INT:
        /* int argument */
        ret = get_errno(safe_ioctl(fd, ie->host_cmd, arg));
        break;

    case TYPE_PTR:
        arg_type++;
        target_size = thunk_type_size(arg_type, 0);
        switch (ie->access) {
        case IOC_R:
            ret = get_errno(safe_ioctl(fd, ie->host_cmd, buf_temp));
            if (!is_error(ret)) {
                argptr = lock_user(VERIFY_WRITE, arg,
                    target_size, 0);
                if (!argptr) {
                    return -TARGET_EFAULT;
                }
                thunk_convert(argptr, buf_temp, arg_type,
                    THUNK_TARGET);
                unlock_user(argptr, arg, target_size);
            }
            break;

        case IOC_W:
            argptr = lock_user(VERIFY_READ, arg, target_size, 1);
            if (!argptr) {
                return -TARGET_EFAULT;
            }
            thunk_convert(buf_temp, argptr, arg_type, THUNK_HOST);
            unlock_user(argptr, arg, 0);
            ret = get_errno(safe_ioctl(fd, ie->host_cmd, buf_temp));
            break;

        case IOC_RW:
            /* fallthrough */
        default:
            argptr = lock_user(VERIFY_READ, arg, target_size, 1);
            if (!argptr) {
                return -TARGET_EFAULT;
            }
            thunk_convert(buf_temp, argptr, arg_type, THUNK_HOST);
            unlock_user(argptr, arg, 0);
            ret = get_errno(safe_ioctl(fd, ie->host_cmd, buf_temp));
            if (!is_error(ret)) {
                argptr = lock_user(VERIFY_WRITE, arg, target_size, 0);
                if (!argptr) {
                    return -TARGET_EFAULT;
                }
                thunk_convert(argptr, buf_temp, arg_type, THUNK_TARGET);
                unlock_user(argptr, arg, target_size);
            }
            break;
        }
        break;

    default:
        gemu_log("QEMU unknown ioctl: type=%d ", arg_type[0]);
        log_unsupported_ioctl(cmd);
        ret = -TARGET_ENOSYS;
        break;
    }
    return ret;
}

void init_bsd_ioctl(void)
{
    IOCTLEntry *ie;
    const argtype *arg_type;
    int size;

    thunk_init(STRUCT_MAX);

#define STRUCT(name, ...) \
 thunk_register_struct(STRUCT_ ## name, #name, struct_ ## name ## _def);
#define STRUCT_SPECIAL(name) \
 thunk_register_struct_direct(STRUCT_ ## name, #name, &struct_ ## name ## _def);
#include "os-ioctl-types.h"
#undef STRUCT
#undef STRUCT_SPECIAL

    /*
     * Patch the ioctl size if necessary using the fact that no
     * ioctl has all the bits at '1' in the size field
     * (IOCPARM_MAX - 1).
     */
    ie = ioctl_entries;
    while (ie->target_cmd != 0) {
        if (((ie->target_cmd >> TARGET_IOCPARM_SHIFT) &
                    TARGET_IOCPARM_MASK) == TARGET_IOCPARM_MASK) {
            arg_type = ie->arg_type;
            if (arg_type[0] != TYPE_PTR) {
                fprintf(stderr, "cannot patch size for ioctl 0x%x\n",
                        ie->target_cmd);
                exit(1);
            }
            arg_type++;
            size = thunk_type_size(arg_type, 0);
            ie->target_cmd = (ie->target_cmd &
                    ~(TARGET_IOCPARM_MASK << TARGET_IOCPARM_SHIFT)) |
                (size << TARGET_IOCPARM_SHIFT);
        }
        ie++;
    }

}
