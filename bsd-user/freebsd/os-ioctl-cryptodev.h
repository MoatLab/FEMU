/*
 * FreeBSD cryptodev definitions for ioctl(2) emulation
 *
 * Copyright (c) 2014 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef BSD_USER_FREEBSD_OS_IOCTL_CRYPTODEV_H
#define BSD_USER_FREEBSD_OS_IOCTL_CRYPTODEV_H

/* see opencrypto/cryptodev.h */

struct target_session_op {
    u_int32_t       cipher;
    u_int32_t       mac;

    u_int32_t       keylen;
    abi_ulong       key;
    int32_t         mackeylen;
    abi_ulong       mackey;

     u_int32_t       ses;
};


struct target_session2_op {
    u_int32_t       cipher;
    u_int32_t       mac;

    u_int32_t       keylen;
    abi_ulong       key;
    int32_t         mackeylen;
    abi_ulong       mackey;

    u_int32_t       ses;
    int32_t         crid;
    abi_int         ivlen;
    abi_int         maclen;
    abi_int         pad[2];
};

struct target_crypt_op {
    uint32_t        ses;
    uint16_t        op;             /* i.e. COP_ENCRYPT */
#define TARGET_COP_ENCRYPT     1
#define TARGET_COP_DECRYPT     2
    uint16_t        flags;
#define TARGET_COP_F_CIPHER_FIRST      0x0001  /* Cipher before MAC. */
#define TARGET_COP_F_BATCH             0x0008  /* Batch op if possible */
    abi_uint        len;
    abi_ulong       src;            /* become iov[] inside kernel */
    abi_ulong       dst;
    abi_ulong       mac;            /* must be big enough for chosen MAC */
    abi_ulong       iv;
};

/* op and flags the same as crypt_op */
struct target_crypt_aead {
    uint32_t        ses;
    uint16_t        op;             /* i.e. COP_ENCRYPT */
    uint16_t        flags;
    abi_uint        len;
    abi_uint        aadlen;
    abi_uint        ivlen;
    abi_ulong       src;           /* become iov[] inside kernel */
    abi_ulong       dst;
    abi_ulong       aad;           /* additional authenticated data */
    abi_ulong       tag;           /* must fit for chosen TAG length */
    abi_ulong       iv;
};

struct target_crypt_find_op {
    abi_int         crid;
    char            name[32];
};

#define TARGET_CIOCGSESSION     TARGET_IOWR('c', 101, struct target_session_op)
#define TARGET_CIOCFSESSION     TARGET_IOW('c', 102, u_int32_t)
#define TARGET_CIOCCRYPT        TARGET_IOWR('c', 103, struct target_crypt_op)
#define TARGET_CIOCGSESSION2    TARGET_IOWR('c', 106, struct target_session2_op)
#define TARGET_CIOCFINDDEV      TARGET_IOWR('c', 108, struct target_crypt_find_op)
#define TARGET_CIOCCRYPTAEAD    TARGET_IOWR('c', 109, struct target_crypt_aead)

#endif /* BSD_USER_FREEBSD_OS_IOCTL_CRYPTODEV_H */
