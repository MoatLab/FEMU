/*
 * FreeBSD disk.h definitions for ioctl(2) emulation
 *
 * Copyright (c) 2015 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef OS_IOCTL_DISK_H
#define OS_IOCTL_DISK_H

/* See sys/disk.h */

#define TARGET_MAXPATHLEN 1024

#define TARGET_DIOCGSECTORSIZE      TARGET_IOR('d', 128, uint32_t)
#define TARGET_DIOCGMEDIASIZE       TARGET_IOR('d', 129, int64_t)
#define TARGET_DIOCGFWSECTORS       TARGET_IOR('d', 130, uint32_t)
#define TARGET_DIOCGFWHEADS         TARGET_IOR('d', 131, uint32_t)
#define TARGET_DIOCGFLUSH           TARGET_IO('d', 135)
#define TARGET_DIOCGDELETE          TARGET_IOW('d', 136, int64_t[2])
#define TARGET_DISK_IDENT_SIZE 256
#define TARGET_DIOCGIDENT           TARGET_IOR('d', 137, \
                                        char[TARGET_DISK_IDENT_SIZE])
#define TARGET_DIOCGPROVIDERNAME    TARGET_IOR('d', 138, \
                                        char[TARGET_MAXPATHLEN])
#define TARGET_DIOCGSTRIPESIZE      TARGET_IOR('d', 139, int64_t)
#define TARGET_DIOCGSTRIPEOFFSET    TARGET_IOR('d', 140, int64_t)
#define TARGET_DIOCGPHYSPATH        TARGET_IOR('d', 141, \
                                        char[TARGET_MAXPATHLEN])

struct target_diocgattr_arg {
    char name[64];
    abi_int len;
    union {
        char str[TARGET_DISK_IDENT_SIZE];
        int64_t off; /* Want abioff, but this will do */
        abi_int i;
        abi_short u16;
    } value;
};

#define TARGET_DIOCGATTR    TARGET_IOWR('d', 142, struct target_diocgattr_arg)

/* Unsupported, target_disk_zone_args is complicated */
/* #define DIOCZONECMD _IOWR('d', 143, struct target_disk_zone_args) */

/* Enable/Disable the device for kernel core dumps. */
/* #define DIOCSKERNELDUMP _IOW('d', 145, struct diocskerneldump_arg) */
/* Get current kernel netdump configuration details for a given index. */
/* #define DIOCGKERNELDUMP _IOWR('d', 146, struct diocskerneldump_arg) */

#endif /* OS_IOCTL_DISK_H */
