/*
 * miscellaneous FreeBSD system call shims
 *
 * Copyright (c) 2013-2014 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef OS_MISC_H
#define OS_MISC_H

#include <sys/cpuset.h>
#include <sys/random.h>
#include <sched.h>

/*
 * shm_open2 isn't exported, but the __sys_ alias is. We can use either for the
 * static version, but to dynamically link we have to use the sys version.
 */
int __sys_shm_open2(const char *path, int flags, mode_t mode, int shmflags,
    const char *);

#if defined(__FreeBSD_version) && __FreeBSD_version >= 1300048
/* shm_open2(2) */
static inline abi_long do_freebsd_shm_open2(abi_ulong pathptr, abi_ulong flags,
    abi_long mode, abi_ulong shmflags, abi_ulong nameptr)
{
    int ret;
    void *uname, *upath;

    if (pathptr == (uintptr_t)SHM_ANON) {
        upath = SHM_ANON;
    } else {
        upath = lock_user_string(pathptr);
        if (upath == NULL) {
            return -TARGET_EFAULT;
        }
    }

    uname = NULL;
    if (nameptr != 0) {
        uname = lock_user_string(nameptr);
        if (uname == NULL) {
            unlock_user(upath, pathptr, 0);
            return -TARGET_EFAULT;
        }
    }
    ret = get_errno(__sys_shm_open2(upath,
                target_to_host_bitmask(flags, fcntl_flags_tbl), mode,
                target_to_host_bitmask(shmflags, shmflag_flags_tbl), uname));

    if (upath != SHM_ANON) {
        unlock_user(upath, pathptr, 0);
    }
    if (uname != NULL) {
        unlock_user(uname, nameptr, 0);
    }
    return ret;
}
#endif /* __FreeBSD_version >= 1300048 */

#if defined(__FreeBSD_version) && __FreeBSD_version >= 1300049
/* shm_rename(2) */
static inline abi_long do_freebsd_shm_rename(abi_ulong fromptr, abi_ulong toptr,
        abi_ulong flags)
{
    int ret;
    void *ufrom, *uto;

    ufrom = lock_user_string(fromptr);
    if (ufrom == NULL) {
        return -TARGET_EFAULT;
    }
    uto = lock_user_string(toptr);
    if (uto == NULL) {
        unlock_user(ufrom, fromptr, 0);
        return -TARGET_EFAULT;
    }
    ret = get_errno(shm_rename(ufrom, uto, flags));
    unlock_user(ufrom, fromptr, 0);
    unlock_user(uto, toptr, 0);

    return ret;
}
#endif /* __FreeBSD_version >= 1300049 */

#endif /* OS_MISC_H */
