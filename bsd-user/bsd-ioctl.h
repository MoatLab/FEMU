/*
 * ioctl system call definitions
 *
 * Copyright (c) 2013 Stacey D. Son
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef BSD_IOCTL_H
#define BSD_IOCTL_H

abi_long do_bsd_ioctl(int fd, abi_long cmd, abi_long arg);
void init_bsd_ioctl(void);

#endif /* BSD_IOCTL_H */
