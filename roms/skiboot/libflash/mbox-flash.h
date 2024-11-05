// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2017 IBM Corp. */

#ifndef __LIBFLASH_MBOX_FLASH_H
#define __LIBFLASH_MBOX_FLASH_H

int mbox_flash_lock(struct blocklevel_device *bl, uint64_t pos, uint64_t len);
int mbox_flash_init(struct blocklevel_device **bl);
bool mbox_flash_exit(struct blocklevel_device *bl);
#endif /* __LIBFLASH_MBOX_FLASH_H */


