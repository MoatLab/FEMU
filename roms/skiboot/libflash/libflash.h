// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#ifndef __LIBFLASH_H
#define __LIBFLASH_H

#include <stdint.h>
#include <stdbool.h>
#include <libflash/blocklevel.h>

/* API status/return:
 *
 *  <0 = flash controller errors passed through,
 *  0  = success
 *  >0 = libflash error
 */
#include <libflash/errors.h>

#ifndef MIN
#define MIN(a, b)	((a) < (b) ? (a) : (b))
#endif

/* Flash chip, opaque */
struct flash_chip;
struct spi_flash_ctrl;

int flash_init(struct spi_flash_ctrl *ctrl, struct blocklevel_device **bl,
		struct flash_chip **flash_chip);
void flash_exit(struct blocklevel_device *bl);

/*
 * Function which till call close on the underlying struct spi_flash_ctrl
 */
void flash_exit_close(struct blocklevel_device *bl, void (*close)(struct spi_flash_ctrl *ctrl));

/* libflash sets the 4b mode automatically based on the flash
 * size and controller capabilities but it can be overriden
 */
int flash_force_4b_mode(struct flash_chip *c, bool enable_4b);

/*
 * This provides a wapper around flash_read() on ECCed data. All params are
 * the same as to flash_read(). Not passing true in ecc is akin to calling
 * flash_read() directly.
 *
 * len is length of data without ecc attached therefore this will read beyond
 * pos + len.
 */
int flash_read_corrected(struct blocklevel_device *bl, uint32_t pos, void *buf,
		uint32_t len, bool ecc);

/*
 * This provides a wrapper around flash_write() on ECCed data. All params are
 * the same as to flash_write(). Not passing true in ecc is akin to calling
 * flash_write() directly.
 *
 * size is length of data without ECC attached therefore this will write beyond
 * dst + size.
 */
int flash_write_corrected(struct blocklevel_device *bl, uint32_t dst, const void *src,
		uint32_t size, bool verify, bool ecc);

/*
 * This provides a wrapper around flash_smart_write() on ECCed data. All
 * params are the same as to flash_smart_write(). Not passing true in ecc is
 * akin to calling flash_smart_write() directly.
 *
 * size is length of data without ECC attached therefore this will write beyond
 * dst + size.
 */
int flash_smart_write_corrected(struct blocklevel_device *bl, uint32_t dst, const void *src,
		      uint32_t size, bool ecc);

/* chip erase may not be supported by all chips/controllers, get ready
 * for FLASH_ERR_CHIP_ER_NOT_SUPPORTED
 */
int flash_erase_chip(struct flash_chip *c);

#endif /* __LIBFLASH_H */
