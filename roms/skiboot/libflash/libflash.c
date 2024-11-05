// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2017 IBM Corp. */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "libflash.h"
#include "libflash-priv.h"
#include "ecc.h"
#include "blocklevel.h"

static const struct flash_info flash_info[] = {
	{ 0xc22018, 0x01000000, FL_ERASE_ALL | FL_CAN_4B, "Macronix MXxxL12835F"},
	{ 0xc22019, 0x02000000, FL_ERASE_ALL | FL_CAN_4B, "Macronix MXxxL25635F"},
	{ 0xc2201a, 0x04000000, FL_ERASE_ALL | FL_CAN_4B, "Macronix MXxxL51235F"},
	{ 0xc2201b, 0x08000000, FL_ERASE_ALL | FL_CAN_4B, "Macronix MX66L1G45G"},
	{ 0xef4018, 0x01000000, FL_ERASE_ALL,             "Winbond W25Q128BV"   },
	{ 0xef4019, 0x02000000, FL_ERASE_ALL | FL_ERASE_64K | FL_CAN_4B |
				FL_ERASE_BULK,
							"Winbond W25Q256BV"},
	{ 0x20ba20, 0x04000000, FL_ERASE_4K  | FL_ERASE_64K | FL_CAN_4B |
                                FL_ERASE_BULK | FL_MICRON_BUGS,
                                                          "Micron N25Qx512Ax"   },
	{ 0x20ba19, 0x02000000, FL_ERASE_4K  | FL_ERASE_64K | FL_CAN_4B |
                                FL_ERASE_BULK | FL_MICRON_BUGS,
                                                          "Micron N25Q256Ax"    },
	{ 0x1940ef, 0x02000000, FL_ERASE_4K  | FL_ERASE_64K | FL_CAN_4B |
				FL_ERASE_BULK | FL_MICRON_BUGS,
							"Micron N25Qx256Ax"   },
	{ 0x4d5444, 0x02000000, FL_ERASE_ALL | FL_CAN_4B, "File Abstraction"},
	{ 0x55aa55, 0x00100000, FL_ERASE_ALL | FL_CAN_4B, "TEST_FLASH" },
	{ 0xaa55aa, 0x02000000, FL_ERASE_ALL | FL_CAN_4B, "EMULATED_FLASH"},
};

struct flash_chip {
	struct spi_flash_ctrl	*ctrl;		/* Controller */
	struct flash_info	info;		/* Flash info */
	uint32_t		tsize;		/* Corrected flash size */
	uint32_t		min_erase_mask;	/* Minimum erase size */
	bool			mode_4b;	/* Flash currently in 4b mode */
	struct flash_req	*cur_req;	/* Current request */
	void			*smart_buf;	/* Buffer for smart writes */
	struct blocklevel_device bl;
};

#ifndef __SKIBOOT__
bool libflash_debug;
#endif

int fl_read_stat(struct spi_flash_ctrl *ct, uint8_t *stat)
{
	return ct->cmd_rd(ct, CMD_RDSR, false, 0, stat, 1);
}

static void fl_micron_status(struct spi_flash_ctrl *ct)
{
	uint8_t flst;

	/*
	 * After a success status on a write or erase, we
	 * need to do that command or some chip variants will
	 * lock
	 */
	ct->cmd_rd(ct, CMD_MIC_RDFLST, false, 0, &flst, 1);
}

/* Synchronous write completion, probably need a yield hook */
int fl_sync_wait_idle(struct spi_flash_ctrl *ct)
{
	uint8_t stat;
	int rc;

	/* XXX Add timeout */
	for (;;) {
		rc = fl_read_stat(ct, &stat);
		if (rc) return rc;
		if (!(stat & STAT_WIP)) {
			if (ct->finfo->flags & FL_MICRON_BUGS)
				fl_micron_status(ct);
			return 0;
		}
	}
	/* return FLASH_ERR_WIP_TIMEOUT; */
}

/* Exported for internal use */
int fl_wren(struct spi_flash_ctrl *ct)
{
	int i, rc;
	uint8_t stat;

	/* Some flashes need it to be hammered */
	for (i = 0; i < 1000; i++) {
		rc = ct->cmd_wr(ct, CMD_WREN, false, 0, NULL, 0);
		if (rc) return rc;
		rc = fl_read_stat(ct, &stat);
		if (rc) return rc;
		if (stat & STAT_WIP) {
			FL_ERR("LIBFLASH: WREN has WIP status set !\n");
			rc = fl_sync_wait_idle(ct);
			if (rc)
				return rc;
			continue;
		}
		if (stat & STAT_WEN)
			return 0;
	}
	return FLASH_ERR_WREN_TIMEOUT;
}

static int flash_read(struct blocklevel_device *bl, uint64_t pos, void *buf, uint64_t len)
{
	struct flash_chip *c = container_of(bl, struct flash_chip, bl);
	struct spi_flash_ctrl *ct = c->ctrl;

	/* XXX Add sanity/bound checking */

	/*
	 * If the controller supports read and either we are in 3b mode
	 * or we are in 4b *and* the controller supports it, then do a
	 * high level read.
	 */
	if ((!c->mode_4b || ct->set_4b) && ct->read)
		return ct->read(ct, pos, buf, len);

	/* Otherwise, go manual if supported */
	if (!ct->cmd_rd)
		return FLASH_ERR_CTRL_CMD_UNSUPPORTED;
	return ct->cmd_rd(ct, CMD_READ, true, pos, buf, len);
}

#define COPY_BUFFER_LENGTH 4096

/*
 * This provides a wrapper around flash_read on ECCed data
 * len is length of data without ECC attached
 */
int flash_read_corrected(struct blocklevel_device *bl, uint32_t pos, void *buf,
		uint32_t len, bool ecc)
{
	struct ecc64 *bufecc;
	uint32_t copylen;
	int rc;
	uint8_t ret;

	if (!ecc)
		return flash_read(bl, pos, buf, len);

	/* Copy the buffer in chunks */
	bufecc = malloc(ecc_buffer_size(COPY_BUFFER_LENGTH));
	if (!bufecc)
		return FLASH_ERR_MALLOC_FAILED;

	while (len > 0) {
		/* What's left to copy? */
		copylen = MIN(len, COPY_BUFFER_LENGTH);

		/* Read ECCed data from flash */
		rc = flash_read(bl, pos, bufecc, ecc_buffer_size(copylen));
		if (rc)
			goto err;

		/* Extract data from ECCed data */
		ret = memcpy_from_ecc(buf, bufecc, copylen);
		if (ret) {
			rc = FLASH_ERR_ECC_INVALID;
			goto err;
		}

		/* Update for next copy */
		len -= copylen;
		buf = (uint8_t *)buf + copylen;
		pos += ecc_buffer_size(copylen);
	}

	rc = 0;

err:
	free(bufecc);
	return rc;
}

static void fl_get_best_erase(struct flash_chip *c, uint32_t dst, uint32_t size,
			      uint32_t *chunk, uint8_t *cmd)
{
	/* Smaller than 32k, use 4k */
	if ((dst & 0x7fff) || (size < 0x8000)) {
		*chunk = 0x1000;
		*cmd = CMD_SE;
		return;
	}
	/* Smaller than 64k and 32k is supported, use it */
	if ((c->info.flags & FL_ERASE_32K) &&
	    ((dst & 0xffff) || (size < 0x10000))) {
		*chunk = 0x8000;
		*cmd = CMD_BE32K;
		return;
	}
	/* If 64K is not supported, use whatever smaller size is */
	if (!(c->info.flags & FL_ERASE_64K)) {
		if (c->info.flags & FL_ERASE_32K) {
			*chunk = 0x8000;
			*cmd = CMD_BE32K;
		} else {
			*chunk = 0x1000;
			*cmd = CMD_SE;
		}
		return;
	}
	/* Allright, let's go for 64K */
	*chunk = 0x10000;
	*cmd = CMD_BE;
}

static int flash_erase(struct blocklevel_device *bl, uint64_t dst, uint64_t size)
{
	struct flash_chip *c = container_of(bl, struct flash_chip, bl);
	struct spi_flash_ctrl *ct = c->ctrl;
	uint32_t chunk;
	uint8_t cmd;
	int rc;

	/* Some sanity checking */
	if (((dst + size) <= dst) || !size || (dst + size) > c->tsize)
		return FLASH_ERR_PARM_ERROR;

	/* Check boundaries fit erase blocks */
	if ((dst | size) & c->min_erase_mask)
		return FLASH_ERR_ERASE_BOUNDARY;

	FL_DBG("LIBFLASH: Erasing 0x%" PRIx64"..0%" PRIx64 "...\n",
	       dst, dst + size);

	/* Use controller erase if supported */
	if (ct->erase)
		return ct->erase(ct, dst, size);

	/* Allright, loop as long as there's something to erase */
	while(size) {
		/* How big can we make it based on alignent & size */
		fl_get_best_erase(c, dst, size, &chunk, &cmd);

		/* Poke write enable */
		rc = fl_wren(ct);
		if (rc)
			return rc;

		/* Send erase command */
		rc = ct->cmd_wr(ct, cmd, true, dst, NULL, 0);
		if (rc)
			return rc;

		/* Wait for write complete */
		rc = fl_sync_wait_idle(ct);
		if (rc)
			return rc;

		size -= chunk;
		dst += chunk;
	}
	return 0;
}

int flash_erase_chip(struct flash_chip *c)
{
	struct spi_flash_ctrl *ct = c->ctrl;
	int rc;

	/* XXX TODO: Fallback to using normal erases */
	if (!(c->info.flags & (FL_ERASE_CHIP|FL_ERASE_BULK)))
		return FLASH_ERR_CHIP_ER_NOT_SUPPORTED;

	FL_DBG("LIBFLASH: Erasing chip...\n");
	
	/* Use controller erase if supported */
	if (ct->erase)
		return ct->erase(ct, 0, 0xffffffff);

	rc = fl_wren(ct);
	if (rc) return rc;

	if (c->info.flags & FL_ERASE_CHIP)
		rc = ct->cmd_wr(ct, CMD_CE, false, 0, NULL, 0);
	else
		rc = ct->cmd_wr(ct, CMD_MIC_BULK_ERASE, false, 0, NULL, 0);
	if (rc)
		return rc;

	/* Wait for write complete */
	return fl_sync_wait_idle(ct);
}

static int fl_wpage(struct flash_chip *c, uint32_t dst, const void *src,
		    uint32_t size)
{
	struct spi_flash_ctrl *ct = c->ctrl;
	int rc;

	if (size < 1 || size > 0x100)
		return FLASH_ERR_BAD_PAGE_SIZE;

	rc = fl_wren(ct);
	if (rc) return rc;

	rc = ct->cmd_wr(ct, CMD_PP, true, dst, src, size);
	if (rc)
		return rc;

	/* Wait for write complete */
	return fl_sync_wait_idle(ct);
}

static int flash_write(struct blocklevel_device *bl, uint32_t dst, const void *src,
		uint32_t size, bool verify)
{
	struct flash_chip *c = container_of(bl, struct flash_chip, bl);
	struct spi_flash_ctrl *ct = c->ctrl;
	uint32_t todo = size;
	uint32_t d = dst;
	const void *s = src;
	uint8_t vbuf[0x100];
	int rc;	

	/* Some sanity checking */
	if (((dst + size) <= dst) || !size || (dst + size) > c->tsize)
		return FLASH_ERR_PARM_ERROR;

	FL_DBG("LIBFLASH: Writing to 0x%08x..0%08x...\n", dst, dst + size);

	/*
	 * If the controller supports write and either we are in 3b mode
	 * or we are in 4b *and* the controller supports it, then do a
	 * high level write.
	 */
	if ((!c->mode_4b || ct->set_4b) && ct->write) {
		rc = ct->write(ct, dst, src, size);
		if (rc)
			return rc;
		goto writing_done;
	}

	/* Otherwise, go manual if supported */
	if (!ct->cmd_wr)
		return FLASH_ERR_CTRL_CMD_UNSUPPORTED;

	/* Iterate for each page to write */
	while(todo) {
		uint32_t chunk;

		/* Handle misaligned start */
		chunk = 0x100 - (d & 0xff);
		if (chunk > todo)
			chunk = todo;

		rc = fl_wpage(c, d, s, chunk);
		if (rc) return rc;
		d += chunk;
		s += chunk;
		todo -= chunk;
	}

 writing_done:
	if (!verify)
		return 0;

	/* Verify */
	FL_DBG("LIBFLASH: Verifying...\n");

	while(size) {
		uint32_t chunk;

		chunk = sizeof(vbuf);
		if (chunk > size)
			chunk = size;
		rc = flash_read(bl, dst, vbuf, chunk);
		if (rc) return rc;
		if (memcmp(vbuf, src, chunk)) {
			FL_ERR("LIBFLASH: Miscompare at 0x%08x\n", dst);
			return FLASH_ERR_VERIFY_FAILURE;
		}
		dst += chunk;
		src += chunk;
		size -= chunk;
	}
	return 0;
}

int flash_write_corrected(struct blocklevel_device *bl, uint32_t pos, const void *buf,
		uint32_t len, bool verify, bool ecc)
{
	struct ecc64 *bufecc;
	uint32_t copylen, copylen_minus_ecc;
	int rc;
	uint8_t ret;

	if (!ecc)
		return flash_write(bl, pos, buf, len, verify);

	/* Copy the buffer in chunks */
	bufecc = malloc(ecc_buffer_size(COPY_BUFFER_LENGTH));
	if (!bufecc)
		return FLASH_ERR_MALLOC_FAILED;

	while (len > 0) {
		/* What's left to copy? */
		copylen = MIN(len, COPY_BUFFER_LENGTH);
		copylen_minus_ecc = ecc_buffer_size_minus_ecc(copylen);

		/* Add the ecc byte to the data */
		ret = memcpy_to_ecc(bufecc, buf, copylen_minus_ecc);
		if (ret) {
			rc = FLASH_ERR_ECC_INVALID;
			goto err;
		}

		/* Write ECCed data to the flash */
		rc = flash_write(bl, pos, bufecc, copylen, verify);
		if (rc)
			goto err;

		/* Update for next copy */
		len -= copylen_minus_ecc;
		buf = (uint8_t *)buf + copylen_minus_ecc;
		pos += copylen;
	}

	rc = 0;

err:
	free(bufecc);
	return rc;
}

enum sm_comp_res {
	sm_no_change,
	sm_need_write,
	sm_need_erase,
};

static enum sm_comp_res flash_smart_comp(struct flash_chip *c,
					 const void *src,
					 uint32_t offset, uint32_t size)
{
	uint8_t *b = c->smart_buf + offset;
	const uint8_t *s = src;
	bool is_same = true;
	uint32_t i;

	/* SRC DEST  NEED_ERASE
	 *  0   1       0
	 *  1   1       0
         *  0   0       0
         *  1   0       1
         */
	for (i = 0; i < size; i++) {
		/* Any bit need to be set, need erase */
		if (s[i] & ~b[i])
			return sm_need_erase;
		if (is_same && (b[i] != s[i]))
			is_same = false;
	}
	return is_same ? sm_no_change : sm_need_write;
}

static int flash_smart_write(struct blocklevel_device *bl, uint64_t dst, const void *src, uint64_t size)
{
	struct flash_chip *c = container_of(bl, struct flash_chip, bl);
	uint32_t er_size = c->min_erase_mask + 1;
	uint32_t end = dst + size;
	int rc;

	/* Some sanity checking */
	if (end <= dst || !size || end > c->tsize) {
		FL_DBG("LIBFLASH: Smart write param error\n");
		return FLASH_ERR_PARM_ERROR;
	}

	FL_DBG("LIBFLASH: Smart writing to 0x%" PRIx64 "..0%" PRIx64 "...\n",
	       dst, dst + size);

	/* As long as we have something to write ... */
	while(dst < end) {
		uint32_t page, off, chunk;
		enum sm_comp_res sr;

		/* Figure out which erase page we are in and read it */
		page = dst & ~c->min_erase_mask;
		off = dst & c->min_erase_mask;
		FL_DBG("LIBFLASH:   reading page 0x%08x..0x%08x...\n",
		       page, page + er_size);
		rc = flash_read(bl, page, c->smart_buf, er_size);
		if (rc) {
			FL_DBG("LIBFLASH:    ...error %d!\n", rc);
			return rc;
		}

		/* Locate the chunk of data we are working on */
		chunk = er_size - off;
		if (size < chunk)
			chunk = size;

		/* Compare against what we are writing and ff */
		sr = flash_smart_comp(c, src, off, chunk);
		switch(sr) {
		case sm_no_change:
			/* Identical, skip it */
			FL_DBG("LIBFLASH:    ...same !\n");
			break;
		case sm_need_write:
			/* Just needs writing over */
			FL_DBG("LIBFLASH:    ...need write !\n");
			rc = flash_write(bl, dst, src, chunk, true);
			if (rc) {
				FL_DBG("LIBFLASH: Write error %d !\n", rc);
				return rc;
			}
			break;
		case sm_need_erase:
			FL_DBG("LIBFLASH:    ...need erase !\n");
			rc = flash_erase(bl, page, er_size);
			if (rc) {
				FL_DBG("LIBFLASH: erase error %d !\n", rc);
				return rc;
			}
			/* Then update the portion of the buffer and write the block */
			memcpy(c->smart_buf + off, src, chunk);
			rc = flash_write(bl, page, c->smart_buf, er_size, true);
			if (rc) {
				FL_DBG("LIBFLASH: write error %d !\n", rc);
				return rc;
			}
			break;
		}
		dst += chunk;
		src += chunk;
		size -= chunk;
	}
	return 0;
}

int flash_smart_write_corrected(struct blocklevel_device *bl, uint32_t dst, const void *src,
		      uint32_t size, bool ecc)
{
	struct ecc64 *buf;
	int rc;

	if (!ecc)
		return flash_smart_write(bl, dst, src, size);

	buf = malloc(ecc_buffer_size(size));
	if (!buf)
		return FLASH_ERR_MALLOC_FAILED;

	rc = memcpy_to_ecc(buf, src, size);
	if (rc) {
		rc = FLASH_ERR_ECC_INVALID;
		goto out;
	}

	rc = flash_smart_write(bl, dst, buf, ecc_buffer_size(size));

out:
	free(buf);
	return rc;
}

static int fl_chip_id(struct spi_flash_ctrl *ct, uint8_t *id_buf,
		      uint32_t *id_size)
{
	int rc;
	uint8_t stat;

	/* Check initial status */
	rc = fl_read_stat(ct, &stat);
	if (rc)
		return rc;

	/* If stuck writing, wait for idle */
	if (stat & STAT_WIP) {
		FL_ERR("LIBFLASH: Flash in writing state ! Waiting...\n");
		rc = fl_sync_wait_idle(ct);
		if (rc)
			return rc;
	} else
		FL_DBG("LIBFLASH: Init status: %02x\n", stat);

	/* Fallback to get ID manually */
	rc = ct->cmd_rd(ct, CMD_RDID, false, 0, id_buf, 3);
	if (rc)
		return rc;
	*id_size = 3;

	return 0;
}

static int flash_identify(struct flash_chip *c)
{
	struct spi_flash_ctrl *ct = c->ctrl;
	const struct flash_info *info = NULL;
	uint32_t iid, id_size;
#define MAX_ID_SIZE	16
	uint8_t id[MAX_ID_SIZE];
	int rc, i;

	if (ct->chip_id) {
		/* High level controller interface */
		id_size = MAX_ID_SIZE;
		rc = ct->chip_id(ct, id, &id_size);
	} else
		rc = fl_chip_id(ct, id, &id_size);
	if (rc)
		return rc;
	if (id_size < 3)
		return FLASH_ERR_CHIP_UNKNOWN;

	/* Convert to a dword for lookup */
	iid = id[0];
	iid = (iid << 8) | id[1];
	iid = (iid << 8) | id[2];

	FL_DBG("LIBFLASH: Flash ID: %02x.%02x.%02x (%06x)\n",
	       id[0], id[1], id[2], iid);

	/* Lookup in flash_info */
	for (i = 0; i < ARRAY_SIZE(flash_info); i++) {
		info = &flash_info[i];
		if (info->id == iid)
			break;		
	}
	if (!info || info->id != iid)
		return FLASH_ERR_CHIP_UNKNOWN;

	c->info = *info;
	c->tsize = info->size;
	ct->finfo = &c->info;

	/*
	 * Let controller know about our settings and possibly
	 * override them
	 */
	if (ct->setup) {
		rc = ct->setup(ct, &c->tsize);
		if (rc)
			return rc;
	}

	/* Calculate min erase granularity */
	if (c->info.flags & FL_ERASE_4K)
		c->min_erase_mask = 0xfff;
	else if (c->info.flags & FL_ERASE_32K)
		c->min_erase_mask = 0x7fff;
	else if (c->info.flags & FL_ERASE_64K)
		c->min_erase_mask = 0xffff;
	else {
		/* No erase size ? oops ... */
		FL_ERR("LIBFLASH: No erase sizes !\n");
		return FLASH_ERR_CTRL_CONFIG_MISMATCH;
	}

	FL_DBG("LIBFLASH: Found chip %s size %dM erase granule: %dK\n",
	       c->info.name, c->tsize >> 20, (c->min_erase_mask + 1) >> 10);

	return 0;
}

static int flash_set_4b(struct flash_chip *c, bool enable)
{
	struct spi_flash_ctrl *ct = c->ctrl;
	int rc;

	/* Don't have low level interface, assume all is well */
	if (!ct->cmd_wr)
		return 0;

	/* Some flash chips want this */
	rc = fl_wren(ct);
	if (rc) {
		FL_ERR("LIBFLASH: Error %d enabling write for set_4b\n", rc);
		/* Ignore the error & move on (could be wrprotect chip) */
	}

	/* Ignore error in case chip is write protected */
	return ct->cmd_wr(ct, enable ? CMD_EN4B : CMD_EX4B, false, 0, NULL, 0);
}

int flash_force_4b_mode(struct flash_chip *c, bool enable_4b)
{
	struct spi_flash_ctrl *ct = c->ctrl;
	int rc = FLASH_ERR_4B_NOT_SUPPORTED;

	/*
	 * We only allow force 4b if both controller and flash do 4b
	 * as this is mainly used if a 3rd party tries to directly
	 * access a direct mapped read region
	 */
	if (enable_4b && !((c->info.flags & FL_CAN_4B) && ct->set_4b))
		return rc;

	/* Only send to flash directly on controllers that implement
	 * the low level callbacks
	 */
	if (ct->cmd_wr) {
		rc = flash_set_4b(c, enable_4b);
		if (rc)
			return rc;
	}

	/* Then inform the controller */
	if (ct->set_4b)
		rc = ct->set_4b(ct, enable_4b);
	return rc;
}

static int flash_configure(struct flash_chip *c)
{
	struct spi_flash_ctrl *ct = c->ctrl;
	int rc;

	/* Crop flash size if necessary */
	if (c->tsize > 0x01000000 && !(c->info.flags & FL_CAN_4B)) {
		FL_ERR("LIBFLASH: Flash chip cropped to 16M, no 4b mode\n");
		c->tsize = 0x01000000;
	}

	/* If flash chip > 16M, enable 4b mode */
	if (c->tsize > 0x01000000) {
		FL_DBG("LIBFLASH: Flash >16MB, enabling 4B mode...\n");

		/* Set flash to 4b mode if we can */
		if (ct->cmd_wr) {
			rc = flash_set_4b(c, true);
			if (rc) {
				FL_ERR("LIBFLASH: Failed to set flash 4b mode\n");
				return rc;
			}
		}


		/* Set controller to 4b mode if supported */
		if (ct->set_4b) {
			FL_DBG("LIBFLASH: Enabling controller 4B mode...\n");
			rc = ct->set_4b(ct, true);
			if (rc) {
				FL_ERR("LIBFLASH: Failed to set controller 4b mode\n");
				return rc;
			}
		}
	} else {
		FL_DBG("LIBFLASH: Flash <=16MB, disabling 4B mode...\n");

		/*
		 * If flash chip supports 4b mode, make sure we disable
		 * it in case it was left over by the previous user
		 */
		if (c->info.flags & FL_CAN_4B) {
			rc = flash_set_4b(c, false);
			if (rc) {
				FL_ERR("LIBFLASH: Failed to"
				       " clear flash 4b mode\n");
				return rc;
			}
		}
		/* Set controller to 3b mode if mode switch is supported */
		if (ct->set_4b) {
			FL_DBG("LIBFLASH: Disabling controller 4B mode...\n");
			rc = ct->set_4b(ct, false);
			if (rc) {
				FL_ERR("LIBFLASH: Failed to"
				       " clear controller 4b mode\n");
				return rc;
			}
		}
	}
	return 0;
}

static int flash_get_info(struct blocklevel_device *bl, const char **name,
		   uint64_t *total_size, uint32_t *erase_granule)
{
	struct flash_chip *c = container_of(bl, struct flash_chip, bl);
	if (name)
		*name = c->info.name;
	if (total_size)
		*total_size = c->tsize;
	if (erase_granule)
		*erase_granule = c->min_erase_mask + 1;
	return 0;
}

int flash_init(struct spi_flash_ctrl *ctrl, struct blocklevel_device **bl,
		struct flash_chip **flash_chip)
{
	struct flash_chip *c;
	int rc;

	if (!bl)
		return FLASH_ERR_PARM_ERROR;

	*bl = NULL;

	c = malloc(sizeof(struct flash_chip));
	if (!c)
		return FLASH_ERR_MALLOC_FAILED;
	memset(c, 0, sizeof(*c));
	c->ctrl = ctrl;

	rc = flash_identify(c);
	if (rc) {
		FL_ERR("LIBFLASH: Flash identification failed\n");
		goto bail;
	}
	c->smart_buf = malloc(c->min_erase_mask + 1);
	if (!c->smart_buf) {
		FL_ERR("LIBFLASH: Failed to allocate smart buffer !\n");
		rc = FLASH_ERR_MALLOC_FAILED;
		goto bail;
	}
	rc = flash_configure(c);
	if (rc)
		FL_ERR("LIBFLASH: Flash configuration failed\n");
bail:
	if (rc) {
		free(c);
		return rc;
	}

	/* The flash backend doesn't support reiniting it */
	c->bl.keep_alive = true;
	c->bl.reacquire = NULL;
	c->bl.release = NULL;
	c->bl.read = &flash_read;
	c->bl.write = &flash_smart_write;
	c->bl.erase = &flash_erase;
	c->bl.get_info = &flash_get_info;
	c->bl.erase_mask = c->min_erase_mask;
	c->bl.flags = WRITE_NEED_ERASE;

	*bl = &(c->bl);
	if (flash_chip)
		*flash_chip = c;

	return 0;
}

void flash_exit(struct blocklevel_device *bl)
{
	/* XXX Make sure we are idle etc... */
	if (bl) {
		struct flash_chip *c = container_of(bl, struct flash_chip, bl);
		free(c->smart_buf);
		free(c);
	}
}

void flash_exit_close(struct blocklevel_device *bl, void (*close)(struct spi_flash_ctrl *ctrl))
{
	if (bl) {
		struct flash_chip *c = container_of(bl, struct flash_chip, bl);
		close(c->ctrl);
		free(c);
	}
}
