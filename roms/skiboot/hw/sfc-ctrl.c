// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2014 IBM Corp. */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <lpc.h>
#include <sfc-ctrl.h>

#include <libflash/libflash.h>
#include <libflash/libflash-priv.h>

/* Offset of SFC registers in FW space */
#define SFC_CMDREG_OFFSET	0x00000c00
/* Offset of SFC command buffer in FW space */
#define	SFC_CMDBUF_OFFSET	0x00000d00
/* Offset of flash MMIO mapping in FW space */
#define SFC_MMIO_OFFSET		0x0c000000


/*
 * Register definitions
 */
#define SFC_REG_CONF      0x10 /* CONF: Direct Access Configuration */
#define SFC_REG_CONF_FRZE		(1 << 3)
#define SFC_REG_CONF_ECCEN		(1 << 2)
#define SFC_REG_CONF_DRCD		(1 << 1)
#define SFC_REG_CONF_FLRLD		(1 << 0)

#define SFC_REG_STATUS    0x0C /* STATUS : Status Reg */
#define SFC_REG_STATUS_NX_ON_SHFT	28
#define SFC_REG_STATUS_RWP		(1 << 27)
#define SFC_REG_STATUS_FOURBYTEAD	(1 << 26)
#define SFC_REG_STATUS_ILLEGAL		(1 << 4)
#define SFC_REG_STATUS_ECCERRCNTN	(1 << 3)
#define SFC_REG_STATUS_ECCUEN		(1 << 2)
#define SFC_REG_STATUS_DONE		(1 << 0)

#define SFC_REG_CMD       0x40 /* CMD : Command */
#define SFC_REG_CMD_OPCODE_SHFT		9
#define SFC_REG_CMD_LENGTH_SHFT		0

#define SFC_REG_SPICLK    0x3C /* SPICLK: SPI clock rate config */
#define SFC_REG_SPICLK_OUTDLY_SHFT	24
#define SFC_REG_SPICLK_INSAMPDLY_SHFT	16
#define SFC_REG_SPICLK_CLKHI_SHFT	8
#define SFC_REG_SPICLK_CLKLO_SHFT	0

#define SFC_REG_ADR       0x44 /* ADR : Address */
#define SFC_REG_ERASMS    0x48 /* ERASMS : Small Erase Block Size */
#define SFC_REG_ERASLGS   0x4C /* ERALGS : Large Erase Block Size */
#define SFC_REG_CONF4     0x54 /* CONF4  : SPI Op Code for Small Erase */
#define SFC_REG_CONF5     0x58 /* CONF5  : Small Erase Size config reg */

#define SFC_REG_CONF8     0x64 /* CONF8  : Read Command */
#define SFC_REG_CONF8_CSINACTIVERD_SHFT	18
#define SFC_REG_CONF8_DUMMY_SHFT	8
#define SFC_REG_CONF8_READOP_SHFT	0

#define SFC_REG_ADRCBF    0x80 /* ADRCBF : First Intf NOR Addr Offset */
#define SFC_REG_ADRCMF    0x84 /* ADRCMF : First Intf NOR Allocation */
#define SFC_REG_ADRCBS    0x88 /* ADRCBS : Second Intf NOR Addr Offset */
#define SFC_REG_ADRCMS    0x8C /* ADRCMS : Second Intf NOR Allocation */
#define SFC_REG_OADRNB    0x90 /* OADRNB : Direct Access OBP Window Base Address */
#define SFC_REG_OADRNS    0x94 /* OADRNS : DIrect Access OPB Window Size */

#define SFC_REG_CHIPIDCONF    0x9C /* CHIPIDCONF : config ChipId CMD */
#define SFC_REG_CHIPIDCONF_OPCODE_SHFT	24
#define SFC_REG_CHIPIDCONF_READ		(1 << 23)
#define SFC_REG_CHIPIDCONF_WRITE	(1 << 22)
#define SFC_REG_CHIPIDCONF_USE_ADDR	(1 << 21)
#define SFC_REG_CHIPIDCONF_DUMMY_SHFT	16
#define SFC_REG_CHIPIDCONF_LEN_SHFT	0

/*
 * SFC Opcodes
 */
#define SFC_OP_READRAW      0x03 /* Read Raw */
#define SFC_OP_WRITERAW     0x02 /* Write Raw */
#define SFC_OP_ERASM        0x32 /* Erase Small */
#define SFC_OP_ERALG        0x34 /* Erase Large */
#define SFC_OP_ENWRITPROT   0x53 /* Enable WRite Protect */
#define SFC_OP_CHIPID       0x1F /* Get Chip ID */
#define SFC_OP_STATUS       0x05 /* Get Status */
#define SFC_OP_TURNOFF      0x5E /* Turn Off */
#define SFC_OP_TURNON       0x50 /* Turn On */
#define SFC_OP_ABORT        0x6F /* Super-Abort */
#define SFC_OP_START4BA     0x37 /* Start 4BA */
#define SFC_OP_END4BA       0x69 /* End 4BA */

/* Command buffer size */
#define SFC_CMDBUF_SIZE     256

struct sfc_ctrl {
	/* Erase sizes */
	uint32_t		small_er_size;
	uint32_t		large_er_size;

	/* Current 4b mode */
	bool			mode_4b;

	/* Callbacks */
	struct spi_flash_ctrl	ops;
};

/* Command register support */
static inline int sfc_reg_read(uint8_t reg, uint32_t *val)
{
	int rc;

	*val = 0xffffffff;
	rc = lpc_fw_read32(val, SFC_CMDREG_OFFSET + reg);
	if (rc)
		return rc;
	return 0;
}

static inline int sfc_reg_write(uint8_t reg, uint32_t val)
{
	return lpc_fw_write32(val, SFC_CMDREG_OFFSET + reg);
}

static int sfc_buf_write(uint32_t len, const void *data)
{
	__be32 tmp;
	uint32_t off = 0;
	int rc;

	if (len > SFC_CMDBUF_SIZE)
		return FLASH_ERR_PARM_ERROR;

	while (len >= 4) {
		tmp = cpu_to_be32(*(const uint32_t *)data);
		rc = lpc_fw_write32((u32)tmp, SFC_CMDBUF_OFFSET + off);
		if (rc)
			return rc;
		off += 4;
		len -= 4;
		data += 4;
	}
	if (!len)
		return 0;

	/* lpc_fw_write operates on BE values so that's what we layout
	 * in memory with memcpy. The swap in the register on LE doesn't
	 * matter, the result in memory will be in the right order.
	 */
	tmp = cpu_to_be32(-1);
	memcpy(&tmp, data, len); /* XXX: is this right? */
	return lpc_fw_write32((u32)tmp, SFC_CMDBUF_OFFSET + off);
}

static int sfc_buf_read(uint32_t len, void *data)
{
	uint32_t tmp, off = 0;
	int rc;

	if (len > SFC_CMDBUF_SIZE)
		return FLASH_ERR_PARM_ERROR;

	while (len >= 4) {
		rc = lpc_fw_read32(data, SFC_CMDBUF_OFFSET + off);
		if (rc)
			return rc;
		off += 4;
		len -= 4;
		data += 4;
	}
	if (!len)
		return 0;

	rc = lpc_fw_read32(&tmp, SFC_CMDBUF_OFFSET + off);
	if (rc)
		return rc;
	/* We know tmp contains a big endian value, so memcpy is
	 * our friend here
	 */
	memcpy(data, &tmp, len);
	return 0;
}

/* Polls until SFC indicates command is complete */
static int sfc_poll_complete(void)
{
	uint32_t status, timeout;
	struct timespec ts;

	/*
	 * A full 256 bytes read/write command will take at least
	 * 126us. Smaller commands are faster but we use less of
	 * them. So let's sleep in increments of 100us
	 */
	ts.tv_sec = 0;
	ts.tv_nsec = 100000;

	/*
	 * Use a 1s timeout which should be sufficient for the
	 * commands we use
	 */
	timeout = 10000;

	do {
		int rc;

		rc = sfc_reg_read(SFC_REG_STATUS, &status);
		if (rc)
			return rc;
		if (status & SFC_REG_STATUS_DONE)
			break;
		if (--timeout == 0)
			return FLASH_ERR_CTRL_TIMEOUT;
		nanosleep(&ts, NULL);
	} while (true);

	return 0;
}

static int sfc_exec_command(uint8_t opcode, uint32_t length)
{
	int rc = 0;
	uint32_t cmd_reg = 0;

	if (opcode > 0x7f || length > 0x1ff)
		return FLASH_ERR_PARM_ERROR;

	/* Write command register to start execution */
	cmd_reg |= (opcode << SFC_REG_CMD_OPCODE_SHFT);
	cmd_reg |= (length << SFC_REG_CMD_LENGTH_SHFT);
	rc = sfc_reg_write(SFC_REG_CMD, cmd_reg);
	if (rc)
		return rc;

	/* Wait for command to complete */
	return sfc_poll_complete();
}

static int sfc_chip_id(struct spi_flash_ctrl *ctrl, uint8_t *id_buf,
		       uint32_t *id_size)
{
	uint32_t idconf;
	int rc;

	(void)ctrl;

	if ((*id_size) < 3)
		return FLASH_ERR_PARM_ERROR;

	/*
	 * XXX This will not work in locked down mode but we assume that
	 * in this case, the chip ID command is already properly programmed
	 * and the SFC will ignore this. However I haven't verified...
	 */
	idconf = ((uint64_t)CMD_RDID) << SFC_REG_CHIPIDCONF_OPCODE_SHFT;
	idconf |= SFC_REG_CHIPIDCONF_READ;
        idconf |= (3ul << SFC_REG_CHIPIDCONF_LEN_SHFT);
	(void)sfc_reg_write(SFC_REG_CHIPIDCONF, idconf);

	/* Perform command */
	rc = sfc_exec_command(SFC_OP_CHIPID, 0);
	if (rc)
		return rc;

	/* Read chip ID */
        rc = sfc_buf_read(3, id_buf);
	if (rc)
		return rc;
	*id_size = 3;

	return 0;
}


static int sfc_read(struct spi_flash_ctrl *ctrl, uint32_t pos,
		    void *buf, uint32_t len)
{
	(void)ctrl;

	while(len) {
		uint32_t chunk = len;
		int rc;

		if (chunk > SFC_CMDBUF_SIZE)
			chunk = SFC_CMDBUF_SIZE;
		rc = sfc_reg_write(SFC_REG_ADR, pos);
		if (rc)
			return rc;
		rc = sfc_exec_command(SFC_OP_READRAW, chunk);
		if (rc)
			return rc;
		rc = sfc_buf_read(chunk, buf);
		if (rc)
			return rc;
		len -= chunk;
		pos += chunk;
		buf += chunk;
	}
	return 0;
}

static int sfc_write(struct spi_flash_ctrl *ctrl, uint32_t addr,
		     const void *buf, uint32_t size)
{
	uint32_t chunk;
	int rc;

	(void)ctrl;

	while(size) {
		/* We shall not cross a page boundary */
		chunk = 0x100 - (addr & 0xff);
		if (chunk > size)
			chunk = size;

		/* Write to SFC write buffer */
		rc = sfc_buf_write(chunk, buf);
		if (rc)
			return rc;

		/* Program address */
		rc = sfc_reg_write(SFC_REG_ADR, addr);
		if (rc)
			return rc;

		/* Send command */
		rc = sfc_exec_command(SFC_OP_WRITERAW, chunk);
		if (rc)
			return rc;

		addr += chunk;
		buf += chunk;
		size -= chunk;
	}
	return 0;
}

static int sfc_erase(struct spi_flash_ctrl *ctrl, uint32_t addr,
		     uint32_t size)
{
	struct sfc_ctrl *ct = container_of(ctrl, struct sfc_ctrl, ops);
	uint32_t sm_mask = ct->small_er_size - 1;
	uint32_t lg_mask = ct->large_er_size - 1;
	uint32_t chunk;
	uint8_t cmd;
	int rc;

	while(size) {
		/* Choose erase size for this chunk */
		if (((addr | size) & lg_mask) == 0) {
			chunk = ct->large_er_size;
			cmd = SFC_OP_ERALG;
		} else if (((addr | size) & sm_mask) == 0) {
			chunk = ct->small_er_size;
			cmd = SFC_OP_ERASM;
		} else
			return FLASH_ERR_ERASE_BOUNDARY;

		rc = sfc_reg_write(SFC_REG_ADR, addr);
		if (rc)
			return rc;
		rc = sfc_exec_command(cmd, 0);
		if (rc)
			return rc;
		addr += chunk;
		size -= chunk;
	}
	return 0;
}

static int sfc_setup(struct spi_flash_ctrl *ctrl, uint32_t *tsize)
{
	struct sfc_ctrl *ct = container_of(ctrl, struct sfc_ctrl, ops);
	struct flash_info *info = ctrl->finfo;
	uint32_t er_flags;

	(void)tsize;

	/* Keep non-erase related flags */
	er_flags = ~FL_ERASE_ALL;

	/* Add supported erase sizes */
	if (ct->small_er_size == 0x1000 || ct->large_er_size == 0x1000)
		er_flags |= FL_ERASE_4K;
	if (ct->small_er_size == 0x8000 || ct->large_er_size == 0x8000)
		er_flags |= FL_ERASE_32K;
	if (ct->small_er_size == 0x10000 || ct->large_er_size == 0x10000)
		er_flags |= FL_ERASE_64K;

	/* Mask the flags out */
	info->flags &= er_flags;

	return 0;
}

static int sfc_set_4b(struct spi_flash_ctrl *ctrl, bool enable)
{
	struct sfc_ctrl *ct = container_of(ctrl, struct sfc_ctrl, ops);
	int rc;

	rc = sfc_exec_command(enable ? SFC_OP_START4BA : SFC_OP_END4BA, 0);
	if (rc)
		return rc;
	ct->mode_4b = enable;
	return 0;
}

static void sfc_validate_er_size(uint32_t *size)
{
	if (*size == 0)
		return;

	/* We only support 4k, 32k and 64k */
	if (*size != 0x1000 && *size != 0x8000 && *size != 0x10000) {
		FL_ERR("SFC: Erase size %d bytes unsupported\n", *size);
		*size = 0;
	}
}

static int sfc_init(struct sfc_ctrl *ct)
{
	int rc;
	uint32_t status;

	/*
	 * Assumptions: The controller has been fully initialized
	 * by an earlier FW layer setting the chip ID command, the
	 * erase sizes, and configuring the timings for reads and
	 * writes.
	 *
	 * This driver is meant to be usable if the configuration
	 * is in lock down.
	 *
	 * If that wasn't the case, we could configure some sane
	 * defaults here and tuned values in setup() after the
	 * chip has been identified.
	 */

	/* Read erase sizes from flash */
	rc = sfc_reg_read(SFC_REG_ERASMS, &ct->small_er_size);
	if (rc)
		return rc;
	sfc_validate_er_size(&ct->small_er_size);
	rc = sfc_reg_read(SFC_REG_ERASLGS, &ct->large_er_size);
	if (rc)
		return rc;
	sfc_validate_er_size(&ct->large_er_size);

	/* No erase sizes we can cope with ? Ouch... */
	if ((ct->small_er_size == 0 && ct->large_er_size == 0) ||
	    (ct->large_er_size && (ct->small_er_size > ct->large_er_size))) {
		FL_ERR("SFC: No supported erase sizes !\n");
		return FLASH_ERR_CTRL_CONFIG_MISMATCH;
	}

	FL_INF("SFC: Suppored erase sizes:");
	if (ct->small_er_size)
		FL_INF(" %dKB", ct->small_er_size >> 10);
	if (ct->large_er_size)
		FL_INF(" %dKB", ct->large_er_size >> 10);
	FL_INF("\n");

	/* Read current state of 4 byte addressing */
	rc = sfc_reg_read(SFC_REG_STATUS, &status);
	if (rc)
		return rc;
	ct->mode_4b = !!(status & SFC_REG_STATUS_FOURBYTEAD);

	return 0;
}

int sfc_open(struct spi_flash_ctrl **ctrl)
{
	struct sfc_ctrl *ct;
	int rc;

	*ctrl = NULL;
	ct = malloc(sizeof(*ct));
	if (!ct) {
		FL_ERR("SFC: Failed to allocate\n");
		return FLASH_ERR_MALLOC_FAILED;
	}
	memset(ct, 0, sizeof(*ct));
	ct->ops.chip_id = sfc_chip_id;
	ct->ops.setup = sfc_setup;
	ct->ops.set_4b = sfc_set_4b;
	ct->ops.read = sfc_read;
	ct->ops.write = sfc_write;
	ct->ops.erase = sfc_erase;

	rc = sfc_init(ct);
	if (rc)
		goto fail;
	*ctrl = &ct->ops;
	return 0;
 fail:
	free(ct);
	return rc;
}

void sfc_close(struct spi_flash_ctrl *ctrl)
{
	struct sfc_ctrl *ct = container_of(ctrl, struct sfc_ctrl, ops);

	/* Free the whole lot */
	free(ct);
}

