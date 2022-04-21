// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2015 IBM Corp. */

#ifndef __LIBFLASH_PRIV_H
#define __LIBFLASH_PRIV_H

#include <ccan/endian/endian.h>
#include <ccan/array_size/array_size.h>
#include <ccan/container_of/container_of.h>

/* Flash commands */
#define CMD_WRSR		0x01	/* Write Status Register (also config. on Macronix) */
#define CMD_PP			0x02	/* Page Program */
#define CMD_READ		0x03	/* READ */
#define CMD_WRDI		0x04	/* Write Disable */
#define CMD_RDSR		0x05	/* Read Status Register */
#define CMD_WREN		0x06	/* Write Enable */
#define CMD_RDCR		0x15	/* Read configuration register (Macronix) */
#define CMD_SE			0x20	/* Sector (4K) Erase */
#define CMD_RDSCUR		0x2b	/* Read Security Register (Macronix) */
#define CMD_BE32K		0x52	/* Block (32K) Erase */
#define CMD_RDSFDP		0x5a	/* Read SFDP JEDEC info */
#define CMD_CE			0x60	/* Chip Erase (Macronix/Winbond) */
#define CMD_MIC_WREVCONF	0x61	/* Micron Write Enhanced Volatile Config */
#define CMD_MIC_RDEVCONF       	0x65	/* Micron Read Enhanced Volatile Config */
#define CMD_MIC_RDFLST		0x70	/* Micron Read Flag Status */
#define CMD_MIC_WRVCONF		0x81	/* Micron Write Volatile Config */
#define CMD_MIC_RDVCONF		0x85	/* Micron Read Volatile Config */
#define CMD_RDID		0x9f	/* Read JEDEC ID */
#define CMD_EN4B		0xb7	/* Enable 4B addresses */
#define CMD_MIC_BULK_ERASE	0xc7	/* Micron Bulk Erase */
#define CMD_BE			0xd8	/* Block (64K) Erase */
#define CMD_RDDPB		0xe0	/* Read dynamic protection (Macronix) */
#define CMD_RDSPB		0xe2	/* Read static protection (Macronix) */
#define CMD_EX4B		0xe9	/* Exit 4B addresses */

/* Flash status bits */
#define STAT_WIP	0x01
#define STAT_WEN	0x02

/* This isn't exposed to clients but is to controllers */
struct flash_info {
	uint32_t	id;
	uint32_t	size;
	uint32_t	flags;
#define FL_ERASE_4K	0x00000001	/* Supports 4k erase */
#define FL_ERASE_32K	0x00000002	/* Supports 32k erase */
#define FL_ERASE_64K	0x00000004	/* Supports 64k erase */
#define FL_ERASE_CHIP	0x00000008	/* Supports 0x60 cmd chip erase */
#define FL_ERASE_BULK	0x00000010	/* Supports 0xc7 cmd bulk erase */
#define FL_MICRON_BUGS	0x00000020	/* Various micron bug workarounds */
#define FL_ERASE_ALL	(FL_ERASE_4K | FL_ERASE_32K | FL_ERASE_64K | \
			 FL_ERASE_CHIP)
#define FL_CAN_4B	0x00000010	/* Supports 4b mode */
	const char	*name;
};

/* Flash controller, return negative values for errors */
struct spi_flash_ctrl {
	/*
	 * The controller can provide basically two interfaces,
	 * either a fairly high level one and a lower level one.
	 *
	 * If all functions of the high level interface are
	 * implemented then the low level one is optional. A
	 * controller can implement some of the high level one
	 * in which case the missing ones will be handled by
	 * libflash using the low level interface.
	 *
	 * There are also some common functions.
	 */

	/* **************************************************
	 *             Misc / common functions
	 * **************************************************/

	/*
	 * - setup(ctrl, tsize)
	 *
	 * Provides the controller with an option to configure itself
	 * based on the specific flash type. It can also override some
	 * settings in the info block such as available erase sizes etc...
	 * which can be needed for high level controllers. It can also
	 * override the total flash size.
	 */
	int (*setup)(struct spi_flash_ctrl *ctrl, uint32_t *tsize);

	/*
	 * - set_4b(ctrl, enable)
	 *
	 *  enable    : Switch to 4bytes (true) or 3bytes (false) address mode
	 *
	 * Set the controller's address size. If the controller doesn't
	 * implement the low level command interface, then this must also
	 * configure the flash chip itself. Otherwise, libflash will do it.
	 *
	 * Note that if this isn't implemented, then libflash might still
	 * try to switch large flash chips to 4b mode if the low level cmd
	 * interface is implemented. It will then also stop using the high
	 * level command interface since it's assumed that it cannot handle
	 * 4b addresses.
	 */
	int (*set_4b)(struct spi_flash_ctrl *ctrl, bool enable);



	/* **************************************************
	 *             High level interface
	 * **************************************************/

	/*
	 * Read chip ID. This can return up to 16 bytes though the
	 * current libflash will only use 3 (room for things like
	 * extended micron stuff).
	 *
	 * id_size is set on entry to the buffer size and need to
	 * be adjusted to the actual ID size read.
	 *
	 * If NULL, libflash will use cmd_rd to send normal RDID (0x9f)
	 * command.
	 */
	int (*chip_id)(struct spi_flash_ctrl *ctrl, uint8_t *id_buf,
		       uint32_t *id_size);

	/*
	 * Read from flash. There is no specific constraint on
	 * alignment or size other than not reading outside of
	 * the chip.
	 *
	 * If NULL, libflash will use cmd_rd to send normal
	 * READ (0x03) commands.
	 */
	int (*read)(struct spi_flash_ctrl *ctrl, uint32_t addr, void *buf,
		    uint32_t size);

	/*
	 * Write to flash. There is no specific constraint on
	 * alignment or size other than not reading outside of
	 * the chip. The driver is responsible for handling
	 * 256-bytes page alignment and to send the write enable
	 * commands when needed.
	 *
	 * If absent, libflash will use cmd_wr to send WREN (0x06)
	 * and PP (0x02) commands.
	 *
	 * Note: This does not need to handle erasing. libflash
	 * will ensure that this is never used for changing a bit
	 * value from 0 to 1.
	 */
	int (*write)(struct spi_flash_ctrl *ctrl, uint32_t addr,
		     const void *buf, uint32_t size);

	/*
	 * Erase. This will be called for erasing a portion of
	 * the flash using a granularity (alignment of start and
	 * size) that is no less than the smallest supported
	 * erase size in the info block (*). The driver is
	 * responsible to send write enable commands when needed.
	 *
	 * If absent, libflash will use cmd_wr to send WREN (0x06)
	 * and either of SE (0x20), BE32K (0x52) or BE (0xd8)
	 * based on what the flash chip supports.
	 *
	 * (*) Note: This is called with addr=0 and size=0xffffffff
	 * in which case this is used as a "chip erase". Return
	 * FLASH_ERR_CHIP_ER_NOT_SUPPORTED if not supported. Some
	 * future version of libflash might then emulate it using
	 * normal erase commands.
	 */
	int (*erase)(struct spi_flash_ctrl *ctrl, uint32_t addr,
		     uint32_t size);

	/* **************************************************
	 *             Low level interface
	 * **************************************************/

	/* Note: For commands with no data, libflash will might use
	 *       either cmd_rd or cmd_wr.
	 */
	
	/*
	 * - cmd_rd(ctrl, cmd, has_addr, address, buffer, size);
	 *
	 *   cmd      : command opcode
	 *   has_addr : send an address after the command
	 *   address  : address to send
	 *   buffer   : buffer for additional data to read (or NULL)
	 *   size     : size of additional data read (or NULL)
	 *
	 * Sends a command and optionally read additional data
	 */
	int (*cmd_rd)(struct spi_flash_ctrl *ctrl, uint8_t cmd,
		      bool has_addr, uint32_t addr, void *buffer,
		      uint32_t size);
	/*
	 * - cmd_wr(ctrl, cmd, has_addr, address, buffer, size);
	 *
	 *   cmd      : command opcode
	 *   has_addr : send an address after the command
	 *   address  : address to send
	 *   buffer   : buffer for additional data to write (or NULL)
	 *   size     : size of additional data write (or NULL)
	 *
	 * Sends a command and optionally write additional data
	 */
	int (*cmd_wr)(struct spi_flash_ctrl *ctrl, uint8_t cmd,
		      bool has_addr, uint32_t addr, const void *buffer,
		      uint32_t size);

	/* The core will establish this at init, after chip ID has
	 * been probed
	 */
	struct flash_info *finfo;

	void *priv;
};

extern int fl_wren(struct spi_flash_ctrl *ct);
extern int fl_read_stat(struct spi_flash_ctrl *ct, uint8_t *stat);
extern int fl_sync_wait_idle(struct spi_flash_ctrl *ct);

#endif /* LIBFLASH_PRIV_H */
