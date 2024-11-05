// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#ifndef __AST_H
#define __AST_H

/*
 * AHB bus registers
 */

/* SPI Flash controller #1 (BMC) */
#define BMC_SPI_FCTL_BASE	0x1E620000
#define BMC_SPI_FCTL_CE_CTRL	(BMC_SPI_FCTL_BASE + 0x04)
#define BMC_SPI_FCTL_CTRL	(BMC_SPI_FCTL_BASE + 0x10)
#define BMC_SPI_FREAD_TIMING	(BMC_SPI_FCTL_BASE + 0x94)
#define BMC_FLASH_BASE		0x20000000

/* SPI Flash controller #2 (PNOR) */
#define PNOR_SPI_FCTL_BASE	0x1E630000
#define PNOR_SPI_FCTL_CONF	(PNOR_SPI_FCTL_BASE + 0x00)
#define PNOR_SPI_FCTL_CTRL	(PNOR_SPI_FCTL_BASE + 0x04)
#define PNOR_SPI_FREAD_TIMING	(PNOR_SPI_FCTL_BASE + 0x14)
#define PNOR_FLASH_BASE		0x30000000

/* LPC registers */
#define LPC_BASE		0x1e789000
#define LPC_HICR6		(LPC_BASE + 0x80)
#define LPC_HICR7		(LPC_BASE + 0x88)
#define LPC_HICR8		(LPC_BASE + 0x8c)
#define LPC_HICRB               (LPC_BASE + 0x100)
#define  LPC_HICRB_ILPC_DISABLE (1 << 6)
#define LPC_iBTCR0		(LPC_BASE + 0x140)

/* VUART1 */
#define VUART1_BASE		0x1e787000
#define VUART1_GCTRLA		(VUART1_BASE + 0x20)
#define VUART1_GCTRLB		(VUART1_BASE + 0x24)
#define VUART1_ADDRL		(VUART1_BASE + 0x28)
#define VUART1_ADDRH		(VUART1_BASE + 0x2c)

/* SCU registers */
#define SCU_BASE		        0x1e6e2000
#define SCU_HW_STRAPPING	        (SCU_BASE + 0x70)
#define  SCU_STRAP_SIO_DECODE_DISABLE   (1 << 20)
#define SCU_REVISION_ID		        (SCU_BASE + 0x7C)
#define  SCU_REVISION_SOC_FAMILY(x)     (((x) >> 24) & 0xff)
#define   SCU_REVISION_SOC_FAMILY_2400  0x02
#define   SCU_REVISION_SOC_FAMILY_2500  0x04
#define  SCU_REVISION_HW_REVISION_ID(x) (((x) >> 16) & 0xff)
#define  SCU_REVISION_CHIP_BONDING(x)   (((x) >> 8) & 0x3)

/* MCR registers */
#define MCR_BASE		0x1e6e0000
#define MCR_CONFIGURATION	(MCR_BASE + 0x04)
#define MCR_SCU_MPLL		(MCR_BASE + 0x120)
#define MCR_SCU_STRAP		(MCR_BASE + 0x170)

/*
 * AHB Accessors
 */
#ifndef __SKIBOOT__
#include "io.h"
#else

/*
 * Register accessors, return byteswapped values
 * (IE. LE registers)
 */
void ast_ahb_writel(uint32_t val, uint32_t reg);
uint32_t ast_ahb_readl(uint32_t reg);

bool ast_sio_is_enabled(void);
bool ast_sio_init(void);
bool ast_io_init(void);
bool ast_io_is_rw(void);
bool ast_lpc_fw_maps_flash(void);
bool ast_lpc_fw_ipmi_hiomap(void);
bool ast_lpc_fw_mbox_hiomap(void);
bool ast_scratch_reg_is_mbox(void);

/* UART configuration */

bool ast_is_vuart1_enabled(void);
void ast_setup_vuart1(uint16_t io_base, uint8_t irq);
void ast_setup_sio_uart1(uint16_t io_base, uint8_t irq);
void ast_disable_sio_uart1(void);

/* BT configuration */
void ast_setup_ibt(uint16_t io_base, uint8_t irq);

/* MBOX configuration */
void ast_setup_sio_mbox(uint16_t io_base, uint8_t irq);

#endif /* __SKIBOOT__ */

/*
 * SPI Flash controllers
 */
#define AST_SF_TYPE_PNOR	0
#define AST_SF_TYPE_BMC		1
#define AST_SF_TYPE_MEM		2

struct spi_flash_ctrl;
int ast_sf_open(uint8_t type, struct spi_flash_ctrl **ctrl);
void ast_sf_close(struct spi_flash_ctrl *ctrl);


#endif /* __AST_H */
