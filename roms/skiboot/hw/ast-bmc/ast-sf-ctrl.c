// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <libflash/libflash.h>
#include <libflash/libflash-priv.h>
#ifdef __SKIBOOT__
#include "lpc.h"
#endif

#include "ast.h"

#ifndef __unused
#define __unused __attribute__((unused))
#endif

#define CALIBRATE_BUF_SIZE	16384

struct ast_sf_ctrl {
	/* We have 2 controllers, one for the BMC flash, one for the PNOR */
	uint8_t			type;

	/* Address and previous value of the ctrl register */
	uint32_t		ctl_reg;

	/* Control register value for normal commands */
	uint32_t		ctl_val;

	/* Control register value for (fast) reads */
	uint32_t		ctl_read_val;

	/* Flash read timing register  */
	uint32_t		fread_timing_reg;
	uint32_t		fread_timing_val;

	/* Address of the flash mapping */
	uint32_t		flash;

	/* Current 4b mode */
	bool			mode_4b;

	/* Callbacks */
	struct spi_flash_ctrl	ops;
};

static uint32_t ast_ahb_freq;

static const uint32_t ast_ct_hclk_divs[] = {
	0xf, /* HCLK */
	0x7, /* HCLK/2 */
	0xe, /* HCLK/3 */
	0x6, /* HCLK/4 */
	0xd, /* HCLK/5 */
};

#ifdef __SKIBOOT__
#define PNOR_AHB_ADDR	0x30000000
static uint32_t pnor_lpc_offset;

static int ast_copy_to_ahb(uint32_t reg, const void *src, uint32_t len)
{
	/* Check we don't cross IDSEL segments */
	if ((reg ^ (reg + len - 1)) >> 28)
		return -EINVAL;

	/* SPI flash, use LPC->AHB bridge */
	if ((reg >> 28) == (PNOR_AHB_ADDR >> 28)) {
		uint32_t chunk, off = reg - PNOR_AHB_ADDR + pnor_lpc_offset;
		int64_t rc;

		while(len) {
			/* Chose access size */
			if (len > 3 && !(off & 3)) {
				rc = lpc_write(OPAL_LPC_FW, off,
					       *(uint32_t *)src, 4);
				chunk = 4;
			} else {
				rc = lpc_write(OPAL_LPC_FW, off,
					       *(uint8_t *)src, 1);
				chunk = 1;
			}
			if (rc) {
				prerror("AST_IO: lpc_write.sb failure %lld"
					" to FW 0x%08x\n", rc, off);
				return rc;
			}
			len -= chunk;
			off += chunk;
			src += chunk;
		}
		return 0;
	}

	/* Otherwise we don't do byte access (... yet)  */
	prerror("AST_IO: Attempted write bytes access to %08x\n", reg);
	return -EINVAL;
}

static int ast_copy_from_ahb(void *dst, uint32_t reg, uint32_t len)
{
	/* Check we don't cross IDSEL segments */
	if ((reg ^ (reg + len - 1)) >> 28)
		return -EINVAL;

	/* SPI flash, use LPC->AHB bridge */
	if ((reg >> 28) == (PNOR_AHB_ADDR >> 28)) {
		uint32_t chunk, off = reg - PNOR_AHB_ADDR + pnor_lpc_offset;
		int64_t rc;

		while(len) {
			uint32_t dat;

			/* Chose access size */
			if (len > 3 && !(off & 3)) {
				rc = lpc_read(OPAL_LPC_FW, off, &dat, 4);
				if (!rc)
					*(uint32_t *)dst = dat;
				chunk = 4;
			} else {
				rc = lpc_read(OPAL_LPC_FW, off, &dat, 1);
				if (!rc)
					*(uint8_t *)dst = dat;
				chunk = 1;
			}
			if (rc) {
				prerror("AST_IO: lpc_read.sb failure %lld"
					" to FW 0x%08x\n", rc, off);
				return rc;
			}
			len -= chunk;
			off += chunk;
			dst += chunk;
		}
		return 0;
	}
	/* Otherwise we don't do byte access (... yet)  */
	prerror("AST_IO: Attempted read bytes access to %08x\n", reg);
	return -EINVAL;
}
#endif /* __SKIBOOT__ */

static int ast_sf_start_cmd(struct ast_sf_ctrl *ct, uint8_t cmd)
{
	/* Switch to user mode, CE# dropped */
	ast_ahb_writel(ct->ctl_val | 7, ct->ctl_reg);

	/* user mode, CE# active */
	ast_ahb_writel(ct->ctl_val | 3, ct->ctl_reg);

	/* write cmd */
	return ast_copy_to_ahb(ct->flash, &cmd, 1);
}

static void ast_sf_end_cmd(struct ast_sf_ctrl *ct)
{
	/* clear CE# */
	ast_ahb_writel(ct->ctl_val | 7, ct->ctl_reg);

	/* Switch back to read mode */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);
}

static int ast_sf_send_addr(struct ast_sf_ctrl *ct, uint32_t addr)
{
	const void *ap;
	beint32_t tmp;

	/* Layout address MSB first in memory */
	tmp = cpu_to_be32(addr);

	/* Send the right amount of bytes */
	ap = (char *)&tmp;

	if (ct->mode_4b)
		return ast_copy_to_ahb(ct->flash, ap, 4);
	else
		return ast_copy_to_ahb(ct->flash, ap + 1, 3);
}

static int ast_sf_cmd_rd(struct spi_flash_ctrl *ctrl, uint8_t cmd,
			 bool has_addr, uint32_t addr, void *buffer,
			 uint32_t size)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);
	int rc;

	rc = ast_sf_start_cmd(ct, cmd);
	if (rc)
		goto bail;
	if (has_addr) {
		rc = ast_sf_send_addr(ct, addr);
		if (rc)
			goto bail;
	}
	if (buffer && size)
		rc = ast_copy_from_ahb(buffer, ct->flash, size);
 bail:
	ast_sf_end_cmd(ct);
	return rc;
}

static int ast_sf_cmd_wr(struct spi_flash_ctrl *ctrl, uint8_t cmd,
			 bool has_addr, uint32_t addr, const void *buffer,
			 uint32_t size)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);
	int rc;

	rc = ast_sf_start_cmd(ct, cmd);
	if (rc)
		goto bail;
	if (has_addr) {
		rc = ast_sf_send_addr(ct, addr);
		if (rc)
			goto bail;
	}
	if (buffer && size)
		rc = ast_copy_to_ahb(ct->flash, buffer, size);
 bail:
	ast_sf_end_cmd(ct);
	return rc;
}

static int ast_sf_set_4b(struct spi_flash_ctrl *ctrl, bool enable)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);
	uint32_t ce_ctrl = 0;

	if (ct->type == AST_SF_TYPE_BMC && ct->ops.finfo->size > 0x1000000)
		ce_ctrl = ast_ahb_readl(BMC_SPI_FCTL_CE_CTRL);
	else if (ct->type != AST_SF_TYPE_PNOR)
		return enable ? FLASH_ERR_4B_NOT_SUPPORTED : 0;

	/*
	 * We update the "old" value as well since when quitting
	 * we don't restore the mode of the flash itself so we need
	 * to leave the controller in a compatible setup
	 */
	if (enable) {
		ct->ctl_val |= 0x2000;
		ct->ctl_read_val |= 0x2000;
		ce_ctrl |= 0x1;
	} else {
		ct->ctl_val &= ~0x2000;
		ct->ctl_read_val &= ~0x2000;
		ce_ctrl &= ~0x1;
	}
	ct->mode_4b = enable;

	/* Update read mode */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	if (ce_ctrl && ct->type == AST_SF_TYPE_BMC)
		ast_ahb_writel(ce_ctrl, BMC_SPI_FCTL_CE_CTRL);

	return 0;
}

static int ast_sf_read(struct spi_flash_ctrl *ctrl, uint32_t pos,
		       void *buf, uint32_t len)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);

	/*
	 * We are in read mode by default. We don't yet support fancy
	 * things like fast read or X2 mode
	 */
	return ast_copy_from_ahb(buf, ct->flash + pos, len);
}

static void ast_get_ahb_freq(void)
{
	static const uint32_t cpu_freqs_24_48[] = {
		384000000,
		360000000,
		336000000,
		408000000
	};
	static const uint32_t cpu_freqs_25[] = {
		400000000,
		375000000,
		350000000,
		425000000
	};
	static const uint32_t ahb_div[] = { 1, 2, 4, 3 };
	uint32_t strap, cpu_clk, div;

	if (ast_ahb_freq)
		return;

	/* HW strapping gives us the CPU freq and AHB divisor */
	strap = ast_ahb_readl(SCU_HW_STRAPPING);
	if (strap & 0x00800000) {
		FL_DBG("AST: CLKIN 25Mhz\n");
		cpu_clk = cpu_freqs_25[(strap >> 8) & 3];
	} else {
		FL_DBG("AST: CLKIN 24/48Mhz\n");
		cpu_clk = cpu_freqs_24_48[(strap >> 8) & 3];
	}
	FL_DBG("AST: CPU frequency: %d Mhz\n", cpu_clk / 1000000);
	div = ahb_div[(strap >> 10) & 3];
	ast_ahb_freq = cpu_clk / div;
	FL_DBG("AST: AHB frequency: %d Mhz\n", ast_ahb_freq / 1000000);
}

static int ast_sf_check_reads(struct ast_sf_ctrl *ct,
			      const uint8_t *golden_buf, uint8_t *test_buf)
{
	int i, rc;

	for (i = 0; i < 10; i++) {
		rc = ast_copy_from_ahb(test_buf, ct->flash, CALIBRATE_BUF_SIZE);
		if (rc)
			return rc;
		if (memcmp(test_buf, golden_buf, CALIBRATE_BUF_SIZE) != 0)
			return FLASH_ERR_VERIFY_FAILURE;
	}
	return 0;
}

static int ast_sf_calibrate_reads(struct ast_sf_ctrl *ct, uint32_t hdiv,
				  const uint8_t *golden_buf, uint8_t *test_buf)
{
	int i, rc;
	int good_pass = -1, pass_count = 0;
	uint32_t shift = (hdiv - 1) << 2;
	uint32_t mask = ~(0xfu << shift);

#define FREAD_TPASS(i)	(((i) / 2) | (((i) & 1) ? 0 : 8))

	/* Try HCLK delay 0..5, each one with/without delay and look for a
	 * good pair.
	 */
	for (i = 0; i < 12; i++) {
		bool pass;

		ct->fread_timing_val &= mask;
		ct->fread_timing_val |= FREAD_TPASS(i) << shift;
		ast_ahb_writel(ct->fread_timing_val, ct->fread_timing_reg);
		rc = ast_sf_check_reads(ct, golden_buf, test_buf);
		if (rc && rc != FLASH_ERR_VERIFY_FAILURE)
			return rc;
		pass = (rc == 0);
		FL_DBG("  * [%08x] %d HCLK delay, %dns DI delay : %s\n",
		       ct->fread_timing_val, i/2, (i & 1) ? 0 : 4, pass ? "PASS" : "FAIL");
		if (pass) {
			pass_count++;
			if (pass_count == 3) {
				good_pass = i - 1;
				break;
			}
		} else
			pass_count = 0;
	}

	/* No good setting for this frequency */
	if (good_pass < 0)
		return FLASH_ERR_VERIFY_FAILURE;

	/* We have at least one pass of margin, let's use first pass */
	ct->fread_timing_val &= mask;
	ct->fread_timing_val |= FREAD_TPASS(good_pass) << shift;
	ast_ahb_writel(ct->fread_timing_val, ct->fread_timing_reg);
	FL_DBG("AST:  * -> good is pass %d [0x%08x]\n",
	       good_pass, ct->fread_timing_val);
	return 0;
}

static bool ast_calib_data_usable(const uint8_t *test_buf, uint32_t size)
{
	const uint32_t *tb32 = (const uint32_t *)test_buf;
	uint32_t i, cnt = 0;

	/* We check if we have enough words that are neither all 0
	 * nor all 1's so the calibration can be considered valid.
	 *
	 * I use an arbitrary threshold for now of 64
	 */
	size >>= 2;
	for (i = 0; i < size; i++) {
		if (tb32[i] != 0 && tb32[i] != 0xffffffff)
			cnt++;
	}
	return cnt >= 64;
}

static int ast_sf_optimize_reads(struct ast_sf_ctrl *ct,
				 struct flash_info *info __unused,
				 uint32_t max_freq)
{
	uint8_t *golden_buf, *test_buf;
	int i, rc, best_div = -1;
	uint32_t save_read_val = ct->ctl_read_val;

	test_buf = malloc(CALIBRATE_BUF_SIZE * 2);
	golden_buf = test_buf + CALIBRATE_BUF_SIZE;

	/* We start with the dumbest setting and read some data */
	ct->ctl_read_val = (ct->ctl_read_val & 0x2000) |
		(0x00 << 28) | /* Single bit */
		(0x00 << 24) | /* CE# max */
		(0x03 << 16) | /* use normal reads */
		(0x00 <<  8) | /* HCLK/16 */
		(0x00 <<  6) | /* no dummy cycle */
		(0x00);        /* normal read */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	rc = ast_copy_from_ahb(golden_buf, ct->flash, CALIBRATE_BUF_SIZE);
	if (rc) {
		free(test_buf);
		return rc;
	}

	/* Establish our read mode with freq field set to 0 */
	ct->ctl_read_val = save_read_val & 0xfffff0ff;

	/* Check if calibration data is suitable */
	if (!ast_calib_data_usable(golden_buf, CALIBRATE_BUF_SIZE)) {
		FL_INF("AST: Calibration area too uniform, "
		       "using low speed\n");
		ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);
		free(test_buf);
		return 0;
	}

	/* Now we iterate the HCLK dividers until we find our breaking point */
	for (i = 5; i > 0; i--) {
		uint32_t tv, freq;

		/* Compare timing to max */
		freq = ast_ahb_freq / i;
		if (freq >= max_freq)
			continue;

		/* Set the timing */
		tv = ct->ctl_read_val | (ast_ct_hclk_divs[i - 1] << 8);
		ast_ahb_writel(tv, ct->ctl_reg);
		FL_DBG("AST: Trying HCLK/%d...\n", i);
		rc = ast_sf_calibrate_reads(ct, i, golden_buf, test_buf);

		/* Some other error occurred, bail out */
		if (rc && rc != FLASH_ERR_VERIFY_FAILURE) {
			free(test_buf);
			return rc;
		}
		if (rc == 0)
			best_div = i;
	}
	free(test_buf);

	/* Nothing found ? */
	if (best_div < 0)
		FL_ERR("AST: No good frequency, using dumb slow\n");
	else {
		FL_DBG("AST: Found good read timings at HCLK/%d\n", best_div);
		ct->ctl_read_val |= (ast_ct_hclk_divs[best_div - 1] << 8);
	}
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	return 0;
}

static int ast_sf_get_hclk(uint32_t *ctl_val, uint32_t max_freq)
{
	int i;

	/* It appears that running commands at HCLK/2 on some micron
	 * chips results in occasionally reads of bogus status (that
	 * or unrelated chip hangs).
	 *
	 * Since we cannot calibrate properly the reads for commands,
	 * instead, let's limit our SPI frequency to HCLK/4 to stay
	 * on the safe side of things
	 */
#define MIN_CMD_FREQ	4
	for (i = MIN_CMD_FREQ; i <= 5; i++) {
		uint32_t freq = ast_ahb_freq / i;
		if (freq >= max_freq)
			continue;
		*ctl_val |= (ast_ct_hclk_divs[i - 1] << 8);
		return i;
	}
	return 0;
}

static int ast_sf_setup_macronix(struct ast_sf_ctrl *ct, struct flash_info *info)
{
	int rc, div __unused;
	uint8_t srcr[2];

	/*
	 * Those Macronix chips support dual reads at 104Mhz
	 * and dual IO at 84Mhz with 4 dummies.
	 *
	 * Our calibration algo should give us something along
	 * the lines of HCLK/3 (HCLK/2 seems to work sometimes
	 * but appears to be fairly unreliable) which is 64Mhz
	 *
	 * So we chose dual IO mode.
	 *
	 * The CE# inactive width for reads must be 7ns, we set it
	 * to 3T which is about 15ns at the fastest speed we support
	 * HCLK/2) as I've had issue with smaller values.
	 *
	 * For write and program it's 30ns so let's set the value
	 * for normal ops to 6T.
	 *
	 * Preserve the current 4b mode.
	 */
	FL_DBG("AST: Setting up Macronix...\n");

	/*
	 * Read the status and config registers
	 */
	rc = ast_sf_cmd_rd(&ct->ops, CMD_RDSR, false, 0, &srcr[0], 1);
	if (rc != 0) {
		FL_ERR("AST: Failed to read status\n");
		return rc;
	}
	rc = ast_sf_cmd_rd(&ct->ops, CMD_RDCR, false, 0, &srcr[1], 1);
	if (rc != 0) {
		FL_ERR("AST: Failed to read configuration\n");
		return rc;
	}

	FL_DBG("AST: Macronix SR:CR: 0x%02x:%02x\n", srcr[0], srcr[1]);

	/* Switch to 8 dummy cycles to enable 104Mhz operations */
	srcr[1] = (srcr[1] & 0x3f) | 0x80;

	rc = fl_wren(&ct->ops);
	if (rc) {
		FL_ERR("AST: Failed to WREN for Macronix config\n");
		return rc;
	}

	rc = ast_sf_cmd_wr(&ct->ops, CMD_WRSR, false, 0, srcr, 2);
	if (rc != 0) {
		FL_ERR("AST: Failed to write Macronix config\n");
		return rc;
	}
	rc = fl_sync_wait_idle(&ct->ops);;
	if (rc != 0) {
		FL_ERR("AST: Failed waiting for config write\n");
		return rc;
	}

	FL_DBG("AST: Macronix SR:CR: 0x%02x:%02x\n", srcr[0], srcr[1]);

	/* Use 2READ */
	ct->ctl_read_val = (ct->ctl_read_val & 0x2000) |
		(0x03 << 28) | /* Dual IO */
		(0x0d << 24) | /* CE# width 3T */
		(0xbb << 16) | /* 2READ command */
		(0x00 <<  8) | /* HCLK/16 (optimize later) */
		(0x02 <<  6) | /* 2 bytes dummy cycle (8 clocks) */
		(0x01);	       /* fast read */

	/* Configure SPI flash read timing */
	rc = ast_sf_optimize_reads(ct, info, 104000000);
	if (rc) {
		FL_ERR("AST: Failed to setup proper read timings, rc=%d\n", rc);
		return rc;
	}

	/*
	 * For other commands and writes also increase the SPI clock
	 * to HCLK/2 since the chip supports up to 133Mhz and set
	 * CE# inactive to 6T. We request a timing that is 20% below
	 * the limit of the chip, so about 106Mhz which should fit.
	 */
	ct->ctl_val = (ct->ctl_val & 0x2000) |
		(0x00 << 28) | /* Single bit */
		(0x0a << 24) | /* CE# width 6T (b1010) */
		(0x00 << 16) | /* no command */
		(0x00 <<  8) | /* HCLK/16 (done later) */
		(0x00 <<  6) | /* no dummy cycle */
		(0x00);	       /* normal read */

	div = ast_sf_get_hclk(&ct->ctl_val, 106000000);
	FL_DBG("AST: Command timing set to HCLK/%d\n", div);

	/* Update chip with current read config */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);
	return 0;
}

static int ast_sf_setup_winbond(struct ast_sf_ctrl *ct, struct flash_info *info)
{
	int rc, div __unused;

	FL_DBG("AST: Setting up Windbond...\n");

	/*
	 * This Windbond chip support dual reads at 104Mhz
	 * with 8 dummy cycles.
	 *
	 * The CE# inactive width for reads must be 10ns, we set it
	 * to 3T which is about 15.6ns.
	 */
	ct->ctl_read_val = (ct->ctl_read_val & 0x2000) |
		(0x02 << 28) | /* Dual bit data only */
		(0x0e << 24) | /* CE# width 2T (b1110) */
		(0x3b << 16) | /* DREAD command */
		(0x00 <<  8) | /* HCLK/16 */
		(0x01 <<  6) | /* 1-byte dummy cycle */
		(0x01);	       /* fast read */

	/* Configure SPI flash read timing */
	rc = ast_sf_optimize_reads(ct, info, 104000000);
	if (rc) {
		FL_ERR("AST: Failed to setup proper read timings, rc=%d\n", rc);
		return rc;
	}

	/*
	 * For other commands and writes also increase the SPI clock
	 * to HCLK/2 since the chip supports up to 133Mhz. CE# inactive
	 * for write and erase is 50ns so let's set it to 10T.
	 */
	ct->ctl_val = (ct->ctl_read_val & 0x2000) |
		(0x00 << 28) | /* Single bit */
		(0x06 << 24) | /* CE# width 10T (b0110) */
		(0x00 << 16) | /* no command */
		(0x00 <<  8) | /* HCLK/16 */
		(0x00 <<  6) | /* no dummy cycle */
		(0x01);	       /* fast read */

	div = ast_sf_get_hclk(&ct->ctl_val, 106000000);
	FL_DBG("AST: Command timing set to HCLK/%d\n", div);

	/* Update chip with current read config */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);
	return 0;
}

static int ast_sf_setup_micron(struct ast_sf_ctrl *ct, struct flash_info *info)
{
	uint8_t	vconf, ext_id[6];
	int rc, div __unused;

	FL_DBG("AST: Setting up Micron...\n");

	/*
	 * Read the extended chip ID to try to detect old vs. new
	 * flashes since old Micron flashes have a lot of issues
	 */
	rc = ast_sf_cmd_rd(&ct->ops, CMD_RDID, false, 0, ext_id, 6);
	if (rc != 0) {
		FL_ERR("AST: Failed to read Micron ext ID, sticking to dumb speed\n");
		return 0;
	}
	/* Check ID matches expectations */
	if (ext_id[0] != ((info->id >> 16) & 0xff) ||
	    ext_id[1] != ((info->id >>  8) & 0xff) ||
	    ext_id[2] != ((info->id      ) & 0xff)) {
		FL_ERR("AST: Micron ext ID mismatch, sticking to dumb speed\n");
		return 0;
	}
	FL_DBG("AST: Micron ext ID byte: 0x%02x\n", ext_id[4]);

	/* Check for old (<45nm) chips, don't try to be fancy on those */
	if (!(ext_id[4] & 0x40)) {
		FL_DBG("AST: Old chip, using dumb timings\n");
		goto dumb;
	}

	/*
	 * Read the micron specific volatile configuration reg
	 */
	rc = ast_sf_cmd_rd(&ct->ops, CMD_MIC_RDVCONF, false, 0, &vconf, 1);
	if (rc != 0) {
		FL_ERR("AST: Failed to read Micron vconf, sticking to dumb speed\n");
		goto dumb;
	}
	FL_DBG("AST: Micron VCONF: 0x%02x\n", vconf);

	/* Switch to 8 dummy cycles (we might be able to operate with 4
	 * but let's keep some margin
	 */
	vconf = (vconf & 0x0f) | 0x80;

	rc = ast_sf_cmd_wr(&ct->ops, CMD_MIC_WRVCONF, false, 0, &vconf, 1);
	if (rc != 0) {
		FL_ERR("AST: Failed to write Micron vconf, "
		       " sticking to dumb speed\n");
		goto dumb;
	}
	rc = fl_sync_wait_idle(&ct->ops);;
	if (rc != 0) {
		FL_ERR("AST: Failed waiting for config write\n");
		return rc;
	}
	FL_DBG("AST: Updated to  : 0x%02x\n", vconf);

	/*
	 * Try to do full dual IO, with 8 dummy cycles it supports 133Mhz
	 *
	 * The CE# inactive width for reads must be 20ns, we set it
	 * to 4T which is about 20.8ns.
	 */
	ct->ctl_read_val = (ct->ctl_read_val & 0x2000) |
		(0x03 << 28) | /* Single bit */
		(0x0c << 24) | /* CE# 4T */
		(0xbb << 16) | /* 2READ command */
		(0x00 <<  8) | /* HCLK/16 (optimize later) */
		(0x02 <<  6) | /* 8 dummy cycles (2 bytes) */
		(0x01);	       /* fast read */

	/* Configure SPI flash read timing */
	rc = ast_sf_optimize_reads(ct, info, 133000000);
	if (rc) {
		FL_ERR("AST: Failed to setup proper read timings, rc=%d\n", rc);
		return rc;
	}

	/*
	 * For other commands and writes also increase the SPI clock
	 * to HCLK/2 since the chip supports up to 133Mhz. CE# inactive
	 * for write and erase is 50ns so let's set it to 10T.
	 */
	ct->ctl_val = (ct->ctl_read_val & 0x2000) |
		(0x00 << 28) | /* Single bit */
		(0x06 << 24) | /* CE# width 10T (b0110) */
		(0x00 << 16) | /* no command */
		(0x00 <<  8) | /* HCLK/16 */
		(0x00 <<  6) | /* no dummy cycle */
		(0x00);	       /* norm read */

	div = ast_sf_get_hclk(&ct->ctl_val, 133000000);
	FL_DBG("AST: Command timing set to HCLK/%d\n", div);

	/* Update chip with current read config */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	return 0;

 dumb:
	ct->ctl_val = ct->ctl_read_val = (ct->ctl_read_val & 0x2000) |
		(0x00 << 28) | /* Single bit */
		(0x00 << 24) | /* CE# max */
		(0x03 << 16) | /* use normal reads */
		(0x06 <<  8) | /* HCLK/4 */
		(0x00 <<  6) | /* no dummy cycle */
		(0x00);	       /* normal read */

	/* Update chip with current read config */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	return 0;
}

static int ast_sf_setup(struct spi_flash_ctrl *ctrl, uint32_t *tsize)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);
	struct flash_info *info = ctrl->finfo;

	(void)tsize;

	/*
	 * Configure better timings and read mode for known
	 * flash chips
	 */
	switch(info->id) {
	case 0xc22018: /* MX25L12835F */
	case 0xc22019: /* MX25L25635F */
	case 0xc2201a: /* MX66L51235F */
	case 0xc2201b: /* MX66L1G45G */
		return ast_sf_setup_macronix(ct, info);
	case 0xef4018: /* W25Q128BV */
		return ast_sf_setup_winbond(ct, info);
	case 0x20ba20: /* MT25Qx512xx */
		return ast_sf_setup_micron(ct, info);
	}
	/* No special tuning */
	return 0;
}

static bool ast_sf_init_pnor(struct ast_sf_ctrl *ct)
{
	uint32_t reg;

	ct->ctl_reg = PNOR_SPI_FCTL_CTRL;
	ct->fread_timing_reg = PNOR_SPI_FREAD_TIMING;
	ct->flash = PNOR_FLASH_BASE;

	/* Enable writing to the controller */
	reg = ast_ahb_readl(PNOR_SPI_FCTL_CONF);
	if (reg == 0xffffffff) {
		FL_ERR("AST_SF: Failed read from controller config\n");
		return false;
	}
	ast_ahb_writel(reg | 1, PNOR_SPI_FCTL_CONF);

	/*
	 * Snapshot control reg and sanitize it for our
	 * use, switching to 1-bit mode, clearing user
	 * mode if set, etc...
	 *
	 * Also configure SPI clock to something safe
	 * like HCLK/8 (24Mhz)
	 */
	ct->ctl_val = ast_ahb_readl(ct->ctl_reg);
	if (ct->ctl_val == 0xffffffff) {
		FL_ERR("AST_SF: Failed read from controller control\n");
		return false;
	}

	ct->ctl_val = (ct->ctl_val & 0x2000) |
		(0x00 << 28) | /* Single bit */
		(0x00 << 24) | /* CE# width 16T */
		(0x00 << 16) | /* no command */
		(0x04 <<  8) | /* HCLK/8 */
		(0x00 <<  6) | /* no dummy cycle */
		(0x00);	       /* normal read */

	/* Initial read mode is default */
	ct->ctl_read_val = ct->ctl_val;

	/* Initial read timings all 0 */
	ct->fread_timing_val = 0;

	/* Configure for read */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);
	ast_ahb_writel(ct->fread_timing_val, ct->fread_timing_reg);

	if (ct->ctl_val & 0x2000)
		ct->mode_4b = true;
	else
		ct->mode_4b = false;

	return true;
}

static bool ast_sf_init_bmc(struct ast_sf_ctrl *ct)
{
	ct->ctl_reg = BMC_SPI_FCTL_CTRL;
	ct->fread_timing_reg = BMC_SPI_FREAD_TIMING;
	ct->flash = BMC_FLASH_BASE;

	/*
	 * Snapshot control reg and sanitize it for our
	 * use, switching to 1-bit mode, clearing user
	 * mode if set, etc...
	 *
	 * Also configure SPI clock to something safe
	 * like HCLK/8 (24Mhz)
	 */
	ct->ctl_val =
		(0x00 << 28) | /* Single bit */
		(0x00 << 24) | /* CE# width 16T */
		(0x00 << 16) | /* no command */
		(0x04 <<  8) | /* HCLK/8 */
		(0x00 <<  6) | /* no dummy cycle */
		(0x00);	       /* normal read */

	/* Initial read mode is default */
	ct->ctl_read_val = ct->ctl_val;

	/* Initial read timings all 0 */
	ct->fread_timing_val = 0;

	/* Configure for read */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);
	ast_ahb_writel(ct->fread_timing_val, ct->fread_timing_reg);

	ct->mode_4b = false;

	return true;
}

static int ast_mem_set4b(struct spi_flash_ctrl *ctrl __unused,
			 bool enable __unused)
{
	return 0;
}

static int ast_mem_setup(struct spi_flash_ctrl *ctrl __unused,
			 uint32_t *tsize __unused)
{
	return 0;
}

static int ast_mem_chipid(struct spi_flash_ctrl *ctrl __unused, uint8_t *id_buf,
			  uint32_t *id_size)
{
	if (*id_size < 3)
		return -1;

	id_buf[0] = 0xaa;
	id_buf[1] = 0x55;
	id_buf[2] = 0xaa;
	*id_size = 3;
	return 0;
}

static int ast_mem_write(struct spi_flash_ctrl *ctrl, uint32_t pos,
			const void *buf, uint32_t len)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);

	/*
	 * This only works when the ahb is pointed at system memory.
	 */
	return ast_copy_to_ahb(ct->flash + pos, buf, len);
}

static int ast_mem_erase(struct spi_flash_ctrl *ctrl, uint32_t addr, uint32_t size)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);
	uint32_t pos, len, end = addr + size;
	uint64_t zero = 0;
	int ret;

	for (pos = addr; pos < end; pos += sizeof(zero)) {
		if (pos + sizeof(zero) > end)
			len = end - pos;
		else
			len = sizeof(zero);

		ret = ast_copy_to_ahb(ct->flash + pos, &zero, len);
		if (ret)
			return ret;
	}

	return 0;
}

int ast_sf_open(uint8_t type, struct spi_flash_ctrl **ctrl)
{
	struct ast_sf_ctrl *ct;
#ifdef __SKIBOOT__
	uint32_t hicr7;

	if (!ast_sio_is_enabled())
		return -ENODEV;
#endif /* __SKIBOOT__ */

	if (type != AST_SF_TYPE_PNOR && type != AST_SF_TYPE_BMC
	    && type != AST_SF_TYPE_MEM)
		return -EINVAL;

	*ctrl = NULL;
	ct = malloc(sizeof(*ct));
	if (!ct) {
		FL_ERR("AST_SF: Failed to allocate\n");
		return -ENOMEM;
	}
	memset(ct, 0, sizeof(*ct));
	ct->type = type;

	if (type == AST_SF_TYPE_MEM) {
		ct->ops.cmd_wr = NULL;
		ct->ops.cmd_rd = NULL;
		ct->ops.read = ast_sf_read;
		ct->ops.set_4b = ast_mem_set4b;
		ct->ops.write = ast_mem_write;
		ct->ops.erase = ast_mem_erase;
		ct->ops.setup = ast_mem_setup;
		ct->ops.chip_id = ast_mem_chipid;
		ct->flash = PNOR_FLASH_BASE;
	} else {
		ct->ops.cmd_wr = ast_sf_cmd_wr;
		ct->ops.cmd_rd = ast_sf_cmd_rd;
		ct->ops.set_4b = ast_sf_set_4b;
		ct->ops.read = ast_sf_read;
		ct->ops.setup = ast_sf_setup;
	}

	ast_get_ahb_freq();

	if (type == AST_SF_TYPE_PNOR) {
		if (!ast_sf_init_pnor(ct))
			goto fail;
	} else if (type == AST_SF_TYPE_BMC) {
		if (!ast_sf_init_bmc(ct))
			goto fail;
	}

#ifdef __SKIBOOT__
	/* Read the configuration of the LPC->AHB bridge for PNOR
	 * to extract the PNOR LPC offset which can be different
	 * depending on flash size
	 */
	hicr7 = ast_ahb_readl(LPC_HICR7);
	pnor_lpc_offset = (hicr7 & 0xffffu) << 16;
	prlog(PR_DEBUG, "AST: PNOR LPC offset: 0x%08x\n", pnor_lpc_offset);
#endif /* __SKIBOOT__ */

	*ctrl = &ct->ops;

	return 0;
 fail:
	free(ct);
	return -EIO;
}

void ast_sf_close(struct spi_flash_ctrl *ctrl)
{
	struct ast_sf_ctrl *ct = container_of(ctrl, struct ast_sf_ctrl, ops);

	/* Restore control reg to read */
	ast_ahb_writel(ct->ctl_read_val, ct->ctl_reg);

	/* Additional cleanup */
	if (ct->type == AST_SF_TYPE_PNOR) {
		uint32_t reg = ast_ahb_readl(PNOR_SPI_FCTL_CONF);
		if (reg != 0xffffffff)
			ast_ahb_writel(reg & ~1, PNOR_SPI_FCTL_CONF);
	}

	/* Free the whole lot */
	free(ct);
}
