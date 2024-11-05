// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <skiboot.h>
#include <device.h>
#include <console.h>
#include <opal.h>
#include <libflash/ipmi-hiomap.h>
#include <libflash/mbox-flash.h>
#include <libflash/libflash.h>
#include <libflash/libffs.h>
#include <libflash/blocklevel.h>
#include <ast.h>

#include "astbmc.h"

enum ast_flash_style {
    raw_flash,
    raw_mem,
    ipmi_hiomap,
    mbox_hiomap,
};

static enum ast_flash_style ast_flash_get_fallback_style(void)
{
    if (ast_lpc_fw_mbox_hiomap())
	return mbox_hiomap;

    if (ast_lpc_fw_maps_flash())
	return raw_flash;

    return raw_mem;
}

int pnor_init(void)
{
	struct spi_flash_ctrl *pnor_ctrl = NULL;
	struct blocklevel_device *bl = NULL;
	enum ast_flash_style style;
	int rc = 0;

	if (ast_lpc_fw_ipmi_hiomap()) {
		style = ipmi_hiomap;
		rc = ipmi_hiomap_init(&bl);
	}

	if (!ast_lpc_fw_ipmi_hiomap() || rc) {
		if (!ast_sio_is_enabled())
			return -ENODEV;

		style = ast_flash_get_fallback_style();
		if (style == mbox_hiomap)
			rc = mbox_flash_init(&bl);
		else if (style == raw_flash)
			rc = ast_sf_open(AST_SF_TYPE_PNOR, &pnor_ctrl);
		else if (style == raw_mem)
			rc = ast_sf_open(AST_SF_TYPE_MEM, &pnor_ctrl);
		else {
			prerror("Unhandled flash mode: %d\n", style);
			return -ENODEV;
		}
	}

	if (rc) {
		prerror("PLAT: Failed to init PNOR driver\n");
		goto fail;
	}

	if (style == raw_flash || style == raw_mem) {
	    rc = flash_init(pnor_ctrl, &bl, NULL);
	    if (rc)
		goto fail;
	}

	rc = flash_register(bl);
	if (!rc)
		return 0;

fail:
	if (bl) {
		switch (style) {
		case raw_flash:
		case raw_mem:
			flash_exit(bl);
			break;
		case ipmi_hiomap:
			ipmi_hiomap_exit(bl);
			break;
		case mbox_hiomap:
			mbox_flash_exit(bl);
			break;
		}
	}
	if (pnor_ctrl)
		ast_sf_close(pnor_ctrl);

	return rc;
}
