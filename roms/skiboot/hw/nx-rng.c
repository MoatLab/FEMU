// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * NX Hardware Random Number Generator
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <nx.h>
#include <chip.h>
#include <phys-map.h>
#include <xscom-p9-regs.h>

/*
 * On P9 the DARN instruction is used to access the HW RNG. There is still
 * an NX RNG BAR, but it is used to configure which NX a core will source
 * random numbers from rather than being a MMIO window.
 */
static void nx_init_p9_rng(uint32_t chip_id)
{
	uint64_t bar, tmp;

	if (chip_quirk(QUIRK_NO_RNG))
		return;

	phys_map_get(chip_id, NX_RNG, 0, &bar, NULL);
	xscom_write(chip_id, P9X_NX_MMIO_BAR, bar | P9X_NX_MMIO_BAR_EN);

	/* Read config register for pace info */
	xscom_read(chip_id, P9X_NX_RNG_CFG, &tmp);
	prlog(PR_INFO, "NX RNG[%x] pace:%lli\n", chip_id, 0xffff & (tmp >> 2));
}

void nx_create_rng_node(struct dt_node *node)
{
	u64 bar, cfg;
	u64 xbar, xcfg;
	u32 pb_base;
	u32 gcid;
	u64 rng_addr, rng_len, len, addr_mask;
	struct dt_node *rng;
	int rc;

	gcid = dt_get_chip_id(node);
	pb_base = dt_get_address(node, 0, NULL);

	if (dt_node_is_compatible(node, "ibm,power8-nx")) {
		xbar = pb_base + NX_P8_RNG_BAR;
		xcfg = pb_base + NX_P8_RNG_CFG;
		addr_mask = NX_P8_RNG_BAR_ADDR;
	} else if (dt_node_is_compatible(node, "ibm,power9-nx")) {
		nx_init_p9_rng(gcid);
		return;
	} else {
		prerror("NX%d: Unknown NX type!\n", gcid);
		return;
	}

	rc = xscom_read(gcid, xbar, &bar); /* Get RNG BAR */
	if (rc) {
                prerror("NX%d: ERROR: XSCOM RNG BAR read failure %d\n",
			 gcid, rc);
		return;
	}

	rc = xscom_read(gcid, xcfg, &cfg); /* Get RNG CFG */
	if (rc) {
                prerror("NX%d: ERROR: XSCOM RNG config read failure %d\n",
			 gcid, rc);
		return;
	}

	/*
	 * We mask in-place rather than using GETFIELD for the base address
	 * as we happen to *know* that it's properly aligned in the register.
	 *
	 * FIXME? Always assusme BAR gets a valid address from FSP
	 */
	rng_addr = bar & addr_mask;
	len  = GETFIELD(NX_RNG_BAR_SIZE, bar);
	if (len > 4) {
		prerror("NX%d: Corrupted bar size %lld\n", gcid, len);
		return;
	}
	rng_len = (u64[]){  0x1000,         /* 4K */
			    0x10000,        /* 64K */
			    0x400000000UL,    /* 16G*/
			    0x100000,       /* 1M */
			    0x1000000       /* 16M */} [len];


	prlog(PR_INFO, "NX%d: RNG BAR set to 0x%016llx..0x%016llx\n",
	      gcid, rng_addr, rng_addr + rng_len - 1);

	/* RNG must be enabled before MMIO is enabled */
	rc = xscom_write(gcid, xcfg, cfg | NX_RNG_CFG_ENABLE);
	if (rc) {
                prerror("NX%d: ERROR: XSCOM RNG config enable failure %d\n",
			 gcid, rc);
		return;
	}

	/* The BAR needs to be enabled too */
	rc = xscom_write(gcid, xbar, bar | NX_RNG_BAR_ENABLE);
	if (rc) {
                prerror("NX%d: ERROR: XSCOM RNG config enable failure %d\n",
			 gcid, rc);
		return;
	}

	rng = dt_new_addr(dt_root, "hwrng", rng_addr);
	if (!rng)
		return;

	dt_add_property_strings(rng, "compatible", "ibm,power-rng");
	dt_add_property_u64s(rng, "reg", rng_addr, rng_len);
	dt_add_property_cells(rng, "ibm,chip-id", gcid);
}
