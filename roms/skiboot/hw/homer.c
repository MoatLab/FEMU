// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <skiboot.h>
#include <xscom.h>
#include <io.h>
#include <cpu.h>
#include <chip.h>
#include <mem_region.h>
#include <hostservices.h>

#define P8_PBA_BAR0		0x2013f00
#define P8_PBA_BARMASK0		0x2013f04

#define P9_PBA_BAR0		0x5012B00
#define P9_PBA_BARMASK0		0x5012B04

#define P10_PBA_BAR0		0x01010CDA
#define P10_PBA_BARMASK0	0x01010CDE

#define PBA_MASK_ALL_BITS 0x000001FFFFF00000ULL /* Bits 23:43 */

enum P8_BAR {
	P8_BAR_HOMER = 0,
	P8_BAR_CENTAUR = 1,
	P8_BAR_SLW = 2,
	P8_BAR_OCC_COMMON = 3,
};

enum P9_BAR {
	P9_BAR_HOMER = 0,
	P9_BAR_CENTAUR = 1,
	P9_BAR_OCC_COMMON = 2,
	P9_BAR_SBE = 3,
};

enum P10_BAR {
	P10_BAR_HOMER = 0,
	P10_BAR_OCMB_THERMAL = 1,
	P10_BAR_OCC_COMMON = 2,
	P10_BAR_SBE = 3,
};

static u64 pba_bar0, pba_barmask0;
static u8 bar_homer, bar_slw, bar_occ_common;

static bool read_pba_bar(struct proc_chip *chip, unsigned int bar_no,
			 uint64_t *base, uint64_t *size)
{
	uint64_t bar, mask;
	int rc;

	rc = xscom_read(chip->id, pba_bar0 + bar_no, &bar);
	if (rc) {
		prerror("SLW: Error %d reading PBA BAR%d on chip %d\n",
			rc, bar_no, chip->id);
		return false;
	}
	rc = xscom_read(chip->id, pba_barmask0 + bar_no, &mask);
	if (rc) {
		prerror("SLW: Error %d reading PBA BAR MASK%d on chip %d\n",
			rc, bar_no, chip->id);
		return false;
	}
	prlog(PR_DEBUG, "  PBA BAR%d : 0x%016llx\n", bar_no, bar);
	prlog(PR_DEBUG, "  PBA MASK%d: 0x%016llx\n", bar_no, mask);

	if (mask == PBA_MASK_ALL_BITS) {
		/*
		 * This could happen if all HOMER users are not enabled during
		 * early system bringup. Skip using the PBA BAR.
		 */
		mask = 0;
		bar = 0;
		prerror("  PBA MASK%d uninitalized skipping BAR\n", bar_no);
	}

	*base = bar & 0x0ffffffffffffffful;
	*size = (mask | 0xfffff) + 1;

	return (*base) != 0;
}

static void homer_init_chip(struct proc_chip *chip)
{
	uint64_t hbase = 0, hsize = 0;
	uint64_t sbase, ssize, obase, osize;

	/*
	 * PBA BARs assigned by HB:
	 *
	 * P8:
	 *   0 : Entire HOMER
	 *   1 : OCC to Centaur path (we don't care)
	 *   2 : SLW image
	 *   3 : OCC Common area
	 *
	 * We need to reserve the memory covered by BAR 0 and BAR 3, however
	 * on earlier HBs, BAR0 isn't set so we need BAR 2 instead in that
	 * case to cover SLW (OCC not running).
	 *
	 * P9:
	 *   0 : Entire HOMER
	 *   1 : OCC to Centaur path (Cumulus only)
	 *   2 : OCC Common area
	 *   3 : SBE communication
	 *
	 */
	if (read_pba_bar(chip, bar_homer, &hbase, &hsize)) {
		prlog(PR_DEBUG, "  HOMER Image at 0x%llx size %lldMB\n",
		      hbase, hsize / 0x100000);

		if (!mem_range_is_reserved(hbase, hsize)) {
			prlog(PR_WARNING,
				"HOMER image is not reserved! Reserving\n");
			mem_reserve_fw("ibm,homer-image", hbase, hsize);
		}

		chip->homer_base = hbase;
		chip->homer_size = hsize;
	}

	/*
	 * We always read the SLW BAR since we need to grab info about the
	 * SLW image in the struct proc_chip for use by the slw.c code
	 */
	if (proc_gen == proc_gen_p8 &&
	    read_pba_bar(chip, bar_slw, &sbase, &ssize)) {
		prlog(PR_DEBUG, "  SLW Image at 0x%llx size %lldMB\n",
		      sbase, ssize / 0x100000);

		/*
		 * Only reserve it if we have no homer image or if it
		 * doesn't fit in it (only check the base).
		 */
		if ((sbase < hbase || sbase > (hbase + hsize) ||
				(hbase == 0 && sbase > 0)) &&
				!mem_range_is_reserved(sbase, ssize)) {
			prlog(PR_WARNING,
				"SLW image is not reserved! Reserving\n");
			mem_reserve_fw("ibm,slw-image", sbase, ssize);
		}

		chip->slw_base = sbase;
		chip->slw_bar_size = ssize;
		chip->slw_image_size = ssize; /* will be adjusted later */
	}

	if (read_pba_bar(chip, bar_occ_common, &obase, &osize)) {
		prlog(PR_DEBUG, "  OCC Common Area at 0x%llx size %lldMB\n",
		      obase, osize / 0x100000);
		chip->occ_common_base = obase;
		chip->occ_common_size = osize;
	}
}


static void host_services_occ_base_setup(void)
{
	struct proc_chip *chip;
	uint64_t occ_common;

	chip = next_chip(NULL); /* Frist chip */
	occ_common = (uint64_t) local_alloc(chip->id, OCC_COMMON_SIZE, OCC_COMMON_SIZE);

	for_each_chip(chip) {
		chip->occ_common_base = occ_common;
		chip->occ_common_size = OCC_COMMON_SIZE;

		chip->homer_base = (uint64_t) local_alloc(chip->id, HOMER_IMAGE_SIZE,
							HOMER_IMAGE_SIZE);
		chip->homer_size = HOMER_IMAGE_SIZE;
		memset((void *)chip->homer_base, 0, chip->homer_size);

		prlog(PR_DEBUG, "HBRT: Chip %d HOMER base %016llx : %08llx\n",
		      chip->id, chip->homer_base, chip->homer_size);
		prlog(PR_DEBUG, "HBRT: OCC common base %016llx : %08llx\n",
		      chip->occ_common_base, chip->occ_common_size);
	}
}

void homer_init(void)
{
	struct proc_chip *chip;

	if (chip_quirk(QUIRK_NO_PBA))
		return;

	switch (proc_gen) {
	case proc_gen_p8:
		pba_bar0 = P8_PBA_BAR0;
		pba_barmask0 = P8_PBA_BARMASK0;
		bar_homer = P8_BAR_HOMER;
		bar_slw = P8_BAR_SLW;
		bar_occ_common = P8_BAR_OCC_COMMON;
		break;
	case proc_gen_p9:
		pba_bar0 = P9_PBA_BAR0;
		pba_barmask0 = P9_PBA_BARMASK0;
		bar_homer = P9_BAR_HOMER;
		bar_occ_common = P9_BAR_OCC_COMMON;
		break;
	case proc_gen_p10:
		pba_bar0 = P10_PBA_BAR0;
		pba_barmask0 = P10_PBA_BARMASK0;
		bar_homer = P10_BAR_HOMER;
		bar_occ_common = P10_BAR_OCC_COMMON;
		break;
	default:
		return;
	};

	/*
	 * XXX This is temporary, on P8 we look for any configured
	 * SLW/OCC BAR and reserve the memory. Eventually, this will be
	 * done via HostBoot using the device-tree "reserved-ranges"
	 * or we'll load the SLW & OCC images ourselves using Host Services.
	 */
	for_each_chip(chip) {
		prlog(PR_DEBUG, "HOMER: Init chip %d\n", chip->id);
		homer_init_chip(chip);
	}

	/*
	 * Check is PBA BARs are already loaded with HOMER and
	 * skip host services.
	 */

	chip = next_chip(NULL);
	/* Both HOMER images and OCC areas are setup */
	if (chip->homer_base && chip->occ_common_base) {
		/* Reserve OCC common area from BAR */
		if (!mem_range_is_reserved(chip->occ_common_base,
					chip->occ_common_size)) {
			prlog(PR_WARNING,
				"OCC common area is not reserved! Reserving\n");
			mem_reserve_fw("ibm,occ-common-area",
						chip->occ_common_base,
						chip->occ_common_size);
		}
	} else if (chip->homer_base) {
		/*
		 * HOMER is setup but not OCC!! Do not allocate HOMER
		 * regions.  This case is possible during early system
		 * bringup where OCC images are not yet operational.
		 */
	} else {
		/* Allocate memory for HOMER and OCC common area */
		host_services_occ_base_setup();
	}
}

