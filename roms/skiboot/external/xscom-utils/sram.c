// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2014-2019 IBM Corp. */

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <time.h>

#include "xscom.h"

#define DBG(fmt...)	do { if (verbose) printf(fmt); } while(0)
#define ERR(fmt...)	do { fprintf(stderr, fmt); } while(0)

#define OCB_PIB_BASE_P8 0x0006B000
#define OCB_PIB_BASE_P9 0x0006D000

#define OCBCSR0         0x11
#define OCBCSR0_AND     0x12
#define OCBCSR0_OR      0x13
#define   OCB_STREAM_MODE			PPC_BIT(4)
#define   OCB_STREAM_TYPE			PPC_BIT(5)
#define OCBAR0          0x10
#define OCBDR0          0x15

#define PVR_TYPE_P8E    0x004b /* Murano */
#define PVR_TYPE_P8     0x004d /* Venice */
#define PVR_TYPE_P8NVL  0x004c /* Naples */
#define PVR_TYPE_P9     0x004e
#define PVR_TYPE_P9P    0x004f /* Axone */
#define PVR_TYPE_P10	0x0080

#ifdef __powerpc__
static uint64_t get_xscom_base(void)
{
	unsigned int pvr;

	asm volatile("mfpvr %0" : "=r" (pvr));

	switch (pvr >> 16) {
	case PVR_TYPE_P9:
	case PVR_TYPE_P9P:
	case PVR_TYPE_P10: /* P10 OCB_PIB OCC Control Register is same for P9 and P10 */
		return OCB_PIB_BASE_P9;

	case PVR_TYPE_P8E:
	case PVR_TYPE_P8:
	case PVR_TYPE_P8NVL:
		return OCB_PIB_BASE_P8;
	}

	ERR("Unknown processor, exiting\n");
	exit(1);
	return 0;
}
#else
/* Just so it compiles on x86 */
static uint64_t get_xscom_base(void) { return 0; }
#endif

int sram_read(uint32_t chip_id, int chan, uint32_t addr, uint64_t *val)
{
	uint64_t sdat, base = get_xscom_base();
	uint32_t coff = chan * 0x20;
	int rc;

	/* Read for debug purposes */
	rc = xscom_read(chip_id, base + OCBCSR0 + coff, &sdat);
	if (rc) {
		ERR("xscom OCBCSR0 read error %d\n", rc);
		return -1;
	}

	/* Create an AND mask to clear bit 4 and 5 and poke the AND register */
	sdat = ~(OCB_STREAM_MODE | OCB_STREAM_TYPE);
	rc = xscom_write(chip_id, base + OCBCSR0_AND + coff, sdat);
	if (rc) {
		ERR("xscom OCBCSR0_AND write error %d\n", rc);
		return -1;
	}

	sdat = ((uint64_t)addr) << 32;
	rc = xscom_write(chip_id, base + OCBAR0 + coff, sdat);
	if (rc) {
		ERR("xscom OCBAR0 write error %d\n", rc);
		return -1;
	}

	rc = xscom_read(chip_id, base + OCBDR0 + coff, val);
	if (rc) {
		ERR("xscom OCBDR0 read error %d\n", rc);
		return -1;
	}
	return 0;
}

int sram_write(uint32_t chip_id, int chan, uint32_t addr, uint64_t val)
{
	uint64_t sdat, base = get_xscom_base();
	uint32_t coff = chan * 0x20;
	int rc;

#if 0
	if (dummy) {
		printf("[dummy] write chip %d OCC sram 0x%08x = %016lx\n",
		       chip_id, addr, val);
		return 0;
	}
#endif

	/* Read for debug purposes */
	rc = xscom_read(chip_id, base + OCBCSR0 + coff, &sdat);
	if (rc) {
		ERR("xscom OCBCSR0 read error %d\n", rc);
		return -1;
	}

	/* Create an AND mask to clear bit 4 and 5 and poke the AND register */
	sdat = ~(OCB_STREAM_MODE | OCB_STREAM_TYPE);
	rc = xscom_write(chip_id, base + OCBCSR0_AND + coff, sdat);
	if (rc) {
		ERR("xscom OCBCSR0_AND write error %d\n", rc);
		return -1;
	}

	sdat = ((uint64_t)addr) << 32;
	rc = xscom_write(chip_id, base + OCBAR0 + coff, sdat);
	if (rc) {
		ERR("xscom OCBAR0 write error %d\n", rc);
		return -1;
	}

	rc = xscom_write(chip_id, base + OCBDR0 + coff, val);
	if (rc) {
		ERR("xscom OCBDR0 write error %d\n", rc);
		return -1;
	}
	return 0;
}
