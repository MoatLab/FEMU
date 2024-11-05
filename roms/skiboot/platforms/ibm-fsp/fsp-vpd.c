// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <skiboot.h>
#include <vpd.h>
#include <string.h>
#include <fsp.h>
#include <device.h>
#include "ibm-fsp.h"

static void *vpd_lid;
static size_t vpd_lid_size;
static uint32_t vpd_lid_no;


void vpd_iohub_load(struct dt_node *hub_node)
{
	uint8_t record[4] = { 'L','X','R','0' }; /* not null terminated */
	const void *valid_lx;
	uint8_t lx_size;
	int r;
	const uint32_t *p;
	const uint8_t *lx;
	unsigned int lxrn;

	if (!fsp_present())
		return;

	p = dt_prop_get_def(hub_node, "ibm,vpd-lx-info", NULL);
	if (!p)
		return;

	lxrn = p[0];
        lx = (const char *)&p[1];

	/* verify the lid preload has started */
	if (!vpd_lid || !vpd_lid_no) {
		prlog(PR_WARNING, "VPD: WARNING: Unable to load VPD lid");
		return;
	}

	r = fsp_wait_lid_loaded(vpd_lid_no);

	if (r)
		goto fail;

	/* Validate it */
	if (lxrn < 9)
		record[3] = '0' + lxrn;
	else
		memcpy(record, "VINI", 4);

	valid_lx = vpd_find(vpd_lid, vpd_lid_size, record, "LX", &lx_size);
	if (!valid_lx || lx_size != 8) {
		prerror("VPD: Cannot find validation LX record\n");
		goto fail;
	}
	if (memcmp(valid_lx, lx, 8) != 0) {
		prerror("VPD: LX record mismatch !\n");
		goto fail;
	}

	printf("VPD: Loaded %zu bytes\n", vpd_lid_size);

	dt_add_property(hub_node, "ibm,io-vpd", vpd_lid, vpd_lid_size);
	free(vpd_lid);
	return;

fail:
	free(vpd_lid);
	vpd_lid = NULL;
	prerror("VPD: Failed to load VPD LID\n");
	return;
}

/* Helper to load a VPD LID. Pass a ptr to the corresponding LX keyword */
static void *vpd_lid_preload(const uint8_t *lx)
{
	int rc;

	if (!fsp_present())
		return NULL;

	/* Now this is a guess game as we don't have the info from the
	 * pHyp folks. But basically, it seems to boil down to loading
	 * a LID whose name is 0x80e000yy where yy is the last 2 digits
	 * of the LX record in hex.
	 *
	 * [ Correction: After a chat with some folks, it looks like it's
	 * actually 4 digits, though the lid number is limited to fff
	 * so we weren't far off. ]
	 *
	 * For safety, we look for a matching LX record in an LXRn
	 * (n = lxrn argument) or in VINI if lxrn=0xff
	 */
	vpd_lid_no = 0x80e00000 | ((lx[6] & 0xf) << 8) | lx[7];

	/* We don't quite know how to get to the LID directory so
	 * we don't know the size. Let's allocate 16K. All the VPD LIDs
	 * I've seen so far are much smaller.
	 */
#define VPD_LID_MAX_SIZE	0x4000
	vpd_lid = malloc(VPD_LID_MAX_SIZE);

	if (!vpd_lid) {
		prerror("VPD: Failed to allocate memory for LID\n");
		return NULL;
	}

	/* Adjust LID number for flash side */
	vpd_lid_no = fsp_adjust_lid_side(vpd_lid_no);
	printf("VPD: Trying to load VPD LID 0x%08x...\n", vpd_lid_no);

	vpd_lid_size = VPD_LID_MAX_SIZE;

	/* Load it from the FSP */
	rc = fsp_preload_lid(vpd_lid_no, vpd_lid, &vpd_lid_size);
	if (rc) {
		prerror("VPD: Error %d loading VPD LID\n", rc);
		goto fail;
	}

	return vpd_lid;
 fail:
	free(vpd_lid);
	return NULL;
}

void vpd_preload(struct dt_node *hub_node)
{
	const uint32_t *p;
	const char *lxr;

	p = dt_prop_get_def(hub_node, "ibm,vpd-lx-info", NULL);
	if (!p)
		return;

	lxr = (const char *)&p[1];

	vpd_lid = vpd_lid_preload(lxr);
}

void preload_io_vpd(void)
{
	const struct dt_property *prop;

	prop = dt_find_property(dt_root, "ibm,io-vpd");
	if (!prop) {
		/* LX VPD Lid not already loaded */
		vpd_preload(dt_root);
	}
}
