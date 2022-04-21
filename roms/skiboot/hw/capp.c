// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * CAPP unit (i.e. CAPI)
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <io.h>
#include <opal.h>
#include <chip.h>
#include <xscom.h>
#include <capp.h>

#define PHBERR(opal_id, chip_id, index, fmt, a...) \
	       prlog(PR_ERR, "PHB#%04x[%d:%d]: " fmt, \
		     opal_id, chip_id, \
		     index,  ## a)

static struct {
	uint32_t			ec_level;
	struct capp_lid_hdr		*lid;
	size_t size;
	int load_result;
} capp_ucode_info = { 0, NULL, 0, false };

#define CAPP_UCODE_MAX_SIZE 0x20000

struct lock capi_lock = LOCK_UNLOCKED;
struct capp_ops capi_ops = { NULL };

bool capp_ucode_loaded(struct proc_chip *chip, unsigned int index)
{
	return (chip->capp_ucode_loaded & (1 << index));
}

int preload_capp_ucode(void)
{
	struct dt_node *p;
	struct proc_chip *chip;
	uint32_t index;
	uint64_t rc;
	int ret;

	/* CAPI is supported on P8 and P9 only */
	p = dt_find_compatible_node(dt_root, NULL, "ibm,power8-pbcq");
	if (!p)
		p = dt_find_compatible_node(dt_root, NULL, "ibm,power9-pbcq");
	if (!p)
		return OPAL_SUCCESS;

	chip = get_chip(dt_get_chip_id(p));

	rc = xscom_read_cfam_chipid(chip->id, &index);
	if (rc) {
		prerror("CAPP: Error reading cfam chip-id\n");
		ret = OPAL_HARDWARE;
		return ret;
	}
	/* Keep ChipID and Major/Minor EC.  Mask out the Location Code. */
	index = index & 0xf0fff;

	/* Assert that we're preloading */
	assert(capp_ucode_info.lid == NULL);
	capp_ucode_info.load_result = OPAL_EMPTY;

	capp_ucode_info.ec_level = index;

	/* Is the ucode preloaded like for BML? */
	if (dt_has_node_property(p, "ibm,capp-ucode", NULL)) {
		capp_ucode_info.lid = (struct capp_lid_hdr *)(u64)
			dt_prop_get_u32(p, "ibm,capp-ucode");
		capp_ucode_info.load_result = OPAL_SUCCESS;
		ret = OPAL_SUCCESS;
		goto end;
	}
	/* If we successfully download the ucode, we leave it around forever */
	capp_ucode_info.size = CAPP_UCODE_MAX_SIZE;
	capp_ucode_info.lid = malloc(CAPP_UCODE_MAX_SIZE);
	if (!capp_ucode_info.lid) {
		prerror("CAPP: Can't allocate space for ucode lid\n");
		ret = OPAL_NO_MEM;
		goto end;
	}

	prlog(PR_INFO, "CAPI: Preloading ucode %x\n", capp_ucode_info.ec_level);

	ret = start_preload_resource(RESOURCE_ID_CAPP, index,
				     capp_ucode_info.lid,
				     &capp_ucode_info.size);

	if (ret != OPAL_SUCCESS) {
		prerror("CAPI: Failed to preload resource %d\n", ret);
		capp_ucode_info.load_result = ret;
	}

end:
	return ret;
}

static int64_t capp_lid_download(void)
{
	int64_t ret;

	if (capp_ucode_info.load_result != OPAL_EMPTY)
		return capp_ucode_info.load_result;

	capp_ucode_info.load_result = wait_for_resource_loaded(
		RESOURCE_ID_CAPP,
		capp_ucode_info.ec_level);

	if (capp_ucode_info.load_result != OPAL_SUCCESS) {
		prerror("CAPP: Error loading ucode lid. index=%x\n",
			capp_ucode_info.ec_level);
		ret = OPAL_RESOURCE;
		free(capp_ucode_info.lid);
		capp_ucode_info.lid = NULL;
		goto end;
	}

	ret = OPAL_SUCCESS;
end:
	return ret;
}

int64_t capp_load_ucode(unsigned int chip_id, uint32_t opal_id,
			unsigned int index, u64 lid_eyecatcher,
			uint32_t reg_offset,
			uint64_t apc_master_addr, uint64_t apc_master_write,
			uint64_t snp_array_addr, uint64_t snp_array_write)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct capp_ucode_lid *ucode;
	struct capp_ucode_data *data;
	struct capp_lid_hdr *lid;
	uint64_t rc, val, addr;
	uint32_t chunk_count, offset;
	int i;

	if (capp_ucode_loaded(chip, index))
		return OPAL_SUCCESS;

	rc = capp_lid_download();
	if (rc)
		return rc;

	prlog(PR_INFO, "CHIP%i: CAPP ucode lid loaded at %p\n",
	      chip_id, capp_ucode_info.lid);

	lid = capp_ucode_info.lid;
	/*
	 * If lid header is present (on FSP machines), it'll tell us where to
	 * find the ucode.  Otherwise this is the ucode.
	 */
	ucode = (struct capp_ucode_lid *)lid;
	if (be64_to_cpu(lid->eyecatcher) == lid_eyecatcher) {
		if (be64_to_cpu(lid->version) != 0x1) {
			PHBERR(opal_id, chip_id, index,
			       "capi ucode lid header invalid\n");
			return OPAL_HARDWARE;
		}
		ucode = (struct capp_ucode_lid *)
			((char *)ucode + be64_to_cpu(lid->ucode_offset));
	}

	/* 'CAPPULID' in ASCII */
	if ((be64_to_cpu(ucode->eyecatcher) != 0x43415050554C4944UL) ||
	    (be64_to_cpu(ucode->version) != 1)) {
		PHBERR(opal_id, chip_id, index,
		       "CAPP: ucode header invalid\n");
		return OPAL_HARDWARE;
	}

	offset = 0;
	while (offset < be64_to_cpu(ucode->data_size)) {
		data = (struct capp_ucode_data *)
			((char *)&ucode->data + offset);
		chunk_count = be32_to_cpu(data->hdr.chunk_count);
		offset += sizeof(struct capp_ucode_data_hdr) + chunk_count * 8;

		/* 'CAPPUCOD' in ASCII */
		if (be64_to_cpu(data->hdr.eyecatcher) != 0x4341505055434F44UL) {
			PHBERR(opal_id, chip_id, index,
			       "CAPP: ucode data header invalid:%i\n",
			       offset);
			return OPAL_HARDWARE;
		}

		switch (data->hdr.reg) {
		case apc_master_cresp:
			xscom_write(chip_id, apc_master_addr + reg_offset,
				    0);
			addr = apc_master_write;
			break;
		case apc_master_uop_table:
			xscom_write(chip_id, apc_master_addr + reg_offset,
				    0x180ULL << 52);
			addr = apc_master_write;
			break;
		case snp_ttype:
			xscom_write(chip_id, snp_array_addr + reg_offset,
				    0x5000ULL << 48);
			addr = snp_array_write;
			break;
		case snp_uop_table:
			xscom_write(chip_id, snp_array_addr + reg_offset,
				    0x4000ULL << 48);
			addr = snp_array_write;
			break;
		default:
			continue;
		}

		for (i = 0; i < chunk_count; i++) {
			val = be64_to_cpu(data->data[i]);
			xscom_write(chip_id, addr + reg_offset, val);
		}
	}

	chip->capp_ucode_loaded |= (1 << index);

	return OPAL_SUCCESS;
}

int64_t capp_get_info(int chip_id, struct phb *phb, struct capp_info *info)
{
	if (capi_ops.get_capp_info)
		return capi_ops.get_capp_info(chip_id, phb, info);

	return OPAL_PARAMETER;
}

int64_t capp_xscom_read(struct capp *capp, int64_t off, uint64_t *val)
{
	return capp == NULL ? OPAL_PARAMETER :
		xscom_read(capp->chip_id, off + capp->capp_xscom_offset, val);
}

int64_t capp_xscom_write(struct capp *capp, int64_t off, uint64_t val)
{
	return capp == NULL ? OPAL_PARAMETER :
		xscom_write(capp->chip_id, off + capp->capp_xscom_offset, val);
}
