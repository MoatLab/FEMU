// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2018 IBM Corp. */

#ifndef pr_fmt
#define pr_fmt(fmt) "TPMREL: " fmt
#endif

#include <skiboot.h>
#include <device.h>

#include "spira.h"
#include "hdata.h"
#include "hdif.h"

static void tpmrel_add_firmware_event_log(const struct HDIF_common_hdr *hdif_hdr)
{
	const struct secureboot_tpm_info *stinfo;
	struct dt_node *xscom, *node;
	uint64_t addr;
	int count, i;
	unsigned int asize;

	/* Are the hdat values populated? */
	if (!HDIF_get_idata(hdif_hdr, TPMREL_IDATA_SECUREBOOT_TPM_INFO, &asize))
		return;
	if (asize < sizeof(struct HDIF_array_hdr)) {
		prlog(PR_ERR, "secureboot_tpm_info idata not populated\n");
		return;
	}

	count = HDIF_get_iarray_size(hdif_hdr, TPMREL_IDATA_SECUREBOOT_TPM_INFO);
	if (count > 1) {
		prlog(PR_ERR, "multiple TPM not supported, count=%d\n", count);
		return;
	}

	/*
	 * There can be multiple secureboot_tpm_info entries with each entry
	 * corresponding to a master processor that has a tpm device.
	 * This looks for the tpm node that supposedly exists under the xscom
	 * node associated with the respective chip_id.
	 */
	for (i = 0; i < count; i++) {

		stinfo = HDIF_get_iarray_item(hdif_hdr,
					      TPMREL_IDATA_SECUREBOOT_TPM_INFO,
					      i, NULL);

		/*
		 * If tpm is not present, hostboot creates an empty
		 * secureboot_tpm_info entry, but setting
		 * tpm_status=TPM_NOT_PRESENT
		 */
		if (stinfo->tpm_status == TPM_NOT_PRESENT)
			continue;

		xscom = find_xscom_for_chip(be32_to_cpu(stinfo->chip_id));
		if (xscom) {
			dt_for_each_node(xscom, node) {
				if (dt_has_node_property(node, "label", "tpm"))
					break;
			}

			if (node) {
				addr = (uint64_t) stinfo +
					be32_to_cpu(stinfo->srtm_log_offset);
				dt_add_property_u64s(node, "linux,sml-base", addr);
				dt_add_property_cells(node, "linux,sml-size",
						      be32_to_cpu(stinfo->srtm_log_size));

				if (stinfo->tpm_status == TPM_PRESENT_AND_NOT_FUNCTIONAL)
					dt_add_property_string(node, "status", "disabled");
			} else {
				/**
				 * @fwts-label HDATNoTpmForChipId
				 * @fwts-advice HDAT secureboot_tpm_info
				 * structure described a chip id, but no tpm
				 * node was found under that xscom chip id.
				 * This is most certainly a hostboot bug.
				 */
				prlog(PR_ERR, "TPM node not found for "
				      "chip_id=%d (HB bug)\n", stinfo->chip_id);
				continue;
			}
		} else {
			/**
			 * @fwts-label HDATBadChipIdForTPM
			 * @fwts-advice HDAT secureboot_tpm_info structure
			 * described a chip id, but the xscom node for the
			 * chip_id was not found.
			 * This is most certainly a firmware bug.
			 */
			prlog(PR_ERR, "xscom node not found for chip_id=%d\n",
			      stinfo->chip_id);
			continue;
		}
	}
}

static struct dt_node *get_hb_reserved_memory(const char *label)
{
	struct dt_node *node, *hb_reserved_mem;

	hb_reserved_mem = dt_find_by_path(dt_root, "/ibm,hostboot/reserved-memory");
	if (!hb_reserved_mem) {
		prlog(PR_DEBUG, "/ibm,hostboot/reserved-memory node not found\n");
		return NULL;
	}

	dt_for_each_node(hb_reserved_mem, node) {
		const char *prd_label;
		if (!dt_find_property(node, "ibm,prd-label"))
			continue;
		prd_label = dt_prop_get(node, "ibm,prd-label");
		if (!strcmp(prd_label, label))
			return node;
	}
	return NULL;
}

static struct {
	uint32_t type;
	const char *compat;
} cvc_services[] = {
	{ TPMREL_HV_SHA512, "ibm,cvc-sha512" },
	{ TPMREL_HV_VERIFY, "ibm,cvc-verify" },
};

static const char* cvc_service_map_compat(uint32_t type) {
	int i;
	for (i = 0; i < ARRAY_SIZE(cvc_services); i++) {
		if (cvc_services[i].type == type)
			return cvc_services[i].compat;
	}
	return NULL;
}

static void tpmrel_cvc_init(struct HDIF_common_hdr *hdif_hdr)
{
	struct dt_node *cvc_reserved_mem, *node, *parent;
	int count, i;
	unsigned int asize;

	/* Are the hdat values populated? */
	if (!HDIF_get_idata(hdif_hdr, TPMREL_IDATA_HASH_VERIF_OFFSETS, &asize))
		return;
	if (asize < sizeof(struct HDIF_array_hdr)) {
		prlog(PR_ERR, "hash_and_verification idata not populated\n");
		return;
	}

	node = dt_find_by_path(dt_root, "/ibm,secureboot");
	if (!node)
		return;

	cvc_reserved_mem = get_hb_reserved_memory("secure-crypt-algo-code");
	if (!cvc_reserved_mem) {
		/* Fallback to old style ibm,prd-label */
		cvc_reserved_mem = get_hb_reserved_memory("ibm,secure-crypt-algo-code");
		if (!cvc_reserved_mem) {
			prlog(PR_ERR, "CVC reserved memory not found\n");
			return;
		}
	}

	parent = dt_new(node, "ibm,cvc");
	assert(parent);
	dt_add_property_cells(parent, "#address-cells", 1);
	dt_add_property_cells(parent, "#size-cells", 0);
	dt_add_property_strings(parent, "compatible", "ibm,container-verification-code");
	dt_add_property_cells(parent, "memory-region", cvc_reserved_mem->phandle);

	/*
	 * Initialize each service provided by the container verification code
	 */
	count = HDIF_get_iarray_size(hdif_hdr, TPMREL_IDATA_HASH_VERIF_OFFSETS);
	if (count <= 0 ) {
		prlog(PR_ERR, "no CVC service found\n");
		return;
	}

	for (i = 0; i < count; i++) {
		const struct hash_and_verification *hv;
		uint32_t type, offset, version;
		const char *compat;

		hv = HDIF_get_iarray_item(hdif_hdr,
					  TPMREL_IDATA_HASH_VERIF_OFFSETS,
					  i, NULL);
		type = be32_to_cpu(hv->type);
		offset = be32_to_cpu(hv->offset);
		version = be32_to_cpu(hv->version);

		compat = cvc_service_map_compat(type);

		if (!compat) {
			prlog(PR_WARNING, "CVC service type 0x%x unknown\n", type);
			continue;
		}

		node = dt_new_addr(parent, "ibm,cvc-service", offset);
		dt_add_property_strings(node, "compatible", compat);
		dt_add_property_cells(node, "reg", offset);
		dt_add_property_cells(node, "version", version);
	}
}

void node_stb_parse(void)
{
	struct HDIF_common_hdr *hdif_hdr;

	hdif_hdr = get_hdif(&spira.ntuples.node_stb_data, STB_HDIF_SIG);
	if (!hdif_hdr) {
		prlog(PR_DEBUG, "TPMREL data not found\n");
		return;
	}

	tpmrel_add_firmware_event_log(hdif_hdr);
	tpmrel_cvc_init(hdif_hdr);
}
