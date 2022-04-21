// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <skiboot.h>
#include "spira.h"
#include <cpu.h>
#include <fsp.h>
#include <opal.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>
#include <device.h>
#include <vpd.h>
#include <inttypes.h>
#include <string.h>

#include "hdata.h"

static bool io_get_lx_info(const void *kwvpd, unsigned int kwvpd_sz,
			   int lx_idx, struct dt_node *hn)
{
	const void *lxr;
	char recname[5];
	beint32_t lxrbuf[2] = { 0, 0 };

	/* Find LXRn, where n is the index passed in*/
	strcpy(recname, "LXR0");
	recname[3] += lx_idx;
	lxr = vpd_find(kwvpd, kwvpd_sz, recname, "LX", NULL);
	if (!lxr) {
		/* Not found, try VINI */
		lxr = vpd_find(kwvpd, kwvpd_sz, "VINI",
			       "LX",  NULL);
		if (lxr)
			lx_idx = VPD_LOAD_LXRN_VINI;
	}
	if (!lxr) {
		prlog(PR_DEBUG, "CEC:     LXR%x not found !\n", lx_idx);
		return false;
	}

	memcpy(lxrbuf, lxr, sizeof(beint32_t)*2);

	prlog(PR_DEBUG, "CEC:     LXRn=%d LXR=%08x%08x\n", lx_idx, be32_to_cpu(lxrbuf[0]), be32_to_cpu(lxrbuf[1]));
	prlog(PR_DEBUG, "CEC:     LX Info added to %llx\n", (long long)hn);

	/* Add the LX info */
	if (!dt_has_node_property(hn, "ibm,vpd-lx-info", NULL)) {
		dt_add_property_cells(hn, "ibm,vpd-lx-info",
				      lx_idx,
				      be32_to_cpu(lxrbuf[0]),
				      be32_to_cpu(lxrbuf[1]));
	}

	return true;
}


static void io_get_loc_code(const void *sp_iohubs, struct dt_node *hn, const char *prop_name)
{
	const struct spira_fru_id *fru_id;
	unsigned int fru_id_sz;
	char loc_code[LOC_CODE_SIZE + 1];
	const char *slca_loc_code;

	/* Find SLCA Index */
	fru_id = HDIF_get_idata(sp_iohubs, CECHUB_FRU_ID_DATA, &fru_id_sz);
	if (fru_id) {
		memset(loc_code, 0, sizeof(loc_code));

		/* Find LOC Code from SLCA Index */
		slca_loc_code = slca_get_loc_code_index(be16_to_cpu(fru_id->slca_index));
		if (slca_loc_code) {
			strncpy(loc_code, slca_loc_code, LOC_CODE_SIZE);
			if (!dt_has_node_property(hn, prop_name, NULL)) {
				dt_add_property(hn, prop_name, loc_code,
						strlen(loc_code) + 1);
			}
			prlog(PR_DEBUG, "CEC:     %s: %s (SLCA rsrc 0x%x)\n",
			      prop_name, loc_code,
			      be16_to_cpu(fru_id->rsrc_id));
		} else {
			prlog(PR_DEBUG, "CEC:     SLCA Loc not found: "
			      "index %d\n", fru_id->slca_index);
		}
	} else {
		prlog(PR_DEBUG, "CEC:     Hub FRU ID not found...\n");
	}
}

static struct dt_node *io_add_phb3(const struct cechub_io_hub *hub,
				   const struct HDIF_common_hdr *sp_iohubs,
				   unsigned int index, struct dt_node *xcom,
				   unsigned int pe_xscom,
				   unsigned int pci_xscom,
				   unsigned int spci_xscom)
{
	struct dt_node *pbcq;
	unsigned int hdif_vers;

	/* Get HDIF version */
	hdif_vers = be16_to_cpu(sp_iohubs->version);

	/* Create PBCQ node under xscom */
	pbcq = dt_new_addr(xcom, "pbcq", pe_xscom);
	if (!pbcq)
		return NULL;

	/* "reg" property contains in order the PE, PCI and SPCI XSCOM
	 * addresses
	 */
	dt_add_property_cells(pbcq, "reg",
				pe_xscom, 0x20,
				pci_xscom, 0x05,
				spci_xscom, 0x15);

	/* A couple more things ... */
	dt_add_property_strings(pbcq, "compatible", "ibm,power8-pbcq");
	dt_add_property_cells(pbcq, "ibm,phb-index", index);
	dt_add_property_cells(pbcq, "ibm,hub-id", be16_to_cpu(hub->hub_num));

	/* The loc code of the PHB itself is different from the base
	 * loc code of the slots (It's actually the DCM's loc code).
	 */
	io_get_loc_code(sp_iohubs, pbcq, "ibm,loc-code");

	/* We indicate that this is an IBM setup, which means that
	 * the presence detect A/B bits are meaningful. So far we
	 * don't know whether they make any sense on customer setups
	 * so we only set that when booting with HDAT
	 */
	dt_add_property(pbcq, "ibm,use-ab-detect", NULL, 0);

	/* HDAT spec has these in version 0x6A and later */
	if (hdif_vers >= 0x6a) {
		u64 eq0 = be64_to_cpu(hub->phb_lane_eq[index][0]);
		u64 eq1 = be64_to_cpu(hub->phb_lane_eq[index][1]);
		u64 eq2 = be64_to_cpu(hub->phb_lane_eq[index][2]);
		u64 eq3 = be64_to_cpu(hub->phb_lane_eq[index][3]);

		dt_add_property_u64s(pbcq, "ibm,lane-eq", eq0, eq1, eq2, eq3);
	}

	/* Currently we only create a PBCQ node, the actual PHB nodes
	 * will be added by sapphire later on.
	 */
	return pbcq;
}

static struct dt_node *add_pec_stack(const struct cechub_io_hub *hub,
				     struct dt_node *pbcq, int stack_index,
				     int phb_index, u8 active_phbs)
{
	struct dt_node *stack;
	const char *compat;
	u64 eq[12];
	u8 *ptr;
	int i;

	stack = dt_new_addr(pbcq, "stack", stack_index);
	assert(stack);

	if (proc_gen == proc_gen_p9)
		compat = "ibm,power9-phb-stack";
	else
		compat = "ibm,power10-phb-stack";

	dt_add_property_cells(stack, "reg", stack_index);
	dt_add_property_cells(stack, "ibm,phb-index", phb_index);
	dt_add_property_string(stack, "compatible", compat);

	/* XXX: This should probably just return if the PHB is disabled
	 *      rather than adding the extra properties.
	 */

	if (active_phbs & (0x80 >> phb_index))
		dt_add_property_string(stack, "status", "okay");
	else
		dt_add_property_string(stack, "status", "disabled");

	for (i = 0; i < 4; i++) /* gen 3 eq settings */
		eq[i] = be64_to_cpu(hub->phb_lane_eq[phb_index][i]);
	for (i = 0; i < 4; i++) /* gen 4 eq settings */
		eq[i+4] = be64_to_cpu(hub->phb4_lane_eq[phb_index][i]);
	for (i = 0; i < 4; i++) /* gen 5 eq settings */
		eq[i+8] = be64_to_cpu(hub->phb5_lane_eq[phb_index][i]);

	/* Lane-eq settings are packed 2 bytes per lane for 16 lanes
	 * On P9 DD2 and P10, 1 byte per lane is used in the hardware
	 */

	/* Repack 2 byte lane settings into 1 byte for gen 4 & 5 */
	ptr = (u8 *)&eq[4];
	for (i = 0; i < 32; i++)
		ptr[i] = ptr[2*i];

	if (proc_gen == proc_gen_p9)
		dt_add_property_u64s(stack, "ibm,lane-eq",
				     eq[0], eq[1], eq[2], eq[3],
				     eq[4], eq[5]);
	else
		dt_add_property_u64s(stack, "ibm,lane-eq",
				     eq[0], eq[1], eq[2], eq[3],
				     eq[4], eq[5],
				     eq[6], eq[7]);
	return stack;
}

/* Add PHB4 on p9, PHB5 on p10 */
static struct dt_node *io_add_phb4(const struct cechub_io_hub *hub,
				   const struct HDIF_common_hdr *sp_iohubs,
				   struct dt_node *xcom,
				   unsigned int pec_index,
				   int stacks,
				   int phb_base)
{
	struct dt_node *pbcq;
	uint8_t active_phb_mask = hub->fab_br0_pdt;
	uint32_t pe_xscom;
	uint32_t pci_xscom;
	const char *compat;
	int i;

	if (proc_gen == proc_gen_p9) {
		pe_xscom  = 0x4010c00 + (pec_index * 0x0000400);
		pci_xscom = 0xd010800 + (pec_index * 0x1000000);
		compat = "ibm,power9-pbcq";
	} else {
		pe_xscom  = 0x3011800 - (pec_index * 0x1000000);
		pci_xscom = 0x8010800 + (pec_index * 0x1000000);
		compat = "ibm,power10-pbcq";
	}

	/* Create PBCQ node under xscom */
	pbcq = dt_new_addr(xcom, "pbcq", pe_xscom);
	if (!pbcq)
		return NULL;

	/* "reg" property contains (in order) the PE and PCI XSCOM addresses */
	dt_add_property_cells(pbcq, "reg",
				pe_xscom, 0x100,
				pci_xscom, 0x200);

	/* The hubs themselves go under the stacks */
	dt_add_property_strings(pbcq, "compatible", compat);
	dt_add_property_cells(pbcq, "ibm,pec-index", pec_index);
	dt_add_property_cells(pbcq, "#address-cells", 1);
	dt_add_property_cells(pbcq, "#size-cells", 0);

	for (i = 0; i < stacks; i++)
		add_pec_stack(hub, pbcq, i, phb_base + i, active_phb_mask);

	dt_add_property_cells(pbcq, "ibm,hub-id", be16_to_cpu(hub->hub_num));

	/* The loc code of the PHB itself is different from the base
	 * loc code of the slots (It's actually the DCM's loc code).
	 */
	io_get_loc_code(sp_iohubs, pbcq, "ibm,loc-code");

	prlog(PR_INFO, "CEC: Added PBCQ %d with %d stacks\n",
		pec_index, stacks);

	/* the actual PHB nodes created later on by skiboot */
	return pbcq;
}

static struct dt_node *io_add_p8(const struct cechub_io_hub *hub,
				 const struct HDIF_common_hdr *sp_iohubs)
{
	struct dt_node *xscom;
	unsigned int i, chip_id;

	chip_id = pcid_to_chip_id(be32_to_cpu(hub->proc_chip_id));

	prlog(PR_INFO, "CEC:     HW CHIP=0x%x, HW TOPO=0x%04x\n", chip_id,
	      be16_to_cpu(hub->hw_topology));

	xscom = find_xscom_for_chip(chip_id);
	if (!xscom) {
		prerror("P8: Can't find XSCOM for chip %d\n", chip_id);
		return NULL;
	}

	/* Create PHBs, max 3 */
	for (i = 0; i < 3; i++) {
		if (hub->fab_br0_pdt & (0x80 >> i))
			/* XSCOM addresses are the same on Murano and Venice */
			io_add_phb3(hub, sp_iohubs, i, xscom,
				    0x02012000 + (i * 0x400),
				    0x09012000 + (i * 0x400),
				    0x09013c00 + (i * 0x40));
	}

	/* HACK: We return the XSCOM device for the VPD info */
	return xscom;
}

/* Add PBCQs for p9/p10 */
static struct dt_node *io_add_p9(const struct cechub_io_hub *hub,
				 const struct HDIF_common_hdr *sp_iohubs)
{
	struct dt_node *xscom;
	unsigned int chip_id;

	chip_id = pcid_to_chip_id(be32_to_cpu(hub->proc_chip_id));

	prlog(PR_INFO, "CEC:     HW CHIP=0x%x, HW TOPO=0x%04x\n", chip_id,
	      be16_to_cpu(hub->hw_topology));

	xscom = find_xscom_for_chip(chip_id);
	if (!xscom) {
		prerror("IOHUB: Can't find XSCOM for chip %d\n", chip_id);
		return NULL;
	}

	prlog(PR_DEBUG, "IOHUB: PHB active bridge mask %x\n",
		(u32) hub->fab_br0_pdt);

	/* Create PBCQs */
	if (proc_gen == proc_gen_p9) {
		io_add_phb4(hub, sp_iohubs, xscom, 0, 1, 0);
		io_add_phb4(hub, sp_iohubs, xscom, 1, 2, 1);
		io_add_phb4(hub, sp_iohubs, xscom, 2, 3, 3);
	} else { /* p10 */
		io_add_phb4(hub, sp_iohubs, xscom, 0, 3, 0);
		io_add_phb4(hub, sp_iohubs, xscom, 1, 3, 3);
	}

	return xscom;
}


static void io_add_p8_cec_vpd(const struct HDIF_common_hdr *sp_iohubs)
{
	const struct HDIF_child_ptr *iokids;
	const void *iokid;	
	const void *kwvpd;
	unsigned int kwvpd_sz;

	/* P8 LXR0 kept in IO KID Keyword VPD */
	iokids = HDIF_child_arr(sp_iohubs, CECHUB_CHILD_IO_KIDS);
	if (!CHECK_SPPTR(iokids)) {
		prlog(PR_WARNING, "CEC:     No IOKID child array !\n");
		return;
	}
	if (!iokids->count) {
		prlog(PR_WARNING, "CEC:     IOKID count is 0 !\n");
		return;
	}
	if (be32_to_cpu(iokids->count) > 1) {
		prlog(PR_WARNING, "CEC:     WARNING ! More than 1 IO KID !!! (%d)\n",
		      be32_to_cpu(iokids->count));
		/* Ignoring the additional ones */
	}

	iokid = HDIF_child(sp_iohubs, iokids, 0, "IO KID");
	if (!iokid) {
		prlog(PR_WARNING, "CEC:     No IO KID structure in child array !\n");
		return;
	}

	/* Grab base location code for slots */
	io_get_loc_code(iokid, dt_root, "ibm,io-base-loc-code");

	kwvpd = HDIF_get_idata(iokid, CECHUB_ASCII_KEYWORD_VPD, &kwvpd_sz);
	if (!kwvpd) {
		prlog(PR_WARNING, "CEC:     No VPD entry in IO KID !\n");
		return;
	}

	/* Grab LX load info */
	io_get_lx_info(kwvpd, kwvpd_sz, 0, dt_root);
}

/*
 * Assumptions:
 *
 * a) the IOSLOT index is the hub ID -CHECK
 *
 */

static struct dt_node *dt_slots;

static void add_i2c_link(struct dt_node *node, const char *link_name,
			u32 i2c_link)
{
	/* FIXME: Do something not shit */
	dt_add_property_cells(node, link_name, i2c_link);
}

/*
 * the root of the slots node has #address-cells = 2, <hub-index, phb-index>
 * can we ditch hub-index?
 */


static const struct slot_map_details *find_slot_details(
		const struct HDIF_common_hdr *ioslot, int entry)
{
	const struct slot_map_details *details = NULL;
	const struct HDIF_array_hdr *arr;
	unsigned int i;

	arr = HDIF_get_iarray(ioslot, IOSLOT_IDATA_DETAILS, NULL);
	HDIF_iarray_for_each(arr, i, details)
		if (be16_to_cpu(details->entry) == entry)
			break;

	return details;
}

static void parse_slot_details(struct dt_node *slot,
		const struct slot_map_details *details)
{
	u32 slot_caps;

	/*
	 * generic slot options
	 */

	dt_add_property_cells(slot, "max-power",
		be16_to_cpu(details->max_power));

	if (details->perst_ctl_type == SLOT_PERST_PHB_OR_SW)
		dt_add_property(slot, "pci-perst", NULL, 0);
	else if (details->perst_ctl_type == SLOT_PERST_SW_GPIO)
		dt_add_property_cells(slot, "gpio-perst", details->perst_gpio);

	if (details->presence_det_type == SLOT_PRESENCE_PCI)
		dt_add_property(slot, "pci-presence-detect", NULL, 0);

	/*
	 * specific slot capabilities
	 */
	slot_caps = be32_to_cpu(details->slot_caps);

	if (slot_caps & SLOT_CAP_LSI)
		dt_add_property(slot, "lsi", NULL, 0);

	if (slot_caps & SLOT_CAP_CAPI) {
		/* XXX: should we be more specific here?
		 *
		 * Also we should double check that this slot
		 * is a root connected slot.
		 */
		dt_add_property(slot, "capi", NULL, 0);
	}

	if (slot_caps & SLOT_CAP_CCARD) {
		dt_add_property(slot, "cable-card", NULL, 0);

		if (details->presence_det_type == SLOT_PRESENCE_I2C)
			add_i2c_link(slot, "i2c-presence-detect",
				be32_to_cpu(details->i2c_cable_card));
	}

	if (slot_caps & SLOT_CAP_HOTPLUG) {
		dt_add_property(slot, "hotplug", NULL, 0);

		/*
		 * Power control should only exist when the slot is hotplug
		 * capable
		 */
		if (details->power_ctrl_type == SLOT_PWR_I2C)
			add_i2c_link(slot, "i2c-power-ctrl",
				be32_to_cpu(details->i2c_power_ctl));
	}

	/*
	 * NB: Additional NVLink specific info is added to this node
	 *     when the SMP Link structures are parsed later on.
	 */
	if (slot_caps & SLOT_CAP_NVLINK)
		dt_add_property(slot, "nvlink", NULL, 0);
}

struct dt_node *find_slot_entry_node(struct dt_node *root, u32 entry_id)
{
	struct dt_node *node;

	for (node = dt_first(root); node; node = dt_next(root, node)) {
		if (!dt_has_node_property(node, DT_PRIVATE "entry_id", NULL))
			continue;

		if (dt_prop_get_u32(node, DT_PRIVATE "entry_id") == entry_id)
			return node;
	}

	return NULL;
}

/*
 * The internal HDAT representation of the various types of slot is kinda
 * dumb, translate it into something more sensible
 */
enum slot_types {
	st_root,
	st_slot,
	st_rc_slot,
	st_sw_upstream,
	st_sw_downstream,
	st_builtin
};

static const char *st_name(enum slot_types type)
{
	switch(type) {
	case st_root:		return "root-complex";
	case st_slot:		return "pluggable";
	case st_rc_slot:	return "pluggable"; /* differentiate? */
	case st_sw_upstream:	return "switch-up";
	case st_sw_downstream:	return "switch-down";
	case st_builtin:	return "builtin";
	}

	return "(none)";
}

static enum slot_types xlate_type(uint8_t type, u32 features)
{
	bool is_slot = features & SLOT_FEAT_SLOT;

	switch (type) {
	case SLOT_TYPE_ROOT_COMPLEX:
		return is_slot ? st_rc_slot : st_root;
	case SLOT_TYPE_BUILTIN:
		return st_builtin;
	case SLOT_TYPE_SWITCH_UP:
		return st_sw_upstream;
	case SLOT_TYPE_SWITCH_DOWN:
		return is_slot ? st_slot : st_sw_downstream;
	}

	return -1; /* shouldn't happen */
}

static bool is_port(struct dt_node *n)
{
	//return dt_node_is_compatible(n, "compatible", "ibm,pcie-port");
	return dt_node_is_compatible(n, "ibm,pcie-port");
}

/* this only works inside parse_one_ioslot() */
#define SM_LOG(level, fmt, ...) \
	prlog(level, "SLOTMAP: %x:%d:%d " \
		fmt, /* user input */ \
		chip_id, entry->phb_index, eid, \
		##__VA_ARGS__ /* user args */)

#define SM_ERR(fmt, ...) SM_LOG(PR_ERR, fmt, ##__VA_ARGS__)
#define SM_DBG(fmt, ...) SM_LOG(PR_DEBUG, fmt, ##__VA_ARGS__)

static void parse_one_slot(const struct slot_map_entry *entry,
		const struct slot_map_details *details, int chip_id)
{
	struct dt_node *node, *parent = NULL;
	u16 eid, pid, vid, did;
	u32 flags;
	int type;

	flags = be32_to_cpu(entry->features);
	type = xlate_type(entry->type, flags);

	eid = be16_to_cpu(entry->entry_id);
	pid = be16_to_cpu(entry->parent_id);

	SM_DBG("%s - eid = %d, pid = %d, name = %8s\n",
		st_name(type), eid, pid,
		strnlen(entry->name, 8) ? entry->name : "");

	/* empty slot, ignore it */
	if (eid == 0x0 && pid == 0x0)
		return;

	if (type != st_root && type != st_rc_slot) {
		parent = find_slot_entry_node(dt_slots, pid);
		if (!parent) {
			SM_ERR("Unable to find node for parent slot (id = %d)\n",
				pid);
			return;
		}
	}

	switch (type) {
	case st_root:
	case st_rc_slot:
		node = dt_new_2addr(dt_slots, "root-complex",
						chip_id, entry->phb_index);
		if (!node) {
			SM_ERR("Couldn't add DT node\n");
			return;
		}
		dt_add_property_cells(node, "reg", chip_id, entry->phb_index);
		dt_add_property_cells(node, "#address-cells", 2);
		dt_add_property_cells(node, "#size-cells", 0);
		dt_add_property_strings(node, "compatible",
				"ibm,pcie-port", "ibm,pcie-root-port");
		dt_add_property_cells(node, "ibm,chip-id", chip_id);
		parent = node;

		/*
		 * The representation of slots attached directly to the
		 * root complex is a bit wierd. If this is just a root
		 * complex then stop here, otherwise fall through to create
		 * the slot node.
		 */
		if (type == st_root)
			break;

		/* fallthrough*/
	case st_sw_upstream:
	case st_builtin:
	case st_slot:
		if (!is_port(parent)) {
			SM_ERR("%s connected to %s (%d), should be %s or %s!\n",
				st_name(type), parent->name, pid,
				st_name(st_root), st_name(st_sw_downstream));
			return;
		}

		vid = (be32_to_cpu(entry->vendor_id) & 0xffff);
		did = (be32_to_cpu(entry->device_id) & 0xffff);

		prlog(PR_DEBUG, "Found %s slot with %x:%x\n",
			st_name(type), vid, did);

		/* The VID:DID is only meaningful for builtins and switches */
		if (type == st_sw_upstream && vid && did) {
			node = dt_new_2addr(parent, st_name(type), vid, did);
			dt_add_property_cells(node, "reg", vid, did);
		} else {
			/*
			 * If we get no vdid then create a "wildcard" slot
			 * that matches any device
			 */
			node = dt_new(parent, st_name(type));
		}

		if (type == st_sw_upstream) {
			dt_add_property_cells(node, "#address-cells", 1);
			dt_add_property_cells(node, "#size-cells", 0);
			dt_add_property_cells(node, "upstream-port",
					entry->up_port);
		}
		break;

	case st_sw_downstream: /* slot connected to switch output */
		node = dt_new_addr(parent, "down-port", entry->down_port);
		dt_add_property_strings(node, "compatible",
				"ibm,pcie-port");
		dt_add_property_cells(node, "reg", entry->down_port);

		break;

	default:
		SM_ERR("Unknown slot map type %x\n", entry->type);
		return;
	}

	/*
	 * Now add any generic slot map properties.
	 */

	/* private since we don't want hdat stuff leaking */
	dt_add_property_cells(node, DT_PRIVATE "entry_id", eid);

	if (entry->mrw_slot_id)
		dt_add_property_cells(node, "mrw-slot-id",
				be16_to_cpu(entry->mrw_slot_id));

	if (entry->lane_mask)
		dt_add_property_cells(node, "lane-mask",
				be16_to_cpu(entry->lane_mask));

	/* what is the difference between this and the lane reverse? */
	if (entry->lane_reverse)
		dt_add_property_cells(node, "lanes-reversed",
				be16_to_cpu(entry->lane_reverse));

	if (strnlen(entry->name, sizeof(entry->name))) {
		/*
		 * HACK: On some platforms (witherspoon) the slot label is
		 * applied to the device rather than the pcie downstream port
		 * that has the slot under it. Hack around this by moving the
		 * slot label up if the parent port doesn't have one.
		 */
		if (dt_node_is_compatible(node->parent, "ibm,pcie-port") &&
		    !dt_find_property(node->parent, "ibm,slot-label")) {
			dt_add_property_nstr(node->parent, "ibm,slot-label",
					entry->name, sizeof(entry->name));
		}

		dt_add_property_nstr(node, "ibm,slot-label",
				entry->name, sizeof(entry->name));
	}

	if (entry->type == st_slot || entry->type == st_rc_slot)
		dt_add_property(node, "ibm,pluggable", NULL, 0);

	if (details)
		parse_slot_details(node, details);
}

/*
 * Under the IOHUB structure we have and idata array describing
 * the PHBs under each chip. The IOHUB structure also has a child
 * array called IOSLOT which describes slot map. The i`th element
 * of the IOSLOT array corresponds to the slot map of the i`th
 * element of the iohubs idata array.
 *
 * Probably.
 *
 * Furthermore, arrayarrayarrayarrayarray.
 */

static struct dt_node *get_slot_node(void)
{
	struct dt_node *slots = dt_find_by_name(dt_root, "ibm,pcie-slots");

	if (!slots) {
		slots = dt_new(dt_root, "ibm,pcie-slots");
		dt_add_property_cells(slots, "#address-cells", 2);
		dt_add_property_cells(slots, "#size-cells", 0);
	}

	return slots;
}

static void io_parse_slots(const struct HDIF_common_hdr *sp_iohubs, int hub_id)
{
	const struct HDIF_child_ptr *ioslot_arr;
	const struct HDIF_array_hdr *entry_arr;
	const struct HDIF_common_hdr *ioslot;
	const struct slot_map_entry *entry;
	unsigned int i, count;

	if (be16_to_cpu(sp_iohubs->child_count) <= CECHUB_CHILD_IOSLOTS)
		return;

	ioslot_arr = HDIF_child_arr(sp_iohubs, CECHUB_CHILD_IOSLOTS);
	if (!ioslot_arr)
		return;

	count = be32_to_cpu(ioslot_arr->count); /* should only be 1 */
	if (!count)
		return;

	dt_slots = get_slot_node();

	prlog(PR_DEBUG, "CEC: Found slot map for IOHUB %d\n", hub_id);
	if (count > 1)
		prerror("CEC: Multiple IOSLOTs found for IO HUB %d\n", hub_id);

	ioslot = HDIF_child(sp_iohubs, ioslot_arr, 0, "IOSLOT");
	if (!ioslot)
		return;

	entry_arr = HDIF_get_iarray(ioslot, IOSLOT_IDATA_SLOTMAP, NULL);
	HDIF_iarray_for_each(entry_arr, i, entry) {
		const struct slot_map_details *details;

		details = find_slot_details(ioslot,
				be16_to_cpu(entry->entry_id));
		parse_one_slot(entry, details, hub_id);
	}
}

static void io_parse_fru(const void *sp_iohubs)
{
	unsigned int i;
	int count;

	count = HDIF_get_iarray_size(sp_iohubs, CECHUB_FRU_IO_HUBS);
	if (count < 1) {
		prerror("CEC: IO FRU with no chips !\n");
		return;
	}

	prlog(PR_INFO, "CEC:   %d chips in FRU\n", count);

	/* Iterate IO hub array */
	for (i = 0; i < count; i++) {
		const struct cechub_io_hub *hub;
		unsigned int size, hub_id;
		uint32_t chip_id;

		hub = HDIF_get_iarray_item(sp_iohubs, CECHUB_FRU_IO_HUBS,
					   i, &size);
		if (!hub || size < CECHUB_IOHUB_MIN_SIZE) {
			prerror("CEC:     IO-HUB Chip %d bad idata\n", i);
			continue;
		}

		switch (hub->flags & CECHUB_HUB_FLAG_STATE_MASK) {
		case CECHUB_HUB_FLAG_STATE_OK:
			prlog(PR_DEBUG, "CEC:   IO Hub Chip #%d OK\n", i);
			break;
		case CECHUB_HUB_FLAG_STATE_FAILURES:
			prlog(PR_WARNING, "CEC:   IO Hub Chip #%d OK"
			      " with failures\n", i);
			break;
		case CECHUB_HUB_FLAG_STATE_NOT_INST:
			prlog(PR_DEBUG, "CEC:   IO Hub Chip #%d"
			      " Not installed\n", i);
			continue;
		case CECHUB_HUB_FLAG_STATE_UNUSABLE:
			prlog(PR_DEBUG, "CEC:   IO Hub Chip #%d Unusable\n", i);
			continue;
		}

		hub_id = be16_to_cpu(hub->iohub_id);

		/* GX BAR assignment */
		prlog(PR_DEBUG, "CEC:   PChip: %d HUB ID: %04x [EC=0x%x]"
		      " Hub#=%d)\n",
		      be32_to_cpu(hub->proc_chip_id), hub_id,
		      be32_to_cpu(hub->ec_level), be16_to_cpu(hub->hub_num));

		switch(hub_id) {
		case CECHUB_HUB_MURANO:
		case CECHUB_HUB_MURANO_SEGU:
			prlog(PR_INFO, "CEC:     Murano !\n");
			io_add_p8(hub, sp_iohubs);
			break;
		case CECHUB_HUB_VENICE_WYATT:
			prlog(PR_INFO, "CEC:     Venice !\n");
			io_add_p8(hub, sp_iohubs);
			break;
		case CECHUB_HUB_NIMBUS_SFORAZ:
		case CECHUB_HUB_NIMBUS_MONZA:
		case CECHUB_HUB_NIMBUS_LAGRANGE:
			prlog(PR_INFO, "CEC:     Nimbus !\n");
			io_add_p9(hub, sp_iohubs);
			break;
		case CECHUB_HUB_CUMULUS_DUOMO:
			prlog(PR_INFO, "CEC:     Cumulus !\n");
			io_add_p9(hub, sp_iohubs);
			break;
		case CECHUB_HUB_AXONE_HOPPER:
			prlog(PR_INFO, "CEC:     Axone !\n");
			io_add_p9(hub, sp_iohubs);
			break;
		case CECHUB_HUB_RAINIER:
			prlog(PR_INFO, "CEC:     Rainier !\n");
			io_add_p9(hub, sp_iohubs);
			break;
		case CECHUB_HUB_DENALI:
			prlog(PR_INFO, "CEC:     Denali !\n");
			io_add_p9(hub, sp_iohubs);
			break;
		default:
			prlog(PR_ERR, "CEC:     Hub ID 0x%04x unsupported !\n",
			      hub_id);
		}

		chip_id = pcid_to_chip_id(be32_to_cpu(hub->proc_chip_id));

		/* parse the slot map if we have one */
		io_parse_slots(sp_iohubs, chip_id);
	}

	if (proc_gen == proc_gen_p8 || proc_gen == proc_gen_p9 || proc_gen == proc_gen_p10)
		io_add_p8_cec_vpd(sp_iohubs);
}

void io_parse(void)
{
	const struct HDIF_common_hdr *sp_iohubs;
	unsigned int i, size;

	/* Look for IO Hubs */
	if (!get_hdif(&spira.ntuples.cec_iohub_fru, "IO HUB")) {
		prerror("CEC: Cannot locate IO Hub FRU data !\n");
		return;
	}

	/*
	 * Note about LXRn numbering ...
	 *
	 * I can't completely make sense of what that is supposed to be, so
	 * for now, what we do is look for the first one we can find and
	 * increment it for each chip. Works for the machines I have here
	 */

	for_each_ntuple_idx(&spira.ntuples.cec_iohub_fru, sp_iohubs, i,
			    CECHUB_FRU_HDIF_SIG) {
		const struct cechub_hub_fru_id *fru_id_data;
		unsigned int type;
		static const char *typestr[] = {
			"Reservation",
			"Card",
			"CPU Card",
			"Backplane",
			"Backplane Extension"
		};
		fru_id_data = HDIF_get_idata(sp_iohubs, CECHUB_FRU_ID_DATA_AREA,
					     &size);
		if (!fru_id_data || size < sizeof(struct cechub_hub_fru_id)) {
			prerror("CEC: IO-HUB FRU %d, bad ID data\n", i);
			continue;
		}
		type = be32_to_cpu(fru_id_data->card_type);

		prlog(PR_INFO, "CEC: HUB FRU %d is %s\n",
		      i, type > 4 ? "Unknown" : typestr[type]);

		/*
		 * We currently only handle the backplane (Juno) and
		 * processor FRU (P8 machines)
		 */
		if (type != CECHUB_FRU_TYPE_CEC_BKPLANE &&
		    type != CECHUB_FRU_TYPE_CPU_CARD) {
			prerror("CEC:   Unsupported type\n");
			continue;
		}

		/* We don't support Hubs connected to pass-through ports */
		if (fru_id_data->flags & (CECHUB_FRU_FLAG_HEADLESS |
					  CECHUB_FRU_FLAG_PASSTHROUGH)) {
			prerror("CEC:   Headless or Passthrough unsupported\n");
			continue;
		}

		/* Ok, we have a reasonable candidate */
		io_parse_fru(sp_iohubs);
	}
}

