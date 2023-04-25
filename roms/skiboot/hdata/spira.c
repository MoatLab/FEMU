// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <inttypes.h>
#include <device.h>
#include <cpu.h>
#include <vpd.h>
#include <interrupts.h>
#include <ccan/str/str.h>
#include <chip.h>
#include <opal-dump.h>
#include <fsp-attn.h>
#include <fsp-leds.h>
#include <skiboot.h>
#include <vas.h>

#include "hdata.h"
#include "hostservices.h"
#include "naca.h"
#include "spira.h"

/* Processor Initialization structure, contains
 * the initial NIA and MSR values for the entry
 * point
 *
 * Note: It appears to be ignoring the entry point
 *       and always going to 0x180
 */

static int cpu_type;

extern struct proc_init_data proc_init_data;

__section(".procin.data") struct proc_init_data proc_init_data = {
	.hdr = HDIF_SIMPLE_HDR("PROCIN", 1, struct proc_init_data),
	.regs_ptr = HDIF_IDATA_PTR(offsetof(struct proc_init_data, regs), 0x10),
	.regs = {
		.nia = CPU_TO_BE64(0x180),
		.msr = CPU_TO_BE64(MSR_SF | MSR_HV),
	},
};

extern struct cpu_ctl_init_data cpu_ctl_init_data;
extern struct sp_addr_table cpu_ctl_spat_area;
extern struct sp_attn_area cpu_ctl_sp_attn_area1;
extern struct sp_attn_area cpu_ctl_sp_attn_area2;
extern struct hsr_data_area cpu_ctl_hsr_area;

/*
 * cpuctrl.data begins at CPU_CTL_OFF	- cpu_ctl_init_data is located there.
 * + sizeof(struct cpu_ctl_init_data)	- cpu_ctl_spat_area
 * + sizeof(struct sp_addr_table)	- cpu_ctl_sp_attn_area1
 * + sizeof(struct sp_attn_area)	- cpu_ctl_sp_attn_area2
 * + sizeof(struct sp_attn_area)	- cpu_ctl_hsr_area
 *
 * Can't use CPU_TO_BE64 directly on the labels as a constant initialiser.
 *
 * CPU_CTL_INIT_DATA_OFF is offset from 0, the others are addressed from the
 * relocated address (+SKIBOOT_BASE)
 */
#define CPU_CTL_INIT_DATA_OFF		(CPU_CTL_OFF)
#define CPU_CTL_SPAT_AREA_OFF		(CPU_CTL_INIT_DATA_OFF + sizeof(struct cpu_ctl_init_data) + SKIBOOT_BASE)
#define CPU_CTL_SP_ATTN_AREA1_OFF	(ALIGN_UP((CPU_CTL_SPAT_AREA_OFF + sizeof(struct sp_addr_table)), ATTN_AREA_SZ))
#define CPU_CTL_SP_ATTN_AREA2_OFF	(CPU_CTL_SP_ATTN_AREA1_OFF + sizeof(struct sp_attn_area))
#define CPU_CTL_HSR_AREA_OFF		(CPU_CTL_SP_ATTN_AREA2_OFF + sizeof(struct sp_attn_area))

__section(".cpuctrl.data") struct hsr_data_area cpu_ctl_hsr_area;
__section(".cpuctrl.data") struct sp_attn_area cpu_ctl_sp_attn_area2;
__section(".cpuctrl.data") struct sp_attn_area cpu_ctl_sp_attn_area1;
__section(".cpuctrl.data") struct sp_addr_table cpu_ctl_spat_area;

__section(".cpuctrl.data") struct cpu_ctl_init_data cpu_ctl_init_data = {
	.hdr = HDIF_SIMPLE_HDR(CPU_CTL_HDIF_SIG, 2, struct cpu_ctl_init_data),
	.cpu_ctl = HDIF_IDATA_PTR(offsetof(struct cpu_ctl_init_data, cpu_ctl_lt),
					sizeof(struct cpu_ctl_legacy_table)),
	.cpu_ctl_lt = {
		.spat = {
			.addr = CPU_TO_BE64(CPU_CTL_SPAT_AREA_OFF),
			.size = CPU_TO_BE64(sizeof(struct sp_addr_table)),
		},
		.sp_attn_area1 = {
			.addr = CPU_TO_BE64(CPU_CTL_SP_ATTN_AREA1_OFF),
			.size = CPU_TO_BE64(sizeof(struct sp_attn_area)),
		},
		.sp_attn_area2 = {
			.addr = CPU_TO_BE64(CPU_CTL_SP_ATTN_AREA2_OFF),
			.size = CPU_TO_BE64(sizeof(struct sp_attn_area)),
		},
		.hsr_area = {
			.addr = CPU_TO_BE64(CPU_CTL_HSR_AREA_OFF),
			.size = CPU_TO_BE64(sizeof(struct hsr_data_area)),
		},
	},
};

/* Populate MDST table
 *
 * Note that we only pass sapphire console buffer here so that we can
 * capture early failure logs. Later dump component (fsp_dump_mdst_init)
 * creates new table with all the memory sections we are interested and
 * sends updated table to FSP via MBOX.
 *
 * To help the FSP distinguishing between TCE tokens and actual physical
 * addresses, we set the top bit to 1 on physical addresses
 */

extern struct mdst_table init_mdst_table[];

__section(".mdst.data") struct mdst_table init_mdst_table[2] = {
	{
		.addr = CPU_TO_BE64(INMEM_CON_START | HRMOR_BIT),
		.data_region = DUMP_REGION_CONSOLE,
		.dump_type = DUMP_TYPE_SYSDUMP,
		.size = CPU_TO_BE32(INMEM_CON_LEN),
	},
	{
		.addr = CPU_TO_BE64(HBRT_CON_START | HRMOR_BIT),
		.data_region = DUMP_REGION_HBRT_LOG,
		.dump_type = DUMP_TYPE_SYSDUMP,
		.size = CPU_TO_BE32(HBRT_CON_LEN),
	},
};

/* SP Interface Root Array, aka SPIRA */
__section(".spira.data") struct spira spira = {
	.hdr = HDIF_SIMPLE_HDR("SPIRA ", SPIRA_VERSION, struct spira),
	.ntuples_ptr = HDIF_IDATA_PTR(offsetof(struct spira, ntuples),
				      sizeof(struct spira_ntuples)),
	.ntuples = {
		.array_hdr = {
			.offset		= CPU_TO_BE32(HDIF_ARRAY_OFFSET),
			.ecnt		= CPU_TO_BE32(SPIRA_NTUPLES_COUNT),
			.esize
				= CPU_TO_BE32(sizeof(struct spira_ntuple)),
			.eactsz		= CPU_TO_BE32(0x18),
		},
		/* We only populate some n-tuples */
		.proc_init = {
			.addr  		= CPU_TO_BE64(PROCIN_OFF),
			.alloc_cnt	= CPU_TO_BE16(1),
			.act_cnt	= CPU_TO_BE16(1),
			.alloc_len
			= CPU_TO_BE32(sizeof(struct proc_init_data)),
		},
		.heap = {
			.addr		= CPU_TO_BE64(SPIRA_HEAP_BASE),
			.alloc_cnt	= CPU_TO_BE16(1),
			.alloc_len	= CPU_TO_BE32(SPIRA_HEAP_SIZE),
		},
		.mdump_src = {
			.addr		= CPU_TO_BE64(MDST_TABLE_OFF),
			.alloc_cnt	= CPU_TO_BE16(ARRAY_SIZE(init_mdst_table)),
			.act_cnt	= CPU_TO_BE16(ARRAY_SIZE(init_mdst_table)),
			.alloc_len	=
				CPU_TO_BE32(sizeof(init_mdst_table)),
		},
		.cpu_ctrl = {
			.addr		= CPU_TO_BE64(CPU_CTL_INIT_DATA_OFF),
			.alloc_cnt	= CPU_TO_BE16(1),
			.act_cnt	= CPU_TO_BE16(1),
			.alloc_len	= CPU_TO_BE32(sizeof(cpu_ctl_init_data)),
		},
	},
};

/* The Hypervisor SPIRA-H Structure */
__section(".spirah.data") struct spirah spirah = {
	.hdr = HDIF_SIMPLE_HDR(SPIRAH_HDIF_SIG, SPIRAH_VERSION, struct spirah),
	.ntuples_ptr = HDIF_IDATA_PTR(offsetof(struct spirah, ntuples),
				      sizeof(struct spirah_ntuples)),
	.ntuples = {
		.array_hdr = {
			.offset		= CPU_TO_BE32(HDIF_ARRAY_OFFSET),
			.ecnt		= CPU_TO_BE32(SPIRAH_NTUPLES_COUNT),
			.esize
				= CPU_TO_BE32(sizeof(struct spira_ntuple)),
			.eactsz		= CPU_TO_BE32(0x18),
		},
		/* Host Data Areas */
		.hs_data_area = {
			.addr		= CPU_TO_BE64(SPIRA_HEAP_BASE),
			.alloc_cnt	= CPU_TO_BE16(1),
			.alloc_len	= CPU_TO_BE32(SPIRA_HEAP_SIZE),
		},
		/* We only populate some n-tuples */
		.proc_init = {
			.addr		= CPU_TO_BE64(PROCIN_OFF),
			.alloc_cnt	= CPU_TO_BE16(1),
			.act_cnt	= CPU_TO_BE16(1),
			.alloc_len
			= CPU_TO_BE32(sizeof(struct proc_init_data)),
		},
		.cpu_ctrl = {
			.addr		= CPU_TO_BE64(CPU_CTL_INIT_DATA_OFF),
			.alloc_cnt	= CPU_TO_BE16(1),
			.act_cnt	= CPU_TO_BE16(1),
			.alloc_len	=
					CPU_TO_BE32(sizeof(cpu_ctl_init_data)),
		},
		.mdump_src = {
			.addr		= CPU_TO_BE64(MDST_TABLE_OFF),
			.alloc_cnt	= CPU_TO_BE16(MDST_TABLE_SIZE / sizeof(struct mdst_table)),
			.act_cnt	= CPU_TO_BE16(ARRAY_SIZE(init_mdst_table)),
			.alloc_len	= CPU_TO_BE32(sizeof(struct mdst_table)),
			.act_len	= CPU_TO_BE32(sizeof(struct mdst_table)),
		},
		.mdump_dst = {
			.addr		= CPU_TO_BE64(MDDT_TABLE_OFF),
			.alloc_cnt	= CPU_TO_BE16(MDDT_TABLE_SIZE / sizeof(struct mddt_table)),
			.act_cnt	= CPU_TO_BE16(0),
			.alloc_len	= CPU_TO_BE32(sizeof(struct mddt_table)),
			.act_len	= CPU_TO_BE32(sizeof(struct mddt_table)),
		},
		.mdump_res = {
			.addr		= CPU_TO_BE64(MDRT_TABLE_BASE),
			.alloc_cnt	= CPU_TO_BE16(MDRT_TABLE_SIZE / sizeof(struct mdrt_table)),
			/*
			 * XXX: Ideally hostboot should use allocated count and
			 *      length. But looks like hostboot uses actual count
			 *      and length to get MDRT table size. And post dump
			 *      hostboot will update act_cnt. Hence update both
			 *      alloc_cnt and act_cnt.
			 */
			.act_cnt        = CPU_TO_BE16(MDRT_TABLE_SIZE / sizeof(struct mdrt_table)),
			.alloc_len      = CPU_TO_BE32(sizeof(struct mdrt_table)),
			.act_len        = CPU_TO_BE32(sizeof(struct mdrt_table)),
		},
		.proc_dump_area = {
			.addr		= CPU_TO_BE64(PROC_DUMP_AREA_OFF),
			.alloc_cnt	= CPU_TO_BE16(1),
			.act_cnt	= CPU_TO_BE16(1),
			.alloc_len	= CPU_TO_BE32(sizeof(struct proc_dump_area)),
			.act_len	= CPU_TO_BE32(sizeof(struct proc_dump_area)),
		},
	},
};

/* The service processor SPIRA-S structure */
struct spiras *spiras;

/* Overridden for testing. */
#ifndef spira_check_ptr
bool spira_check_ptr(const void *ptr, const char *file, unsigned int line)
{
	if (!ptr)
		return false;
	if (((unsigned long)ptr) >= SPIRA_HEAP_BASE &&
	    ((unsigned long)ptr) < (SPIRA_HEAP_BASE + SPIRA_HEAP_SIZE))
		return true;

	prerror("SPIRA: Bad pointer %p at %s line %d\n", ptr, file, line);
	return false;
}
#endif

struct HDIF_common_hdr *__get_hdif(struct spira_ntuple *n, const char id[],
				   const char *file, int line)
{
	struct HDIF_common_hdr *h = ntuple_addr(n);
	u16 act_cnt, alloc_cnt;
	u32 act_len, alloc_len;

	if (!spira_check_ptr(h, file, line))
		return NULL;

	act_cnt = be16_to_cpu(n->act_cnt);
	alloc_cnt = be16_to_cpu(n->alloc_cnt);

	if (act_cnt > alloc_cnt) {
		prerror("SPIRA: bad ntuple, act_cnt > alloc_cnt (%u > %u)\n",
			act_cnt, alloc_cnt);
		return NULL;
	}

	act_len = be32_to_cpu(n->act_len);
	alloc_len = be32_to_cpu(n->alloc_len);

	if (act_len > alloc_len) {
		prerror("SPIRA: bad ntuple, act_len > alloc_len (%u > %u)\n",
			act_len, alloc_len);
		return NULL;
	}

	if (!HDIF_check(h, id)) {
		prerror("SPIRA: bad tuple %p: expected %s at %s line %d\n",
			h, id, file, line);
		return NULL;
	}
	return h;
}

uint32_t get_xscom_id(const struct sppcrd_chip_info *cinfo)
{
	if (proc_gen <= proc_gen_p9)
		return be32_to_cpu(cinfo->xscom_id);

	/* On P10 use Processor fabric topology id for chip id */
	return (uint32_t)(cinfo->fab_topology_id);
}

static struct dt_node *add_xscom_node(uint64_t base,
				      const struct sppcrd_chip_info *cinfo)
{
	struct dt_node *node;
	uint64_t addr, size;
	uint64_t freq;
	uint32_t hw_id = get_xscom_id(cinfo);
	uint32_t proc_chip_id = be32_to_cpu(cinfo->proc_chip_id);

	switch (proc_gen) {
	case proc_gen_p8:
		/* On P8 all the chip SCOMs share single region */
		addr = base | ((uint64_t)hw_id << PPC_BITLSHIFT(28));
		break;
	case proc_gen_p9:
		/* On P9 we need to put the chip ID in the natural powerbus
		 * position.
		 */
		addr = base | (((uint64_t)hw_id) << 42);
		break;
	case proc_gen_p10:
	default:
		/* Use Primary topology table index for xscom address */
		addr = base | (((uint64_t)cinfo->topology_id_table[cinfo->primary_topology_loc]) << 44);
		break;
	};

	size = (u64)1 << PPC_BITLSHIFT(28);

	prlog(PR_INFO, "XSCOM: Found HW ID 0x%x (PCID 0x%x) @ 0x%llx\n",
	       hw_id, proc_chip_id, (long long)addr);

	node = dt_new_addr(dt_root, "xscom", addr);
	assert(node);

	dt_add_property_cells(node, "ibm,chip-id", hw_id);
	dt_add_property_cells(node, "ibm,proc-chip-id", proc_chip_id);
	dt_add_property_cells(node, "#address-cells", 1);
	dt_add_property_cells(node, "#size-cells", 1);
	dt_add_property(node, "scom-controller", NULL, 0);

	switch(proc_gen) {
	case proc_gen_p8:
		dt_add_property_strings(node, "compatible",
					"ibm,xscom", "ibm,power8-xscom");
		break;
	case proc_gen_p9:
		dt_add_property_strings(node, "compatible",
					"ibm,xscom", "ibm,power9-xscom");
		break;
	case proc_gen_p10:
		dt_add_property_strings(node, "compatible",
					"ibm,xscom", "ibm,power10-xscom");
		break;
	default:
		dt_add_property_strings(node, "compatible", "ibm,xscom");
	}
	dt_add_property_u64s(node, "reg", addr, size);

	/*
	 * The bus-frequency of the xscom node is actually the PIB/PCB
	 * frequency. It is derived from the nest-clock via a 4:1 divider
	 */
	freq = dt_prop_get_u64_def(dt_root, "nest-frequency", 0);
	freq /= 4;
	if (freq)
		dt_add_property_u64(node, "bus-frequency", freq);

	return node;
}

/*
 * Given a xscom@ node this will return a pointer into the SPPCRD
 * structure corresponding to that node
 */
#define GET_HDIF_HDR -1
static const void *xscom_to_pcrd(struct dt_node *xscom, int idata_index)
{
	struct spira_ntuple *t = &spira.ntuples.proc_chip;
	const struct HDIF_common_hdr *hdif;
	const void *idata;
	unsigned int size;
	uint32_t i;
	void *base;

	i = dt_prop_get_u32_def(xscom, DT_PRIVATE "sppcrd-index", 0xffffffff);
	if (i == 0xffffffff)
		return NULL;

	base = get_hdif(t, "SPPCRD");
	assert(base);
	assert(i < be16_to_cpu(t->act_cnt));

	hdif = base + i * be32_to_cpu(t->alloc_len);
	assert(hdif);

	if (idata_index == GET_HDIF_HDR)
		return hdif;

	idata = HDIF_get_idata(hdif, idata_index, &size);
	if (!idata || !size)
		return NULL;

	return idata;
}

struct dt_node *find_xscom_for_chip(uint32_t chip_id)
{
	struct dt_node *node;
	uint32_t id;

	dt_for_each_compatible(dt_root, node, "ibm,xscom") {
		id = dt_get_chip_id(node);
		if (id == chip_id)
			return node;
	}

	return NULL;
}

static void add_psihb_node(struct dt_node *np)
{
	u32 psi_scom, psi_slen;
	const char *psi_comp;

	/*
	 * We add a few things under XSCOM that aren't added
	 * by any other HDAT path
	 */

	/* PSI host bridge */
	switch(proc_gen) {
	case proc_gen_p8:
		psi_scom = 0x2010900;
		psi_slen = 0x20;
		psi_comp = "ibm,power8-psihb-x";
		break;
	case proc_gen_p9:
		psi_scom = 0x5012900;
		psi_slen = 0x100;
		psi_comp = "ibm,power9-psihb-x";
		break;
	case proc_gen_p10:
		psi_scom = 0x3011d00;
		psi_slen = 0x100;
		psi_comp = "ibm,power10-psihb-x";
		break;
	default:
		psi_comp = NULL;
	}
	if (psi_comp) {
		struct dt_node *psi_np;

		psi_np = dt_new_addr(np, "psihb", psi_scom);
		if (!psi_np)
			return;

		dt_add_property_cells(psi_np, "reg", psi_scom, psi_slen);
		dt_add_property_strings(psi_np, "compatible", psi_comp,
					"ibm,psihb-x");
	}
}

static void add_xive_node(struct dt_node *np)
{
	struct dt_node *xive;
	const char *comp;
	u32 scom, slen;

	switch (proc_gen) {
	case proc_gen_p9:
		scom = 0x5013000;
		slen = 0x300;
		comp = "ibm,power9-xive-x";
		break;
	case proc_gen_p10:
		scom = 0x2010800;
		slen = 0x400;
		comp = "ibm,power10-xive-x";
		break;
	default:
		return;
	}

	xive = dt_new_addr(np, "xive", scom);
	dt_add_property_cells(xive, "reg", scom, slen);
	dt_add_property_string(xive, "compatible", comp);

	/* HACK: required for simics */
	dt_add_property(xive, "force-assign-bars", NULL, 0);
}

static void add_vas_node(struct dt_node *np, int idx)
{
	struct  dt_node *vas;
	const char *comp;
	uint64_t base_addr;

	if (proc_gen == proc_gen_p9) {
		base_addr = P9_VAS_SCOM_BASE_ADDR;
		comp = "ibm,power9-vas-x";
	} else {
		base_addr = VAS_SCOM_BASE_ADDR;
		comp = "ibm,power10-vas-x";
	}

	vas = dt_new_addr(np, "vas", base_addr);
	dt_add_property_cells(vas, "reg", base_addr, 0x300);
	dt_add_property_string(vas, "compatible", comp);
	dt_add_property_cells(vas, "ibm,vas-id", idx);
}

static void add_ecid_data(const struct HDIF_common_hdr *hdr,
			  struct dt_node *xscom)
{
	char wafer_id[11];
	uint8_t tmp;
	int i;
	uint32_t size = 0;
	struct sppcrd_ecid *ecid;
	const struct HDIF_array_hdr *ec_hdr;

	ec_hdr = HDIF_get_idata(hdr, SPPCRD_IDATA_EC_LEVEL, &size);
	if (!ec_hdr || !size)
		return;

	ecid = (void *)ec_hdr + be32_to_cpu(ec_hdr->offset);
	dt_add_property_u64s(xscom, "ecid", be64_to_cpu(ecid->low),
			     be64_to_cpu(ecid->high));

	/*
	 * bits 4:63 of ECID data contains wafter ID data (ten 6 bit fields
	 * each containing a code).
	 */
	for (i = 0; i < 10; i++) {
		tmp = (u8)((be64_to_cpu(ecid->low) >> (i * 6)) & 0x3f);
		if (tmp <= 9)
			wafer_id[9 - i] = tmp + '0';
		else if (tmp >= 0xA && tmp <= 0x23)
			wafer_id[9 - i] = tmp + '0' + 7;
		else if (tmp == 0x3D)
			wafer_id[9 - i] = '-';
		else if (tmp == 0x3E)
			wafer_id[9 - i] = '.';
		else if (tmp == 0x3F)
			wafer_id[9 - i] = ' ';
		else /* Unknown code */
			wafer_id[9 - i] = tmp + '0';
	}
	wafer_id[10] = '\0';
	dt_add_property_nstr(xscom, "wafer-id", wafer_id, 10);

	dt_add_property_cells(xscom, "wafer-location",
			      (u32)((be64_to_cpu(ecid->high) >> 56) & 0xff),
			      (u32)((be64_to_cpu(ecid->high) >> 48) & 0xff));
}

static void add_xscom_add_pcia_assoc(struct dt_node *np, uint32_t pcid)
{
	const struct HDIF_common_hdr *hdr;
	u32 size;


	/*
	 * The SPPCRD doesn't contain all the affinity data, we have
	 * to dig it out of a core. I assume this is so that node
	 * affinity can be different for groups of cores within the
	 * chip, but for now we are going to ignore that
	 */
	hdr = get_hdif(&spira.ntuples.pcia, SPPCIA_HDIF_SIG);
	if (!hdr)
		return;

	for_each_pcia(hdr) {
		const struct sppcia_core_unique *id;

		id = HDIF_get_idata(hdr, SPPCIA_IDATA_CORE_UNIQUE, &size);
		if (!id || size < sizeof(*id))
			continue;

		if (be32_to_cpu(id->proc_chip_id) != pcid)
			continue;

		dt_add_property_cells(np, "ibm,ccm-node-id",
				      be32_to_cpu(id->ccm_node_id));
		dt_add_property_cells(np, "ibm,hw-card-id",
				      be32_to_cpu(id->hw_card_id));
		dt_add_property_cells(np, "ibm,hw-module-id",
				      be32_to_cpu(id->hw_module_id));
		if (!dt_find_property(np, "ibm,dbob-id"))
			dt_add_property_cells(np, "ibm,dbob-id",
				  be32_to_cpu(id->drawer_book_octant_blade_id));
		if (proc_gen < proc_gen_p9) {
			dt_add_property_cells(np, "ibm,mem-interleave-scope",
			          be32_to_cpu(id->memory_interleaving_scope));
		}
		return;
	}
}

static bool add_xscom_sppcrd(uint64_t xscom_base)
{
	const struct HDIF_common_hdr *hdif;
	unsigned int i, vpd_sz;
	const void *vpd;
	struct dt_node *np, *vpd_node;

	for_each_ntuple_idx(&spira.ntuples.proc_chip, hdif, i,
			    SPPCRD_HDIF_SIG) {
		const struct sppcrd_chip_info *cinfo;
		const struct spira_fru_id *fru_id = NULL;
		unsigned int csize;
		u32 ve, version;

		cinfo = HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_INFO, &csize);
		if (!CHECK_SPPTR(cinfo)) {
			prerror("XSCOM: Bad ChipID data %d\n", i);
			continue;
		}

		ve = be32_to_cpu(cinfo->verif_exist_flags) & CHIP_VERIFY_MASK;
		ve >>= CHIP_VERIFY_SHIFT;
		if (ve == CHIP_VERIFY_NOT_INSTALLED ||
		    ve == CHIP_VERIFY_UNUSABLE)
			continue;

		/* Create the XSCOM node */
		np = add_xscom_node(xscom_base, cinfo);
		if (!np)
			continue;


		dt_add_property_cells(np, DT_PRIVATE "sppcrd-index", i);

		version = be16_to_cpu(hdif->version);

		/* Version 0A has additional OCC related stuff */
		if (version >= 0x000a) {
			if (!dt_find_property(np, "ibm,dbob-id"))
				dt_add_property_cells(np, "ibm,dbob-id",
					be32_to_cpu(cinfo->dbob_id));
			dt_add_property_cells(np, "ibm,occ-functional-state",
					      be32_to_cpu(cinfo->occ_state));
		}

		/* Add chip VPD */
		vpd_node = dt_add_vpd_node(hdif, SPPCRD_IDATA_FRU_ID,
					   SPPCRD_IDATA_KW_VPD);
		if (vpd_node)
			dt_add_property_cells(vpd_node, "ibm,chip-id",
					      get_xscom_id(cinfo));

		fru_id = HDIF_get_idata(hdif, SPPCRD_IDATA_FRU_ID, NULL);
		if (fru_id)
			slca_vpd_add_loc_code(np, be16_to_cpu(fru_id->slca_index));

		/* Add module VPD on version A and later */
		if (version >= 0x000a) {
			vpd = HDIF_get_idata(hdif, SPPCRD_IDATA_MODULE_VPD,
					     &vpd_sz);
			if (CHECK_SPPTR(vpd)) {
				dt_add_property(np, "ibm,module-vpd", vpd,
						vpd_sz);
				vpd_data_parse(np, vpd, vpd_sz);
				if (vpd_node)
					dt_add_proc_vendor(vpd_node, vpd, vpd_sz);
			}
		}

		/*
		 * Extract additional associativity information from
		 * the core data. Pick one core on that chip
		 */
		add_xscom_add_pcia_assoc(np, be32_to_cpu(cinfo->proc_chip_id));

		/* Add PSI Host bridge */
		add_psihb_node(np);

		if (proc_gen >= proc_gen_p9) {
			add_xive_node(np);
			parse_i2c_devs(hdif, SPPCRD_IDATA_HOST_I2C, np);
			add_vas_node(np, i);
			add_ecid_data(hdif, np);

			if (be32_to_cpu(cinfo->verif_exist_flags) & CHIP_VERIFY_MASTER_PROC)
				dt_add_property(np, "primary", NULL, 0);
		}

		/*
		 * Add sw checkstop scom address (ibm,sw-checkstop-fir)
		 *
		 * The latest HDAT versions have sw checkstop scom address
		 * info.  But not sure from which version onwards (at least
		 * HDAT spec do not mention that explicitly). Hence use the
		 * sppcrd struct size returned by HDIF_get_idata to figure out
		 * whether it contains sw checkstop scom address info. Also
		 * check if sw_xstop_fir_scom address is non-zero.
		 */
		if ((csize >= (offsetof(struct sppcrd_chip_info,
					sw_xstop_fir_bitpos) + 1)) &&
						cinfo->sw_xstop_fir_scom) {
			uint8_t fir_bit = cinfo->sw_xstop_fir_bitpos;

			if (!dt_find_property(dt_root, "ibm,sw-checkstop-fir"))
				dt_add_property_cells(dt_root,
					"ibm,sw-checkstop-fir",
					be32_to_cpu(cinfo->sw_xstop_fir_scom),
					fir_bit);
		}

		if (proc_gen >= proc_gen_p10) {
			uint8_t primary_loc = cinfo->primary_topology_loc;

			if (primary_loc >= CHIP_MAX_TOPOLOGY_ENTRIES) {
				prerror("XSCOM: Invalid primary topology index %d\n",
					primary_loc);
				continue;
			}
			dt_add_property_cells(np, "ibm,primary-topology-index",
					cinfo->topology_id_table[primary_loc]);
		}
	}

	return i > 0;
}

static void add_xscom(void)
{
	const void *ms_vpd;
	const struct msvpd_pmover_bsr_synchro *pmbs;
	unsigned int size;
	uint64_t xscom_base;

	ms_vpd = get_hdif(&spira.ntuples.ms_vpd, MSVPD_HDIF_SIG);
	if (!ms_vpd) {
		prerror("XSCOM: Can't find MS VPD\n");
		return;
	}

	pmbs = HDIF_get_idata(ms_vpd, MSVPD_IDATA_PMOVER_SYNCHRO, &size);
	if (!CHECK_SPPTR(pmbs) || size < sizeof(*pmbs)) {
		prerror("XSCOM: absent or bad PMBS size %u @ %p\n", size, pmbs);
		return;
	}

	if (!(be32_to_cpu(pmbs->flags) & MSVPD_PMS_FLAG_XSCOMBASE_VALID)) {
		prerror("XSCOM: No XSCOM base in PMBS, using default\n");
		return;
	}

	xscom_base = be64_to_cpu(pmbs->xscom_addr);

	/* Get rid of the top bits */
	xscom_base = cleanup_addr(xscom_base);

	/* First, try the new proc_chip ntuples for chip data */
	if (add_xscom_sppcrd(xscom_base))
		return;
}

static void add_chiptod_node(unsigned int chip_id, int flags)
{
	struct dt_node *node, *xscom_node;
	const char *compat_str;
	uint32_t addr, len;

	if ((flags & CHIPTOD_ID_FLAGS_STATUS_MASK) !=
			CHIPTOD_ID_FLAGS_STATUS_OK)
		return;

	xscom_node = find_xscom_for_chip(chip_id);
	if (!xscom_node) {
		prerror("CHIPTOD: No xscom for chiptod %d?\n", chip_id);
		return;
	}

	addr = 0x40000;
	len = 0x34;

	switch(proc_gen) {
	case proc_gen_p8:
		compat_str = "ibm,power8-chiptod";
		break;
	case proc_gen_p9:
		compat_str = "ibm,power9-chiptod";
		break;
	case proc_gen_p10:
		compat_str = "ibm,power10-chiptod";
		break;
	default:
		return;
	}

	prlog(PR_DEBUG, "CHIPTOD: Found on chip 0x%x %s\n", chip_id,
	      (flags & CHIPTOD_ID_FLAGS_PRIMARY) ? "[primary]" :
	      ((flags & CHIPTOD_ID_FLAGS_SECONDARY) ? "[secondary]" : ""));

	node = dt_new_addr(xscom_node, "chiptod", addr);
	if (!node)
		return;

	dt_add_property_cells(node, "reg", addr, len);
	dt_add_property_strings(node, "compatible", "ibm,power-chiptod",
			       compat_str);

	if (flags & CHIPTOD_ID_FLAGS_PRIMARY)
		dt_add_property(node, "primary", NULL, 0);
	if (flags & CHIPTOD_ID_FLAGS_SECONDARY)
		dt_add_property(node, "secondary", NULL, 0);
}

static bool add_chiptod_old(void)
{
	const void *hdif;
	unsigned int i;
	bool found = false;

	/*
	 * Locate chiptod ID structures in SPIRA
	 */
	if (!get_hdif(&spira.ntuples.chip_tod, "TOD   "))
		return found;

	for_each_ntuple_idx(&spira.ntuples.chip_tod, hdif, i, "TOD   ") {
		const struct chiptod_chipid *id;

		id = HDIF_get_idata(hdif, CHIPTOD_IDATA_CHIPID, NULL);
		if (!CHECK_SPPTR(id)) {
			prerror("CHIPTOD: Bad ChipID data %d\n", i);
			continue;
		}

		add_chiptod_node(pcid_to_chip_id(be32_to_cpu(id->chip_id)),
				 be32_to_cpu(id->flags));
		found = true;
	}
	return found;
}

static bool add_chiptod_new(void)
{
	const void *hdif;
	unsigned int i;
	bool found = false;

	/*
	 * Locate Proc Chip ID structures in SPIRA
	 */
	if (!get_hdif(&spira.ntuples.proc_chip, SPPCRD_HDIF_SIG))
		return found;

	for_each_ntuple_idx(&spira.ntuples.proc_chip, hdif, i,
			    SPPCRD_HDIF_SIG) {
		const struct sppcrd_chip_info *cinfo;
		const struct sppcrd_chip_tod *tinfo;
		unsigned int size;
		u32 ve, flags;

		cinfo = HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_INFO, NULL);
		if (!CHECK_SPPTR(cinfo)) {
			prerror("CHIPTOD: Bad ChipID data %d\n", i);
			continue;
		}

		ve = be32_to_cpu(cinfo->verif_exist_flags) & CHIP_VERIFY_MASK;
		ve >>= CHIP_VERIFY_SHIFT;
		if (ve == CHIP_VERIFY_NOT_INSTALLED ||
		    ve == CHIP_VERIFY_UNUSABLE)
			continue;

		tinfo = HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_TOD, &size);
		if (!CHECK_SPPTR(tinfo)) {
			prerror("CHIPTOD: Bad TOD data %d\n", i);
			continue;
		}

		flags = be32_to_cpu(tinfo->flags);

		/* The FSP may strip the chiptod info from HDAT; if we find
		 * a zero-ed out entry, assume that the chiptod is
		 * present, but we don't have any primary/secondary info. In
		 * this case, pick chip zero as the master.
		 */
		if (!size) {
			flags = CHIPTOD_ID_FLAGS_STATUS_OK;
			if (be32_to_cpu(cinfo->xscom_id) == 0x0)
				flags |= CHIPTOD_ID_FLAGS_PRIMARY;
		}

		add_chiptod_node(get_xscom_id(cinfo), flags);
		found = true;
	}
	return found;
}

static void add_nx_node(u32 gcid)
{
	struct dt_node *nx;
	u32 addr;
	u32 size;
	struct dt_node *xscom;

	xscom = find_xscom_for_chip(gcid);
	if (xscom == NULL) {
		prerror("NX%d: did not found xscom node.\n", gcid);
		return;
	}

	/*
	 * The NX register space is relatively self contained on P7+ but
	 * a bit more messy on P8. However it's all contained within the
	 * PB chiplet port 1 so we'll stick to that in the "reg" property
	 * and let the NX "driver" deal with the details.
	 */
	addr = 0x2010000;
	size = 0x0004000;

	nx = dt_new_addr(xscom, "nx", addr);
	if (!nx)
		return;

	switch (proc_gen) {
	case proc_gen_p8:
		dt_add_property_strings(nx, "compatible", "ibm,power-nx",
					"ibm,power8-nx");
		break;
	case proc_gen_p9:
	case proc_gen_p10:
		/* POWER9 NX is not software compatible with P8 NX */
		dt_add_property_strings(nx, "compatible", "ibm,power9-nx");
		break;
	default:
		return;
	}

	dt_add_property_cells(nx, "reg", addr, size);
}

static void add_nx(void)
{
	unsigned int i;
	void *hdif;

	for_each_ntuple_idx(&spira.ntuples.proc_chip, hdif, i,
			SPPCRD_HDIF_SIG) {
		const struct sppcrd_chip_info *cinfo;
		u32 ve;

		cinfo = HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_INFO, NULL);
		if (!CHECK_SPPTR(cinfo)) {
			prerror("NX: Bad ChipID data %d\n", i);
			continue;
		}

		ve = be32_to_cpu(cinfo->verif_exist_flags) & CHIP_VERIFY_MASK;
		ve >>= CHIP_VERIFY_SHIFT;
		if (ve == CHIP_VERIFY_NOT_INSTALLED ||
				ve == CHIP_VERIFY_UNUSABLE)
			continue;

		if (cinfo->nx_state)
			add_nx_node(get_xscom_id(cinfo));
	}
}

static void add_nmmu(void)
{
	struct dt_node *xscom, *nmmu;
	u32 scom1, scom2;
	u32 chip_id;

	/* Nest MMU only exists on POWER9 or later */
	if (proc_gen < proc_gen_p9)
		return;

	if (proc_gen == proc_gen_p10) {
		scom1 = 0x2010c40;
		scom2 = 0x3010c40;
	} else
		scom1 = 0x5012c40;

	dt_for_each_compatible(dt_root, xscom, "ibm,xscom") {
		nmmu = dt_new_addr(xscom, "nmmu", scom1);
		dt_add_property_strings(nmmu, "compatible", "ibm,power9-nest-mmu");
		dt_add_property_cells(nmmu, "reg", scom1, 0x20);

		/*
		 * P10 has a second nMMU, a.k.a "south" nMMU.
		 * It exists only on P1 and P3
		 */
		if (proc_gen == proc_gen_p10) {

			chip_id = __dt_get_chip_id(xscom);
			if (chip_id != 2 && chip_id != 6)
				continue;

			nmmu = dt_new_addr(xscom, "nmmu", scom2);
			dt_add_property_strings(nmmu, "compatible", "ibm,power9-nest-mmu");
			dt_add_property_cells(nmmu, "reg", scom2, 0x20);
		}
	}
}

static void dt_init_secureboot_node(const struct iplparams_sysparams *sysparams)
{
	struct dt_node *node;
	u16 sys_sec_setting;
	u16 hw_key_hash_size;
	u16 host_fw_key_clear;

	node = dt_new(dt_root, "ibm,secureboot");
	assert(node);

	dt_add_property_strings(node, "compatible",
				"ibm,secureboot", "ibm,secureboot-v2");

	sys_sec_setting = be16_to_cpu(sysparams->sys_sec_setting);
	if (sys_sec_setting & SEC_CONTAINER_SIG_CHECKING)
		dt_add_property(node, "secure-enabled", NULL, 0);
	if (sys_sec_setting & SEC_HASHES_EXTENDED_TO_TPM)
		dt_add_property(node, "trusted-enabled", NULL, 0);
	if (sys_sec_setting & PHYSICAL_PRESENCE_ASSERTED)
		dt_add_property(node, "physical-presence-asserted", NULL, 0);

	host_fw_key_clear = be16_to_cpu(sysparams->host_fw_key_clear);
	if (host_fw_key_clear & KEY_CLEAR_OS_KEYS)
		dt_add_property(node, "clear-os-keys", NULL, 0);
	if (host_fw_key_clear & KEY_CLEAR_MFG)
		dt_add_property(node, "clear-mfg-keys", NULL, 0);
	if (host_fw_key_clear & KEY_CLEAR_ALL)
		dt_add_property(node, "clear-all-keys", NULL, 0);

	hw_key_hash_size = be16_to_cpu(sysparams->hw_key_hash_size);

	/* Prevent hw-key-hash buffer overflow by truncating hw-key-hash-size if
	 * it is bigger than the hw-key-hash buffer.
	 * Secure boot will be enforced later in skiboot, if the hw-key-hash-size
	 * was not supposed to be SYSPARAMS_HW_KEY_HASH_MAX.
	 */
	if (hw_key_hash_size > SYSPARAMS_HW_KEY_HASH_MAX) {
		prlog(PR_ERR, "IPLPARAMS: hw-key-hash-size=%d too big, "
		      "truncating to %d\n", hw_key_hash_size,
		      SYSPARAMS_HW_KEY_HASH_MAX);
		hw_key_hash_size = SYSPARAMS_HW_KEY_HASH_MAX;
	}

	dt_add_property(node, "hw-key-hash", sysparams->hw_key_hash,
			hw_key_hash_size);
	dt_add_property_cells(node, "hw-key-hash-size", hw_key_hash_size);
}

static void opal_dump_add_mpipl_boot(const struct iplparams_iplparams *p)
{
	u32 mdrt_cnt = be16_to_cpu(spira.ntuples.mdump_res.act_cnt);
	u32 mdrt_max_cnt = MDRT_TABLE_SIZE / sizeof(struct mdrt_table);
	struct dt_node *dump_node;

	dump_node = dt_find_by_path(opal_node, "dump");
	if (!dump_node)
		return;

	/* Check boot params to detect MPIPL boot or not */
	if (p->cec_ipl_maj_type != IPLPARAMS_MAJ_TYPE_REIPL)
		return;

	/*
	 * On FSP system we get minor type as post dump IPL and on BMC system
	 * we get platform reboot. Hence lets check for both values.
	 */
	if (p->cec_ipl_min_type != IPLPARAMS_MIN_TYPE_POST_DUMP &&
	    p->cec_ipl_min_type != IPLPARAMS_MIN_TYPE_PLAT_REBOOT) {
		prlog(PR_NOTICE, "DUMP: Non MPIPL reboot "
		      "[minor type = 0x%x]\n", p->cec_ipl_min_type);
		return;
	}

	if (be16_to_cpu(p->cec_ipl_attrib) != IPLPARAMS_ATTRIB_MEM_PRESERVE) {
		prlog(PR_DEBUG, "DUMP: Memory not preserved\n");
		return;
	}

	if (mdrt_cnt == 0 || mdrt_cnt >= mdrt_max_cnt) {
		prlog(PR_DEBUG, "DUMP: Invalid MDRT count : %x\n", mdrt_cnt);
		return;
	}

	prlog(PR_NOTICE, "DUMP: Dump found, MDRT count = 0x%x\n", mdrt_cnt);

	dt_add_property(dump_node, "mpipl-boot", NULL, 0);
}

static void add_opal_dump_node(void)
{
	__be64 fw_load_area[4];
	struct dt_node *node;

	opal_node = dt_new_check(dt_root, "ibm,opal");
	node = dt_new(opal_node, "dump");
	assert(node);
	dt_add_property_string(node, "compatible", "ibm,opal-dump");

	fw_load_area[0] = cpu_to_be64((u64)KERNEL_LOAD_BASE);
	fw_load_area[1] = cpu_to_be64(KERNEL_LOAD_SIZE);
	fw_load_area[2] = cpu_to_be64((u64)INITRAMFS_LOAD_BASE);
	fw_load_area[3] = cpu_to_be64(INITRAMFS_LOAD_SIZE);
	dt_add_property(node, "fw-load-area", fw_load_area, sizeof(fw_load_area));
}

static void add_iplparams_sys_params(const void *iplp, struct dt_node *node)
{
	const struct iplparams_sysparams *p;
	const struct HDIF_common_hdr *hdif = iplp;
	u16 version = be16_to_cpu(hdif->version);
	const char *vendor = NULL;
	u32 sys_attributes;
	u64 bus_speed;

	p = HDIF_get_idata(iplp, IPLPARAMS_SYSPARAMS, NULL);
	if (!CHECK_SPPTR(p)) {
		prerror("IPLPARAMS: No SYS Parameters\n");
		/* Create a generic compatible property */
		dt_add_property_string(dt_root, "compatible", "ibm,powernv");
		return;
	}

	node = dt_new(node, "sys-params");
	assert(node);
	dt_add_property_cells(node, "#address-cells", 0);
	dt_add_property_cells(node, "#size-cells", 0);

	dt_add_property_nstr(node, "ibm,sys-model", p->sys_model, 4);

	/*
	 * Compatible has up to three entries:
	 *	"ibm,powernv", the system family and system type.
	 *
	 * On P9 and above the family and type strings come from the HDAT
	 * directly. On P8 we find it from the system ID numbers.
	 */
	if (proc_gen >= proc_gen_p9) {
		dt_add_property_strings(dt_root, "compatible", "ibm,powernv",
					p->sys_family_str, p->sys_type_str);

		prlog(PR_INFO, "IPLPARAMS: v0x70 Platform family/type: %s/%s\n",
		      p->sys_family_str, p->sys_type_str);
	} else {
		u32 sys_type = be32_to_cpu(p->system_type);
		const char *sys_family;

		switch (sys_type >> 28) {
		case 0:
			sys_family = "ibm,squadrons";
			break;
		case 1:
			sys_family = "ibm,eclipz";
			break;
		case 2:
			sys_family = "ibm,apollo";
			break;
		case 3:
			sys_family = "ibm,firenze";
			break;
		default:
			sys_family = NULL;
			prerror("IPLPARAMS: Unknown system family\n");
			break;
		}

		dt_add_property_strings(dt_root, "compatible", "ibm,powernv",
					sys_family);
		prlog(PR_INFO,
		      "IPLPARAMS: Legacy platform family: %s"
		      " (sys_type=0x%08x)\n", sys_family, sys_type);
	}

	/* Grab nest frequency when available */
	if (version >= 0x005b) {
		u64 freq = be32_to_cpu(p->nest_freq_mhz);

		freq *= 1000000;
		dt_add_property_u64(dt_root, "nest-frequency", freq);
	}

	/* Grab ABC bus speed */
	bus_speed = be32_to_cpu(p->abc_bus_speed);
	if (bus_speed)
		dt_add_property_u64(node, "abc-bus-freq-mhz", bus_speed);

	/* Grab WXYZ bus speed */
	bus_speed = be32_to_cpu(p->wxyz_bus_speed);
	if (bus_speed)
		dt_add_property_u64(node, "wxyz-bus-freq-mhz", bus_speed);

	if (version >= 0x5f)
		vendor = p->sys_vendor;

	/* Workaround a bug where we have NULL vendor */
	if (!vendor || vendor[0] == '\0')
		vendor = "IBM";

	dt_add_property_string(dt_root, "vendor", vendor);

	sys_attributes = be32_to_cpu(p->sys_attributes);
	if (sys_attributes & SYS_ATTR_RISK_LEVEL)
		dt_add_property(node, "elevated-risk-level", NULL, 0);

	/* Populate OPAL dump node */
	if (sys_attributes & SYS_ATTR_MPIPL_SUPPORTED)
		add_opal_dump_node();

	if (version >= 0x60 && proc_gen >= proc_gen_p9)
		dt_init_secureboot_node(p);
}

static void add_iplparams_ipl_params(const void *iplp, struct dt_node *node)
{
	const struct iplparams_iplparams *p;
	struct dt_node *led_node;

	p = HDIF_get_idata(iplp, IPLPARAMS_IPLPARAMS, NULL);
	if (!CHECK_SPPTR(p)) {
		prerror("IPLPARAMS: No IPL Parameters\n");
		return;
	}

	node = dt_new(node, "ipl-params");
	assert(node);
	dt_add_property_cells(node, "#address-cells", 0);
	dt_add_property_cells(node, "#size-cells", 0);

	/* On an ASM initiated factory reset, this bit will be set
	 * and the FSP expects the firmware to reset the PCI bus
	 * numbers and respond with a Power Down (CE,4D,02) message
	 */
	if (be32_to_cpu(p->other_attrib) & IPLPARAMS_OATTR_RST_PCI_BUSNO)
		dt_add_property_cells(node, "pci-busno-reset-ipl", 1);
	dt_add_property_strings(node, "cec-ipl-side",
				(p->ipl_side & IPLPARAMS_CEC_FW_IPL_SIDE_TEMP) ?
				"temp" : "perm");
	if (proc_gen >= proc_gen_p9) {
		dt_add_property_strings(node, "sp-ipl-side",
					(p->ipl_side & IPLPARAMS_FSP_FW_IPL_SIDE_TEMP) ?
					"temp" : "perm");
	} else {
		dt_add_property_strings(node, "fsp-ipl-side",
					(p->ipl_side & IPLPARAMS_FSP_FW_IPL_SIDE_TEMP) ?
					"temp" : "perm");
	}
	dt_add_property_cells(node, "os-ipl-mode", p->os_ipl_mode);
	dt_add_property_strings(node, "cec-major-type",
				p->cec_ipl_maj_type ? "hot" : "cold");

	/* Add LED type info under '/ibm,opal/led' node */
	led_node = dt_find_by_path(opal_node, DT_PROPERTY_LED_NODE);
	assert(led_node);

	if (be32_to_cpu(p->other_attrib) & IPLPARAMS_OATRR_LIGHT_PATH)
		dt_add_property_strings(led_node, DT_PROPERTY_LED_MODE,
					LED_MODE_LIGHT_PATH);
	else
		dt_add_property_strings(led_node, DT_PROPERTY_LED_MODE,
					LED_MODE_GUIDING_LIGHT);

	/* Populate opal dump result table */
	opal_dump_add_mpipl_boot(p);
}

static void add_iplparams_serials(const void *iplp, struct dt_node *node)
{
	const struct iplparms_serial *ipser;
	struct dt_node *ser_node;
	int count, i;

	count = HDIF_get_iarray_size(iplp, IPLPARMS_IDATA_SERIAL);
	if (count <= 0)
		return;
	prlog(PR_INFO, "IPLPARAMS: %d serial ports in array\n", count);

	node = dt_new(node, "fsp-serial");
	assert(node);
	dt_add_property_cells(node, "#address-cells", 1);
	dt_add_property_cells(node, "#size-cells", 0);

	for (i = 0; i < count; i++) {
		u16 rsrc_id;
		ipser = HDIF_get_iarray_item(iplp, IPLPARMS_IDATA_SERIAL,
					     i, NULL);
		if (!CHECK_SPPTR(ipser))
			continue;
		rsrc_id = be16_to_cpu(ipser->rsrc_id);
		prlog(PR_INFO, "IPLPARAMS: Serial %d rsrc: %04x loc: %s\n",
		      i, rsrc_id, ipser->loc_code);
		ser_node = dt_new_addr(node, "serial", rsrc_id);
		if (!ser_node)
			continue;

		dt_add_property_cells(ser_node, "reg", rsrc_id);
		dt_add_property_nstr(ser_node, "ibm,loc-code",
				     ipser->loc_code, LOC_CODE_SIZE);
		dt_add_property_string(ser_node, "compatible",
				       "ibm,fsp-serial");
		/* XXX handle CALLHOME flag ? */
	}
}

/*
 * Check for platform dump, if present populate DT
 */
static void add_iplparams_platform_dump(const void *iplp, struct dt_node *node)
{
	const struct iplparams_dump *ipl_dump;

	ipl_dump = HDIF_get_idata(iplp, IPLPARAMS_PLATFORM_DUMP, NULL);
	if (!CHECK_SPPTR(ipl_dump))
		return;

	node = dt_new(node, "platform-dump");
	assert(node);

	if (be32_to_cpu(ipl_dump->dump_id)) {
		dt_add_property_cells(node, "dump-id",
				      be32_to_cpu(ipl_dump->dump_id));
		dt_add_property_u64(node, "total-size",
				    be64_to_cpu(ipl_dump->act_dump_sz));
		dt_add_property_u64(node, "hw-dump-size",
				    be32_to_cpu(ipl_dump->act_hw_dump_sz));
		dt_add_property_cells(node, "plog-id",
				      be32_to_cpu(ipl_dump->plid));
	}
}

static void add_iplparams_features(const struct HDIF_common_hdr *iplp)
{
	const struct iplparams_feature *feature;
	const struct HDIF_array_hdr *array;
	struct dt_node *fw_features;
	unsigned int count, i;
	char name[65];

	array = HDIF_get_iarray(iplp, IPLPARAMS_FEATURES, &count);
	if (!array || !count)
		return;

	opal_node = dt_new_check(dt_root, "ibm,opal");
	fw_features = dt_new(opal_node, "fw-features");
	if (!fw_features)
		return;

	HDIF_iarray_for_each(array, i, feature) {
		struct dt_node *n;
		uint64_t flags;

		/* the name field isn't necessarily null terminated */
		BUILD_ASSERT(sizeof(name) > sizeof(feature->name));
		strncpy(name, feature->name, sizeof(name)-1);
		name[sizeof(name)-1] = '\0';
		flags = be64_to_cpu(feature->flags);

		if (strlen(name) == 0) {
			prlog(PR_DEBUG, "IPLPARAMS: FW feature name is NULL\n");
			continue;
		}

		prlog(PR_DEBUG, "IPLPARAMS: FW feature %s = %016"PRIx64"\n",
				name, flags);

		/* get rid of tm-suspend-mode-enabled being disabled */
		if (strcmp(name, "tm-suspend-mode-enabled") == 0)
			strcpy(name, "tm-suspend-mode");

		n = dt_new(fw_features, name);

		/*
		 * This is a bit overkill, but we'll want seperate properties
		 * for each flag bit(s).
		 */
		if (flags & PPC_BIT(0))
			dt_add_property(n, "enabled", NULL, 0);
		else
			dt_add_property(n, "disabled", NULL, 0);
	}
}

static void add_iplparams(void)
{
	struct dt_node *iplp_node;
	const void *ipl_parms;

	ipl_parms = get_hdif(&spira.ntuples.ipl_parms, "IPLPMS");
	if (!ipl_parms) {
		prerror("IPLPARAMS: Cannot find IPL Parms in SPIRA\n");
		return;
	}

	iplp_node = dt_new(dt_root, "ipl-params");
	assert(iplp_node);
	dt_add_property_cells(iplp_node, "#address-cells", 0);
	dt_add_property_cells(iplp_node, "#size-cells", 0);

	add_iplparams_sys_params(ipl_parms, iplp_node);
	add_iplparams_ipl_params(ipl_parms, iplp_node);
	add_iplparams_serials(ipl_parms, iplp_node);
	add_iplparams_platform_dump(ipl_parms, iplp_node);
	add_iplparams_features(ipl_parms);
}

/* Various structure contain a "proc_chip_id" which is an arbitrary
 * numbering used by HDAT to reference chips, which doesn't correspond
 * to the HW IDs. We want to use the HW IDs everywhere in the DT so
 * we convert using this.
 */
uint32_t pcid_to_chip_id(uint32_t proc_chip_id)
{
	unsigned int i;
	const void *hdif;

	/* First, try the proc_chip ntuples for chip data */
	for_each_ntuple_idx(&spira.ntuples.proc_chip, hdif, i,
			    SPPCRD_HDIF_SIG) {
		const struct sppcrd_chip_info *cinfo;

		cinfo = HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_INFO,
						NULL);
		if (!CHECK_SPPTR(cinfo)) {
			prerror("XSCOM: Bad ChipID data %d\n", i);
			continue;
		}
		if (proc_chip_id == be32_to_cpu(cinfo->proc_chip_id))
			return get_xscom_id(cinfo);
	}

	/* Not found, what to do ? Assert ? For now return a number
	 * guaranteed to not exist
	 */
	return (uint32_t)-1;
}

uint32_t pcid_to_topology_idx(uint32_t proc_chip_id)
{
	unsigned int i;
	const void *hdif;

	/* First, try the proc_chip ntuples for chip data */
	for_each_ntuple_idx(&spira.ntuples.proc_chip, hdif, i,
			    SPPCRD_HDIF_SIG) {
		const struct sppcrd_chip_info *cinfo;

		cinfo = HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_INFO, NULL);
		if (!CHECK_SPPTR(cinfo)) {
			prerror("XSCOM: Bad ChipID data %d\n", i);
			continue;
		}
		if (proc_chip_id == be32_to_cpu(cinfo->proc_chip_id)) {
			if (proc_gen <= proc_gen_p9)
				return get_xscom_id(cinfo);
			else
				return ((u32)cinfo->topology_id_table[cinfo->primary_topology_loc]);
		}
	}

	/* Not found, what to do ? Assert ? For now return a number
	 * guaranteed to not exist
	 */
	return (uint32_t)-1;
}
/* Create '/ibm,opal/led' node */
static void dt_init_led_node(void)
{
	struct dt_node *led_node;

	/* Create /ibm,opal node, if its not created already */
	if (!opal_node) {
		opal_node = dt_new(dt_root, "ibm,opal");
		assert(opal_node);
	}

	/* Crete LED parent node */
	led_node = dt_new(opal_node, DT_PROPERTY_LED_NODE);
	assert(led_node);
}

static void hostservices_parse(void)
{
	struct HDIF_common_hdr *hs_hdr;
	const void *dt_blob;
	unsigned int size;
	unsigned int ntuples_size;

	/* Deprecated on P9 */
	if (proc_gen >= proc_gen_p9)
		return;

	ntuples_size = sizeof(struct HDIF_array_hdr) + 
		be32_to_cpu(spira.ntuples.array_hdr.ecnt) *
		sizeof(struct spira_ntuple);

	if (offsetof(struct spira_ntuples, hs_data) >= ntuples_size) {
		prerror("SPIRA: No host services data found\n");
		return;
	}

	hs_hdr = get_hdif(&spira.ntuples.hs_data, HSERV_HDIF_SIG);
	if (!hs_hdr) {
		prerror("SPIRA: No host services data found\n");
		return;
	}

	dt_blob = HDIF_get_idata(hs_hdr, 0, &size);
	if (!dt_blob) {
		prerror("SPIRA: No host services idata found\n");
		return;
	}
	hservices_from_hdat(dt_blob, size);
}

static void add_stop_levels(void)
{
	struct spira_ntuple *t = &spira.ntuples.proc_chip;
	struct HDIF_common_hdr *hdif;
	u32 stop_levels = ~0;
	bool valid = false;
	int i;

	if (proc_gen < proc_gen_p9)
		return;

	/*
	 * OPAL only exports a single set of flags to indicate the supported
	 * STOP modes while the HDAT descibes the support top levels *per chip*
	 * We parse the list of chips to find a common set of STOP levels to
	 * export.
	 */
	for_each_ntuple_idx(t, hdif, i, SPPCRD_HDIF_SIG) {
		unsigned int size;
		const struct sppcrd_chip_info *cinfo =
			HDIF_get_idata(hdif, SPPCRD_IDATA_CHIP_INFO, &size);
		u32 ve, chip_levels;

		if (!cinfo)
			continue;

		/*
		 * If the chip info field is too small then assume we have no
		 * STOP level information.
		 */
		if (size < 0x44) {
			stop_levels = 0;
			break;
		}

		ve = be32_to_cpu(cinfo->verif_exist_flags) & CPU_ID_VERIFY_MASK;
		ve >>= CPU_ID_VERIFY_SHIFT;
		if (ve == CHIP_VERIFY_NOT_INSTALLED ||
		    ve == CHIP_VERIFY_UNUSABLE)
			continue;

		chip_levels = be32_to_cpu(cinfo->stop_levels);

		prlog(PR_INSANE, "CHIP[%x] supported STOP mask 0x%.8x\n",
			be32_to_cpu(cinfo->proc_chip_id), chip_levels);

		stop_levels &= chip_levels;
		valid = true;
	}

	if (!valid)
		stop_levels = 0;

	dt_add_property_cells(dt_new_check(opal_node, "power-mgt"),
		"ibm,enabled-stop-levels", stop_levels);
}

#define NPU_BASE 0x5011000
#define NPU_SIZE 0x2c
#define NPU_INDIRECT0	0x8000000009010c3fULL
#define NPU_INDIRECT1	0x800000000c010c3fULL

static void add_npu(struct dt_node *xscom, const struct HDIF_array_hdr *links,
			int npu_index)
{
	const struct sppcrd_smp_link *link;
	struct dt_node *npu;
	int group_target[6]; /* Tracks the PCI slot targeted each link group */
	int group_count = 0;
	int link_count = 0;
	uint32_t size, chip_id;
	int i;

	size = be32_to_cpu(links->esize);
	chip_id = dt_get_chip_id(xscom);

	memset(group_target, 0, sizeof(group_target));

	npu = dt_new_addr(xscom, "npu", NPU_BASE);
	dt_add_property_cells(npu, "reg", NPU_BASE, NPU_SIZE);
	dt_add_property_cells(npu, "#size-cells", 0);
	dt_add_property_cells(npu, "#address-cells", 1);

	dt_add_property_strings(npu, "compatible", "ibm,power9-npu");
	dt_add_property_cells(npu, "ibm,npu-index", npu_index);

	HDIF_iarray_for_each(links, i, link) {
		uint16_t slot_id = be16_to_cpu(link->pci_slot_idx);
		uint32_t link_id = be32_to_cpu(link->link_id);
		uint64_t speed = 0, nvlink_speed = 0;
		struct dt_node *node;

		/*
		 * Only add a link node if this link is targeted at a
		 * GPU device.
		 *
		 * If we ever activate it for an opencapi device, we
		 * should revisit the link definitions hard-coded
		 * on ZZ.
		 */
		if (be32_to_cpu(link->usage) != SMP_LINK_USE_GPU)
			continue;

		/*
		 * XXX: The link_id that we get from HDAT is essentially an
		 * arbitrary ID number so we can't use it as the reg for the
		 * link node.
		 *
		 * a) There's a 1-1 mapping between entries in the SMP link
		 *    structure and the NPU links.
		 *
		 * b) The SMP link array contains them in ascending order.
		 *
		 * We have some assurances that b) is correct, but if we get
		 * broken link numbering it's something to watch for.
		 *
		 * If we every have actual A-Bus (SMP) link info in here
		 * this is going to break.
		 */

		prlog(PR_DEBUG, "NPU: %04x:%d: Link (%d) targets slot %u\n",
			chip_id, link_count, link_count, slot_id);

		if (link_count >= 6) {
			prerror("NPU: %04x:%d: Ignoring extra link (max 6)\n",
				chip_id, link_count);
			break;
		}

		node = dt_new_addr(npu, "link", link_count);
		if (!node) {
			prerror("NPU: %04x:%d: Creating link node failed\n",
				chip_id, link_count);
			continue;
		}

		dt_add_property_string(node, "compatible", "ibm,npu-link");
		dt_add_property_cells(node, "reg", link_count);
		dt_add_property_cells(node, "ibm,npu-link-index", link_count);
		dt_add_property_cells(node, "ibm,workbook-link-id", link_id);

		dt_add_property_u64s(node, "ibm,npu-phy",
				link_count < 3 ? NPU_INDIRECT0 : NPU_INDIRECT1);
		dt_add_property_cells(node, "ibm,npu-lane-mask",
				be32_to_cpu(link->lane_mask));
		dt_add_property_cells(node, "ibm,npu-brick-id",
				be32_to_cpu(link->brick_id));

		link_count++;

		/*
		 * Add the group details if this is an NVlink.
		 *
		 * TODO: Cable card stuff.
		 */
		if (slot_id) {
			struct dt_node *slot;
			const char *name;
			int group;

			/*
			 * Search the existing groups for one targeting
			 * this PCI slot
			 */
			for (group = 0; group < group_count; group++)
				if (group_target[group] == slot_id)
					break;

			/* no group, make a new one */
			if (group == group_count) {
				group_target[group] = slot_id;
				group_count++;
			}

			dt_add_property_cells(node, "ibm,npu-group-id", group);

			slot = find_slot_entry_node(dt_root, slot_id);
			if (!slot) {
				prerror("NPU: %04x:%d: Unable find node for targeted PCIe slot\n",
					chip_id, link_count - 1);
				continue;
			}

			/*
			 * The slot_id points to a node that indicates that
			 * this GPU should appear under the slot. Grab the
			 * slot-label from the parent node that represents
			 * the actual slot.
			 */
			name = dt_prop_get_def(slot->parent, "ibm,slot-label",
						(char *)"<SLOT NAME MISSING>");

			prlog(PR_DEBUG, "NPU: %04x:%d: Target slot %s\n",
				chip_id, link_count - 1, name);

			dt_add_property_string(node, "ibm,slot-label", name);
			dt_add_property_cells(node, "ibm,pcie-slot",
					slot->phandle);
		}

		/* Newer fields which might not be populated */
		if (size <= 0x24)
			continue;

		switch (link->link_speed) {
			case 0: /* 20Gbps */
				speed = 20000000000ul;
				nvlink_speed = 0x3;
				break;
			case 1: /* 25Gbps */
				speed = 25000000000ul;
				nvlink_speed = 0x9;
				break;
			case 2: /* 25.78125 Gbps */
				nvlink_speed =  0x8;
				speed = 25781250000ul;
				break;
		}

		/* ibm,link-speed is in bps and nvidia,link-speed is ~magic~ */
		dt_add_property_u64s(node, "ibm,link-speed", speed);
		dt_add_property_cells(node, "nvidia,link-speed", nvlink_speed);

		dt_add_property_cells(node, DT_PRIVATE "occ-flag-pos",
				PPC_BIT(link->occ_flag_bit));
	}

	dt_add_property_cells(npu, "ibm,npu-links", link_count);
}

static void add_npus(void)
{
	struct dt_node *xscom;
	int npu_index = 0;

	/* Only consult HDAT for npu2 */
	if (cpu_type != PVR_TYPE_P9)
		return;

	dt_for_each_compatible(dt_root, xscom, "ibm,xscom") {
		const struct HDIF_array_hdr *links;

		links = xscom_to_pcrd(xscom, SPPCRD_IDATA_SMP_LINK);
		if (!links) {
			prerror("NPU: Unable to find matching SPPCRD for %s\n",
				xscom->name);
			continue;
		}

		/* should never happen, but stranger things have */
		if (!dt_find_by_name(dt_root, "ibm,pcie-slots")) {
			prerror("PCIe slot information missing, can't add npu");
			continue;
		}

		/* some hostboots will give us an empty array */
		if (be32_to_cpu(links->ecnt))
			add_npu(xscom, links, npu_index++);
	}
}

/*
 * Legacy SPIRA is being deprecated and we have new SPIRA-H/S structures.
 * But on older system (p7?) we will continue to get legacy SPIRA.
 *
 * SPIRA-S is initialized and provided by FSP. We use SPIRA-S signature
 * to identify supported format. Also if required adjust spira pointer.
 */
static void fixup_spira(void)
{
#if !defined(TEST)
	spiras = (struct spiras *)SPIRA_HEAP_BASE;
#endif

	/* Validate SPIRA-S signature */
	if (!spiras)
		return;
	if (!HDIF_check(&spiras->hdr, SPIRAS_HDIF_SIG))
		return;

	prlog(PR_DEBUG, "SPIRA-S found.\n");

	spira.ntuples.sp_subsys = spiras->ntuples.sp_subsys;
	spira.ntuples.ipl_parms = spiras->ntuples.ipl_parms;
	spira.ntuples.nt_enclosure_vpd = spiras->ntuples.nt_enclosure_vpd;
	spira.ntuples.slca = spiras->ntuples.slca;
	spira.ntuples.backplane_vpd = spiras->ntuples.backplane_vpd;
	spira.ntuples.system_vpd = spiras->ntuples.system_vpd;
	spira.ntuples.proc_init = spirah.ntuples.proc_init;
	spira.ntuples.clock_vpd = spiras->ntuples.clock_vpd;
	spira.ntuples.anchor_vpd = spiras->ntuples.anchor_vpd;
	spira.ntuples.op_panel_vpd = spiras->ntuples.op_panel_vpd;
	spira.ntuples.misc_cec_fru_vpd = spiras->ntuples.misc_cec_fru_vpd;
	spira.ntuples.ms_vpd = spiras->ntuples.ms_vpd;
	spira.ntuples.cec_iohub_fru = spiras->ntuples.cec_iohub_fru;
	spira.ntuples.cpu_ctrl = spirah.ntuples.cpu_ctrl;
	spira.ntuples.mdump_src = spirah.ntuples.mdump_src;
	spira.ntuples.mdump_dst = spirah.ntuples.mdump_dst;
	spira.ntuples.mdump_res  = spirah.ntuples.mdump_res;
	spira.ntuples.proc_dump_area = spirah.ntuples.proc_dump_area;
	spira.ntuples.pcia = spiras->ntuples.pcia;
	spira.ntuples.proc_chip = spiras->ntuples.proc_chip;
	spira.ntuples.hs_data = spiras->ntuples.hs_data;
	spira.ntuples.ipmi_sensor = spiras->ntuples.ipmi_sensor;
	spira.ntuples.node_stb_data = spiras->ntuples.node_stb_data;
}

/*
 * All the data structure addresses are relative to payload base. Hence adjust
 * structures that are needed to capture OPAL dump during MPIPL.
 */
static void update_spirah_addr(void)
{
#if !defined(TEST)
	if (proc_gen < proc_gen_p9)
		return;

	naca.spirah_addr = CPU_TO_BE64(SPIRAH_OFF);
	naca.spira_addr = CPU_TO_BE64(SPIRA_OFF);
	spirah.ntuples.hs_data_area.addr = CPU_TO_BE64(SPIRA_HEAP_BASE - SKIBOOT_BASE);
	spirah.ntuples.mdump_res.addr = CPU_TO_BE64(MDRT_TABLE_BASE - SKIBOOT_BASE);
#endif
}

int parse_hdat(bool is_opal)
{
	cpu_type = PVR_TYPE(mfspr(SPR_PVR));

	prlog(PR_DEBUG, "Parsing HDAT...\n");

	fixup_spira();

	update_spirah_addr();

	/*
	 * Basic DT root stuff
	 */
	dt_add_property_cells(dt_root, "#address-cells", 2);
	dt_add_property_cells(dt_root, "#size-cells", 2);

	if (proc_gen < proc_gen_p9)
		dt_add_property_string(dt_root, "lid-type", is_opal ? "opal" : "phyp");

	/* Add any BMCs and enable the LPC UART */
	bmc_parse();

	/* Create and populate /vpd node */
	dt_init_vpd_node();

	/* Create /ibm,opal/led node */
	dt_init_led_node();

	/* Parse PCIA */
	if (!pcia_parse())
		return -1;

	/* IPL params */
	add_iplparams();

	/* Add XSCOM node (must be before chiptod, IO and FSP) */
	add_xscom();

	/* Parse MS VPD */
	memory_parse();

	/* Add any FSPs */
	fsp_parse();

	/* Add ChipTOD's */
	if (!add_chiptod_old() && !add_chiptod_new())
		prerror("CHIPTOD: No ChipTOD found !\n");

	/* Add NX */
	add_nx();

	/* Add nest mmu */
	add_nmmu();

	/* Add IO HUBs and/or PHBs */
	io_parse();

	/* Add NPU nodes */
	add_npus();

	/* Parse VPD */
	vpd_parse();

	/* Host services information. */
 	hostservices_parse();

	/* Parse System Attention Indicator inforamtion */
	slca_dt_add_sai_node();

	add_stop_levels();

	/* Parse node secure and trusted boot data */
	if (proc_gen >= proc_gen_p9)
		node_stb_parse();

	prlog(PR_DEBUG, "Parsing HDAT...done\n");

	return 0;
}
