// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <cpu.h>
#include <device.h>
#include <vpd.h>
#include <ccan/str/str.h>
#include <libfdt/libfdt.h>
#include <mem_region.h>
#include <types.h>
#include <inttypes.h>
#include <processor.h>

#include "spira.h"
#include "hdata.h"

struct HDIF_ram_area_id {
	__be16 id;
#define RAM_AREA_INSTALLED	0x8000
#define RAM_AREA_FUNCTIONAL	0x4000
	__be16 flags;
	__be32 dimm_id;
	__be32 speed;
} __packed;

struct HDIF_ram_area_size {
	__be32 reserved1;
	__be32 mb;
} __packed;

struct HDIF_ms_area_address_range {
	__be64 start;
	__be64 end;
	__be32 chip;
	__be32 mirror_attr;
	__be64 mirror_start;
	__be32 controller_id;
	__be32 phys_attr;
} __packed;
#define PHYS_ATTR_TYPE_MASK 	0xff000000
#define   PHYS_ATTR_TYPE_STD		0
#define   PHYS_ATTR_TYPE_NVDIMM		1
#define   PHYS_ATTR_TYPE_MRAM		2
#define   PHYS_ATTR_TYPE_PCM		3

#define PHYS_ATTR_STATUS_MASK 	0x00ff0000
/*
 * The values here are mutually exclusive. I have no idea why anyone
 * decided encoding these are flags rather than sequential numbers was
 * a good idea, but here we are.
 */
#define   PHYS_ATTR_STATUS_CANT_SAVE 	0x01
#define   PHYS_ATTR_STATUS_SAVE_FAILED	0x02
#define   PHYS_ATTR_STATUS_SAVED	0x04
#define   PHYS_ATTR_STATUS_NOT_SAVED	0x08
#define   PHYS_ATTR_STATUS_ENCRYPTED	0x10
#define   PHYS_ATTR_STATUS_ERR_DETECTED	0x40
#define   PHYS_ATTR_STATUS_MEM_INVALID	0xff

/* Memory Controller ID for Nimbus P9 systems */
#define MS_CONTROLLER_MCBIST_ID(id)	GETFIELD(PPC_BITMASK32(0, 1), id)
#define MS_CONTROLLER_MCS_ID(id)	GETFIELD(PPC_BITMASK32(4, 7), id)
#define MS_CONTROLLER_MCA_ID(id)	GETFIELD(PPC_BITMASK32(8, 15), id)

/* Memory Controller ID for P9 AXONE systems */
#define MS_CONTROLLER_MC_ID(id)		GETFIELD(PPC_BITMASK32(0, 1), id)
#define MS_CONTROLLER_MI_ID(id)		GETFIELD(PPC_BITMASK32(4, 7), id)
#define MS_CONTROLLER_MCC_ID(id)	GETFIELD(PPC_BITMASK32(8, 15), id)
#define MS_CONTROLLER_OMI_ID(id)	GETFIELD(PPC_BITMASK32(16, 31), id)

struct HDIF_ms_area_id {
	__be16 id;
#define MS_PTYPE_RISER_CARD	0x8000
#define MS_PTYPE_MEM_CARD	0x4000
#define MS_PTYPE_CEC_FRU	0x2000
#define MS_PTYPE_HYBRID_CARD	0x1000
	__be16 parent_type;
#define MS_AREA_INSTALLED	0x8000
#define MS_AREA_FUNCTIONAL	0x4000
#define MS_AREA_SHARED		0x2000
	__be16 flags;
	__be16 share_id;
} __packed;


// FIXME: it should be 9, current HDATs are broken
#define MSAREA_IDATA_MMIO_IDX 8
struct HDIF_ms_area_ocmb_mmio {
	__be64 range_start;
	__be64 range_end;
	__be32 controller_id;
	__be32 proc_chip_id;
	__be64 hbrt_id;
#define OCMB_SCOM_8BYTE_ACCESS	PPC_BIT(0)
#define OCMB_SCOM_4BYTE_ACCESS	PPC_BIT(1)
	__be64 flags;
} __packed;

static void append_chip_id(struct dt_node *mem, u32 id)
{
	struct dt_property *prop;
	size_t len, i;

	prop = __dt_find_property(mem, "ibm,chip-id");
	if (!prop)
		return;
	len = prop->len >> 2;

	/* Check if it exists already */
	for (i = 0; i < len; i++) {
		if (dt_property_get_cell(prop, i) == id)
			return;
	}

	/* Add it to the list */
	dt_resize_property(&prop, (len + 1) << 2);
	dt_property_set_cell(prop, len, id);
}

static void update_status(struct dt_node *mem, uint32_t status)
{
	switch (status) {
	case PHYS_ATTR_STATUS_CANT_SAVE:
		if (!dt_find_property(mem, "save-trigged-unarmed"))
			dt_add_property(mem, "save-trigger-unarmed", NULL, 0);
		break;

	case PHYS_ATTR_STATUS_SAVE_FAILED:
		if (!dt_find_property(mem, "save-failed"))
			dt_add_property(mem, "save-failed", NULL, 0);

		break;

	case PHYS_ATTR_STATUS_MEM_INVALID:
		if (dt_find_property(mem, "save-trigged-unarmed"))
			dt_add_property_string(mem, "status",
				"disabled-memory-invalid");
		break;
	}
}

static bool add_address_range(struct dt_node *root,
			      const struct HDIF_ms_area_id *id,
			      const struct HDIF_ms_area_address_range *arange,
			      uint32_t mem_type, uint32_t mem_status)
{
	const char *compat = NULL, *dev_type = NULL, *name = NULL;
	struct dt_node *mem;
	u32 chip_id;
	u64 reg[2];

	chip_id = pcid_to_chip_id(be32_to_cpu(arange->chip));

	prlog(PR_DEBUG, "  Range: 0x%016llx..0x%016llx "
	      "on Chip 0x%x mattr: 0x%x pattr: 0x%x status:0x%x\n",
	      (long long)be64_to_cpu(arange->start),
	      (long long)be64_to_cpu(arange->end),
	      chip_id, be32_to_cpu(arange->mirror_attr),
	      mem_type, mem_status);

	/* reg contains start and length */
	reg[0] = cleanup_addr(be64_to_cpu(arange->start));
	reg[1] = cleanup_addr(be64_to_cpu(arange->end)) - reg[0];

	switch (mem_type) {
	case PHYS_ATTR_TYPE_STD:
		name = "memory";
		dev_type = "memory";
		break;

	case PHYS_ATTR_TYPE_NVDIMM:
	case PHYS_ATTR_TYPE_MRAM:
	case PHYS_ATTR_TYPE_PCM:
		/* fall through */
		name = "nvdimm";
		compat = "pmem-region";
		break;

	/*
	 * Future memory types could be volatile or non-volatile. Bail if don't
	 * recognise the type so we don't end up trashing data accidently.
	 */
	default:
		return false;
	}

	if (be16_to_cpu(id->flags) & MS_AREA_SHARED) {
		mem = dt_find_by_name_addr(dt_root, name, reg[0]);
		if (mem) {
			append_chip_id(mem, chip_id);
			if (mem_type == PHYS_ATTR_TYPE_NVDIMM)
				update_status(mem, mem_status);
			return true;
		}
	}

	mem = dt_new_addr(root, name, reg[0]);
	if (compat)
		dt_add_property_string(mem, "compatible", compat);
	if (dev_type)
		dt_add_property_string(mem, "device_type", dev_type);

	/* add in the nvdimm backup status flags */
	if (mem_type == PHYS_ATTR_TYPE_NVDIMM)
		update_status(mem, mem_status);

	/* common properties */

	dt_add_property_u64s(mem, "reg", reg[0], reg[1]);
	dt_add_property_cells(mem, "ibm,chip-id", chip_id);
	return true;
}

static u32 add_chip_id_to_ram_area(const struct HDIF_common_hdr *msarea,
				    struct dt_node *ram_area)
{
	const struct HDIF_array_hdr *arr;
	const struct HDIF_ms_area_address_range *arange;
	unsigned int size;
	u32 chip_id;

	/* Safe to assume pointers are valid here. */
	arr = HDIF_get_idata(msarea, 4, &size);
	arange = (void *)arr + be32_to_cpu(arr->offset);
	chip_id = pcid_to_chip_id(be32_to_cpu(arange->chip));
	dt_add_property_cells(ram_area, "ibm,chip-id", chip_id);

	return chip_id;
}

static void add_bus_freq_to_ram_area(struct dt_node *ram_node, u32 chip_id)
{
	const struct sppcia_cpu_timebase *timebase;
	bool got_pcia = false;
	const void *pcia;
	u64 freq;
	u32 size;

	pcia = get_hdif(&spira.ntuples.pcia, SPPCIA_HDIF_SIG);
	if (!pcia) {
		prlog(PR_WARNING, "HDAT: Failed to add memory bus frequency "
		      "as PCIA does not exist\n");
		return;
	}

	for_each_pcia(pcia) {
		const struct sppcia_core_unique *id;

		id = HDIF_get_idata(pcia, SPPCIA_IDATA_CORE_UNIQUE, &size);
		if (!id || size < sizeof(*id)) {
			prlog(PR_WARNING, "HDAT: Bad id size %u @ %p\n", size, id);
			return;
		}

		if (chip_id == pcid_to_chip_id(be32_to_cpu(id->proc_chip_id))) {
			got_pcia = true;
			break;
		}
	}

	if (got_pcia == false)
		return;

	timebase = HDIF_get_idata(pcia, SPPCIA_IDATA_TIMEBASE, &size);
	if (!timebase || size < sizeof(*timebase)) {
		/**
		 * @fwts-label HDATBadTimebaseSize
		 * @fwts-advice HDAT described an invalid size for timebase,
		 * which means there's a disagreement between HDAT and OPAL.
		 * This is most certainly a firmware bug.
		 */
		prlog(PR_ERR, "HDAT: Bad timebase size %u @ %p\n", size,
		      timebase);
		return;
	}

	freq = ((u64)be32_to_cpu(timebase->memory_bus_frequency)) * 1000000ul;
	dt_add_property_u64(ram_node, "ibm,memory-bus-frequency", freq);
}

static void add_size_to_ram_area(struct dt_node *ram_node,
				 const struct HDIF_common_hdr *ramarea)
{
	char	str[16];
	const struct HDIF_ram_area_size *ram_area_sz;

	/* DIMM size */
	ram_area_sz = HDIF_get_idata(ramarea, 3, NULL);
	if (!CHECK_SPPTR(ram_area_sz))
		return;

	memset(str, 0, 16);
	snprintf(str, 16, "%d", be32_to_cpu(ram_area_sz->mb));
	dt_add_property_string(ram_node, "size", str);
}

static void vpd_add_ram_area(const struct HDIF_common_hdr *msarea)
{
	unsigned int i;
	unsigned int ram_sz;
	const struct HDIF_common_hdr *ramarea;
	const struct HDIF_child_ptr *ramptr;
	const struct HDIF_ram_area_id *ram_id;
	struct dt_node *ram_node;
	u32 chip_id;
	const void *vpd_blob;

	ramptr = HDIF_child_arr(msarea, 0);
	if (!CHECK_SPPTR(ramptr)) {
		prerror("MS AREA: No RAM area at %p\n", msarea);
		return;
	}

	for (i = 0; i < be32_to_cpu(ramptr->count); i++) {
		ramarea = HDIF_child(msarea, ramptr, i, "RAM   ");
		if (!CHECK_SPPTR(ramarea))
			continue;

		ram_id = HDIF_get_idata(ramarea, 2, &ram_sz);
		if (!CHECK_SPPTR(ram_id))
			continue;

		/* Don't add VPD for non-existent RAM */
		if (!(be16_to_cpu(ram_id->flags) & RAM_AREA_INSTALLED))
			continue;

		ram_node = dt_add_vpd_node(ramarea, 0, 1);
		if (!ram_node)
			continue;

		chip_id = add_chip_id_to_ram_area(msarea, ram_node);
		add_bus_freq_to_ram_area(ram_node, chip_id);

		if (ram_sz >= offsetof(struct HDIF_ram_area_id, speed)) {
			dt_add_property_cells(ram_node, "frequency",
					      be32_to_cpu(ram_id->speed)*1000000);
		}

		vpd_blob = HDIF_get_idata(ramarea, 1, &ram_sz);

		/* DIMM size */
		add_size_to_ram_area(ram_node, ramarea);
		/*
		 * For direct-attached memory we have a DDR "Serial
		 * Presence Detection" blob rather than an IBM keyword
		 * blob.
		 */
		if (!vpd_valid(vpd_blob, ram_sz))
			dt_add_property(ram_node, "spd", vpd_blob, ram_sz);
	}
}

static void vpd_parse_spd(struct dt_node *dimm, const char *spd, u32 size)
{
	__be16 *vendor;
	__be32 *sn;

	/* SPD is too small */
	if (size < 512) {
		prlog(PR_WARNING, "MSVPD: Invalid SPD size. "
		      "Expected 512 bytes, got %d\n", size);
		return;
	}

	/* Supports DDR4 format pasing only */
	if (spd[0x2] < 0xc) {
		prlog(PR_WARNING,
		      "MSVPD: SPD format (%x) not supported\n", spd[0x2]);
		return;
	}

	dt_add_property_string(dimm, "device_type", "memory-dimm-ddr4");

	/* DRAM device type */
	dt_add_property_cells(dimm, "memory-id", spd[0x2]);

	/* Module revision code */
	dt_add_property_cells(dimm, "product-version", spd[0x15d]);

	/* Serial number */
	sn = (__be32 *)&spd[0x145];
	dt_add_property_cells(dimm, "serial-number", be32_to_cpu(*sn));

	/* Part number */
	dt_add_property_nstr(dimm, "part-number", &spd[0x149], 20);

	/* Module manufacturer ID */
	vendor = (__be16 *)&spd[0x140];
	dt_add_property_cells(dimm, "manufacturer-id", be16_to_cpu(*vendor));
}

static void add_dimm_info(struct dt_node *parent,
			      const struct HDIF_common_hdr *msarea)
{
	unsigned int i, size;
	const struct HDIF_child_ptr *ramptr;
	const struct HDIF_common_hdr *ramarea;
	const struct spira_fru_id *fru_id;
	const struct HDIF_ram_area_id *ram_id;
	const struct HDIF_ram_area_size *ram_area_sz;
	struct dt_node *dimm;
	const void *vpd_blob;

	ramptr = HDIF_child_arr(msarea, 0);
	if (!CHECK_SPPTR(ramptr)) {
		prerror("MS AREA: No RAM area at %p\n", msarea);
		return;
	}

	for (i = 0; i < be32_to_cpu(ramptr->count); i++) {
		ramarea = HDIF_child(msarea, ramptr, i, "RAM   ");
		if (!CHECK_SPPTR(ramarea))
			continue;

		fru_id = HDIF_get_idata(ramarea, 0, NULL);
		if (!fru_id)
			continue;

		/* Use Resource ID to add dimm node */
		dimm = dt_find_by_name_addr(parent, "dimm",
					    be16_to_cpu(fru_id->rsrc_id));
		if (dimm)
			continue;
		dimm= dt_new_addr(parent, "dimm", be16_to_cpu(fru_id->rsrc_id));
		assert(dimm);
		dt_add_property_cells(dimm, "reg", be16_to_cpu(fru_id->rsrc_id));

		/* Add location code */
		slca_vpd_add_loc_code(dimm, be16_to_cpu(fru_id->slca_index));

		/* DIMM size */
		ram_area_sz = HDIF_get_idata(ramarea, 3, NULL);
		if (!CHECK_SPPTR(ram_area_sz))
			continue;
		dt_add_property_cells(dimm, "size", be32_to_cpu(ram_area_sz->mb));

		/* DIMM state */
		ram_id = HDIF_get_idata(ramarea, 2, NULL);
		if (!CHECK_SPPTR(ram_id))
			continue;

		if ((be16_to_cpu(ram_id->flags) & RAM_AREA_INSTALLED) &&
		    (be16_to_cpu(ram_id->flags) & RAM_AREA_FUNCTIONAL))
			dt_add_property_string(dimm, "status", "okay");
		else
			dt_add_property_string(dimm, "status", "disabled");

		vpd_blob = HDIF_get_idata(ramarea, 1, &size);
		if (!CHECK_SPPTR(vpd_blob))
			continue;
		if (vpd_valid(vpd_blob, size))
			vpd_data_parse(dimm, vpd_blob, size);
		else
			vpd_parse_spd(dimm, vpd_blob, size);
	}
}

static inline void dt_add_mem_reg_property(struct dt_node *node, u64 addr)
{
	dt_add_property_cells(node, "#address-cells", 1);
	dt_add_property_cells(node, "#size-cells", 0);
	dt_add_property_cells(node, "reg", addr);
}

static void add_memory_controller_p9n(const struct HDIF_common_hdr *msarea,
				  const struct HDIF_ms_area_address_range *arange)
{
	uint32_t chip_id;
	uint32_t controller_id, mcbist_id, mcs_id, mca_id;
	struct dt_node *xscom, *mcbist, *mcs, *mca;

	chip_id = pcid_to_chip_id(be32_to_cpu(arange->chip));
	controller_id = be32_to_cpu(arange->controller_id);
	xscom = find_xscom_for_chip(chip_id);
	if (!xscom) {
		prlog(PR_WARNING,
		      "MS AREA: Can't find XSCOM for chip %d\n", chip_id);
		return;
	}

	mcbist_id = MS_CONTROLLER_MCBIST_ID(controller_id);
	mcbist = dt_find_by_name_addr(xscom, "mcbist", mcbist_id);
	if (!mcbist) {
		mcbist = dt_new_addr(xscom, "mcbist", mcbist_id);
		assert(mcbist);
		dt_add_property_cells(mcbist, "#address-cells", 1);
		dt_add_property_cells(mcbist, "#size-cells", 0);
		dt_add_property_cells(mcbist, "reg", mcbist_id, 0);
	}

	mcs_id = MS_CONTROLLER_MCS_ID(controller_id);
	mcs = dt_find_by_name_addr(mcbist, "mcs", mcs_id);
	if (!mcs) {
		mcs = dt_new_addr(mcbist, "mcs", mcs_id);
		assert(mcs);
		dt_add_mem_reg_property(mcs, mcs_id);
	}

	mca_id = MS_CONTROLLER_MCA_ID(controller_id);
	mca = dt_find_by_name_addr(mcs, "mca", mca_id);
	if (!mca) {
		mca = dt_new_addr(mcs, "mca", mca_id);
		assert(mca);
		dt_add_mem_reg_property(mca, mca_id);
	}

	add_dimm_info(mca, msarea);
}

static void add_memory_buffer_mmio(const struct HDIF_common_hdr *msarea)
{
	const struct HDIF_ms_area_ocmb_mmio *mmio;
	uint64_t min_addr = ~0ull, hbrt_id = 0;
	const struct HDIF_array_hdr *array;
	unsigned int i, count, ranges = 0;
	struct dt_node *membuf;
	beint64_t *reg, *flags;

	if (proc_gen <= proc_gen_p9 && PVR_TYPE(mfspr(SPR_PVR)) != PVR_TYPE_P9P)
		return;

	if (be16_to_cpu(msarea->version) < 0x50) {
		prlog(PR_WARNING, "MS AREA: Inconsistent MSAREA version %x for P9P system",
			be16_to_cpu(msarea->version));
		return;
	}

	array = HDIF_get_iarray(msarea, MSAREA_IDATA_MMIO_IDX, &count);
	if (!array || count <= 0) {
		prerror("MS AREA: No OCMB MMIO array at MS Area %p\n", msarea);
		return;
	}

	reg = zalloc(count * 2 * sizeof(*reg));
	flags = zalloc(count * sizeof(*flags));

	/* grab the hbrt id from the first range. */
	HDIF_iarray_for_each(array, i, mmio) {
		hbrt_id = be64_to_cpu(mmio->hbrt_id);
		break;
	}

	prlog(PR_DEBUG, "Adding memory buffer MMIO ranges for %"PRIx64"\n",
	      hbrt_id);

	HDIF_iarray_for_each(array, i, mmio) {
		uint64_t start, end;

		if (hbrt_id != be64_to_cpu(mmio->hbrt_id)) {
			prerror("HBRT ID mismatch!\n");
			continue;
		}

		start = cleanup_addr(be64_to_cpu(mmio->range_start));
		end   = cleanup_addr(be64_to_cpu(mmio->range_end));
		if (start < min_addr)
			min_addr = start;

		prlog(PR_DEBUG, "  %"PRIx64" - [%016"PRIx64"-%016"PRIx64")\n",
			hbrt_id, start, end);

		reg[2 * ranges    ] = cpu_to_be64(start);
		reg[2 * ranges + 1] = cpu_to_be64(end - start + 1);
		flags[ranges] = mmio->flags; /* both are BE */
		ranges++;
	}

	membuf = dt_find_by_name_addr(dt_root, "memory-buffer", min_addr);
	if (membuf) {
		prerror("attempted to duplicate %s\n", membuf->name);
		goto out;
	}

	membuf = dt_new_addr(dt_root, "memory-buffer", min_addr);
	assert(membuf);

	dt_add_property_string(membuf, "compatible", "ibm,explorer");
	dt_add_property_cells(membuf, "ibm,chip-id", hbrt_id);

	/*
	 * FIXME: We should probably be sorting the address ranges based
	 * on the starting address.
	 */
	dt_add_property(membuf, "reg",   reg,   sizeof(*reg) * 2 * ranges);
	dt_add_property(membuf, "flags", flags, sizeof(*flags)   * ranges);

out:
	free(flags);
	free(reg);
}

static void add_memory_controller(const struct HDIF_common_hdr *msarea,
				  const struct HDIF_ms_area_address_range *arange)
{
	const uint32_t version = PVR_TYPE(mfspr(SPR_PVR));
	/*
	 * Memory hierarchy may change between processor version. Presently
	 * it's only creating memory hierarchy for P9 (Nimbus) and P9P (Axone).
	 */

	if (version == PVR_TYPE_P9)
		return add_memory_controller_p9n(msarea, arange);
	else if (version == PVR_TYPE_P9P)
		return; //return add_memory_controller_p9p(msarea, arange);
	else
		return;
}

static void get_msareas(struct dt_node *root,
			const struct HDIF_common_hdr *ms_vpd)
{
	unsigned int i;
	const struct HDIF_child_ptr *msptr;

	/* First childptr refers to msareas. */
	msptr = HDIF_child_arr(ms_vpd, MSVPD_CHILD_MS_AREAS);
	if (!CHECK_SPPTR(msptr)) {
		prerror("MS VPD: no children at %p\n", ms_vpd);
		return;
	}

	for (i = 0; i < be32_to_cpu(msptr->count); i++) {
		const struct HDIF_common_hdr *msarea;
		const struct HDIF_array_hdr *arr;
		const struct HDIF_ms_area_address_range *arange;
		const struct HDIF_ms_area_id *id;
		const void *fruid;
		unsigned int size, j, offset;
		u16 flags;

		msarea = HDIF_child(ms_vpd, msptr, i, "MSAREA");
		if (!CHECK_SPPTR(msarea))
			return;

		id = HDIF_get_idata(msarea, 2, &size);
		if (!CHECK_SPPTR(id))
			return;
		if (size < sizeof(*id)) {
			prerror("MS VPD: %p msarea #%i id size too small!\n",
				ms_vpd, i);
			return;
		}

		flags = be16_to_cpu(id->flags);
		prlog(PR_DEBUG, "MS VPD: %p, area %i: %s %s %s\n",
		       ms_vpd, i,
		       flags & MS_AREA_INSTALLED ?
		       "installed" : "not installed",
		       flags & MS_AREA_FUNCTIONAL ?
		       "functional" : "not functional",
		       flags & MS_AREA_SHARED ?
		       "shared" : "not shared");

		if ((flags & (MS_AREA_INSTALLED|MS_AREA_FUNCTIONAL))
		    != (MS_AREA_INSTALLED|MS_AREA_FUNCTIONAL))
			continue;

		arr = HDIF_get_idata(msarea, 4, &size);
		if (!CHECK_SPPTR(arr))
			continue;

		if (size < sizeof(*arr)) {
			prerror("MS VPD: %p msarea #%i arr size too small!\n",
				ms_vpd, i);
			return;
		}

		offset = offsetof(struct HDIF_ms_area_address_range, mirror_start);
		if (be32_to_cpu(arr->eactsz) < offset) {
			prerror("MS VPD: %p msarea #%i arange size too small!\n",
				ms_vpd, i);
			return;
		}

		fruid = HDIF_get_idata(msarea, 0, &size);
		if (!CHECK_SPPTR(fruid))
			return;

		/* Add Raiser card VPD */
		if (be16_to_cpu(id->parent_type) & MS_PTYPE_RISER_CARD)
			dt_add_vpd_node(msarea, 0, 1);

		/* Add RAM Area VPD */
		vpd_add_ram_area(msarea);

		add_memory_buffer_mmio(msarea);

		/* This offset is from the arr, not the header! */
		arange = (void *)arr + be32_to_cpu(arr->offset);
		for (j = 0; j < be32_to_cpu(arr->ecnt); j++) {
			uint32_t type = 0, status = 0;

			/*
			 * Check that the required fields are present in this
			 * version of the HDAT structure.
			 */
			offset = offsetof(struct HDIF_ms_area_address_range, controller_id);
			if (be32_to_cpu(arr->eactsz) >= offset)
				add_memory_controller(msarea, arange);

			offset = offsetof(struct HDIF_ms_area_address_range, phys_attr);
			if (be32_to_cpu(arr->eactsz) >= offset) {
				uint32_t attr = be32_to_cpu(arange->phys_attr);

				type = GETFIELD(PHYS_ATTR_TYPE_MASK, attr);
				status = GETFIELD(PHYS_ATTR_STATUS_MASK, attr);
			}

			if (!add_address_range(root, id, arange, type, status))
				prerror("Unable to use memory range %d from MSAREA %d\n", j, i);

			arange = (void *)arange + be32_to_cpu(arr->esize);
		}
	}
}

static struct dt_node *dt_hb_reserves;

static struct dt_node *add_hb_reserve_node(const char *name, u64 start, u64 end)
{
	/* label size + "ibm," + NULL */
	char node_name[HB_RESERVE_MEM_LABEL_SIZE + 5] = { 0 };
	struct dt_node *node, *hb;

	if (!dt_hb_reserves) {
		hb = dt_new_check(dt_root, "ibm,hostboot");
		dt_add_property_cells(hb, "#size-cells", 2);
		dt_add_property_cells(hb, "#address-cells", 2);

		dt_hb_reserves = dt_new_check(hb, "reserved-memory");
		dt_add_property(dt_hb_reserves, "ranges", NULL, 0);
		dt_add_property_cells(dt_hb_reserves, "#size-cells", 2);
		dt_add_property_cells(dt_hb_reserves, "#address-cells", 2);
	}

	/* Add "ibm," to reserved node name */
	if (strncasecmp(name, "ibm", 3))
		snprintf(node_name, 5, "ibm,");
	strcat(node_name, name);

	node = dt_new_addr(dt_hb_reserves, node_name, start);
	if (!node) {
		prerror("Unable to create node for %s@%llx\n",
			node_name, (unsigned long long) start);
		return NULL;
	}

	dt_add_property_u64s(node, "reg", start, end - start + 1);

	return node;
}

static void get_hb_reserved_mem(struct HDIF_common_hdr *ms_vpd)
{
	const struct msvpd_hb_reserved_mem *hb_resv_mem;
	u64 start_addr, end_addr, label_size;
	struct dt_node *node;
	int count, i;
	char label[HB_RESERVE_MEM_LABEL_SIZE + 1];

	/*
	 * XXX: Reservation names only exist on P9 and on P7/8 we get the
	 *      reserved ranges through the hostboot mini-FDT instead.
	 */
	if (proc_gen < proc_gen_p9)
		return;

	count = HDIF_get_iarray_size(ms_vpd, MSVPD_IDATA_HB_RESERVED_MEM);
	if (count <= 0) {
		prerror("MS VPD: No hostboot reserved memory found\n");
		return;
	}

	for (i = 0; i < count; i++) {
		hb_resv_mem = HDIF_get_iarray_item(ms_vpd,
						   MSVPD_IDATA_HB_RESERVED_MEM,
						   i, NULL);
		if (!CHECK_SPPTR(hb_resv_mem))
			continue;

		label_size = be32_to_cpu(hb_resv_mem->label_size);
		start_addr = be64_to_cpu(hb_resv_mem->start_addr);
		end_addr = be64_to_cpu(hb_resv_mem->end_addr);

		/* Zero length regions are a normal, but should be ignored */
		if (start_addr - end_addr == 0) {
			prlog(PR_DEBUG, "MEM: Ignoring zero length range\n");
			continue;
		}

		/*
		 * Workaround broken HDAT reserve regions which are
		 * bigger than 512MB
		 */
		if ((end_addr - start_addr) > 0x20000000) {
			prlog(PR_ERR, "MEM: Ignoring Bad HDAT reserve: too big\n");
			continue;
		}

		/* remove the HRMOR bypass bit */
		start_addr &= ~HRMOR_BIT;
		end_addr &= ~HRMOR_BIT;
		if (label_size > HB_RESERVE_MEM_LABEL_SIZE)
			label_size = HB_RESERVE_MEM_LABEL_SIZE;

		memset(label, 0, HB_RESERVE_MEM_LABEL_SIZE + 1);
		memcpy(label, hb_resv_mem->label, label_size);
		label[label_size] = '\0';

		/* Unnamed reservations are always broken. Ignore them. */
		if (strlen(label) == 0)
			continue;

		prlog(PR_DEBUG, "MEM: Reserve '%s' %#" PRIx64 "-%#" PRIx64 " (type/inst=0x%08x)\n",
		      label, start_addr, end_addr, be32_to_cpu(hb_resv_mem->type_instance));

		node = add_hb_reserve_node(label, start_addr, end_addr);
		if (!node) {
			prerror("unable to add node?\n");
			continue;
		}

		/* the three low bytes of type_instance is the instance data */
		dt_add_property_cells(node, "ibm,prd-instance",
			(be32_to_cpu(hb_resv_mem->type_instance) & 0xffffff));

		/*
		 * Most reservations are used by HBRT itself so we should leave
		 * the label as-is. The exception is hbrt-code-image which is
		 * used by opal-prd to locate the HBRT image. Older versions
		 * of opal-prd expect this to be "ibm,hbrt-code-image" so make
		 * sure the prefix is there.
		 */
		if (!strcmp(label, "hbrt-code-image"))
			strcpy(label, "ibm,hbrt-code-image");
		dt_add_property_string(node, "ibm,prd-label", label);
	}
}

static void parse_trace_reservations(struct HDIF_common_hdr *ms_vpd)
{
	unsigned int size;
	int count, i;

	/*
	 * The trace arrays are only setup when hostboot is explicitly
	 * configured to enable them. We need to check and gracefully handle
	 * when they're not present.
	 */

	if (!HDIF_get_idata(ms_vpd, MSVPD_IDATA_TRACE_AREAS, &size) || !size) {
		prlog(PR_DEBUG, "MS VPD: No trace areas found\n");
		return;
	}

	count = HDIF_get_iarray_size(ms_vpd, MSVPD_IDATA_TRACE_AREAS);
	if (count <= 0) {
		prlog(PR_DEBUG, "MS VPD: No trace areas found\n");
		return;
	}

	prlog(PR_INFO, "MS VPD: Found %d trace areas\n", count);

	for (i = 0; i < count; i++) {
		const struct msvpd_trace *trace_area;
		struct dt_node *node;
		u64 start, end;

		trace_area = HDIF_get_iarray_item(ms_vpd,
				MSVPD_IDATA_TRACE_AREAS, i, &size);

		if (!trace_area)
			return; /* shouldn't happen */

		start = be64_to_cpu(trace_area->start) & ~HRMOR_BIT;
		end = be64_to_cpu(trace_area->end) & ~HRMOR_BIT;

		prlog(PR_INFO,
			"MS VPD: Trace area: 0x%.16"PRIx64"-0x%.16"PRIx64"\n",
			start, end);

		node = add_hb_reserve_node("trace-area", start, end);
		if (!node) {
			prerror("MEM: Unable to reserve trace area %p-%p\n",
				(void *) start, (void *) end);
			continue;
		}

		dt_add_property(node, "no-map", NULL, 0);
	}
}

static bool __memory_parse(struct dt_node *root)
{
	struct HDIF_common_hdr *ms_vpd;
	const struct msvpd_ms_addr_config *msac;
	const struct msvpd_total_config_ms *tcms;
	unsigned int size;

	ms_vpd = get_hdif(&spira.ntuples.ms_vpd, MSVPD_HDIF_SIG);
	if (!ms_vpd) {
		prerror("MS VPD: invalid\n");
		op_display(OP_FATAL, OP_MOD_MEM, 0x0000);
		return false;
	}
	if (be32_to_cpu(spira.ntuples.ms_vpd.act_len) < sizeof(*ms_vpd)) {
		prerror("MS VPD: invalid size %u\n",
			be32_to_cpu(spira.ntuples.ms_vpd.act_len));
		op_display(OP_FATAL, OP_MOD_MEM, 0x0001);
		return false;
	}

	prlog(PR_DEBUG, "MS VPD: is at %p\n", ms_vpd);

	msac = HDIF_get_idata(ms_vpd, MSVPD_IDATA_MS_ADDR_CONFIG, &size);
	if (!CHECK_SPPTR(msac) ||
	    size < offsetof(struct msvpd_ms_addr_config, max_possible_ms_address)) {
		prerror("MS VPD: bad msac size %u @ %p\n", size, msac);
		op_display(OP_FATAL, OP_MOD_MEM, 0x0002);
		return false;
	}
	prlog(PR_DEBUG, "MS VPD: MSAC is at %p\n", msac);

	dt_add_property_u64(dt_root, DT_PRIVATE "maxmem",
			    be64_to_cpu(msac->max_configured_ms_address));

	tcms = HDIF_get_idata(ms_vpd, MSVPD_IDATA_TOTAL_CONFIG_MS, &size);
	if (!CHECK_SPPTR(tcms) || size < sizeof(*tcms)) {
		prerror("MS VPD: Bad tcms size %u @ %p\n", size, tcms);
		op_display(OP_FATAL, OP_MOD_MEM, 0x0003);
		return false;
	}
	prlog(PR_DEBUG, "MS VPD: TCMS is at %p\n", tcms);

	prlog(PR_DEBUG, "MS VPD: Maximum configured address: 0x%llx\n",
	      (long long)be64_to_cpu(msac->max_configured_ms_address));
	prlog(PR_DEBUG, "MS VPD: Maximum possible address: 0x%llx\n",
	      (long long)be64_to_cpu(msac->max_possible_ms_address));

	get_msareas(root, ms_vpd);

	get_hb_reserved_mem(ms_vpd);

	parse_trace_reservations(ms_vpd);

	prlog(PR_INFO, "MS VPD: Total MB of RAM: 0x%llx\n",
	       (long long)be64_to_cpu(tcms->total_in_mb));

	return true;
}

void memory_parse(void)
{
	if (!__memory_parse(dt_root)) {
		prerror("MS VPD: Failed memory init !\n");
		abort();
	}
}
