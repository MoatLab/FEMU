// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * In-Memory Counters (IMC)
 * Sometimes called IMA, but that's also a different thing.
 *
 * Copyright 2016-2019 IBM Corp.
 */

#define pr_fmt(fmt)  "IMC: " fmt
#include <skiboot.h>
#include <xscom.h>
#include <imc.h>
#include <chip.h>
#include <libxz/xz.h>
#include <device.h>
#include <p9_stop_api.H>

/*
 * IMC trace scom values
 */
#define IMC_TRACE_CPMC1                0       /* select cpmc1 */
#define IMC_TRACE_CPMC2                1       /* select cpmc2 */
#define IMC_TRACE_CPMCLOAD_VAL	0xfa	/*
					 * Value to be loaded into cpmc2
					 * at sampling start
					 */

/* Event: CPM_32MHZ_CYC */
#define IMC_TRACE_CPMC2SEL_VAL	2
#define IMC_TRACE_CPMC1SEL_VAL	4

#define IMC_TRACE_BUFF_SIZE	0	/*
					 * b’000’- 4K entries * 64 per
					 * entry = 256K buffersize
					 */
static uint64_t TRACE_IMC_ADDR;
static uint64_t CORE_IMC_EVENT_MASK_ADDR;
static uint64_t trace_scom_val;
/*
 * Initialise these with the pdbar and htm scom port address array
 * at run time, based on the processor version.
 */
static unsigned int *pdbar_scom_index;
static unsigned int *htm_scom_index;

/*
 * Nest IMC PMU names along with their bit values as represented in the
 * imc_chip_avl_vector(in struct imc_chip_cb, look at include/imc.h).
 * nest_pmus[] is an array containing all the possible nest IMC PMU node names.
 */
static char const *nest_pmus[] = {
	"powerbus0",
	"mcs0",
	"mcs1",
	"mcs2",
	"mcs3",
	"mcs4",
	"mcs5",
	"mcs6",
	"mcs7",
	"mba0",
	"mba1",
	"mba2",
	"mba3",
	"mba4",
	"mba5",
	"mba6",
	"mba7",
	"cen0",
	"cen1",
	"cen2",
	"cen3",
	"cen4",
	"cen5",
	"cen6",
	"cen7",
	"xlink0",
	"xlink1",
	"xlink2",
	"mcd0",
	"mcd1",
	"phb0",
	"phb1",
	"phb2",
	"phb3",
	"phb4",
	"phb5",
	"nx",
	"capp0",
	"capp1",
	"vas",
	"int",
	"alink0",
	"alink1",
	"alink2",
	"alink3",
	"nvlink0",
	"nvlink1",
	"nvlink2",
	"nvlink3",
	"nvlink4",
	"nvlink5",
	/* reserved bits : 51 - 63 */
};

/*
 * Due to Nest HW/OCC restriction, microcode will not support individual unit
 * events for these nest units mcs0, mcs1 ... mcs7 in the accumulation mode.
 * And events to monitor each mcs units individually will be supported only
 * in the debug mode (which will be supported by microcode in the future).
 * These will be advertised only when OPAL provides interface for the it.
 */
static char const *debug_mode_units[] = {
	"mcs0",
	"mcs1",
	"mcs2",
	"mcs3",
	"mcs4",
	"mcs5",
	"mcs6",
	"mcs7",
};

/*
 * Combined unit node events are counted when any of the individual
 * unit is enabled in the availability vector. That is,
 * ex, mcs01 unit node should be enabled only when mcs0 or mcs1 enabled.
 * mcs23 unit node should be enabled only when mcs2 or mcs3 is enabled
 */
static struct combined_units_node cu_node[] = {
	{ .name = "mcs01", .unit1 = PPC_BIT(1), .unit2 = PPC_BIT(2) },
	{ .name = "mcs23", .unit1 = PPC_BIT(3), .unit2 = PPC_BIT(4) },
	{ .name = "mcs45", .unit1 = PPC_BIT(5), .unit2 = PPC_BIT(6) },
	{ .name = "mcs67", .unit1 = PPC_BIT(7), .unit2 = PPC_BIT(8) },
};

static char *compress_buf;
static size_t compress_buf_size;
const char **prop_to_fix(struct dt_node *node);
static const char *props_to_fix[] = {"events", NULL};

static bool is_nest_mem_initialized(struct imc_chip_cb *ptr)
{
	/*
	 * Non zero value in "Status" field indicate memory initialized.
	 */
	if (!ptr->imc_chip_run_status)
		return false;

	return true;
}

/*
 * A Quad contains 4 cores in Power 9, and there are 4 addresses for
 * the Core Hardware Trace Macro (CHTM) attached to each core.
 * So, for core index 0 to core index 3, we have a sequential range of
 * SCOM port addresses in the arrays below, each for Hardware Trace Macro (HTM)
 * mode and PDBAR.
 */
static unsigned int pdbar_scom_index_p9[] = {
	0x1001220B,
	0x1001230B,
	0x1001260B,
	0x1001270B
};
static unsigned int htm_scom_index_p9[] = {
	0x10012200,
	0x10012300,
	0x10012600,
	0x10012700
};

static unsigned int pdbar_scom_index_p10[] = {
	0x2001868B,
	0x2001468B,
	0x2001268B,
	0x2001168B
};

static unsigned int htm_scom_index_p10[] = {
	0x20018680,
	0x20014680,
	0x20012680,
	0x20011680
};

static struct imc_chip_cb *get_imc_cb(uint32_t chip_id)
{
	struct proc_chip *chip = get_chip(chip_id);
	struct imc_chip_cb *cb;

	if (!chip->homer_base)
		return NULL; /* The No Homers Club */

	cb = (struct imc_chip_cb *)(chip->homer_base + P9_CB_STRUCT_OFFSET);
	if (!is_nest_mem_initialized(cb))
		return NULL;

	return cb;
}

static int pause_microcode_at_boot(void)
{
	struct proc_chip *chip;
	struct imc_chip_cb *cb;

	for_each_chip(chip) {
		cb = get_imc_cb(chip->id);
		if (cb)
			cb->imc_chip_command =  cpu_to_be64(NEST_IMC_DISABLE);
		else
			return -1; /* ucode is not init-ed */
	}

	return 0;
}

/*
 * Function return list of properties names for the fixup
 */
const char **prop_to_fix(struct dt_node *node)
{
	if (dt_node_is_compatible(node, "ibm,imc-counters"))
		return props_to_fix;

	return NULL;
}

/* Helper to get the IMC device type for a device node */
static int get_imc_device_type(struct dt_node *node)
{
	const struct dt_property *type;
	u32 val=0;

	if (!node)
		return -1;

	type = dt_find_property(node, "type");
	if (!type)
		return -1;

	val = dt_prop_get_u32(node, "type");
	switch (val){
	case IMC_COUNTER_CHIP:
		return IMC_COUNTER_CHIP;
	case IMC_COUNTER_CORE:
		return IMC_COUNTER_CORE;
	case IMC_COUNTER_THREAD:
		return IMC_COUNTER_THREAD;
	case IMC_COUNTER_TRACE:
		return IMC_COUNTER_TRACE;
	default:
		break;
	}

	/* Unknown/Unsupported IMC device type */
	return -1;
}

static bool is_nest_node(struct dt_node *node)
{
	if (get_imc_device_type(node) == IMC_COUNTER_CHIP)
		return true;

	return false;
}

static bool is_imc_device_type_supported(struct dt_node *node)
{
	u32 val = get_imc_device_type(node);
	struct proc_chip *chip = get_chip(this_cpu()->chip_id);
	uint64_t pvr;

	if ((val == IMC_COUNTER_CHIP) || (val == IMC_COUNTER_CORE) ||
						(val == IMC_COUNTER_THREAD))
		return true;

	if (val == IMC_COUNTER_TRACE) {
		pvr = mfspr(SPR_PVR);

		switch (chip->type) {
		case PROC_CHIP_P9_NIMBUS:
			/*
			 * Trace mode is supported in Nimbus DD2.2
			 * and later versions.
			 */
			if ((PVR_VERS_MAJ(pvr) == 2) &&
				(PVR_VERS_MIN(pvr) >= 2))
					return true;
			break;
		case PROC_CHIP_P10:
			return true;
		default:
			return false;
		}

	}
	return false;
}

/*
 * Helper to check for the imc device type in the incoming device tree.
 * Remove unsupported device node.
 */
static void check_imc_device_type(struct dt_node *dev)
{
	struct dt_node *node;

	dt_for_each_compatible(dev, node, "ibm,imc-counters") {
		if (!is_imc_device_type_supported(node)) {
			/*
			 * ah nice, found a device type which I didnt know.
			 * Remove it and also mark node as NULL, since dt_next
			 * will try to fetch info for "prev" which is removed
			 * by dt_free.
			 */
			dt_free(node);
			node = NULL;
		}
	}

	return;
}

static void imc_dt_exports_prop_add(struct dt_node *dev)
{
	struct dt_node *node;
	struct proc_chip *chip;
	const struct dt_property *type;
	uint32_t offset = 0, size = 0;
	uint64_t baddr;
	char namebuf[32];


	dt_for_each_compatible(dev, node, "ibm,imc-counters") {
		type = dt_find_property(node, "type");
		if (type && is_nest_node(node)) {
			offset = dt_prop_get_u32(node, "offset");
			size = dt_prop_get_u32(node, "size");
		}
	}

	/*
	 * Enable only if we have valid values.
	 */
	if (!size && !offset)
		return;

	node = dt_find_by_name(opal_node, "exports");
	if (!node)
		return;

	for_each_chip(chip) {
		snprintf(namebuf, sizeof(namebuf), "imc_nest_chip_%x", chip->id);
		baddr = chip->homer_base;
		baddr += offset;
		dt_add_property_u64s(node, namebuf, baddr, size);
	}
}

/*
 * Remove the PMU device nodes from the incoming new subtree, if they are not
 * available in the hardware. The availability is described by the
 * control block's imc_chip_avl_vector.
 * Each bit represents a device unit. If the device is available, then
 * the bit is set else its unset.
 */
static void disable_unavailable_units(struct dt_node *dev)
{
	uint64_t avl_vec;
	struct imc_chip_cb *cb;
	struct dt_node *target;
	int i;
	bool disable_all_nests = false;
	struct proc_chip *chip;

	/*
	 * Check the state of ucode in all the chip.
	 * Disable the nest unit if ucode is not initialized
	 * in any of the chip.
	 */
	for_each_chip(chip) {
		cb = get_imc_cb(chip->id);
		if (!cb) {
			/*
			 * At least currently, if one chip isn't functioning,
			 * none of the IMC Nest units will be functional.
			 * So while you may *think* this should be per chip,
			 * it isn't.
			 */
			disable_all_nests = true;
			break;
		}
	}

	/* Add a property to "exports" node in opal_node */
	imc_dt_exports_prop_add(dev);

	/* Fetch the IMC control block structure */
	cb = get_imc_cb(this_cpu()->chip_id);
	if (cb && !disable_all_nests)
		avl_vec = be64_to_cpu(cb->imc_chip_avl_vector);
	else {
		avl_vec = 0; /* Remove only nest imc device nodes */

		/* Incase of mambo, just fake it */
		if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS)
			avl_vec = (0xffULL) << 56;
	}

	for (i = 0; i < ARRAY_SIZE(nest_pmus); i++) {
		if (!(PPC_BITMASK(i, i) & avl_vec)) {
			/* Check if the device node exists */
			target = dt_find_by_name(dev, nest_pmus[i]);
			if (!target)
				continue;
			/* Remove the device node */
			dt_free(target);
		}
	}

	/*
	 * Loop to detect debug mode units and remove them
	 * since the microcode does not support debug mode function yet.
	 */
	for (i = 0; i < ARRAY_SIZE(debug_mode_units); i++) {
		target = dt_find_by_name(dev, debug_mode_units[i]);
		if (!target)
			continue;
		/* Remove the device node */
		dt_free(target);
	}

	/*
	 * Based on availability unit vector from control block,
	 * check and enable combined unit nodes in the device tree.
	 */
	for (i = 0; i < MAX_NEST_COMBINED_UNITS ; i++ ) {
		if (!(cu_node[i].unit1 & avl_vec) &&
				!(cu_node[i].unit2 & avl_vec)) {
			target = dt_find_by_name(dev, cu_node[i].name);
			if (!target)
				continue;

			/* Remove the device node */
			dt_free(target);
		}
	}

	return;
}

static void disable_imc_type_from_dt(struct dt_node *dev, int imc_type)
{
	struct dt_node *node;

	dt_for_each_compatible(dev, node, "ibm,imc-counters") {
		if (get_imc_device_type(node) == imc_type) {
			dt_free(node);
			node = NULL;
		}
	}

	return;
}

/*
 * Function to queue the loading of imc catalog data
 * from the IMC pnor partition.
 */
void imc_catalog_preload(void)
{
	uint32_t pvr = (mfspr(SPR_PVR) & ~(0xf0ff));
	int ret = OPAL_SUCCESS;
	compress_buf_size = MAX_COMPRESSED_IMC_DTB_SIZE;

	if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS)
		return;

	/* Enable only for power 9/10 */
	if (proc_gen < proc_gen_p9)
		return;

	compress_buf = malloc(MAX_COMPRESSED_IMC_DTB_SIZE);
	if (!compress_buf) {
		prerror("Memory allocation for catalog failed\n");
		return;
	}

	ret = start_preload_resource(RESOURCE_ID_IMA_CATALOG,
					pvr, compress_buf, &compress_buf_size);
	if (ret != OPAL_SUCCESS) {
		prerror("Failed to load IMA_CATALOG: %d\n", ret);
		free(compress_buf);
		compress_buf = NULL;
	}

	return;
}

static void imc_dt_update_nest_node(struct dt_node *dev)
{
	struct proc_chip *chip;
	__be64 *base_addr = NULL;
	__be32 *chipids = NULL;
	int i=0, nr_chip = nr_chips();
	struct dt_node *node;
	const struct dt_property *type;

	/* Add the base_addr and chip-id properties for the nest node */
	base_addr = malloc(sizeof(u64) * nr_chip);
	chipids = malloc(sizeof(u32) * nr_chip);
	for_each_chip(chip) {
		base_addr[i] = cpu_to_be64(chip->homer_base);
		chipids[i] = cpu_to_be32(chip->id);
		i++;
	}

	dt_for_each_compatible(dev, node, "ibm,imc-counters") {
		type = dt_find_property(node, "type");
		if (type && is_nest_node(node)) {
			dt_add_property(node, "base-addr", base_addr, (i * sizeof(u64)));
			dt_add_property(node, "chip-id", chipids, (i * sizeof(u32)));
		}
	}
}

static struct xz_decompress *imc_xz;

void imc_decompress_catalog(void)
{
	void *decompress_buf = NULL;
	uint32_t pvr = (mfspr(SPR_PVR) & ~(0xf0ff));
	int ret;

	/* Check we succeeded in starting the preload */
	if (compress_buf == NULL)
		return;

	ret = wait_for_resource_loaded(RESOURCE_ID_IMA_CATALOG, pvr);
	if (ret != OPAL_SUCCESS) {
		prerror("IMC Catalog load failed\n");
		return;
	}

	/*
	 * Memory for decompression.
	 */
	decompress_buf = malloc(MAX_DECOMPRESSED_IMC_DTB_SIZE);
	if (!decompress_buf) {
		prerror("No memory for decompress_buf \n");
		return;
	}

	/*
	 * Decompress the compressed buffer
	 */
	imc_xz = malloc(sizeof(struct xz_decompress));
	if (!imc_xz) {
		prerror("No memory to decompress IMC catalog\n");
		free(decompress_buf);
		return;
	}

	imc_xz->dst = decompress_buf;
	imc_xz->src = compress_buf;
	imc_xz->dst_size = MAX_DECOMPRESSED_IMC_DTB_SIZE;
	imc_xz->src_size = compress_buf_size;
	xz_start_decompress(imc_xz);
}

static int setup_imc_scoms(void)
{
	switch (proc_gen) {
	case proc_gen_p9:
		CORE_IMC_EVENT_MASK_ADDR = CORE_IMC_EVENT_MASK_ADDR_P9;
		TRACE_IMC_ADDR = TRACE_IMC_ADDR_P9;
		pdbar_scom_index = pdbar_scom_index_p9;
		htm_scom_index = htm_scom_index_p9;
		trace_scom_val = TRACE_IMC_SCOM(IMC_TRACE_CPMC2,
						IMC_TRACE_CPMCLOAD_VAL,
						IMC_TRACE_CPMC1SEL_VAL,
						IMC_TRACE_CPMC2SEL_VAL,
						IMC_TRACE_BUFF_SIZE);
		return 0;
	case proc_gen_p10:
		CORE_IMC_EVENT_MASK_ADDR = CORE_IMC_EVENT_MASK_ADDR_P10;
		TRACE_IMC_ADDR = TRACE_IMC_ADDR_P10;
		pdbar_scom_index = pdbar_scom_index_p10;
		htm_scom_index = htm_scom_index_p10;
		trace_scom_val = TRACE_IMC_SCOM(IMC_TRACE_CPMC1,
						IMC_TRACE_CPMCLOAD_VAL,
						IMC_TRACE_CPMC1SEL_VAL,
						IMC_TRACE_CPMC2SEL_VAL,
						IMC_TRACE_BUFF_SIZE);
		return 0;
	default:
		prerror("%s: Unknown cpu type\n", __func__);
		break;
	}
	return -1;
}

/*
 * Load the IMC pnor partition and find the appropriate sub-partition
 * based on the platform's PVR.
 * Decompress the sub-partition and link the imc device tree to the
 * existing device tree.
 */
void imc_init(void)
{
	struct dt_node *dev;
	int err_flag = -1;

	if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS) {
		dev = dt_find_compatible_node(dt_root, NULL,
					"ibm,opal-in-memory-counters");
		if (!dev)
			return;

		goto imc_mambo;
	}

	/* Enable only for power 9/10 */
	if (proc_gen < proc_gen_p9)
		return;

	if (!imc_xz)
		return;

	wait_xz_decompress(imc_xz);
	if (imc_xz->status != OPAL_SUCCESS) {
		prerror("IMC: xz_decompress failed\n");
		goto err;
	}

	/*
	 * Flow of the data from PNOR to main device tree:
	 *
	 * PNOR -> compressed local buffer (compress_buf)
	 * compressed local buffer -> decompressed local buf (decompress_buf)
	 * decompress local buffer -> main device tree
	 * free compressed local buffer
	 */


	/* Create a device tree entry for imc counters */
	dev = dt_new_root("imc-counters");
	if (!dev) {
		prerror("IMC: Failed to add an imc-counters root node\n");
		goto err;
	}

	/*
	 * Attach the new decompress_buf to the imc-counters node.
	 * dt_expand_node() does sanity checks for fdt_header, piggyback
	 */
	if (dt_expand_node(dev, imc_xz->dst, 0) < 0) {
		dt_free(dev);
		prerror("IMC: dt_expand_node failed\n");
		goto err;
	}

imc_mambo:
	if (setup_imc_scoms()) {
		prerror("IMC: Failed to setup the scoms\n");
		goto err;
	}

	/* Check and remove unsupported imc device types */
	check_imc_device_type(dev);

	/*
	 * Check and remove unsupported nest unit nodes by the microcode,
	 * from the incoming device tree.
	 */
	disable_unavailable_units(dev);

	/* Fix the phandle in the incoming device tree */
	dt_adjust_subtree_phandle(dev, prop_to_fix);

	/* Update the base_addr and chip-id for nest nodes */
	imc_dt_update_nest_node(dev);

	if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS)
		return;

	/*
	 * IMC nest counters has both in-band (ucode access) and out of band
	 * access to it. Since not all nest counter configurations are supported
	 * by ucode, out of band tools are used to characterize other
	 * configuration.
	 *
	 * If the ucode not paused and OS does not have IMC driver support,
	 * then out to band tools will race with ucode and end up getting
	 * undesirable values. Hence pause the ucode if it is already running.
	 */
	if (pause_microcode_at_boot()) {
		prerror("IMC: Pausing ucode failed, disabling nest imc\n");
		disable_imc_type_from_dt(dev, IMC_COUNTER_CHIP);
	}

	/*
	 * If the dt_attach_root() fails, "imc-counters" node will not be
	 * seen in the device-tree and hence OS should not make any
	 * OPAL_IMC_* calls.
	 */
	if (!dt_attach_root(dt_root, dev)) {
		dt_free(dev);
		prerror("IMC: Failed to attach imc-counter node to dt root\n");
		goto err;
	}

	err_flag = OPAL_SUCCESS;

err:
	if (err_flag != OPAL_SUCCESS)
		prerror("IMC Devices not added\n");

	free(compress_buf);
	free(imc_xz->dst);
	free(imc_xz);
}

static int stop_api_init(struct proc_chip *chip, int phys_core_id,
			uint32_t scoms,  uint64_t data,
			const ScomOperation_t operation,
			const ScomSection_t section,
			const char *type)
{
	int ret;

	prlog(PR_DEBUG, "Configuring stopapi for IMC\n");
	ret = p9_stop_save_scom((void *)chip->homer_base, scoms,
				data, operation, section);
	if (ret) {
		prerror("IMC %s stopapi ret = %d, scoms = %x (core id = %x)\n",\
				type, ret, scoms, phys_core_id);
		if (ret != STOP_SAVE_SCOM_ENTRY_UPDATE_FAILED)
			wakeup_engine_state = WAKEUP_ENGINE_FAILED;
		else
			prerror("SCOM entries are full\n");
		return OPAL_HARDWARE;
	}

	return ret;
}

/* Function to return the scom address for the specified core */
static uint32_t get_imc_scom_addr_for_core(int core, uint64_t addr)
{
	uint32_t scom_addr;

	switch (proc_gen) {
	case proc_gen_p9:
		scom_addr = XSCOM_ADDR_P9_EC(core, addr);
		return scom_addr;
	case proc_gen_p10:
		scom_addr = XSCOM_ADDR_P10_EC(core, addr);
		return scom_addr;
	default:
		return 0;
	}
}

/* Function to return the scom address for the specified core in the quad */
static uint32_t get_imc_scom_addr_for_quad(int core, uint64_t addr)
{
	uint32_t scom_addr;

	switch (proc_gen) {
	case proc_gen_p9:
		scom_addr = XSCOM_ADDR_P9_EQ(core, addr);
		return scom_addr;
	case proc_gen_p10:
		scom_addr = XSCOM_ADDR_P10_EQ(core, addr);
		return scom_addr;
	default:
		return 0;
	}
}

static int64_t core_imc_counters_init(uint64_t addr, int port_id,
				int phys_core_id, struct cpu_thread *c)
{
	uint32_t pdbar_addr, event_mask_addr, htm_addr;
	int ret;

	/* Get the scom address for this core, based on the platform */
	pdbar_addr = get_imc_scom_addr_for_quad(phys_core_id,
				pdbar_scom_index[port_id]);
	event_mask_addr = get_imc_scom_addr_for_core(phys_core_id,
				CORE_IMC_EVENT_MASK_ADDR);

	/*
	 * Core IMC hardware mandate initing of three scoms
	 * to enbale or disable of the Core IMC engine.
	 *
	 * PDBAR: Scom contains the real address to store per-core
	 *        counter data in memory along with other bits.
	 *
	 * EventMask: Scom contain bits to denote event to multiplex
	 *            at different MSR[HV PR] values, along with bits for
	 *            sampling duration.
	 *
	 * HTM Scom: scom to enable counter data movement to memory.
	 */


	 if (xscom_write(c->chip_id, pdbar_addr,
			(u64)(CORE_IMC_PDBAR_MASK & addr))) {
		prerror("error in xscom_write for pdbar\n");
		return OPAL_HARDWARE;
	}

	if (has_deep_states) {
		if (wakeup_engine_state == WAKEUP_ENGINE_PRESENT) {
			struct proc_chip *chip = get_chip(c->chip_id);

			ret = stop_api_init(chip, phys_core_id, pdbar_addr,
					(u64)(CORE_IMC_PDBAR_MASK & addr),
					P9_STOP_SCOM_REPLACE,
					P9_STOP_SECTION_EQ_SCOM,
					"pdbar");
			if (ret)
				return ret;
			ret = stop_api_init(chip, phys_core_id,
					event_mask_addr,
					(u64)CORE_IMC_EVENT_MASK,
					P9_STOP_SCOM_REPLACE,
					P9_STOP_SECTION_CORE_SCOM,
					"event_mask");
			if (ret)
				return ret;
		} else {
			prerror("IMC: Wakeup engine not present!");
			return OPAL_HARDWARE;
		}
	}

	if (xscom_write(c->chip_id, event_mask_addr,
				(u64)CORE_IMC_EVENT_MASK)) {
		prerror("error in xscom_write for event mask\n");
		return OPAL_HARDWARE;
	}

	/* Get the scom address for htm_mode scom based on the platform */
	htm_addr = get_imc_scom_addr_for_quad(phys_core_id,
			htm_scom_index[port_id]);
	if (xscom_write(c->chip_id, htm_addr,
			(u64)CORE_IMC_HTM_MODE_DISABLE)) {
		prerror("error in xscom_write for htm mode\n");
		return OPAL_HARDWARE;
	}
	return OPAL_SUCCESS;
}

/*
 * opal_imc_counters_init : This call initialize the IMC engine.
 *
 * For Nest IMC, this is no-op and returns OPAL_SUCCESS at this point.
 * For Core IMC, this initializes core IMC Engine, by initializing
 * these scoms "PDBAR", "HTM_MODE" and the "EVENT_MASK" in a given cpu.
 */
static int64_t opal_imc_counters_init(uint32_t type, uint64_t addr, uint64_t cpu_pir)
{
	struct cpu_thread *c = find_cpu_by_pir(cpu_pir);
	int port_id, phys_core_id;
	int ret;
	uint32_t htm_addr, trace_addr;

	switch (type) {
	case OPAL_IMC_COUNTERS_NEST:
		return OPAL_SUCCESS;
	case OPAL_IMC_COUNTERS_CORE:
		if (!c)
			return OPAL_PARAMETER;

		/*
		 * Core IMC hardware mandates setting of htm_mode and
		 * pdbar in specific scom ports. port_id are in
		 * pdbar_scom_index[] and htm_scom_index[].
		 */
		phys_core_id = pir_to_core_id(c->pir);
		port_id = phys_core_id % 4;

		if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS)
			return OPAL_SUCCESS;

		ret = core_imc_counters_init(addr, port_id, phys_core_id, c);
		if (ret < 0)
			return ret;
		/*
		 * If fused core is supported, do the scoms for the
		 * secondary core also.
		 */
		if (this_cpu()->is_fused_core) {
			struct cpu_thread *c1 = find_cpu_by_pir(cpu_pir ^ 1);

			phys_core_id = pir_to_core_id(c1->pir);
			port_id = phys_core_id % 4;

			ret = core_imc_counters_init(addr, port_id, phys_core_id, c1);
			if (ret < 0)
				return ret;
		}
		return ret;
	case OPAL_IMC_COUNTERS_TRACE:
		if (!c)
			return OPAL_PARAMETER;

		phys_core_id = pir_to_core_id(c->pir);
		port_id = phys_core_id % 4;

		if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS)
			return OPAL_SUCCESS;

		trace_addr = get_imc_scom_addr_for_core(phys_core_id,
				TRACE_IMC_ADDR);
		htm_addr = get_imc_scom_addr_for_quad(phys_core_id,
				htm_scom_index[port_id]);

		if (has_deep_states) {
			if (wakeup_engine_state == WAKEUP_ENGINE_PRESENT) {
				struct proc_chip *chip = get_chip(c->chip_id);

				ret = stop_api_init(chip, phys_core_id,
						    trace_addr,
						    trace_scom_val,
						    P9_STOP_SCOM_REPLACE,
						    P9_STOP_SECTION_CORE_SCOM,
						    "trace_imc");
				if (ret)
					return ret;
			} else {
				prerror("IMC-trace:Wakeup engine not present!");
				return OPAL_HARDWARE;
			}
		}
		if (xscom_write(c->chip_id, htm_addr, (u64)CORE_IMC_HTM_MODE_DISABLE)) {
				prerror("IMC-trace: error in xscom_write for htm mode\n");
				return OPAL_HARDWARE;
		}
		if (xscom_write(c->chip_id, trace_addr, trace_scom_val)) {
			prerror("IMC-trace: error in xscom_write for trace mode\n");
			return OPAL_HARDWARE;
		}
		return OPAL_SUCCESS;

	}

	return OPAL_SUCCESS;
}
opal_call(OPAL_IMC_COUNTERS_INIT, opal_imc_counters_init, 3);

/* opal_imc_counters_control_start: This call starts the nest/core imc engine. */
static int64_t opal_imc_counters_start(uint32_t type, uint64_t cpu_pir)
{
	u64 op;
	struct cpu_thread *c = find_cpu_by_pir(cpu_pir);
	struct imc_chip_cb *cb;
	int port_id, phys_core_id;
	uint32_t htm_addr;

	if (!c)
		return OPAL_PARAMETER;

	switch (type) {
	case OPAL_IMC_COUNTERS_NEST:
		/* Fetch the IMC control block structure */
		cb = get_imc_cb(c->chip_id);
		if (!cb)
			return OPAL_HARDWARE;

		/* Set the run command */
		op = NEST_IMC_ENABLE;

		if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS)
			return OPAL_SUCCESS;

		/* Write the command to the control block now */
		cb->imc_chip_command = cpu_to_be64(op);

		return OPAL_SUCCESS;
	case OPAL_IMC_COUNTERS_CORE:
	case OPAL_IMC_COUNTERS_TRACE:
		/*
		 * Core IMC hardware mandates setting of htm_mode in specific
		 * scom ports (port_id are in htm_scom_index[])
		 */
		phys_core_id = pir_to_core_id(c->pir);
		port_id = phys_core_id % 4;

		if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS)
			return OPAL_SUCCESS;

		htm_addr = get_imc_scom_addr_for_quad(phys_core_id,
					htm_scom_index[port_id]);
		/*
		 * Enables the core imc engine by appropriately setting
		 * bits 4-9 of the HTM_MODE scom port. No initialization
		 * is done in this call. This just enables the the counters
		 * to count with the previous initialization.
		 */
		if (xscom_write(c->chip_id, htm_addr, (u64)CORE_IMC_HTM_MODE_ENABLE)) {
			prerror("IMC OPAL_start: error in xscom_write for htm_mode\n");
			return OPAL_HARDWARE;
		}

		return OPAL_SUCCESS;
	}

	return OPAL_SUCCESS;
}
opal_call(OPAL_IMC_COUNTERS_START, opal_imc_counters_start, 2);

/* opal_imc_counters_control_stop: This call stops the nest imc engine. */
static int64_t opal_imc_counters_stop(uint32_t type, uint64_t cpu_pir)
{
	u64 op;
	struct imc_chip_cb *cb;
	struct cpu_thread *c = find_cpu_by_pir(cpu_pir);
	int port_id, phys_core_id;
	uint32_t htm_addr;

	if (!c)
		return OPAL_PARAMETER;

	switch (type) {
	case OPAL_IMC_COUNTERS_NEST:
		/* Fetch the IMC control block structure */
		cb = get_imc_cb(c->chip_id);
		if (!cb)
			return OPAL_HARDWARE;

		/* Set the run command */
		op = NEST_IMC_DISABLE;

		if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS)
			return OPAL_SUCCESS;

		/* Write the command to the control block */
		cb->imc_chip_command = cpu_to_be64(op);

		return OPAL_SUCCESS;

	case OPAL_IMC_COUNTERS_CORE:
	case OPAL_IMC_COUNTERS_TRACE:
		/*
		 * Core IMC hardware mandates setting of htm_mode in specific
		 * scom ports (port_id are in htm_scom_index[])
		 */
		phys_core_id = pir_to_core_id(c->pir);
		port_id = phys_core_id % 4;

		if (proc_chip_quirks & QUIRK_MAMBO_CALLOUTS)
			return OPAL_SUCCESS;

		htm_addr = get_imc_scom_addr_for_quad(phys_core_id,
					htm_scom_index[port_id]);
		/*
		 * Disables the core imc engine by clearing
		 * bits 4-9 of the HTM_MODE scom port.
		 */
		if (xscom_write(c->chip_id, htm_addr, (u64) CORE_IMC_HTM_MODE_DISABLE)) {
			prerror("error in xscom_write for htm_mode\n");
			return OPAL_HARDWARE;
		}

		return OPAL_SUCCESS;
	}

	return OPAL_SUCCESS;
}
opal_call(OPAL_IMC_COUNTERS_STOP, opal_imc_counters_stop, 2);
