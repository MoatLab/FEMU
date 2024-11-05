/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 * Copyright 2021 IBM Corp.
 */

#include <interrupts.h>
#include <pci-slot.h>
#include <phys-map.h>
#include <xive.h>
#include <pau.h>
#include <pau-regs.h>
#include <xscom-p10-regs.h>

/* Number of PEs supported */
#define PAU_MAX_PE_NUM		16
#define PAU_RESERVED_PE_NUM	15

#define PAU_TL_MAX_TEMPLATE	63
#define PAU_TL_RATE_BUF_SIZE	32

#define PAU_SLOT_NORMAL 		PCI_SLOT_STATE_NORMAL
#define PAU_SLOT_LINK			PCI_SLOT_STATE_LINK
#define   PAU_SLOT_LINK_START		(PAU_SLOT_LINK + 1)
#define   PAU_SLOT_LINK_WAIT		(PAU_SLOT_LINK + 2)
#define   PAU_SLOT_LINK_TRAINED		(PAU_SLOT_LINK + 3)
#define PAU_SLOT_FRESET			PCI_SLOT_STATE_FRESET
#define   PAU_SLOT_FRESET_START		(PAU_SLOT_FRESET + 1)
#define   PAU_SLOT_FRESET_INIT		(PAU_SLOT_FRESET + 2)
#define   PAU_SLOT_FRESET_ASSERT_DELAY	(PAU_SLOT_FRESET + 3)
#define   PAU_SLOT_FRESET_DEASSERT_DELAY	(PAU_SLOT_FRESET + 4)
#define   PAU_SLOT_FRESET_INIT_DELAY	(PAU_SLOT_FRESET + 5)

#define PAU_LINK_TRAINING_RETRIES	2
#define PAU_LINK_TRAINING_TIMEOUT	15000 /* ms */
#define PAU_LINK_STATE_TRAINED		0x7

struct pau_dev *pau_next_dev(struct pau *pau, struct pau_dev *dev,
			     enum pau_dev_type type)
{
	uint32_t i = 0;

	if (dev)
		i = dev->index + 1;

	for (; i < pau->links; i++) {
		dev = &pau->devices[i];

		if (dev->type == type || type == PAU_DEV_TYPE_ANY)
			return dev;
	}

	return NULL;
}

static void pau_opencapi_dump_scom_reg(struct pau *pau, uint64_t reg)
{
	PAUDBG(pau, "0x%llx = 0x%016llx\n", reg, pau_read(pau, reg));
}

void pau_opencapi_dump_scoms(struct pau *pau)
{
	struct pau_dev *dev;
	uint64_t cq_sm;

	for (uint32_t i = 1; i < 4; i++) {
		cq_sm = PAU_BLOCK_CQ_SM(i);

		pau_opencapi_dump_scom_reg(pau, cq_sm + PAU_REG_OFFSET(PAU_MCP_MISC_CERR_MESSAGE0));
		pau_opencapi_dump_scom_reg(pau, cq_sm + PAU_REG_OFFSET(PAU_MCP_MISC_CERR_MESSAGE1));
		pau_opencapi_dump_scom_reg(pau, cq_sm + PAU_REG_OFFSET(PAU_MCP_MISC_CERR_MESSAGE2));
		pau_opencapi_dump_scom_reg(pau, cq_sm + PAU_REG_OFFSET(PAU_MCP_MISC_CERR_MESSAGE3));
		pau_opencapi_dump_scom_reg(pau, cq_sm + PAU_REG_OFFSET(PAU_MCP_MISC_CERR_MESSAGE4));
		pau_opencapi_dump_scom_reg(pau, cq_sm + PAU_REG_OFFSET(PAU_MCP_MISC_CERR_MESSAGE5));
		pau_opencapi_dump_scom_reg(pau, cq_sm + PAU_REG_OFFSET(PAU_MCP_MISC_CERR_MESSAGE6));
		pau_opencapi_dump_scom_reg(pau, cq_sm + PAU_REG_OFFSET(PAU_MCP_MISC_CERR_MESSAGE7));
		pau_opencapi_dump_scom_reg(pau, cq_sm + PAU_REG_OFFSET(PAU_MCP_MISC_CERR_FIRST0));
		pau_opencapi_dump_scom_reg(pau, cq_sm + PAU_REG_OFFSET(PAU_MCP_MISC_CERR_FIRST1));
		pau_opencapi_dump_scom_reg(pau, cq_sm + PAU_REG_OFFSET(PAU_MCP_MISC_CERR_FIRST2));
	}

	pau_opencapi_dump_scom_reg(pau, PAU_CTL_MISC_CERR_MESSAGE0);
	pau_opencapi_dump_scom_reg(pau, PAU_CTL_MISC_CERR_MESSAGE1);
	pau_opencapi_dump_scom_reg(pau, PAU_CTL_MISC_CERR_MESSAGE2);
	pau_opencapi_dump_scom_reg(pau, PAU_CTL_MISC_CERR_FIRST0);
	pau_opencapi_dump_scom_reg(pau, PAU_CTL_MISC_CERR_FIRST1);
	pau_opencapi_dump_scom_reg(pau, PAU_DAT_MISC_CERR_ECC_HOLD);
	pau_opencapi_dump_scom_reg(pau, PAU_DAT_MISC_CERR_ECC_MASK);
	pau_opencapi_dump_scom_reg(pau, PAU_DAT_MISC_CERR_ECC_FIRST);

	pau_for_each_opencapi_dev(dev, pau) {
		pau_opencapi_dump_scom_reg(pau, PAU_OTL_MISC_ERR_RPT_HOLD0(dev->index));
		pau_opencapi_dump_scom_reg(pau, PAU_OTL_MISC_OTL_REM0(dev->index));
		pau_opencapi_dump_scom_reg(pau, PAU_OTL_MISC_ERROR_SIG_RXI(dev->index));
		pau_opencapi_dump_scom_reg(pau, PAU_OTL_MISC_ERROR_SIG_RXO(dev->index));
		pau_opencapi_dump_scom_reg(pau, PAU_OTL_MISC_ERR_RPT_HOLD1(dev->index));
	}
}

static void pau_dt_create_link(struct dt_node *pau, uint32_t pau_index,
			       uint32_t dev_index)
{
	struct dt_node *link;
	uint32_t phy_lane_mask = 0, pau_unit = 0;
	uint32_t op_unit = 0, odl_index = 0;

	link = dt_new_addr(pau, "link", dev_index);

	dt_add_property_string(link, "compatible", "ibm,pau-link");
	dt_add_property_cells(link, "reg", dev_index);
	dt_add_property_cells(link, "ibm,pau-link-index", dev_index);

	/* pau_index	Interface Link - OPxA/B
	 * 0		OPT0 -- PAU0
	 *		OPT1 -- no PAU, SMP only
	 *		OPT2 -- no PAU, SMP only
	 * 1		OPT3 -- PAU3
	 * 2		OPT4 -- PAU4 by default, but can be muxed to use PAU5
	 * 3		OPT5 -- PAU5 by default, but can be muxed to use PAU4
	 * 4		OPT6 -- PAU6 by default, but can be muxed to use PAU7
	 * 5		OPT7 -- PAU7 by default, but can be muxed to use PAU6
	 */
	switch (pau_index) {
	case 0:
		/* OP0A - OP0B */
		pau_unit = 0;
		op_unit = 0;
		break;
	case 1:
		/* OP3A - OP3B */
		pau_unit = 3;
		op_unit = 3;
		break;
	case 2:
		/* OP4A - OP4B or OP5A - OP5B (TO DO) */
		pau_unit = 4;
		op_unit = 4;
		break;
	case 3:
		/* OP5A - OP5B or OP4A - OP4B (TO DO) */
		pau_unit = 5;
		op_unit = 5;
		break;
	case 4:
		/* OP6A - OP6B or OP7A - OP7B (TO DO) */
		pau_unit = 6;
		op_unit = 6;
		break;
	case 5:
		/* OP7A - OP7B or OP6A - OP6B (TO DO) */
		pau_unit = 7;
		op_unit = 7;
		break;
	default:
		return;
	}

	/* ODL0 is hooked up to OTL0 */
	if (dev_index == 0) {
		odl_index = 0;
		phy_lane_mask = PPC_BITMASK32(0, 3);
		phy_lane_mask |= PPC_BITMASK32(5, 8);
	} else if (dev_index == 1) {
		odl_index = 1;
		phy_lane_mask = PPC_BITMASK32(9, 12);
		phy_lane_mask |= PPC_BITMASK32(14, 17);
	}

	dt_add_property_cells(link, "ibm,odl-index", odl_index);
	dt_add_property_cells(link, "ibm,pau-unit", pau_unit);
	dt_add_property_cells(link, "ibm,op-unit", op_unit);
	dt_add_property_cells(link, "ibm,pau-lane-mask", phy_lane_mask);
	dt_add_property_cells(link, "ibm,phb-index", pau_get_phb_index(pau_index, dev_index));
}

static void pau_dt_create_pau(struct dt_node *xscom, uint32_t pau_index)
{
	const uint32_t pau_base[] = { 0x10010800, 0x11010800,
				      0x12010800, 0x12011000,
				      0x13010800, 0x13011000};
	struct dt_node *pau;
	uint32_t links;

	assert(pau_index < PAU_NBR);
	pau = dt_new_addr(xscom, "pau", pau_base[pau_index]);

	dt_add_property_cells(pau, "#size-cells", 0);
	dt_add_property_cells(pau, "#address-cells", 1);
	dt_add_property_cells(pau, "reg", pau_base[pau_index], 0x2c);
	dt_add_property_string(pau, "compatible", "ibm,power10-pau");
	dt_add_property_cells(pau, "ibm,pau-chiplet", pau_base[pau_index] >> 24);
	dt_add_property_cells(pau, "ibm,pau-index", pau_index);

	links = PAU_LINKS_OPENCAPI_PER_PAU;
	for (uint32_t i = 0; i < links; i++)
		pau_dt_create_link(pau, pau_index, i);
}

static bool pau_dt_create(void)
{
	struct dt_node *xscom;

	/* P10 chips only */
	if (proc_gen < proc_gen_p10)
		return false;

	dt_for_each_compatible(dt_root, xscom, "ibm,xscom")
		for (uint32_t i = 0; i < PAU_NBR; i++)
			pau_dt_create_pau(xscom, i);

	return true;
}

static struct pau *pau_create(struct dt_node *dn)
{
	struct pau *pau;
	struct dt_node *link;
	struct pau_dev *dev;
	char *path;
	uint32_t i;

	pau = zalloc(sizeof(*pau));
	assert(pau);

	init_lock(&pau->lock);
	init_lock(&pau->procedure_state.lock);

	pau->dt_node = dn;
	pau->index = dt_prop_get_u32(dn, "ibm,pau-index");
	pau->xscom_base = dt_get_address(dn, 0, NULL);

	pau->chip_id = dt_get_chip_id(dn);
	pau->op_chiplet = dt_prop_get_u32(dn, "ibm,pau-chiplet");
	assert(get_chip(pau->chip_id));

	pau->links = PAU_LINKS_OPENCAPI_PER_PAU;
	dt_for_each_compatible(dn, link, "ibm,pau-link") {
		i = dt_prop_get_u32(link, "ibm,pau-link-index");
		assert(i < PAU_LINKS_OPENCAPI_PER_PAU);

		dev = &pau->devices[i];
		dev->index = i;
		dev->pau = pau;
		dev->dn = link;
		dev->odl_index = dt_prop_get_u32(link, "ibm,odl-index");
		dev->pau_unit = dt_prop_get_u32(link, "ibm,pau-unit");
		dev->op_unit = dt_prop_get_u32(link, "ibm,op-unit");
		dev->phy_lane_mask = dt_prop_get_u32(link, "ibm,pau-lane-mask");
	};

	path = dt_get_path(dn);
	PAUINF(pau, "Found %s\n", path);
	PAUINF(pau, "SCOM base: 0x%llx\n", pau->xscom_base);
	free(path);

	return pau;
}

static void pau_device_detect_fixup(struct pau_dev *dev)
{
	struct dt_node *dn = dev->dn;

	if (dev->type == PAU_DEV_TYPE_OPENCAPI) {
		PAUDEVDBG(dev, "Link type opencapi\n");
		dt_add_property_strings(dn, "ibm,pau-link-type", "opencapi");
		return;
	}

	PAUDEVDBG(dev, "Link type unknown\n");
	dt_add_property_strings(dn, "ibm,pau-link-type", "unknown");
}

int64_t pau_opencapi_map_atsd_lpar(struct phb *phb, uint64_t __unused bdf,
				   uint64_t lparid, uint64_t __unused lpcr)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(phb);
	struct pau *pau = dev->pau;
	uint64_t val;

	if (lparid >= PAU_XTS_ATSD_MAX)
		return OPAL_PARAMETER;

	lock(&pau->lock);

	/* We need to allocate an ATSD per link */
	val = SETFIELD(PAU_XTS_ATSD_HYP_LPARID, 0ull, lparid);
	if (!lparid)
		val |= PAU_XTS_ATSD_HYP_MSR_HV;

	pau_write(pau, PAU_XTS_ATSD_HYP(lparid), val);

	unlock(&pau->lock);
	return OPAL_SUCCESS;
}

int64_t pau_opencapi_spa_setup(struct phb *phb, uint32_t __unused bdfn,
			       uint64_t addr, uint64_t PE_mask)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(phb);
	struct pau *pau = dev->pau;
	uint64_t reg, val;
	int64_t rc;

	lock(&pau->lock);

	reg = PAU_XSL_OSL_SPAP_AN(dev->index);
	val = pau_read(pau, reg);
	if ((addr && (val & PAU_XSL_OSL_SPAP_AN_EN)) ||
		(!addr && !(val & PAU_XSL_OSL_SPAP_AN_EN))) {
		rc = OPAL_BUSY;
		goto out;
	}

	/* SPA is disabled by passing a NULL address */
	val = addr;
	if (addr)
		val = addr | PAU_XSL_OSL_SPAP_AN_EN;
	pau_write(pau, reg, val);

	/*
	 * set the PE mask that the OS uses for PASID -> PE handle
	 * conversion
	 */
	reg = PAU_OTL_MISC_CFG0(dev->index);
	val = pau_read(pau, reg);
	val = SETFIELD(PAU_OTL_MISC_CFG0_PE_MASK, val, PE_mask);
	pau_write(pau, reg, val);
	rc = OPAL_SUCCESS;
out:
	unlock(&pau->lock);
	return rc;
}

int64_t pau_opencapi_spa_clear_cache(struct phb *phb,
				     uint32_t __unused bdfn,
				     uint64_t PE_handle)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(phb);
	struct pau *pau = dev->pau;
	uint64_t reg, val;
	int64_t rc, retries = 5;

	lock(&pau->lock);

	reg = PAU_XSL_OSL_CCINV;
	val = pau_read(pau, reg);
	if (val & PAU_XSL_OSL_CCINV_PENDING) {
		rc = OPAL_BUSY;
		goto out;
	}

	val = PAU_XSL_OSL_CCINV_REMOVE;
	val |= SETFIELD(PAU_XSL_OSL_CCINV_PE_HANDLE, val, PE_handle);
	if (dev->index)
		val |= PAU_XSL_OSL_CCINV_BRICK;
	pau_write(pau, reg, val);

	rc = OPAL_HARDWARE;
	while (retries--) {
		val = pau_read(pau, reg);
		if (!(val & PAU_XSL_OSL_CCINV_PENDING)) {
			rc = OPAL_SUCCESS;
			break;
		}
		/* the bit expected to flip in less than 200us */
		time_wait_us(200);
	}
out:
	unlock(&pau->lock);
	return rc;
}

static int pau_opencapi_get_templ_rate(unsigned int templ,
				       char *rate_buf)
{
	int shift, idx, val;

	/*
	 * Each rate is encoded over 4 bits (0->15), with 15 being the
	 * slowest. The buffer is a succession of rates for all the
	 * templates. The first 4 bits are for template 63, followed
	 * by 4 bits for template 62, ... etc. So the rate for
	 * template 0 is at the very end of the buffer.
	 */
	idx = (PAU_TL_MAX_TEMPLATE - templ) / 2;
	shift = 4 * (1 - ((PAU_TL_MAX_TEMPLATE - templ) % 2));
	val = rate_buf[idx] >> shift;
	return val;
}

static bool pau_opencapi_is_templ_supported(unsigned int templ,
					    long capabilities)
{
	return !!(capabilities & (1ull << templ));
}

int64_t pau_opencapi_tl_set(struct phb *phb, uint32_t __unused bdfn,
			    long capabilities, char *rate_buf)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(phb);
	struct pau *pau;
	uint64_t reg, val, templ_rate;
	int i, rate_pos;

	if (!dev)
		return OPAL_PARAMETER;
	pau = dev->pau;

	/* The 'capabilities' argument defines what TL template the
	 * device can receive. OpenCAPI 5.0 defines 64 templates, so
	 * that's one bit per template.
	 *
	 * For each template, the device processing time may vary, so
	 * the device advertises at what rate a message of a given
	 * template can be sent. That's encoded in the 'rate' buffer.
	 *
	 * On P10, PAU only knows about TL templates 0 -> 3.
	 * Per the spec, template 0 must be supported.
	 */
	if (!pau_opencapi_is_templ_supported(0, capabilities))
		return OPAL_PARAMETER;

	reg = PAU_OTL_MISC_CFG_TX(dev->index);
	val = pau_read(pau, reg);
	val &= ~PAU_OTL_MISC_CFG_TX_TEMP1_EN;
	val &= ~PAU_OTL_MISC_CFG_TX_TEMP2_EN;
	val &= ~PAU_OTL_MISC_CFG_TX_TEMP3_EN;

	for (i = 0; i < 4; i++) {
		/* Skip template 0 as it is implicitly enabled.
		 * Enable other template If supported by AFU
		 */
		if (i && pau_opencapi_is_templ_supported(i, capabilities))
			val |= PAU_OTL_MISC_CFG_TX_TEMP_EN(i);
		/* The tx rate should still be set for template 0 */
		templ_rate = pau_opencapi_get_templ_rate(i, rate_buf);
		rate_pos = 8 + i * 4;
		val = SETFIELD(PAU_OTL_MISC_CFG_TX_TEMP_RATE(rate_pos, rate_pos + 3),
			       val, templ_rate);
	}
	pau_write(pau, reg, val);
	PAUDEVDBG(dev, "OTL configuration register set to %llx\n", val);

	return OPAL_SUCCESS;
}

static int64_t pau_opencapi_afu_memory_bars(struct pau_dev *dev,
					    uint64_t size,
					    uint64_t *bar)
{
	struct pau *pau = dev->pau;
	uint64_t addr, psize;
	uint64_t reg, val;

	PAUDEVDBG(dev, "Setup AFU Memory BARs\n");

	if (dev->memory_bar.enable) {
		PAUDEVERR(dev, "AFU memory allocation failed - BAR already in use\n");
		return OPAL_RESOURCE;
	}

	phys_map_get(pau->chip_id, OCAPI_MEM,
		     dev->index,
		     &addr, &psize);

	if (size > psize) {
		PAUDEVERR(dev, "Invalid AFU memory BAR allocation size "
			       "requested: 0x%llx bytes (limit 0x%llx)\n",
			  size, psize);
		return OPAL_PARAMETER;
	}

	if (size < (1 << 30))
		size = 1 << 30;

	dev->memory_bar.enable = true;
	dev->memory_bar.addr = addr;
	dev->memory_bar.size = size;

	reg = PAU_GPU_MEM_BAR(dev->index);
	val = PAU_GPU_MEM_BAR_ENABLE |
	      PAU_GPU_MEM_BAR_POISON;
	val = SETFIELD(PAU_GPU_MEM_BAR_ADDR, val, addr >> 30);
	if (!is_pow2(size))
		size = 1ull << (ilog2(size) + 1);

	size = (size >> 30) - 1;
	val = SETFIELD(PAU_GPU_MEM_BAR_SIZE, val, size);
	pau_write(pau, reg, val);

	reg = PAU_CTL_MISC_GPU_MEM_BAR(dev->index);
	pau_write(pau, reg, val);

	reg = PAU_XSL_GPU_MEM_BAR(dev->index);
	pau_write(pau, reg, val);

	*bar = addr;
	return OPAL_SUCCESS;
}

int64_t pau_opencapi_mem_alloc(struct phb *phb, uint32_t __unused bdfn,
			       uint64_t size, uint64_t *bar)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(phb);
	int64_t rc;

	if (!dev)
		return OPAL_PARAMETER;

	if (!opal_addr_valid(bar))
		return OPAL_PARAMETER;

	lock(&dev->pau->lock);
	rc = pau_opencapi_afu_memory_bars(dev, size, bar);

	unlock(&dev->pau->lock);
	return rc;
}

int64_t pau_opencapi_mem_release(struct phb *phb, uint32_t __unused bdfn)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(phb);

	if (!dev)
		return OPAL_PARAMETER;

	lock(&dev->pau->lock);
	pau_write(dev->pau, PAU_GPU_MEM_BAR(dev->index), 0ull);
	pau_write(dev->pau, PAU_CTL_MISC_GPU_MEM_BAR(dev->index), 0ull);
	pau_write(dev->pau, PAU_XSL_GPU_MEM_BAR(dev->index), 0ull);

	dev->memory_bar.enable = false;
	dev->memory_bar.addr = 0ull;
	dev->memory_bar.size = 0ull;
	unlock(&dev->pau->lock);

	return OPAL_SUCCESS;
}

#define CQ_CTL_STATUS_TIMEOUT  10 /* milliseconds */

static int pau_opencapi_set_fence_control(struct pau_dev *dev,
					  uint8_t state_requested)
{
	uint64_t timeout = mftb() + msecs_to_tb(CQ_CTL_STATUS_TIMEOUT);
	uint8_t status;
	struct pau *pau = dev->pau;
	uint64_t reg, val;

	reg = PAU_CTL_MISC_FENCE_CTRL(dev->index);
	val = pau_read(pau, reg);
	val = SETFIELD(PAU_CTL_MISC_FENCE_REQUEST, val, state_requested);
	pau_write(pau, reg, val);

	/* Wait for fence status to update */
	do {
		reg = PAU_CTL_MISC_STATUS(dev->index);
		val = pau_read(pau, reg);
		status = GETFIELD(PAU_CTL_MISC_STATUS_AM_FENCED(dev->index), val);
		if (status == state_requested)
			return OPAL_SUCCESS;
		time_wait_ms(1);
	} while (tb_compare(mftb(), timeout) == TB_ABEFOREB);

	/*
	 * @fwts-label OCAPIFenceStatusTimeout
	 * @fwts-advice The PAU fence status did not update as expected. This
	 * could be the result of a firmware or hardware bug. OpenCAPI
	 * functionality could be broken.
	 */
	PAUDEVERR(dev, "Bad fence status: expected 0x%x, got 0x%x\n",
		       state_requested, status);
	return OPAL_HARDWARE;
}

#define PAU_DEV_STATUS_BROKEN	0x1

static void pau_opencapi_set_broken(struct pau_dev *dev)
{
	PAUDEVDBG(dev, "Update status to broken\n");

	dev->status = PAU_DEV_STATUS_BROKEN;
}

static void pau_opencapi_mask_firs(struct pau *pau)
{
	uint64_t reg, val;

	reg = pau->xscom_base + PAU_FIR_MASK(1);
	xscom_read(pau->chip_id, reg, &val);
	val |= PAU_FIR1_NDL_BRICKS_0_5;
	val |= PAU_FIR1_NDL_BRICKS_6_11;
	xscom_write(pau->chip_id, reg, val);

	reg = pau->xscom_base + PAU_FIR_MASK(2);
	xscom_read(pau->chip_id, reg, &val);
	val |= PAU_FIR2_OTL_PERR;
	xscom_write(pau->chip_id, reg, val);
}

static void pau_opencapi_assign_bars(struct pau *pau)
{
	struct pau_dev *dev;
	uint64_t addr, size, val;

	/* Global MMIO bar (per pau)
	 * 16M aligned address -> 0x1000000 (bit 24)
	 */
	phys_map_get(pau->chip_id, PAU_REGS, pau->index, &addr, &size);
	val = SETFIELD(PAU_MMIO_BAR_ADDR, 0ull, addr >> 24);
	val |= PAU_MMIO_BAR_ENABLE;
	pau_write(pau, PAU_MMIO_BAR, val);

	PAUINF(pau, "MMIO base: 0x%016llx (%lldMB)\n", addr, size >> 20);
	pau->regs[0] = addr;
	pau->regs[1] = size;

	/* NTL bar (per device)
	 * 64K aligned address -> 0x10000 (bit 16)
	 */
	pau_for_each_dev(dev, pau) {
		if (dev->type == PAU_DEV_TYPE_UNKNOWN)
			continue;

		phys_map_get(pau->chip_id, PAU_OCAPI_MMIO,
			     pau_dev_index(dev, PAU_LINKS_OPENCAPI_PER_PAU),
			     &addr, &size);

		val = SETFIELD(PAU_NTL_BAR_ADDR, 0ull, addr >> 16);
		val = SETFIELD(PAU_NTL_BAR_SIZE, val, ilog2(size >> 16));
		pau_write(pau, PAU_NTL_BAR(dev->index), val);

		val = SETFIELD(PAU_CTL_MISC_MMIOPA_CONFIG_BAR_ADDR, 0ull, addr >> 16);
		val = SETFIELD(PAU_CTL_MISC_MMIOPA_CONFIG_BAR_SIZE, val, ilog2(size >> 16));
		pau_write(pau, PAU_CTL_MISC_MMIOPA_CONFIG(dev->index), val);

		dev->ntl_bar.addr = addr;
		dev->ntl_bar.size = size;
	}

	/* GENID bar (logically divided per device)
	 * 512K aligned address -> 0x80000 (bit 19)
	 */
	phys_map_get(pau->chip_id, PAU_GENID, pau->index, &addr, &size);
	val = SETFIELD(PAU_GENID_BAR_ADDR, 0ull, addr >> 19);
	pau_write(pau, PAU_GENID_BAR, val);

	pau_for_each_dev(dev, pau) {
		if (dev->type == PAU_DEV_TYPE_UNKNOWN)
			continue;

		dev->genid_bar.size = size;
		/* +320K = Bricks 0-4 Config Addr/Data registers */
		dev->genid_bar.cfg = addr + 0x50000;
	}
}

static uint64_t pau_opencapi_ipi_attributes(struct irq_source *is,
					    uint32_t isn)
{
	struct pau *pau = is->data;
	uint32_t level = isn - pau->irq_base;

	if (level >= 37 && level <= 40) {
		/* level 37-40: OTL/XSL interrupt */
		return IRQ_ATTR_TARGET_OPAL |
		       IRQ_ATTR_TARGET_RARE |
		       IRQ_ATTR_TYPE_MSI;
	}

	return IRQ_ATTR_TARGET_LINUX;
}

static void pau_opencapi_ipi_interrupt(struct irq_source *is,
				       uint32_t isn)
{
	struct pau *pau = is->data;
	uint32_t level = isn - pau->irq_base;
	struct pau_dev *dev;

	switch (level) {
	case 37 ... 40:
		pau_for_each_opencapi_dev(dev, pau)
			pau_opencapi_set_broken(dev);

		opal_update_pending_evt(OPAL_EVENT_PCI_ERROR,
					OPAL_EVENT_PCI_ERROR);
		break;
	default:
		PAUERR(pau, "Received unknown interrupt %d\n", level);
		return;
	}
}

#define PAU_IRQ_LEVELS 60

static char *pau_opencapi_ipi_name(struct irq_source *is, uint32_t isn)
{
	struct pau *pau = is->data;
	uint32_t level = isn - pau->irq_base;

	switch (level) {
	case 0 ... 19:
		return strdup("Reserved");
	case 20:
		return strdup("An error event related to PAU CQ functions");
	case 21:
		return strdup("An error event related to PAU MISC functions");
	case 22 ... 34:
		return strdup("Reserved");
	case 35:
		return strdup("Translation failure for OCAPI link 0");
	case 36:
		return strdup("Translation failure for OCAPI link 1");
	case 37:
		return strdup("An error event related to OTL for link 0");
	case 38:
		return strdup("An error event related to OTL for link 1");
	case 39:
		return strdup("An error event related to XSL for link 0");
	case 40:
		return strdup("An error event related to XSL for link 1");
	case 41 ... 59:
		return strdup("Reserved");
	}

	return strdup("Unknown");
}

static const struct irq_source_ops pau_opencapi_ipi_ops = {
	.attributes	= pau_opencapi_ipi_attributes,
	.interrupt	= pau_opencapi_ipi_interrupt,
	.name		= pau_opencapi_ipi_name,
};

static void pau_opencapi_setup_irqs(struct pau *pau)
{
	uint64_t reg, val;
	uint32_t base;

	base = xive2_alloc_ipi_irqs(pau->chip_id, PAU_IRQ_LEVELS, 64);
	if (base == XIVE_IRQ_ERROR) {
		PAUERR(pau, "Failed to allocate interrupt sources\n");
		return;
	}

	xive2_register_ipi_source(base, PAU_IRQ_LEVELS, pau, &pau_opencapi_ipi_ops);

	/* Set IPI configuration */
	reg = PAU_MISC_CONFIG;
	val = pau_read(pau, reg);
	val = SETFIELD(PAU_MISC_CONFIG_IPI_PS, val, PAU_MISC_CONFIG_IPI_PS_64K);
	val = SETFIELD(PAU_MISC_CONFIG_IPI_OS, val, PAU_MISC_CONFIG_IPI_OS_AIX);
	pau_write(pau, reg, val);

	/* Set IRQ base */
	reg = PAU_MISC_INT_BAR;
	val = SETFIELD(PAU_MISC_INT_BAR_ADDR, 0ull,
		       (uint64_t)xive2_get_trigger_port(base) >> 12);
	pau_write(pau, reg, val);

	pau->irq_base = base;
}

static void pau_opencapi_enable_bars(struct pau_dev *dev, bool enable)
{
	struct pau *pau = dev->pau;
	uint64_t reg, val;

	if (dev->ntl_bar.enable == enable) /* No state change */
		return;

	dev->ntl_bar.enable = enable;
	dev->genid_bar.enable = enable;

	reg = PAU_NTL_BAR(dev->index);
	val = pau_read(pau, reg);
	val = SETFIELD(PAU_NTL_BAR_ENABLE, val, enable);
	pau_write(pau, reg, val);

	/*
	 * Generation IDs are a single space in the hardware but we split them
	 * per device. Only disable in hardware if every device has disabled.
	 */
	if (!enable)
		pau_for_each_dev(dev, pau)
			if (dev->genid_bar.enable)
				return;

	reg = PAU_GENID_BAR;
	val = pau_read(pau, reg);
	val = SETFIELD(PAU_GENID_BAR_ENABLE, val, enable);
	pau_write(pau, reg, val);
}

static int64_t pau_opencapi_creset(struct pci_slot *slot)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(slot->phb);

	PAUDEVERR(dev, "creset not supported\n");
	return OPAL_UNSUPPORTED;
}

static int64_t pau_opencapi_hreset(struct pci_slot *slot)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(slot->phb);

	PAUDEVERR(dev, "hreset not supported\n");
	return OPAL_UNSUPPORTED;
}

static void pau_opencapi_assert_odl_reset(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint64_t reg, val;

	reg = P10_OB_ODL_CONFIG(dev->op_unit, dev->odl_index);
	val = P10_OB_ODL_CONFIG_RESET;
	val = SETFIELD(P10_OB_ODL_CONFIG_VERSION, val, 0b000100); // OCAPI 4
	val = SETFIELD(P10_OB_ODL_CONFIG_TRAIN_MODE, val, 0b0101); // ts2
	val = SETFIELD(P10_OB_ODL_CONFIG_SUPPORTED_MODES, val, 0b0010);
	val |= P10_OB_ODL_CONFIG_X4_BACKOFF_ENABLE;
	val = SETFIELD(P10_OB_ODL_CONFIG_PHY_CNTR_LIMIT, val, 0b1111);
	val |= P10_OB_ODL_CONFIG_DEBUG_ENABLE;
	val = SETFIELD(P10_OB_ODL_CONFIG_FWD_PROGRESS_TIMER, val, 0b0110);
	xscom_write(pau->chip_id, reg, val);
}

static void pau_opencapi_deassert_odl_reset(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint64_t reg, val;

	reg = P10_OB_ODL_CONFIG(dev->op_unit, dev->odl_index);
	xscom_read(pau->chip_id, reg, &val);
	val &= ~P10_OB_ODL_CONFIG_RESET;
	xscom_write(pau->chip_id, reg, val);
}

static void pau_opencapi_training_mode(struct pau_dev *dev,
				       uint8_t pattern)
{
	struct pau *pau = dev->pau;
	uint64_t reg, val;

	reg = P10_OB_ODL_CONFIG(dev->op_unit, dev->odl_index);
	xscom_read(pau->chip_id, reg, &val);
	val = SETFIELD(P10_OB_ODL_CONFIG_TRAIN_MODE, val, pattern);
	xscom_write(pau->chip_id, reg, val);
}

static int64_t pau_opencapi_assert_adapter_reset(struct pau_dev *dev)
{
	int64_t rc = OPAL_PARAMETER;

	if (platform.ocapi->i2c_assert_reset)
		rc = platform.ocapi->i2c_assert_reset(dev->i2c_bus_id);

	if (rc)
		PAUDEVERR(dev, "Error writing I2C reset signal: %lld\n", rc);
	return rc;
}

static int64_t pau_opencapi_deassert_adapter_reset(struct pau_dev *dev)
{
	int64_t rc = OPAL_PARAMETER;

	if (platform.ocapi->i2c_deassert_reset)
		rc = platform.ocapi->i2c_deassert_reset(dev->i2c_bus_id);

	if (rc)
		PAUDEVERR(dev, "Error writing I2C reset signal: %lld\n", rc);
	return rc;
}

static void pau_opencapi_fence_brick(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;

	PAUDEVDBG(dev, "Fencing brick\n");
	pau_opencapi_set_fence_control(dev, 0b11);

	/* Place all bricks into Fence state */
	pau_write(pau, PAU_MISC_FENCE_STATE,
		  PAU_MISC_FENCE_STATE_SET(pau_dev_index(dev, PAU_LINKS_OPENCAPI_PER_PAU)));
}

static void pau_opencapi_unfence_brick(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;

	PAUDEVDBG(dev, "Unfencing brick\n");
	pau_write(pau, PAU_MISC_FENCE_STATE,
		  PAU_MISC_FENCE_STATE_CLEAR(pau_dev_index(dev, PAU_LINKS_OPENCAPI_PER_PAU)));

	pau_opencapi_set_fence_control(dev, 0b10);
	pau_opencapi_set_fence_control(dev, 0b00);
}

static int64_t pau_opencapi_freset(struct pci_slot *slot)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(slot->phb);
	uint8_t presence = 1;
	int64_t rc = OPAL_SUCCESS;

	switch (slot->state) {
	case PAU_SLOT_NORMAL:
	case PAU_SLOT_FRESET_START:
		PAUDEVDBG(dev, "FRESET: Starts\n");

		if (slot->ops.get_presence_state)
			slot->ops.get_presence_state(slot, &presence);
		if (!presence) {
			/*
			 * FIXME: if there's no card on the link, we
			 * should consider powering off the unused
			 * lanes to save energy
			 */
			PAUDEVINF(dev, "no card detected\n");
			return OPAL_SUCCESS;
		}
		slot->link_retries = PAU_LINK_TRAINING_RETRIES;
		/* fall-through */
	case PAU_SLOT_FRESET_INIT:
		pau_opencapi_fence_brick(dev);
		pau_opencapi_enable_bars(dev, false);
		pau_opencapi_assert_odl_reset(dev);
		pau_opencapi_assert_adapter_reset(dev);
		pci_slot_set_state(slot, PAU_SLOT_FRESET_ASSERT_DELAY);
		/* assert for 5ms */
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(5));

	case PAU_SLOT_FRESET_ASSERT_DELAY:
		rc = pau_dev_phy_reset(dev);
		if (rc) {
			PAUDEVERR(dev, "FRESET: PHY reset error\n");
			return OPAL_HARDWARE;
		}
		pau_opencapi_deassert_odl_reset(dev);
		pau_opencapi_deassert_adapter_reset(dev);
		pci_slot_set_state(slot, PAU_SLOT_FRESET_DEASSERT_DELAY);
		/* give 250ms to device to be ready */
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(250));

	case PAU_SLOT_FRESET_DEASSERT_DELAY:
		pau_opencapi_unfence_brick(dev);
		pau_opencapi_enable_bars(dev, true);
		pau_opencapi_training_mode(dev, 0b0001); /* send pattern A */
		pci_slot_set_state(slot, PAU_SLOT_FRESET_INIT_DELAY);
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(5));

	case PAU_SLOT_FRESET_INIT_DELAY:
		pau_opencapi_training_mode(dev, 0b1000); /* enable training */
		dev->train_start = mftb();
		dev->train_timeout = dev->train_start +
			msecs_to_tb(PAU_LINK_TRAINING_TIMEOUT);
		pci_slot_set_state(slot, PAU_SLOT_LINK_START);
		return slot->ops.poll_link(slot);

	default:
		PAUDEVERR(dev, "FRESET: unexpected slot state %08x\n",
			   slot->state);
	}
	pci_slot_set_state(slot, PAU_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static uint64_t pau_opencapi_get_odl_endpoint_info(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint64_t val;

	xscom_read(pau->chip_id,
		   P10_OB_ODL_DLX_INFO(dev->op_unit, dev->odl_index),
		   &val);
	return val;
}

static uint64_t pau_opencapi_get_odl_training_status(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint64_t val;

	xscom_read(pau->chip_id,
		   P10_OB_ODL_TRAIN_STAT(dev->op_unit, dev->odl_index),
		   &val);
	return val;
}

static uint64_t pau_opencapi_get_odl_status(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint64_t val;

	xscom_read(pau->chip_id,
		   P10_OB_ODL_STATUS(dev->op_unit, dev->odl_index),
		   &val);
	return val;
}

static uint64_t pau_opencapi_get_odl_link_speed_status(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint64_t val;

	xscom_read(pau->chip_id,
		   P10_OB_ODL_LINK_SPEED_STATUS(dev->op_unit, dev->odl_index),
		   &val);
	return val;
}

static enum OpalShpcLinkState pau_opencapi_get_link_width(uint64_t status)
{
	uint64_t tx_lanes, rx_lanes, state;

	state = GETFIELD(P10_OB_ODL_STATUS_TRAINING_STATE, status);
	if (state != PAU_LINK_STATE_TRAINED)
		return OPAL_SHPC_LINK_DOWN;

	rx_lanes = GETFIELD(P10_OB_ODL_STATUS_RX_TRAINED_LANES, status);
	tx_lanes = GETFIELD(P10_OB_ODL_STATUS_TX_TRAINED_LANES, status);
	if ((rx_lanes != 0xFF) || (tx_lanes != 0xFF))
		return OPAL_SHPC_LINK_UP_x4;
	else
		return OPAL_SHPC_LINK_UP_x8;
}

static int64_t pau_opencapi_get_link_state(struct pci_slot *slot,
					   uint8_t *val)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(slot->phb);
	uint64_t status;

	status = pau_opencapi_get_odl_status(dev);
	*val = pau_opencapi_get_link_width(status);

	return OPAL_SUCCESS;

}

static int64_t pau_opencapi_get_power_state(struct pci_slot *slot,
					    uint8_t *val)
{
	*val = slot->power_state;
	return OPAL_SUCCESS;
}

static int64_t pau_opencapi_get_presence_state(struct pci_slot __unused * slot,
					       uint8_t *val)
{
	/*
	 * Presence detection for OpenCAPI is currently done at the start of
	 * PAU initialisation, and we only create slots if a device is present.
	 * As such we will never be asked to get the presence of a slot that's
	 * empty.
	 *
	 * This may change if we ever support hotplug down the track.
	 */
	*val = OPAL_PCI_SLOT_PRESENT;
	return OPAL_SUCCESS;
}

static void pau_opencapi_check_trained_link(struct pau_dev *dev,
					    uint64_t status)
{
	if (pau_opencapi_get_link_width(status) != OPAL_SHPC_LINK_UP_x8) {
		PAUDEVERR(dev, "Link trained in degraded mode (%016llx)\n",
				status);
		PAUDEVDBG(dev, "Link endpoint info: %016llx\n",
				pau_opencapi_get_odl_endpoint_info(dev));
	}
}

static int64_t pau_opencapi_retry_state(struct pci_slot *slot,
					uint64_t status)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(slot->phb);

	if (!slot->link_retries--) {
		/**
		 * @fwts-label OCAPILinkTrainingFailed
		 * @fwts-advice The OpenCAPI link training procedure failed.
		 * This indicates a hardware or firmware bug. OpenCAPI
		 * functionality will not be available on this link.
		 */
		PAUDEVERR(dev,
			   "Link failed to train, final link status: %016llx\n",
			   status);
		PAUDEVDBG(dev, "Final link training status: %016llx (Link Speed Status: %016llx)\n",
			   pau_opencapi_get_odl_training_status(dev),
			   pau_opencapi_get_odl_link_speed_status(dev));
		return OPAL_HARDWARE;
	}

	PAUDEVERR(dev, "Link failed to train, retrying\n");
	PAUDEVERR(dev, "Link status: %016llx, training status: %016llx "
		       "(Link Speed Status: %016llx)\n",
		status,
		pau_opencapi_get_odl_training_status(dev),
		pau_opencapi_get_odl_link_speed_status(dev));

	pci_slot_set_state(slot, PAU_SLOT_FRESET_INIT);
	return pci_slot_set_sm_timeout(slot, msecs_to_tb(1));
}

static void pau_opencapi_otl_tx_send_enable(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint64_t reg, val;

	/* Allows OTL TX to send out packets to AFU */
	PAUDEVDBG(dev, "OTL TX Send Enable\n");

	reg = PAU_OTL_MISC_CFG_TX2(dev->index);
	val = pau_read(pau, reg);
	val |= PAU_OTL_MISC_CFG_TX2_SEND_EN;
	pau_write(pau, reg, val);
}

static void pau_opencapi_setup_perf_counters(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint64_t reg, val;

	PAUDEVDBG(dev, "Setup perf counter\n");

	reg = P10_OB_ODL_PERF_MON_CONFIG(dev->op_unit);
	xscom_read(pau->chip_id, reg, &val);
	val = SETFIELD(P10_OB_ODL_PERF_MON_CONFIG_ENABLE, val,
		       P10_OB_ODL_PERF_MON_CONFIG_LINK0 >> dev->index);
	val = SETFIELD(P10_OB_ODL_PERF_MON_CONFIG_SIZE, val,
		       P10_OB_ODL_PERF_MON_CONFIG_SIZE16);
	xscom_write(pau->chip_id, reg, val);
	PAUDEVDBG(dev, "perf counter config %llx = %llx\n", reg, val);

	reg = P10_OB_ODL_PERF_MON_SELECT(dev->op_unit);
	xscom_read(pau->chip_id, reg, &val);
	val = SETFIELD(P10_OB_ODL_PERF_MON_SELECT_COUNTER >> (dev->index * 16),
		val, P10_OB_ODL_PERF_MON_SELECT_CRC_ODL);
	val = SETFIELD(P10_OB_ODL_PERF_MON_SELECT_COUNTER >> ((dev->index * 16) + 8),
		val, P10_OB_ODL_PERF_MON_SELECT_CRC_DLX);
	xscom_write(pau->chip_id, reg, val);
	PAUDEVDBG(dev, "perf counter select %llx = %llx\n", reg, val);
}

static void pau_opencapi_check_perf_counters(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint64_t reg, val;

	reg = P10_OB_PERF_COUNTER0(dev->op_unit);
	xscom_read(pau->chip_id, reg, &val);

	if (val)
		PAUDEVERR(dev, "CRC error count perf_counter0..3=0%#llx\n",
			  val);
}

static int64_t pau_opencapi_poll_link(struct pci_slot *slot)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(slot->phb);
	uint64_t status;

	switch (slot->state) {
	case PAU_SLOT_NORMAL:
	case PAU_SLOT_LINK_START:
		PAUDEVDBG(dev, "Start polling\n");
		pci_slot_set_state(slot, PAU_SLOT_LINK_WAIT);
		/* fall-through */
	case PAU_SLOT_LINK_WAIT:
		status = pau_opencapi_get_odl_status(dev);
		if (GETFIELD(P10_OB_ODL_STATUS_TRAINING_STATE, status) ==
			PAU_LINK_STATE_TRAINED) {
			PAUDEVINF(dev, "link trained in %ld ms (Link Speed Status: %016llx)\n",
				   tb_to_msecs(mftb() - dev->train_start),
				   pau_opencapi_get_odl_link_speed_status(dev));
			pau_opencapi_check_trained_link(dev, status);

			pci_slot_set_state(slot, PAU_SLOT_LINK_TRAINED);
			return pci_slot_set_sm_timeout(slot, msecs_to_tb(1));
		}
		if (tb_compare(mftb(), dev->train_timeout) == TB_AAFTERB)
			return pau_opencapi_retry_state(slot, status);

		return pci_slot_set_sm_timeout(slot, msecs_to_tb(1));

	case PAU_SLOT_LINK_TRAINED:
		pau_opencapi_otl_tx_send_enable(dev);
		pci_slot_set_state(slot, PAU_SLOT_NORMAL);
		if (dev->status & PAU_DEV_STATUS_BROKEN) {
			PAUDEVERR(dev, "Resetting a device which hit a "
				       "previous error. Device recovery "
				       "is not supported, so future behavior is undefined\n");
			dev->status &= ~PAU_DEV_STATUS_BROKEN;
		}
		pau_opencapi_check_perf_counters(dev);
		dev->phb.scan_map = 1;
		return OPAL_SUCCESS;

	default:
		PAUDEVERR(dev, "unexpected slot state %08x\n", slot->state);

	}
	pci_slot_set_state(slot, PAU_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static void pau_opencapi_prepare_link_change(struct pci_slot *slot __unused,
					     bool up __unused)
{
	/*
	 * PCI hotplug wants it defined, but we don't need to do anything
	 */
}

static int64_t pau_opencapi_set_power_state(struct pci_slot *slot,
					    uint8_t val)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(slot->phb);

	switch (val) {
	case PCI_SLOT_POWER_OFF:
		PAUDEVDBG(dev, "Fake power off\n");
		pau_opencapi_fence_brick(dev);
		pau_opencapi_assert_adapter_reset(dev);
		slot->power_state = PCI_SLOT_POWER_OFF;
		return OPAL_SUCCESS;

	case PCI_SLOT_POWER_ON:
		if (slot->power_state != PCI_SLOT_POWER_OFF)
			return OPAL_SUCCESS;
		PAUDEVDBG(dev, "Fake power on\n");
		slot->power_state = PCI_SLOT_POWER_ON;
		slot->state = PAU_SLOT_NORMAL;
		return OPAL_SUCCESS;

	default:
		return OPAL_UNSUPPORTED;
	}
}

static void pau_opencapi_create_phb_slot(struct pau_dev *dev)
{
	struct pci_slot *slot;

	slot = pci_slot_alloc(&dev->phb, NULL);
	if (!slot) {
		/**
		 * @fwts-label OCAPICannotCreatePHBSlot
		 * @fwts-advice Firmware probably ran out of memory creating
		 * PAU slot. OpenCAPI functionality could be broken.
		 */
		PAUDEVERR(dev, "Cannot create PHB slot\n");
	}

	/* Elementary functions */
	slot->ops.creset                = pau_opencapi_creset;
	slot->ops.hreset                = pau_opencapi_hreset;
	slot->ops.freset                = pau_opencapi_freset;
	slot->ops.get_link_state        = pau_opencapi_get_link_state;
	slot->ops.get_power_state       = pau_opencapi_get_power_state;
	slot->ops.get_presence_state    = pau_opencapi_get_presence_state;
	slot->ops.poll_link             = pau_opencapi_poll_link;
	slot->ops.prepare_link_change   = pau_opencapi_prepare_link_change;
	slot->ops.set_power_state       = pau_opencapi_set_power_state;

	/* hotplug capability */
	slot->pluggable = 1;

}

static int64_t pau_opencapi_pcicfg_check(struct pau_dev *dev,
					 uint32_t offset,
					 uint32_t size)
{
	if (!dev || offset > 0xfff || (offset & (size - 1)))
		return OPAL_PARAMETER;

	return OPAL_SUCCESS;
}

static int64_t pau_opencapi_pcicfg_read(struct phb *phb, uint32_t bdfn,
					uint32_t offset, uint32_t size,
					void *data)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(phb);
	uint64_t cfg_addr, genid_base;
	int64_t rc;

	rc = pau_opencapi_pcicfg_check(dev, offset, size);
	if (rc)
		return rc;

	/* Config Address for Brick 0 – Offset 0
	 * Config Address for Brick 1 – Offset 256
	 */
	genid_base = dev->genid_bar.cfg + (dev->index << 8);

	cfg_addr = PAU_CTL_MISC_CFG_ADDR_ENABLE;
	cfg_addr = SETFIELD(PAU_CTL_MISC_CFG_ADDR_BUS_NBR |
			    PAU_CTL_MISC_CFG_ADDR_DEVICE_NBR |
			    PAU_CTL_MISC_CFG_ADDR_FUNCTION_NBR,
			    cfg_addr, bdfn);
	cfg_addr = SETFIELD(PAU_CTL_MISC_CFG_ADDR_REGISTER_NBR,
			    cfg_addr, offset & ~3u);

	out_be64((uint64_t *)genid_base, cfg_addr);
	sync();

	switch (size) {
	case 1:
		*((uint8_t *)data) =
			in_8((uint8_t *)(genid_base + 128 + (offset & 3)));
		break;
	case 2:
		*((uint16_t *)data) =
			in_le16((uint16_t *)(genid_base + 128 + (offset & 2)));
		break;
	case 4:
		*((uint32_t *)data) = in_le32((uint32_t *)(genid_base + 128));
		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

#define PAU_OPENCAPI_PCI_CFG_READ(size, type)					\
static int64_t pau_opencapi_pcicfg_read##size(struct phb *phb, uint32_t bdfn,	\
					      uint32_t offset, type * data)	\
{										\
	/* Initialize data in case of error */					\
	*data = (type)0xffffffff;						\
	return pau_opencapi_pcicfg_read(phb, bdfn, offset, sizeof(type), data);	\
}

static int64_t pau_opencapi_pcicfg_write(struct phb *phb, uint32_t bdfn,
					 uint32_t offset, uint32_t size,
					 uint32_t data)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(phb);
	uint64_t genid_base, cfg_addr;
	int64_t rc;

	rc = pau_opencapi_pcicfg_check(dev, offset, size);
	if (rc)
		return rc;

	/* Config Address for Brick 0 – Offset 0
	 * Config Address for Brick 1 – Offset 256
	 */
	genid_base = dev->genid_bar.cfg + (dev->index << 8);

	cfg_addr = PAU_CTL_MISC_CFG_ADDR_ENABLE;
	cfg_addr = SETFIELD(PAU_CTL_MISC_CFG_ADDR_BUS_NBR |
			    PAU_CTL_MISC_CFG_ADDR_DEVICE_NBR |
			    PAU_CTL_MISC_CFG_ADDR_FUNCTION_NBR,
			    cfg_addr, bdfn);
	cfg_addr = SETFIELD(PAU_CTL_MISC_CFG_ADDR_REGISTER_NBR,
			    cfg_addr, offset & ~3u);

	out_be64((uint64_t *)genid_base, cfg_addr);
	sync();

	switch (size) {
	case 1:
		out_8((uint8_t *)(genid_base + 128 + (offset & 3)), data);
		break;
	case 2:
		out_le16((uint16_t *)(genid_base + 128 + (offset & 2)), data);
		break;
	case 4:
		out_le32((uint32_t *)(genid_base + 128), data);
		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

#define PAU_OPENCAPI_PCI_CFG_WRITE(size, type)					\
static int64_t pau_opencapi_pcicfg_write##size(struct phb *phb, uint32_t bdfn,	\
						uint32_t offset, type data)	\
{										\
	return pau_opencapi_pcicfg_write(phb, bdfn, offset, sizeof(type), data);\
}

PAU_OPENCAPI_PCI_CFG_READ(8, u8)
PAU_OPENCAPI_PCI_CFG_READ(16, u16)
PAU_OPENCAPI_PCI_CFG_READ(32, u32)
PAU_OPENCAPI_PCI_CFG_WRITE(8, u8)
PAU_OPENCAPI_PCI_CFG_WRITE(16, u16)
PAU_OPENCAPI_PCI_CFG_WRITE(32, u32)

static int64_t pau_opencapi_eeh_freeze_status(struct phb *phb __unused,
					      uint64_t pe_num __unused,
					      uint8_t *freeze_state,
					      uint16_t *pci_error_type,
					      uint16_t *severity)
{
	*freeze_state = OPAL_EEH_STOPPED_NOT_FROZEN;
	*pci_error_type = OPAL_EEH_NO_ERROR;

	if (severity)
		*severity = OPAL_EEH_SEV_NO_ERROR;

	return OPAL_SUCCESS;
}

static int64_t pau_opencapi_ioda_reset(struct phb __unused * phb,
				       bool __unused purge)
{
	/* Not relevant to OpenCAPI - we do this just to silence the error */
	return OPAL_SUCCESS;
}

static int64_t pau_opencapi_next_error(struct phb *phb,
				       uint64_t *first_frozen_pe,
				       uint16_t *pci_error_type,
				       uint16_t *severity)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(phb);
	struct pau *pau = dev->pau;
	uint32_t pe_num;
	uint64_t val;

	if (!first_frozen_pe || !pci_error_type || !severity)
		return OPAL_PARAMETER;

	if (dev->status & PAU_DEV_STATUS_BROKEN) {
		val = pau_read(pau, PAU_MISC_BDF2PE_CFG(dev->index));
		pe_num = GETFIELD(PAU_MISC_BDF2PE_CFG_PE, val);

		PAUDEVDBG(dev, "Reporting device as broken\n");
		PAUDEVDBG(dev, "Brick %d fenced! (pe_num: %08x\n",
				pau_dev_index(dev, PAU_LINKS_OPENCAPI_PER_PAU),
				pe_num);
		*first_frozen_pe = pe_num;
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_DEAD;
	} else {
		*first_frozen_pe = -1;
		*pci_error_type = OPAL_EEH_NO_ERROR;
		*severity = OPAL_EEH_SEV_NO_ERROR;
	}
	return OPAL_SUCCESS;
}

static uint32_t pau_opencapi_dev_interrupt_level(struct pau_dev *dev)
{
	/* Interrupt Levels
	 * 35: Translation failure for OCAPI link 0
	 * 36: Translation failure for OCAPI link 1
	 */
	const uint32_t level[2] = {35, 36};

	return level[dev->index];
}

static int pau_opencapi_dt_add_interrupts(struct phb *phb,
					  struct pci_device *pd,
					  void *data __unused)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(phb);
	struct pau *pau = dev->pau;
	uint64_t dsisr, dar, tfc, handle;
	uint32_t irq;

	irq = pau->irq_base + pau_opencapi_dev_interrupt_level(dev);

	/* When an address translation fail causes the PAU to send an
	 * interrupt, information is stored in three registers for use
	 * by the interrupt handler. The OS accesses them by mmio.
	 */
	dsisr  = pau->regs[0] + PAU_OTL_MISC_PSL_DSISR_AN(dev->index);
	dar    = pau->regs[0] + PAU_OTL_MISC_PSL_DAR_AN(dev->index);
	tfc    = pau->regs[0] + PAU_OTL_MISC_PSL_TFC_AN(dev->index);
	handle = pau->regs[0] + PAU_OTL_MISC_PSL_PEHANDLE_AN(dev->index);
	dt_add_property_cells(pd->dn, "ibm,opal-xsl-irq", irq);
	dt_add_property_cells(pd->dn, "ibm,opal-xsl-mmio",
			hi32(dsisr), lo32(dsisr),
			hi32(dar), lo32(dar),
			hi32(tfc), lo32(tfc),
			hi32(handle), lo32(handle));
	return 0;
}

static void pau_opencapi_phb_final_fixup(struct phb *phb)
{
	pci_walk_dev(phb, NULL, pau_opencapi_dt_add_interrupts, NULL);
}

static int64_t pau_opencapi_set_pe(struct phb *phb,
				   uint64_t pe_num,
				   uint64_t bdfn,
				   uint8_t bcompare,
				   uint8_t dcompare,
				   uint8_t fcompare,
				   uint8_t action)
{
	struct pau_dev *dev = pau_phb_to_opencapi_dev(phb);
	struct pau *pau = dev->pau;
	uint64_t val;

	PAUDEVDBG(dev, "Set partitionable endpoint = %08llx, bdfn =  %08llx\n",
			pe_num, bdfn);

	if (action != OPAL_MAP_PE && action != OPAL_UNMAP_PE)
		return OPAL_PARAMETER;

	if (pe_num >= PAU_MAX_PE_NUM)
		return OPAL_PARAMETER;

	if (bcompare != OpalPciBusAll ||
	    dcompare != OPAL_COMPARE_RID_DEVICE_NUMBER ||
	    fcompare != OPAL_COMPARE_RID_FUNCTION_NUMBER)
		return OPAL_UNSUPPORTED;

	val = PAU_MISC_BDF2PE_CFG_ENABLE;
	val = SETFIELD(PAU_MISC_BDF2PE_CFG_PE, val, pe_num);
	val = SETFIELD(PAU_MISC_BDF2PE_CFG_BDF, val, 0);
	pau_write(pau, PAU_MISC_BDF2PE_CFG(dev->index), val);

	return OPAL_SUCCESS;
}

static const struct phb_ops pau_opencapi_ops = {
	.cfg_read8		= pau_opencapi_pcicfg_read8,
	.cfg_read16		= pau_opencapi_pcicfg_read16,
	.cfg_read32		= pau_opencapi_pcicfg_read32,
	.cfg_write8		= pau_opencapi_pcicfg_write8,
	.cfg_write16		= pau_opencapi_pcicfg_write16,
	.cfg_write32		= pau_opencapi_pcicfg_write32,
	.eeh_freeze_status	= pau_opencapi_eeh_freeze_status,
	.next_error		= pau_opencapi_next_error,
	.ioda_reset		= pau_opencapi_ioda_reset,
	.phb_final_fixup	= pau_opencapi_phb_final_fixup,
	.set_pe			= pau_opencapi_set_pe,
};

static void pau_opencapi_create_phb(struct pau_dev *dev)
{
	struct phb *phb = &dev->phb;
	uint64_t mm_win[2];

	mm_win[0] = dev->ntl_bar.addr;
	mm_win[1] = dev->ntl_bar.size;

	phb->phb_type = phb_type_pau_opencapi;
	phb->scan_map = 0;

	phb->ops = &pau_opencapi_ops;
	phb->dt_node = dt_new_addr(dt_root, "pciex", mm_win[0]);
	assert(phb->dt_node);

	pci_register_phb(phb, pau_get_opal_id(dev->pau->chip_id,
					      pau_get_phb_index(dev->pau->index, dev->index)));
	pau_opencapi_create_phb_slot(dev);
}

static void pau_dt_add_mmio_atsd(struct pau_dev *dev)
{
	struct dt_node *dn = dev->phb.dt_node;
	struct pau *pau = dev->pau;
	uint64_t mmio_atsd[PAU_XTS_ATSD_MAX];

	for (uint32_t i = 0; i < PAU_XTS_ATSD_MAX; i++)
		mmio_atsd[i] = pau->regs[0] + PAU_XTS_ATSD_LAUNCH(i);

	dt_add_property(dn, "ibm,mmio-atsd", mmio_atsd, sizeof(mmio_atsd));
}

static void pau_opencapi_dt_add_mmio_window(struct pau_dev *dev)
{
	struct dt_node *dn = dev->phb.dt_node;
	uint64_t mm_win[2];

	mm_win[0] = dev->ntl_bar.addr;
	mm_win[1] = dev->ntl_bar.size;
	PAUDEVDBG(dev, "Setting AFU MMIO window to %016llx  %016llx\n",
			mm_win[0], mm_win[1]);

	dt_add_property(dn, "reg", mm_win, sizeof(mm_win));
	dt_add_property(dn, "ibm,mmio-window", mm_win, sizeof(mm_win));
	dt_add_property_cells(dn, "ranges", 0x02000000,
			      hi32(mm_win[0]), lo32(mm_win[0]),
			      hi32(mm_win[0]), lo32(mm_win[0]),
			      hi32(mm_win[1]), lo32(mm_win[1]));
}

static void pau_opencapi_dt_add_hotpluggable(struct pau_dev *dev)
{
	struct pci_slot *slot = dev->phb.slot;
	struct dt_node *dn = dev->phb.dt_node;
	char label[40];

	/*
	 * Add a few definitions to the DT so that the linux PCI
	 * hotplug framework can find the slot and identify it as
	 * hot-pluggable.
	 *
	 * The "ibm,slot-label" property is used by linux as the slot name
	 */
	pci_slot_add_dt_properties(slot, dn);

	snprintf(label, sizeof(label), "OPENCAPI-%04x",
		 (int)PCI_SLOT_PHB_INDEX(slot->id));
	dt_add_property_string(dn, "ibm,slot-label", label);
}

static void pau_opencapi_dt_add_props(struct pau_dev *dev)
{
	struct dt_node *dn = dev->phb.dt_node;
	struct pau *pau = dev->pau;

	dt_add_property_strings(dn,
				"compatible",
				"ibm,power10-pau-opencapi-pciex",
				"ibm,ioda3-pau-opencapi-phb",
				"ibm,ioda2-npu2-opencapi-phb");

	dt_add_property_cells(dn, "#address-cells", 3);
	dt_add_property_cells(dn, "#size-cells", 2);
	dt_add_property_cells(dn, "#interrupt-cells", 1);
	dt_add_property_cells(dn, "bus-range", 0, 0xff);
	dt_add_property_cells(dn, "clock-frequency", 0x200, 0);
	dt_add_property_cells(dn, "interrupt-parent", get_ics_phandle());

	dt_add_property_strings(dn, "device_type", "pciex");
	dt_add_property_cells(dn, "ibm,pau-index", pau->index);
	dt_add_property_cells(dn, "ibm,chip-id", pau->chip_id);
	dt_add_property_cells(dn, "ibm,xscom-base", pau->xscom_base);
	dt_add_property_cells(dn, "ibm,npcq", pau->dt_node->phandle);
	dt_add_property_cells(dn, "ibm,links", 1);
	dt_add_property_cells(dn, "ibm,phb-diag-data-size", 0);
	dt_add_property_cells(dn, "ibm,opal-num-pes", PAU_MAX_PE_NUM);
	dt_add_property_cells(dn, "ibm,opal-reserved-pe", PAU_RESERVED_PE_NUM);

	pau_dt_add_mmio_atsd(dev);
	pau_opencapi_dt_add_mmio_window(dev);
	pau_opencapi_dt_add_hotpluggable(dev);
}

static void pau_opencapi_set_transport_mux_controls(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint32_t typemap = 0;
	uint64_t reg, val = 0;

	PAUDEVDBG(dev, "Setting transport mux controls\n");
	typemap = 0x2 >> dev->index;

	reg = PAU_MISC_OPTICAL_IO_CONFIG;
	val = pau_read(pau, reg);
	typemap |= GETFIELD(PAU_MISC_OPTICAL_IO_CONFIG_OTL, val);
	val = SETFIELD(PAU_MISC_OPTICAL_IO_CONFIG_OTL, val, typemap);
	pau_write(pau, reg, val);
}

static void pau_opencapi_odl_config_phy(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint8_t typemap = 0;
	uint64_t reg, val;

	PAUDEVDBG(dev, "Configure ODL\n");

	/* ODL must be in reset when enabling.
	 * It stays in reset until the link is trained
	 */
	pau_opencapi_assert_odl_reset(dev);

	/* DLO (Open CAPI links) */
	typemap = 0x2 >> dev->odl_index;

	reg = P10_OB_ODL_PHY_CONFIG(dev->op_unit);
	xscom_read(pau->chip_id, reg, &val);
	typemap |= GETFIELD(P10_OB_ODL_PHY_CONFIG_LINK_SELECT, val);
	val = SETFIELD(P10_OB_ODL_PHY_CONFIG_LINK_SELECT, val, typemap);
	val = SETFIELD(P10_OB_ODL_PHY_CONFIG_DL_SELECT, val, 0b10);
	xscom_write(pau->chip_id, reg, val);
}

static void pau_opencapi_enable_xsl_clocks(struct pau *pau)
{
	uint64_t reg, val;

	PAUDBG(pau, "Enable clocks in XSL\n");

	reg = PAU_XSL_WRAP_CFG;
	val = pau_read(pau, reg);
	val |= PAU_XSL_WRAP_CFG_CLOCK_ENABLE;
	pau_write(pau, reg, val);
}

static void pau_opencapi_enable_misc_clocks(struct pau *pau)
{
	uint64_t reg, val;

	PAUDBG(pau, "Enable clocks in MISC\n");

	/* clear any spurious NDL stall or no_stall_c_err_rpts */
	reg = PAU_MISC_HOLD;
	val = pau_read(pau, reg);
	val = SETFIELD(PAU_MISC_HOLD_NDL_STALL, val, 0b0000);
	pau_write(pau, reg, val);

	reg = PAU_MISC_CONFIG;
	val = pau_read(pau, reg);
	val |= PAU_MISC_CONFIG_OC_MODE;
	pau_write(pau, reg, val);
}

static void pau_opencapi_set_npcq_config(struct pau *pau)
{
	struct pau_dev *dev;
	uint8_t oc_typemap = 0;
	uint64_t reg, val;

	/* MCP_MISC_CFG0
	 * SNP_MISC_CFG0 done in pau_opencapi_enable_pb
	 */
	pau_for_each_opencapi_dev(dev, pau)
		oc_typemap |= 0x10 >> dev->index;

	PAUDBG(pau, "Set NPCQ Config\n");
	reg = PAU_CTL_MISC_CFG2;
	val = pau_read(pau, reg);
	val = SETFIELD(PAU_CTL_MISC_CFG2_OCAPI_MODE, val, oc_typemap);
	val = SETFIELD(PAU_CTL_MISC_CFG2_OCAPI_4, val, oc_typemap);
	val = SETFIELD(PAU_CTL_MISC_CFG2_OCAPI_C2, val, oc_typemap);
	val = SETFIELD(PAU_CTL_MISC_CFG2_OCAPI_AMO, val, oc_typemap);
	val = SETFIELD(PAU_CTL_MISC_CFG2_OCAPI_MEM_OS_BIT, val, oc_typemap);
	pau_write(pau, reg, val);

	reg = PAU_DAT_MISC_CFG1;
	val = pau_read(pau, reg);
	val = SETFIELD(PAU_DAT_MISC_CFG1_OCAPI_MODE, val, oc_typemap);
	pau_write(pau, reg, val);
}

static void pau_opencapi_enable_xsl_xts_interfaces(struct pau *pau)
{
	uint64_t reg, val;

	PAUDBG(pau, "Enable XSL-XTS Interfaces\n");
	reg = PAU_XTS_CFG;
	val = pau_read(pau, reg);
	val |= PAU_XTS_CFG_OPENCAPI;
	pau_write(pau, reg, val);

	reg = PAU_XTS_CFG2;
	val = pau_read(pau, reg);
	val |= PAU_XTS_CFG2_XSL2_ENA;
	pau_write(pau, reg, val);
}

static void pau_opencapi_enable_sm_allocation(struct pau *pau)
{
	uint64_t reg, val;

	PAUDBG(pau, "Enable State Machine Allocation\n");

	reg = PAU_MISC_MACHINE_ALLOC;
	val = pau_read(pau, reg);
	val |= PAU_MISC_MACHINE_ALLOC_ENABLE;
	pau_write(pau, reg, val);
}

static void pau_opencapi_enable_powerbus(struct pau *pau)
{
	struct pau_dev *dev;
	uint8_t oc_typemap = 0;
	uint64_t reg, val;

	PAUDBG(pau, "Enable PowerBus\n");

	pau_for_each_opencapi_dev(dev, pau)
		oc_typemap |= 0x10 >> dev->index;

	/* PowerBus interfaces must be enabled prior to MMIO */
	reg = PAU_MCP_MISC_CFG0;
	val = pau_read(pau, reg);
	val |= PAU_MCP_MISC_CFG0_ENABLE_PBUS;
	val |= PAU_MCP_MISC_CFG0_MA_MCRESP_OPT_WRP;
	val = SETFIELD(PAU_MCP_MISC_CFG0_OCAPI_MODE, val, oc_typemap);
	pau_write(pau, reg, val);

	reg = PAU_SNP_MISC_CFG0;
	val = pau_read(pau, reg);
	val |= PAU_SNP_MISC_CFG0_ENABLE_PBUS;
	val = SETFIELD(PAU_SNP_MISC_CFG0_OCAPI_MODE, val, oc_typemap);
	val = SETFIELD(PAU_SNP_MISC_CFG0_OCAPI_C2, val, oc_typemap);
	pau_write(pau, reg, val);
}

static void pau_opencapi_tl_config(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint64_t val;

	PAUDEVDBG(dev, "TL Configuration\n");

	/* OTL Config 0 */
	val = 0;
	val |= PAU_OTL_MISC_CFG0_EN;
	val |= PAU_OTL_MISC_CFG0_BLOCK_PE_HANDLE;
	val = SETFIELD(PAU_OTL_MISC_CFG0_BRICKID, val, dev->index);
	val |= PAU_OTL_MISC_CFG0_ENABLE_4_0;
	val |= PAU_OTL_MISC_CFG0_XLATE_RELEASE;
	val |= PAU_OTL_MISC_CFG0_ENABLE_5_0;
	pau_write(pau, PAU_OTL_MISC_CFG0(dev->index), val);

	/* OTL Config 1 */
	val = 0;
	val = SETFIELD(PAU_OTL_MISC_CFG_TX_DRDY_WAIT, val, 0b010);
	val = SETFIELD(PAU_OTL_MISC_CFG_TX_TEMP0_RATE, val, 0b0000);
	val = SETFIELD(PAU_OTL_MISC_CFG_TX_TEMP1_RATE, val, 0b0011);
	val = SETFIELD(PAU_OTL_MISC_CFG_TX_TEMP2_RATE, val, 0b0111);
	val = SETFIELD(PAU_OTL_MISC_CFG_TX_TEMP3_RATE, val, 0b0010);
	val = SETFIELD(PAU_OTL_MISC_CFG_TX_CRET_FREQ, val, 0b001);
	pau_write(pau, PAU_OTL_MISC_CFG_TX(dev->index), val);

	/* OTL Config 2 - Done after link training, in otl_tx_send_enable() */

	/* TLX Credit Configuration */
	val = 0;
	val = SETFIELD(PAU_OTL_MISC_CFG_TLX_CREDITS_VC0, val, 0x40);
	val = SETFIELD(PAU_OTL_MISC_CFG_TLX_CREDITS_VC1, val, 0x40);
	val = SETFIELD(PAU_OTL_MISC_CFG_TLX_CREDITS_VC2, val, 0x40);
	val = SETFIELD(PAU_OTL_MISC_CFG_TLX_CREDITS_VC3, val, 0x40);
	val = SETFIELD(PAU_OTL_MISC_CFG_TLX_CREDITS_DCP0, val, 0x80);
	val = SETFIELD(PAU_OTL_MISC_CFG_TLX_CREDITS_SPARE, val, 0x80);
	val = SETFIELD(PAU_OTL_MISC_CFG_TLX_CREDITS_DCP2, val, 0x80);
	val = SETFIELD(PAU_OTL_MISC_CFG_TLX_CREDITS_DCP3, val, 0x80);
	pau_write(pau, PAU_OTL_MISC_CFG_TLX_CREDITS(dev->index), val);
}

static void pau_opencapi_enable_otlcq_interface(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint8_t typemap = 0;
	uint64_t reg, val;

	PAUDEVDBG(dev, "Enabling OTL-CQ Interface\n");

	typemap |= 0x10 >> dev->index;
	reg = PAU_CTL_MISC_CFG0;
	val = pau_read(pau, reg);
	typemap |= GETFIELD(PAU_CTL_MISC_CFG0_OTL_ENABLE, val);
	val = SETFIELD(PAU_CTL_MISC_CFG0_OTL_ENABLE, val, typemap);
	pau_write(pau, reg, val);
}

static void pau_opencapi_address_translation_config(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint64_t reg, val;

	PAUDEVDBG(dev, "Address Translation Configuration\n");

	/* OpenCAPI 4.0 Mode */
	reg = PAU_XSL_OSL_XLATE_CFG(dev->index);
	val = pau_read(pau, reg);
	val |= PAU_XSL_OSL_XLATE_CFG_AFU_DIAL;
	val &= ~PAU_XSL_OSL_XLATE_CFG_OPENCAPI3;
	pau_write(pau, reg, val);

	/* MMIO shootdowns (OpenCAPI 5.0) */
	reg = PAU_XTS_CFG3;
	val = pau_read(pau, reg);
	val |= PAU_XTS_CFG3_MMIOSD_OCAPI;
	pau_write(pau, reg, val);

	/* XSL_GP  - use defaults */
}

static void pau_opencapi_enable_interrupt_on_error(struct pau_dev *dev)
{
	struct pau *pau = dev->pau;
	uint64_t reg, val;

	PAUDEVDBG(dev, "Enable Interrupt-on-error\n");

	/* translation fault */
	reg = PAU_MISC_INT_2_CONFIG;
	val = pau_read(pau, reg);
	val |= PAU_MISC_INT_2_CONFIG_XFAULT_2_5(dev->index);
	pau_write(pau, reg, val);

	/* freeze disable */
	reg = PAU_MISC_FREEZE_1_CONFIG;
	val = pau_read(pau, reg);
	val &= ~PAU_FIR1_NDL_BRICKS_0_5;
	val &= ~PAU_FIR1_NDL_BRICKS_6_11;
	pau_write(pau, reg, val);

	/* fence disable */
	reg = PAU_MISC_FENCE_1_CONFIG;
	val = pau_read(pau, reg);
	val &= ~PAU_FIR1_NDL_BRICKS_0_5;
	val &= ~PAU_FIR1_NDL_BRICKS_6_11;
	pau_write(pau, reg, val);

	/* irq disable */
	reg = PAU_MISC_INT_1_CONFIG;
	val = pau_read(pau, reg);
	val &= ~PAU_FIR1_NDL_BRICKS_0_5;
	val &= ~PAU_FIR1_NDL_BRICKS_6_11;
	pau_write(pau, reg, val);
}

static void pau_opencapi_enable_ref_clock(struct pau_dev *dev)
{
	uint64_t reg, val;
	int bit;

	switch (dev->pau_unit) {
	case 0:
		if (dev->index == 0)
			bit = 16;
		else
			bit = 17;
		break;
	case 3:
		if (dev->index == 0)
			bit = 18;
		else
			bit = 19;
		break;
	case 4:
		bit = 20;
		break;
	case 5:
		bit = 21;
		break;
	case 6:
		bit = 22;
		break;
	case 7:
		bit = 23;
		break;
	default:
		assert(false);
	}

	reg = P10_ROOT_CONTROL_7;
	xscom_read(dev->pau->chip_id, reg, &val);
	val |= PPC_BIT(bit);
	PAUDEVDBG(dev, "Enabling ref clock for PAU%d => %llx\n",
		  dev->pau_unit, val);
	xscom_write(dev->pau->chip_id, reg, val);
}

static void pau_opencapi_init_hw(struct pau *pau)
{
	struct pau_dev *dev = NULL;

	pau_opencapi_mask_firs(pau);
	pau_opencapi_assign_bars(pau);
	pau_opencapi_setup_irqs(pau);

	/* Create phb */
	pau_for_each_opencapi_dev(dev, pau) {
		PAUDEVINF(dev, "Create phb\n");
		pau_opencapi_create_phb(dev);
		pau_opencapi_enable_bars(dev, true);
		pau_opencapi_dt_add_props(dev);
	}

	/* Procedure 17.1.3.1 - Enabling OpenCAPI */
	pau_for_each_opencapi_dev(dev, pau) {
		PAUDEVINF(dev, "Configuring link ...\n");
		pau_opencapi_set_transport_mux_controls(dev);	/* step 1 */
		pau_opencapi_odl_config_phy(dev);
	}
	pau_opencapi_enable_xsl_clocks(pau);		/* step 2 */
	pau_opencapi_enable_misc_clocks(pau);		/* step 3 */

	/* OTL disabled */
	pau_for_each_opencapi_dev(dev, pau)
		pau_opencapi_set_fence_control(dev, 0b01);

	pau_opencapi_set_npcq_config(pau);		/* step 4 */
	pau_opencapi_enable_xsl_xts_interfaces(pau);	/* step 5 */
	pau_opencapi_enable_sm_allocation(pau);		/* step 6 */
	pau_opencapi_enable_powerbus(pau);		/* step 7 */

	/*
	 * access to the PAU registers through mmio requires setting
	 * up the PAU mmio BAR (in pau_opencapi_assign_bars() above)
	 * and machine state allocation
	 */
	pau->mmio_access = true;

	pau_for_each_opencapi_dev(dev, pau) {
		/* Procedure 17.1.3.4 - Transaction Layer Configuration
		 * OCAPI Link Transaction Layer functions
		 */
		pau_opencapi_tl_config(dev);

		/* Procedure 17.1.3.4.1 - Enabling OTL-CQ Interface */
		pau_opencapi_enable_otlcq_interface(dev);

		/* Procedure 17.1.3.4.2 - Place OTL into Reset State
		 * Reset (Fence) both OTL and the PowerBus for this
		 * Brick
		 */
		pau_opencapi_set_fence_control(dev, 0b11);

		/* Take PAU out of OTL Reset State
		 * Reset (Fence) only the PowerBus for this Brick, OTL
		 * will be operational
		 */
		pau_opencapi_set_fence_control(dev, 0b10);

		/* Procedure 17.1.3.5 - Address Translation Configuration */
		pau_opencapi_address_translation_config(dev);

		/* Procedure 17.1.3.6 - AFU Memory Range BARs */
		/* Will be done out of this process */

		/* Procedure 17.1.3.8 - AFU MMIO Range BARs */
		/* done in pau_opencapi_assign_bars() */

		/* Procedure 17.1.3.9 - AFU Config BARs */
		/* done in pau_opencapi_assign_bars() */

		/* Precedure 17.1.3.10 - Relaxed Ordering Configuration */
		/* Procedure 17.1.3.10.1 - Generation-Id Registers MMIO Bars */
		/* done in pau_opencapi_assign_bars() */

		/* Procedure 17.1.3.10.2 - Relaxed Ordering Source Configuration */
		/* For an OpenCAPI AFU that uses M2 Memory Mode,
		 * Relaxed Ordering can be used for accesses to the
		 * AFU's memory
		 */

		/* Procedure 17.1.3.11 - Interrupt Configuration */
		/* done in pau_opencapi_setup_irqs() */
		pau_opencapi_enable_interrupt_on_error(dev);

		/* enable performance monitor */
		pau_opencapi_setup_perf_counters(dev);

		/* Reset disabled. Place OTLs into Run State */
		pau_opencapi_set_fence_control(dev, 0b00);

		/* Enable reference clock */
		pau_opencapi_enable_ref_clock(dev);
	}
}

static void pau_opencapi_init(struct pau *pau)
{
	if (!pau_next_dev(pau, NULL, PAU_DEV_TYPE_OPENCAPI))
		return;

	assert(platform.ocapi);

	pau_opencapi_init_hw(pau);

	disable_fast_reboot("OpenCAPI device enabled");
}

static void pau_init(struct pau *pau)
{
	struct pau_dev *dev;

	platform.pau_device_detect(pau);
	pau_for_each_dev(dev, pau)
		pau_device_detect_fixup(dev);

	pau_opencapi_init(pau);
}

void probe_pau(void)
{
	struct dt_node *dn;
	struct pau *pau;

	/* This can be removed when/if we decide to use HDAT instead */
	if (!pau_dt_create())
		return;

	if (!platform.pau_device_detect) {
		prlog(PR_INFO, "PAU: Platform does not support PAU\n");
		return;
	}

	dt_for_each_compatible(dt_root, dn, "ibm,power10-pau") {
		pau = pau_create(dn);
		pau_init(pau);
	}
}
