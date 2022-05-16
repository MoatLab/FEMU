// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Copyright 2019 IBM Corp.
 */

#include <io.h>
#include <xscom.h>
#include <npu3.h>
#include <npu3-regs.h>
#include <nvram.h>
#include <interrupts.h>
#include <xive.h>

#define NPU3LOG(l, npu, fmt, a...) \
	prlog(l, "NPU[%d:%d]: " fmt, (npu)->chip_id, (npu)->index, ##a)
#define NPU3DBG(npu, fmt, a...) NPU3LOG(PR_DEBUG, npu, fmt, ##a)
#define NPU3INF(npu, fmt, a...) NPU3LOG(PR_INFO, npu, fmt, ##a)
#define NPU3ERR(npu, fmt, a...) NPU3LOG(PR_ERR, npu, fmt, ##a)

#define NPU3DEVLOG(l, dev, fmt, a...)		\
	prlog(l, "NPU[%d:%d:%d]: " fmt,		\
	      (dev)->npu->chip_id,		\
	      (dev)->npu->index,		\
	      (dev)->index, ##a)
#define NPU3DEVDBG(dev, fmt, a...) NPU3DEVLOG(PR_DEBUG, dev, fmt, ##a)
#define NPU3DEVINF(dev, fmt, a...) NPU3DEVLOG(PR_INFO, dev, fmt, ##a)
#define NPU3DEVERR(dev, fmt, a...) NPU3DEVLOG(PR_ERR, dev, fmt, ##a)

static void npu3_dt_create_link(struct dt_node *npu, uint32_t npu_index,
				uint32_t dev_index)
{
	struct dt_node *link;
	uint32_t phy_lane_mask, ob_chiplet;

	link = dt_new_addr(npu, "link", dev_index);

	dt_add_property_string(link, "compatible", "ibm,npu-link");
	dt_add_property_cells(link, "reg", dev_index);
	dt_add_property_cells(link, "ibm,npu-link-index", dev_index);

	switch (npu_index) {
	case 0:
		/* fall through */
	case 2:
		ob_chiplet = npu_index ? 3 : 0;

		switch (dev_index) {
		case 0:
			phy_lane_mask = PPC_BITMASK32(0, 3);
			break;
		case 1:
			phy_lane_mask = PPC_BITMASK32(13, 16);
			break;
		case 2:
			phy_lane_mask = PPC_BITMASK32(7, 10);
			break;
		case 3:
			phy_lane_mask = PPC_BITMASK32(20, 23);
			break;
		}

		break;
	case 1:
		switch (dev_index) {
		case 0:
			ob_chiplet = 1;
			phy_lane_mask = PPC_BITMASK32(0, 3);
			break;
		case 1:
			ob_chiplet = 2;
			phy_lane_mask = PPC_BITMASK32(0, 3);
			break;
		case 2:
			ob_chiplet = 1;
			phy_lane_mask = PPC_BITMASK32(7, 10);
			break;
		case 3:
			ob_chiplet = 2;
			phy_lane_mask = PPC_BITMASK32(7, 10);
			break;
		}

		break;
	default:
		return;
	}

	dt_add_property_cells(link, "ibm,npu-phy", ob_chiplet);
	dt_add_property_cells(link, "ibm,npu-lane-mask", phy_lane_mask);
}

static void npu3_dt_create_npu(struct dt_node *xscom, uint32_t npu_index)
{
	const uint32_t npu_base[] = { 0x5011000, 0x5011400, 0x3011c00 };
	struct dt_node *npu;

	npu = dt_new_addr(xscom, "npu", npu_base[npu_index]);

	dt_add_property_cells(npu, "#size-cells", 0);
	dt_add_property_cells(npu, "#address-cells", 1);
	dt_add_property_cells(npu, "reg", npu_base[npu_index], 0x2c);
	dt_add_property_string(npu, "compatible", "ibm,power9-npu3");
	dt_add_property_cells(npu, "ibm,npu-index", npu_index);

	for (uint32_t i = 0; i < NPU3_LINKS_PER_NPU; i++)
		npu3_dt_create_link(npu, npu_index, i);
}

/* This can be removed when/if we decide to use HDAT instead */
static bool npu3_dt_create(void)
{
	struct proc_chip *chip = next_chip(NULL);
	struct dt_node *xscom;

	/* npu3 chips only */
	if (proc_gen < proc_gen_p9 ||
	    chip->type == PROC_CHIP_P9_NIMBUS ||
	    chip->type == PROC_CHIP_P9_CUMULUS)
		return false;

	dt_for_each_compatible(dt_root, xscom, "ibm,xscom")
		for (uint32_t i = 0; i < 3; i++)
			npu3_dt_create_npu(xscom, i);

	return true;
}

static struct npu3 *npu3_create(struct dt_node *dn)
{
	struct npu3 *npu;
	struct dt_node *link;
	struct npu3_dev *dev;
	char *path;
	uint32_t i;

	npu = zalloc(sizeof(*npu));
	assert(npu);

	init_lock(&npu->lock);

	npu->dt_node = dn;
	npu->index = dt_prop_get_u32(dn, "ibm,npu-index");
	npu->xscom_base = dt_get_address(dn, 0, NULL);

	npu->chip_id = dt_get_chip_id(dn);
	assert(get_chip(npu->chip_id));

	dt_for_each_compatible(dn, link, "ibm,npu-link") {
		i = dt_prop_get_u32(link, "ibm,npu-link-index");
		assert(i < NPU3_LINKS_PER_NPU);

		dev = &npu->devices[i];
		dev->index = i;
		dev->npu = npu;
		dev->dn = link;
		dev->ob_chiplet = dt_prop_get_u32(link, "ibm,npu-phy");
		dev->phy_lane_mask = dt_prop_get_u32(link, "ibm,npu-lane-mask");
		dev->proc.status = NPU3_PROC_COMPLETE;
	};

	path = dt_get_path(dn);
	NPU3INF(npu, "Found %s\n", path);
	NPU3INF(npu, "SCOM base: 0x%llx\n", npu->xscom_base);
	free(path);

	return npu;
}

struct npu3_dev *npu3_next_dev(struct npu3 *npu, struct npu3_dev *dev,
			       enum npu3_dev_type type)
{
	uint32_t i = 0;

	if (dev)
		i = dev->index + 1;

	for (; i < NPU3_LINKS_PER_NPU; i++) {
		dev = &npu->devices[i];

		if (dev->type == type || type == NPU3_DEV_TYPE_ANY)
			return dev;
	}

	return NULL;
}

static void npu3_device_detect_fixup(struct npu3_dev *dev)
{
	struct dt_node *dn = dev->dn;

	if (dev->type == NPU3_DEV_TYPE_NVLINK) {
		dt_add_property_strings(dn, "ibm,npu-link-type", "nvlink");
		dev->link_speed = dt_prop_get_u32_def(
					dn, "nvidia,link-speed", 0xff);
		return;
	}

	NPU3DEVDBG(dev, "Link type unknown\n");
	dt_add_property_strings(dn, "ibm,npu-link-type", "unknown");
}

/*
 * We use the indirect method because it uses the same addresses as
 * the MMIO offsets (NPU RING)
 */
static void npu3_scom_sel(struct npu3 *npu, uint64_t reg, uint64_t size)
{
	uint64_t val;

	val = SETFIELD(NPU3_MISC_DA_ADDR, 0ull, reg);
	val = SETFIELD(NPU3_MISC_DA_LEN, val, size);
	xscom_write(npu->chip_id,
		    npu->xscom_base + NPU3_MISC_SCOM_IND_SCOM_ADDR,
		    val);
}

static void npu3_scom_write(struct npu3 *npu, uint64_t reg, uint64_t size,
			    uint64_t val)
{
	npu3_scom_sel(npu, reg, size);
	xscom_write(npu->chip_id,
		    npu->xscom_base + NPU3_MISC_SCOM_IND_SCOM_DATA,
		    val);
}

static uint64_t npu3_scom_read(struct npu3 *npu, uint64_t reg, uint64_t size)
{
	uint64_t val;

	npu3_scom_sel(npu, reg, size);
	xscom_read(npu->chip_id,
		   npu->xscom_base + NPU3_MISC_SCOM_IND_SCOM_DATA,
		   &val);

	return val;
}

void npu3_write(struct npu3 *npu, uint64_t reg, uint64_t val)
{
	void *mmio = (void *)npu->regs[0];

	if (mmio)
		out_be64(mmio + reg, val);
	else
		npu3_scom_write(npu, reg, NPU3_MISC_DA_LEN_8B, val);

	/* CQ_SM writes should be mirrored in all four blocks */
	if (NPU3_REG_BLOCK(reg) != NPU3_BLOCK_CQ_SM(0))
		return;

	for (uint32_t i = 1; i < 4; i++)
		npu3_write(npu, NPU3_BLOCK_CQ_SM(i) + NPU3_REG_OFFSET(reg),
			   val);
}

uint64_t npu3_read(struct npu3 *npu, uint64_t reg)
{
	void *mmio = (void *)npu->regs[0];

	if (mmio)
		return in_be64(mmio + reg);

	return npu3_scom_read(npu, reg, NPU3_MISC_DA_LEN_8B);
}

void npu3_write_4b(struct npu3 *npu, uint64_t reg, uint32_t val)
{
	void *mmio = (void *)npu->regs[0];

	if (mmio)
		out_be32(mmio + reg, val);
	else
		npu3_scom_write(npu, reg, NPU3_MISC_DA_LEN_4B,
				(uint64_t)val << 32);

	if (NPU3_REG_BLOCK(reg) != NPU3_BLOCK_CQ_SM(0))
		return;

	for (uint32_t i = 1; i < 4; i++)
		npu3_write_4b(npu, NPU3_BLOCK_CQ_SM(i) + NPU3_REG_OFFSET(reg),
			      val);
}

uint32_t npu3_read_4b(struct npu3 *npu, uint64_t reg)
{
	void *mmio = (void *)npu->regs[0];

	if (mmio)
		return in_be32(mmio + reg);

	return npu3_scom_read(npu, reg, NPU3_MISC_DA_LEN_4B) >> 32;
}

static void npu3_misc_config(struct npu3 *npu)
{
	struct npu3_dev *dev;
	uint32_t typemap = 0;
	uint64_t reg, val;

	npu3_for_each_nvlink_dev(dev, npu)
		typemap |= 0x10 >> dev->index;

	reg = NPU3_MCP_MISC_CFG0;
	val = npu3_read(npu, reg);
	val |= NPU3_MCP_MISC_CFG0_ENABLE_PBUS;
	val &= ~NPU3_MCP_MISC_CFG0_ENABLE_SNARF_CPM;
	val = SETFIELD(NPU3_MCP_MISC_CFG0_NVLINK_MODE, val, typemap);
	val = SETFIELD(NPU3_MCP_MISC_CFG0_OCAPI_MODE, val, ~typemap);
	npu3_write(npu, reg, val);

	reg = NPU3_SNP_MISC_CFG0;
	val = npu3_read(npu, reg);
	val |= NPU3_SNP_MISC_CFG0_ENABLE_PBUS;
	val = SETFIELD(NPU3_SNP_MISC_CFG0_NVLINK_MODE, val, typemap);
	val = SETFIELD(NPU3_SNP_MISC_CFG0_OCAPI_MODE, val, ~typemap);
	npu3_write(npu, reg, val);

	reg = NPU3_CTL_MISC_CFG2;
	val = npu3_read(npu, reg);
	val = SETFIELD(NPU3_CTL_MISC_CFG2_NVLINK_MODE, val, typemap);
	val = SETFIELD(NPU3_CTL_MISC_CFG2_OCAPI_MODE, val, ~typemap);
	npu3_write(npu, reg, val);

	reg = NPU3_DAT_MISC_CFG1;
	val = npu3_read(npu, reg);
	val = SETFIELD(NPU3_DAT_MISC_CFG1_NVLINK_MODE, val, typemap);
	val = SETFIELD(NPU3_DAT_MISC_CFG1_OCAPI_MODE, val, ~typemap);
	npu3_write(npu, reg, val);
}

static void npu3_assign_bars(struct npu3 *npu)
{
	struct npu3_dev *dev;
	uint64_t addr, size, val;

	/* Global MMIO bar (per npu) */
	phys_map_get(npu->chip_id, NPU_REGS, npu->index, &addr, &size);
	val = SETFIELD(NPU3_MMIO_BAR_ADDR, 0ull, addr >> 24);
	val |= NPU3_MMIO_BAR_ENABLE;
	npu3_write(npu, NPU3_MMIO_BAR, val);

	NPU3INF(npu, "MMIO base: 0x%016llx (%lldMB)\n", addr, size >> 20);
	npu->regs[0] = addr;
	npu->regs[1] = size;

	/* NTL bar (per device) */
	npu3_for_each_dev(dev, npu) {
		phys_map_get(npu->chip_id, NPU_NTL, npu3_chip_dev_index(dev),
			     &addr, &size);
		val = SETFIELD(NPU3_NTL_BAR_ADDR, 0ull, addr >> 16);
		val = SETFIELD(NPU3_NTL_BAR_SIZE, val, ilog2(size >> 16));
		npu3_write(npu, NPU3_NTL_BAR(dev->index), val);

		dev->ntl_bar.addr = addr;
		dev->ntl_bar.size = size;
	}

	/* GENID bar (logically divided per device) */
	phys_map_get(npu->chip_id, NPU_GENID, npu->index, &addr, NULL);
	val = SETFIELD(NPU3_GENID_BAR_ADDR, 0ull, addr >> 19);
	npu3_write(npu, NPU3_GENID_BAR, val);

	npu3_for_each_dev(dev, npu) {
		dev->genid_bar.addr = addr + (dev->index << 16);
		dev->genid_bar.size = 64 << 10;
	}
}

void npu3_dev_enable_bars(struct npu3_dev *dev, bool enable)
{
	struct npu3 *npu = dev->npu;
	uint64_t reg, val;

	if (dev->ntl_bar.enable == enable) /* No state change */
		return;

	dev->ntl_bar.enable = enable;
	dev->genid_bar.enable = enable;

	reg = NPU3_NTL_BAR(dev->index);
	val = npu3_read(npu, reg);
	val = SETFIELD(NPU3_NTL_BAR_ENABLE, val, enable);
	npu3_write(npu, reg, val);

	/*
	 * Generation IDs are a single space in the hardware but we split them
	 * per device. Only disable in hardware if every device has disabled.
	 */
	if (!enable)
		npu3_for_each_dev(dev, npu)
			if (dev->genid_bar.enable)
				return;

	reg = NPU3_GENID_BAR;
	val = npu3_read(npu, reg);
	val = SETFIELD(NPU3_GENID_BAR_ENABLE, val, enable);
	npu3_write(npu, reg, val);
}

static uint64_t npu3_ipi_attributes(struct irq_source *is, uint32_t isn)
{
	struct npu3 *npu = is->data;
	uint32_t level = isn - npu->irq_base;

	/* TCE interrupt is used to detect a frozen PE */
	if (level == 18)
		return IRQ_ATTR_TARGET_OPAL |
		       IRQ_ATTR_TARGET_RARE |
		       IRQ_ATTR_TYPE_MSI;

	return IRQ_ATTR_TARGET_LINUX;
}

static void npu3_ipi_interrupt(struct irq_source *is, uint32_t isn)
{
	struct npu3 *npu = is->data;
	uint32_t level = isn - npu->irq_base;

	if (level != 18) {
		NPU3ERR(npu, "Received unknown interrupt %d\n", level);
		return;
	}

	opal_update_pending_evt(OPAL_EVENT_PCI_ERROR, OPAL_EVENT_PCI_ERROR);
}

#define NPU3_IRQ_LEVELS 60

static char *npu3_ipi_name(struct irq_source *is, uint32_t isn)
{
	struct npu3 *npu = is->data;
	uint32_t level = isn - npu->irq_base;
	static const char *names[NPU3_IRQ_LEVELS] = {
		[0] = "NDL 0 Stall Event (brick 0)",
		[1] = "NDL 0 No-Stall Event (brick 0)",
		[2] = "NDL 1 Stall Event (brick 1)",
		[3] = "NDL 1 No-Stall Event (brick 1)",
		[4] = "NDL 2 Stall Event (brick 2)",
		[5] = "NDL 2 No-Stall Event (brick 2)",
		[6] = "NDL 3 Stall Event (brick 3)",
		[7] = "NDL 3 No-Stall Event (brick 3)",
		[8] = "NDL 4 Stall Event (brick 4)",
		[9] = "NDL 4 No-Stall Event (brick 4)",
		[10] = "NDL 5 Stall Event (brick 5)",
		[11] = "NDL 5 No-Stall Event (brick 5)",
		[12] = "NTL 0 Event",
		[13] = "NTL 1 Event",
		[14] = "NTL 2 Event",
		[15] = "NTL 3 Event",
		[16] = "NTL 4 Event",
		[17] = "NTL 5 Event",
		[18] = "TCE Event",
		[19] = "ATS Event",
		[20] = "CQ Event",
		[21] = "MISC Event",
		[41] = "Memory Controller Event",
		[42] = "NDL 6 Stall Event (brick 6)",
		[43] = "NDL 6 No-Stall Event (brick 6)",
		[44] = "NDL 7 Stall Event (brick 7)",
		[45] = "NDL 7 No-Stall Event (brick 7)",
		[46] = "NDL 8 Stall Event (brick 8)",
		[47] = "NDL 8 No-Stall Event (brick 8)",
		[48] = "NDL 9 Stall Event (brick 9)",
		[49] = "NDL 9 No-Stall Event (brick 9)",
		[50] = "NDL 10 Stall Event (brick 10)",
		[51] = "NDL 10 No-Stall Event (brick 10)",
		[52] = "NDL 11 Stall Event (brick 11)",
		[53] = "NDL 11 No-Stall Event (brick 11)",
		[54] = "NTL 6 Event",
		[55] = "NTL 7 Event",
		[56] = "NTL 8 Event",
		[57] = "NTL 9 Event",
		[58] = "NTL 10 Event",
		[59] = "NTL 11 Event",
	};

	if (level >= NPU3_IRQ_LEVELS || !names[level])
		return strdup("Unknown");

	return strdup(names[level]);
}

static const struct irq_source_ops npu3_ipi_ops = {
	.attributes	= npu3_ipi_attributes,
	.interrupt	= npu3_ipi_interrupt,
	.name		= npu3_ipi_name,
};

static void npu3_setup_irqs(struct npu3 *npu)
{
	uint64_t reg, val;
	uint32_t base;

	base = xive_alloc_ipi_irqs(npu->chip_id, NPU3_IRQ_LEVELS, 64);
	if (base == XIVE_IRQ_ERROR) {
		NPU3ERR(npu, "Failed to allocate interrupt sources\n");
		return;
	}

	xive_register_ipi_source(base, NPU3_IRQ_LEVELS, npu, &npu3_ipi_ops);

	/* Set IPI configuration */
	reg = NPU3_MISC_CFG;
	val = npu3_read(npu, reg);
	val = SETFIELD(NPU3_MISC_CFG_IPI_PS, val, NPU3_MISC_CFG_IPI_PS_64K);
	val = SETFIELD(NPU3_MISC_CFG_IPI_OS, val, NPU3_MISC_CFG_IPI_OS_AIX);
	npu3_write(npu, reg, val);

	/* Set IRQ base */
	reg = NPU3_MISC_INT_BAR;
	val = SETFIELD(NPU3_MISC_INT_BAR_ADDR, 0ull,
		       (uint64_t)xive_get_trigger_port(base) >> 12);
	npu3_write(npu, reg, val);

	npu->irq_base = base;
}

static void npu3_init(struct npu3 *npu)
{
	struct npu3_dev *dev;

	platform.npu3_device_detect(npu);
	npu3_for_each_dev(dev, npu)
		npu3_device_detect_fixup(dev);

	npu3_misc_config(npu);
	npu3_assign_bars(npu);
	npu3_setup_irqs(npu);
	npu3_init_nvlink(npu);
}

void probe_npu3(void)
{
	struct dt_node *dn;
	struct npu3 *npu;

	if (!npu3_dt_create())
		return;

	if (!platform.npu3_device_detect) {
		prlog(PR_INFO, "NPU: Platform does not support NPU\n");
		return;
	}

	dt_for_each_compatible(dt_root, dn, "ibm,power9-npu3") {
		npu = npu3_create(dn);
		npu3_init(npu);
	}
}
