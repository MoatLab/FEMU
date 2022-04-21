// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/* Copyright 2013-2019 IBM Corp. */

#include <skiboot.h>
#include <xscom.h>
#include <pci.h>
#include <npu2.h>
#include <npu2-regs.h>
#include <bitutils.h>
#include <nvram.h>
#include <i2c.h>
#include <interrupts.h>
#include <xive.h>

#define NPU2_IRQ_BASE_SHIFT 13
#define NPU2_N_DL_IRQS 35
#define NPU2_N_DL_IRQS_ALIGN 64

/*
 * We use the indirect method because it uses the same addresses as
 * the MMIO offsets (NPU RING)
 */
static void npu2_scom_set_addr(uint64_t gcid, uint64_t scom_base,
			       uint64_t addr, uint64_t size)
{
	addr = SETFIELD(NPU2_MISC_DA_ADDR, 0ull, addr);
	addr = SETFIELD(NPU2_MISC_DA_LEN, addr, size);
	xscom_write(gcid, scom_base + NPU2_MISC_SCOM_IND_SCOM_ADDR, addr);
}

void npu2_scom_write(uint64_t gcid, uint64_t scom_base,
		     uint64_t reg, uint64_t size,
		     uint64_t val)
{
	npu2_scom_set_addr(gcid, scom_base, reg, size);
	xscom_write(gcid, scom_base + NPU2_MISC_SCOM_IND_SCOM_DATA, val);
}

uint64_t npu2_scom_read(uint64_t gcid, uint64_t scom_base,
			uint64_t reg, uint64_t size)
{
	uint64_t val;

	npu2_scom_set_addr(gcid, scom_base, reg, size);
	xscom_read(gcid, scom_base + NPU2_MISC_SCOM_IND_SCOM_DATA, &val);

	return val;
}

void npu2_write_4b(struct npu2 *p, uint64_t reg, uint32_t val)
{
	npu2_scom_write(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_4B,
			(uint64_t)val << 32);
}

uint32_t npu2_read_4b(struct npu2 *p, uint64_t reg)
{
	return npu2_scom_read(p->chip_id, p->xscom_base, reg,
			      NPU2_MISC_DA_LEN_4B) >> 32;
}

void npu2_write(struct npu2 *p, uint64_t reg, uint64_t val)
{
	npu2_scom_write(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_8B, val);
}

uint64_t npu2_read(struct npu2 *p, uint64_t reg)
{
	return npu2_scom_read(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_8B);
}

void npu2_write_mask(struct npu2 *p, uint64_t reg, uint64_t val, uint64_t mask)
{
	uint64_t new_val;

	new_val = npu2_read(p, reg);
	new_val &= ~mask;
	new_val |= val & mask;
	npu2_scom_write(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_8B, new_val);
}

void npu2_write_mask_4b(struct npu2 *p, uint64_t reg, uint32_t val, uint32_t mask)
{
	uint32_t new_val;

	new_val = npu2_read_4b(p, reg);
	new_val &= ~mask;
	new_val |= val & mask;
	npu2_scom_write(p->chip_id, p->xscom_base, reg, NPU2_MISC_DA_LEN_4B,
			(uint64_t)new_val << 32);
}

typedef struct {
	const char *name;
	uint32_t block;
	uint32_t offset;
} npu2_scom_dump_t;

static npu2_scom_dump_t npu2_scom_dump_global[] = {
	/* CQ State Machine */
	{ "CS.SM0.MISC.CERR_MESSAGE0", NPU2_BLOCK_SM_0, NPU2_C_ERR_RPT_MSG0 },
	{ "CS.SM1.MISC.CERR_MESSAGE0", NPU2_BLOCK_SM_1, NPU2_C_ERR_RPT_MSG0 },
	{ "CS.SM2.MISC.CERR_MESSAGE0", NPU2_BLOCK_SM_2, NPU2_C_ERR_RPT_MSG0 },
	{ "CS.SM3.MISC.CERR_MESSAGE0", NPU2_BLOCK_SM_3, NPU2_C_ERR_RPT_MSG0 },

	{ "CS.SM0.MISC.CERR_MESSAGE1", NPU2_BLOCK_SM_0, NPU2_C_ERR_RPT_MSG1 },
	{ "CS.SM1.MISC.CERR_MESSAGE1", NPU2_BLOCK_SM_1, NPU2_C_ERR_RPT_MSG1 },
	{ "CS.SM2.MISC.CERR_MESSAGE1", NPU2_BLOCK_SM_2, NPU2_C_ERR_RPT_MSG1 },
	{ "CS.SM3.MISC.CERR_MESSAGE1", NPU2_BLOCK_SM_3, NPU2_C_ERR_RPT_MSG1 },

	{ "CS.SM0.MISC.CERR_MESSAGE2", NPU2_BLOCK_SM_0, NPU2_C_ERR_RPT_MSG2 },
	{ "CS.SM1.MISC.CERR_MESSAGE2", NPU2_BLOCK_SM_1, NPU2_C_ERR_RPT_MSG2 },
	{ "CS.SM2.MISC.CERR_MESSAGE2", NPU2_BLOCK_SM_2, NPU2_C_ERR_RPT_MSG2 },
	{ "CS.SM3.MISC.CERR_MESSAGE2", NPU2_BLOCK_SM_3, NPU2_C_ERR_RPT_MSG2 },

	{ "CS.SM0.MISC.CERR_MESSAGE3", NPU2_BLOCK_SM_0, NPU2_C_ERR_RPT_MSG3 },
	{ "CS.SM1.MISC.CERR_MESSAGE3", NPU2_BLOCK_SM_1, NPU2_C_ERR_RPT_MSG3 },
	{ "CS.SM2.MISC.CERR_MESSAGE3", NPU2_BLOCK_SM_2, NPU2_C_ERR_RPT_MSG3 },
	{ "CS.SM3.MISC.CERR_MESSAGE3", NPU2_BLOCK_SM_3, NPU2_C_ERR_RPT_MSG3 },

	{ "CS.SM0.MISC.CERR_MESSAGE4", NPU2_BLOCK_SM_0, NPU2_C_ERR_RPT_MSG4 },
	{ "CS.SM1.MISC.CERR_MESSAGE4", NPU2_BLOCK_SM_1, NPU2_C_ERR_RPT_MSG4 },
	{ "CS.SM2.MISC.CERR_MESSAGE4", NPU2_BLOCK_SM_2, NPU2_C_ERR_RPT_MSG4 },
	{ "CS.SM3.MISC.CERR_MESSAGE4", NPU2_BLOCK_SM_3, NPU2_C_ERR_RPT_MSG4 },

	{ "CS.SM0.MISC.CERR_MESSAGE5", NPU2_BLOCK_SM_0, NPU2_C_ERR_RPT_MSG5 },
	{ "CS.SM1.MISC.CERR_MESSAGE5", NPU2_BLOCK_SM_1, NPU2_C_ERR_RPT_MSG5 },
	{ "CS.SM2.MISC.CERR_MESSAGE5", NPU2_BLOCK_SM_2, NPU2_C_ERR_RPT_MSG5 },
	{ "CS.SM3.MISC.CERR_MESSAGE5", NPU2_BLOCK_SM_3, NPU2_C_ERR_RPT_MSG5 },

	{ "CS.SM0.MISC.CERR_MESSAGE6", NPU2_BLOCK_SM_0, NPU2_C_ERR_RPT_MSG6 },
	{ "CS.SM1.MISC.CERR_MESSAGE6", NPU2_BLOCK_SM_1, NPU2_C_ERR_RPT_MSG6 },
	{ "CS.SM2.MISC.CERR_MESSAGE6", NPU2_BLOCK_SM_2, NPU2_C_ERR_RPT_MSG6 },
	{ "CS.SM3.MISC.CERR_MESSAGE6", NPU2_BLOCK_SM_3, NPU2_C_ERR_RPT_MSG6 },

	{ "CS.SM0.MISC.CERR_FIRST0", NPU2_BLOCK_SM_0, NPU2_C_ERR_RPT_FIRST0 },
	{ "CS.SM1.MISC.CERR_FIRST0", NPU2_BLOCK_SM_1, NPU2_C_ERR_RPT_FIRST0 },
	{ "CS.SM2.MISC.CERR_FIRST0", NPU2_BLOCK_SM_2, NPU2_C_ERR_RPT_FIRST0 },
	{ "CS.SM3.MISC.CERR_FIRST0", NPU2_BLOCK_SM_3, NPU2_C_ERR_RPT_FIRST0 },

	{ "CS.SM0.MISC.CERR_FIRST1", NPU2_BLOCK_SM_0, NPU2_C_ERR_RPT_FIRST1 },
	{ "CS.SM1.MISC.CERR_FIRST1", NPU2_BLOCK_SM_1, NPU2_C_ERR_RPT_FIRST1 },
	{ "CS.SM2.MISC.CERR_FIRST1", NPU2_BLOCK_SM_2, NPU2_C_ERR_RPT_FIRST1 },
	{ "CS.SM3.MISC.CERR_FIRST1", NPU2_BLOCK_SM_3, NPU2_C_ERR_RPT_FIRST1 },

	{ "CS.SM0.MISC.CERR_FIRST2", NPU2_BLOCK_SM_0, NPU2_C_ERR_RPT_FIRST2 },
	{ "CS.SM1.MISC.CERR_FIRST2", NPU2_BLOCK_SM_1, NPU2_C_ERR_RPT_FIRST2 },
	{ "CS.SM2.MISC.CERR_FIRST2", NPU2_BLOCK_SM_2, NPU2_C_ERR_RPT_FIRST2 },
	{ "CS.SM3.MISC.CERR_FIRST2", NPU2_BLOCK_SM_3, NPU2_C_ERR_RPT_FIRST2 },

	/* CQ Control */
	{ "CS.CTL.MISC.CERR_MESSAGE0", NPU2_BLOCK_CTL, NPU2_CQ_C_ERR_RPT_MSG0 },
	{ "CS.CTL.MISC.CERR_MESSAGE1", NPU2_BLOCK_CTL, NPU2_CQ_C_ERR_RPT_MSG1 },
	{ "CS.CTL.MISC.CERR_FIRST0", NPU2_BLOCK_CTL, NPU2_CQ_C_ERR_RPT_FIRST0 },
	{ "CS.CTL.MISC.CERR_FIRST1", NPU2_BLOCK_CTL, NPU2_CQ_C_ERR_RPT_FIRST1 },

	/* CQ Data */
	{ "DAT.MISC.CERR_ECC_HOLD", NPU2_BLOCK_DAT, NPU2_CQ_DAT_ECC_STATUS },
	{ "DAT.MISC.CERR_ECC_MASK", NPU2_BLOCK_DAT, NPU2_CQ_DAT_ECC_MASK },
	{ "DAT.MISC.CERR_ECC_FIRST", NPU2_BLOCK_DAT, NPU2_CQ_DAT_ECC_FIRST },
	{ "DAT.MISC.REM0", NPU2_BLOCK_DAT, NPU2_CQ_DAT_RAS_MSG0 },
	{ "DAT.MISC.REM1", NPU2_BLOCK_DAT, NPU2_CQ_DAT_RAS_MSG1 },
};

static npu2_scom_dump_t npu2_scom_dump_nvlink[] = {
	{ "NTL0.REGS.CERR_FIRST1", NPU2_BLOCK_NTL0, NPU2_NTL_ERR_FIRST1_OFF },
	{ "NTL1.REGS.CERR_FIRST1", NPU2_BLOCK_NTL1, NPU2_NTL_ERR_FIRST1_OFF },
	{ "NTL0.REGS.CERR_FIRST2", NPU2_BLOCK_NTL0, NPU2_NTL_ERR_FIRST2_OFF },
	{ "NTL1.REGS.CERR_FIRST2", NPU2_BLOCK_NTL1, NPU2_NTL_ERR_FIRST2_OFF },
};

static npu2_scom_dump_t npu2_scom_dump_ocapi[] = {
	{ "OTL0.MISC.C_ERR_RPT_HOLD0", NPU2_BLOCK_OTL0, NPU2_OTL_ERR_RPT_HOLD0 },
	{ "OTL1.MISC.C_ERR_RPT_HOLD0", NPU2_BLOCK_OTL1, NPU2_OTL_ERR_RPT_HOLD0 },
	{ "OTL0.MISC.OTL_REM0", NPU2_BLOCK_OTL0, NPU2_OTL_RAS_ERR_MSG0 },
	{ "OTL1.MISC.OTL_REM0", NPU2_BLOCK_OTL1, NPU2_OTL_RAS_ERR_MSG0 },
	{ "OTL0.MISC.ERROR_SIG_RXI", NPU2_BLOCK_OTL0, NPU2_OTL_RXI_ERR_SIG },
	{ "OTL1.MISC.ERROR_SIG_RXI", NPU2_BLOCK_OTL1, NPU2_OTL_RXI_ERR_SIG },
	{ "OTL0.MISC.ERROR_SIG_RXO", NPU2_BLOCK_OTL0, NPU2_OTL_RXO_ERR_SIG },
	{ "OTL1.MISC.ERROR_SIG_RXO", NPU2_BLOCK_OTL1, NPU2_OTL_RXO_ERR_SIG },
	{ "OTL0.MISC.C_ERR_RPT_HOLD1", NPU2_BLOCK_OTL0, NPU2_OTL_ERR_RPT_HOLD1 },
	{ "OTL1.MISC.C_ERR_RPT_HOLD1", NPU2_BLOCK_OTL1, NPU2_OTL_ERR_RPT_HOLD1 },
};

static void print_one_npu_reg(struct npu2 *npu, npu2_scom_dump_t *scom, int stack)
{
	uint64_t reg, val;

	reg = NPU2_REG_OFFSET(stack, scom->block, scom->offset);
	val = npu2_scom_read(npu->chip_id, npu->xscom_base,
			reg, NPU2_MISC_DA_LEN_8B);

	prlog(PR_ERR, "NPU[%d] STCK%d.%s 0x%llx = 0x%016llx\n",
		npu->chip_id, stack - 4, scom->name, reg, val);
}

/* same as above, but for direct access registers */
static void print_one_reg(int chip_id, int brick_index,
			uint64_t reg_addr, const char *reg_name)
{
	uint64_t val;

	xscom_read(chip_id, reg_addr, &val);
	prlog(PR_ERR, "NPU[%d] %s brick %d 0x%llx = 0x%016llx\n",
		chip_id, reg_name, brick_index, reg_addr, val);
}

static void show_nvlink_regs(struct npu2 *npu, int brick_index)
{
	uint32_t stack, ntl;
	int i;

	stack = NPU2_STACK_STCK_0 + brick_index / 2;
	ntl = NPU2_BLOCK_NTL0 + (brick_index % 2) * 2;

	for (i = 0; i < ARRAY_SIZE(npu2_scom_dump_nvlink); i++) {
		if (npu2_scom_dump_nvlink[i].block == ntl)
			print_one_npu_reg(npu, &npu2_scom_dump_nvlink[i], stack);
	}
}

static void show_opencapi_regs(struct npu2 *npu, int brick_index)
{
	uint32_t stack, otl;
	int i;

	stack = NPU2_STACK_STCK_0 + brick_index / 2;
	otl = NPU2_BLOCK_OTL0 + (brick_index % 2);

	/* NPU registers */
	for (i = 0; i < ARRAY_SIZE(npu2_scom_dump_ocapi); i++) {
		if (npu2_scom_dump_ocapi[i].block == otl)
			print_one_npu_reg(npu, &npu2_scom_dump_ocapi[i], stack);
	}

	/* Fabric registers */
	print_one_reg(npu->chip_id, brick_index,
		OB_ODL_STATUS(brick_index), "ODL status");
	print_one_reg(npu->chip_id, brick_index,
		OB_ODL_TRAINING_STATUS(brick_index), "ODL training status");
	print_one_reg(npu->chip_id, brick_index,
		OB_ODL_ENDPOINT_INFO(brick_index), "ODL endpoint info");
}

static void show_all_regs(struct npu2 *npu, int brick_index)
{
	int i, stack, stack_min, stack_max;
	uint64_t fir_val, mask_val, fir_addr, mask_addr;
	struct npu2_dev *dev;
	npu2_scom_dump_t scom_reg;

	if (brick_index != -1) {
		stack_min = stack_max = NPU2_STACK_STCK_0 + brick_index / 2;
	} else {
		stack_min = NPU2_STACK_STCK_0;
		stack_max = NPU2_STACK_STCK_2;
		/* Avoid dumping unused stacks for opencapi on Lagrange */
		if (npu->total_devices == 2)
			stack_min = stack_max = NPU2_STACK_STCK_1;
	}

	/* NPU FIRs */
	for (i = 0; i < NPU2_TOTAL_FIR_REGISTERS; i++) {
		fir_addr  = NPU2_FIR_REGISTER_0 + i * NPU2_FIR_OFFSET;
		mask_addr = fir_addr + NPU2_FIR_MASK_OFFSET;
		xscom_read(npu->chip_id, fir_addr, &fir_val);
		xscom_read(npu->chip_id, mask_addr, &mask_val);
		prlog(PR_ERR, "NPU[%d] FIR%d = 0x%016llx (mask 0x%016llx => 0x%016llx)\n",
			npu->chip_id, i, fir_val, mask_val, fir_val & ~mask_val);
	}

	/* NPU global, per-stack registers */
	for (i = 0; i < ARRAY_SIZE(npu2_scom_dump_global); i++) {
		for (stack = stack_min; stack <= stack_max; stack++)
			print_one_npu_reg(npu, &npu2_scom_dump_global[i], stack);
	}

	/*
	 * NPU global registers, stack independent
	 * We have only one for now, so dump it directly
	 */
	scom_reg.name = "XTS.REG.ERR_HOLD";
	scom_reg.block = NPU2_BLOCK_XTS;
	scom_reg.offset = 0;
	print_one_npu_reg(npu, &scom_reg, NPU2_STACK_MISC);

	/* nvlink- or opencapi-specific registers */
	for (i = 0; i < npu->total_devices; i++) {
		dev = &npu->devices[i];
		if (brick_index == -1 || dev->brick_index == brick_index) {
			if (dev->type == NPU2_DEV_TYPE_NVLINK)
				show_nvlink_regs(npu, dev->brick_index);
			else if (dev->type == NPU2_DEV_TYPE_OPENCAPI)
				show_opencapi_regs(npu, dev->brick_index);
		}
	}
}

void npu2_dump_scoms(int chip_id)
{
	struct npu2 *npu;
	struct phb *phb;
	struct npu2_dev *dev;

	/*
	 * Look for the npu2 structure for that chip ID. We can access it
	 * through the array of phbs, looking for a nvlink or opencapi
	 * phb. We can have several entries, but they all point
	 * to the same npu2 structure
	 */
	for_each_phb(phb) {
		npu = NULL;
		if (phb->phb_type == phb_type_npu_v2) {
			npu = phb_to_npu2_nvlink(phb);
		} else if (phb->phb_type == phb_type_npu_v2_opencapi) {
			dev = phb_to_npu2_dev_ocapi(phb);
			npu = dev->npu;
		}
		if (npu && npu->chip_id == chip_id) {
			show_all_regs(npu, -1 /* all bricks */);
			break;
		}
	}
}

static uint64_t npu2_ipi_attributes(struct irq_source *is __unused, uint32_t isn __unused)
{
	struct npu2 *p = is->data;
	uint32_t idx = isn - p->base_lsi;

	if ((idx == 18) || (idx >= 27 && idx <= 34))
		/*
		 * level 18: TCE Interrupt - used to detect a frozen PE (nvlink)
		 * level 27-30: OTL interrupt (opencapi)
		 * level 31-34: XSL interrupt (opencapi)
		 */
		return IRQ_ATTR_TARGET_OPAL | IRQ_ATTR_TARGET_RARE | IRQ_ATTR_TYPE_MSI;
	else
		return IRQ_ATTR_TARGET_LINUX;
}

static char *npu2_ipi_name(struct irq_source *is, uint32_t isn)
{
	struct npu2 *p = is->data;
	uint32_t idx = isn - p->base_lsi;
	const char *name;

	switch (idx) {
	case 0: name = "NDL 0 Stall Event (brick 0)"; break;
	case 1: name = "NDL 0 No-Stall Event (brick 0)"; break;
	case 2: name = "NDL 1 Stall Event (brick 1)"; break;
	case 3: name = "NDL 1 No-Stall Event (brick 1)"; break;
	case 4: name = "NDL 2 Stall Event (brick 2)"; break;
	case 5: name = "NDL 2 No-Stall Event (brick 2)"; break;
	case 6: name = "NDL 5 Stall Event (brick 3)"; break;
	case 7: name = "NDL 5 No-Stall Event (brick 3)"; break;
	case 8: name = "NDL 4 Stall Event (brick 4)"; break;
	case 9: name = "NDL 4 No-Stall Event (brick 4)"; break;
	case 10: name = "NDL 3 Stall Event (brick 5)"; break;
	case 11: name = "NDL 3 No-Stall Event (brick 5)"; break;
	case 12: name = "NTL 0 Event"; break;
	case 13: name = "NTL 1 Event"; break;
	case 14: name = "NTL 2 Event"; break;
	case 15: name = "NTL 3 Event"; break;
	case 16: name = "NTL 4 Event"; break;
	case 17: name = "NTL 5 Event"; break;
	case 18: name = "TCE Event"; break;
	case 19: name = "ATS Event"; break;
	case 20: name = "CQ Event"; break;
	case 21: name = "MISC Event"; break;
	case 22: name = "NMMU Local Xstop"; break;
	case 23: name = "Translate Fail (brick 2)"; break;
	case 24: name = "Translate Fail (brick 3)"; break;
	case 25: name = "Translate Fail (brick 4)"; break;
	case 26: name = "Translate Fail (brick 5)"; break;
	case 27: name = "OTL Event (brick 2)"; break;
	case 28: name = "OTL Event (brick 3)"; break;
	case 29: name = "OTL Event (brick 4)"; break;
	case 30: name = "OTL Event (brick 5)"; break;
	case 31: name = "XSL Event (brick 2)"; break;
	case 32: name = "XSL Event (brick 3)"; break;
	case 33: name = "XSL Event (brick 4)"; break;
	case 34: name = "XSL Event (brick 5)"; break;
	default: name = "Unknown";
	}
	return strdup(name);
}

static void npu2_err_interrupt(struct irq_source *is, uint32_t isn)
{
	struct npu2 *p = is->data;
	uint32_t idx = isn - p->base_lsi;
	char *irq_name;
	int brick;

	switch (idx) {
	case 18:
		opal_update_pending_evt(OPAL_EVENT_PCI_ERROR,
					OPAL_EVENT_PCI_ERROR);
		break;
	case 27 ... 34:
		/* opencapi only */
		brick = 2 + ((idx - 27) % 4);
		irq_name = npu2_ipi_name(is, isn);
		prlog(PR_ERR, "NPU[%d] received error interrupt '%s'\n",
			p->chip_id, irq_name);
		free(irq_name);
		show_all_regs(p, brick);
		/*
		 * P9 NPU doesn't support recovering a link going down
		 * unexpectedly. So we mark the device as broken and
		 * report it to the OS, so that the error is logged
		 * and the drivers notified.
		 */
		npu2_opencapi_set_broken(p, brick);
		opal_update_pending_evt(OPAL_EVENT_PCI_ERROR,
					OPAL_EVENT_PCI_ERROR);
		break;
	default:
		prerror("OPAL received unknown NPU2 interrupt %d\n", idx);
		return;
	}
}

static const struct irq_source_ops npu2_ipi_ops = {
	.interrupt	= npu2_err_interrupt,
	.attributes	= npu2_ipi_attributes,
	.name = npu2_ipi_name,
};

static void setup_irqs(struct npu2 *p)
{
	uint64_t reg, val;
	void *tp;

	p->base_lsi = xive_alloc_ipi_irqs(p->chip_id, NPU2_N_DL_IRQS, NPU2_N_DL_IRQS_ALIGN);
	if (p->base_lsi == XIVE_IRQ_ERROR) {
		prlog(PR_ERR, "NPU: Failed to allocate interrupt sources\n");
		return;
	}
	xive_register_ipi_source(p->base_lsi, NPU2_N_DL_IRQS, p, &npu2_ipi_ops);

	/* Set IPI configuration */
	reg = NPU2_REG_OFFSET(NPU2_STACK_MISC, NPU2_BLOCK_MISC, NPU2_MISC_CFG);
	val = npu2_read(p, reg);
	val = SETFIELD(NPU2_MISC_CFG_IPI_PS, val, NPU2_MISC_CFG_IPI_PS_64K);
	val = SETFIELD(NPU2_MISC_CFG_IPI_OS, val, NPU2_MISC_CFG_IPI_OS_AIX);
	npu2_write(p, reg, val);

	/* Set IRQ base */
	reg = NPU2_REG_OFFSET(NPU2_STACK_MISC, NPU2_BLOCK_MISC, NPU2_MISC_IRQ_BASE);
	tp = xive_get_trigger_port(p->base_lsi);
	val = ((uint64_t)tp) << NPU2_IRQ_BASE_SHIFT;
	npu2_write(p, reg, val);
}

static bool _i2c_presence_detect(struct npu2_dev *dev)
{
	uint8_t state, data;
	int rc;

	rc = i2c_request_send(dev->npu->i2c_port_id_ocapi,
			platform.ocapi->i2c_presence_addr,
			SMBUS_READ, 0, 1,
			&state, 1, 120);
	if (rc) {
		OCAPIERR(dev, "error detecting link presence: %d\n", rc);
		return true; /* assume link exists */
	}

	OCAPIDBG(dev, "I2C presence detect: 0x%x\n", state);

	switch (dev->link_index) {
	case 2:
		data = platform.ocapi->i2c_presence_brick2;
		break;
	case 3:
		data = platform.ocapi->i2c_presence_brick3;
		break;
	case 4:
		data = platform.ocapi->i2c_presence_brick4;
		break;
	case 5:
		data = platform.ocapi->i2c_presence_brick5;
		break;
	default:
		OCAPIERR(dev, "presence detection on invalid link\n");
		return true;
	}
	/* Presence detect bits are active low */
	return !(state & data);
}

/*
 * A default presence detection implementation for platforms like ZZ and Zaius
 * that don't implement their own. Assumes all devices found will be OpenCAPI.
 */
void npu2_i2c_presence_detect(struct npu2 *npu)
{
	struct npu2_dev *dev;
	assert(platform.ocapi);
	for (int i = 0; i < npu->total_devices; i++) {
		dev = &npu->devices[i];
		if (_i2c_presence_detect(dev))
			dev->type = NPU2_DEV_TYPE_OPENCAPI;
		else
			dev->type = NPU2_DEV_TYPE_UNKNOWN;
	}
}

static struct npu2 *setup_npu(struct dt_node *dn)
{
	struct npu2 *npu;
	struct npu2_dev *dev;
	struct dt_node *np;
	uint32_t num_links;
	char port_name[17];
	void *npumem;
	char *path;
	int gcid;
	struct proc_chip *chip;
	int i = 0;

	/* Retrieve chip ID */
	path = dt_get_path(dn);
	gcid = dt_get_chip_id(dn);
	chip = get_chip(gcid);
	assert(chip);

	num_links = dt_prop_get_u32(dn, "ibm,npu-links");
	npumem = zalloc(sizeof(struct npu2) + num_links *
			sizeof(struct npu2_dev));
	assert(npumem);
	npu = npumem;

	npu->dt_node = dn;
	npu->index = dt_prop_get_u32(dn, "ibm,npu-index");
	npu->chip_id = gcid;
	npu->xscom_base = dt_get_address(dn, 0, NULL);

	init_lock(&npu->i2c_lock);
	npu->i2c_pin_mode = ~0; // input mode by default
	npu->i2c_pin_wr_state = ~0; // reset is active low
	if (platform.ocapi) {
		/* Find I2C port for handling device presence/reset */
		snprintf(port_name, sizeof(port_name), "p8_%08x_e%dp%d",
			 gcid, platform.ocapi->i2c_engine,
			 platform.ocapi->i2c_port);
		prlog(PR_DEBUG, "NPU: Looking for I2C port %s\n", port_name);

		dt_for_each_compatible(dt_root, np, "ibm,power9-i2c-port") {
			if (streq(port_name, dt_prop_get(np, "ibm,port-name"))) {
				npu->i2c_port_id_ocapi = dt_prop_get_u32(np, "ibm,opal-id");
				break;
			}
		}

		if (!npu->i2c_port_id_ocapi) {
			prlog(PR_ERR, "NPU: Couldn't find I2C port %s\n",
			      port_name);
			goto failed;
		}
	}

	npu->devices = npumem + sizeof(struct npu2);

	dt_for_each_compatible(dn, np, "ibm,npu-link") {
		assert(i < num_links);
		dev = &npu->devices[i];
		dev->link_index = dt_prop_get_u32(np, "ibm,npu-link-index");
		/* May be overridden by platform presence detection */
		dev->brick_index = dev->link_index;
		/* Will be overridden by presence detection */
		dev->type = NPU2_DEV_TYPE_UNKNOWN;
		dev->npu = npu;
		dev->dt_node = np;
		dev->pl_xscom_base = dt_prop_get_u64(np, "ibm,npu-phy");
		dev->lane_mask = dt_prop_get_u32(np, "ibm,npu-lane-mask");
		dev->link_speed = dt_prop_get_u64(np, "ibm,link-speed");
		i++;
	};
	npu->total_devices = i;

	prlog(PR_INFO, "NPU: Chip %d Found NPU2#%d (%d links) at %s\n",
	      npu->chip_id, npu->index, npu->total_devices, path);
	prlog(PR_INFO, "   SCOM Base:  %08llx\n", npu->xscom_base);
	free(path);
	return npu;

failed:
	prlog(PR_ERR, "NPU: Chip %d NPU setup failed\n", gcid);
	free(path);
	free(npu);
	return NULL;
}

static void setup_devices(struct npu2 *npu)
{
	bool nvlink_detected = false, ocapi_detected = false;
	struct npu2_dev *dev;

	/*
	 * TODO: In future, we'll do brick configuration here to support mixed
	 * setups.
	 */
	for (int i = 0; i < npu->total_devices; i++) {
		dev = &npu->devices[i];
		switch (dev->type) {
		case NPU2_DEV_TYPE_NVLINK:
			nvlink_detected = true;
			dt_add_property_strings(dev->dt_node,
						"ibm,npu-link-type",
						"nvlink");
			break;
		case NPU2_DEV_TYPE_OPENCAPI:
			ocapi_detected = true;
			dt_add_property_strings(dev->dt_node,
						"ibm,npu-link-type",
						"opencapi");
			break;
		default:
			prlog(PR_INFO, "NPU: Link %d device not present\n",
			      npu->devices[i].link_index);
			dt_add_property_strings(dev->dt_node,
						"ibm,npu-link-type",
						"unknown");
		}
	}

	if (nvlink_detected && ocapi_detected) {
		prlog(PR_ERR, "NPU: NVLink and OpenCAPI devices on same chip not supported, aborting NPU init\n");
		return;
	}

	setup_irqs(npu);

	if (nvlink_detected)
		npu2_nvlink_init_npu(npu);
	else if (ocapi_detected)
		npu2_opencapi_init_npu(npu);
}

void probe_npu2(void)
{
	struct proc_chip *chip = next_chip(NULL);
	struct npu2 *npu;
	struct dt_node *np;
	const char *zcal;

	/* npu2 only */
	if (!dt_find_compatible_node(dt_root, NULL, "ibm,power9-npu"))
		return;

	/* Abort if we're running on POWER9C DD1 (P9N DD1 is not supported) */
	if (chip &&
	    chip->type == PROC_CHIP_P9_CUMULUS &&
	    (chip->ec_level & 0xf0) == 0x10) {
		prlog(PR_INFO, "NPU2: DD1 not supported\n");
		return;
	}

	/* Check for a zcal override */
	zcal = nvram_query_dangerous("nv_zcal_override");
	if (zcal) {
		nv_zcal_nominal = atoi(zcal);
		prlog(PR_WARNING, "NPU2: Using ZCAL impedance override = %d\n", nv_zcal_nominal);
	}

	if (!platform.npu2_device_detect) {
		prlog(PR_INFO, "NPU: Platform does not support NPU\n");
		return;
	}

	dt_for_each_compatible(dt_root, np, "ibm,power9-npu") {
	        npu = setup_npu(np);
		if (!npu)
			continue;
		platform.npu2_device_detect(npu);
		setup_devices(npu);
	}
}
