// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * PHB3: PCI Host Bridge 3, in POWER8
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <io.h>
#include <timebase.h>
#include <pci-cfg.h>
#include <pci.h>
#include <pci-slot.h>
#include <vpd.h>
#include <interrupts.h>
#include <opal.h>
#include <cpu.h>
#include <device.h>
#include <ccan/str/str.h>
#include <ccan/array_size/array_size.h>
#include <xscom.h>
#include <affinity.h>
#include <phb3.h>
#include <phb3-regs.h>
#include <phb3-capp.h>
#include <capp.h>
#include <fsp.h>
#include <chip.h>
#include <chiptod.h>

/* Enable this to disable error interrupts for debug purposes */
#undef DISABLE_ERR_INTS

static void phb3_init_hw(struct phb3 *p, bool first_init);

#define PHBDBG(p, fmt, a...)	prlog(PR_DEBUG, "PHB#%04x: " fmt, \
				      (p)->phb.opal_id, ## a)
#define PHBINF(p, fmt, a...)	prlog(PR_INFO, "PHB#%04x: " fmt, \
				      (p)->phb.opal_id, ## a)
#define PHBERR(p, fmt, a...)	prlog(PR_ERR, "PHB#%04x: " fmt, \
				      (p)->phb.opal_id, ## a)

#define PE_CAPP_EN 0x9013c03

#define PE_REG_OFFSET(p) \
	((PHB3_IS_NAPLES(p) && (p)->index) ? 0x40 : 0x0)

/* Helper to select an IODA table entry */
static inline void phb3_ioda_sel(struct phb3 *p, uint32_t table,
				 uint32_t addr, bool autoinc)
{
	out_be64(p->regs + PHB_IODA_ADDR,
		 (autoinc ? PHB_IODA_AD_AUTOINC : 0)	|
		 SETFIELD(PHB_IODA_AD_TSEL, 0ul, table)	|
		 SETFIELD(PHB_IODA_AD_TADR, 0ul, addr));
}

static void phb3_eeh_dump_regs(struct phb3 *p,
				struct OpalIoPhb3ErrorData *regs);

/* Check if AIB is fenced via PBCQ NFIR */
static bool phb3_fenced(struct phb3 *p)
{
	uint64_t nfir;

	/* We still probably has crazy xscom */
	xscom_read(p->chip_id, p->pe_xscom + 0x0, &nfir);
	if (nfir & PPC_BIT(16)) {
		p->flags |= PHB3_AIB_FENCED;

		phb3_eeh_dump_regs(p, NULL);
		return true;
	}
	return false;
}

static int64_t phb3_pcicfg_rc_pref_window(void *dev __unused,
					  struct pci_cfg_reg_filter *pcrf,
					  uint32_t offset, uint32_t len,
					  uint32_t *data,  bool write)
{
	uint8_t *pdata;
	uint32_t i;

	/* Cache whatever we received */
	if (write) {
		pdata = &pcrf->data[offset - pcrf->start];
		for (i = 0; i < len; i++, pdata++)
			*pdata = (uint8_t)(*data >> (8 * i));
		return OPAL_SUCCESS;
	}

	/* Return whatever we cached */
	*data = 0;
	pdata = &pcrf->data[offset - pcrf->start + len - 1];
	for (i = len; i > 0; i--, pdata--) {
		*data = (*data) << 8;
		if (offset + i == PCI_CFG_PREF_MEM_BASE) {
			*data |= ((*pdata & 0xf0) | 0x1);
			continue;
		}

		*data |= *pdata;
	}

	return OPAL_SUCCESS;
}

/*
 * Configuration space access
 *
 * The PHB lock is assumed to be already held
 */
static int64_t phb3_pcicfg_check(struct phb3 *p, uint32_t bdfn,
				 uint32_t offset, uint32_t size,
				 uint8_t *pe)
{
	uint32_t sm = size - 1;

	if (offset > 0xfff || bdfn > 0xffff)
		return OPAL_PARAMETER;
	if (offset & sm)
		return OPAL_PARAMETER;

	/* The root bus only has a device at 0 and we get into an
	 * error state if we try to probe beyond that, so let's
	 * avoid that and just return an error to Linux
	 */
	if (PCI_BUS_NUM(bdfn) == 0 && (bdfn & 0xff))
		return OPAL_HARDWARE;

	/* Check PHB state */
	if (p->broken)
		return OPAL_HARDWARE;

	/* Fetch the PE# from cache */
	*pe = p->rte_cache[bdfn];

	return OPAL_SUCCESS;
}

static void phb3_link_update(struct phb *phb, uint16_t data)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint32_t new_spd, new_wid;
	uint32_t old_spd, old_wid;
	uint16_t old_data;
	uint64_t lreg;
	int i;

	/* Read the old speed and width */
	pci_cfg_read16(phb, 0, 0x5a, &old_data);

	/* Decode the register values */
	new_spd = data & PCICAP_EXP_LSTAT_SPEED;
	new_wid = (data & PCICAP_EXP_LSTAT_WIDTH) >> 4;
	old_spd = old_data & PCICAP_EXP_LSTAT_SPEED;
	old_wid = (old_data & PCICAP_EXP_LSTAT_WIDTH) >> 4;

	/* Apply maximums */
	if (new_wid > 16)
		new_wid = 16;
	if (new_wid < 1)
		new_wid = 1;
	if (new_spd > 3)
		new_spd = 3;
	if (new_spd < 1)
		new_spd = 1;

	PHBINF(p, "Link change request: speed %d->%d, width %d->%d\n",
	       old_spd, new_spd, old_wid, new_wid);

	/* Check if width needs to be changed */
	if (old_wid != new_wid) {
		PHBINF(p, "Changing width...\n");
		lreg = in_be64(p->regs + PHB_PCIE_LINK_MANAGEMENT);
		lreg = SETFIELD(PHB_PCIE_LM_TGT_LINK_WIDTH, lreg, new_wid);
		lreg |= PHB_PCIE_LM_CHG_LINK_WIDTH;
		out_be64(p->regs + PHB_PCIE_LINK_MANAGEMENT, lreg);
		for (i=0; i<10;i++) {
			lreg = in_be64(p->regs + PHB_PCIE_LINK_MANAGEMENT);
			if (lreg & PHB_PCIE_LM_DL_WCHG_PENDING)
				break;
			time_wait_ms_nopoll(1);
		}
		if (!(lreg & PHB_PCIE_LM_DL_WCHG_PENDING))
			PHBINF(p, "Timeout waiting for speed change start\n");
		for (i=0; i<100;i++) {
			lreg = in_be64(p->regs + PHB_PCIE_LINK_MANAGEMENT);
			if (!(lreg & PHB_PCIE_LM_DL_WCHG_PENDING))
				break;
			time_wait_ms_nopoll(1);
		}
		if (lreg & PHB_PCIE_LM_DL_WCHG_PENDING)
			PHBINF(p, "Timeout waiting for speed change end\n");
	}
	/* Check if speed needs to be changed */
	if (old_spd != new_spd) {
		PHBINF(p, "Changing speed...\n");
		lreg = in_be64(p->regs + PHB_PCIE_LINK_MANAGEMENT);
		if (lreg & PPC_BIT(19)) {
			uint16_t lctl2;
			PHBINF(p, " Bit19 set ! working around...\n");
			pci_cfg_read16(phb, 0, 0x78, &lctl2);
			PHBINF(p, " LCTL2=%04x\n", lctl2);
			lctl2 &= ~PCICAP_EXP_LCTL2_HWAUTSPDIS;
			pci_cfg_write16(phb, 0, 0x78, lctl2);
		}
		lreg = in_be64(p->regs + PHB_PCIE_LINK_MANAGEMENT);
		lreg = SETFIELD(PHB_PCIE_LM_TGT_SPEED, lreg, new_spd);
		lreg |= PHB_PCIE_LM_CHG_SPEED;
		out_be64(p->regs + PHB_PCIE_LINK_MANAGEMENT, lreg);
	}
}

static int64_t phb3_pcicfg_rc_link_speed(void *dev,
					 struct pci_cfg_reg_filter *pcrf __unused,
					 uint32_t offset, uint32_t len,
					 uint32_t *data,  bool write)
{
	struct pci_device *pd = dev;

	/* Hack for link speed changes. We intercept attempts at writing
	 * the link control/status register
	 */
	if (write && len == 4 && offset == 0x58) {
		phb3_link_update(pd->phb, (*data) >> 16);
		return OPAL_SUCCESS;
	}
	if (write && len == 2 && offset == 0x5a) {
		phb3_link_update(pd->phb, *(uint16_t *)data);
		return OPAL_SUCCESS;
	}

	return OPAL_PARTIAL;
}

#define PHB3_PCI_CFG_READ(size, type)	\
static int64_t phb3_pcicfg_read##size(struct phb *phb, uint32_t bdfn,	\
                                      uint32_t offset, type *data)	\
{									\
	struct phb3 *p = phb_to_phb3(phb);				\
	uint64_t addr, val64;						\
	int64_t rc;							\
	uint8_t pe;							\
	bool use_asb = false;						\
									\
	/* Initialize data in case of error */				\
	*data = (type)0xffffffff;					\
									\
	rc = phb3_pcicfg_check(p, bdfn, offset, sizeof(type), &pe);	\
	if (rc)								\
		return rc;						\
									\
	if (p->flags & PHB3_AIB_FENCED) {				\
		if (!(p->flags & PHB3_CFG_USE_ASB))			\
			return OPAL_HARDWARE;				\
		use_asb = true;						\
	} else if ((p->flags & PHB3_CFG_BLOCKED) && bdfn != 0) {	\
		return OPAL_HARDWARE;					\
	}								\
									\
	rc = pci_handle_cfg_filters(phb, bdfn, offset, sizeof(type),	\
				    (uint32_t *)data, false);		\
	if (rc != OPAL_PARTIAL)						\
		return rc;						\
									\
	addr = PHB_CA_ENABLE;						\
	addr = SETFIELD(PHB_CA_BDFN, addr, bdfn);			\
	addr = SETFIELD(PHB_CA_REG, addr, offset);			\
	addr = SETFIELD(PHB_CA_PE, addr, pe);				\
	if (use_asb) {							\
		phb3_write_reg_asb(p, PHB_CONFIG_ADDRESS, addr);	\
		sync();							\
		val64 = bswap_64(phb3_read_reg_asb(p, PHB_CONFIG_DATA));	\
		*data = (type)(val64 >> (8 * (offset & (4 - sizeof(type)))));	\
	} else {							\
		out_be64(p->regs + PHB_CONFIG_ADDRESS, addr);		\
		*data = in_le##size(p->regs + PHB_CONFIG_DATA +		\
				    (offset & (4 - sizeof(type))));	\
	}								\
									\
	return OPAL_SUCCESS;						\
}

#define PHB3_PCI_CFG_WRITE(size, type)	\
static int64_t phb3_pcicfg_write##size(struct phb *phb, uint32_t bdfn,	\
                                       uint32_t offset, type data)	\
{									\
	struct phb3 *p = phb_to_phb3(phb);				\
	uint64_t addr, val64 = 0;					\
	int64_t rc;							\
	uint8_t pe;							\
	bool use_asb = false;						\
									\
	rc = phb3_pcicfg_check(p, bdfn, offset, sizeof(type), &pe);	\
	if (rc)								\
		return rc;						\
									\
	if (p->flags & PHB3_AIB_FENCED) {				\
		if (!(p->flags & PHB3_CFG_USE_ASB))			\
			return OPAL_HARDWARE;				\
		use_asb = true;						\
	} else if ((p->flags & PHB3_CFG_BLOCKED) && bdfn != 0) {	\
		return OPAL_HARDWARE;					\
	}								\
									\
	rc = pci_handle_cfg_filters(phb, bdfn, offset, sizeof(type),	\
				    (uint32_t *)&data, true);		\
	if (rc != OPAL_PARTIAL)						\
		return rc;						\
									\
	addr = PHB_CA_ENABLE;						\
	addr = SETFIELD(PHB_CA_BDFN, addr, bdfn);			\
	addr = SETFIELD(PHB_CA_REG, addr, offset);			\
	addr = SETFIELD(PHB_CA_PE, addr, pe);				\
	if (use_asb) {							\
		val64 = data;						\
		val64 = bswap_64(val64 << 8 * (offset & (4 - sizeof(type))));	\
		phb3_write_reg_asb(p, PHB_CONFIG_ADDRESS, addr);	\
		sync();							\
		phb3_write_reg_asb(p, PHB_CONFIG_DATA, val64);		\
	} else {							\
		out_be64(p->regs + PHB_CONFIG_ADDRESS, addr);		\
		out_le##size(p->regs + PHB_CONFIG_DATA +		\
			     (offset & (4 - sizeof(type))), data);	\
	}								\
									\
        return OPAL_SUCCESS;						\
}

PHB3_PCI_CFG_READ(8, u8)
PHB3_PCI_CFG_READ(16, u16)
PHB3_PCI_CFG_READ(32, u32)
PHB3_PCI_CFG_WRITE(8, u8)
PHB3_PCI_CFG_WRITE(16, u16)
PHB3_PCI_CFG_WRITE(32, u32)

static int64_t phb3_get_reserved_pe_number(struct phb *phb __unused)
{
	return PHB3_RESERVED_PE_NUM;
}

static inline void phb3_enable_ecrc(struct phb *phb, bool enable)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint32_t ctl;

	if (p->aercap <= 0)
		return;

	pci_cfg_read32(phb, 0, p->aercap + PCIECAP_AER_CAPCTL, &ctl);
	if (enable) {
		ctl |= (PCIECAP_AER_CAPCTL_ECRCG_EN |
			PCIECAP_AER_CAPCTL_ECRCC_EN);
	} else {
		ctl &= ~(PCIECAP_AER_CAPCTL_ECRCG_EN |
			 PCIECAP_AER_CAPCTL_ECRCC_EN);
	}

	pci_cfg_write32(phb, 0, p->aercap + PCIECAP_AER_CAPCTL, ctl);
}

static void phb3_root_port_init(struct phb *phb, struct pci_device *dev,
				int ecap, int aercap)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint16_t bdfn = dev->bdfn;
	uint16_t val16;
	uint32_t val32;

	/* Use PHB's callback so that the UTL events will be masked
	 * or unmasked when the link is down or up.
	 */
	if (dev->slot && dev->slot->ops.prepare_link_change &&
	    phb->slot && phb->slot->ops.prepare_link_change)
		dev->slot->ops.prepare_link_change =
			phb->slot->ops.prepare_link_change;

	/* Mask UTL link down event if root slot supports surprise
	 * hotplug as the event should be handled by hotplug driver
	 * instead of EEH subsystem.
	 */
	if (dev->slot && dev->slot->surprise_pluggable)
		out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN, 0xad42800000000000UL);

	/* Enable SERR and parity checking */
	pci_cfg_read16(phb, bdfn, PCI_CFG_CMD, &val16);
	val16 |= (PCI_CFG_CMD_SERR_EN | PCI_CFG_CMD_PERR_RESP);
	pci_cfg_write16(phb, bdfn, PCI_CFG_CMD, val16);

	/* Enable reporting various errors */
	if (!ecap) return;
	pci_cfg_read16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, &val16);
	val16 |= (PCICAP_EXP_DEVCTL_CE_REPORT |
		  PCICAP_EXP_DEVCTL_NFE_REPORT |
		  PCICAP_EXP_DEVCTL_FE_REPORT |
		  PCICAP_EXP_DEVCTL_UR_REPORT);
	pci_cfg_write16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, val16);

	if (!aercap) return;

	/* Mask various unrecoverable errors. The link surprise down
	 * event should be masked when its PCI slot support surprise
	 * hotplug. The link surprise down event should be handled by
	 * PCI hotplug driver instead of EEH subsystem.
	 */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_UE_MASK, &val32);
	val32 |= (PCIECAP_AER_UE_MASK_POISON_TLP |
		  PCIECAP_AER_UE_MASK_COMPL_TIMEOUT |
		  PCIECAP_AER_UE_MASK_COMPL_ABORT |
		  PCIECAP_AER_UE_MASK_ECRC);
	if (dev->slot && dev->slot->surprise_pluggable)
		val32 |= PCIECAP_AER_UE_MASK_SURPRISE_DOWN;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_UE_MASK, val32);

	/* Report various unrecoverable errors as fatal errors */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_UE_SEVERITY, &val32);
	val32 |= (PCIECAP_AER_UE_SEVERITY_DLLP |
		  PCIECAP_AER_UE_SEVERITY_SURPRISE_DOWN |
		  PCIECAP_AER_UE_SEVERITY_FLOW_CTL_PROT |
		  PCIECAP_AER_UE_SEVERITY_UNEXP_COMPL |
		  PCIECAP_AER_UE_SEVERITY_RECV_OVFLOW |
		  PCIECAP_AER_UE_SEVERITY_MALFORMED_TLP);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_UE_SEVERITY, val32);

	/* Mask various recoverable errors */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CE_MASK, &val32);
	val32 |= PCIECAP_AER_CE_MASK_ADV_NONFATAL;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CE_MASK, val32);

	/* Enable ECRC check */
	phb3_enable_ecrc(phb, true);

	/* Enable all error reporting */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_RERR_CMD, &val32);
	val32 |= (PCIECAP_AER_RERR_CMD_FE |
		  PCIECAP_AER_RERR_CMD_NFE |
		  PCIECAP_AER_RERR_CMD_CE);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_RERR_CMD, val32);
}

static void phb3_switch_port_init(struct phb *phb,
				  struct pci_device *dev,
				  int ecap, int aercap)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint16_t bdfn = dev->bdfn;
	uint16_t val16;
	uint32_t val32;

	/* Enable SERR and parity checking and disable INTx */
	pci_cfg_read16(phb, bdfn, PCI_CFG_CMD, &val16);
	val16 |= (PCI_CFG_CMD_PERR_RESP |
		  PCI_CFG_CMD_SERR_EN |
		  PCI_CFG_CMD_INTx_DIS);
	pci_cfg_write16(phb, bdfn, PCI_CFG_CMD, val16);

	/* Disable partity error and enable system error */
	pci_cfg_read16(phb, bdfn, PCI_CFG_BRCTL, &val16);
	val16 &= ~PCI_CFG_BRCTL_PERR_RESP_EN;
	val16 |= PCI_CFG_BRCTL_SERR_EN;
	pci_cfg_write16(phb, bdfn, PCI_CFG_BRCTL, val16);

	/* Enable reporting various errors */
	if (!ecap) return;
	pci_cfg_read16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, &val16);
	val16 |= (PCICAP_EXP_DEVCTL_CE_REPORT |
		  PCICAP_EXP_DEVCTL_NFE_REPORT |
		  PCICAP_EXP_DEVCTL_FE_REPORT);
	/* HW279570 - Disable reporting of correctable errors */
	val16 &= ~PCICAP_EXP_DEVCTL_CE_REPORT;
	pci_cfg_write16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, val16);

	/* Unmask all unrecoverable errors for upstream port. For
	 * downstream port, the surprise link down is masked because
	 * it should be handled by hotplug driver instead of EEH
	 * subsystem.
	 */
	if (!aercap) return;
	if (dev->dev_type == PCIE_TYPE_SWITCH_DNPORT &&
	    dev->slot && dev->slot->surprise_pluggable)
		pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_UE_MASK,
				PCIECAP_AER_UE_MASK_SURPRISE_DOWN);
	else
		pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_UE_MASK, 0x0);

	/* Severity of unrecoverable errors */
	if (dev->dev_type == PCIE_TYPE_SWITCH_UPPORT)
		val32 = (PCIECAP_AER_UE_SEVERITY_DLLP |
			 PCIECAP_AER_UE_SEVERITY_SURPRISE_DOWN |
			 PCIECAP_AER_UE_SEVERITY_FLOW_CTL_PROT |
			 PCIECAP_AER_UE_SEVERITY_RECV_OVFLOW |
			 PCIECAP_AER_UE_SEVERITY_MALFORMED_TLP |
			 PCIECAP_AER_UE_SEVERITY_INTERNAL);
	else
		val32 = (PCIECAP_AER_UE_SEVERITY_FLOW_CTL_PROT |
			 PCIECAP_AER_UE_SEVERITY_INTERNAL);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_UE_SEVERITY, val32);

	/*
	 * Mask various correctable errors
	 *
         * On Murano and Venice DD1.0 we disable emission of corrected
         * error messages to the PHB completely to workaround errata
         * HW257476 causing the loss of tags.
	 */
	if (p->rev < PHB3_REV_MURANO_DD20)
		val32 = 0xffffffff;
	else
		val32 = PCIECAP_AER_CE_MASK_ADV_NONFATAL;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CE_MASK, val32);

	/* Enable ECRC generation and disable ECRC check */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, &val32);
	val32 |= PCIECAP_AER_CAPCTL_ECRCG_EN;
	val32 &= ~PCIECAP_AER_CAPCTL_ECRCC_EN;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, val32);
}

static void phb3_endpoint_init(struct phb *phb,
			       struct pci_device *dev,
			       int ecap, int aercap)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint16_t bdfn = dev->bdfn;
	uint16_t val16;
	uint32_t val32;

	/* Enable SERR and parity checking */
	pci_cfg_read16(phb, bdfn, PCI_CFG_CMD, &val16);
	val16 |= (PCI_CFG_CMD_PERR_RESP |
		  PCI_CFG_CMD_SERR_EN);
	pci_cfg_write16(phb, bdfn, PCI_CFG_CMD, val16);

	/* Enable reporting various errors */
	if (!ecap) return;
	pci_cfg_read16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, &val16);
	val16 &= ~PCICAP_EXP_DEVCTL_CE_REPORT;
	val16 |= (PCICAP_EXP_DEVCTL_NFE_REPORT |
		  PCICAP_EXP_DEVCTL_FE_REPORT |
		  PCICAP_EXP_DEVCTL_UR_REPORT);
	/* HW279570 - Disable reporting of correctable errors */
	val16 &= ~PCICAP_EXP_DEVCTL_CE_REPORT;
	pci_cfg_write16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, val16);

	/*
	 * On Murano and Venice DD1.0 we disable emission of corrected
	 * error messages to the PHB completely to workaround errata
	 * HW257476 causing the loss of tags.
	 */
	if (p->rev < PHB3_REV_MURANO_DD20)
		pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CE_MASK,
				0xffffffff);

	/* Enable ECRC generation and check */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, &val32);
	val32 |= (PCIECAP_AER_CAPCTL_ECRCG_EN |
		  PCIECAP_AER_CAPCTL_ECRCC_EN);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, val32);
}

static int64_t phb3_pcicfg_no_dstate(void *dev __unused,
				     struct pci_cfg_reg_filter *pcrf,
				     uint32_t offset, uint32_t len __unused,
				     uint32_t *data __unused,  bool write)
{
	uint32_t loff = offset - pcrf->start;

	/* Disable D-state change on children of the PHB. For now we
	 * simply block all writes to the PM control/status
	 */
	if (write && loff >= 4 && loff < 6)
		return OPAL_SUCCESS;

	return OPAL_PARTIAL;
}

static void phb3_check_device_quirks(struct phb *phb, struct pci_device *dev)
{
	struct phb3 *p = phb_to_phb3(phb);

	if (dev->primary_bus != 0 &&
	    dev->primary_bus != 1)
		return;

	if (dev->primary_bus == 1) {
		u64 modectl;

		/*
		 * For these adapters, if they are directly under the PHB, we
		 * adjust the disable_wr_scope_group bit for performances
		 *
		 * 15b3:1003   Mellanox Travis3-EN (CX3)
		 * 15b3:1011   Mellanox HydePark (ConnectIB)
		 * 15b3:1013   Mellanox GlacierPark (CX4)
		 */
		xscom_read(p->chip_id, p->pe_xscom + 0x0b, &modectl);
		if (PCI_VENDOR_ID(dev->vdid) == 0x15b3 &&
		    (PCI_DEVICE_ID(dev->vdid) == 0x1003	||
		     PCI_DEVICE_ID(dev->vdid) == 0x1011 ||
		     PCI_DEVICE_ID(dev->vdid) == 0x1013))
			modectl |= PPC_BIT(14);
		else
			modectl &= ~PPC_BIT(14);
		xscom_write(p->chip_id, p->pe_xscom + 0x0b, modectl);

		/*
		 * Naples has a problem with D-states at least on Mellanox CX4,
		 * disable changing D-state on Naples like we do it for PHB4.
		 */
		if (PHB3_IS_NAPLES(p) &&
		    pci_has_cap(dev, PCI_CFG_CAP_ID_PM, false)) {
			pci_add_cfg_reg_filter(dev,
					pci_cap(dev, PCI_CFG_CAP_ID_PM, false),
					8,
					PCI_REG_FLAG_WRITE,
					phb3_pcicfg_no_dstate);
		}
	} else if (dev->primary_bus == 0) {
		/*
		 * Emulate the prefetchable window of the root port
		 * when the corresponding HW registers are readonly.
		 *
		 * 1014:03dc   Root port on P8/P8E/P8NVL
		 */
		if (PCI_VENDOR_ID(dev->vdid) == 0x1014 &&
		    PCI_DEVICE_ID(dev->vdid) == 0x03dc) {
			uint32_t pref_hi, tmp;

			pci_cfg_read32(phb, dev->bdfn,
				PCI_CFG_PREF_MEM_BASE_U32, &pref_hi);
			pci_cfg_write32(phb, dev->bdfn,
				PCI_CFG_PREF_MEM_BASE_U32, ~pref_hi);
			pci_cfg_read32(phb, dev->bdfn,
				PCI_CFG_PREF_MEM_BASE_U32, &tmp);
			pci_cfg_write32(phb, dev->bdfn,
				PCI_CFG_PREF_MEM_BASE_U32, pref_hi);
			if (tmp == pref_hi)
				pci_add_cfg_reg_filter(dev,
					PCI_CFG_PREF_MEM_BASE_U32, 12,
					PCI_REG_FLAG_READ | PCI_REG_FLAG_WRITE,
					phb3_pcicfg_rc_pref_window);
			/* Add filter to control link speed */
			pci_add_cfg_reg_filter(dev,
					       0x58, 4,
					       PCI_REG_FLAG_WRITE,
					       phb3_pcicfg_rc_link_speed);
		}
	}
}

static inline int phb3_should_disable_ecrc(struct pci_device *pd)
{
	/*
	 * When we have PMC PCIe switch, we need disable ECRC on root port.
	 * Otherwise, the adapters behind the switch downstream ports might
	 * not probed successfully.
	 */
	if (pd->vdid == 0x854611f8)
		return true;

	return false;
}

static int phb3_device_init(struct phb *phb,
			    struct pci_device *dev,
			    void *data)
{
	struct phb3 *p = phb_to_phb3(phb);
	int ecap, aercap;

	/* Some special adapter tweaks for devices directly under the PHB */
	phb3_check_device_quirks(phb, dev);

	/* Common initialization for the device */
	pci_device_init(phb, dev);

	ecap = pci_cap(dev, PCI_CFG_CAP_ID_EXP, false);
	aercap = pci_cap(dev, PCIECAP_ID_AER, true);
	if (dev->dev_type == PCIE_TYPE_ROOT_PORT)
		phb3_root_port_init(phb, dev, ecap, aercap);
	else if (dev->dev_type == PCIE_TYPE_SWITCH_UPPORT ||
		 dev->dev_type == PCIE_TYPE_SWITCH_DNPORT)
		phb3_switch_port_init(phb, dev, ecap, aercap);
	else
		phb3_endpoint_init(phb, dev, ecap, aercap);

	/*
	 * Check if we need disable ECRC functionality on root port. It
	 * only happens when PCI topology changes, meaning it's skipped
	 * when reinitializing PCI device after EEH reset.
	 */
	if (!data && phb3_should_disable_ecrc(dev)) {
		if (p->no_ecrc_devs++ == 0)
			phb3_enable_ecrc(phb, false);
	}

	return 0;
}

static void phb3_device_remove(struct phb *phb, struct pci_device *pd)
{
	struct phb3 *p = phb_to_phb3(phb);

	if (!phb3_should_disable_ecrc(pd) || p->no_ecrc_devs == 0)
		return;

	if (--p->no_ecrc_devs == 0)
		phb3_enable_ecrc(phb, true);
}

static int64_t phb3_pci_reinit(struct phb *phb, uint64_t scope, uint64_t data)
{
	struct pci_device *pd;
	uint16_t bdfn = data;
	int ret;

	if (scope != OPAL_REINIT_PCI_DEV)
		return OPAL_PARAMETER;

	pd = pci_find_dev(phb, bdfn);
	if (!pd)
		return OPAL_PARAMETER;

	ret = phb3_device_init(phb, pd, pd);
	if (ret)
		return OPAL_HARDWARE;

	return OPAL_SUCCESS;
}

/* Clear IODA cache tables */
static void phb3_init_ioda_cache(struct phb3 *p)
{
	uint32_t i;
	uint64_t *data64;

	/*
	 * RTT and PELTV. RTE should be 0xFF's to indicate
	 * invalid PE# for the corresponding RID.
	 *
	 * Note: Instead we set all RTE entries to 0x00 to
	 * work around a problem where PE lookups might be
	 * done before Linux has established valid PE's
	 * (during PCI probing). We can revisit that once/if
	 * Linux has been fixed to always setup valid PEs.
	 *
	 * The value 0x00 corresponds to the default PE# Linux
	 * uses to check for config space freezes before it
	 * has assigned PE# to busses.
	 *
	 * WARNING: Additionally, we need to be careful, there's
	 * a HW issue, if we get an MSI on an RTT entry that is
	 * FF, things will go bad. We need to ensure we don't
	 * ever let a live FF RTT even temporarily when resetting
	 * for EEH etc... (HW278969).
	 */
	for (i = 0; i < ARRAY_SIZE(p->rte_cache); i++)
		p->rte_cache[i] = PHB3_RESERVED_PE_NUM;
	memset(p->peltv_cache, 0x0,  sizeof(p->peltv_cache));

	/* Disable all LSI */
	for (i = 0; i < ARRAY_SIZE(p->lxive_cache); i++) {
		data64 = &p->lxive_cache[i];
		*data64 = SETFIELD(IODA2_LXIVT_PRIORITY, 0ul, 0xff);
		*data64 = SETFIELD(IODA2_LXIVT_SERVER, *data64, 0x0);
	}

	/* Diable all MSI */
	for (i = 0; i < ARRAY_SIZE(p->ive_cache); i++) {
		data64 = &p->ive_cache[i];
		*data64 = SETFIELD(IODA2_IVT_PRIORITY, 0ul, 0xff);
		*data64 = SETFIELD(IODA2_IVT_SERVER, *data64, 0x0);
	}

	/* Clear TVT */
	memset(p->tve_cache, 0x0, sizeof(p->tve_cache));
	/* Clear M32 domain */
	memset(p->m32d_cache, 0x0, sizeof(p->m32d_cache));
	/* Clear M64 domain */
	memset(p->m64b_cache, 0x0, sizeof(p->m64b_cache));
}

/* phb3_ioda_reset - Reset the IODA tables
 *
 * @purge: If true, the cache is cleared and the cleared values
 *         are applied to HW. If false, the cached values are
 *         applied to HW
 *
 * This reset the IODA tables in the PHB. It is called at
 * initialization time, on PHB reset, and can be called
 * explicitly from OPAL
 */
static int64_t phb3_ioda_reset(struct phb *phb, bool purge)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t server, prio;
	uint64_t *pdata64, data64;
	uint32_t i;

	if (purge) {
		prlog(PR_DEBUG, "PHB%x: Purging all IODA tables...\n",
		      p->phb.opal_id);
		phb3_init_ioda_cache(p);
	}

	/* Init_27..28 - LIXVT */
	phb3_ioda_sel(p, IODA2_TBL_LXIVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->lxive_cache); i++) {
		data64 = p->lxive_cache[i];
		server = GETFIELD(IODA2_LXIVT_SERVER, data64);
		prio = GETFIELD(IODA2_LXIVT_PRIORITY, data64);
		data64 = SETFIELD(IODA2_LXIVT_SERVER, data64, server);
		data64 = SETFIELD(IODA2_LXIVT_PRIORITY, data64, prio);
		out_be64(p->regs + PHB_IODA_DATA0, data64);
	}

	/* Init_29..30 - MRT */
	phb3_ioda_sel(p, IODA2_TBL_MRT, 0, true);
	for (i = 0; i < 8; i++)
		out_be64(p->regs + PHB_IODA_DATA0, 0);

	/* Init_31..32 - TVT */
	phb3_ioda_sel(p, IODA2_TBL_TVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->tve_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->tve_cache[i]);

	/* Init_33..34 - M64BT */
	phb3_ioda_sel(p, IODA2_TBL_M64BT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->m64b_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->m64b_cache[i]);

	/* Init_35..36 - M32DT */
	phb3_ioda_sel(p, IODA2_TBL_M32DT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->m32d_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->m32d_cache[i]);

	/* Load RTE, PELTV */
	if (p->tbl_rtt)
		memcpy((void *)p->tbl_rtt, p->rte_cache, RTT_TABLE_SIZE);
	if (p->tbl_peltv)
		memcpy((void *)p->tbl_peltv, p->peltv_cache, PELTV_TABLE_SIZE);

	/* Load IVT */
	if (p->tbl_ivt) {
		pdata64 = (uint64_t *)p->tbl_ivt;
		for (i = 0; i < IVT_TABLE_ENTRIES; i++)
			pdata64[i * IVT_TABLE_STRIDE] = p->ive_cache[i];
	}

	/* Invalidate RTE, IVE, TCE cache */
	out_be64(p->regs + PHB_RTC_INVALIDATE, PHB_RTC_INVALIDATE_ALL);
	out_be64(p->regs + PHB_IVC_INVALIDATE, PHB_IVC_INVALIDATE_ALL);
	out_be64(p->regs + PHB_TCE_KILL, PHB_TCE_KILL_ALL);

	/* Clear RBA */
	if (p->rev >= PHB3_REV_MURANO_DD20) {
		phb3_ioda_sel(p, IODA2_TBL_RBA, 0, true);
		for (i = 0; i < 32; i++)
			out_be64(p->regs + PHB_IODA_DATA0, 0x0ul);
	}

	/* Clear PEST & PEEV */
	for (i = 0; i < PHB3_MAX_PE_NUM; i++) {
		uint64_t pesta, pestb;

		phb3_ioda_sel(p, IODA2_TBL_PESTA, i, false);
		pesta = in_be64(p->regs + PHB_IODA_DATA0);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
		phb3_ioda_sel(p, IODA2_TBL_PESTB, i, false);
		pestb = in_be64(p->regs + PHB_IODA_DATA0);
		out_be64(p->regs + PHB_IODA_DATA0, 0);

		if ((pesta & IODA2_PESTA_MMIO_FROZEN) ||
		    (pestb & IODA2_PESTB_DMA_STOPPED))
			PHBDBG(p, "Frozen PE#%x (%s - %s)\n",
			       i, (pesta & IODA2_PESTA_MMIO_FROZEN) ? "DMA" : "",
			       (pestb & IODA2_PESTB_DMA_STOPPED) ? "MMIO" : "");
	}

	phb3_ioda_sel(p, IODA2_TBL_PEEV, 0, true);
	for (i = 0; i < 4; i++)
		out_be64(p->regs + PHB_IODA_DATA0, 0);

	return OPAL_SUCCESS;
}

/*
 * Clear anything we have in PAPR Error Injection registers. Though
 * the spec says the PAPR error injection should be one-shot without
 * the "sticky" bit. However, that's false according to the experiments
 * I had. So we have to clear it at appropriate point in kernel to
 * avoid endless frozen PE.
 */
static int64_t phb3_papr_errinjct_reset(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	out_be64(p->regs + PHB_PAPR_ERR_INJ_CTL, 0x0ul);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_ADDR, 0x0ul);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_MASK, 0x0ul);

	return OPAL_SUCCESS;
}

static int64_t phb3_set_phb_mem_window(struct phb *phb,
				       uint16_t window_type,
				       uint16_t window_num,
				       uint64_t addr,
				       uint64_t __unused pci_addr,
				       uint64_t size)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t data64;

	/*
	 * By design, PHB3 doesn't support IODT any more.
	 * Besides, we can't enable M32 BAR as well. So
	 * the function is used to do M64 mapping and each
	 * BAR is supposed to be shared by all PEs.
	 */
	switch (window_type) {
	case OPAL_IO_WINDOW_TYPE:
	case OPAL_M32_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num >= 16)
			return OPAL_PARAMETER;

		data64 = p->m64b_cache[window_num];
		if (data64 & IODA2_M64BT_SINGLE_PE) {
			if ((addr & 0x1FFFFFFul) ||
			    (size & 0x1FFFFFFul))
				return OPAL_PARAMETER;
		} else {
			if ((addr & 0xFFFFFul) ||
			    (size & 0xFFFFFul))
				return OPAL_PARAMETER;
		}

		/* size should be 2^N */
		if (!size || size & (size-1))
			return OPAL_PARAMETER;

		/* address should be size aligned */
		if (addr & (size - 1))
			return OPAL_PARAMETER;

		break;
	default:
		return OPAL_PARAMETER;
	}

	if (data64 & IODA2_M64BT_SINGLE_PE) {
		data64 = SETFIELD(IODA2_M64BT_SINGLE_BASE, data64,
				  addr >> 25);
		data64 = SETFIELD(IODA2_M64BT_SINGLE_MASK, data64,
				  0x20000000 - (size >> 25));
	} else {
		data64 = SETFIELD(IODA2_M64BT_BASE, data64,
				  addr >> 20);
		data64 = SETFIELD(IODA2_M64BT_MASK, data64,
				  0x40000000 - (size >> 20));
	}
	p->m64b_cache[window_num] = data64;

	return OPAL_SUCCESS;
}

/*
 * For one specific M64 BAR, it can be shared by all PEs,
 * or owned by single PE exclusively.
 */
static int64_t phb3_phb_mmio_enable(struct phb *phb,
				    uint16_t window_type,
				    uint16_t window_num,
				    uint16_t enable)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t data64, base, mask;

	/*
	 * By design, PHB3 doesn't support IODT any more.
	 * Besides, we can't enable M32 BAR as well. So
	 * the function is used to do M64 mapping and each
	 * BAR is supposed to be shared by all PEs.
	 */
	switch (window_type) {
	case OPAL_IO_WINDOW_TYPE:
	case OPAL_M32_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num >= 16 ||
		    enable > OPAL_ENABLE_M64_NON_SPLIT)
			return OPAL_PARAMETER;
		break;
	default:
		return OPAL_PARAMETER;
	}

	/*
	 * We need check the base/mask while enabling
	 * the M64 BAR. Otherwise, invalid base/mask
	 * might cause fenced AIB unintentionally
	 */
	data64 = p->m64b_cache[window_num];
	switch (enable) {
	case OPAL_DISABLE_M64:
		data64 &= ~IODA2_M64BT_SINGLE_PE;
		data64 &= ~IODA2_M64BT_ENABLE;
		break;
	case OPAL_ENABLE_M64_SPLIT:
		if (data64 & IODA2_M64BT_SINGLE_PE)
			return OPAL_PARAMETER;
		base = GETFIELD(IODA2_M64BT_BASE, data64);
		base = (base << 20);
		mask = GETFIELD(IODA2_M64BT_MASK, data64);
		if (base < p->mm0_base || !mask)
			return OPAL_PARTIAL;

		data64 |= IODA2_M64BT_ENABLE;
		break;
	case OPAL_ENABLE_M64_NON_SPLIT:
		if (!(data64 & IODA2_M64BT_SINGLE_PE))
			return OPAL_PARAMETER;
		base = GETFIELD(IODA2_M64BT_SINGLE_BASE, data64);
		base = (base << 25);
		mask = GETFIELD(IODA2_M64BT_SINGLE_MASK, data64);
		if (base < p->mm0_base || !mask)
			return OPAL_PARTIAL;

		data64 |= IODA2_M64BT_SINGLE_PE;
		data64 |= IODA2_M64BT_ENABLE;
		break;
	}

	/* Update HW and cache */
	phb3_ioda_sel(p, IODA2_TBL_M64BT, window_num, false);
	out_be64(p->regs + PHB_IODA_DATA0, data64);
	p->m64b_cache[window_num] = data64;
	return OPAL_SUCCESS;
}

static int64_t phb3_map_pe_mmio_window(struct phb *phb,
				       uint64_t pe_number,
				       uint16_t window_type,
				       uint16_t window_num,
				       uint16_t segment_num)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t data64, *cache;

	if (pe_number >= PHB3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	/*
	 * PHB3 doesn't support IODT any more. On the other
	 * hand, PHB3 support M64DT with much more flexibility.
	 * we need figure it out later. At least, we never use
	 * M64DT in kernel.
	 */
	switch(window_type) {
	case OPAL_IO_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M32_WINDOW_TYPE:
		if (window_num != 0 || segment_num >= PHB3_MAX_PE_NUM)
			return OPAL_PARAMETER;

		cache = &p->m32d_cache[segment_num];
		phb3_ioda_sel(p, IODA2_TBL_M32DT, segment_num, false);
		out_be64(p->regs + PHB_IODA_DATA0,
			 SETFIELD(IODA2_M32DT_PE, 0ull, pe_number));
		*cache = SETFIELD(IODA2_M32DT_PE, 0ull, pe_number);

		break;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num >= 16)
			return OPAL_PARAMETER;
		cache = &p->m64b_cache[window_num];
		data64 = *cache;

		/* The BAR shouldn't be enabled yet */
		if (data64 & IODA2_M64BT_ENABLE)
			return OPAL_PARTIAL;

		data64 |= IODA2_M64BT_SINGLE_PE;
		data64 = SETFIELD(IODA2_M64BT_PE_HI, data64, pe_number >> 5);
		data64 = SETFIELD(IODA2_M64BT_PE_LOW, data64, pe_number);
		*cache = data64;

		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_map_pe_dma_window(struct phb *phb,
				      uint64_t pe_number,
				      uint16_t window_id,
				      uint16_t tce_levels,
				      uint64_t tce_table_addr,
				      uint64_t tce_table_size,
				      uint64_t tce_page_size)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t tts_encoded;
	uint64_t data64 = 0;

	/*
	 * Sanity check. We currently only support "2 window per PE" mode
	 * ie, only bit 59 of the PCI address is used to select the window
	 */
	if (pe_number >= PHB3_MAX_PE_NUM ||
	    (window_id >> 1) != pe_number)
		return OPAL_PARAMETER;

	/*
	 * tce_table_size == 0 is used to disable an entry, in this case
	 * we ignore other arguments
	 */
	if (tce_table_size == 0) {
		phb3_ioda_sel(p, IODA2_TBL_TVT, window_id, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
		p->tve_cache[window_id] = 0;
		return OPAL_SUCCESS;
	}

	/* Additional arguments validation */
	if (tce_levels < 1 || tce_levels > 5 ||
	    !is_pow2(tce_table_size) ||
	    tce_table_size < 0x1000)
		return OPAL_PARAMETER;

	/* Encode TCE table size */
	data64 = SETFIELD(IODA2_TVT_TABLE_ADDR, 0ul, tce_table_addr >> 12);
	tts_encoded = ilog2(tce_table_size) - 11;
	if (tts_encoded > 31)
		return OPAL_PARAMETER;
	data64 = SETFIELD(IODA2_TVT_TCE_TABLE_SIZE, data64, tts_encoded);

	/* Encode TCE page size */
	switch (tce_page_size) {
	case 0x1000:	/* 4K */
		data64 = SETFIELD(IODA2_TVT_IO_PSIZE, data64, 1);
		break;
	case 0x10000:	/* 64K */
		data64 = SETFIELD(IODA2_TVT_IO_PSIZE, data64, 5);
		break;
	case 0x1000000:	/* 16M */
		data64 = SETFIELD(IODA2_TVT_IO_PSIZE, data64, 13);
		break;
	case 0x10000000: /* 256M */
		data64 = SETFIELD(IODA2_TVT_IO_PSIZE, data64, 17);
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* Encode number of levels */
	data64 = SETFIELD(IODA2_TVT_NUM_LEVELS, data64, tce_levels - 1);

	phb3_ioda_sel(p, IODA2_TBL_TVT, window_id, false);
	out_be64(p->regs + PHB_IODA_DATA0, data64);
	p->tve_cache[window_id] = data64;

	return OPAL_SUCCESS;
}

static int64_t phb3_map_pe_dma_window_real(struct phb *phb,
					   uint64_t pe_number,
					   uint16_t window_id,
					   uint64_t pci_start_addr,
					   uint64_t pci_mem_size)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t end;
	uint64_t tve;

	if (pe_number >= PHB3_MAX_PE_NUM ||
	    (window_id >> 1) != pe_number)
		return OPAL_PARAMETER;

	if (pci_mem_size) {
		/* Enable */

		/*
		 * Check that the start address has the right TVE index,
		 * we only support the 1 bit mode where each PE has 2
		 * TVEs
		 */
		if ((pci_start_addr >> 59) != (window_id & 1))
			return OPAL_PARAMETER;
		pci_start_addr &= ((1ull << 59) - 1);
		end = pci_start_addr + pci_mem_size;

		/* We have to be 16M aligned */
		if ((pci_start_addr & 0x00ffffff) ||
		    (pci_mem_size & 0x00ffffff))
			return OPAL_PARAMETER;

		/*
		 * It *looks* like this is the max we can support (we need
		 * to verify this. Also we are not checking for rollover,
		 * but then we aren't trying too hard to protect ourselves
		 * againt a completely broken OS.
		 */
		if (end > 0x0003ffffffffffffull)
			return OPAL_PARAMETER;

		/*
		 * Put start address bits 49:24 into TVE[52:53]||[0:23]
		 * and end address bits 49:24 into TVE[54:55]||[24:47]
		 * and set TVE[51]
		 */
		tve  = (pci_start_addr << 16) & (0xffffffull << 48);
		tve |= (pci_start_addr >> 38) & (3ull << 10);
		tve |= (end >>  8) & (0xfffffful << 16);
		tve |= (end >> 40) & (3ull << 8);
		tve |= PPC_BIT(51);
	} else {
		/* Disable */
		tve = 0;
	}

	phb3_ioda_sel(p, IODA2_TBL_TVT, window_id, false);
	out_be64(p->regs + PHB_IODA_DATA0, tve);
	p->tve_cache[window_id] = tve;

	return OPAL_SUCCESS;
}

static bool phb3_pci_msi_check_q(struct phb3 *p, uint32_t ive_num)
{
	uint64_t ive, ivc, ffi, state;
	uint8_t *q_byte;

	/* Each IVE has 16-bytes or 128-bytes */
	ive = p->tbl_ivt + (ive_num * IVT_TABLE_STRIDE * 8);
	q_byte = (uint8_t *)(ive + 5);

	/*
	 * Handle Q bit. If the Q bit doesn't show up,
	 * we would have CI load to make that.
	 */
	if (!(*q_byte & 0x1)) {
		/* Read from random PHB reg to force flush */
		in_be64(p->regs + PHB_IVC_UPDATE);

		/* Order with subsequent read of Q */
		sync();

		/* Q still not set, bail out */
		if (!(*q_byte & 0x1))
			return false;
	}

	/* Lock FFI and send interrupt */
	while (1) {
		state = in_be64(p->regs + PHB_FFI_LOCK);
		if (!state)
			break;
		if (state == ~0ULL) /* PHB Fenced */
			return false;
	}

	/* Clear Q bit and update IVC */
	*q_byte = 0;
	ivc = SETFIELD(PHB_IVC_UPDATE_SID, 0ul, ive_num) |
		PHB_IVC_UPDATE_ENABLE_Q;
	out_be64(p->regs + PHB_IVC_UPDATE, ivc);

	/*
	 * Resend interrupt. Note the lock clear bit isn't documented in
	 * the PHB3 spec and thus is probably unnecessary but it's in
	 * IODA2 so let's be safe here, it won't hurt to set it
	 */
	ffi = SETFIELD(PHB_FFI_REQUEST_ISN, 0ul, ive_num) | PHB_FFI_LOCK_CLEAR;
	out_be64(p->regs + PHB_FFI_REQUEST, ffi);

	return true;
}

static void phb3_pci_msi_flush_ive(struct phb3 *p, uint32_t ive_num)
{
	asm volatile("dcbf %0,%1"
		     :
		     : "b" (p->tbl_ivt), "r" (ive_num * IVT_TABLE_STRIDE * 8)
		     : "memory");
}

static int64_t phb3_pci_msi_eoi(struct phb *phb,
				uint32_t hwirq)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint32_t ive_num = PHB3_IRQ_NUM(hwirq);
	uint64_t ive, ivc;
	uint8_t *p_byte, gp, gen, newgen;

	/* OS might not configure IVT yet */
	if (!p->tbl_ivt)
		return OPAL_HARDWARE;

	/* Each IVE has 16-bytes or 128-bytes */
	ive = p->tbl_ivt + (ive_num * IVT_TABLE_STRIDE * 8);
	p_byte = (uint8_t *)(ive + 4);

	/* Read generation and P */
	gp = *p_byte;
	gen = (gp >> 1) & 3;
	newgen = (gen + 1) & 3;

	/* Increment generation count and clear P */
	*p_byte = newgen << 1;

	/* If at this point:
	 *   - the IVC is invalid (due to high IRQ load) and
	 *   - we get a new interrupt on this hwirq.
	 * Due to the new interrupt, the IVC will fetch from the IVT.
	 * This IVC reload will result in P set and gen=n+1.  This
	 * interrupt may not actually be delievered at this point
	 * though.
	 *
	 * Software will then try to clear P in the IVC (out_be64
	 * below).  This could cause an interrupt to be lost because P
	 * is cleared in the IVC without the new interrupt being
	 * delivered.
	 *
	 * To avoid this race, we increment the generation count in
	 * the IVT when we clear P. When software writes the IVC with
	 * P cleared but with gen=n, the IVC won't actually clear P
	 * because gen doesn't match what it just cached from the IVT.
	 * Hence we don't lose P being set.
	 */

	/* Update the P bit in the IVC is gen count matches */
	ivc = SETFIELD(PHB_IVC_UPDATE_SID, 0ul, ive_num) |
		PHB_IVC_UPDATE_ENABLE_P |
		PHB_IVC_UPDATE_ENABLE_GEN |
		PHB_IVC_UPDATE_ENABLE_CON |
		SETFIELD(PHB_IVC_UPDATE_GEN_MATCH, 0ul, gen) |
		SETFIELD(PHB_IVC_UPDATE_GEN, 0ul, newgen);
	/* out_be64 has a sync to order with the IVT update above */
	out_be64(p->regs + PHB_IVC_UPDATE, ivc);

	/* Handle Q bit */
	phb3_pci_msi_check_q(p, ive_num);

	phb3_pci_msi_flush_ive(p, ive_num);

	return OPAL_SUCCESS;
}

static int64_t phb3_set_ive_pe(struct phb *phb,
			       uint64_t pe_number,
			       uint32_t ive_num)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t *cache, ivep, data64;
	uint16_t *pe_word;

	/* OS should enable the BAR in advance */
	if (!p->tbl_ivt)
		return OPAL_HARDWARE;

	/* Each IVE reserves 128 bytes */
	if (pe_number >= PHB3_MAX_PE_NUM ||
	    ive_num >= IVT_TABLE_ENTRIES)
		return OPAL_PARAMETER;

	/* Update IVE cache */
	cache = &p->ive_cache[ive_num];
	*cache = SETFIELD(IODA2_IVT_PE, *cache, pe_number);

	/* Update in-memory IVE without clobbering P and Q */
	ivep = p->tbl_ivt + (ive_num * IVT_TABLE_STRIDE * 8);
	pe_word = (uint16_t *)(ivep + 6);
	*pe_word = pe_number;

	/* Invalidate IVC */
	data64 = SETFIELD(PHB_IVC_INVALIDATE_SID, 0ul, ive_num);
	out_be64(p->regs + PHB_IVC_INVALIDATE, data64);

	return OPAL_SUCCESS;
}

static int64_t phb3_get_msi_32(struct phb *phb __unused,
			       uint64_t pe_number,
			       uint32_t ive_num,
			       uint8_t msi_range,
			       uint32_t *msi_address,
			       uint32_t *message_data)
{
	/*
	 * Sanity check. We needn't check on mve_number (PE#)
	 * on PHB3 since the interrupt source is purely determined
	 * by its DMA address and data, but the check isn't
	 * harmful.
	 */
	if (pe_number >= PHB3_MAX_PE_NUM ||
	    ive_num >= IVT_TABLE_ENTRIES ||
	    msi_range != 1 || !msi_address|| !message_data)
		return OPAL_PARAMETER;

	/*
	 * DMA address and data will form the IVE index.
	 * For more details, please refer to IODA2 spec.
	 */
	*msi_address = 0xFFFF0000 | ((ive_num << 4) & 0xFFFFFE0F);
	*message_data = ive_num & 0x1F;

	return OPAL_SUCCESS;
}

static int64_t phb3_get_msi_64(struct phb *phb __unused,
			       uint64_t pe_number,
			       uint32_t ive_num,
			       uint8_t msi_range,
			       uint64_t *msi_address,
			       uint32_t *message_data)
{
	/* Sanity check */
	if (pe_number >= PHB3_MAX_PE_NUM ||
	    ive_num >= IVT_TABLE_ENTRIES ||
	    msi_range != 1 || !msi_address || !message_data)
		return OPAL_PARAMETER;

	/*
	 * DMA address and data will form the IVE index.
	 * For more details, please refer to IODA2 spec.
	 */
	*msi_address = (0x1ul << 60) | ((ive_num << 4) & 0xFFFFFFFFFFFFFE0Ful);
	*message_data = ive_num & 0x1F;

	return OPAL_SUCCESS;
}

static bool phb3_err_check_pbcq(struct phb3 *p)
{
	uint64_t nfir, mask, wof, val64;
	int32_t class, bit;
	uint64_t severity[PHB3_ERR_CLASS_LAST] = {
		0x0000000000000000UL,	/* NONE	*/
		0x018000F800000000UL,	/* DEAD */
		0x7E7DC70000000000UL,	/* FENCED */
		0x0000000000000000UL,	/* ER	*/
		0x0000000000000000UL	/* INF	*/
	};

	/*
	 * Read on NFIR to see if XSCOM is working properly.
	 * If XSCOM doesn't work well, we need take the PHB
	 * into account any more.
	 */
	xscom_read(p->chip_id, p->pe_xscom + 0x0, &nfir);
	if (nfir == 0xffffffffffffffffUL) {
		p->err.err_src = PHB3_ERR_SRC_NONE;
		p->err.err_class = PHB3_ERR_CLASS_DEAD;
		phb3_set_err_pending(p, true);
		return true;
	}

	/*
	 * Check WOF. We need handle unmasked errors firstly.
	 * We probably run into the situation (on simulator)
	 * where we have asserted FIR bits, but WOF has nothing.
	 * For that case, we should check FIR as well.
	 */
	xscom_read(p->chip_id, p->pe_xscom + 0x3, &mask);
	xscom_read(p->chip_id, p->pe_xscom + 0x8, &wof);
	if (wof & ~mask)
		wof &= ~mask;
	if (!wof) {
		if (nfir & ~mask)
			nfir &= ~mask;
		if (!nfir)
			return false;
		wof = nfir;
	}

	/* We shouldn't hit class PHB3_ERR_CLASS_NONE */
	for (class = PHB3_ERR_CLASS_NONE;
	     class < PHB3_ERR_CLASS_LAST;
	     class++) {
		val64 = wof & severity[class];
		if (!val64)
			continue;

		for (bit = 0; bit < 64; bit++) {
			if (val64 & PPC_BIT(bit)) {
				p->err.err_src = PHB3_ERR_SRC_PBCQ;
				p->err.err_class = class;
				p->err.err_bit = 63 - bit;
				phb3_set_err_pending(p, true);
				return true;
			}
		}
	}

	return false;
}

static bool phb3_err_check_lem(struct phb3 *p)
{
	uint64_t fir, wof, mask, val64;
	int32_t class, bit;
	uint64_t severity[PHB3_ERR_CLASS_LAST] = {
		0x0000000000000000UL,	/* NONE */
		0x0000000000000000UL,	/* DEAD */
		0xADB670C980ADD151UL,	/* FENCED */
		0x000800107F500A2CUL,	/* ER   */
		0x42018E2200002482UL	/* INF  */
	};

	/*
	 * Read FIR. If XSCOM or ASB is frozen, we needn't
	 * go forward and just mark the PHB with dead state
	 */
	fir = phb3_read_reg_asb(p, PHB_LEM_FIR_ACCUM);
	if (fir == 0xffffffffffffffffUL) {
		p->err.err_src = PHB3_ERR_SRC_PHB;
		p->err.err_class = PHB3_ERR_CLASS_DEAD;
		phb3_set_err_pending(p, true);
		return true;
	}

	/*
	 * Check on WOF for the unmasked errors firstly. Under
	 * some situation where we run skiboot on simulator,
	 * we already had FIR bits asserted, but WOF is still zero.
	 * For that case, we check FIR directly.
	 */
	wof = phb3_read_reg_asb(p, PHB_LEM_WOF);
	mask = phb3_read_reg_asb(p, PHB_LEM_ERROR_MASK);
	if (wof & ~mask)
		wof &= ~mask;
	if (!wof) {
		if (fir & ~mask)
			fir &= ~mask;
		if (!fir)
			return false;
		wof = fir;
	}

	/* We shouldn't hit PHB3_ERR_CLASS_NONE */
	for (class = PHB3_ERR_CLASS_NONE;
	     class < PHB3_ERR_CLASS_LAST;
	     class++) {
		val64 = wof & severity[class];
		if (!val64)
			continue;

		for (bit = 0; bit < 64; bit++) {
			if (val64 & PPC_BIT(bit)) {
				p->err.err_src = PHB3_ERR_SRC_PHB;
				p->err.err_class = class;
				p->err.err_bit = 63 - bit;
				phb3_set_err_pending(p, true);
				return true;
			}
		}
	}

	return false;
}

/*
 * The function can be called during error recovery for INF
 * and ER class. For INF case, it's expected to be called
 * when grabbing the error log. We will call it explicitly
 * when clearing frozen PE state for ER case.
 */
static void phb3_err_ER_clear(struct phb3 *p)
{
	uint32_t val32;
	uint64_t val64;
	uint64_t fir = in_be64(p->regs + PHB_LEM_FIR_ACCUM);

	/* Rec 1: Grab the PCI config lock */
	/* Removed... unnecessary. We have our own lock here */

	/* Rec 2/3/4: Take all inbound transactions */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000001c00000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0x10000000);

	/* Rec 5/6/7: Clear pending non-fatal errors */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000005000000000ul);
	val32 = in_be32(p->regs + PHB_CONFIG_DATA);
	out_be32(p->regs + PHB_CONFIG_DATA, (val32 & 0xe0700000) | 0x0f000f00);

	/* Rec 8/9/10: Clear pending fatal errors for AER */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000010400000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 11/12/13: Clear pending non-fatal errors for AER */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000011000000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 22/23/24: Clear root port errors */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000013000000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0xffffffff);

	/* Rec 25/26/27: Enable IO and MMIO bar */
	out_be64(p->regs + PHB_CONFIG_ADDRESS, 0x8000004000000000ul);
	out_be32(p->regs + PHB_CONFIG_DATA, 0x470100f8);

	/* Rec 28: Release the PCI config lock */
	/* Removed... unnecessary. We have our own lock here */

	/* Rec 29...34: Clear UTL errors */
	val64 = in_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS, val64);
	val64 = in_be64(p->regs + UTL_PCIE_PORT_STATUS);
	out_be64(p->regs + UTL_PCIE_PORT_STATUS, val64);
	val64 = in_be64(p->regs + UTL_RC_STATUS);
	out_be64(p->regs + UTL_RC_STATUS, val64);

	/* Rec 39...66: Clear PHB error trap */
	val64 = in_be64(p->regs + PHB_ERR_STATUS);
	out_be64(p->regs + PHB_ERR_STATUS, val64);
	out_be64(p->regs + PHB_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_ERR_LOG_1, 0x0ul);

	val64 = in_be64(p->regs + PHB_OUT_ERR_STATUS);
	out_be64(p->regs + PHB_OUT_ERR_STATUS, val64);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_OUT_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_OUT_ERR_LOG_1, 0x0ul);

	val64 = in_be64(p->regs + PHB_INA_ERR_STATUS);
	out_be64(p->regs + PHB_INA_ERR_STATUS, val64);
	out_be64(p->regs + PHB_INA_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_INA_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_INA_ERR_LOG_1, 0x0ul);

	val64 = in_be64(p->regs + PHB_INB_ERR_STATUS);
	out_be64(p->regs + PHB_INB_ERR_STATUS, val64);
	out_be64(p->regs + PHB_INB_ERR1_STATUS, 0x0ul);
	out_be64(p->regs + PHB_INB_ERR_LOG_0, 0x0ul);
	out_be64(p->regs + PHB_INB_ERR_LOG_1, 0x0ul);

	/* Rec 67/68: Clear FIR/WOF */
	out_be64(p->regs + PHB_LEM_FIR_AND_MASK, ~fir);
	out_be64(p->regs + PHB_LEM_WOF, 0x0ul);
}

static void phb3_read_phb_status(struct phb3 *p,
				 struct OpalIoPhb3ErrorData *stat)
{
	uint16_t val;
	uint64_t *pPEST;
	uint64_t val64 = 0;
	uint32_t i;

	memset(stat, 0, sizeof(struct OpalIoPhb3ErrorData));

	/* Error data common part */
	stat->common.version = OPAL_PHB_ERROR_DATA_VERSION_1;
	stat->common.ioType  = OPAL_PHB_ERROR_DATA_TYPE_PHB3;
	stat->common.len     = sizeof(struct OpalIoPhb3ErrorData);

	/*
	 * We read some registers using config space through AIB.
	 *
	 * Get to other registers using ASB when possible to get to them
	 * through a fence if one is present.
	 */

	/* Use ASB to access PCICFG if the PHB has been fenced */
	p->flags |= PHB3_CFG_USE_ASB;

	/* Grab RC bridge control, make it 32-bit */
	phb3_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &val);
	stat->brdgCtl = val;

	/* Grab UTL status registers */
	stat->portStatusReg = hi32(phb3_read_reg_asb(p, UTL_PCIE_PORT_STATUS));
	stat->rootCmplxStatus = hi32(phb3_read_reg_asb(p, UTL_RC_STATUS));
	stat->busAgentStatus = hi32(phb3_read_reg_asb(p, UTL_SYS_BUS_AGENT_STATUS));

	/*
	 * Grab various RC PCIe capability registers. All device, slot
	 * and link status are 16-bit, so we grab the pair control+status
	 * for each of them
	 */
	phb3_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_DEVCTL,
			   &stat->deviceStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_SLOTCTL,
			   &stat->slotStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_LCTL,
			   &stat->linkStatus);

	/*
	 * I assume those are the standard config space header, cmd & status
	 * together makes 32-bit. Secondary status is 16-bit so I'll clear
	 * the top on that one
	 */
	phb3_pcicfg_read32(&p->phb, 0, PCI_CFG_CMD, &stat->devCmdStatus);
	phb3_pcicfg_read16(&p->phb, 0, PCI_CFG_SECONDARY_STATUS, &val);
	stat->devSecStatus = val;

	/* Grab a bunch of AER regs */
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_RERR_STA,
			   &stat->rootErrorStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_UE_STATUS,
			   &stat->uncorrErrorStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_STATUS,
			   &stat->corrErrorStatus);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG0,
			   &stat->tlpHdr1);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG1,
			   &stat->tlpHdr2);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG2,
			   &stat->tlpHdr3);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG3,
			   &stat->tlpHdr4);
	phb3_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_SRCID,
			   &stat->sourceId);

	/* Restore to AIB */
	p->flags &= ~PHB3_CFG_USE_ASB;

	/* PEC NFIR */
	xscom_read(p->chip_id, p->pe_xscom + 0x0, &stat->nFir);
	xscom_read(p->chip_id, p->pe_xscom + 0x3, &stat->nFirMask);
	xscom_read(p->chip_id, p->pe_xscom + 0x8, &stat->nFirWOF);

	/* PHB3 inbound and outbound error Regs */
	stat->phbPlssr = phb3_read_reg_asb(p, PHB_CPU_LOADSTORE_STATUS);
	stat->phbCsr = phb3_read_reg_asb(p, PHB_DMA_CHAN_STATUS);
	stat->lemFir = phb3_read_reg_asb(p, PHB_LEM_FIR_ACCUM);
	stat->lemErrorMask = phb3_read_reg_asb(p, PHB_LEM_ERROR_MASK);
	stat->lemWOF = phb3_read_reg_asb(p, PHB_LEM_WOF);
	stat->phbErrorStatus = phb3_read_reg_asb(p, PHB_ERR_STATUS);
	stat->phbFirstErrorStatus = phb3_read_reg_asb(p, PHB_ERR1_STATUS);
	stat->phbErrorLog0 = phb3_read_reg_asb(p, PHB_ERR_LOG_0);
	stat->phbErrorLog1 = phb3_read_reg_asb(p, PHB_ERR_LOG_1);
	stat->mmioErrorStatus = phb3_read_reg_asb(p, PHB_OUT_ERR_STATUS);
	stat->mmioFirstErrorStatus = phb3_read_reg_asb(p, PHB_OUT_ERR1_STATUS);
	stat->mmioErrorLog0 = phb3_read_reg_asb(p, PHB_OUT_ERR_LOG_0);
	stat->mmioErrorLog1 = phb3_read_reg_asb(p, PHB_OUT_ERR_LOG_1);
	stat->dma0ErrorStatus = phb3_read_reg_asb(p, PHB_INA_ERR_STATUS);
	stat->dma0FirstErrorStatus = phb3_read_reg_asb(p, PHB_INA_ERR1_STATUS);
	stat->dma0ErrorLog0 = phb3_read_reg_asb(p, PHB_INA_ERR_LOG_0);
	stat->dma0ErrorLog1 = phb3_read_reg_asb(p, PHB_INA_ERR_LOG_1);
	stat->dma1ErrorStatus = phb3_read_reg_asb(p, PHB_INB_ERR_STATUS);
	stat->dma1FirstErrorStatus = phb3_read_reg_asb(p, PHB_INB_ERR1_STATUS);
	stat->dma1ErrorLog0 = phb3_read_reg_asb(p, PHB_INB_ERR_LOG_0);
	stat->dma1ErrorLog1 = phb3_read_reg_asb(p, PHB_INB_ERR_LOG_1);

	/*
	 * Grab PESTA & B content. The error bit (bit#0) should
	 * be fetched from IODA and the left content from memory
	 * resident tables.
	 */
	pPEST = (uint64_t *)p->tbl_pest;
	val64 = PHB_IODA_AD_AUTOINC;
	val64 = SETFIELD(PHB_IODA_AD_TSEL, val64, IODA2_TBL_PESTA);
	phb3_write_reg_asb(p, PHB_IODA_ADDR, val64);
	for (i = 0; i < OPAL_PHB3_NUM_PEST_REGS; i++) {
		stat->pestA[i] = phb3_read_reg_asb(p, PHB_IODA_DATA0);
		stat->pestA[i] |= pPEST[2 * i];
	}

	val64 = PHB_IODA_AD_AUTOINC;
	val64 = SETFIELD(PHB_IODA_AD_TSEL, val64, IODA2_TBL_PESTB);
	phb3_write_reg_asb(p, PHB_IODA_ADDR, val64);
	for (i = 0; i < OPAL_PHB3_NUM_PEST_REGS; i++) {
		stat->pestB[i] = phb3_read_reg_asb(p, PHB_IODA_DATA0);
		stat->pestB[i] |= pPEST[2 * i + 1];
	}
}

static void phb3_eeh_dump_regs(struct phb3 *p, struct OpalIoPhb3ErrorData *regs)
{
	struct OpalIoPhb3ErrorData *s;
	unsigned int i;

	if (!verbose_eeh)
		return;

	if (!regs) {
		s = zalloc(sizeof(struct OpalIoPhb3ErrorData));
		if (!s) {
			PHBERR(p, "Failed to allocate error info !\n");
			return;
		}

		phb3_read_phb_status(p, s);
	} else {
		s = regs;
	}

	PHBERR(p, "Error detected!\n");

	PHBERR(p, "       portStatusReg = %08x\n", s->portStatusReg);
	PHBERR(p, "     rootCmplxStatus = %08x\n", s->rootCmplxStatus);
	PHBERR(p, "      busAgentStatus = %08x\n", s->busAgentStatus);

	PHBERR(p, "          errorClass = %016llx\n", s->errorClass);
	PHBERR(p, "          correlator = %016llx\n", s->correlator);

	PHBERR(p, "             brdgCtl = %08x\n", s->brdgCtl);
	PHBERR(p, "        deviceStatus = %08x\n", s->deviceStatus);
	PHBERR(p, "          slotStatus = %08x\n", s->slotStatus);
	PHBERR(p, "          linkStatus = %08x\n", s->linkStatus);
	PHBERR(p, "        devCmdStatus = %08x\n", s->devCmdStatus);
	PHBERR(p, "        devSecStatus = %08x\n", s->devSecStatus);
	PHBERR(p, "     rootErrorStatus = %08x\n", s->rootErrorStatus);
	PHBERR(p, "     corrErrorStatus = %08x\n", s->corrErrorStatus);
	PHBERR(p, "   uncorrErrorStatus = %08x\n", s->uncorrErrorStatus);

	/* Byte swap TLP headers so they are the same as the PCIe spec */
	PHBERR(p, "             tlpHdr1 = %08x\n", bswap_32(s->tlpHdr1));
	PHBERR(p, "             tlpHdr2 = %08x\n", bswap_32(s->tlpHdr2));
	PHBERR(p, "             tlpHdr3 = %08x\n", bswap_32(s->tlpHdr3));
	PHBERR(p, "             tlpHdr4 = %08x\n", bswap_32(s->tlpHdr4));
	PHBERR(p, "            sourceId = %08x\n", s->sourceId);

	PHBERR(p, "                nFir = %016llx\n", s->nFir);
	PHBERR(p, "            nFirMask = %016llx\n", s->nFirMask);
	PHBERR(p, "             nFirWOF = %016llx\n", s->nFirWOF);
	PHBERR(p, "            phbPlssr = %016llx\n", s->phbPlssr);
	PHBERR(p, "              phbCsr = %016llx\n", s->phbCsr);
	PHBERR(p, "              lemFir = %016llx\n", s->lemFir);
	PHBERR(p, "        lemErrorMask = %016llx\n", s->lemErrorMask);
	PHBERR(p, "              lemWOF = %016llx\n", s->lemWOF);

	PHBERR(p, "      phbErrorStatus = %016llx\n", s->phbErrorStatus);
	PHBERR(p, " phbFirstErrorStatus = %016llx\n", s->phbFirstErrorStatus);
	PHBERR(p, "        phbErrorLog0 = %016llx\n", s->phbErrorLog0);
	PHBERR(p, "        phbErrorLog1 = %016llx\n", s->phbErrorLog1);

	PHBERR(p, "     mmioErrorStatus = %016llx\n", s->mmioErrorStatus);
	PHBERR(p, "mmioFirstErrorStatus = %016llx\n", s->mmioFirstErrorStatus);
	PHBERR(p, "       mmioErrorLog0 = %016llx\n", s->mmioErrorLog0);
	PHBERR(p, "       mmioErrorLog1 = %016llx\n", s->mmioErrorLog1);

	PHBERR(p, "     dma0ErrorStatus = %016llx\n", s->dma0ErrorStatus);
	PHBERR(p, "dma0FirstErrorStatus = %016llx\n", s->dma0FirstErrorStatus);
	PHBERR(p, "       dma0ErrorLog0 = %016llx\n", s->dma0ErrorLog0);
	PHBERR(p, "       dma0ErrorLog1 = %016llx\n", s->dma0ErrorLog1);

	PHBERR(p, "     dma1ErrorStatus = %016llx\n", s->dma1ErrorStatus);
	PHBERR(p, "dma1FirstErrorStatus = %016llx\n", s->dma1FirstErrorStatus);
	PHBERR(p, "       dma1ErrorLog0 = %016llx\n", s->dma1ErrorLog0);
	PHBERR(p, "       dma1ErrorLog1 = %016llx\n", s->dma1ErrorLog1);

	for (i = 0; i < OPAL_PHB3_NUM_PEST_REGS; i++) {
		if (!s->pestA[i] && !s->pestB[i])
			continue;
		PHBERR(p, "          PEST[%03x] = %016llx %016llx\n",
		       i, s->pestA[i], s->pestB[i]);
	}

	if (s != regs)
		free(s);
}

static int64_t phb3_msi_get_xive(struct irq_source *is, uint32_t isn,
				 uint16_t *server, uint8_t *prio)
{
	struct phb3 *p = is->data;
	uint32_t chip, index, irq;
	uint64_t ive;

	chip = p8_irq_to_chip(isn);
	index = p8_irq_to_phb(isn);
	irq = PHB3_IRQ_NUM(isn);

	if (chip != p->chip_id ||
	    index != p->index ||
	    irq > PHB3_MSI_IRQ_MAX)
		return OPAL_PARAMETER;

	/*
	 * Each IVE has 16 bytes in cache. Note that the kernel
	 * should strip the link bits from server field.
	 */
	ive = p->ive_cache[irq];
	*server = GETFIELD(IODA2_IVT_SERVER, ive);
	*prio = GETFIELD(IODA2_IVT_PRIORITY, ive);

	return OPAL_SUCCESS;
}

static int64_t phb3_msi_set_xive(struct irq_source *is, uint32_t isn,
				 uint16_t server, uint8_t prio)
{
	struct phb3 *p = is->data;
	uint32_t chip, index;
	uint64_t *cache, ive_num, data64, m_server, m_prio, ivc;
	uint32_t *ive;

	chip = p8_irq_to_chip(isn);
	index = p8_irq_to_phb(isn);
	ive_num = PHB3_IRQ_NUM(isn);

	if (p->broken || !p->tbl_rtt)
		return OPAL_HARDWARE;
	if (chip != p->chip_id ||
	    index != p->index ||
	    ive_num > PHB3_MSI_IRQ_MAX)
		return OPAL_PARAMETER;

	phb_lock(&p->phb);

	/*
	 * We need strip the link from server. As Milton told
	 * me, the server is assigned as follows and the left
	 * bits unused: node/chip/core/thread/link = 2/3/4/3/2
	 *
	 * Note: the server has added the link bits to server.
	 */
	m_server = server;
	m_prio = prio;

	cache = &p->ive_cache[ive_num];
	*cache = SETFIELD(IODA2_IVT_SERVER,   *cache, m_server);
	*cache = SETFIELD(IODA2_IVT_PRIORITY, *cache, m_prio);

	/*
	 * Update IVT and IVC. We need use IVC update register
	 * to do that. Each IVE in the table has 128 bytes
	 */
	ive = (uint32_t *)(p->tbl_ivt + ive_num * IVT_TABLE_STRIDE * 8);
	data64 = PHB_IVC_UPDATE_ENABLE_SERVER | PHB_IVC_UPDATE_ENABLE_PRI;
	data64 = SETFIELD(PHB_IVC_UPDATE_SID, data64, ive_num);
	data64 = SETFIELD(PHB_IVC_UPDATE_SERVER, data64, m_server);
	data64 = SETFIELD(PHB_IVC_UPDATE_PRI, data64, m_prio);

	/*
	 * We don't use SETFIELD because we are doing a 32-bit access
	 * in order to avoid touching the P and Q bits
	 */
	*ive = (m_server << 8) | m_prio;
	out_be64(p->regs + PHB_IVC_UPDATE, data64);

	if (prio != 0xff) {
		/*
		 * Handle Q bit if we're going to enable the
		 * interrupt.  The OS should make sure the interrupt
		 * handler has been installed already.
		 */
		if (phb3_pci_msi_check_q(p, ive_num))
			phb3_pci_msi_flush_ive(p, ive_num);
	} else {
		/* Read from random PHB reg to force flush */
		in_be64(p->regs + PHB_IVC_UPDATE);

		/* Order with subsequent read of Q */
		sync();

		/* Clear P, Q and Gen, preserve PE# */
		ive[1] &= 0x0000ffff;

		/*
		 * Update the IVC with a match against the old gen
		 * count. No need to worry about racing with P being
		 * set in the cache since IRQ is masked at this point.
		 */
		ivc = SETFIELD(PHB_IVC_UPDATE_SID, 0ul, ive_num) |
			PHB_IVC_UPDATE_ENABLE_P |
			PHB_IVC_UPDATE_ENABLE_Q |
			PHB_IVC_UPDATE_ENABLE_GEN;
		out_be64(p->regs + PHB_IVC_UPDATE, ivc);
	}

	phb_unlock(&p->phb);

	return OPAL_SUCCESS;
}

static int64_t phb3_lsi_get_xive(struct irq_source *is, uint32_t isn,
				 uint16_t *server, uint8_t *prio)
{
	struct phb3 *p = is->data;
	uint32_t chip, index, irq;
	uint64_t lxive;

	chip = p8_irq_to_chip(isn);
	index = p8_irq_to_phb(isn);
	irq = PHB3_IRQ_NUM(isn);

	if (chip != p->chip_id	||
	    index != p->index	||
	    irq < PHB3_LSI_IRQ_MIN ||
	    irq > PHB3_LSI_IRQ_MAX)
		return OPAL_PARAMETER;

	lxive = p->lxive_cache[irq - PHB3_LSI_IRQ_MIN];
	*server = GETFIELD(IODA2_LXIVT_SERVER, lxive);
	*prio = GETFIELD(IODA2_LXIVT_PRIORITY, lxive);

	return OPAL_SUCCESS;
}

static int64_t phb3_lsi_set_xive(struct irq_source *is, uint32_t isn,
				 uint16_t server, uint8_t prio)
{
	struct phb3 *p = is->data;
	uint32_t chip, index, irq, entry;
	uint64_t lxive;

	chip = p8_irq_to_chip(isn);
	index = p8_irq_to_phb(isn);
	irq = PHB3_IRQ_NUM(isn);

	if (p->broken)
		return OPAL_HARDWARE;

	if (chip != p->chip_id	||
	    index != p->index	||
	    irq < PHB3_LSI_IRQ_MIN ||
	    irq > PHB3_LSI_IRQ_MAX)
		return OPAL_PARAMETER;

	lxive = SETFIELD(IODA2_LXIVT_SERVER, 0ul, server);
	lxive = SETFIELD(IODA2_LXIVT_PRIORITY, lxive, prio);

	phb_lock(&p->phb);

	/*
	 * We cache the arguments because we have to mangle
	 * it in order to hijack 3 bits of priority to extend
	 * the server number
	 */
	entry = irq - PHB3_LSI_IRQ_MIN;
	p->lxive_cache[entry] = lxive;

	/* We use HRT entry 0 always for now */
	phb3_ioda_sel(p, IODA2_TBL_LXIVT, entry, false);
	lxive = in_be64(p->regs + PHB_IODA_DATA0);
	lxive = SETFIELD(IODA2_LXIVT_SERVER, lxive, server);
	lxive = SETFIELD(IODA2_LXIVT_PRIORITY, lxive, prio);
	out_be64(p->regs + PHB_IODA_DATA0, lxive);

	phb_unlock(&p->phb);

	return OPAL_SUCCESS;
}

static void phb3_err_interrupt(struct irq_source *is, uint32_t isn)
{
	struct phb3 *p = is->data;

	PHBDBG(p, "Got interrupt 0x%08x\n", isn);

	/* Update pending event */
	opal_update_pending_evt(OPAL_EVENT_PCI_ERROR,
				OPAL_EVENT_PCI_ERROR);

	/* If the PHB is broken, go away */
	if (p->broken)
		return;

	/*
	 * Mark the PHB has pending error so that the OS
	 * can handle it at late point.
	 */
	phb3_set_err_pending(p, true);
}

static uint64_t phb3_lsi_attributes(struct irq_source *is, uint32_t isn)
{
#ifndef DISABLE_ERR_INTS
	struct phb3 *p = is->data;
	uint32_t idx = isn - p->base_lsi;

	if (idx == PHB3_LSI_PCIE_INF || idx == PHB3_LSI_PCIE_ER)
		return IRQ_ATTR_TARGET_OPAL | IRQ_ATTR_TARGET_RARE | IRQ_ATTR_TYPE_LSI;
#endif
	return IRQ_ATTR_TARGET_LINUX;
}

/* MSIs (OS owned) */
static const struct irq_source_ops phb3_msi_irq_ops = {
	.get_xive = phb3_msi_get_xive,
	.set_xive = phb3_msi_set_xive,
};

/* LSIs (OS owned) */
static const struct irq_source_ops phb3_lsi_irq_ops = {
	.get_xive = phb3_lsi_get_xive,
	.set_xive = phb3_lsi_set_xive,
	.attributes = phb3_lsi_attributes,
	.interrupt = phb3_err_interrupt,
};

static int64_t phb3_set_pe(struct phb *phb,
			   uint64_t pe_number,
			   uint64_t bdfn,
			   uint8_t bcompare,
			   uint8_t dcompare,
			   uint8_t fcompare,
			   uint8_t action)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t mask, val, tmp, idx;
	int32_t all = 0;
	uint16_t *rte;

	/* Sanity check */
	if (!p->tbl_rtt)
		return OPAL_HARDWARE;
	if (action != OPAL_MAP_PE && action != OPAL_UNMAP_PE)
		return OPAL_PARAMETER;
	if (pe_number >= PHB3_MAX_PE_NUM || bdfn > 0xffff ||
	    bcompare > OpalPciBusAll ||
	    dcompare > OPAL_COMPARE_RID_DEVICE_NUMBER ||
	    fcompare > OPAL_COMPARE_RID_FUNCTION_NUMBER)
		return OPAL_PARAMETER;

	/* Figure out the RID range */
	if (bcompare == OpalPciBusAny) {
		mask = 0x0;
		val  = 0x0;
		all  = 0x1;
	} else {
		tmp  = ((0x1 << (bcompare + 1)) - 1) << (15 - bcompare);
		mask = tmp;
		val  = bdfn & tmp;
	}

	if (dcompare == OPAL_IGNORE_RID_DEVICE_NUMBER)
		all = (all << 1) | 0x1;
	else {
		mask |= 0xf8;
		val  |= (bdfn & 0xf8);
	}

	if (fcompare == OPAL_IGNORE_RID_FUNCTION_NUMBER)
		all = (all << 1) | 0x1;
	else {
		mask |= 0x7;
		val  |= PCI_FUNC(bdfn);
	}

	/* Map or unmap the RTT range */
	if (all == 0x7) {
		if (action == OPAL_MAP_PE) {
			for (idx = 0; idx < RTT_TABLE_ENTRIES; idx++)
				p->rte_cache[idx] = pe_number;
		} else {
			for ( idx = 0; idx < ARRAY_SIZE(p->rte_cache); idx++)
				p->rte_cache[idx] = PHB3_RESERVED_PE_NUM;
		}
		memcpy((void *)p->tbl_rtt, p->rte_cache, RTT_TABLE_SIZE);
	} else {
		rte = (uint16_t *)p->tbl_rtt;
		for (idx = 0; idx < RTT_TABLE_ENTRIES; idx++, rte++) {
			if ((idx & mask) != val)
				continue;
			if (action == OPAL_MAP_PE)
				p->rte_cache[idx] = pe_number;
			else
				p->rte_cache[idx] = PHB3_RESERVED_PE_NUM;
			*rte = p->rte_cache[idx];
		}
	}

	/* Invalidate the entire RTC */
	out_be64(p->regs + PHB_RTC_INVALIDATE, PHB_RTC_INVALIDATE_ALL);

	return OPAL_SUCCESS;
}

static int64_t phb3_set_peltv(struct phb *phb,
			      uint32_t parent_pe,
			      uint32_t child_pe,
			      uint8_t state)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint8_t *peltv;
	uint32_t idx, mask;

	/* Sanity check */
	if (!p->tbl_peltv)
		return OPAL_HARDWARE;
	if (parent_pe >= PHB3_MAX_PE_NUM || child_pe >= PHB3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	/* Find index for parent PE */
	idx = parent_pe * (PHB3_MAX_PE_NUM / 8);
	idx += (child_pe / 8);
	mask = 0x1 << (7 - (child_pe % 8));

	peltv = (uint8_t *)p->tbl_peltv;
	peltv += idx;
	if (state) {
		*peltv |= mask;
		p->peltv_cache[idx] |= mask;
	} else {
		*peltv &= ~mask;
		p->peltv_cache[idx] &= ~mask;
	}

	return OPAL_SUCCESS;
}

static void phb3_prepare_link_change(struct pci_slot *slot,
				     bool is_up)
{
	struct phb3 *p = phb_to_phb3(slot->phb);
	struct pci_device *pd = slot->pd;
	uint32_t reg32;

	p->has_link = is_up;
	if (!is_up) {
		if (!pd || !pd->slot || !pd->slot->surprise_pluggable) {
			/* Mask PCIE port interrupts */
			out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN,
				 0xad42800000000000UL);

			pci_cfg_read32(&p->phb, 0,
				       p->aercap + PCIECAP_AER_UE_MASK, &reg32);
			reg32 |= PCIECAP_AER_UE_MASK_SURPRISE_DOWN;
			pci_cfg_write32(&p->phb, 0,
					p->aercap + PCIECAP_AER_UE_MASK, reg32);
                }

		/* Mask AER receiver error */
		phb3_pcicfg_read32(&p->phb, 0,
				   p->aercap + PCIECAP_AER_CE_MASK, &reg32);
		reg32 |= PCIECAP_AER_CE_RECVR_ERR;
		phb3_pcicfg_write32(&p->phb, 0,
				    p->aercap + PCIECAP_AER_CE_MASK, reg32);

		/* Block PCI-CFG access */
		p->flags |= PHB3_CFG_BLOCKED;
	} else {
		/* Clear AER receiver error status */
		phb3_pcicfg_write32(&p->phb, 0,
				    p->aercap + PCIECAP_AER_CE_STATUS,
				    PCIECAP_AER_CE_RECVR_ERR);

		/* Unmask receiver error status in AER */
		phb3_pcicfg_read32(&p->phb, 0,
				   p->aercap + PCIECAP_AER_CE_MASK, &reg32);
		reg32 &= ~PCIECAP_AER_CE_RECVR_ERR;
		phb3_pcicfg_write32(&p->phb, 0,
				    p->aercap + PCIECAP_AER_CE_MASK, reg32);

		/* Clear spurrious errors and enable PCIE port interrupts */
		out_be64(p->regs + UTL_PCIE_PORT_STATUS,
			 0xffdfffffffffffffUL);

		if (!pd || !pd->slot || !pd->slot->surprise_pluggable) {
			out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN,
				 0xad52800000000000UL);

			pci_cfg_read32(&p->phb, 0,
				       p->aercap + PCIECAP_AER_UE_MASK, &reg32);
			reg32 &= ~PCIECAP_AER_UE_MASK_SURPRISE_DOWN;
			pci_cfg_write32(&p->phb, 0,
					p->aercap + PCIECAP_AER_UE_MASK, reg32);
		}

		/* Don't block PCI-CFG */
		p->flags &= ~PHB3_CFG_BLOCKED;

		/*
		 * We might lose the bus numbers during the reset operation
		 * and we need to restore them. Otherwise, some adapters (e.g.
		 * IPR) can't be probed properly by the kernel. We don't need
		 * to restore bus numbers for every kind of reset, however,
		 * it's not harmful to always restore the bus numbers, which
		 * simplifies the logic.
		 */
		pci_restore_bridge_buses(slot->phb, slot->pd);
		if (slot->phb->ops->device_init)
			pci_walk_dev(slot->phb, slot->pd,
				     slot->phb->ops->device_init, NULL);
	}
}

static int64_t phb3_get_presence_state(struct pci_slot *slot, uint8_t *val)
{
	struct phb3 *p = phb_to_phb3(slot->phb);
	uint64_t hp_override;

	if (p->broken)
		return OPAL_HARDWARE;

	/*
	 * On P8, the slot status isn't wired up properly, we have
	 * to use the hotplug override A/B bits.
	 */
	hp_override = in_be64(p->regs + PHB_HOTPLUG_OVERRIDE);
	if ((hp_override & PHB_HPOVR_PRESENCE_A) &&
	    (hp_override & PHB_HPOVR_PRESENCE_B))
		*val = OPAL_PCI_SLOT_EMPTY;
	else
		*val = OPAL_PCI_SLOT_PRESENT;

	return OPAL_SUCCESS;
}

static int64_t phb3_get_link_state(struct pci_slot *slot, uint8_t *val)
{
	struct phb3 *p = phb_to_phb3(slot->phb);
	uint64_t reg;
	uint16_t state;
	int64_t rc;

	/* Link is up, let's find the actual speed */
	reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
	if (!(reg & PHB_PCIE_DLP_TC_DL_LINKACT)) {
		*val = 0;
		return OPAL_SUCCESS;
	}

	rc = phb3_pcicfg_read16(&p->phb, 0,
				p->ecap + PCICAP_EXP_LSTAT, &state);
	if (rc != OPAL_SUCCESS) {
		PHBERR(p, "%s: Error %lld getting link state\n", __func__, rc);
		return OPAL_HARDWARE;
	}

	if (state & PCICAP_EXP_LSTAT_DLLL_ACT)
		*val = ((state & PCICAP_EXP_LSTAT_WIDTH) >> 4);
	else
		*val = 0;

	return OPAL_SUCCESS;
}

static int64_t phb3_retry_state(struct pci_slot *slot)
{
	struct phb3 *p = phb_to_phb3(slot->phb);

	if (slot->retry_state == PCI_SLOT_STATE_NORMAL)
		return OPAL_WRONG_STATE;

	PHBDBG(p, "Retry state %08x\n", slot->retry_state);
	slot->delay_tgt_tb = 0;
	pci_slot_set_state(slot, slot->retry_state);
	slot->retry_state = PCI_SLOT_STATE_NORMAL;
	return slot->ops.run_sm(slot);
}

static int64_t phb3_poll_link(struct pci_slot *slot)
{
	struct phb3 *p = phb_to_phb3(slot->phb);
	uint64_t reg;
	int64_t rc;

	switch (slot->state) {
	case PHB3_SLOT_NORMAL:
	case PHB3_SLOT_LINK_START:
		PHBDBG(p, "LINK: Start polling\n");
		slot->retries = PHB3_LINK_ELECTRICAL_RETRIES;
		pci_slot_set_state(slot, PHB3_SLOT_LINK_WAIT_ELECTRICAL);
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(100));
	case PHB3_SLOT_LINK_WAIT_ELECTRICAL:
		/*
		 * Wait for the link electrical connection to be
		 * established (shorter timeout). This allows us to
		 * workaround spurrious presence detect on some machines
		 * without waiting 10s each time
		 *
		 * Note: We *also* check for the full link up bit here
		 * because simics doesn't seem to implement the electrical
		 * link bit at all
		 */
		reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (reg & (PHB_PCIE_DLP_INBAND_PRESENCE |
			   PHB_PCIE_DLP_TC_DL_LINKACT)) {
			PHBDBG(p, "LINK: Electrical link detected\n");
			pci_slot_set_state(slot, PHB3_SLOT_LINK_WAIT);
			slot->retries = PHB3_LINK_WAIT_RETRIES;
			return pci_slot_set_sm_timeout(slot, msecs_to_tb(100));
		}

		if (slot->retries-- == 0) {
			PHBDBG(p, "LINK: Timeout waiting for electrical link\n");
			PHBDBG(p, "LINK: DLP train control: 0x%016llx\n", reg);
			rc = phb3_retry_state(slot);
			if (rc >= OPAL_SUCCESS)
				return rc;

			pci_slot_set_state(slot, PHB3_SLOT_NORMAL);
			return OPAL_SUCCESS;
		}
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(100));
	case PHB3_SLOT_LINK_WAIT:
		reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (reg & PHB_PCIE_DLP_TC_DL_LINKACT) {
			PHBDBG(p, "LINK: Link is up\n");
			if (slot->ops.prepare_link_change)
				slot->ops.prepare_link_change(slot, true);
			pci_slot_set_state(slot, PHB3_SLOT_NORMAL);
			return OPAL_SUCCESS;
		}

		if (slot->retries-- == 0) {
			PHBDBG(p, "LINK: Timeout waiting for link up\n");
			PHBDBG(p, "LINK: DLP train control: 0x%016llx\n", reg);
			rc = phb3_retry_state(slot);
			if (rc >= OPAL_SUCCESS)
				return rc;

			pci_slot_set_state(slot, PHB3_SLOT_NORMAL);
			return OPAL_SUCCESS;
		}
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(100));
	default:
		PHBERR(p, "LINK: Unexpected slot state %08x\n",
		       slot->state);
	}

	pci_slot_set_state(slot, PHB3_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static int64_t phb3_hreset(struct pci_slot *slot)
{
	struct phb3 *p = phb_to_phb3(slot->phb);
	uint16_t brctl;
	uint8_t presence = 1;

	switch (slot->state) {
	case PHB3_SLOT_NORMAL:
		PHBDBG(p, "HRESET: Starts\n");
		if (slot->ops.get_presence_state)
			slot->ops.get_presence_state(slot, &presence);
		if (!presence) {
			PHBDBG(p, "HRESET: No device\n");
			return OPAL_SUCCESS;
		}

		PHBDBG(p, "HRESET: Prepare for link down\n");
		if (slot->ops.prepare_link_change)
			slot->ops.prepare_link_change(slot, false);
		/* fall through */
	case PHB3_SLOT_HRESET_START:
		PHBDBG(p, "HRESET: Assert\n");

		phb3_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl |= PCI_CFG_BRCTL_SECONDARY_RESET;
		phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);
		pci_slot_set_state(slot, PHB3_SLOT_HRESET_DELAY);

		return pci_slot_set_sm_timeout(slot, secs_to_tb(1));
	case PHB3_SLOT_HRESET_DELAY:
		PHBDBG(p, "HRESET: Deassert\n");

		phb3_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl &= ~PCI_CFG_BRCTL_SECONDARY_RESET;
		phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);

		/*
		 * Due to some oddball adapters bouncing the link
		 * training a couple of times, we wait for a full second
		 * before we start checking the link status, otherwise
		 * we can get a spurrious link down interrupt which
		 * causes us to EEH immediately.
		 */
		pci_slot_set_state(slot, PHB3_SLOT_HRESET_DELAY2);
		return pci_slot_set_sm_timeout(slot, secs_to_tb(1));
	case PHB3_SLOT_HRESET_DELAY2:
		pci_slot_set_state(slot, PHB3_SLOT_LINK_START);
		return slot->ops.poll_link(slot);
	default:
		PHBERR(p, "Unexpected slot state %08x\n", slot->state);
	}

	pci_slot_set_state(slot, PHB3_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static int64_t phb3_freset(struct pci_slot *slot)
{
	struct phb3 *p = phb_to_phb3(slot->phb);
	uint8_t presence = 1;
	uint64_t reg;

	switch(slot->state) {
	case PHB3_SLOT_NORMAL:
		PHBDBG(p, "FRESET: Starts\n");

		/* Nothing to do without adapter connected */
		if (slot->ops.get_presence_state)
			slot->ops.get_presence_state(slot, &presence);
		if (!presence) {
			PHBDBG(p, "FRESET: No device\n");
			return OPAL_SUCCESS;
		}

		PHBDBG(p, "FRESET: Prepare for link down\n");
		slot->retry_state = PHB3_SLOT_FRESET_START;
		if (slot->ops.prepare_link_change)
			slot->ops.prepare_link_change(slot, false);
		/* fall through */
	case PHB3_SLOT_FRESET_START:
		if (!p->skip_perst) {
			PHBDBG(p, "FRESET: Assert\n");
			reg = in_be64(p->regs + PHB_RESET);
			reg &= ~0x2000000000000000ul;
			out_be64(p->regs + PHB_RESET, reg);
			pci_slot_set_state(slot,
				PHB3_SLOT_FRESET_ASSERT_DELAY);
			return pci_slot_set_sm_timeout(slot, secs_to_tb(1));
		}

		/* To skip the assert during boot time */
		PHBDBG(p, "FRESET: Assert skipped\n");
		pci_slot_set_state(slot, PHB3_SLOT_FRESET_ASSERT_DELAY);
		p->skip_perst = false;
		/* fall through */
	case PHB3_SLOT_FRESET_ASSERT_DELAY:
		PHBDBG(p, "FRESET: Deassert\n");
		reg = in_be64(p->regs + PHB_RESET);
		reg |= 0x2000000000000000ul;
		out_be64(p->regs + PHB_RESET, reg);
		pci_slot_set_state(slot,
			PHB3_SLOT_FRESET_DEASSERT_DELAY);

		/* CAPP FPGA requires 1s to flash before polling link */
		return pci_slot_set_sm_timeout(slot, secs_to_tb(1));
	case PHB3_SLOT_FRESET_DEASSERT_DELAY:
		pci_slot_set_state(slot, PHB3_SLOT_LINK_START);
		return slot->ops.poll_link(slot);
	default:
		PHBERR(p, "Unexpected slot state %08x\n", slot->state);
	}

	pci_slot_set_state(slot, PHB3_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static int64_t load_capp_ucode(struct phb3 *p)
{
	int64_t rc;

	if (p->index > PHB3_CAPP_MAX_PHB_INDEX(p))
		return OPAL_HARDWARE;

	/* 0x434150504c494448 = 'CAPPLIDH' in ASCII */
	rc = capp_load_ucode(p->chip_id, p->phb.opal_id, p->index,
			0x434150504c494448UL, PHB3_CAPP_REG_OFFSET(p),
			CAPP_APC_MASTER_ARRAY_ADDR_REG,
			CAPP_APC_MASTER_ARRAY_WRITE_REG,
			CAPP_SNP_ARRAY_ADDR_REG,
			CAPP_SNP_ARRAY_WRITE_REG);
	return rc;
}

static void do_capp_recovery_scoms(struct phb3 *p)
{
	uint64_t reg;
	uint32_t offset;

	PHBDBG(p, "Doing CAPP recovery scoms\n");

	offset = PHB3_CAPP_REG_OFFSET(p);
	/* disable snoops */
	xscom_write(p->chip_id, SNOOP_CAPI_CONFIG + offset, 0);
	load_capp_ucode(p);
	/* clear err rpt reg*/
	xscom_write(p->chip_id, CAPP_ERR_RPT_CLR + offset, 0);
	/* clear capp fir */
	xscom_write(p->chip_id, CAPP_FIR + offset, 0);

	xscom_read(p->chip_id, CAPP_ERR_STATUS_CTRL + offset, &reg);
	reg &= ~(PPC_BIT(0) | PPC_BIT(1));
	xscom_write(p->chip_id, CAPP_ERR_STATUS_CTRL + offset, reg);
}

/*
 * Disable CAPI mode on a PHB.
 *
 * Must be done while PHB is fenced and in recovery. Leaves CAPP in recovery -
 * we can't come out of recovery until the PHB has been reinitialised.
 *
 * We don't reset generic error registers here - we rely on phb3_init_hw() to
 * do that.
 *
 * Sets PHB3_CAPP_DISABLING flag when complete.
 */
static void disable_capi_mode(struct phb3 *p)
{
	struct proc_chip *chip = get_chip(p->chip_id);
	uint64_t reg;
	uint32_t offset = PHB3_CAPP_REG_OFFSET(p);

	lock(&capi_lock);

	xscom_read(p->chip_id, PE_CAPP_EN + PE_REG_OFFSET(p), &reg);
	if (!(reg & PPC_BIT(0))) {
	        /* Not in CAPI mode, no action required */
	        goto out;
	}

	PHBDBG(p, "CAPP: Disabling CAPI mode\n");
	if (!(chip->capp_phb3_attached_mask & (1 << p->index)))
		PHBERR(p, "CAPP: CAPP attached mask not set!\n");

	xscom_read(p->chip_id, CAPP_ERR_STATUS_CTRL + offset, &reg);
	if (!(reg & PPC_BIT(0))) {
		PHBERR(p, "CAPP: not in recovery, can't disable CAPI mode!\n");
		goto out;
	}

	/* Snoop CAPI Configuration Register - disable snooping */
	xscom_write(p->chip_id, SNOOP_CAPI_CONFIG + offset, 0ull);

	/* APC Master PB Control Register - disable examining cResps */
	xscom_read(p->chip_id, APC_MASTER_PB_CTRL + offset, &reg);
	reg &= ~PPC_BIT(3);
	xscom_write(p->chip_id, APC_MASTER_PB_CTRL + offset, reg);

	/* APC Master Config Register - de-select PHBs */
	xscom_read(p->chip_id, APC_MASTER_CAPI_CTRL + offset, &reg);
	reg &= ~PPC_BITMASK(1, 3);
	xscom_write(p->chip_id, APC_MASTER_CAPI_CTRL + offset, reg);

	/* PE Bus AIB Mode Bits */
	xscom_read(p->chip_id, p->pci_xscom + 0xf, &reg);
	reg |= PPC_BITMASK(7, 8);	/* Ch2 command credit */
	reg &= ~PPC_BITMASK(40, 42);	/* Disable HOL blocking */
	xscom_write(p->chip_id, p->pci_xscom + 0xf, reg);

	/* PCI Hardware Configuration 0 Register - all store queues free */
	xscom_read(p->chip_id, p->pe_xscom + 0x18, &reg);
	reg &= ~PPC_BIT(14);
	reg |= PPC_BIT(15);
	xscom_write(p->chip_id, p->pe_xscom + 0x18, reg);

	/*
	 * PCI Hardware Configuration 1 Register - enable read response
	 * arrival/address request ordering
	 */
	xscom_read(p->chip_id, p->pe_xscom + 0x19, &reg);
	reg |= PPC_BITMASK(17,18);
	xscom_write(p->chip_id, p->pe_xscom + 0x19, reg);

	/*
	 * AIB TX Command Credit Register - set AIB credit values back to
	 * normal
	 */
	xscom_read(p->chip_id, p->pci_xscom + 0xd, &reg);
	reg |= PPC_BIT(42);
	reg &= ~PPC_BITMASK(43, 47);
	xscom_write(p->chip_id, p->pci_xscom + 0xd, reg);

	/* AIB TX Credit Init Timer - reset timer */
	xscom_write(p->chip_id, p->pci_xscom + 0xc, 0xff00000000000000UL);

	/*
	 * PBCQ Mode Control Register - set dcache handling to normal, not CAPP
	 * mode
	 */
	xscom_read(p->chip_id, p->pe_xscom + 0xb, &reg);
	reg &= ~PPC_BIT(25);
	xscom_write(p->chip_id, p->pe_xscom + 0xb, reg);

	/* Registers touched by phb3_init_capp_regs() */

	/* CAPP Transport Control Register */
	xscom_write(p->chip_id, TRANSPORT_CONTROL + offset, 0x0001000000000000UL);

	/* Canned pResp Map Register 0/1/2 */
	xscom_write(p->chip_id, CANNED_PRESP_MAP0 + offset, 0);
	xscom_write(p->chip_id, CANNED_PRESP_MAP1 + offset, 0);
	xscom_write(p->chip_id, CANNED_PRESP_MAP2 + offset, 0);

	/* Flush SUE State Map Register */
	xscom_write(p->chip_id, FLUSH_SUE_STATE_MAP + offset, 0);

	/* CAPP Epoch and Recovery Timers Control Register */
	xscom_write(p->chip_id, CAPP_EPOCH_TIMER_CTRL + offset, 0);

	/* PE Secure CAPP Enable Register - we're all done! Disable CAPP mode! */
	xscom_write(p->chip_id, PE_CAPP_EN + PE_REG_OFFSET(p), 0ull);

	/* Trigger CAPP recovery scoms after reinit */
	p->flags |= PHB3_CAPP_DISABLING;

	chip->capp_phb3_attached_mask &= ~(1 << p->index);

out:
	unlock(&capi_lock);
}

static int64_t phb3_creset(struct pci_slot *slot)
{
	struct phb3 *p = phb_to_phb3(slot->phb);
	uint64_t cqsts, val;

	switch (slot->state) {
	case PHB3_SLOT_NORMAL:
	case PHB3_SLOT_CRESET_START:
		PHBDBG(p, "CRESET: Starts\n");

		/* do steps 3-5 of capp recovery procedure */
		if (p->flags & PHB3_CAPP_RECOVERY)
			do_capp_recovery_scoms(p);

		/*
		 * The users might be doing error injection through PBCQ
		 * Error Inject Control Register. Without clearing that,
		 * we will get recrusive error during recovery and it will
		 * fail eventually.
		 */
		xscom_write(p->chip_id, p->pe_xscom + 0xa, 0x0ul);

		/*
		 * We might have escalated frozen state on non-existing PE
		 * to fenced PHB. For the case, the PHB isn't fenced in the
		 * hardware level and it's not safe to do ETU reset. So we
		 * have to force fenced PHB prior to ETU reset.
		 */
		if (!phb3_fenced(p))
			xscom_write(p->chip_id, p->pe_xscom + 0x2, 0x000000f000000000ull);

		/* Now that we're guaranteed to be fenced, disable CAPI mode */
		if (!(p->flags & PHB3_CAPP_RECOVERY))
			disable_capi_mode(p);

		/* Clear errors in NFIR and raise ETU reset */
		xscom_read(p->chip_id, p->pe_xscom + 0x0, &p->nfir_cache);

		xscom_read(p->chip_id, p->spci_xscom + 1, &val);/* HW275117 */
		xscom_write(p->chip_id, p->pci_xscom + 0xa,
			    0x8000000000000000UL);
		pci_slot_set_state(slot, PHB3_SLOT_CRESET_WAIT_CQ);
		slot->retries = 500;
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(10));
	case PHB3_SLOT_CRESET_WAIT_CQ:
		xscom_read(p->chip_id, p->pe_xscom + 0x1c, &val);
		xscom_read(p->chip_id, p->pe_xscom + 0x1d, &val);
		xscom_read(p->chip_id, p->pe_xscom + 0x1e, &val);
		xscom_read(p->chip_id, p->pe_xscom + 0xf, &cqsts);
		if (!(cqsts & 0xC000000000000000UL)) {
			PHBDBG(p, "CRESET: No pending transactions\n");
			xscom_write(p->chip_id, p->pe_xscom + 0x1, ~p->nfir_cache);

			pci_slot_set_state(slot, PHB3_SLOT_CRESET_REINIT);
			return pci_slot_set_sm_timeout(slot, msecs_to_tb(100));
		}

		if (slot->retries-- == 0) {
			PHBERR(p, "Timeout waiting for pending transaction\n");
			goto error;
		}
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(10));
	case PHB3_SLOT_CRESET_REINIT:
		PHBDBG(p, "CRESET: Reinitialization\n");

		/*
		 * Clear AIB fenced state. Otherwise, we can't access the
		 * PCI config space of root complex when reinitializing
		 * the PHB.
		 */
		p->flags &= ~PHB3_AIB_FENCED;
		p->flags &= ~PHB3_CAPP_RECOVERY;
		phb3_init_hw(p, false);

		if (p->flags & PHB3_CAPP_DISABLING) {
			do_capp_recovery_scoms(p);
			p->flags &= ~PHB3_CAPP_DISABLING;
		}

		pci_slot_set_state(slot, PHB3_SLOT_CRESET_FRESET);
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(100));
	case PHB3_SLOT_CRESET_FRESET:
		pci_slot_set_state(slot, PHB3_SLOT_NORMAL);
		return slot->ops.freset(slot);
	default:
		PHBERR(p, "CRESET: Unexpected slot state %08x\n",
		       slot->state);
	}

error:
	return OPAL_HARDWARE;
}

/*
 * Initialize root complex slot, which is mainly used to
 * do fundamental reset before PCI enumeration in PCI core.
 * When probing root complex and building its real slot,
 * the operations will be copied over.
 */
static struct pci_slot *phb3_slot_create(struct phb *phb)
{
	struct pci_slot *slot;

	slot = pci_slot_alloc(phb, NULL);
	if (!slot)
		return slot;

	/* Elementary functions */
	slot->ops.get_presence_state  = phb3_get_presence_state;
	slot->ops.get_link_state      = phb3_get_link_state;
	slot->ops.get_power_state     = NULL;
	slot->ops.get_attention_state = NULL;
	slot->ops.get_latch_state     = NULL;
	slot->ops.set_power_state     = NULL;
	slot->ops.set_attention_state = NULL;

	/*
	 * For PHB slots, we have to split the fundamental reset
	 * into 2 steps. We might not have the first step which
	 * is to power off/on the slot, or it's controlled by
	 * individual platforms.
	 */
	slot->ops.prepare_link_change	= phb3_prepare_link_change;
	slot->ops.poll_link		= phb3_poll_link;
	slot->ops.hreset		= phb3_hreset;
	slot->ops.freset		= phb3_freset;
	slot->ops.creset		= phb3_creset;

	return slot;
}

static int64_t phb3_eeh_freeze_status(struct phb *phb, uint64_t pe_number,
				      uint8_t *freeze_state,
				      uint16_t *pci_error_type,
				      uint16_t *severity)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t peev_bit = PPC_BIT(pe_number & 0x3f);
	uint64_t peev, pesta, pestb;

	/* Defaults: not frozen */
	*freeze_state = OPAL_EEH_STOPPED_NOT_FROZEN;
	*pci_error_type = OPAL_EEH_NO_ERROR;

	/* Check dead */
	if (p->broken) {
		*freeze_state = OPAL_EEH_STOPPED_MMIO_DMA_FREEZE;
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		if (severity)
			*severity = OPAL_EEH_SEV_PHB_DEAD;
		return OPAL_HARDWARE;
	}

	/* Check fence and CAPP recovery */
	if (phb3_fenced(p) || (p->flags & PHB3_CAPP_RECOVERY)) {
		*freeze_state = OPAL_EEH_STOPPED_MMIO_DMA_FREEZE;
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		if (severity)
			*severity = OPAL_EEH_SEV_PHB_FENCED;
		return OPAL_SUCCESS;
	}

	/* Check the PEEV */
	phb3_ioda_sel(p, IODA2_TBL_PEEV, pe_number / 64, false);
	peev = in_be64(p->regs + PHB_IODA_DATA0);
	if (!(peev & peev_bit))
		return OPAL_SUCCESS;

	/* Indicate that we have an ER pending */
	phb3_set_err_pending(p, true);
	if (severity)
		*severity = OPAL_EEH_SEV_PE_ER;

	/* Read the PESTA & PESTB */
	phb3_ioda_sel(p, IODA2_TBL_PESTA, pe_number, false);
	pesta = in_be64(p->regs + PHB_IODA_DATA0);
	phb3_ioda_sel(p, IODA2_TBL_PESTB, pe_number, false);
	pestb = in_be64(p->regs + PHB_IODA_DATA0);

	/* Convert them */
	if (pesta & IODA2_PESTA_MMIO_FROZEN)
		*freeze_state |= OPAL_EEH_STOPPED_MMIO_FREEZE;
	if (pestb & IODA2_PESTB_DMA_STOPPED)
		*freeze_state |= OPAL_EEH_STOPPED_DMA_FREEZE;

	return OPAL_SUCCESS;
}

static int64_t phb3_eeh_freeze_clear(struct phb *phb, uint64_t pe_number,
				     uint64_t eeh_action_token)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t err, peev[4];
	int32_t i;
	bool frozen_pe = false;

	if (p->broken)
		return OPAL_HARDWARE;

	/* Summary. If nothing, move to clearing the PESTs which can
	 * contain a freeze state from a previous error or simply set
	 * explicitely by the user
	 */
	err = in_be64(p->regs + PHB_ETU_ERR_SUMMARY);
	if (err == 0xffffffffffffffffUL) {
		if (phb3_fenced(p)) {
			PHBERR(p, "eeh_freeze_clear on fenced PHB\n");
			return OPAL_HARDWARE;
		}
	}
	if (err != 0)
		phb3_err_ER_clear(p);

	/*
	 * We have PEEV in system memory. It would give more performance
	 * to access that directly.
	 */
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_MMIO) {
		phb3_ioda_sel(p, IODA2_TBL_PESTA, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_DMA) {
		phb3_ioda_sel(p, IODA2_TBL_PESTB, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}


	/* Update ER pending indication */
	phb3_ioda_sel(p, IODA2_TBL_PEEV, 0, true);
	for (i = 0; i < ARRAY_SIZE(peev); i++) {
		peev[i] = in_be64(p->regs + PHB_IODA_DATA0);
		if (peev[i]) {
			frozen_pe = true;
			break;
		}
	}
	if (frozen_pe) {
		p->err.err_src	 = PHB3_ERR_SRC_PHB;
		p->err.err_class = PHB3_ERR_CLASS_ER;
		p->err.err_bit   = -1;
		phb3_set_err_pending(p, true);
	} else
		phb3_set_err_pending(p, false);

	return OPAL_SUCCESS;
}

static int64_t phb3_eeh_freeze_set(struct phb *phb, uint64_t pe_number,
                                   uint64_t eeh_action_token)
{
        struct phb3 *p = phb_to_phb3(phb);
        uint64_t data;

	if (p->broken)
		return OPAL_HARDWARE;

	if (pe_number >= PHB3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	if (eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_MMIO &&
	    eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_DMA &&
	    eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_ALL)
		return OPAL_PARAMETER;

	if (eeh_action_token & OPAL_EEH_ACTION_SET_FREEZE_MMIO) {
		phb3_ioda_sel(p, IODA2_TBL_PESTA, pe_number, false);
		data = in_be64(p->regs + PHB_IODA_DATA0);
		data |= IODA2_PESTA_MMIO_FROZEN;
		out_be64(p->regs + PHB_IODA_DATA0, data);
	}

	if (eeh_action_token & OPAL_EEH_ACTION_SET_FREEZE_DMA) {
		phb3_ioda_sel(p, IODA2_TBL_PESTB, pe_number, false);
		data = in_be64(p->regs + PHB_IODA_DATA0);
		data |= IODA2_PESTB_DMA_STOPPED;
		out_be64(p->regs + PHB_IODA_DATA0, data);
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_eeh_next_error(struct phb *phb,
				   uint64_t *first_frozen_pe,
				   uint16_t *pci_error_type,
				   uint16_t *severity)
{
	struct phb3 *p = phb_to_phb3(phb);
	uint64_t fir, peev[4];
	uint32_t cfg32;
	int32_t i, j;

	/* If the PHB is broken, we needn't go forward */
	if (p->broken) {
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_DEAD;
		return OPAL_SUCCESS;
	}

	if ((p->flags & PHB3_CAPP_RECOVERY)) {
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_FENCED;
		return OPAL_SUCCESS;
	}

	/*
	 * Check if we already have pending errors. If that's
	 * the case, then to get more information about the
	 * pending errors. Here we try PBCQ prior to PHB.
	 */
	if (phb3_err_pending(p) &&
	    !phb3_err_check_pbcq(p) &&
	    !phb3_err_check_lem(p))
		phb3_set_err_pending(p, false);

	/* Clear result */
	*pci_error_type  = OPAL_EEH_NO_ERROR;
	*severity	 = OPAL_EEH_SEV_NO_ERROR;
	*first_frozen_pe = (uint64_t)-1;

	/* Check frozen PEs */
	if (!phb3_err_pending(p)) {
		phb3_ioda_sel(p, IODA2_TBL_PEEV, 0, true);
		for (i = 0; i < ARRAY_SIZE(peev); i++) {
			peev[i] = in_be64(p->regs + PHB_IODA_DATA0);
			if (peev[i]) {
				p->err.err_src	 = PHB3_ERR_SRC_PHB;
				p->err.err_class = PHB3_ERR_CLASS_ER;
				p->err.err_bit	 = -1;
				phb3_set_err_pending(p, true);
				break;
			}
		}
        }

	/* Mapping errors */
	if (phb3_err_pending(p)) {
		/*
		 * If the frozen PE is caused by a malfunctioning TLP, we
		 * need reset the PHB. So convert ER to PHB-fatal error
		 * for the case.
		 */
		if (p->err.err_class == PHB3_ERR_CLASS_ER) {
			fir = phb3_read_reg_asb(p, PHB_LEM_FIR_ACCUM);
			if (fir & PPC_BIT(60)) {
				phb3_pcicfg_read32(&p->phb, 0,
					p->aercap + PCIECAP_AER_UE_STATUS, &cfg32);
				if (cfg32 & PCIECAP_AER_UE_MALFORMED_TLP)
					p->err.err_class = PHB3_ERR_CLASS_FENCED;
			}
		}

		switch (p->err.err_class) {
		case PHB3_ERR_CLASS_DEAD:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_PHB_DEAD;
			break;
		case PHB3_ERR_CLASS_FENCED:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_PHB_FENCED;
			break;
		case PHB3_ERR_CLASS_ER:
			*pci_error_type = OPAL_EEH_PE_ERROR;
			*severity = OPAL_EEH_SEV_PE_ER;

			phb3_ioda_sel(p, IODA2_TBL_PEEV, 0, true);
			for (i = 0; i < ARRAY_SIZE(peev); i++)
				peev[i] = in_be64(p->regs + PHB_IODA_DATA0);
			for (i = ARRAY_SIZE(peev) - 1; i >= 0; i--) {
				for (j = 0; j < 64; j++) {
					if (peev[i] & PPC_BIT(j)) {
						*first_frozen_pe = i * 64 + j;
						break;
					}
				}

				if (*first_frozen_pe != (uint64_t)(-1))
					break;
			}

			/* No frozen PE ? */
			if (*first_frozen_pe == (uint64_t)-1) {
				*pci_error_type = OPAL_EEH_NO_ERROR;
				*severity = OPAL_EEH_SEV_NO_ERROR;
				phb3_set_err_pending(p, false);
			}

                        break;
		case PHB3_ERR_CLASS_INF:
			*pci_error_type = OPAL_EEH_PHB_ERROR;
			*severity = OPAL_EEH_SEV_INF;
			break;
		default:
			*pci_error_type = OPAL_EEH_NO_ERROR;
			*severity = OPAL_EEH_SEV_NO_ERROR;
			phb3_set_err_pending(p, false);
		}
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_err_inject_finalize(struct phb3 *p, uint64_t addr,
					uint64_t mask, uint64_t ctrl,
					bool is_write)
{
	if (is_write)
		ctrl |= PHB_PAPR_ERR_INJ_CTL_WR;
	else
		ctrl |= PHB_PAPR_ERR_INJ_CTL_RD;

	out_be64(p->regs + PHB_PAPR_ERR_INJ_ADDR, addr);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_MASK, mask);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_CTL, ctrl);

	return OPAL_SUCCESS;
}

static int64_t phb3_err_inject_mem32(struct phb3 *p, uint64_t pe_number,
				     uint64_t addr, uint64_t mask,
				     bool is_write)
{
	uint64_t base, len, segstart, segsize;
	uint64_t a, m;
	uint64_t ctrl = PHB_PAPR_ERR_INJ_CTL_OUTB;
	uint32_t index;

	segsize = (M32_PCI_SIZE / PHB3_MAX_PE_NUM);
	a = base = len = 0x0ull;

	for (index = 0; index < PHB3_MAX_PE_NUM; index++) {
		if (GETFIELD(IODA2_M32DT_PE, p->m32d_cache[index]) != pe_number)
			continue;

		/* Obviously, we can't support discontiguous segments.
		 * We have to pick the first batch of contiguous segments
		 * for that case
		 */
		segstart = p->mm1_base + segsize * index;
		if (!len) {
			base = segstart;
			len = segsize;
		} else if ((base + len) == segstart) {
			len += segsize;
		}

		/* Check the specified address is valid one */
		if (addr >= segstart && addr < (segstart + segsize)) {
			a = addr;
			break;
		}
	}

	/* No MM32 segments assigned to the PE */
	if (!len)
		return OPAL_PARAMETER;

	/* Specified address is out of range */
	if (!a) {
		a = base;
		len = len & ~(len - 1);
		m = ~(len - 1);
	} else {
		m = mask;
	}

	a = SETFIELD(PHB_PAPR_ERR_INJ_ADDR_MMIO, 0x0ull, a);
	m = SETFIELD(PHB_PAPR_ERR_INJ_MASK_MMIO, 0x0ull, m);

	return phb3_err_inject_finalize(p, a, m, ctrl, is_write);
}

static int64_t phb3_err_inject_mem64(struct phb3 *p, uint64_t pe_number,
				     uint64_t addr, uint64_t mask,
				     bool is_write)
{
	uint64_t base, len, segstart, segsize;
	uint64_t cache, a, m;
	uint64_t ctrl = PHB_PAPR_ERR_INJ_CTL_OUTB;
	uint32_t index, s_index, e_index;

	/* By default, the PE is PCI device dependent one */
	s_index = 0;
	e_index = ARRAY_SIZE(p->m64b_cache) - 2;
	for (index = 0; index < RTT_TABLE_ENTRIES; index++) {
		if (p->rte_cache[index] != pe_number)
			continue;

		if (index + 8 >= RTT_TABLE_ENTRIES)
			break;

		/* PCI bus dependent PE */
		if (p->rte_cache[index + 8] == pe_number) {
			s_index = e_index = ARRAY_SIZE(p->m64b_cache) - 1;
			break;
		}
	}

	a = base = len = 0x0ull;
	for (index = s_index; !len && index <= e_index; index++) {
		cache = p->m64b_cache[index];
		if (!(cache & IODA2_M64BT_ENABLE))
			continue;

		if (cache & IODA2_M64BT_SINGLE_PE) {
			if (GETFIELD(IODA2_M64BT_PE_HI, cache) != (pe_number >> 5) ||
			    GETFIELD(IODA2_M64BT_PE_LOW, cache) != (pe_number & 0x1f))
				continue;

			segstart = GETFIELD(IODA2_M64BT_SINGLE_BASE, cache);
			segstart <<= 25;	/* 32MB aligned */
			segsize = GETFIELD(IODA2_M64BT_SINGLE_MASK, cache);
			segsize = (0x2000000ull - segsize) << 25;
		} else {
			segstart = GETFIELD(IODA2_M64BT_BASE, cache);
			segstart <<= 20;	/* 1MB aligned */
			segsize = GETFIELD(IODA2_M64BT_MASK, cache);
			segsize = (0x40000000ull - segsize) << 20;

			segsize /= PHB3_MAX_PE_NUM;
			segstart = segstart + segsize * pe_number;
		}

		/* First window always wins based on the ascending
		 * searching priority the 16 BARs have. We're using
		 * the feature to assign resource for SRIOV VFs.
		 */
		if (!len) {
			base = segstart;
			len = segsize;
		}

		/* Specified address is valid one */
		if (addr >= segstart && addr < (segstart + segsize)) {
			a = addr;
		}
	}

	/* No MM64 segments assigned to the PE */
	if (!len)
		return OPAL_PARAMETER;

	/* Address specified or calculated */
	if (!a) {
		a = base;
		len = len & ~(len - 1);
		m = ~(len - 1);
	} else {
		m = mask;
	}

	a = SETFIELD(PHB_PAPR_ERR_INJ_ADDR_MMIO, 0x0ull, a);
	m = SETFIELD(PHB_PAPR_ERR_INJ_MASK_MMIO, 0x0ull, m);

	return phb3_err_inject_finalize(p, a, m, ctrl, is_write);
}

static int64_t phb3_err_inject_cfg(struct phb3 *p, uint64_t pe_number,
				   uint64_t addr, uint64_t mask,
				   bool is_write)
{
	uint64_t a, m, prefer;
	uint64_t ctrl = PHB_PAPR_ERR_INJ_CTL_CFG;
	int bdfn;
	bool is_bus_pe;

	a = 0xffffull;
	prefer = 0xffffull;
	m = PHB_PAPR_ERR_INJ_MASK_CFG_ALL;
	for (bdfn = 0; bdfn < RTT_TABLE_ENTRIES; bdfn++) {
		if (p->rte_cache[bdfn] != pe_number)
			continue;

		/* The PE can be associated with PCI bus or device */
		is_bus_pe = false;
		if ((bdfn + 8) < RTT_TABLE_ENTRIES &&
		    p->rte_cache[bdfn + 8] == pe_number)
			is_bus_pe = true;

		/* Figure out the PCI config address */
		if (prefer == 0xffffull) {
			if (is_bus_pe) {
				m = PHB_PAPR_ERR_INJ_MASK_CFG;
				prefer = SETFIELD(m, 0x0ull, PCI_BUS_NUM(bdfn));
			} else {
				m = PHB_PAPR_ERR_INJ_MASK_CFG_ALL;
				prefer = SETFIELD(m, 0x0ull, bdfn);
			}
		}

		/* Check the input address is valid or not */
		if (!is_bus_pe &&
		    GETFIELD(PHB_PAPR_ERR_INJ_MASK_CFG_ALL, addr) == bdfn) {
			a = addr;
			break;
		}

		if (is_bus_pe &&
		    GETFIELD(PHB_PAPR_ERR_INJ_MASK_CFG, addr) == PCI_BUS_NUM(bdfn)) {
			a = addr;
			break;
		}
	}

	/* Invalid PE number */
	if (prefer == 0xffffull)
		return OPAL_PARAMETER;

	/* Specified address is out of range */
	if (a == 0xffffull)
		a = prefer;
	else
		m = mask;

	return phb3_err_inject_finalize(p, a, m, ctrl, is_write);
}

static int64_t phb3_err_inject_dma(struct phb3 *p, uint64_t pe_number,
				   uint64_t addr, uint64_t mask,
				   bool is_write, bool is_64bits)
{
	uint32_t index, page_size;
	uint64_t tve, table_entries;
	uint64_t base, start, end, len, a, m;
	uint64_t ctrl = PHB_PAPR_ERR_INJ_CTL_INB;

	/* TVE index and base address */
	if (!is_64bits) {
		index = (pe_number << 1);
		base = 0x0ull;
	} else {
		index = ((pe_number << 1) + 1);
		base = (0x1ull << 59);
	}

	/* Raw data of table entries and page size */
	tve = p->tve_cache[index];
	table_entries = GETFIELD(IODA2_TVT_TCE_TABLE_SIZE, tve);
	table_entries = (0x1ull << (table_entries + 8));
	page_size = GETFIELD(IODA2_TVT_IO_PSIZE, tve);
	if (!page_size && !(tve & PPC_BIT(51)))
		return OPAL_UNSUPPORTED;

	/* Check the page size */
	switch (page_size) {
	case 0:	/* bypass */
		start = ((tve & (0x3ull << 10)) << 14) |
			((tve & (0xffffffull << 40)) >> 40);
		end   = ((tve & (0x3ull << 8)) << 16) |
			((tve & (0xffffffull << 16)) >> 16);

		/* 16MB aligned size */
		len   = (end - start) << 24;
		break;
	case 5:  /* 64KB */
		len = table_entries * 0x10000ull;
		break;
	case 13: /* 16MB */
		len = table_entries * 0x1000000ull;
		break;
	case 17: /* 256MB */
		len = table_entries * 0x10000000ull;
		break;
	case 1:  /* 4KB */
	default:
		len = table_entries * 0x1000ull;
	}

	/* The specified address is in range */
	if (addr && addr >= base && addr < (base + len)) {
		a = addr;
		m = mask;
	} else {
		a = base;
		len = len & ~(len - 1);
		m = ~(len - 1);
	}

	return phb3_err_inject_finalize(p, a, m, ctrl, is_write);
}

static int64_t phb3_err_inject_dma32(struct phb3 *p, uint64_t pe_number,
				     uint64_t addr, uint64_t mask,
				     bool is_write)
{
	return phb3_err_inject_dma(p, pe_number, addr, mask, is_write, false);
}

static int64_t phb3_err_inject_dma64(struct phb3 *p, uint64_t pe_number,
				     uint64_t addr, uint64_t mask,
				     bool is_write)
{
	return phb3_err_inject_dma(p, pe_number, addr, mask, is_write, true);
}

static int64_t phb3_err_inject(struct phb *phb, uint64_t pe_number,
			       uint32_t type, uint32_t func,
			       uint64_t addr, uint64_t mask)
{
	struct phb3 *p = phb_to_phb3(phb);
	int64_t (*handler)(struct phb3 *p, uint64_t pe_number,
			   uint64_t addr, uint64_t mask, bool is_write);
	bool is_write;

	/* How could we get here without valid RTT? */
	if (!p->tbl_rtt)
		return OPAL_HARDWARE;

	/* We can't inject error to the reserved PE */
	if (pe_number == PHB3_RESERVED_PE_NUM || pe_number >= PHB3_MAX_PE_NUM)
		return OPAL_PARAMETER;

	/* Clear leftover from last time */
	out_be64(p->regs + PHB_PAPR_ERR_INJ_CTL, 0x0ul);

	switch (func) {
	case OPAL_ERR_INJECT_FUNC_IOA_LD_MEM_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_LD_MEM_DATA:
		is_write = false;
		if (type == OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
			handler = phb3_err_inject_mem64;
		else
			handler = phb3_err_inject_mem32;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_ST_MEM_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_ST_MEM_DATA:
		is_write = true;
		if (type == OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
			handler = phb3_err_inject_mem64;
		else
			handler = phb3_err_inject_mem32;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_LD_CFG_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_LD_CFG_DATA:
		is_write = false;
		handler = phb3_err_inject_cfg;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_ST_CFG_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_ST_CFG_DATA:
		is_write = true;
		handler = phb3_err_inject_cfg;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_DATA:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_MASTER:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_TARGET:
		is_write = false;
		if (type == OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
			handler = phb3_err_inject_dma64;
		else
			handler = phb3_err_inject_dma32;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_DATA:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_MASTER:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_TARGET:
		is_write = true;
		if (type == OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
			handler = phb3_err_inject_dma64;
		else
			handler = phb3_err_inject_dma32;
		break;
	default:
		return OPAL_PARAMETER;
	}

	return handler(p, pe_number, addr, mask, is_write);
}

static int64_t phb3_get_diag_data(struct phb *phb,
				  void *diag_buffer,
				  uint64_t diag_buffer_len)
{
	struct phb3 *p = phb_to_phb3(phb);
	struct OpalIoPhb3ErrorData *data = diag_buffer;
	bool fenced;

	if (diag_buffer_len < sizeof(struct OpalIoPhb3ErrorData))
		return OPAL_PARAMETER;
	if (p->broken)
		return OPAL_HARDWARE;

	/*
	 * Dummy check for fence so that phb3_read_phb_status knows
	 * whether to use ASB or AIB
	 */
	fenced = phb3_fenced(p);
	phb3_read_phb_status(p, data);

	if (!fenced)
		phb3_eeh_dump_regs(p, data);

	/*
	 * We're running to here probably because of errors
	 * (INF class). For that case, we need clear the error
	 * explicitly.
	 */
	if (phb3_err_pending(p) &&
	    p->err.err_class == PHB3_ERR_CLASS_INF &&
	    p->err.err_src == PHB3_ERR_SRC_PHB) {
		phb3_err_ER_clear(p);
		phb3_set_err_pending(p, false);
	}

	return OPAL_SUCCESS;
}

static int64_t phb3_get_capp_info(int chip_id, struct phb *phb,
				  struct capp_info *info)
{
	struct phb3 *p = phb_to_phb3(phb);
	struct proc_chip *chip = get_chip(p->chip_id);
	uint32_t offset;

	if (chip_id != p->chip_id)
		return OPAL_PARAMETER;

	if (!((1 << p->index) & chip->capp_phb3_attached_mask))
		return OPAL_PARAMETER;

	offset = PHB3_CAPP_REG_OFFSET(p);

	if (PHB3_IS_NAPLES(p)) {
		if (p->index == 0)
			info->capp_index = 0;
		else
			info->capp_index = 1;
	} else
		info->capp_index = 0;
	info->phb_index = p->index;
	info->capp_fir_reg = CAPP_FIR + offset;
	info->capp_fir_mask_reg = CAPP_FIR_MASK + offset;
	info->capp_fir_action0_reg = CAPP_FIR_ACTION0 + offset;
	info->capp_fir_action1_reg = CAPP_FIR_ACTION1 + offset;
	info->capp_err_status_ctrl_reg = CAPP_ERR_STATUS_CTRL + offset;

	return OPAL_SUCCESS;
}

static void phb3_init_capp_regs(struct phb3 *p, bool dma_mode)
{
	uint64_t reg;
	uint32_t offset;
	uint64_t read_buffers = 0;

	offset = PHB3_CAPP_REG_OFFSET(p);
	xscom_read(p->chip_id, APC_MASTER_PB_CTRL + offset, &reg);
	reg &= ~PPC_BITMASK(10, 11);
	reg |= PPC_BIT(3);
	if (dma_mode) {
		/* In DMA mode, the CAPP only owns some of the PHB read buffers */
		read_buffers = 0x1;

		/*
		 * HW301991 - XSL sends PTE updates with nodal scope instead of
		 * group scope. The workaround is to force all commands to
		 * unlimited scope by setting bit 4. This may have a slight
		 * performance impact, but it would be negligible on the XSL.
		 * To avoid the possibility it might impact other cards, key it
		 * off DMA mode since the XSL based Mellanox CX4 is the only
		 * card to use this mode in P8 timeframe:
		 */
		reg |= PPC_BIT(4);
	}
	reg |= read_buffers << PPC_BITLSHIFT(11);
	xscom_write(p->chip_id, APC_MASTER_PB_CTRL + offset, reg);

	/* Dynamically workout which PHB to connect to port 0 of the CAPP.
	 * Here is the table from the CAPP workbook:
	 *	     APC_MASTER		CAPP		CAPP
	 *	      bits 1:3		port0		port1
	 *		000		 disabled	 disabled
	 *	     *	001		 PHB2		 disabled
	 *	     *	010		 PHB1		 disabled
	 *		011		 PHB1		 PHB2
	 *	     *	100		 PHB0		 disabled
	 *		101		 PHB0		 PHB2
	 *		110		 PHB0		 PHB1
	 *
	 * We don't use port1 so only those starred above are used.
	 * Hence reduce table to:
	 *    PHB0 -> APC MASTER(bits 1:3) = 0b100
	 *    PHB1 -> APC MASTER(bits 1:3) = 0b010
	 *    PHB2 -> APC MASTER(bits 1:3) = 0b001
	 *
	 * Note: Naples has two CAPP units, statically mapped:
	 *    CAPP0/PHB0 -> APC MASTER(bits 1:3) = 0b100
	 *    CAPP1/PHB1 -> APC MASTER(bits 1:3) = 0b010
	 */
	reg = 0x4000000000000000ULL >> p->index;
	reg |= 0x0070000000000000UL;
	xscom_write(p->chip_id, APC_MASTER_CAPI_CTRL + offset, reg);
	PHBINF(p, "CAPP: port attached\n");

	/* tlb and mmio */
	xscom_write(p->chip_id, TRANSPORT_CONTROL + offset, 0x4028000104000000UL);

	xscom_write(p->chip_id, CANNED_PRESP_MAP0 + offset, 0);
	xscom_write(p->chip_id, CANNED_PRESP_MAP1 + offset, 0xFFFFFFFF00000000UL);
	xscom_write(p->chip_id, CANNED_PRESP_MAP2 + offset, 0);

	/* error recovery */
	xscom_write(p->chip_id, CAPP_ERR_STATUS_CTRL + offset, 0);

	xscom_write(p->chip_id, FLUSH_SUE_STATE_MAP + offset,
		    0x1DC20B6600000000UL);
	xscom_write(p->chip_id, CAPP_EPOCH_TIMER_CTRL + offset,
		    0xC0000000FFF0FFE0UL);
	xscom_write(p->chip_id,  FLUSH_UOP_CONFIG1 + offset,
		    0xB188280728000000UL);
	xscom_write(p->chip_id, FLUSH_UOP_CONFIG2 + offset, 0xB188400F00000000UL);

	reg = 0xA1F0000000000000UL;
	reg |= read_buffers << PPC_BITLSHIFT(39);
	xscom_write(p->chip_id, SNOOP_CAPI_CONFIG + offset, reg);
}

/* override some inits with CAPI defaults */
static void phb3_init_capp_errors(struct phb3 *p)
{
	out_be64(p->regs + PHB_ERR_AIB_FENCE_ENABLE,       0xffffffdd8c80ffc0UL);
	out_be64(p->regs + PHB_OUT_ERR_AIB_FENCE_ENABLE,   0x9cf3fe08f8dc700fUL);
	out_be64(p->regs + PHB_INA_ERR_AIB_FENCE_ENABLE,   0xffff57fbff01ffdeUL);
	out_be64(p->regs + PHB_INB_ERR_AIB_FENCE_ENABLE,   0xfcffe0fbff7ff0ecUL);
	out_be64(p->regs + PHB_LEM_ERROR_MASK,		   0x40018e2400022482UL);
}

/*
 * Enable CAPI mode on a PHB
 *
 * Changes to this init sequence may require updating disable_capi_mode().
 */
static int64_t enable_capi_mode(struct phb3 *p, uint64_t pe_number, bool dma_mode)
{
	uint64_t reg;
	int i;

	xscom_read(p->chip_id, PE_CAPP_EN + PE_REG_OFFSET(p), &reg);
	if (reg & PPC_BIT(0)) {
		PHBDBG(p, "Already in CAPP mode\n");
	}

	/* poll cqstat */
	for (i = 0; i < 500000; i++) {
		xscom_read(p->chip_id, p->pe_xscom + 0xf, &reg);
		if (!(reg & 0xC000000000000000UL))
			break;
		time_wait_us(10);
	}
	if (reg & 0xC000000000000000UL) {
		PHBERR(p, "CAPP: Timeout waiting for pending transaction\n");
		return OPAL_HARDWARE;
	}

	/* pb aib capp enable */
	reg = PPC_BIT(0); /* capp enable */
	if (dma_mode)
		reg |= PPC_BIT(1); /* capp dma mode */
	xscom_write(p->chip_id, p->spci_xscom + 0x3, reg);

	/* FIXME security timer bar
	xscom_write(p->chip_id, p->spci_xscom + 0x4, 0x8000000000000000ull);
	*/

	/* aib mode */
	xscom_read(p->chip_id, p->pci_xscom + 0xf, &reg);
	reg &= ~PPC_BITMASK(6,7);
	reg |= PPC_BIT(8);
	reg |= PPC_BITMASK(40, 41);
	reg &= ~PPC_BIT(42);
	xscom_write(p->chip_id, p->pci_xscom + 0xf, reg);

	/* pci hwconf0 */
	xscom_read(p->chip_id, p->pe_xscom + 0x18, &reg);
	reg |= PPC_BIT(14);
	reg &= ~PPC_BIT(15);
	xscom_write(p->chip_id, p->pe_xscom + 0x18, reg);

	/* pci hwconf1 */
	xscom_read(p->chip_id, p->pe_xscom + 0x19, &reg);
	reg &= ~PPC_BITMASK(17,18);
	xscom_write(p->chip_id, p->pe_xscom + 0x19, reg);

	/* aib tx cmd cred */
	xscom_read(p->chip_id, p->pci_xscom + 0xd, &reg);
	if (dma_mode) {
		/*
		 * In DMA mode, increase AIB credit value for ch 2 (DMA read)
		 * for performance reasons
		 */
		reg &= ~PPC_BITMASK(42, 47);
		reg |= PPC_BITMASK(43, 45);
	} else {
		reg &= ~PPC_BITMASK(42, 46);
		reg |= PPC_BIT(47);
	}
	xscom_write(p->chip_id, p->pci_xscom + 0xd, reg);

	xscom_write(p->chip_id, p->pci_xscom + 0xc, 0xff00000000000000ull);

	/* pci mode ctl */
	xscom_read(p->chip_id, p->pe_xscom + 0xb, &reg);
	reg |= PPC_BIT(25);
	xscom_write(p->chip_id, p->pe_xscom + 0xb, reg);

	/* set tve no translate mode allow mmio window */
	memset(p->tve_cache, 0x0, sizeof(p->tve_cache));
	if (dma_mode) {
		/*
		 * CAPP DMA mode needs access to all of memory, set address
		 * range to 0x0000000000000000: 0x0002FFFFFFFFFFF
		 */
		p->tve_cache[pe_number * 2] = 0x000000FFFFFF0200ULL;
	} else {
		/* Allow address range 0x0002000000000000: 0x0002FFFFFFFFFFF */
		p->tve_cache[pe_number * 2] = 0x000000FFFFFF0a00ULL;
	}

	phb3_ioda_sel(p, IODA2_TBL_TVT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->tve_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->tve_cache[i]);

	/* set m64 bar to pass mmio window */
	memset(p->m64b_cache, 0x0, sizeof(p->m64b_cache));
	p->m64b_cache[0] = PPC_BIT(0); /*enable*/
	p->m64b_cache[0] |= PPC_BIT(1); /*single pe*/
	p->m64b_cache[0] |= (p->mm0_base << 12) | ((pe_number & 0x3e0) << 27); /*base and upper pe*/
	p->m64b_cache[0] |= 0x3fffc000 | (pe_number & 0x1f); /*mask and lower pe*/

	p->m64b_cache[1] = PPC_BIT(0); /*enable*/
	p->m64b_cache[1] |= PPC_BIT(1); /*single pe*/
	p->m64b_cache[1] |= (0x0002000000000000ULL << 12) | ((pe_number & 0x3e0) << 27); /*base and upper pe*/
	p->m64b_cache[1] |= 0x3f000000 | (pe_number & 0x1f); /*mask and lower pe*/

	phb3_ioda_sel(p, IODA2_TBL_M64BT, 0, true);
	for (i = 0; i < ARRAY_SIZE(p->m64b_cache); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->m64b_cache[i]);

	out_be64(p->regs + PHB_PHB3_CONFIG, PHB_PHB3C_64B_TCE_EN);
	out_be64(p->regs + PHB_PHB3_CONFIG, PHB_PHB3C_64BIT_MSI_EN);

	phb3_init_capp_errors(p);

	phb3_init_capp_regs(p, dma_mode);

	if (!chiptod_capp_timebase_sync(p->chip_id, CAPP_TFMR, CAPP_TB,
					PHB3_CAPP_REG_OFFSET(p))) {
		PHBERR(p, "CAPP: Failed to sync timebase\n");
		return OPAL_HARDWARE;
	}

	/* set callbacks to handle HMI events */
	capi_ops.get_capp_info = &phb3_get_capp_info;

	return OPAL_SUCCESS;
}

static int64_t phb3_set_capi_mode(struct phb *phb, uint64_t mode,
				  uint64_t pe_number)
{
	struct phb3 *p = phb_to_phb3(phb);
	struct proc_chip *chip = get_chip(p->chip_id);
	uint64_t reg;
	uint64_t read_buffers;
	uint32_t offset;
	u8 mask;

	if (!capp_ucode_loaded(chip, p->index)) {
		PHBERR(p, "CAPP: ucode not loaded\n");
		return OPAL_RESOURCE;
	}

	lock(&capi_lock);
	if (PHB3_IS_NAPLES(p)) {
		/* Naples has two CAPP units, statically mapped. */
		chip->capp_phb3_attached_mask |= 1 << p->index;
	} else {
		/*
		* Check if CAPP port is being used by any another PHB.
		* Check and set chip->capp_phb3_attached_mask atomically
		* incase two phb3_set_capi_mode() calls race.
		*/
		mask = ~(1 << p->index);
		if (chip->capp_phb3_attached_mask & mask) {
			PHBERR(p,
			       "CAPP: port already in use by another PHB:%x\n",
			       chip->capp_phb3_attached_mask);
			unlock(&capi_lock);
			return false;
		}
		chip->capp_phb3_attached_mask = 1 << p->index;
	}
	unlock(&capi_lock);

	offset = PHB3_CAPP_REG_OFFSET(p);
	xscom_read(p->chip_id, CAPP_ERR_STATUS_CTRL + offset, &reg);
	if ((reg & PPC_BIT(5))) {
		PHBERR(p, "CAPP: recovery failed (%016llx)\n", reg);
		return OPAL_HARDWARE;
	} else if ((reg & PPC_BIT(0)) && (!(reg & PPC_BIT(1)))) {
		PHBDBG(p, "CAPP: recovery in progress\n");
		return OPAL_BUSY;
	}

	switch (mode) {
	case OPAL_PHB_CAPI_MODE_PCIE:
		/* Switching back to PCIe mode requires a creset */
		return OPAL_UNSUPPORTED;

	case OPAL_PHB_CAPI_MODE_CAPI:
		return enable_capi_mode(p, pe_number, false);

	case OPAL_PHB_CAPI_MODE_DMA:
		return enable_capi_mode(p, pe_number, true);

	case OPAL_PHB_CAPI_MODE_SNOOP_OFF:
		xscom_write(p->chip_id, SNOOP_CAPI_CONFIG + offset,
			    0x0000000000000000);
		return OPAL_SUCCESS;

	case OPAL_PHB_CAPI_MODE_SNOOP_ON:
		xscom_write(p->chip_id, CAPP_ERR_STATUS_CTRL + offset,
			    0x0000000000000000);
		/*
		 * Make sure the PHB read buffers being snooped match those
		 * being used so we don't need another mode to set SNOOP+DMA
		 */
		xscom_read(p->chip_id, APC_MASTER_PB_CTRL + offset, &reg);
		read_buffers = (reg >> PPC_BITLSHIFT(11)) & 0x3;
		reg = 0xA1F0000000000000UL;
		reg |= read_buffers << PPC_BITLSHIFT(39);
		xscom_write(p->chip_id, SNOOP_CAPI_CONFIG + offset, reg);

		return OPAL_SUCCESS;
	}

	return OPAL_UNSUPPORTED;
}

static int64_t phb3_set_capp_recovery(struct phb *phb)
{
	struct phb3 *p = phb_to_phb3(phb);

	if (p->flags & PHB3_CAPP_RECOVERY)
		return 0;

	/* set opal event flag to indicate eeh condition */
	opal_update_pending_evt(OPAL_EVENT_PCI_ERROR,
				OPAL_EVENT_PCI_ERROR);

	p->flags |= PHB3_CAPP_RECOVERY;

	return 0;
}

static const struct phb_ops phb3_ops = {
	.cfg_read8		= phb3_pcicfg_read8,
	.cfg_read16		= phb3_pcicfg_read16,
	.cfg_read32		= phb3_pcicfg_read32,
	.cfg_write8		= phb3_pcicfg_write8,
	.cfg_write16		= phb3_pcicfg_write16,
	.cfg_write32		= phb3_pcicfg_write32,
	.get_reserved_pe_number	= phb3_get_reserved_pe_number,
	.device_init		= phb3_device_init,
	.device_remove		= phb3_device_remove,
	.ioda_reset		= phb3_ioda_reset,
	.papr_errinjct_reset	= phb3_papr_errinjct_reset,
	.pci_reinit		= phb3_pci_reinit,
	.set_phb_mem_window	= phb3_set_phb_mem_window,
	.phb_mmio_enable	= phb3_phb_mmio_enable,
	.map_pe_mmio_window	= phb3_map_pe_mmio_window,
	.map_pe_dma_window	= phb3_map_pe_dma_window,
	.map_pe_dma_window_real = phb3_map_pe_dma_window_real,
	.pci_msi_eoi		= phb3_pci_msi_eoi,
	.set_xive_pe		= phb3_set_ive_pe,
	.get_msi_32		= phb3_get_msi_32,
	.get_msi_64		= phb3_get_msi_64,
	.set_pe			= phb3_set_pe,
	.set_peltv		= phb3_set_peltv,
	.eeh_freeze_status	= phb3_eeh_freeze_status,
	.eeh_freeze_clear	= phb3_eeh_freeze_clear,
	.eeh_freeze_set		= phb3_eeh_freeze_set,
	.next_error		= phb3_eeh_next_error,
	.err_inject		= phb3_err_inject,
	.get_diag_data2		= phb3_get_diag_data,
	.set_capi_mode		= phb3_set_capi_mode,
	.set_capp_recovery	= phb3_set_capp_recovery,
};

/*
 * We should access those registers at the stage since the
 * AIB isn't ready yet.
 */
static void phb3_setup_aib(struct phb3 *p)
{
	/* Init_2 - AIB TX Channel Mapping Register */
	phb3_write_reg_asb(p, PHB_AIB_TX_CHAN_MAPPING,    	0x0211230000000000UL);

	/* Init_3 - AIB RX command credit register */
	if (p->rev >= PHB3_REV_VENICE_DD20)
		phb3_write_reg_asb(p, PHB_AIB_RX_CMD_CRED,	0x0020000100020001UL);
	else
		phb3_write_reg_asb(p, PHB_AIB_RX_CMD_CRED,	0x0020000100010001UL);
	
	/* Init_4 - AIB rx data credit register */
	if (p->rev >= PHB3_REV_VENICE_DD20)
		phb3_write_reg_asb(p, PHB_AIB_RX_DATA_CRED,	0x0020002000010001UL);
	else
		phb3_write_reg_asb(p, PHB_AIB_RX_DATA_CRED,	0x0020002000000001UL);

	/* Init_5 - AIB rx credit init timer register */
	phb3_write_reg_asb(p, PHB_AIB_RX_CRED_INIT_TIMER,	0x0f00000000000000UL);

	/* Init_6 - AIB Tag Enable register */
	phb3_write_reg_asb(p, PHB_AIB_TAG_ENABLE,		0xffffffff00000000UL);

	/* Init_7 - TCE Tag Enable register */
	phb3_write_reg_asb(p, PHB_TCE_TAG_ENABLE,         0xffffffff00000000UL);
}

static void phb3_init_ioda2(struct phb3 *p)
{
	/* Init_14 - LSI Source ID */
	out_be64(p->regs + PHB_LSI_SOURCE_ID,
		 SETFIELD(PHB_LSI_SRC_ID, 0ul, 0xff));

	/* Init_15 - IVT BAR / Length
	 * Init_16 - RBA BAR
	 * 	   - RTT BAR
	 * Init_17 - PELT-V BAR
	 */
	out_be64(p->regs + PHB_RTT_BAR,
		 p->tbl_rtt | PHB_RTT_BAR_ENABLE);
	out_be64(p->regs + PHB_PELTV_BAR,
		 p->tbl_peltv | PHB_PELTV_BAR_ENABLE);
	out_be64(p->regs + PHB_IVT_BAR,
		 p->tbl_ivt | 0x800 | PHB_IVT_BAR_ENABLE);

	/* DD2.0 or the subsequent chips don't have memory
	 * resident RBA.
	 */
	if (p->rev >= PHB3_REV_MURANO_DD20)
		out_be64(p->regs + PHB_RBA_BAR, 0x0ul);
	else
		out_be64(p->regs + PHB_RBA_BAR,
			 p->tbl_rba | PHB_RBA_BAR_ENABLE);

	/* Init_18..21 - Setup M32 */
	out_be64(p->regs + PHB_M32_BASE_ADDR, p->mm1_base);
	out_be64(p->regs + PHB_M32_BASE_MASK, ~(M32_PCI_SIZE - 1));
	out_be64(p->regs + PHB_M32_START_ADDR, M32_PCI_START);

	/* Init_22 - Setup PEST BAR */
	out_be64(p->regs + PHB_PEST_BAR,
		 p->tbl_pest | PHB_PEST_BAR_ENABLE);

	/* Init_23 - PCIE Outbound upper address */
	out_be64(p->regs + PHB_M64_UPPER_BITS, 0);

	/* Init_24 - Interrupt represent timers
	 * The register doesn't take effect on Murano DD1.0
	 */
	if (p->rev >= PHB3_REV_NAPLES_DD10)
		out_be64(p->regs + PHB_INTREP_TIMER, 0x0014000000000000UL);
	else if (p->rev >= PHB3_REV_MURANO_DD20)
		out_be64(p->regs + PHB_INTREP_TIMER, 0x0004000000000000UL);
	else
		out_be64(p->regs + PHB_INTREP_TIMER, 0);

	/* Init_25 - PHB3 Configuration Register. Clear TCE cache then
	 *           configure the PHB
	 */
	out_be64(p->regs + PHB_PHB3_CONFIG, PHB_PHB3C_64B_TCE_EN);
	out_be64(p->regs + PHB_PHB3_CONFIG,
		 PHB_PHB3C_M32_EN | PHB_PHB3C_32BIT_MSI_EN |
		 PHB_PHB3C_64BIT_MSI_EN);

	/* Init_26 - At least 512ns delay according to spec */
	time_wait_us(2);

	/* Init_27..36 - On-chip IODA tables init */
	phb3_ioda_reset(&p->phb, false);
}

static bool phb3_wait_dlp_reset(struct phb3 *p)
{
	unsigned int i;
	uint64_t val;

	/*
	 * Firmware cannot access the UTL core regs or PCI config space
	 * until the cores are out of DL_PGRESET.
	 * DL_PGRESET should be polled until it is inactive with a value
	 * of '0'. The recommended polling frequency is once every 1ms.
	 * Firmware should poll at least 200 attempts before giving up.
	 * MMIO Stores to the link are silently dropped by the UTL core if
	 * the link is down.
	 * MMIO Loads to the link will be dropped by the UTL core and will
	 * eventually time-out and will return an all ones response if the
	 * link is down.
	 */
#define DLP_RESET_ATTEMPTS	40000

	PHBDBG(p, "Waiting for DLP PG reset to complete...\n");
	for (i = 0; i < DLP_RESET_ATTEMPTS; i++) {
		val = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (!(val & PHB_PCIE_DLP_TC_DL_PGRESET))
			break;
		time_wait_us(10);
	}
	if (val & PHB_PCIE_DLP_TC_DL_PGRESET) {
		PHBERR(p, "Timeout waiting for DLP PG reset !\n");
		return false;
	}
	return true;
}

/* phb3_init_rc - Initialize the Root Complex config space
 */
static bool phb3_init_rc_cfg(struct phb3 *p)
{
	int64_t ecap, aercap;

	/* XXX Handle errors ? */

	/* Init_45..46:
	 *
	 * Set primary bus to 0, secondary to 1 and subordinate to 0xff
	 */
	phb3_pcicfg_write32(&p->phb, 0, PCI_CFG_PRIMARY_BUS, 0x00ff0100);

	/* Init_47..52
	 *
	 * IO and Memory base & limits are set to base > limit, which
	 * allows all inbounds.
	 *
	 * XXX This has the potential of confusing the OS which might
	 * think that nothing is forwarded downstream. We probably need
	 * to fix this to match the IO and M32 PHB windows
	 */
	phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_IO_BASE, 0x0010);
	phb3_pcicfg_write32(&p->phb, 0, PCI_CFG_MEM_BASE, 0x00000010);
	phb3_pcicfg_write32(&p->phb, 0, PCI_CFG_PREF_MEM_BASE, 0x00000010);

	/* Init_53..54 - Setup bridge control enable forwarding of CORR, FATAL,
	 * and NONFATAL errors
	*/
	phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, PCI_CFG_BRCTL_SERR_EN);

	/* Init_55..56
	 *
	 * PCIE Device control/status, enable error reporting, disable relaxed
	 * ordering, set MPS to 128 (see note), clear errors.
	 *
	 * Note: The doc recommends to set MPS to 4K. This has proved to have
	 * some issues as it requires specific claming of MRSS on devices and
	 * we've found devices in the field that misbehave when doing that.
	 *
	 * We currently leave it all to 128 bytes (minimum setting) at init
	 * time. The generic PCIe probing later on might apply a different
	 * value, or the kernel will, but we play it safe at early init
	 */
	if (p->ecap <= 0) {
		ecap = pci_find_cap(&p->phb, 0, PCI_CFG_CAP_ID_EXP);
		if (ecap < 0) {
			PHBERR(p, "Can't locate PCI-E capability\n");
			return false;
		}
		p->ecap = ecap;
	} else {
		ecap = p->ecap;
	}

	phb3_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DEVSTAT,
			     PCICAP_EXP_DEVSTAT_CE	|
			     PCICAP_EXP_DEVSTAT_NFE	|
			     PCICAP_EXP_DEVSTAT_FE	|
			     PCICAP_EXP_DEVSTAT_UE);

	phb3_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DEVCTL,
			     PCICAP_EXP_DEVCTL_CE_REPORT	|
			     PCICAP_EXP_DEVCTL_NFE_REPORT	|
			     PCICAP_EXP_DEVCTL_FE_REPORT	|
			     PCICAP_EXP_DEVCTL_UR_REPORT	|
			     SETFIELD(PCICAP_EXP_DEVCTL_MPS, 0, PCIE_MPS_128B));

	/* Init_57..58
	 *
	 * Root Control Register. Enable error reporting
	 *
	 * Note: Added CRS visibility.
	 */
	phb3_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_RC,
			     PCICAP_EXP_RC_SYSERR_ON_CE		|
			     PCICAP_EXP_RC_SYSERR_ON_NFE	|
			     PCICAP_EXP_RC_SYSERR_ON_FE		|
			     PCICAP_EXP_RC_CRS_VISIBLE);

	/* Init_59..60
	 *
	 * Device Control 2. Enable ARI fwd, set timer to RTOS timer
	 */
	phb3_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DCTL2,
			     SETFIELD(PCICAP_EXP_DCTL2_CMPTOUT, 0, 0xf) |
			     PCICAP_EXP_DCTL2_ARI_FWD);

	/* Init_61..76
	 *
	 * AER inits
	 */
	if (p->aercap <= 0) {
		aercap = pci_find_ecap(&p->phb, 0, PCIECAP_ID_AER, NULL);
		if (aercap < 0) {
			PHBERR(p, "Can't locate AER capability\n");
			return false;
		}
		p->aercap = aercap;
	} else {
		aercap = p->aercap;
	}

	/* Clear all UE status */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_STATUS,
			     0xffffffff);
	/* Disable some error reporting as per the PHB3 spec */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_MASK,
			     PCIECAP_AER_UE_POISON_TLP		|
			     PCIECAP_AER_UE_COMPL_TIMEOUT	|
			     PCIECAP_AER_UE_COMPL_ABORT		|
			     PCIECAP_AER_UE_ECRC);
	/* Report some errors as fatal */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_SEVERITY,
			     PCIECAP_AER_UE_DLP 		|
			     PCIECAP_AER_UE_SURPRISE_DOWN	|
			     PCIECAP_AER_UE_FLOW_CTL_PROT	|
			     PCIECAP_AER_UE_UNEXP_COMPL		|
			     PCIECAP_AER_UE_RECV_OVFLOW		|
			     PCIECAP_AER_UE_MALFORMED_TLP);
	/* Clear all CE status */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CE_STATUS,
			     0xffffffff);
	/* Disable some error reporting as per the PHB3 spec */
	/* Note: When link down, also disable rcvr errors */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CE_MASK,
			    PCIECAP_AER_CE_ADV_NONFATAL |
			    (p->has_link ? 0 : PCIECAP_AER_CE_RECVR_ERR));

	/* Enable or disable ECRC generation & checking */
	phb3_enable_ecrc(&p->phb, !p->no_ecrc_devs);

	/* Enable reporting in root error control */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_RERR_CMD,
			     PCIECAP_AER_RERR_CMD_FE		|
			     PCIECAP_AER_RERR_CMD_NFE		|
			     PCIECAP_AER_RERR_CMD_CE);
	/* Clear root error status */
	phb3_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_RERR_STA,
			     0xffffffff);

	return true;
}

static void phb3_init_utl(struct phb3 *p)
{
	/* Init_77..79: Clear spurrious errors and assign errors to the
	 * right "interrupt" signal
	 */
	out_be64(p->regs + UTL_SYS_BUS_AGENT_STATUS,       0xffffffffffffffffUL);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_ERR_SEVERITY, 0x5000000000000000UL);
	out_be64(p->regs + UTL_SYS_BUS_AGENT_IRQ_EN,       0xfcc0000000000000UL);

	/* Init_80..81: Setup tag allocations
	 *
         * Stick to HW defaults. May differs between PHB implementations
	 */

	/* Init_82: PCI Express port control
	 * SW283991: Set Outbound Non-Posted request timeout to 16ms (RTOS).
	 */
	out_be64(p->regs + UTL_PCIE_PORT_CONTROL,          0x8588007000000000UL);

	/* Init_83..85: Clean & setup port errors */
	out_be64(p->regs + UTL_PCIE_PORT_STATUS,           0xffdfffffffffffffUL);
	out_be64(p->regs + UTL_PCIE_PORT_ERROR_SEV,        0x5039000000000000UL);

	if (p->has_link)
		out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN,   0xad52800000000000UL);
	else
		out_be64(p->regs + UTL_PCIE_PORT_IRQ_EN,   0xad42800000000000UL);

	/* Init_86 : Cleanup RC errors */
	out_be64(p->regs + UTL_RC_STATUS,                  0xffffffffffffffffUL);
}

static void phb3_init_errors(struct phb3 *p)
{
	/* Init_88: LEM Error Mask : Temporarily disable error interrupts */
	out_be64(p->regs + PHB_LEM_ERROR_MASK,		   0xffffffffffffffffUL);

	/* Init_89..97: Disable all error interrupts until end of init */
	out_be64(p->regs + PHB_ERR_STATUS,		   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_ERR1_STATUS,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_ERR_LEM_ENABLE,		   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_ERR_FREEZE_ENABLE,	   0x0000000080800000UL);
	out_be64(p->regs + PHB_ERR_AIB_FENCE_ENABLE,	   0xffffffdd0c00ffc0UL);
	out_be64(p->regs + PHB_ERR_LOG_0,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_ERR_LOG_1,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_ERR_STATUS_MASK,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_ERR1_STATUS_MASK,	   0x0000000000000000UL);

	/* Init_98_106: Configure MMIO error traps & clear old state
	 *
	 * Don't enable BAR multi-hit detection in bit 41.
	 */
	out_be64(p->regs + PHB_OUT_ERR_STATUS,		   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_OUT_ERR_LEM_ENABLE,	   0xfdffffffffbfffffUL);
	out_be64(p->regs + PHB_OUT_ERR_FREEZE_ENABLE,	   0x0000420800000000UL);
	out_be64(p->regs + PHB_OUT_ERR_AIB_FENCE_ENABLE,   0x9cf3bc00f89c700fUL);
	out_be64(p->regs + PHB_OUT_ERR_LOG_0,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_OUT_ERR_LOG_1,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_OUT_ERR_STATUS_MASK,	   0x0000000000400000UL);
	out_be64(p->regs + PHB_OUT_ERR1_STATUS_MASK,	   0x0000000000400000UL);

	/* Init_107_115: Configure DMA_A error traps & clear old state */
	out_be64(p->regs + PHB_INA_ERR_STATUS,		   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_INA_ERR1_STATUS,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_INA_ERR_LEM_ENABLE,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_INA_ERR_FREEZE_ENABLE,	   0xc00003a901006000UL);
	out_be64(p->regs + PHB_INA_ERR_AIB_FENCE_ENABLE,   0x3fff5452fe019fdeUL);
	out_be64(p->regs + PHB_INA_ERR_LOG_0,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_INA_ERR_LOG_1,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_INA_ERR_STATUS_MASK,	   0x0000000000000000UL);
	out_be64(p->regs + PHB_INA_ERR1_STATUS_MASK,	   0x0000000000000000UL);

	/* Init_116_124: Configure DMA_B error traps & clear old state */
	out_be64(p->regs + PHB_INB_ERR_STATUS,		   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_INB_ERR1_STATUS,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_INB_ERR_LEM_ENABLE,	   0xffffffffffffffffUL);

	/*
	 * Workaround for errata HW257476, turn correctable messages into
	 * ER freezes on Murano and Venice DD1.0
	 */
	if (p->rev < PHB3_REV_MURANO_DD20)
		out_be64(p->regs + PHB_INB_ERR_FREEZE_ENABLE,
			                                   0x0000600000000070UL);
	else
		out_be64(p->regs + PHB_INB_ERR_FREEZE_ENABLE,
			                                   0x0000600000000060UL);

	out_be64(p->regs + PHB_INB_ERR_AIB_FENCE_ENABLE,   0xfcff80fbff7ff08cUL);
	out_be64(p->regs + PHB_INB_ERR_LOG_0,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_INB_ERR_LOG_1,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_INB_ERR_STATUS_MASK,	   0x0000000000000000UL);
	out_be64(p->regs + PHB_INB_ERR1_STATUS_MASK,	   0x0000000000000000UL);

	/* Init_125..128: Cleanup & configure LEM */
	out_be64(p->regs + PHB_LEM_FIR_ACCUM,		   0x0000000000000000UL);
	out_be64(p->regs + PHB_LEM_ACTION0,		   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_LEM_ACTION1,		   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_LEM_WOF,			   0x0000000000000000UL);
}

static int64_t phb3_fixup_pec_inits(struct phb3 *p)
{
	int64_t rc;
	uint64_t val;

	/* These fixups handle some timer updates that HB doesn't yet do
	 * to work around problems with some adapters or external drawers
	 * (SW283991)
	 */

	/* PCI Hardware Configuration 0 Register */
	rc = xscom_read(p->chip_id, p->pe_xscom + 0x18, &val);
	if (rc) {
		PHBERR(p, "Can't read CS0 !\n");
		return rc;
	}
	val = val & 0x0f0fffffffffffffull;
	val = val | 0x1010000000000000ull;
	rc = xscom_write(p->chip_id, p->pe_xscom + 0x18, val);
	if (rc) {
		PHBERR(p, "Can't write CS0 !\n");
		return rc;
	}
	return 0;
}

static void phb3_init_hw(struct phb3 *p, bool first_init)
{
	uint64_t val;

	PHBDBG(p, "Initializing PHB...\n");

	/* Fixups for PEC inits */
	if (phb3_fixup_pec_inits(p)) {
		PHBERR(p, "Failed to init PEC, PHB appears broken\n");
		goto failed;
	}

	/* Lift reset */
	xscom_read(p->chip_id, p->spci_xscom + 1, &val);/* HW275117 */
	xscom_write(p->chip_id, p->pci_xscom + 0xa, 0);

	/* XXX FIXME, turn that into a state machine or a worker thread */
	time_wait_ms(100);

	/* Grab version and fit it in an int */
	val = phb3_read_reg_asb(p, PHB_VERSION);
	if (val == 0 || val == 0xffffffffffffffffUL) {
		PHBERR(p, "Failed to read version, PHB appears broken\n");
		goto failed;
	}

	p->rev = ((val >> 16) & 0x00ff0000) | (val & 0xffff);
	PHBDBG(p, "Core revision 0x%x\n", p->rev);

	/* Setup AIB credits etc... */
	phb3_setup_aib(p);

	/* Init_8 - PCIE System Configuration Register
	 *
	 * Use default values, clear bit 15 (SYS_EC00_SLOT) to avoid incorrect
	 * slot power limit message and adjust max speed based on system
	 * config. Don't hard wire default value as some bits are different
	 * between implementations.
	 */
	val = in_be64(p->regs + PHB_PCIE_SYSTEM_CONFIG);
	PHBDBG(p, "Default system config: 0x%016llx\n", val);
	val = SETFIELD(PHB_PCIE_SCONF_SLOT, val, 0);
	val = SETFIELD(PHB_PCIE_SCONF_MAXLINKSPEED, val, p->max_link_speed);
	out_be64(p->regs + PHB_PCIE_SYSTEM_CONFIG, val);
	PHBDBG(p, "New system config    : 0x%016llx\n",
	       in_be64(p->regs + PHB_PCIE_SYSTEM_CONFIG));

	/* Init_9..12 - PCIE DLP Lane EQ control */
	if (p->lane_eq) {
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL0,
			 be64_to_cpu(p->lane_eq[0]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL1,
			 be64_to_cpu(p->lane_eq[1]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL2,
			 be64_to_cpu(p->lane_eq[2]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL3,
			 be64_to_cpu(p->lane_eq[3]));
	}

	/* Init_XX - (PHB2 errata)
	 *
         * Set proper credits, needs adjustment due to wrong defaults
	 * on PHB2 before we lift the reset. This only applies to Murano
	 * and Venice
	 */
	if (p->index == 2 && p->rev < PHB3_REV_NAPLES_DD10)
		out_be64(p->regs + PHB_PCIE_SYS_LINK_INIT, 0x9008133332120000UL);

	/* Init_13 - PCIE Reset */
	/*
	 * Lift the PHB resets but not PERST, this will be lifted
	 * later by the initial PERST state machine
	 */
	PHBDBG(p, "PHB_RESET is 0x%016llx\n", in_be64(p->regs + PHB_RESET));
	out_be64(p->regs + PHB_RESET,			   0xd000000000000000UL);

	/* Architected IODA2 inits */
	phb3_init_ioda2(p);

	/* Init_37..42 - Clear UTL & DLP error logs */
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG1,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG2,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG3,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_PCIE_UTL_ERRLOG4,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_PCIE_DLP_ERRLOG1,	   0xffffffffffffffffUL);
	out_be64(p->regs + PHB_PCIE_DLP_ERRLOG2,	   0xffffffffffffffffUL);

	/* Init_43 - Wait for UTL core to come out of reset */
	if (!phb3_wait_dlp_reset(p))
		goto failed;

	/* Init_44 - Clear port status */
	out_be64(p->regs + UTL_PCIE_PORT_STATUS,	   0xffffffffffffffffUL);

	/* Init_45..76: Init root complex config space */
	if (!phb3_init_rc_cfg(p))
		goto failed;

	/* Init_77..86 : Init UTL */
	phb3_init_utl(p);

	/*
	 * Init_87: PHB Control register. Various PHB settings
	 *          Enable IVC for Murano DD2.0 or later one
	 */
#ifdef IVT_TABLE_IVE_16B
	val = 0xf3a80e4b00000000UL;
#else
	val = 0xf3a80ecb00000000UL;
#endif
	if (p->rev >= PHB3_REV_MURANO_DD20)
		val |= 0x0000010000000000UL;
	if (first_init && p->rev >= PHB3_REV_NAPLES_DD10) {
		/* Enable 32-bit bypass support on Naples and tell the OS
		 * about it
		 */
		val |= 0x0010000000000000UL;
		dt_add_property(p->phb.dt_node,
				"ibm,32-bit-bypass-supported", NULL, 0);
	}
	out_be64(p->regs + PHB_CONTROL, val);

	/* Init_88..128  : Setup error registers */
	phb3_init_errors(p);

	/* Init_129: Read error summary */
	val = in_be64(p->regs + PHB_ETU_ERR_SUMMARY);
	if (val) {
		PHBERR(p, "Errors detected during PHB init: 0x%16llx\n", val);
		goto failed;
	}

	/* NOTE: At this point the spec waits for the link to come up. We
	 * don't bother as we are doing a PERST soon.
	 */

	/* XXX I don't know why the spec does this now and not earlier, so
	 * to be sure to get it right we might want to move it to the freset
	 * state machine, though the generic PCI layer will probably do
	 * this anyway (ie, enable MEM, etc... in the RC)
	 *
	 * Note:The spec enables IO but PHB3 doesn't do IO space .... so we
	 * leave that clear.
	 */
	phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_CMD,
			    PCI_CFG_CMD_MEM_EN |
			    PCI_CFG_CMD_BUS_MASTER_EN |
			    PCI_CFG_CMD_PERR_RESP |
			    PCI_CFG_CMD_SERR_EN);

	/* Clear errors */
	phb3_pcicfg_write16(&p->phb, 0, PCI_CFG_STAT,
			    PCI_CFG_STAT_SENT_TABORT |
			    PCI_CFG_STAT_RECV_TABORT |
			    PCI_CFG_STAT_RECV_MABORT |
			    PCI_CFG_STAT_SENT_SERR |
			    PCI_CFG_STAT_RECV_PERR);

	/* Init_136 - Re-enable error interrupts */

	/* TBD: Should we mask any of these for PERST ? */
	out_be64(p->regs + PHB_ERR_IRQ_ENABLE,	   0x0000002280b80000UL);
	out_be64(p->regs + PHB_OUT_ERR_IRQ_ENABLE, 0x600c42fc042080f0UL);
	out_be64(p->regs + PHB_INA_ERR_IRQ_ENABLE, 0xc000a3a901826020UL);
	out_be64(p->regs + PHB_INB_ERR_IRQ_ENABLE, 0x0000600000800070UL);
	out_be64(p->regs + PHB_LEM_ERROR_MASK,	   0x42498e367f502eaeUL);

	/*
	 * Init_141 - Enable DMA address speculation
	 *
	 * Errata#20131017: Disable speculation until Murano DD2.0
	 *
	 * Note: We keep IVT speculation disabled (bit 4). It should work with
	 * Murano DD2.0 and later but lacks sufficient testing. We will re-enable
	 * it once that has been done.
	 */
	if (p->rev >= PHB3_REV_MURANO_DD20)
		out_be64(p->regs + PHB_TCE_SPEC_CTL,		0xf000000000000000UL);
	else
		out_be64(p->regs + PHB_TCE_SPEC_CTL,		0x0ul);

	/* Errata#20131017: avoid TCE queue overflow */
	if (p->rev == PHB3_REV_MURANO_DD20)
		phb3_write_reg_asb(p, PHB_TCE_WATERMARK,	0x0003000000030302UL);

	/* Init_142 - PHB3 - Timeout Control Register 1
	 * SW283991: Increase timeouts
	 */
	out_be64(p->regs + PHB_TIMEOUT_CTRL1,			0x1715152016200000UL);

	/* Init_143 - PHB3 - Timeout Control Register 2 */
	out_be64(p->regs + PHB_TIMEOUT_CTRL2,			0x2320d71600000000UL);

	/* Mark the PHB as functional which enables all the various sequences */
	p->broken = false;

	PHBDBG(p, "Initialization complete\n");

	return;

 failed:
	PHBERR(p, "Initialization failed\n");
	p->broken = true;
}

static void phb3_allocate_tables(struct phb3 *p)
{
	uint16_t *rte;
	uint32_t i;

	/* XXX Our current memalign implementation sucks,
	 *
	 * It will do the job, however it doesn't support freeing
	 * the memory and wastes space by always allocating twice
	 * as much as requested (size + alignment)
	 */
	p->tbl_rtt = (uint64_t)local_alloc(p->chip_id, RTT_TABLE_SIZE, RTT_TABLE_SIZE);
	assert(p->tbl_rtt);
	rte = (uint16_t *)(p->tbl_rtt);
	for (i = 0; i < RTT_TABLE_ENTRIES; i++, rte++)
		*rte = PHB3_RESERVED_PE_NUM;

	p->tbl_peltv = (uint64_t)local_alloc(p->chip_id, PELTV_TABLE_SIZE, PELTV_TABLE_SIZE);
	assert(p->tbl_peltv);
	memset((void *)p->tbl_peltv, 0, PELTV_TABLE_SIZE);

	p->tbl_pest = (uint64_t)local_alloc(p->chip_id, PEST_TABLE_SIZE, PEST_TABLE_SIZE);
	assert(p->tbl_pest);
	memset((void *)p->tbl_pest, 0, PEST_TABLE_SIZE);

	p->tbl_ivt = (uint64_t)local_alloc(p->chip_id, IVT_TABLE_SIZE, IVT_TABLE_SIZE);
	assert(p->tbl_ivt);
	memset((void *)p->tbl_ivt, 0, IVT_TABLE_SIZE);

	p->tbl_rba = (uint64_t)local_alloc(p->chip_id, RBA_TABLE_SIZE, RBA_TABLE_SIZE);
	assert(p->tbl_rba);
	memset((void *)p->tbl_rba, 0, RBA_TABLE_SIZE);
}

static void phb3_add_properties(struct phb3 *p)
{
	struct dt_node *np = p->phb.dt_node;
	uint32_t lsibase, icsp = get_ics_phandle();
	uint64_t m32b, m64b, m64s, reg, tkill;

	reg = cleanup_addr((uint64_t)p->regs);

	/* Add various properties that HB doesn't have to
	 * add, some of them simply because they result from
	 * policy decisions made in skiboot rather than in HB
	 * such as the MMIO windows going to PCI, interrupts,
	 * etc...
	 */
	dt_add_property_cells(np, "#address-cells", 3);
	dt_add_property_cells(np, "#size-cells", 2);
	dt_add_property_cells(np, "#interrupt-cells", 1);
	dt_add_property_cells(np, "bus-range", 0, 0xff);
	dt_add_property_cells(np, "clock-frequency", 0x200, 0); /* ??? */

	dt_add_property_cells(np, "interrupt-parent", icsp);

	/* XXX FIXME: add slot-name */
	//dt_property_cell("bus-width", 8); /* Figure it out from VPD ? */

	/* "ranges", we only expose M32 (PHB3 doesn't do IO)
	 *
	 * Note: The kernel expects us to have chopped of 64k from the
	 * M32 size (for the 32-bit MSIs). If we don't do that, it will
	 * get confused (OPAL does it)
	 */
	m32b = cleanup_addr(p->mm1_base);
	m64b = cleanup_addr(p->mm0_base);
	m64s = p->mm0_size;
	dt_add_property_cells(np, "ranges",
			      /* M32 space */
			      0x02000000, 0x00000000, M32_PCI_START,
			      hi32(m32b), lo32(m32b), 0, M32_PCI_SIZE - 0x10000);

	/* XXX FIXME: add opal-memwin32, dmawins, etc... */
	dt_add_property_u64s(np, "ibm,opal-m64-window", m64b, m64b, m64s);
	dt_add_property(np, "ibm,opal-single-pe", NULL, 0);
	//dt_add_property_cells(np, "ibm,opal-msi-ports", 2048);
	dt_add_property_cells(np, "ibm,opal-num-pes", 256);
	dt_add_property_cells(np, "ibm,opal-reserved-pe",
			      PHB3_RESERVED_PE_NUM);
	dt_add_property_cells(np, "ibm,opal-msi-ranges",
			      p->base_msi, PHB3_MSI_IRQ_COUNT);
	tkill = reg + PHB_TCE_KILL;
	dt_add_property_cells(np, "ibm,opal-tce-kill",
			      hi32(tkill), lo32(tkill));
	dt_add_property_cells(np, "ibm,supported-tce-sizes",
			      12, // 4K
			      16, // 64K
			      24, // 16M
			      28); // 256M

	/*
	 * Indicate to Linux that the architected IODA2 MSI EOI method
	 * is supported
	 */
	dt_add_property_string(np, "ibm,msi-eoi-method", "ioda2");

	/* Indicate to Linux that CAPP timebase sync is supported */
	dt_add_property_string(np, "ibm,capp-timebase-sync", NULL);

	/* The interrupt maps will be generated in the RC node by the
	 * PCI code based on the content of this structure:
	 */
	lsibase = p->base_lsi;
	p->phb.lstate.int_size = 2;
	p->phb.lstate.int_val[0][0] = lsibase + PHB3_LSI_PCIE_INTA;
	p->phb.lstate.int_val[0][1] = 1;
	p->phb.lstate.int_val[1][0] = lsibase + PHB3_LSI_PCIE_INTB;
	p->phb.lstate.int_val[1][1] = 1;
	p->phb.lstate.int_val[2][0] = lsibase + PHB3_LSI_PCIE_INTC;
	p->phb.lstate.int_val[2][1] = 1;
	p->phb.lstate.int_val[3][0] = lsibase + PHB3_LSI_PCIE_INTD;
	p->phb.lstate.int_val[3][1] = 1;
	p->phb.lstate.int_parent[0] = icsp;
	p->phb.lstate.int_parent[1] = icsp;
	p->phb.lstate.int_parent[2] = icsp;
	p->phb.lstate.int_parent[3] = icsp;

	/* Indicators for variable tables */
	dt_add_property_cells(np, "ibm,opal-rtt-table",
		hi32(p->tbl_rtt), lo32(p->tbl_rtt), RTT_TABLE_SIZE);
	dt_add_property_cells(np, "ibm,opal-peltv-table",
		hi32(p->tbl_peltv), lo32(p->tbl_peltv), PELTV_TABLE_SIZE);
	dt_add_property_cells(np, "ibm,opal-pest-table",
		hi32(p->tbl_pest), lo32(p->tbl_pest), PEST_TABLE_SIZE);
	dt_add_property_cells(np, "ibm,opal-ivt-table",
		hi32(p->tbl_ivt), lo32(p->tbl_ivt), IVT_TABLE_SIZE);
	dt_add_property_cells(np, "ibm,opal-ive-stride",
		IVT_TABLE_STRIDE);
	dt_add_property_cells(np, "ibm,opal-rba-table",
		hi32(p->tbl_rba), lo32(p->tbl_rba), RBA_TABLE_SIZE);

	dt_add_property_cells(np, "ibm,phb-diag-data-size",
			      sizeof(struct OpalIoPhb3ErrorData));
}

static bool phb3_calculate_windows(struct phb3 *p)
{
	const struct dt_property *prop;

	/* Get PBCQ MMIO windows from device-tree */
	prop = dt_require_property(p->phb.dt_node,
				   "ibm,mmio-window", -1);
	assert(prop->len >= (2 * sizeof(uint64_t)));

	p->mm0_base = ((const uint64_t *)prop->prop)[0];
	p->mm0_size = ((const uint64_t *)prop->prop)[1];
	if (prop->len > 16) {
		p->mm1_base = ((const uint64_t *)prop->prop)[2];
		p->mm1_size = ((const uint64_t *)prop->prop)[3];
	}

	/* Sort them so that 0 is big and 1 is small */
	if (p->mm1_size && p->mm1_size > p->mm0_size) {
		uint64_t b = p->mm0_base;
		uint64_t s = p->mm0_size;
		p->mm0_base = p->mm1_base;
		p->mm0_size = p->mm1_size;
		p->mm1_base = b;
		p->mm1_size = s;
	}

	/* If 1 is too small, ditch it */
	if (p->mm1_size < M32_PCI_SIZE)
		p->mm1_size = 0;

	/* If 1 doesn't exist, carve it out of 0 */
	if (p->mm1_size == 0) {
		p->mm0_size /= 2;
		p->mm1_base = p->mm0_base + p->mm0_size;
		p->mm1_size = p->mm0_size;
	}

	/* Crop mm1 to our desired size */
	if (p->mm1_size > M32_PCI_SIZE)
		p->mm1_size = M32_PCI_SIZE;

	return true;
}

/*
 * Trigger a creset to disable CAPI mode on kernel shutdown.
 *
 * This helper is called repeatedly by the host sync notifier mechanism, which
 * relies on the kernel to regularly poll the OPAL_SYNC_HOST_REBOOT call as it
 * shuts down.
 *
 * This is a somewhat hacky abuse of the host sync notifier mechanism, but the
 * alternatives require a new API call which won't work for older kernels.
 */
static bool phb3_host_sync_reset(void *data)
{
	struct phb3 *p = (struct phb3 *)data;
	struct pci_slot *slot = p->phb.slot;
	struct proc_chip *chip = get_chip(p->chip_id);
	int64_t rc;

	switch (slot->state) {
	case PHB3_SLOT_NORMAL:
		lock(&capi_lock);
		rc = (chip->capp_phb3_attached_mask & (1 << p->index)) ?
			OPAL_PHB_CAPI_MODE_CAPI :
			OPAL_PHB_CAPI_MODE_PCIE;
		unlock(&capi_lock);

		if (rc == OPAL_PHB_CAPI_MODE_PCIE)
			return true;

		PHBINF(p, "PHB in CAPI mode, resetting\n");
		p->flags &= ~PHB3_CAPP_RECOVERY;
		phb3_creset(slot);
		return false;
	default:
		rc = slot->ops.run_sm(slot);
		return rc <= OPAL_SUCCESS;
	}
}

static void phb3_create(struct dt_node *np)
{
	const struct dt_property *prop;
	struct phb3 *p = zalloc(sizeof(struct phb3));
	struct pci_slot *slot;
	size_t lane_eq_len;
	struct dt_node *iplp;
	struct proc_chip *chip;
	int opal_id;
	char *path;

	assert(p);

	/* Populate base stuff */
	p->index = dt_prop_get_u32(np, "ibm,phb-index");
	p->chip_id = dt_prop_get_u32(np, "ibm,chip-id");
	p->regs = (void *)dt_get_address(np, 0, NULL);
	p->base_msi = PHB3_MSI_IRQ_BASE(p->chip_id, p->index);
	p->base_lsi = PHB3_LSI_IRQ_BASE(p->chip_id, p->index);
	p->phb.dt_node = np;
	p->phb.ops = &phb3_ops;
	p->phb.phb_type = phb_type_pcie_v3;
	p->phb.scan_map = 0x1; /* Only device 0 to scan */

	if (!phb3_calculate_windows(p))
		return;

	/* Get the various XSCOM register bases from the device-tree */
	prop = dt_require_property(np, "ibm,xscom-bases", 3 * sizeof(uint32_t));
	p->pe_xscom = ((const uint32_t *)prop->prop)[0];
	p->spci_xscom = ((const uint32_t *)prop->prop)[1];
	p->pci_xscom = ((const uint32_t *)prop->prop)[2];

	/*
	 * We skip the initial PERST assertion requested by the generic code
	 * when doing a cold boot because we are coming out of cold boot already
	 * so we save boot time that way. The PERST state machine will still
	 * handle waiting for the link to come up, it will just avoid actually
	 * asserting & deasserting the PERST output
	 *
	 * For a hot IPL, we still do a PERST
	 *
	 * Note: In absence of property (ie, FSP-less), we stick to the old
	 * behaviour and set skip_perst to true
	 */
	p->skip_perst = true; /* Default */

	iplp = dt_find_by_path(dt_root, "ipl-params/ipl-params");
	if (iplp) {
		const char *ipl_type = dt_prop_get_def(iplp, "cec-major-type", NULL);
		if (ipl_type && (!strcmp(ipl_type, "hot")))
			p->skip_perst = false;
	}

	/* By default link is assumed down */
	p->has_link = false;

	/* We register the PHB before we initialize it so we
	 * get a useful OPAL ID for it. We use a different numbering here
	 * between Naples and Venice/Murano in order to leave room for the
	 * NPU on Naples.
	 */
	chip = next_chip(NULL); /* Just need any chip */
	if (chip && chip->type == PROC_CHIP_P8_NAPLES)
		opal_id = p->chip_id * 8 + p->index;
	else
		opal_id = p->chip_id * 4 + p->index;
	pci_register_phb(&p->phb, opal_id);
	slot = phb3_slot_create(&p->phb);
	if (!slot)
		PHBERR(p, "Cannot create PHB slot\n");

	/* Hello ! */
	path = dt_get_path(np);
	PHBINF(p, "Found %s @[%d:%d]\n", path, p->chip_id, p->index);
	PHBINF(p, "  M32 [0x%016llx..0x%016llx]\n",
	       p->mm1_base, p->mm1_base + p->mm1_size - 1);
	PHBINF(p, "  M64 [0x%016llx..0x%016llx]\n",
	       p->mm0_base, p->mm0_base + p->mm0_size - 1);
	free(path);

	/* Find base location code from root node */
	p->phb.base_loc_code = dt_prop_get_def(dt_root,
					       "ibm,io-base-loc-code", NULL);
	if (!p->phb.base_loc_code)
		PHBDBG(p, "Base location code not found !\n");

	/* Priority order: NVRAM -> dt -> GEN3 */
	p->max_link_speed = 3;
	if (dt_has_node_property(np, "ibm,max-link-speed", NULL))
		p->max_link_speed = dt_prop_get_u32(np, "ibm,max-link-speed");
	if (pcie_max_link_speed)
		p->max_link_speed = pcie_max_link_speed;
	if (p->max_link_speed > 3) /* clamp to 3 */
		p->max_link_speed = 3;
	PHBINF(p, "Max link speed: GEN%i\n", p->max_link_speed);

	/* Check for lane equalization values from HB or HDAT */
	p->lane_eq = dt_prop_get_def_size(np, "ibm,lane-eq", NULL, &lane_eq_len);
	if (p->lane_eq && lane_eq_len != (8 * 4)) {
		PHBERR(p, "Device-tree has ibm,lane-eq with wrong len %ld\n",
			lane_eq_len);
		p->lane_eq = NULL;
	}
	if (p->lane_eq) {
		PHBDBG(p, "Override lane equalization settings:\n");
		PHBDBG(p, "  0x%016llx 0x%016llx\n",
		       be64_to_cpu(p->lane_eq[0]), be64_to_cpu(p->lane_eq[1]));
		PHBDBG(p, "  0x%016llx 0x%016llx\n",
		       be64_to_cpu(p->lane_eq[2]), be64_to_cpu(p->lane_eq[3]));
	}

	/*
	 * Grab CEC IO VPD load info from the root of the device-tree,
	 * on P8 there's a single such VPD for the whole machine
	 */
	prop = dt_find_property(dt_root, "ibm,io-vpd");
	if (!prop) {
		/* LX VPD Lid not already loaded */
		if (platform.vpd_iohub_load)
			platform.vpd_iohub_load(dt_root);
	}

	/* Allocate the SkiBoot internal in-memory tables for the PHB */
	phb3_allocate_tables(p);

	phb3_add_properties(p);

	/* Clear IODA2 cache */
	phb3_init_ioda_cache(p);

	/* Register interrupt sources */
	register_irq_source(&phb3_msi_irq_ops, p, p->base_msi,
			    PHB3_MSI_IRQ_COUNT);
	register_irq_source(&phb3_lsi_irq_ops, p, p->base_lsi, 8);

	/* Get the HW up and running */
	phb3_init_hw(p, true);

	/* Load capp microcode into capp unit */
	load_capp_ucode(p);

	opal_add_host_sync_notifier(phb3_host_sync_reset, p);

	/* Platform additional setup */
	if (platform.pci_setup_phb)
		platform.pci_setup_phb(&p->phb, p->index);
}

static void phb3_probe_pbcq(struct dt_node *pbcq)
{
	uint32_t spci_xscom, pci_xscom, pe_xscom, gcid, pno;
	uint64_t val, phb_bar, bar_en;
	uint64_t mmio0_bar, mmio0_bmask, mmio0_sz;
	uint64_t mmio1_bar, mmio1_bmask, mmio1_sz;
	uint64_t reg[2];
	uint64_t mmio_win[4];
	unsigned int mmio_win_sz;
	struct dt_node *np;
	char *path;
	uint64_t capp_ucode_base;
	unsigned int max_link_speed;

	gcid = dt_get_chip_id(pbcq);
	pno = dt_prop_get_u32(pbcq, "ibm,phb-index");
	path = dt_get_path(pbcq);
	prlog(PR_NOTICE, "Chip %d Found PBCQ%d at %s\n", gcid, pno, path);
	free(path);

	pe_xscom = dt_get_address(pbcq, 0, NULL);
	pci_xscom = dt_get_address(pbcq, 1, NULL);
	spci_xscom = dt_get_address(pbcq, 2, NULL);
	prlog(PR_DEBUG, "PHB3[%x:%x]: X[PE]=0x%08x X[PCI]=0x%08x"
	      " X[SPCI]=0x%08x\n",
	      gcid, pno, pe_xscom, pci_xscom, spci_xscom);

	/* Check if CAPP mode */
	if (xscom_read(gcid, spci_xscom + 0x03, &val)) {
		prerror("PHB3[%x:%x]: Cannot read AIB CAPP ENABLE\n",
			gcid, pno);
		return;
	}
	if (val >> 63) {
		prerror("PHB3[%x:%x]: Ignoring bridge in CAPP mode\n",
			gcid, pno);
		return;
	}

	/* Get PE BARs, assume only 0 and 2 are used for now */
	xscom_read(gcid, pe_xscom + 0x42, &phb_bar);
	phb_bar >>= 14;
	prlog(PR_DEBUG, "PHB3[%x:%x] REGS     = 0x%016llx [4k]\n",
		gcid, pno, phb_bar);
	if (phb_bar == 0) {
		prerror("PHB3[%x:%x]: No PHB BAR set !\n", gcid, pno);
		return;
	}

	/* Dbl check PHB BAR */
	xscom_read(gcid, spci_xscom + 1, &val);/* HW275117 */
	xscom_read(gcid, pci_xscom + 0x0b, &val);
	val >>= 14;
	prlog(PR_DEBUG, "PHB3[%x:%x] PCIBAR   = 0x%016llx\n", gcid, pno, val);
	if (phb_bar != val) {
		prerror("PHB3[%x:%x] PCIBAR invalid, fixing up...\n",
			gcid, pno);
		xscom_read(gcid, spci_xscom + 1, &val);/* HW275117 */
		xscom_write(gcid, pci_xscom + 0x0b, phb_bar << 14);
	}

	/* Check MMIO BARs */
	xscom_read(gcid, pe_xscom + 0x40, &mmio0_bar);
	xscom_read(gcid, pe_xscom + 0x43, &mmio0_bmask);
	mmio0_bmask &= 0xffffffffc0000000ull;
	mmio0_sz = ((~mmio0_bmask) >> 14) + 1;
	mmio0_bar >>= 14;
	prlog(PR_DEBUG, "PHB3[%x:%x] MMIO0    = 0x%016llx [0x%016llx]\n",
		gcid, pno, mmio0_bar, mmio0_sz);
	xscom_read(gcid, pe_xscom + 0x41, &mmio1_bar);
	xscom_read(gcid, pe_xscom + 0x44, &mmio1_bmask);
	mmio1_bmask &= 0xffffffffc0000000ull;
	mmio1_sz = ((~mmio1_bmask) >> 14) + 1;
	mmio1_bar >>= 14;
	prlog(PR_DEBUG, "PHB3[%x:%x] MMIO1    = 0x%016llx [0x%016llx]\n",
		gcid, pno, mmio1_bar, mmio1_sz);

	/* Check BAR enable
	 *
	 * XXX BAR aren't always enabled by HB, we'll make assumptions
	 * that BARs are valid if they value is non-0
	 */
	xscom_read(gcid, pe_xscom + 0x45, &bar_en);
	prlog(PR_DEBUG, "PHB3[%x:%x] BAREN    = 0x%016llx\n",
		gcid, pno, bar_en);

	/* Always enable PHB BAR */
	bar_en |= 0x2000000000000000ull;

	/* Build MMIO windows list */
	mmio_win_sz = 0;
	if (mmio0_bar) {
		mmio_win[mmio_win_sz++] = mmio0_bar;
		mmio_win[mmio_win_sz++] = mmio0_sz;
		bar_en |= 0x8000000000000000ul;
	}
	if (mmio1_bar) {
		mmio_win[mmio_win_sz++] = mmio1_bar;
		mmio_win[mmio_win_sz++] = mmio1_sz;
		bar_en |= 0x4000000000000000ul;
	}

	/* No MMIO windows ? Barf ! */
	if (mmio_win_sz == 0) {
		prerror("PHB3[%x:%x]: No MMIO windows enabled !\n",
			gcid, pno);
		return;
	}

	/* Set the interrupt routing stuff, 8 relevant bits in mask
	 * (11 bits per PHB)
	 */
	val = p8_chip_irq_phb_base(gcid, pno);
	val = (val << 45);
	xscom_write(gcid, pe_xscom + 0x1a, val);
	xscom_write(gcid, pe_xscom + 0x1b, 0xff00000000000000ul);

	/* Configure LSI location to the top of the map */
	xscom_write(gcid, pe_xscom + 0x1f, 0xff00000000000000ul);

	/* Now add IRSN message bits to BAR enable and write it */
	bar_en |= 0x1800000000000000ul;
	xscom_write(gcid, pe_xscom + 0x45, bar_en);

	prlog(PR_DEBUG, "PHB3[%x:%x] NEWBAREN = 0x%016llx\n",
	      gcid, pno, bar_en);

	xscom_read(gcid, pe_xscom + 0x1a, &val);
	prlog(PR_DEBUG, "PHB3[%x:%x] IRSNC    = 0x%016llx\n",
	      gcid, pno, val);
	xscom_read(gcid, pe_xscom + 0x1b, &val);
	prlog(PR_DEBUG, "PHB3[%x:%x] IRSNM    = 0x%016llx\n",
	      gcid, pno, val);
	prlog(PR_DEBUG, "PHB3[%x:%x] LSI      = 0x%016llx\n",
	      gcid, pno, val);

	/* Create PHB node */
	reg[0] = phb_bar;
	reg[1] = 0x1000;

	np = dt_new_addr(dt_root, "pciex", reg[0]);
	if (!np)
		return;

	dt_add_property_strings(np, "compatible", "ibm,power8-pciex",
				"ibm,ioda2-phb");
	dt_add_property_strings(np, "device_type", "pciex");
	dt_add_property(np, "reg", reg, sizeof(reg));

	/* Everything else is handled later by skiboot, we just
	 * stick a few hints here
	 */
	dt_add_property_cells(np, "ibm,xscom-bases",
			      pe_xscom, spci_xscom, pci_xscom);
	dt_add_property(np, "ibm,mmio-window", mmio_win, 8 * mmio_win_sz);
	dt_add_property_cells(np, "ibm,phb-index", pno);
	dt_add_property_cells(np, "ibm,pbcq", pbcq->phandle);
	dt_add_property_cells(np, "ibm,chip-id", gcid);
	if (dt_has_node_property(pbcq, "ibm,use-ab-detect", NULL))
		dt_add_property(np, "ibm,use-ab-detect", NULL, 0);
	if (dt_has_node_property(pbcq, "ibm,hub-id", NULL))
		dt_add_property_cells(np, "ibm,hub-id",
				      dt_prop_get_u32(pbcq, "ibm,hub-id"));
	if (dt_has_node_property(pbcq, "ibm,loc-code", NULL)) {
		const char *lc = dt_prop_get(pbcq, "ibm,loc-code");
		dt_add_property_string(np, "ibm,loc-code", lc);
	}
	if (dt_has_node_property(pbcq, "ibm,lane-eq", NULL)) {
		size_t leq_size;
		const void *leq = dt_prop_get_def_size(pbcq, "ibm,lane-eq",
						       NULL, &leq_size);
		if (leq != NULL && leq_size == 4 * 8)
			dt_add_property(np, "ibm,lane-eq", leq, leq_size);
	}
	if (dt_has_node_property(pbcq, "ibm,capp-ucode", NULL)) {
		capp_ucode_base = dt_prop_get_u32(pbcq, "ibm,capp-ucode");
		dt_add_property_cells(np, "ibm,capp-ucode", capp_ucode_base);
	}
	if (dt_has_node_property(pbcq, "ibm,max-link-speed", NULL)) {
		max_link_speed = dt_prop_get_u32(pbcq, "ibm,max-link-speed");
		dt_add_property_cells(np, "ibm,max-link-speed", max_link_speed);
	}
	dt_add_property_cells(np, "ibm,capi-flags",
			      OPAL_PHB_CAPI_FLAG_SNOOP_CONTROL);

	add_chip_dev_associativity(np);
}


void probe_phb3(void)
{
	struct dt_node *np;

	/* Look for PBCQ XSCOM nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power8-pbcq")
		phb3_probe_pbcq(np);

	/* Look for newly created PHB nodes */
	dt_for_each_compatible(dt_root, np, "ibm,power8-pciex")
		phb3_create(np);
}


