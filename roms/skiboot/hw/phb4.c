// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * PHB4: PCI Host Bridge 4, in POWER9
 *
 * Copyright 2013-2019 IBM Corp.
 * Copyright 2018 Raptor Engineering, LLC
 */

/*
 *
 * FIXME:
 *   More stuff for EEH support:
 *      - PBCQ error reporting interrupt
 *	- I2C-based power management (replacing SHPC)
 *	- Directly detect fenced PHB through one dedicated HW reg
 */

/*
 * This is a simplified view of the PHB4 reset and link training steps
 *
 * Step 1:
 * - Check for hotplug status:
 *  o PHB_PCIE_HOTPLUG_STATUS bit PHB_PCIE_HPSTAT_PRESENCE
 *  o If not set -> Bail out (Slot is empty)
 *
 * Step 2:
 * - Do complete PHB reset:
 *   o PHB/ETU reset procedure
 *
 * Step 3:
 * - Drive PERST active (skip if already asserted. ie. after cold reboot)
 * - Wait 250ms (for cards to reset)
 *   o powervm have used 250ms for a long time without any problems
 *
 * Step 4:
 * - Drive PERST inactive
 *
 * Step 5:
 * - Look for inband presence:
 *   o From PERST we have two stages to get inband presence detected
 *     1) Devices must enter Detect state within 20 ms of the end of
 *          Fundamental Reset
 *     2) Receiver detect pulse are every 12ms
 *      - Hence minimum wait time 20 + 12 = 32ms
 *   o Unfortunatey, we've seen cards take 440ms
 *   o Hence we are conservative and poll here for 1000ms (> 440ms)
 * - If no inband presence after 100ms -> Bail out (Slot is broken)
 *   o PHB_PCIE_DLP_TRAIN_CTL bit PHB_PCIE_DLP_INBAND_PRESENCE
 *
 * Step 6:
 * - Look for link training done:
 *   o PHB_PCIE_DLP_TRAIN_CTL bit PHB_PCIE_DLP_TL_LINKACT
 * - If not set after 2000ms, Retry (3 times) -> Goto Step 2
 *   o phy lockup could link training failure, hence going back to a
 *     complete PHB reset on retry
 *   o not expect to happen very often
 *
 * Step 7:
 * - Wait for 1 sec (before touching device config space):
 * -  From PCIe spec:
 *     Root Complex and/or system software must allow at least 1.0 s after
 *     a Conventional Reset of a device, before it may determine that a
 *     device which fails to return a Successful Completion status for a
 *     valid Configuration Request is a broken device.
 *
 * Step 8:
 * - Sanity check for fence and link still up:
 *   o If fenced or link down, Retry (3 times) -> Goto Step 2
 *   o This is not nessary but takes no time and can be useful
 *   o Once we leave here, much harder to recover from errors
 *
 * Step 9:
 * - Check for optimised link for directly attached devices:
 *   o Wait for CRS (so we can read device config space)
 *   o Check chip and device are in allowlist. if not, Goto Step 10
 *   o If trained link speed is degraded, retry ->  Goto Step 2
 *   o If trained link width is degraded, retry -> Goto Step 2
 *   o If still degraded after 3 retries. Give up, Goto Step 10.
 *
 * Step 10:
 *  - PHB good, start probing config space.
 *    o core/pci.c: pci_reset_phb() -> pci_scan_phb()
 */


#undef NO_ASB
#undef LOG_CFG

#include <skiboot.h>
#include <io.h>
#include <timebase.h>
#include <pci.h>
#include <pci-cfg.h>
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
#include <phb4.h>
#include <phb4-regs.h>
#include <phb4-capp.h>
#include <capp.h>
#include <fsp.h>
#include <chip.h>
#include <chiptod.h>
#include <xive.h>
#include <xscom-p9-regs.h>
#include <phys-map.h>
#include <nvram.h>

/* Enable this to disable error interrupts for debug purposes */
#undef DISABLE_ERR_INTS

static void phb4_init_hw(struct phb4 *p);

#define PHBDBG(p, fmt, a...)	prlog(PR_DEBUG, "PHB#%04x[%d:%d]: " fmt, \
				      (p)->phb.opal_id, (p)->chip_id, \
				      (p)->index,  ## a)
#define PHBINF(p, fmt, a...)	prlog(PR_INFO, "PHB#%04x[%d:%d]: " fmt, \
				      (p)->phb.opal_id, (p)->chip_id, \
				      (p)->index,  ## a)
#define PHBNOTICE(p, fmt, a...)	prlog(PR_NOTICE, "PHB#%04x[%d:%d]: " fmt, \
				      (p)->phb.opal_id, (p)->chip_id, \
				      (p)->index,  ## a)
#define PHBERR(p, fmt, a...)	prlog(PR_ERR, "PHB#%04x[%d:%d]: " fmt, \
				      (p)->phb.opal_id, (p)->chip_id, \
				      (p)->index,  ## a)
#ifdef LOG_CFG
#define PHBLOGCFG(p, fmt, a...)	PHBDBG(p, fmt, ## a)
#else
#define PHBLOGCFG(p, fmt, a...) do {} while (0)
#endif

static bool pci_eeh_mmio;
static bool pci_retry_all;
static int rx_err_max = PHB4_RX_ERR_MAX;

static inline bool is_phb4(void)
{
	return (proc_gen == proc_gen_p9);
}

static inline bool is_phb5(void)
{
	return (proc_gen == proc_gen_p10);
}

/* PQ offloading on the XIVE IC. */
static inline bool phb_pq_disable(struct phb4 *p __unused)
{
	if (is_phb5())
		return xive2_cap_phb_pq_disable();

	return false;
}

/*
 * Use the ESB page of the XIVE IC for event notification. Latency
 * improvement.
 */
static inline bool phb_abt_mode(struct phb4 *p __unused)
{
	if (is_phb5())
		return xive2_cap_phb_abt();

	return false;
}

static inline bool phb_can_store_eoi(struct phb4 *p)
{
	if (is_phb5())
		/* PQ offloading is required for StoreEOI */
		return XIVE2_STORE_EOI_ENABLED && phb_pq_disable(p);

	return XIVE_STORE_EOI_ENABLED;
}

/* Note: The "ASB" name is historical, practically this means access via
 * the XSCOM backdoor
 */
static inline uint64_t phb4_read_reg_asb(struct phb4 *p, uint32_t offset)
{
#ifdef NO_ASB
	return in_be64(p->regs + offset);
#else
	int64_t rc;
	uint64_t addr, val;

	/* Address register: must use 4 bytes for built-in config space.
	 *
	 * This path isn't usable for outbound configuration space
	 */
	if (((offset & 0xfffffffc) == PHB_CONFIG_DATA) && (offset & 3)) {
		PHBERR(p, "XSCOM unaligned access to CONFIG_DATA unsupported\n");
		return -1ull;
	}
	addr = XETU_HV_IND_ADDR_VALID | offset;
	if ((offset >= 0x1000 && offset < 0x1800) || (offset == PHB_CONFIG_DATA))
		addr |= XETU_HV_IND_ADDR_4B;
 	rc = xscom_write(p->chip_id, p->etu_xscom + XETU_HV_IND_ADDRESS, addr);
	if (rc != 0) {
		PHBERR(p, "XSCOM error addressing register 0x%x\n", offset);
		return -1ull;
	}
 	rc = xscom_read(p->chip_id, p->etu_xscom + XETU_HV_IND_DATA, &val);
	if (rc != 0) {
		PHBERR(p, "XSCOM error reading register 0x%x\n", offset);
		return -1ull;
	}
	return val;
#endif
}

static inline void phb4_write_reg_asb(struct phb4 *p,
				      uint32_t offset, uint64_t val)
{
#ifdef NO_ASB
	out_be64(p->regs + offset, val);
#else
	int64_t rc;
	uint64_t addr;

	/* Address register: must use 4 bytes for built-in config space.
	 *
	 * This path isn't usable for outbound configuration space
	 */
	if (((offset & 0xfffffffc) == PHB_CONFIG_DATA) && (offset & 3)) {
		PHBERR(p, "XSCOM access to CONFIG_DATA unsupported\n");
		return;
	}
	addr = XETU_HV_IND_ADDR_VALID | offset;
	if ((offset >= 0x1000 && offset < 0x1800) || (offset == PHB_CONFIG_DATA))
		addr |= XETU_HV_IND_ADDR_4B;
 	rc = xscom_write(p->chip_id, p->etu_xscom + XETU_HV_IND_ADDRESS, addr);
	if (rc != 0) {
		PHBERR(p, "XSCOM error addressing register 0x%x\n", offset);
		return;
	}
 	rc = xscom_write(p->chip_id, p->etu_xscom + XETU_HV_IND_DATA, val);
	if (rc != 0) {
		PHBERR(p, "XSCOM error writing register 0x%x\n", offset);
		return;
	}
#endif
}

static uint64_t phb4_read_reg(struct phb4 *p, uint32_t offset)
{
	/* No register accesses are permitted while in reset */
	if (p->flags & PHB4_ETU_IN_RESET)
		return -1ull;

	if (p->flags & PHB4_CFG_USE_ASB)
		return phb4_read_reg_asb(p, offset);
	else
		return in_be64(p->regs + offset);
}

static void phb4_write_reg(struct phb4 *p, uint32_t offset, uint64_t val)
{
	/* No register accesses are permitted while in reset */
	if (p->flags & PHB4_ETU_IN_RESET)
		return;

	if (p->flags & PHB4_CFG_USE_ASB)
		phb4_write_reg_asb(p, offset, val);
	else
		return out_be64(p->regs + offset, val);
}

/* Helper to select an IODA table entry */
static inline void phb4_ioda_sel(struct phb4 *p, uint32_t table,
				 uint32_t addr, bool autoinc)
{
	phb4_write_reg(p, PHB_IODA_ADDR,
		       (autoinc ? PHB_IODA_AD_AUTOINC : 0)	|
		       SETFIELD(PHB_IODA_AD_TSEL, 0ul, table)	|
		       SETFIELD(PHB_IODA_AD_TADR, 0ul, addr));
}

/*
 * Configuration space access
 *
 * The PHB lock is assumed to be already held
 */
static int64_t phb4_pcicfg_check(struct phb4 *p, uint32_t bdfn,
				 uint32_t offset, uint32_t size,
				 uint16_t *pe)
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
	*pe = be16_to_cpu(p->tbl_rtt[bdfn]);

	return OPAL_SUCCESS;
}

static int64_t phb4_rc_read(struct phb4 *p, uint32_t offset, uint8_t sz,
			    void *data, bool use_asb)
{
	uint32_t reg = offset & ~3;
	uint32_t oval;

	/* Some registers are handled locally */
	switch (reg) {
		/* Bridge base/limit registers are cached here as HW
		 * doesn't implement them (it hard codes values that
		 * will confuse a proper PCI implementation).
		 */
	case PCI_CFG_MEM_BASE:		/* Includes PCI_CFG_MEM_LIMIT */
		oval = p->rc_cache[(reg - 0x20) >> 2] & 0xfff0fff0;
		break;
	case PCI_CFG_PREF_MEM_BASE:	/* Includes PCI_CFG_PREF_MEM_LIMIT */
		oval = p->rc_cache[(reg - 0x20) >> 2] & 0xfff0fff0;
		oval |= 0x00010001;
		break;
	case PCI_CFG_IO_BASE_U16:	/* Includes PCI_CFG_IO_LIMIT_U16 */
		oval = 0;
		break;
	case PCI_CFG_PREF_MEM_BASE_U32:
	case PCI_CFG_PREF_MEM_LIMIT_U32:
		oval = p->rc_cache[(reg - 0x20) >> 2];
		break;
	default:
		oval = 0xffffffff; /* default if offset too big */
		if (reg < PHB_RC_CONFIG_SIZE) {
			if (use_asb)
				oval = bswap_32(phb4_read_reg_asb(p, PHB_RC_CONFIG_BASE
								  + reg));
			else
				oval = in_le32(p->regs + PHB_RC_CONFIG_BASE + reg);
		}
	}

	/* Apply any post-read fixups */
	switch (reg) {
	case PCI_CFG_IO_BASE:
		oval |= 0x01f1; /* Set IO base < limit to disable the window */
		break;
	}

	switch (sz) {
	case 1:
		offset &= 3;
		*((uint8_t *)data) = (oval >> (offset << 3)) & 0xff;
		PHBLOGCFG(p, "000 CFG08 Rd %02x=%02x\n",
			  offset, *((uint8_t *)data));
		break;
	case 2:
		offset &= 2;
		*((uint16_t *)data) = (oval >> (offset << 3)) & 0xffff;
		PHBLOGCFG(p, "000 CFG16 Rd %02x=%04x\n",
			  offset, *((uint16_t *)data));
		break;
	case 4:
		*((uint32_t *)data) = oval;
		PHBLOGCFG(p, "000 CFG32 Rd %02x=%08x\n",
			  offset, *((uint32_t *)data));
		break;
	default:
		assert(false);
	}
	return OPAL_SUCCESS;
}

static int64_t phb4_rc_write(struct phb4 *p, uint32_t offset, uint8_t sz,
			     uint32_t val, bool use_asb)
{
	uint32_t reg = offset & ~3;
	uint32_t old, mask, shift, oldold;
	int64_t rc;

	if (reg > PHB_RC_CONFIG_SIZE)
		return OPAL_SUCCESS;

	/* If size isn't 4-bytes, do a RMW cycle */
	if (sz < 4) {
		rc = phb4_rc_read(p, reg, 4, &old, use_asb);
		if (rc != OPAL_SUCCESS)
			return rc;

		/*
		 * Since we have to Read-Modify-Write here, we need to filter
		 * out registers that have write-1-to-clear bits to prevent
		 * clearing stuff we shouldn't be.  So for any register this
		 * applies to, mask out those bits.
		 */
		oldold = old;
		switch(reg) {
		case 0x1C: /* Secondary status */
			old &= 0x00ffffff; /* mask out 24-31 */
			break;
		case 0x50: /* EC - Device status */
			old &= 0xfff0ffff; /* mask out 16-19 */
			break;
		case 0x58: /* EC - Link status */
			old &= 0x3fffffff; /* mask out 30-31 */
			break;
		case 0x78: /* EC - Link status 2 */
			old &= 0xf000ffff; /* mask out 16-27 */
			break;
		/* These registers *only* have write-1-to-clear bits */
		case 0x104: /* AER - Uncorr. error status */
		case 0x110: /* AER - Corr. error status */
		case 0x130: /* AER - Root error status */
		case 0x180: /* P16 - status */
		case 0x184: /* P16 - LDPM status */
		case 0x188: /* P16 - FRDPM status */
		case 0x18C: /* P16 - SRDPM status */
			old &= 0x00000000;
			break;
		}

		if (old != oldold) {
			PHBLOGCFG(p, "Rewrote %x to %x for reg %x for W1C\n",
				  oldold, old, reg);
		}

		if (sz == 1) {
			shift = (offset & 3) << 3;
			mask = 0xff << shift;
			val = (old & ~mask) | ((val & 0xff) << shift);
		} else {
			shift = (offset & 2) << 3;
			mask = 0xffff << shift;
			val = (old & ~mask) | ((val & 0xffff) << shift);
		}
	}

	/* Some registers are handled locally */
	switch (reg) {
		/* See comment in phb4_rc_read() */
	case PCI_CFG_MEM_BASE:		/* Includes PCI_CFG_MEM_LIMIT */
	case PCI_CFG_PREF_MEM_BASE:	/* Includes PCI_CFG_PREF_MEM_LIMIT */
	case PCI_CFG_PREF_MEM_BASE_U32:
	case PCI_CFG_PREF_MEM_LIMIT_U32:
		p->rc_cache[(reg - 0x20) >> 2] = val;
		break;
	case PCI_CFG_IO_BASE_U16:	/* Includes PCI_CFG_IO_LIMIT_U16 */
		break;
	default:
		/* Workaround PHB config space enable */
		PHBLOGCFG(p, "000 CFG%02d Wr %02x=%08x\n", 8 * sz, reg, val);
		if (use_asb)
			phb4_write_reg_asb(p, PHB_RC_CONFIG_BASE + reg, val);
		else
			out_le32(p->regs + PHB_RC_CONFIG_BASE + reg, val);
	}
	return OPAL_SUCCESS;
}

static int64_t phb4_pcicfg_read(struct phb4 *p, uint32_t bdfn,
				uint32_t offset, uint32_t size,
				void *data)
{
	uint64_t addr, val64;
	int64_t rc;
	uint16_t pe;
	bool use_asb = false;

	rc = phb4_pcicfg_check(p, bdfn, offset, size, &pe);
	if (rc)
		return rc;

	if (p->flags & PHB4_AIB_FENCED) {
		if (!(p->flags & PHB4_CFG_USE_ASB))
			return OPAL_HARDWARE;
		if (bdfn != 0)
			return OPAL_HARDWARE;
		use_asb = true;
	} else if ((p->flags & PHB4_CFG_BLOCKED) && bdfn != 0) {
		return OPAL_HARDWARE;
	}

	/* Handle per-device filters */
	rc = pci_handle_cfg_filters(&p->phb, bdfn, offset, size,
				    (uint32_t *)data, false);
	if (rc != OPAL_PARTIAL)
		return rc;

	/* Handle root complex MMIO based config space */
	if (bdfn == 0)
		return phb4_rc_read(p, offset, size, data, use_asb);

	addr = PHB_CA_ENABLE;
	addr = SETFIELD(PHB_CA_BDFN, addr, bdfn);
	addr = SETFIELD(PHB_CA_REG, addr, offset & ~3u);
	addr = SETFIELD(PHB_CA_PE, addr, pe);
	if (use_asb) {
		phb4_write_reg_asb(p, PHB_CONFIG_ADDRESS, addr);
		sync();
		val64 = bswap_64(phb4_read_reg_asb(p, PHB_CONFIG_DATA));
		switch(size) {
		case 1:
			*((uint8_t *)data) = val64 >> (8 * (offset & 3));
			break;
		case 2:
			*((uint16_t *)data) = val64 >> (8 * (offset & 2));
			break;
		case 4:
			*((uint32_t *)data) = val64;
			break;
		default:
			return OPAL_PARAMETER;
		}
	} else {
		out_be64(p->regs + PHB_CONFIG_ADDRESS, addr);
		switch(size) {
		case 1:
			*((uint8_t *)data) =
				in_8(p->regs + PHB_CONFIG_DATA + (offset & 3));
			PHBLOGCFG(p, "%03x CFG08 Rd %02x=%02x\n",
				  bdfn, offset, *((uint8_t *)data));
			break;
		case 2:
			*((uint16_t *)data) =
				in_le16(p->regs + PHB_CONFIG_DATA + (offset & 2));
			PHBLOGCFG(p, "%03x CFG16 Rd %02x=%04x\n",
				  bdfn, offset, *((uint16_t *)data));
			break;
		case 4:
			*((uint32_t *)data) = in_le32(p->regs + PHB_CONFIG_DATA);
			PHBLOGCFG(p, "%03x CFG32 Rd %02x=%08x\n",
				  bdfn, offset, *((uint32_t *)data));
			break;
		default:
			return OPAL_PARAMETER;
		}
	}
	return OPAL_SUCCESS;
}


#define PHB4_PCI_CFG_READ(size, type)					\
static int64_t phb4_pcicfg_read##size(struct phb *phb, uint32_t bdfn,	\
				      uint32_t offset, type *data)	\
{									\
	struct phb4 *p = phb_to_phb4(phb);				\
									\
	/* Initialize data in case of error */				\
	*data = (type)0xffffffff;					\
	return phb4_pcicfg_read(p, bdfn, offset, sizeof(type), data);	\
}

static int64_t phb4_pcicfg_write(struct phb4 *p, uint32_t bdfn,
				 uint32_t offset, uint32_t size,
				 uint32_t data)
{
	uint64_t addr;
	int64_t rc;
	uint16_t pe;
	bool use_asb = false;

	rc = phb4_pcicfg_check(p, bdfn, offset, size, &pe);
	if (rc)
		return rc;

	if (p->flags & PHB4_AIB_FENCED) {
		if (!(p->flags & PHB4_CFG_USE_ASB))
			return OPAL_HARDWARE;
		if (bdfn != 0)
			return OPAL_HARDWARE;
		use_asb = true;
	} else if ((p->flags & PHB4_CFG_BLOCKED) && bdfn != 0) {
		return OPAL_HARDWARE;
	}

	/* Handle per-device filters */
	rc = pci_handle_cfg_filters(&p->phb, bdfn, offset, size,
				    (uint32_t *)&data, true);
	if (rc != OPAL_PARTIAL)
		return rc;

	/* Handle root complex MMIO based config space */
	if (bdfn == 0)
		return phb4_rc_write(p, offset, size, data, use_asb);

	addr = PHB_CA_ENABLE;
	addr = SETFIELD(PHB_CA_BDFN, addr, bdfn);
	addr = SETFIELD(PHB_CA_REG, addr, offset & ~3u);
	addr = SETFIELD(PHB_CA_PE, addr, pe);
	if (use_asb) {
		/* We don't support ASB config space writes */
		return OPAL_UNSUPPORTED;
	} else {
		out_be64(p->regs + PHB_CONFIG_ADDRESS, addr);
		switch(size) {
		case 1:
			out_8(p->regs + PHB_CONFIG_DATA + (offset & 3), data);
			break;
		case 2:
			out_le16(p->regs + PHB_CONFIG_DATA + (offset & 2), data);
			break;
		case 4:
			out_le32(p->regs + PHB_CONFIG_DATA, data);
			break;
		default:
			return OPAL_PARAMETER;
		}
	}
	PHBLOGCFG(p, "%03x CFG%d Wr %02x=%08x\n", bdfn, 8 * size, offset, data);
	return OPAL_SUCCESS;
}

#define PHB4_PCI_CFG_WRITE(size, type)					\
static int64_t phb4_pcicfg_write##size(struct phb *phb, uint32_t bdfn,	\
				       uint32_t offset, type data)	\
{									\
	struct phb4 *p = phb_to_phb4(phb);				\
									\
	return phb4_pcicfg_write(p, bdfn, offset, sizeof(type), data);	\
}

PHB4_PCI_CFG_READ(8, u8)
PHB4_PCI_CFG_READ(16, u16)
PHB4_PCI_CFG_READ(32, u32)
PHB4_PCI_CFG_WRITE(8, u8)
PHB4_PCI_CFG_WRITE(16, u16)
PHB4_PCI_CFG_WRITE(32, u32)

static int64_t phb4_get_reserved_pe_number(struct phb *phb)
{
	struct phb4 *p = phb_to_phb4(phb);

	return PHB4_RESERVED_PE_NUM(p);
}


static void phb4_root_port_init(struct phb *phb, struct pci_device *dev,
				int ecap, int aercap)
{
	struct phb4 *p = phb_to_phb4(phb);
	struct pci_slot *slot = dev->slot;
	uint16_t bdfn = dev->bdfn;
	uint16_t val16;
	uint32_t val32;

	/*
	 * Use the PHB's callback so that UTL events will be masked or
	 * unmasked when the link is down or up.
	 */
	if (dev->slot && dev->slot->ops.prepare_link_change &&
	    phb->slot && phb->slot->ops.prepare_link_change)
		dev->slot->ops.prepare_link_change =
			phb->slot->ops.prepare_link_change;

	// FIXME: check recommended init values for phb4

	/*
	 * Enable the bridge slot capability in the root port's config
	 * space. This should probably be done *before* we start
	 * scanning config space, but we need a pci_device struct to
	 * exist before we do a slot lookup so *faaaaaaaaaaaaaart*
	 */
	if (slot && slot->pluggable && slot->power_limit) {
		uint64_t val;

		val = in_be64(p->regs + PHB_PCIE_SCR);
		val |= PHB_PCIE_SCR_SLOT_CAP;
		out_be64(p->regs + PHB_PCIE_SCR, val);

		/* update the cached slotcap */
		pci_cfg_read32(phb, bdfn, ecap + PCICAP_EXP_SLOTCAP,
				&slot->slot_cap);
	}

	/* Enable SERR and parity checking */
	pci_cfg_read16(phb, bdfn, PCI_CFG_CMD, &val16);
	val16 |= (PCI_CFG_CMD_SERR_EN | PCI_CFG_CMD_PERR_RESP |
		  PCI_CFG_CMD_MEM_EN);
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

	/* Mask various unrecoverable errors */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_UE_MASK, &val32);
	val32 |= (PCIECAP_AER_UE_MASK_POISON_TLP |
		  PCIECAP_AER_UE_MASK_COMPL_TIMEOUT |
		  PCIECAP_AER_UE_MASK_COMPL_ABORT |
		  PCIECAP_AER_UE_MASK_ECRC);
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
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, &val32);
	val32 |= (PCIECAP_AER_CAPCTL_ECRCG_EN |
		  PCIECAP_AER_CAPCTL_ECRCC_EN);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, val32);

	/* Enable all error reporting */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_RERR_CMD, &val32);
	val32 |= (PCIECAP_AER_RERR_CMD_FE |
		  PCIECAP_AER_RERR_CMD_NFE |
		  PCIECAP_AER_RERR_CMD_CE);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_RERR_CMD, val32);
}

static void phb4_switch_port_init(struct phb *phb,
				  struct pci_device *dev,
				  int ecap, int aercap)
{
	uint16_t bdfn = dev->bdfn;
	uint16_t val16;
	uint32_t val32;

	// FIXME: update AER settings for phb4

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

	/* Unmask all unrecoverable errors */
	if (!aercap) return;
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
	 */
	val32 = PCIECAP_AER_CE_MASK_ADV_NONFATAL;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CE_MASK, val32);

	/* Enable ECRC generation and disable ECRC check */
	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, &val32);
	val32 |= PCIECAP_AER_CAPCTL_ECRCG_EN;
	val32 &= ~PCIECAP_AER_CAPCTL_ECRCC_EN;
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, val32);
}

static void phb4_endpoint_init(struct phb *phb,
			       struct pci_device *dev,
			       int ecap, int aercap)
{
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
	pci_cfg_write16(phb, bdfn, ecap + PCICAP_EXP_DEVCTL, val16);

	/* Enable ECRC generation and check */
	if (!aercap)
		return;

	pci_cfg_read32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, &val32);
	val32 |= (PCIECAP_AER_CAPCTL_ECRCG_EN |
		  PCIECAP_AER_CAPCTL_ECRCC_EN);
	pci_cfg_write32(phb, bdfn, aercap + PCIECAP_AER_CAPCTL, val32);
}

static int64_t phb4_pcicfg_no_dstate(void *dev __unused,
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

void phb4_pec2_dma_engine_realloc(struct phb4 *p)
{
	uint64_t reg;

	/*
	 * Allocate 16 extra dma read engines to stack 0, to boost dma
	 * performance for devices on stack 0 of PEC2, i.e PHB3.
	 * It comes at a price of reduced read engine allocation for
	 * devices on stack 1 and 2. The engine allocation becomes
	 * 48/8/8 instead of the default 32/16/16.
	 *
	 * The reallocation magic value should be 0xffff0000ff008000,
	 * but per the PCI designers, dma engine 32 (bit 0) has a
	 * quirk, and 0x7fff80007F008000 has the same effect (engine
	 * 32 goes to PHB4).
	 */
	if (p->index != 3) /* shared slot on PEC2 */
		return;

	PHBINF(p, "Allocating an extra 16 dma read engines on PEC2 stack0\n");
	reg = 0x7fff80007F008000ULL;
	xscom_write(p->chip_id,
		    p->pci_xscom + XPEC_PCI_PRDSTKOVR, reg);
	xscom_write(p->chip_id,
		    p->pe_xscom  + XPEC_NEST_READ_STACK_OVERRIDE, reg);
}

static void phb4_check_device_quirks(struct pci_device *dev)
{
	/* Some special adapter tweaks for devices directly under the PHB */
	if (dev->primary_bus != 1)
		return;

	/* PM quirk */
	if (!pci_has_cap(dev, PCI_CFG_CAP_ID_PM, false))
		return;

	pci_add_cfg_reg_filter(dev,
			       pci_cap(dev, PCI_CFG_CAP_ID_PM, false), 8,
			       PCI_REG_FLAG_WRITE,
			       phb4_pcicfg_no_dstate);
}

static int phb4_device_init(struct phb *phb, struct pci_device *dev,
			    void *data __unused)
{
	int ecap, aercap;

	/* Setup special device quirks */
	phb4_check_device_quirks(dev);

	/* Common initialization for the device */
	pci_device_init(phb, dev);

	ecap = pci_cap(dev, PCI_CFG_CAP_ID_EXP, false);
	aercap = pci_cap(dev, PCIECAP_ID_AER, true);
	if (dev->dev_type == PCIE_TYPE_ROOT_PORT)
		phb4_root_port_init(phb, dev, ecap, aercap);
	else if (dev->dev_type == PCIE_TYPE_SWITCH_UPPORT ||
		 dev->dev_type == PCIE_TYPE_SWITCH_DNPORT)
		phb4_switch_port_init(phb, dev, ecap, aercap);
	else
		phb4_endpoint_init(phb, dev, ecap, aercap);

	return 0;
}

static int64_t phb4_pci_reinit(struct phb *phb, uint64_t scope, uint64_t data)
{
	struct pci_device *pd;
	uint16_t bdfn = data;
	int ret;

	if (scope != OPAL_REINIT_PCI_DEV)
		return OPAL_PARAMETER;

	pd = pci_find_dev(phb, bdfn);
	if (!pd)
		return OPAL_PARAMETER;

	ret = phb4_device_init(phb, pd, NULL);
	if (ret)
		return OPAL_HARDWARE;

	return OPAL_SUCCESS;
}

/* Default value for MBT0, see comments in init_ioda_cache() */
static uint64_t phb4_default_mbt0(struct phb4 *p, unsigned int bar_idx)
{
	uint64_t mbt0;

	switch (p->mbt_size - bar_idx - 1) {
	case 0:
		mbt0 = SETFIELD(IODA3_MBT0_MODE, 0ull, IODA3_MBT0_MODE_MDT);
		mbt0 = SETFIELD(IODA3_MBT0_MDT_COLUMN, mbt0, 3);
		break;
	case 1:
		mbt0 = SETFIELD(IODA3_MBT0_MODE, 0ull, IODA3_MBT0_MODE_MDT);
		mbt0 = SETFIELD(IODA3_MBT0_MDT_COLUMN, mbt0, 2);
		break;
	case 2:
		mbt0 = SETFIELD(IODA3_MBT0_MODE, 0ull, IODA3_MBT0_MODE_MDT);
		mbt0 = SETFIELD(IODA3_MBT0_MDT_COLUMN, mbt0, 1);
		break;
	default:
		mbt0 = SETFIELD(IODA3_MBT0_MODE, 0ull, IODA3_MBT0_MODE_PE_SEG);
	}
	return mbt0;
}

/*
 * Clear the saved (cached) IODA state.
 *
 * The caches here are used to save the configuration of the IODA tables
 * done by the OS. When the PHB is reset it loses all of its internal state
 * so we need to keep a copy to restore from. This function re-initialises
 * the saved state to sane defaults.
 */
static void phb4_init_ioda_cache(struct phb4 *p)
{
	uint32_t i;

	/*
	 * The RTT entries (RTE) are supposed to be initialised to
	 * 0xFF which indicates an invalid PE# for that RTT index
	 * (the bdfn). However, we set them to 0x00 since Linux
	 * needs to find the devices first by scanning config space
	 * and this occurs before PEs have been assigned.
	 */
	for (i = 0; i < RTT_TABLE_ENTRIES; i++)
		p->tbl_rtt[i] = cpu_to_be16(PHB4_RESERVED_PE_NUM(p));
	memset(p->tbl_peltv, 0x0, p->tbl_peltv_size);
	memset(p->tve_cache, 0x0, sizeof(p->tve_cache));

	/* XXX Should we mask them ? */
	memset(p->mist_cache, 0x0, sizeof(p->mist_cache));

	/* Configure MBT entries 1...N */

	/* Column 0 is left 0 and will be used fo M32 and configured
	 * by the OS. We use MDT column 1..3 for the last 3 BARs, thus
	 * allowing Linux to remap those, and setup all the other ones
	 * for now in mode 00 (segment# == PE#). By default those
	 * columns are set to map the same way.
	 */
	for (i = 0; i < p->max_num_pes; i++) {
		p->mdt_cache[i]  = SETFIELD(IODA3_MDT_PE_B, 0ull, i);
		p->mdt_cache[i] |= SETFIELD(IODA3_MDT_PE_C, 0ull, i);
		p->mdt_cache[i] |= SETFIELD(IODA3_MDT_PE_D, 0ull, i);
	}

	/* Initialize MBT entries for BARs 1...N */
	for (i = 1; i < p->mbt_size; i++) {
		p->mbt_cache[i][0] = phb4_default_mbt0(p, i);
		p->mbt_cache[i][1] = 0;
	}

	/* Initialize M32 bar using MBT entry 0, MDT colunm A */
	p->mbt_cache[0][0] = SETFIELD(IODA3_MBT0_MODE, 0ull, IODA3_MBT0_MODE_MDT);
	p->mbt_cache[0][0] |= SETFIELD(IODA3_MBT0_MDT_COLUMN, 0ull, 0);
	p->mbt_cache[0][0] |= IODA3_MBT0_TYPE_M32 | (p->mm1_base & IODA3_MBT0_BASE_ADDR);
	p->mbt_cache[0][1] = IODA3_MBT1_ENABLE | ((~(M32_PCI_SIZE - 1)) & IODA3_MBT1_MASK);
}

static int64_t phb4_wait_bit(struct phb4 *p, uint32_t reg,
			     uint64_t mask, uint64_t want_val)
{
	uint64_t val;

	/* Wait for all pending TCE kills to complete
	 *
	 * XXX Add timeout...
	 */
	/* XXX SIMICS is nasty... */
	if ((reg == PHB_TCE_KILL || reg == PHB_DMA_READ_WRITE_SYNC) &&
	    chip_quirk(QUIRK_SIMICS))
		return OPAL_SUCCESS;

	for (;;) {
		val = in_be64(p->regs + reg);
		if (val == 0xffffffffffffffffull) {
			/* XXX Fenced ? */
			return OPAL_HARDWARE;
		}
		if ((val & mask) == want_val)
			break;

	}
	return OPAL_SUCCESS;
}

static int64_t phb4_tce_kill(struct phb *phb, uint32_t kill_type,
			     uint64_t pe_number, uint32_t tce_size,
			     uint64_t dma_addr, uint32_t npages)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t val;
	int64_t rc;

	/*
	 * HW560152: a page-level kill can be dropped if the
	 *	 processing queue is backed-up, which can cause data
	 *	 integrity issues
	 */
	if (kill_type == OPAL_PCI_TCE_KILL_PAGES)
		kill_type = OPAL_PCI_TCE_KILL_PE;

	sync();
	switch(kill_type) {
	case OPAL_PCI_TCE_KILL_PAGES:
		while (npages--) {
			/* Wait for a slot in the HW kill queue */
			rc = phb4_wait_bit(p, PHB_TCE_KILL,
					   PHB_TCE_KILL_ALL |
					   PHB_TCE_KILL_PE |
					   PHB_TCE_KILL_ONE, 0);
			if (rc)
				return rc;
			val = SETFIELD(PHB_TCE_KILL_PENUM, dma_addr, pe_number);

			/* Set appropriate page size */
			switch(tce_size) {
			case 0x1000:
				if (dma_addr & 0xf000000000000fffull)
					return OPAL_PARAMETER;
				break;
			case 0x10000:
				if (dma_addr & 0xf00000000000ffffull)
					return OPAL_PARAMETER;
				val |= PHB_TCE_KILL_PSEL | PHB_TCE_KILL_64K;
				break;
			case 0x200000:
				if (dma_addr & 0xf0000000001fffffull)
					return OPAL_PARAMETER;
				val |= PHB_TCE_KILL_PSEL | PHB_TCE_KILL_2M;
				break;
			case 0x40000000:
				if (dma_addr & 0xf00000003fffffffull)
					return OPAL_PARAMETER;
				val |= PHB_TCE_KILL_PSEL | PHB_TCE_KILL_1G;
				break;
			default:
				return OPAL_PARAMETER;
			}
			/* Perform kill */
			out_be64(p->regs + PHB_TCE_KILL, PHB_TCE_KILL_ONE | val);
			/* Next page */
			dma_addr += tce_size;
		}
		break;
	case OPAL_PCI_TCE_KILL_PE:
		/* Wait for a slot in the HW kill queue */
		rc = phb4_wait_bit(p, PHB_TCE_KILL,
				   PHB_TCE_KILL_ALL |
				   PHB_TCE_KILL_PE |
				   PHB_TCE_KILL_ONE, 0);
		if (rc)
			return rc;
		/* Perform kill */
		out_be64(p->regs + PHB_TCE_KILL, PHB_TCE_KILL_PE |
			 SETFIELD(PHB_TCE_KILL_PENUM, 0ull, pe_number));
		break;
	case OPAL_PCI_TCE_KILL_ALL:
		/* Wait for a slot in the HW kill queue */
		rc = phb4_wait_bit(p, PHB_TCE_KILL,
				   PHB_TCE_KILL_ALL |
				   PHB_TCE_KILL_PE |
				   PHB_TCE_KILL_ONE, 0);
		if (rc)
			return rc;
		/* Perform kill */
		out_be64(p->regs + PHB_TCE_KILL, PHB_TCE_KILL_ALL);
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* Start DMA sync process */
	if (is_phb5()){
		val = in_be64(p->regs + PHB_DMA_READ_WRITE_SYNC) &
					(PHB_DMA_READ_SYNC_COMPLETE |
					 PHB_DMA_WRITE_SYNC_COMPLETE);
		out_be64(p->regs + PHB_DMA_READ_WRITE_SYNC,
					val | PHB_DMA_READ_SYNC_START);

	} else {
		out_be64(p->regs + PHB_DMA_READ_WRITE_SYNC,
			 PHB_DMA_READ_SYNC_START);
	}

	/* Wait for kill to complete */
	rc = phb4_wait_bit(p, PHB_Q_DMA_R, PHB_Q_DMA_R_TCE_KILL_STATUS, 0);
	if (rc)
		return rc;

	/* Wait for DMA sync to complete */
	return phb4_wait_bit(p, PHB_DMA_READ_WRITE_SYNC,
			     PHB_DMA_READ_SYNC_COMPLETE,
			     PHB_DMA_READ_SYNC_COMPLETE);
}

/* phb4_ioda_reset - Reset the IODA tables
 *
 * @purge: If true, the cache is cleared and the cleared values
 *         are applied to HW. If false, the cached values are
 *         applied to HW
 *
 * This reset the IODA tables in the PHB. It is called at
 * initialization time, on PHB reset, and can be called
 * explicitly from OPAL
 */
static int64_t phb4_ioda_reset(struct phb *phb, bool purge)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint32_t i;
	uint64_t val;

	if (purge) {
		PHBDBG(p, "Purging all IODA tables...\n");
		if (phb->slot)
			phb->slot->link_retries = PHB4_LINK_LINK_RETRIES;
		phb4_init_ioda_cache(p);
	}

	/* Init_30..31 - Errata workaround, clear PESTA entry 0 */
	phb4_ioda_sel(p, IODA3_TBL_PESTA, 0, false);
	out_be64(p->regs + PHB_IODA_DATA0, 0);

	/* Init_32..33 - MIST  */
	phb4_ioda_sel(p, IODA3_TBL_MIST, 0, true);
	val = in_be64(p->regs + PHB_IODA_ADDR);
	val = SETFIELD(PHB_IODA_AD_MIST_PWV, val, 0xf);
	out_be64(p->regs + PHB_IODA_ADDR, val);
	for (i = 0; i < (p->num_irqs/4); i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->mist_cache[i]);

	/* Init_34..35 - MRT */
	phb4_ioda_sel(p, IODA3_TBL_MRT, 0, true);
	for (i = 0; i < p->mrt_size; i++)
		out_be64(p->regs + PHB_IODA_DATA0, 0);

	/* Init_36..37 - TVT */
	phb4_ioda_sel(p, IODA3_TBL_TVT, 0, true);
	for (i = 0; i < p->tvt_size; i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->tve_cache[i]);

	/* Init_38..39 - MBT */
	phb4_ioda_sel(p, IODA3_TBL_MBT, 0, true);
	for (i = 0; i < p->mbt_size; i++) {
		out_be64(p->regs + PHB_IODA_DATA0, p->mbt_cache[i][0]);
		out_be64(p->regs + PHB_IODA_DATA0, p->mbt_cache[i][1]);
	}

	/* Init_40..41 - MDT */
	phb4_ioda_sel(p, IODA3_TBL_MDT, 0, true);
	for (i = 0; i < p->max_num_pes; i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->mdt_cache[i]);

	/* Additional OPAL specific inits */

	/* Clear PEST & PEEV */
	for (i = 0; i < p->max_num_pes; i++) {
		phb4_ioda_sel(p, IODA3_TBL_PESTA, i, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
		phb4_ioda_sel(p, IODA3_TBL_PESTB, i, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}

	phb4_ioda_sel(p, IODA3_TBL_PEEV, 0, true);
	for (i = 0; i < p->max_num_pes/64; i++)
		out_be64(p->regs + PHB_IODA_DATA0, 0);

	/* Invalidate RTE, TCE cache */
	out_be64(p->regs + PHB_RTC_INVALIDATE, PHB_RTC_INVALIDATE_ALL);

	return phb4_tce_kill(&p->phb, OPAL_PCI_TCE_KILL_ALL, 0, 0, 0, 0);
}

/*
 * Clear anything we have in PAPR Error Injection registers. Though
 * the spec says the PAPR error injection should be one-shot without
 * the "sticky" bit. However, that's false according to the experiments
 * I had. So we have to clear it at appropriate point in kernel to
 * avoid endless frozen PE.
 */
static int64_t phb4_papr_errinjct_reset(struct phb *phb)
{
	struct phb4 *p = phb_to_phb4(phb);

	out_be64(p->regs + PHB_PAPR_ERR_INJ_CTL, 0x0ul);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_ADDR, 0x0ul);
	out_be64(p->regs + PHB_PAPR_ERR_INJ_MASK, 0x0ul);

	return OPAL_SUCCESS;
}

static int64_t phb4_set_phb_mem_window(struct phb *phb,
				       uint16_t window_type,
				       uint16_t window_num,
				       uint64_t addr,
				       uint64_t pci_addr __unused,
				       uint64_t size)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t mbt0, mbt1;

	/*
	 * We have a unified MBT for all BARs on PHB4.
	 *
	 * So we use it as follow:
	 *
	 *  - M32 is hard wired to be MBT[0] and uses MDT column 0
	 *    for remapping.
	 *
	 *  - MBT[1..n] are available to the OS, currently only as
	 *    fully segmented or single PE (we don't yet expose the
	 *    new segmentation modes).
	 *
	 *  - We configure the 3 last BARs to columnt 1..3 initially
	 *    set to segment# == PE#. We will need to provide some
	 *    extensions to the existing APIs to enable remapping of
	 *    segments on those BARs (and only those) as the current
	 *    API forces single segment mode.
	 */
	switch (window_type) {
	case OPAL_IO_WINDOW_TYPE:
	case OPAL_M32_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num == 0 || window_num >= p->mbt_size) {
			PHBERR(p, "%s: Invalid window %d\n",
			       __func__, window_num);
			return OPAL_PARAMETER;
		}

		mbt0 = p->mbt_cache[window_num][0];
		mbt1 = p->mbt_cache[window_num][1];

		/* XXX For now we assume the 4K minimum alignment,
		 * todo: check with the HW folks what the exact limits
		 * are based on the segmentation model.
		 */
		if ((addr & 0xFFFul) || (size & 0xFFFul)) {
			PHBERR(p, "%s: Bad addr/size alignment %llx/%llx\n",
			       __func__, addr, size);
			return OPAL_PARAMETER;
		}

		/* size should be 2^N */
		if (!size || size & (size-1)) {
			PHBERR(p, "%s: size not a power of 2: %llx\n",
			       __func__,  size);
			return OPAL_PARAMETER;
		}

		/* address should be size aligned */
		if (addr & (size - 1)) {
			PHBERR(p, "%s: addr not size aligned %llx/%llx\n",
			       __func__, addr, size);
			return OPAL_PARAMETER;
		}

		break;
	default:
		return OPAL_PARAMETER;
	}

	/* The BAR shouldn't be enabled yet */
	if (mbt0 & IODA3_MBT0_ENABLE)
		return OPAL_PARTIAL;

	/* Apply the settings */
	mbt0 = SETFIELD(IODA3_MBT0_BASE_ADDR, mbt0, addr >> 12);
	mbt1 = SETFIELD(IODA3_MBT1_MASK, mbt1, ~((size >> 12) -1));
	p->mbt_cache[window_num][0] = mbt0;
	p->mbt_cache[window_num][1] = mbt1;

	return OPAL_SUCCESS;
}

/*
 * For one specific M64 BAR, it can be shared by all PEs,
 * or owned by single PE exclusively.
 */
static int64_t phb4_phb_mmio_enable(struct phb __unused *phb,
				    uint16_t window_type,
				    uint16_t window_num,
				    uint16_t enable)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t mbt0, mbt1, base, mask;

	/*
	 * By design, PHB4 doesn't support IODT any more.
	 * Besides, we can't enable M32 BAR as well. So
	 * the function is used to do M64 mapping and each
	 * BAR is supposed to be shared by all PEs.
	 *
	 * TODO: Add support for some of the new PHB4 split modes
	 */
	switch (window_type) {
	case OPAL_IO_WINDOW_TYPE:
	case OPAL_M32_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M64_WINDOW_TYPE:
		/* Window 0 is reserved for M32 */
		if (window_num == 0 || window_num >= p->mbt_size ||
		    enable > OPAL_ENABLE_M64_NON_SPLIT) {
			PHBDBG(p,
			       "phb4_phb_mmio_enable wrong args (window %d enable %d)\n",
			       window_num, enable);
			return OPAL_PARAMETER;
		}
		break;
	default:
		return OPAL_PARAMETER;
	}

	/*
	 * We need check the base/mask while enabling
	 * the M64 BAR. Otherwise, invalid base/mask
	 * might cause fenced AIB unintentionally
	 */
	mbt0 = p->mbt_cache[window_num][0];
	mbt1 = p->mbt_cache[window_num][1];

	if (enable == OPAL_DISABLE_M64) {
		/* Reset the window to disabled & default mode */
		mbt0 = phb4_default_mbt0(p, window_num);
		mbt1 = 0;
	} else {
		/* Verify that the mode is valid and consistent */
		if (enable == OPAL_ENABLE_M64_SPLIT) {
			uint64_t mode = GETFIELD(IODA3_MBT0_MODE, mbt0);
			if (mode != IODA3_MBT0_MODE_PE_SEG &&
			    mode != IODA3_MBT0_MODE_MDT)
				return OPAL_PARAMETER;
		} else if (enable == OPAL_ENABLE_M64_NON_SPLIT) {
			if (GETFIELD(IODA3_MBT0_MODE, mbt0) !=
			    IODA3_MBT0_MODE_SINGLE_PE)
				return OPAL_PARAMETER;
		} else
			return OPAL_PARAMETER;

		base = GETFIELD(IODA3_MBT0_BASE_ADDR, mbt0);
		base = (base << 12);
		mask = GETFIELD(IODA3_MBT1_MASK, mbt1);
		if (base < p->mm0_base || !mask)
			return OPAL_PARTIAL;

		mbt0 |= IODA3_MBT0_ENABLE;
		mbt1 |= IODA3_MBT1_ENABLE;
	}

	/* Update HW and cache */
	p->mbt_cache[window_num][0] = mbt0;
	p->mbt_cache[window_num][1] = mbt1;
	phb4_ioda_sel(p, IODA3_TBL_MBT, window_num << 1, true);
	out_be64(p->regs + PHB_IODA_DATA0, mbt0);
	out_be64(p->regs + PHB_IODA_DATA0, mbt1);

	return OPAL_SUCCESS;
}

static int64_t phb4_map_pe_mmio_window(struct phb *phb,
				       uint64_t pe_number,
				       uint16_t window_type,
				       uint16_t window_num,
				       uint16_t segment_num)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t mbt0, mbt1, mdt0;

	if (pe_number >= p->num_pes)
		return OPAL_PARAMETER;

	/*
	 * We support a combined MDT that has 4 columns. We let the OS
	 * use kernel 0 for M32.
	 *
	 * We configure the 3 last BARs to map column 3..1 which by default
	 * are set to map segment# == pe#, but can be remapped here if we
	 * extend this function.
	 *
	 * The problem is that the current API was "hijacked" so that an
	 * attempt at remapping any segment of an M64 has the effect of
	 * turning it into a single-PE mode BAR. So if we want to support
	 * remapping we'll have to play around this for example by creating
	 * a new API or a new window type...
	 */
	switch(window_type) {
	case OPAL_IO_WINDOW_TYPE:
		return OPAL_UNSUPPORTED;
	case OPAL_M32_WINDOW_TYPE:
		if (window_num != 0 || segment_num >= p->num_pes)
			return OPAL_PARAMETER;

		mdt0 = p->mdt_cache[segment_num];
		mdt0 = SETFIELD(IODA3_MDT_PE_A, mdt0, pe_number);
		phb4_ioda_sel(p, IODA3_TBL_MDT, segment_num, false);
		out_be64(p->regs + PHB_IODA_DATA0, mdt0);
		break;
	case OPAL_M64_WINDOW_TYPE:
		if (window_num == 0 || window_num >= p->mbt_size)
			return OPAL_PARAMETER;

		mbt0 = p->mbt_cache[window_num][0];
		mbt1 = p->mbt_cache[window_num][1];

		/* The BAR shouldn't be enabled yet */
		if (mbt0 & IODA3_MBT0_ENABLE)
			return OPAL_PARTIAL;

		/* Set to single PE mode and configure the PE */
		mbt0 = SETFIELD(IODA3_MBT0_MODE, mbt0,
				IODA3_MBT0_MODE_SINGLE_PE);
		mbt1 = SETFIELD(IODA3_MBT1_SINGLE_PE_NUM, mbt1, pe_number);
		p->mbt_cache[window_num][0] = mbt0;
		p->mbt_cache[window_num][1] = mbt1;
		break;
	default:
		return OPAL_PARAMETER;
	}

	return OPAL_SUCCESS;
}

static int64_t phb4_map_pe_dma_window(struct phb *phb,
				      uint64_t pe_number,
				      uint16_t window_id,
				      uint16_t tce_levels,
				      uint64_t tce_table_addr,
				      uint64_t tce_table_size,
				      uint64_t tce_page_size)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t tts_encoded;
	uint64_t data64 = 0;

	/*
	 * We configure the PHB in 2 TVE per PE mode to match phb3.
	 * Current Linux implementation *requires* the two windows per
	 * PE.
	 *
	 * Note: On DD2.0 this is the normal mode of operation.
	 */

	/*
	 * Sanity check. We currently only support "2 window per PE" mode
	 * ie, only bit 59 of the PCI address is used to select the window
	 */
	if (pe_number >= p->num_pes || (window_id >> 1) != pe_number)
		return OPAL_PARAMETER;

	/*
	 * tce_table_size == 0 is used to disable an entry, in this case
	 * we ignore other arguments
	 */
	if (tce_table_size == 0) {
		phb4_ioda_sel(p, IODA3_TBL_TVT, window_id, false);
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
	data64 = SETFIELD(IODA3_TVT_TABLE_ADDR, 0ul, tce_table_addr >> 12);
	tts_encoded = ilog2(tce_table_size) - 11;
	if (tts_encoded > 31)
		return OPAL_PARAMETER;
	data64 = SETFIELD(IODA3_TVT_TCE_TABLE_SIZE, data64, tts_encoded);

	/* Encode TCE page size */
	switch (tce_page_size) {
	case 0x1000:	/* 4K */
		data64 = SETFIELD(IODA3_TVT_IO_PSIZE, data64, 1);
		break;
	case 0x10000:	/* 64K */
		data64 = SETFIELD(IODA3_TVT_IO_PSIZE, data64, 5);
		break;
	case 0x200000:	/* 2M */
		data64 = SETFIELD(IODA3_TVT_IO_PSIZE, data64, 10);
		break;
	case 0x40000000: /* 1G */
		data64 = SETFIELD(IODA3_TVT_IO_PSIZE, data64, 19);
		break;
	default:
		return OPAL_PARAMETER;
	}

	/* Encode number of levels */
	data64 = SETFIELD(IODA3_TVT_NUM_LEVELS, data64, tce_levels - 1);

	phb4_ioda_sel(p, IODA3_TBL_TVT, window_id, false);
	out_be64(p->regs + PHB_IODA_DATA0, data64);
	p->tve_cache[window_id] = data64;

	return OPAL_SUCCESS;
}

static int64_t phb4_map_pe_dma_window_real(struct phb *phb,
					   uint64_t pe_number,
					   uint16_t window_id,
					   uint64_t pci_start_addr,
					   uint64_t pci_mem_size)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t end = pci_start_addr + pci_mem_size;
	uint64_t tve;

	if (pe_number >= p->num_pes ||
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
		tve  = (pci_start_addr << 16) & (0xffffffull << 40);
		tve |= (pci_start_addr >> 38) & (3ull << 10);
		tve |= (end >>  8) & (0xfffffful << 16);
		tve |= (end >> 40) & (3ull << 8);
		tve |= PPC_BIT(51) | IODA3_TVT_NON_TRANSLATE_50;
	} else {
		/* Disable */
		tve = 0;
	}

	phb4_ioda_sel(p, IODA3_TBL_TVT, window_id, false);
	out_be64(p->regs + PHB_IODA_DATA0, tve);
	p->tve_cache[window_id] = tve;

	return OPAL_SUCCESS;
}

static int64_t phb4_set_option(struct phb *phb, enum OpalPhbOption opt,
			       uint64_t setting)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t data64;

	data64 = phb4_read_reg(p, PHB_CTRLR);
	switch (opt) {
	case OPAL_PHB_OPTION_TVE1_4GB:
		if (setting > 1)
			return OPAL_PARAMETER;

		PHBDBG(p, "4GB bypass mode = %lld\n", setting);
		if (setting)
			data64 |= PPC_BIT(24);
		else
			data64 &= ~PPC_BIT(24);
		break;
	case OPAL_PHB_OPTION_MMIO_EEH_DISABLE:
		if (setting > 1)
			return OPAL_PARAMETER;

		PHBDBG(p, "MMIO EEH Disable = %lld\n", setting);
		if (setting)
			data64 |= PPC_BIT(14);
		else
			data64 &= ~PPC_BIT(14);
		break;
	default:
		return OPAL_UNSUPPORTED;
	}
	phb4_write_reg(p, PHB_CTRLR, data64);

	return OPAL_SUCCESS;
}

static int64_t phb4_get_option(struct phb *phb, enum OpalPhbOption opt,
			       __be64 *setting)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t data64;

	data64 = phb4_read_reg(p, PHB_CTRLR);
	switch (opt) {
	case OPAL_PHB_OPTION_TVE1_4GB:
		*setting = cpu_to_be64((data64 & PPC_BIT(24)) ? 1 : 0);
		break;
	case OPAL_PHB_OPTION_MMIO_EEH_DISABLE:
		*setting = cpu_to_be64((data64 & PPC_BIT(14)) ? 1 : 0);
		break;
	default:
		return OPAL_UNSUPPORTED;
	}

	return OPAL_SUCCESS;
}

static int64_t phb4_set_ive_pe(struct phb *phb,
			       uint64_t pe_number,
			       uint32_t ive_num)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint32_t mist_idx;
	uint32_t mist_quad;
	uint32_t mist_shift;
	uint64_t val;

	if (pe_number >= p->num_pes || ive_num >= (p->num_irqs - 8))
		return OPAL_PARAMETER;

	mist_idx = ive_num >> 2;
	mist_quad = ive_num & 3;
	mist_shift = (3 - mist_quad) << 4;
	p->mist_cache[mist_idx] &= ~(0x0fffull << mist_shift);
	p->mist_cache[mist_idx] |=  ((uint64_t)pe_number) << mist_shift;

	/* Note: This has the side effect of clearing P/Q, so this
	 * shouldn't be called while the interrupt is "hot"
	 */

	phb4_ioda_sel(p, IODA3_TBL_MIST, mist_idx, false);

	/* We need to inject the appropriate MIST write enable bit
	 * in the IODA table address register
	 */
	val = in_be64(p->regs + PHB_IODA_ADDR);
	val = SETFIELD(PHB_IODA_AD_MIST_PWV, val, 8 >> mist_quad);
	out_be64(p->regs + PHB_IODA_ADDR, val);

	/* Write entry */
	out_be64(p->regs + PHB_IODA_DATA0, p->mist_cache[mist_idx]);

	return OPAL_SUCCESS;
}

static int64_t phb4_get_msi_32(struct phb *phb,
			       uint64_t pe_number,
			       uint32_t ive_num,
			       uint8_t msi_range,
			       uint32_t *msi_address,
			       uint32_t *message_data)
{
	struct phb4 *p = phb_to_phb4(phb);

	/*
	 * Sanity check. We needn't check on mve_number (PE#)
	 * on PHB3 since the interrupt source is purely determined
	 * by its DMA address and data, but the check isn't
	 * harmful.
	 */
	if (pe_number >= p->num_pes ||
	    ive_num >= (p->num_irqs - 8) ||
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

static int64_t phb4_get_msi_64(struct phb *phb,
			       uint64_t pe_number,
			       uint32_t ive_num,
			       uint8_t msi_range,
			       uint64_t *msi_address,
			       uint32_t *message_data)
{
	struct phb4 *p = phb_to_phb4(phb);

	/* Sanity check */
	if (pe_number >= p->num_pes ||
	    ive_num >= (p->num_irqs - 8) ||
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

static void phb4_rc_err_clear(struct phb4 *p)
{
	/* Init_47 - Clear errors */
	phb4_pcicfg_write16(&p->phb, 0, PCI_CFG_SECONDARY_STATUS, 0xffff);

	if (p->ecap <= 0)
		return;

	phb4_pcicfg_write16(&p->phb, 0, p->ecap + PCICAP_EXP_DEVSTAT,
			     PCICAP_EXP_DEVSTAT_CE	|
			     PCICAP_EXP_DEVSTAT_NFE	|
			     PCICAP_EXP_DEVSTAT_FE	|
			     PCICAP_EXP_DEVSTAT_UE);

	if (p->aercap <= 0)
		return;

	/* Clear all UE status */
	phb4_pcicfg_write32(&p->phb, 0, p->aercap + PCIECAP_AER_UE_STATUS,
			     0xffffffff);
	/* Clear all CE status */
	phb4_pcicfg_write32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_STATUS,
			     0xffffffff);
	/* Clear root error status */
	phb4_pcicfg_write32(&p->phb, 0, p->aercap + PCIECAP_AER_RERR_STA,
			     0xffffffff);
}

static void phb4_err_clear_regb(struct phb4 *p)
{
	uint64_t val64;

	val64 = phb4_read_reg(p, PHB_REGB_ERR_STATUS);
	phb4_write_reg(p, PHB_REGB_ERR_STATUS, val64);
	phb4_write_reg(p, PHB_REGB_ERR1_STATUS, 0x0ul);
	phb4_write_reg(p, PHB_REGB_ERR_LOG_0, 0x0ul);
	phb4_write_reg(p, PHB_REGB_ERR_LOG_1, 0x0ul);
}

/*
 * The function can be called during error recovery for all classes of
 * errors.  This is new to PHB4; previous revisions had separate
 * sequences for INF/ER/Fatal errors.
 *
 * "Rec #" in this function refer to "Recov_#" steps in the
 * PHB4 INF recovery sequence.
 */
static void phb4_err_clear(struct phb4 *p)
{
	uint64_t val64;
	uint64_t fir = phb4_read_reg(p, PHB_LEM_FIR_ACCUM);

	/* Rec 1: Acquire the PCI config lock (we don't need to do this) */

	/* Rec 2...15: Clear error status in RC config space */
	phb4_rc_err_clear(p);

	/* Rec 16...23: Clear PBL errors */
	val64 = phb4_read_reg(p, PHB_PBL_ERR_STATUS);
	phb4_write_reg(p, PHB_PBL_ERR_STATUS, val64);
	phb4_write_reg(p, PHB_PBL_ERR1_STATUS, 0x0ul);
	phb4_write_reg(p, PHB_PBL_ERR_LOG_0, 0x0ul);
	phb4_write_reg(p, PHB_PBL_ERR_LOG_1, 0x0ul);

	/* Rec 24...31: Clear REGB errors */
	phb4_err_clear_regb(p);

	/* Rec 32...59: Clear PHB error trap */
	val64 = phb4_read_reg(p, PHB_TXE_ERR_STATUS);
	phb4_write_reg(p, PHB_TXE_ERR_STATUS, val64);
	phb4_write_reg(p, PHB_TXE_ERR1_STATUS, 0x0ul);
	phb4_write_reg(p, PHB_TXE_ERR_LOG_0, 0x0ul);
	phb4_write_reg(p, PHB_TXE_ERR_LOG_1, 0x0ul);

	val64 = phb4_read_reg(p, PHB_RXE_ARB_ERR_STATUS);
	phb4_write_reg(p, PHB_RXE_ARB_ERR_STATUS, val64);
	phb4_write_reg(p, PHB_RXE_ARB_ERR1_STATUS, 0x0ul);
	phb4_write_reg(p, PHB_RXE_ARB_ERR_LOG_0, 0x0ul);
	phb4_write_reg(p, PHB_RXE_ARB_ERR_LOG_1, 0x0ul);

	val64 = phb4_read_reg(p, PHB_RXE_MRG_ERR_STATUS);
	phb4_write_reg(p, PHB_RXE_MRG_ERR_STATUS, val64);
	phb4_write_reg(p, PHB_RXE_MRG_ERR1_STATUS, 0x0ul);
	phb4_write_reg(p, PHB_RXE_MRG_ERR_LOG_0, 0x0ul);
	phb4_write_reg(p, PHB_RXE_MRG_ERR_LOG_1, 0x0ul);

	val64 = phb4_read_reg(p, PHB_RXE_TCE_ERR_STATUS);
	phb4_write_reg(p, PHB_RXE_TCE_ERR_STATUS, val64);
	phb4_write_reg(p, PHB_RXE_TCE_ERR1_STATUS, 0x0ul);
	phb4_write_reg(p, PHB_RXE_TCE_ERR_LOG_0, 0x0ul);
	phb4_write_reg(p, PHB_RXE_TCE_ERR_LOG_1, 0x0ul);

	val64 = phb4_read_reg(p, PHB_ERR_STATUS);
	phb4_write_reg(p, PHB_ERR_STATUS, val64);
	phb4_write_reg(p, PHB_ERR1_STATUS, 0x0ul);
	phb4_write_reg(p, PHB_ERR_LOG_0, 0x0ul);
	phb4_write_reg(p, PHB_ERR_LOG_1, 0x0ul);

	/* Rec 61/62: Clear FIR/WOF */
	phb4_write_reg(p, PHB_LEM_FIR_AND_MASK, ~fir);
	phb4_write_reg(p, PHB_LEM_WOF, 0x0ul);

	/* Rec 63: Update LEM mask to its initial value */
	phb4_write_reg(p, PHB_LEM_ERROR_MASK, 0x0ul);

	/* Rec 64: Clear the PCI config lock (we don't need to do this) */
}

static void phb4_read_phb_status(struct phb4 *p,
				 struct OpalIoPhb4ErrorData *stat)
{
	uint32_t i;
	uint16_t __16;
	uint32_t __32;
	uint64_t __64;

	memset(stat, 0, sizeof(struct OpalIoPhb4ErrorData));

	/* Error data common part */
	stat->common.version = cpu_to_be32(OPAL_PHB_ERROR_DATA_VERSION_1);
	stat->common.ioType  = cpu_to_be32(OPAL_PHB_ERROR_DATA_TYPE_PHB4);
	stat->common.len     = cpu_to_be32(sizeof(struct OpalIoPhb4ErrorData));

	/* Use ASB for config space if the PHB is fenced */
	if (p->flags & PHB4_AIB_FENCED)
		p->flags |= PHB4_CFG_USE_ASB;

	/* Grab RC bridge control, make it 32-bit */
	phb4_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &__16);
	stat->brdgCtl = cpu_to_be32(__16);

	/*
	 * Grab various RC PCIe capability registers. All device, slot
	 * and link status are 16-bit, so we grab the pair control+status
	 * for each of them
	 */
	phb4_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_DEVCTL, &__32);
	stat->deviceStatus = cpu_to_be32(__32);
	phb4_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_SLOTCTL, &__32);
	stat->slotStatus = cpu_to_be32(__32);
	phb4_pcicfg_read32(&p->phb, 0, p->ecap + PCICAP_EXP_LCTL, &__32);
	stat->linkStatus = cpu_to_be32(__32);

	 /*
	 * I assume those are the standard config space header, cmd & status
	 * together makes 32-bit. Secondary status is 16-bit so I'll clear
	 * the top on that one
	 */
	phb4_pcicfg_read32(&p->phb, 0, PCI_CFG_CMD, &__32);
	stat->devCmdStatus = cpu_to_be32(__32);
	phb4_pcicfg_read16(&p->phb, 0, PCI_CFG_SECONDARY_STATUS, &__16);
	stat->devSecStatus = cpu_to_be32(__16);

	/* Grab a bunch of AER regs */
	phb4_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_RERR_STA, &__32);
	stat->rootErrorStatus = cpu_to_be32(__32);
	phb4_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_UE_STATUS, &__32);
	stat->uncorrErrorStatus = cpu_to_be32(__32);

	phb4_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_CE_STATUS, &__32);
	stat->corrErrorStatus = cpu_to_be32(__32);

	phb4_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG0, &__32);
	stat->tlpHdr1 = cpu_to_be32(__32);

	phb4_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG1, &__32);
	stat->tlpHdr2 = cpu_to_be32(__32);

	phb4_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG2, &__32);
	stat->tlpHdr3 = cpu_to_be32(__32);

	phb4_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_HDR_LOG3, &__32);
	stat->tlpHdr4 = cpu_to_be32(__32);

	phb4_pcicfg_read32(&p->phb, 0, p->aercap + PCIECAP_AER_SRCID, &__32);
	stat->sourceId = cpu_to_be32(__32);


	/* PEC NFIR, same as P8/PHB3 */
	xscom_read(p->chip_id, p->pe_stk_xscom + 0x0, &__64);
	stat->nFir = cpu_to_be64(__64);
	xscom_read(p->chip_id, p->pe_stk_xscom + 0x3, &__64);
	stat->nFirMask = cpu_to_be64(__64);
	xscom_read(p->chip_id, p->pe_stk_xscom + 0x8, &__64);
	stat->nFirWOF = cpu_to_be64(__64);

	/* PHB4 inbound and outbound error Regs */
	stat->phbPlssr = cpu_to_be64(phb4_read_reg_asb(p, PHB_CPU_LOADSTORE_STATUS));
	stat->phbCsr = cpu_to_be64(phb4_read_reg_asb(p, PHB_DMA_CHAN_STATUS));
	stat->lemFir = cpu_to_be64(phb4_read_reg_asb(p, PHB_LEM_FIR_ACCUM));
	stat->lemErrorMask = cpu_to_be64(phb4_read_reg_asb(p, PHB_LEM_ERROR_MASK));
	stat->lemWOF = cpu_to_be64(phb4_read_reg_asb(p, PHB_LEM_WOF));
	stat->phbErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_ERR_STATUS));
	stat->phbFirstErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_ERR1_STATUS));
	stat->phbErrorLog0 = cpu_to_be64(phb4_read_reg_asb(p, PHB_ERR_LOG_0));
	stat->phbErrorLog1 = cpu_to_be64(phb4_read_reg_asb(p, PHB_ERR_LOG_1));
	stat->phbTxeErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_TXE_ERR_STATUS));
	stat->phbTxeFirstErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_TXE_ERR1_STATUS));
	stat->phbTxeErrorLog0 = cpu_to_be64(phb4_read_reg_asb(p, PHB_TXE_ERR_LOG_0));
	stat->phbTxeErrorLog1 = cpu_to_be64(phb4_read_reg_asb(p, PHB_TXE_ERR_LOG_1));
	stat->phbRxeArbErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_RXE_ARB_ERR_STATUS));
	stat->phbRxeArbFirstErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_RXE_ARB_ERR1_STATUS));
	stat->phbRxeArbErrorLog0 = cpu_to_be64(phb4_read_reg_asb(p, PHB_RXE_ARB_ERR_LOG_0));
	stat->phbRxeArbErrorLog1 = cpu_to_be64(phb4_read_reg_asb(p, PHB_RXE_ARB_ERR_LOG_1));
	stat->phbRxeMrgErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_RXE_MRG_ERR_STATUS));
	stat->phbRxeMrgFirstErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_RXE_MRG_ERR1_STATUS));
	stat->phbRxeMrgErrorLog0 = cpu_to_be64(phb4_read_reg_asb(p, PHB_RXE_MRG_ERR_LOG_0));
	stat->phbRxeMrgErrorLog1 = cpu_to_be64(phb4_read_reg_asb(p, PHB_RXE_MRG_ERR_LOG_1));
	stat->phbRxeTceErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_RXE_TCE_ERR_STATUS));
	stat->phbRxeTceFirstErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_RXE_TCE_ERR1_STATUS));
	stat->phbRxeTceErrorLog0 = cpu_to_be64(phb4_read_reg_asb(p, PHB_RXE_TCE_ERR_LOG_0));
	stat->phbRxeTceErrorLog1 = cpu_to_be64(phb4_read_reg_asb(p, PHB_RXE_TCE_ERR_LOG_1));

	/* PHB4 REGB error registers */
	stat->phbPblErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_PBL_ERR_STATUS));
	stat->phbPblFirstErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_PBL_ERR1_STATUS));
	stat->phbPblErrorLog0 = cpu_to_be64(phb4_read_reg_asb(p, PHB_PBL_ERR_LOG_0));
	stat->phbPblErrorLog1 = cpu_to_be64(phb4_read_reg_asb(p, PHB_PBL_ERR_LOG_1));

	stat->phbPcieDlpErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_PCIE_DLP_ERR_STATUS));
	stat->phbPcieDlpErrorLog1 = cpu_to_be64(phb4_read_reg_asb(p, PHB_PCIE_DLP_ERRLOG1));
	stat->phbPcieDlpErrorLog2 = cpu_to_be64(phb4_read_reg_asb(p, PHB_PCIE_DLP_ERRLOG2));

	stat->phbRegbErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_REGB_ERR_STATUS));
	stat->phbRegbFirstErrorStatus = cpu_to_be64(phb4_read_reg_asb(p, PHB_REGB_ERR1_STATUS));
	stat->phbRegbErrorLog0 = cpu_to_be64(phb4_read_reg_asb(p, PHB_REGB_ERR_LOG_0));
	stat->phbRegbErrorLog1 = cpu_to_be64(phb4_read_reg_asb(p, PHB_REGB_ERR_LOG_1));

	/*
	 * Grab PESTA & B content. The error bit (bit#0) should
	 * be fetched from IODA and the left content from memory
	 * resident tables.
	 */
	 phb4_ioda_sel(p, IODA3_TBL_PESTA, 0, true);
	 for (i = 0; i < p->max_num_pes; i++) {
		 stat->pestA[i] = cpu_to_be64(phb4_read_reg_asb(p, PHB_IODA_DATA0));
		 stat->pestA[i] |= p->tbl_pest[2 * i];
	 }

	 phb4_ioda_sel(p, IODA3_TBL_PESTB, 0, true);
	 for (i = 0; i < p->max_num_pes; i++) {
		 stat->pestB[i] = cpu_to_be64(phb4_read_reg_asb(p, PHB_IODA_DATA0));
		 stat->pestB[i] |= p->tbl_pest[2 * i + 1];
	 }
}

static void __unused phb4_dump_peltv(struct phb4 *p)
{
	int stride = p->max_num_pes / 64;
	uint64_t *tbl = (void *) p->tbl_peltv;
	unsigned int pe;

	PHBERR(p, "PELT-V: base addr: %p size: %llx (%d PEs, stride = %d)\n",
			tbl, p->tbl_peltv_size, p->max_num_pes, stride);

	for (pe = 0; pe < p->max_num_pes; pe++) {
		unsigned int i, j;
		uint64_t sum = 0;

		i = pe * stride;

		/*
		 * Only print an entry if there's bits set in the PE's
		 * PELT-V entry. There's a few hundred possible PEs and
		 * generally only a handful will be in use.
		 */

		for (j = 0; j < stride; j++)
			sum |= tbl[i + j];
		if (!sum)
			continue; /* unused PE, skip it */

		if (p->max_num_pes == 512) {
			PHBERR(p, "PELT-V[%03x] = "
				"%016llx %016llx %016llx %016llx"
				"%016llx %016llx %016llx %016llx\n", pe,
				tbl[i + 0], tbl[i + 1], tbl[i + 2], tbl[i + 3],
				tbl[i + 4], tbl[i + 5], tbl[i + 6], tbl[i + 7]);
		} else if (p->max_num_pes == 256) {
			PHBERR(p, "PELT-V[%03x] = "
				"%016llx %016llx %016llx %016llx\n", pe,
				tbl[i + 0], tbl[i + 1], tbl[i + 2], tbl[i + 3]);
		}
	}
}

static void __unused phb4_dump_ioda_table(struct phb4 *p, int table)
{
	const char *name;
	int entries, i;

	switch (table) {
	case IODA3_TBL_LIST:
		name = "LIST";
		entries = 8;
		break;
	case IODA3_TBL_MIST:
		name = "MIST";
		entries = 1024;
		break;
	case IODA3_TBL_RCAM:
		name = "RCAM";
		entries = 128;
		break;
	case IODA3_TBL_MRT:
		name = "MRT";
		entries = 16;
		break;
	case IODA3_TBL_PESTA:
		name = "PESTA";
		entries = 512;
		break;
	case IODA3_TBL_PESTB:
		name = "PESTB";
		entries = 512;
		break;
	case IODA3_TBL_TVT:
		name = "TVT";
		entries = 512;
		break;
	case IODA3_TBL_TCAM:
		name = "TCAM";
		entries = 1024;
		break;
	case IODA3_TBL_TDR:
		name = "TDR";
		entries = 1024;
		break;
	case IODA3_TBL_MBT: /* special case, see below */
		name = "MBT";
		entries = 64;
		break;
	case IODA3_TBL_MDT:
		name = "MDT";
		entries = 512;
		break;
	case IODA3_TBL_PEEV:
		name = "PEEV";
		entries = 8;
		break;
	default:
		PHBERR(p, "Invalid IODA table %d!\n", table);
		return;
	}

	PHBERR(p, "Start %s dump (only non-zero entries are printed):\n", name);

	phb4_ioda_sel(p, table, 0, true);

	/*
	 * Each entry in the MBT is 16 bytes. Every other table has 8 byte
	 * entries so we special case the MDT to keep the output readable.
	 */
	if (table == IODA3_TBL_MBT) {
		for (i = 0; i < 32; i++) {
			uint64_t v1 = phb4_read_reg_asb(p, PHB_IODA_DATA0);
			uint64_t v2 = phb4_read_reg_asb(p, PHB_IODA_DATA0);

			if (!v1 && !v2)
				continue;
			PHBERR(p, "MBT[%03x] = %016llx %016llx\n", i, v1, v2);
		}
	} else {
		for (i = 0; i < entries; i++) {
			uint64_t v = phb4_read_reg_asb(p, PHB_IODA_DATA0);

			if (!v)
				continue;
			PHBERR(p, "%s[%03x] = %016llx\n", name, i, v);
		}
	}

	PHBERR(p, "End %s dump\n", name);
}

static void phb4_eeh_dump_regs(struct phb4 *p)
{
	struct OpalIoPhb4ErrorData *s;
	uint16_t reg;
	unsigned int i;

	if (!verbose_eeh)
		return;

	s = zalloc(sizeof(struct OpalIoPhb4ErrorData));
	if (!s) {
		PHBERR(p, "Failed to allocate error info !\n");
		return;
	}
	phb4_read_phb_status(p, s);

	PHBERR(p, "                 brdgCtl = %08x\n", be32_to_cpu(s->brdgCtl));

	/* PHB4 cfg regs */
	PHBERR(p, "            deviceStatus = %08x\n", be32_to_cpu(s->deviceStatus));
	PHBERR(p, "              slotStatus = %08x\n", be32_to_cpu(s->slotStatus));
	PHBERR(p, "              linkStatus = %08x\n", be32_to_cpu(s->linkStatus));
	PHBERR(p, "            devCmdStatus = %08x\n", be32_to_cpu(s->devCmdStatus));
	PHBERR(p, "            devSecStatus = %08x\n", be32_to_cpu(s->devSecStatus));
	PHBERR(p, "         rootErrorStatus = %08x\n", be32_to_cpu(s->rootErrorStatus));
	PHBERR(p, "         corrErrorStatus = %08x\n", be32_to_cpu(s->corrErrorStatus));
	PHBERR(p, "       uncorrErrorStatus = %08x\n", be32_to_cpu(s->uncorrErrorStatus));

	/* Two non OPAL API registers that are useful */
	phb4_pcicfg_read16(&p->phb, 0, p->ecap + PCICAP_EXP_DEVCTL, &reg);
	PHBERR(p, "                  devctl = %08x\n", reg);
	phb4_pcicfg_read16(&p->phb, 0, p->ecap + PCICAP_EXP_DEVSTAT,
			   &reg);
	PHBERR(p, "                 devStat = %08x\n", reg);

	/* Byte swap TLP headers so they are the same as the PCIe spec */
	PHBERR(p, "                 tlpHdr1 = %08x\n", cpu_to_le32(be32_to_cpu(s->tlpHdr1)));
	PHBERR(p, "                 tlpHdr2 = %08x\n", cpu_to_le32(be32_to_cpu(s->tlpHdr2)));
	PHBERR(p, "                 tlpHdr3 = %08x\n", cpu_to_le32(be32_to_cpu(s->tlpHdr3)));
	PHBERR(p, "                 tlpHdr4 = %08x\n", cpu_to_le32(be32_to_cpu(s->tlpHdr4)));
	PHBERR(p, "                sourceId = %08x\n", be32_to_cpu(s->sourceId));
	PHBERR(p, "                    nFir = %016llx\n", be64_to_cpu(s->nFir));
	PHBERR(p, "                nFirMask = %016llx\n", be64_to_cpu(s->nFirMask));
	PHBERR(p, "                 nFirWOF = %016llx\n", be64_to_cpu(s->nFirWOF));
	PHBERR(p, "                phbPlssr = %016llx\n", be64_to_cpu(s->phbPlssr));
	PHBERR(p, "                  phbCsr = %016llx\n", be64_to_cpu(s->phbCsr));
	PHBERR(p, "                  lemFir = %016llx\n", be64_to_cpu(s->lemFir));
	PHBERR(p, "            lemErrorMask = %016llx\n", be64_to_cpu(s->lemErrorMask));
	PHBERR(p, "                  lemWOF = %016llx\n", be64_to_cpu(s->lemWOF));
	PHBERR(p, "          phbErrorStatus = %016llx\n", be64_to_cpu(s->phbErrorStatus));
	PHBERR(p, "     phbFirstErrorStatus = %016llx\n", be64_to_cpu(s->phbFirstErrorStatus));
	PHBERR(p, "            phbErrorLog0 = %016llx\n", be64_to_cpu(s->phbErrorLog0));
	PHBERR(p, "            phbErrorLog1 = %016llx\n", be64_to_cpu(s->phbErrorLog1));
	PHBERR(p, "       phbTxeErrorStatus = %016llx\n", be64_to_cpu(s->phbTxeErrorStatus));
	PHBERR(p, "  phbTxeFirstErrorStatus = %016llx\n", be64_to_cpu(s->phbTxeFirstErrorStatus));
	PHBERR(p, "         phbTxeErrorLog0 = %016llx\n", be64_to_cpu(s->phbTxeErrorLog0));
	PHBERR(p, "         phbTxeErrorLog1 = %016llx\n", be64_to_cpu(s->phbTxeErrorLog1));
	PHBERR(p, "    phbRxeArbErrorStatus = %016llx\n", be64_to_cpu(s->phbRxeArbErrorStatus));
	PHBERR(p, "phbRxeArbFrstErrorStatus = %016llx\n", be64_to_cpu(s->phbRxeArbFirstErrorStatus));
	PHBERR(p, "      phbRxeArbErrorLog0 = %016llx\n", be64_to_cpu(s->phbRxeArbErrorLog0));
	PHBERR(p, "      phbRxeArbErrorLog1 = %016llx\n", be64_to_cpu(s->phbRxeArbErrorLog1));
	PHBERR(p, "    phbRxeMrgErrorStatus = %016llx\n", be64_to_cpu(s->phbRxeMrgErrorStatus));
	PHBERR(p, "phbRxeMrgFrstErrorStatus = %016llx\n", be64_to_cpu(s->phbRxeMrgFirstErrorStatus));
	PHBERR(p, "      phbRxeMrgErrorLog0 = %016llx\n", be64_to_cpu(s->phbRxeMrgErrorLog0));
	PHBERR(p, "      phbRxeMrgErrorLog1 = %016llx\n", be64_to_cpu(s->phbRxeMrgErrorLog1));
	PHBERR(p, "    phbRxeTceErrorStatus = %016llx\n", be64_to_cpu(s->phbRxeTceErrorStatus));
	PHBERR(p, "phbRxeTceFrstErrorStatus = %016llx\n", be64_to_cpu(s->phbRxeTceFirstErrorStatus));
	PHBERR(p, "      phbRxeTceErrorLog0 = %016llx\n", be64_to_cpu(s->phbRxeTceErrorLog0));
	PHBERR(p, "      phbRxeTceErrorLog1 = %016llx\n", be64_to_cpu(s->phbRxeTceErrorLog1));
	PHBERR(p, "       phbPblErrorStatus = %016llx\n", be64_to_cpu(s->phbPblErrorStatus));
	PHBERR(p, "  phbPblFirstErrorStatus = %016llx\n", be64_to_cpu(s->phbPblFirstErrorStatus));
	PHBERR(p, "         phbPblErrorLog0 = %016llx\n", be64_to_cpu(s->phbPblErrorLog0));
	PHBERR(p, "         phbPblErrorLog1 = %016llx\n", be64_to_cpu(s->phbPblErrorLog1));
	PHBERR(p, "     phbPcieDlpErrorLog1 = %016llx\n", be64_to_cpu(s->phbPcieDlpErrorLog1));
	PHBERR(p, "     phbPcieDlpErrorLog2 = %016llx\n", be64_to_cpu(s->phbPcieDlpErrorLog2));
	PHBERR(p, "   phbPcieDlpErrorStatus = %016llx\n", be64_to_cpu(s->phbPcieDlpErrorStatus));

	PHBERR(p, "      phbRegbErrorStatus = %016llx\n", be64_to_cpu(s->phbRegbErrorStatus));
	PHBERR(p, " phbRegbFirstErrorStatus = %016llx\n", be64_to_cpu(s->phbRegbFirstErrorStatus));
	PHBERR(p, "        phbRegbErrorLog0 = %016llx\n", be64_to_cpu(s->phbRegbErrorLog0));
	PHBERR(p, "        phbRegbErrorLog1 = %016llx\n", be64_to_cpu(s->phbRegbErrorLog1));

	for (i = 0; i < p->max_num_pes; i++) {
		if (!s->pestA[i] && !s->pestB[i])
			continue;
		PHBERR(p, "               PEST[%03x] = %016llx %016llx\n",
		       i, be64_to_cpu(s->pestA[i]), be64_to_cpu(s->pestB[i]));
	}
	free(s);
}

static int64_t phb4_set_pe(struct phb *phb,
			   uint64_t pe_number,
			   uint64_t bdfn,
			   uint8_t bcompare,
			   uint8_t dcompare,
			   uint8_t fcompare,
			   uint8_t action)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t mask, idx;

	/* Sanity check */
	if (action != OPAL_MAP_PE && action != OPAL_UNMAP_PE)
		return OPAL_PARAMETER;
	if (pe_number >= p->num_pes || bdfn > 0xffff ||
	    bcompare > OpalPciBusAll ||
	    dcompare > OPAL_COMPARE_RID_DEVICE_NUMBER ||
	    fcompare > OPAL_COMPARE_RID_FUNCTION_NUMBER)
		return OPAL_PARAMETER;

	/* match everything by default */
	mask = 0;

	/* Figure out the RID range */
	if (bcompare != OpalPciBusAny)
		mask  = ((0x1 << (bcompare + 1)) - 1) << (15 - bcompare);

	if (dcompare == OPAL_COMPARE_RID_DEVICE_NUMBER)
		mask |= 0xf8;

	if (fcompare == OPAL_COMPARE_RID_FUNCTION_NUMBER)
		mask |= 0x7;

	if (action == OPAL_UNMAP_PE)
		pe_number = PHB4_RESERVED_PE_NUM(p);

	/* Map or unmap the RTT range */
	for (idx = 0; idx < RTT_TABLE_ENTRIES; idx++)
		if ((idx & mask) == (bdfn & mask))
			p->tbl_rtt[idx] = cpu_to_be16(pe_number);

	/* Invalidate the RID Translation Cache (RTC) inside the PHB */
	out_be64(p->regs + PHB_RTC_INVALIDATE, PHB_RTC_INVALIDATE_ALL);

	return OPAL_SUCCESS;
}

static int64_t phb4_set_peltv(struct phb *phb,
			      uint32_t parent_pe,
			      uint32_t child_pe,
			      uint8_t state)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint32_t idx, mask;

	/* Sanity check */
	if (parent_pe >= p->num_pes || child_pe >= p->num_pes)
		return OPAL_PARAMETER;

	/* Find index for parent PE */
	idx = parent_pe * (p->max_num_pes / 8);
	idx += (child_pe / 8);
	mask = 0x1 << (7 - (child_pe % 8));

	if (state)
		p->tbl_peltv[idx] |= mask;
	else
		p->tbl_peltv[idx] &= ~mask;

	return OPAL_SUCCESS;
}

static void phb4_prepare_link_change(struct pci_slot *slot, bool is_up)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	uint32_t reg32;

	p->has_link = is_up;

	if (is_up) {
		/* Clear AER receiver error status */
		phb4_pcicfg_write32(&p->phb, 0, p->aercap +
				    PCIECAP_AER_CE_STATUS,
				    PCIECAP_AER_CE_RECVR_ERR);
		/* Unmask receiver error status in AER */
		phb4_pcicfg_read32(&p->phb, 0, p->aercap +
				   PCIECAP_AER_CE_MASK, &reg32);
		reg32 &= ~PCIECAP_AER_CE_RECVR_ERR;
		phb4_pcicfg_write32(&p->phb, 0, p->aercap +
				    PCIECAP_AER_CE_MASK, reg32);

		/* Don't block PCI-CFG */
		p->flags &= ~PHB4_CFG_BLOCKED;

		/* Re-enable link down errors */
		out_be64(p->regs + PHB_PCIE_MISC_STRAP,
			 0x0000060000000000ull);

		/* Re-enable error status indicators that trigger irqs */
		out_be64(p->regs + PHB_REGB_ERR_INF_ENABLE,
			 0x2130006efca8bc00ull);
		out_be64(p->regs + PHB_REGB_ERR_ERC_ENABLE,
			 0x0080000000000000ull);
		out_be64(p->regs + PHB_REGB_ERR_FAT_ENABLE,
			 0xde0fff91035743ffull);

	} else {
		/* Mask AER receiver error */
		phb4_pcicfg_read32(&p->phb, 0, p->aercap +
				   PCIECAP_AER_CE_MASK, &reg32);
		reg32 |= PCIECAP_AER_CE_RECVR_ERR;
		phb4_pcicfg_write32(&p->phb, 0, p->aercap +
				    PCIECAP_AER_CE_MASK, reg32);

		/* Clear error link enable & error link down kill enable */
		out_be64(p->regs + PHB_PCIE_MISC_STRAP, 0);

		/* Disable all error status indicators that trigger irqs */
		out_be64(p->regs + PHB_REGB_ERR_INF_ENABLE, 0);
		out_be64(p->regs + PHB_REGB_ERR_ERC_ENABLE, 0);
		out_be64(p->regs + PHB_REGB_ERR_FAT_ENABLE, 0);

		/* Block PCI-CFG access */
		p->flags |= PHB4_CFG_BLOCKED;
	}
}

static int64_t phb4_get_presence_state(struct pci_slot *slot, uint8_t *val)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	uint64_t hps, dtctl;

	/* Test for PHB in error state ? */
	if (p->broken)
		return OPAL_HARDWARE;

	/* Check hotplug status */
	hps = in_be64(p->regs + PHB_PCIE_HOTPLUG_STATUS);
	if (!(hps & PHB_PCIE_HPSTAT_PRESENCE)) {
		*val = OPAL_PCI_SLOT_PRESENT;
	} else {
		/*
		 * If it says not present but link is up, then we assume
		 * we are on a broken simulation environment and still
		 * return a valid presence. Otherwise, not present.
		 */
		dtctl = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (dtctl & PHB_PCIE_DLP_TL_LINKACT) {
			PHBERR(p, "Presence detect 0 but link set !\n");
			*val = OPAL_PCI_SLOT_PRESENT;
		} else {
			*val = OPAL_PCI_SLOT_EMPTY;
		}
	}

	return OPAL_SUCCESS;
}

static int64_t phb4_get_link_info(struct pci_slot *slot, uint8_t *speed,
				   uint8_t *width)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	uint64_t reg;
	uint16_t state;
	int64_t rc;
	uint8_t s;

	/* Link is up, let's find the actual speed */
	reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
	if (!(reg & PHB_PCIE_DLP_TL_LINKACT)) {
		*width = 0;
		if (speed)
			*speed = 0;
		return OPAL_SUCCESS;
	}

	rc = phb4_pcicfg_read16(&p->phb, 0,
				p->ecap + PCICAP_EXP_LSTAT, &state);
	if (rc != OPAL_SUCCESS) {
		PHBERR(p, "%s: Error %lld getting link state\n", __func__, rc);
		return OPAL_HARDWARE;
	}

	if (state & PCICAP_EXP_LSTAT_DLLL_ACT) {
		*width = ((state & PCICAP_EXP_LSTAT_WIDTH) >> 4);
		s =  state & PCICAP_EXP_LSTAT_SPEED;
	} else {
		*width = 0;
		s = 0;
	}

	if (speed)
		*speed = s;

	return OPAL_SUCCESS;
}

static int64_t phb4_get_link_state(struct pci_slot *slot, uint8_t *val)
{
	return phb4_get_link_info(slot, NULL, val);
}

static int64_t phb4_retry_state(struct pci_slot *slot)
{
	struct phb4 *p = phb_to_phb4(slot->phb);

	/* Mark link as down */
	phb4_prepare_link_change(slot, false);

	/* Last attempt to activate link */
	if (slot->link_retries == 1) {
		if (slot->state == PHB4_SLOT_LINK_WAIT) {
			PHBERR(p, "Falling back to GEN1 training\n");
			p->max_link_speed = 1;
		}
	}

	if (!slot->link_retries--) {
		switch (slot->state) {
		case PHB4_SLOT_LINK_WAIT_ELECTRICAL:
			PHBERR(p, "Presence detected but no electrical link\n");
			break;
		case PHB4_SLOT_LINK_WAIT:
			PHBERR(p, "Electrical link detected but won't train\n");
			break;
		case PHB4_SLOT_LINK_STABLE:
			PHBERR(p, "Linked trained but was degraded or unstable\n");
			break;
		default:
			PHBERR(p, "Unknown link issue\n");
		}
		return OPAL_HARDWARE;
	}

	pci_slot_set_state(slot, PHB4_SLOT_CRESET_START);
	return pci_slot_set_sm_timeout(slot, msecs_to_tb(1));
}

static uint64_t phb4_train_info(struct phb4 *p, uint64_t reg, unsigned long dt)
{
	uint64_t ltssm_state = GETFIELD(PHB_PCIE_DLP_LTSSM_TRC, reg);
	char s[80];

	snprintf(s, sizeof(s), "TRACE:0x%016llx % 2lims",
		 reg, tb_to_msecs(dt));

	if (reg & PHB_PCIE_DLP_TL_LINKACT)
		snprintf(s, sizeof(s), "%s trained ", s);
	else if (reg & PHB_PCIE_DLP_TRAINING)
		snprintf(s, sizeof(s), "%s training", s);
	else if (reg & PHB_PCIE_DLP_INBAND_PRESENCE)
		snprintf(s, sizeof(s), "%s presence", s);
	else
		snprintf(s, sizeof(s), "%s         ", s);

	snprintf(s, sizeof(s), "%s GEN%lli:x%02lli:", s,
		 GETFIELD(PHB_PCIE_DLP_LINK_SPEED, reg),
		 GETFIELD(PHB_PCIE_DLP_LINK_WIDTH, reg));

	switch (ltssm_state) {
	case PHB_PCIE_DLP_LTSSM_RESET:
		snprintf(s, sizeof(s), "%sreset", s);
		break;
	case PHB_PCIE_DLP_LTSSM_DETECT:
		snprintf(s, sizeof(s), "%sdetect", s);
		break;
	case PHB_PCIE_DLP_LTSSM_POLLING:
		snprintf(s, sizeof(s), "%spolling", s);
		break;
	case PHB_PCIE_DLP_LTSSM_CONFIG:
		snprintf(s, sizeof(s), "%sconfig", s);
		break;
	case PHB_PCIE_DLP_LTSSM_L0:
		snprintf(s, sizeof(s), "%sL0", s);
		break;
	case PHB_PCIE_DLP_LTSSM_REC:
		snprintf(s, sizeof(s), "%srecovery", s);
		break;
	case PHB_PCIE_DLP_LTSSM_L1:
		snprintf(s, sizeof(s), "%sL1", s);
		break;
	case PHB_PCIE_DLP_LTSSM_L2:
		snprintf(s, sizeof(s), "%sL2", s);
		break;
	case PHB_PCIE_DLP_LTSSM_HOTRESET:
		snprintf(s, sizeof(s), "%shotreset", s);
		break;
	case PHB_PCIE_DLP_LTSSM_DISABLED:
		snprintf(s, sizeof(s), "%sdisabled", s);
		break;
	case PHB_PCIE_DLP_LTSSM_LOOPBACK:
		snprintf(s, sizeof(s), "%sloopback", s);
		break;
	default:
		snprintf(s, sizeof(s), "%sunvalid", s);
	}
	PHBNOTICE(p, "%s\n", s);

	return ltssm_state;
}

static void phb4_dump_pec_err_regs(struct phb4 *p)
{
	uint64_t nfir_p_wof, nfir_n_wof, err_aib;
	uint64_t err_rpt0, err_rpt1;

	/* Read the PCI and NEST FIRs and dump them. Also cache PCI/NEST FIRs */
	xscom_read(p->chip_id,
		   p->pci_stk_xscom + XPEC_PCI_STK_PCI_FIR,  &p->pfir_cache);
	xscom_read(p->chip_id,
		   p->pci_stk_xscom + XPEC_PCI_STK_PCI_FIR_WOF, &nfir_p_wof);
	xscom_read(p->chip_id,
		   p->pe_stk_xscom + XPEC_NEST_STK_PCI_NFIR, &p->nfir_cache);
	xscom_read(p->chip_id,
		   p->pe_stk_xscom + XPEC_NEST_STK_PCI_NFIR_WOF, &nfir_n_wof);
	xscom_read(p->chip_id,
		   p->pe_stk_xscom + XPEC_NEST_STK_ERR_RPT0, &err_rpt0);
	xscom_read(p->chip_id,
		   p->pe_stk_xscom + XPEC_NEST_STK_ERR_RPT1, &err_rpt1);
	xscom_read(p->chip_id,
		   p->pci_stk_xscom + XPEC_PCI_STK_PBAIB_ERR_REPORT, &err_aib);

	PHBERR(p, "            PCI FIR=%016llx\n", p->pfir_cache);
	PHBERR(p, "        PCI FIR WOF=%016llx\n", nfir_p_wof);
	PHBERR(p, "           NEST FIR=%016llx\n", p->nfir_cache);
	PHBERR(p, "       NEST FIR WOF=%016llx\n", nfir_n_wof);
	PHBERR(p, "           ERR RPT0=%016llx\n", err_rpt0);
	PHBERR(p, "           ERR RPT1=%016llx\n", err_rpt1);
	PHBERR(p, "            AIB ERR=%016llx\n", err_aib);
}

static void phb4_dump_capp_err_regs(struct phb4 *p)
{
	uint64_t fir, apc_master_err, snoop_err, transport_err;
	uint64_t tlbi_err, capp_err_status;
	uint64_t offset = PHB4_CAPP_REG_OFFSET(p);

	xscom_read(p->chip_id, CAPP_FIR + offset, &fir);
	xscom_read(p->chip_id, CAPP_APC_MASTER_ERR_RPT + offset,
		   &apc_master_err);
	xscom_read(p->chip_id, CAPP_SNOOP_ERR_RTP + offset, &snoop_err);
	xscom_read(p->chip_id, CAPP_TRANSPORT_ERR_RPT + offset, &transport_err);
	xscom_read(p->chip_id, CAPP_TLBI_ERR_RPT + offset, &tlbi_err);
	xscom_read(p->chip_id, CAPP_ERR_STATUS_CTRL + offset, &capp_err_status);

	PHBERR(p, "           CAPP FIR=%016llx\n", fir);
	PHBERR(p, "CAPP APC MASTER ERR=%016llx\n", apc_master_err);
	PHBERR(p, "     CAPP SNOOP ERR=%016llx\n", snoop_err);
	PHBERR(p, " CAPP TRANSPORT ERR=%016llx\n", transport_err);
	PHBERR(p, "      CAPP TLBI ERR=%016llx\n", tlbi_err);
	PHBERR(p, "    CAPP ERR STATUS=%016llx\n", capp_err_status);
}

/* Check if AIB is fenced via PBCQ NFIR */
static bool phb4_fenced(struct phb4 *p)
{

	/* Already fenced ? */
	if (p->flags & PHB4_AIB_FENCED)
		return true;

	/*
	 * An all 1's from the PHB indicates a PHB freeze/fence. We
	 * don't really differenciate them at this point.
	 */
	if (in_be64(p->regs + PHB_CPU_LOADSTORE_STATUS)!= 0xfffffffffffffffful)
		return false;

	/* Mark ourselves fenced */
	p->flags |= PHB4_AIB_FENCED;

	PHBERR(p, "PHB Freeze/Fence detected !\n");
	phb4_dump_pec_err_regs(p);

	/*
	 * dump capp error registers in case phb was fenced due to capp.
	 * Expect p->nfir_cache already updated in phb4_dump_pec_err_regs()
	 */
	if (p->nfir_cache & XPEC_NEST_STK_PCI_NFIR_CXA_PE_CAPP)
		phb4_dump_capp_err_regs(p);

	phb4_eeh_dump_regs(p);

	return true;
}

static bool phb4_check_reg(struct phb4 *p, uint64_t reg)
{
	if (reg == 0xffffffffffffffffUL)
		return !phb4_fenced(p);
	return true;
}

static void phb4_get_info(struct phb *phb, uint16_t bdfn, uint8_t *speed,
			  uint8_t *width)
{
	int32_t ecap;
	uint32_t cap;

	ecap = pci_find_cap(phb, bdfn, PCI_CFG_CAP_ID_EXP);
	pci_cfg_read32(phb, bdfn, ecap + PCICAP_EXP_LCAP, &cap);
	*width = (cap & PCICAP_EXP_LCAP_MAXWDTH) >> 4;
	*speed = cap & PCICAP_EXP_LCAP_MAXSPD;
}

#define PVR_POWER9_CUMULUS		0x00002000

static bool phb4_chip_retry_workaround(void)
{
	unsigned int pvr;

	if (pci_retry_all)
		return true;

	/* Chips that need this retry are:
	 *  - CUMULUS DD1.0
	 *  - NIMBUS DD2.0 (and DD1.0, but it is unsupported so no check).
	 */
	pvr = mfspr(SPR_PVR);
	if (pvr & PVR_POWER9_CUMULUS) {
		if ((PVR_VERS_MAJ(pvr) == 1) && (PVR_VERS_MIN(pvr) == 0))
			return true;
	} else { /* NIMBUS */
		if ((PVR_VERS_MAJ(pvr) == 2) && (PVR_VERS_MIN(pvr) == 0))
			return true;
	}
	return false;
}

struct pci_card_id {
	uint16_t vendor;
	uint16_t device;
};

static struct pci_card_id retry_allowlist[] = {
	{ 0x1000, 0x005d }, /* LSI Logic MegaRAID SAS-3 3108 */
	{ 0x1000, 0x00c9 }, /* LSI MPT SAS-3 */
	{ 0x104c, 0x8241 }, /* TI xHCI USB */
	{ 0x1077, 0x2261 }, /* QLogic ISP2722-based 16/32Gb FC */
	{ 0x10b5, 0x8725 }, /* PLX Switch: p9dsu, witherspoon */
	{ 0x10b5, 0x8748 }, /* PLX Switch: ZZ */
	{ 0x11f8, 0xf117 }, /* PMC-Sierra/MicroSemi NV1604 */
	{ 0x15b3, 0x1013 }, /* Mellanox ConnectX-4 */
	{ 0x15b3, 0x1017 }, /* Mellanox ConnectX-5 */
	{ 0x15b3, 0x1019 }, /* Mellanox ConnectX-5 Ex */
	{ 0x1a03, 0x1150 }, /* ASPEED AST2500 Switch */
	{ 0x8086, 0x10fb }, /* Intel x520 10G Eth */
	{ 0x9005, 0x028d }, /* MicroSemi PM8069 */
};

#define VENDOR(vdid) ((vdid) & 0xffff)
#define DEVICE(vdid) (((vdid) >> 16) & 0xffff)

static bool phb4_adapter_in_allowlist(uint32_t vdid)
{
	int i;

	if (pci_retry_all)
		return true;

	for (i = 0; i < ARRAY_SIZE(retry_allowlist); i++)
		if ((retry_allowlist[i].vendor == VENDOR(vdid)) &&
		    (retry_allowlist[i].device == DEVICE(vdid)))
			return true;

	return false;
}

static struct pci_card_id lane_eq_disable[] = {
	{ 0x10de, 0x17fd }, /* Nvidia GM200GL [Tesla M40] */
	{ 0x10de, 0x1db4 }, /* Nvidia GV100 */
};

static bool phb4_lane_eq_retry_allowlist(uint32_t vdid)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(lane_eq_disable); i++)
		if ((lane_eq_disable[i].vendor == VENDOR(vdid)) &&
		    (lane_eq_disable[i].device == DEVICE(vdid)))
			return true;
	return false;
}

static void phb4_lane_eq_change(struct phb4 *p, uint32_t vdid)
{
	p->lane_eq_en = !phb4_lane_eq_retry_allowlist(vdid);
}

static bool phb4_link_optimal(struct pci_slot *slot, uint32_t *vdid)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	uint64_t reg;
	uint32_t id;
	uint16_t bdfn, lane_errs;
	uint8_t trained_speed, dev_speed, target_speed, rx_errs;
	uint8_t trained_width, dev_width, target_width;
	bool optimal_speed, optimal_width, optimal, retry_enabled, rx_err_ok;


	/* Current trained state */
	phb4_get_link_info(slot, &trained_speed, &trained_width);

	/* Get device capability */
	bdfn = 0x0100; /* bus=1 dev=0 device=0 */
	/* Since this is the first access, we need to wait for CRS */
	if (!pci_wait_crs(slot->phb, bdfn , &id))
		return true;
	phb4_get_info(slot->phb, bdfn, &dev_speed, &dev_width);

	/* Work out if we are optimally trained */
	target_speed = MIN(p->max_link_speed, dev_speed);
	optimal_speed = (trained_speed >= target_speed);
	target_width = MIN(p->max_link_width, dev_width);
	optimal_width = (trained_width >= target_width);
	optimal = optimal_width && optimal_speed;
	retry_enabled = (phb4_chip_retry_workaround() &&
			 phb4_adapter_in_allowlist(id)) ||
		phb4_lane_eq_retry_allowlist(id);
	reg = in_be64(p->regs + PHB_PCIE_DLP_ERR_COUNTERS);
	rx_errs =  GETFIELD(PHB_PCIE_DLP_RX_ERR_CNT, reg);
	rx_err_ok = (rx_errs < rx_err_max);
	reg = in_be64(p->regs + PHB_PCIE_DLP_ERR_STATUS);
	lane_errs = GETFIELD(PHB_PCIE_DLP_LANE_ERR, reg);

	PHBDBG(p, "LINK: Card [%04x:%04x] %s Retry:%s\n", VENDOR(id),
	       DEVICE(id), optimal ? "Optimal" : "Degraded",
	       retry_enabled ? "enabled" : "disabled");
	PHBDBG(p, "LINK: Speed Train:GEN%i PHB:GEN%i DEV:GEN%i%s\n",
	       trained_speed, p->max_link_speed, dev_speed,
	       optimal_speed ? "" : " *");
	PHBDBG(p, "LINK: Width Train:x%02i PHB:x%02i DEV:x%02i%s\n",
	       trained_width, p->max_link_width, dev_width,
	       optimal_width ? "" : " *");
	PHBDBG(p, "LINK: RX Errors Now:%i Max:%i Lane:0x%04x%s\n",
	       rx_errs, rx_err_max, lane_errs, rx_err_ok ? "" : " *");

	if (vdid)
		*vdid = id;

	/* Always do RX error retry irrespective of chip and card */
	if (!rx_err_ok)
		return false;

	if (!retry_enabled)
		return true;

	return optimal;
}

/*
 * This is a trace function to watch what's happening duing pcie link
 * training.  If any errors are detected it simply returns so the
 * normal code can deal with it.
 */
static void phb4_link_trace(struct phb4 *p, uint64_t target_state, int max_ms)
{
	unsigned long now, end, start = mftb(), state = 0;
	uint64_t trwctl, reg, reglast = -1;
	bool enabled;

	/*
	 * Enable the DLP trace outputs. If we don't the LTSSM state in
	 * PHB_PCIE_DLP_TRAIN_CTL won't be updated and always reads zero.
	 */
	trwctl = phb4_read_reg(p, PHB_PCIE_DLP_TRWCTL);
	enabled = !!(trwctl & PHB_PCIE_DLP_TRWCTL_EN);
	if (!enabled) {
		phb4_write_reg(p, PHB_PCIE_DLP_TRWCTL,
				trwctl | PHB_PCIE_DLP_TRWCTL_EN);
	}

	end = start + msecs_to_tb(max_ms);
	now = start;

	do {
		reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (reg != reglast)
			state = phb4_train_info(p, reg, now - start);
		reglast = reg;

		if (!phb4_check_reg(p, reg)) {
			PHBNOTICE(p, "TRACE: PHB fenced.\n");
			goto out;
		}

		if (tb_compare(now, end) == TB_AAFTERB) {
			PHBNOTICE(p, "TRACE: Timed out after %dms\n", max_ms);
			goto out;
		}

		now = mftb();
	} while (state != target_state);

	PHBNOTICE(p, "TRACE: Reached target state\n");

out:
	/*
	 * The trace enable bit is a clock gate for the tracing logic. Turn
	 * it off to save power if we're not using it otherwise.
	 */
	if (!enabled)
		phb4_write_reg(p, PHB_PCIE_DLP_TRWCTL, trwctl);
}

/*
 * This helper is called repeatedly by the host sync notifier mechanism, which
 * relies on the kernel to regularly poll the OPAL_SYNC_HOST_REBOOT call as it
 * shuts down.
 */
static bool phb4_host_sync_reset(void *data)
{
	struct phb4 *p = (struct phb4 *)data;
	struct phb *phb = &p->phb;
	int64_t rc = 0;

	/* Make sure no-one modifies the phb flags while we are active */
	phb_lock(phb);

	/* Make sure CAPP is attached to the PHB */
	if (p->capp)
		/* Call phb ops to disable capi */
		rc = phb->ops->set_capi_mode(phb, OPAL_PHB_CAPI_MODE_PCIE,
				       p->capp->attached_pe);
	else
		rc = OPAL_SUCCESS;

	/* Continue kicking state-machine if in middle of a mode transition */
	if (rc == OPAL_BUSY)
		rc = phb->slot->ops.run_sm(phb->slot);

	phb_unlock(phb);

	return rc <= OPAL_SUCCESS;
}

/*
 * Notification from the pci-core that a pci slot state machine completed.
 * We use this callback to mark the CAPP disabled if we were waiting for it.
 */
static int64_t phb4_slot_sm_run_completed(struct pci_slot *slot, uint64_t err)
{
	struct phb4 *p = phb_to_phb4(slot->phb);

	/* Check if we are disabling the capp */
	if (p->flags & PHB4_CAPP_DISABLE) {

		/* Unset struct capp so that we dont fall into a creset loop */
		p->flags &= ~(PHB4_CAPP_DISABLE);
		p->capp->phb = NULL;
		p->capp->attached_pe = phb4_get_reserved_pe_number(&p->phb);

		/* Remove the host sync notifier is we are done.*/
		opal_del_host_sync_notifier(phb4_host_sync_reset, p);
		if (err) {
			/* Force a CEC ipl reboot */
			disable_fast_reboot("CAPP: reset failed");
			PHBERR(p, "CAPP: Unable to reset. Error=%lld\n", err);
		} else {
			PHBINF(p, "CAPP: reset complete\n");
		}
	}

	return OPAL_SUCCESS;
}

static int64_t phb4_poll_link(struct pci_slot *slot)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	uint64_t reg;
	uint32_t vdid;

	switch (slot->state) {
	case PHB4_SLOT_NORMAL:
	case PHB4_SLOT_LINK_START:
		PHBDBG(p, "LINK: Start polling\n");
		slot->retries = PHB4_LINK_ELECTRICAL_RETRIES;
		pci_slot_set_state(slot, PHB4_SLOT_LINK_WAIT_ELECTRICAL);
		/* Polling early here has no chance of a false positive */
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(1));
	case PHB4_SLOT_LINK_WAIT_ELECTRICAL:
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
		if (!phb4_check_reg(p, reg)) {
			PHBERR(p, "PHB fence waiting for electrical link\n");
			return phb4_retry_state(slot);
		}

		if (reg & (PHB_PCIE_DLP_INBAND_PRESENCE |
			   PHB_PCIE_DLP_TL_LINKACT)) {
			PHBDBG(p, "LINK: Electrical link detected\n");
			pci_slot_set_state(slot, PHB4_SLOT_LINK_WAIT);
			slot->retries = PHB4_LINK_WAIT_RETRIES;
			/* No wait here since already have an elec link */
			return pci_slot_set_sm_timeout(slot, msecs_to_tb(1));
		}

		if (slot->retries-- == 0) {
			PHBDBG(p, "LINK: No in-band presence\n");
			return OPAL_SUCCESS;
		}
		/* Retry */
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(10));
	case PHB4_SLOT_LINK_WAIT:
		reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (!phb4_check_reg(p, reg)) {
			PHBERR(p, "LINK: PHB fence waiting for link training\n");
			return phb4_retry_state(slot);
		}
		if (reg & PHB_PCIE_DLP_TL_LINKACT) {
			PHBDBG(p, "LINK: Link is up\n");
			phb4_prepare_link_change(slot, true);
			pci_slot_set_state(slot, PHB4_SLOT_LINK_STABLE);
			return pci_slot_set_sm_timeout(slot, secs_to_tb(1));
		}

		if (slot->retries-- == 0) {
			PHBERR(p, "LINK: Timeout waiting for link up\n");
			PHBDBG(p, "LINK: DLP train control: 0x%016llx\n", reg);
			return phb4_retry_state(slot);
		}
		/* Retry */
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(10));
	case PHB4_SLOT_LINK_STABLE:
		/* Sanity check link */
		if (phb4_fenced(p)) {
			PHBERR(p, "LINK: PHB fenced waiting for stabilty\n");
			return phb4_retry_state(slot);
		}
		reg = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (!phb4_check_reg(p, reg)) {
			PHBERR(p, "LINK: PHB fence reading training control\n");
			return phb4_retry_state(slot);
		}
		if (reg & PHB_PCIE_DLP_TL_LINKACT) {
			PHBDBG(p, "LINK: Link is stable\n");
			if (!phb4_link_optimal(slot, &vdid)) {
				PHBDBG(p, "LINK: Link degraded\n");
				if (slot->link_retries) {
					phb4_lane_eq_change(p, vdid);
					return phb4_retry_state(slot);
				}
				/*
				 * Link is degraded but no more retries, so
				 * settle for what we have :-(
				 */
				PHBERR(p, "LINK: Degraded but no more retries\n");
			}
			pci_restore_slot_bus_configs(slot);
			pci_slot_set_state(slot, PHB4_SLOT_NORMAL);
			return OPAL_SUCCESS;
		}
		PHBERR(p, "LINK: Went down waiting for stabilty\n");
		PHBDBG(p, "LINK: DLP train control: 0x%016llx\n", reg);
		return phb4_retry_state(slot);
	default:
		PHBERR(p, "LINK: Unexpected slot state %08x\n",
		       slot->state);
	}

	pci_slot_set_state(slot, PHB4_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static unsigned int phb4_get_max_link_speed(struct phb4 *p, struct dt_node *np)
{
	unsigned int max_link_speed, hw_max_link_speed;
	struct proc_chip *chip;
	chip = get_chip(p->chip_id);

	hw_max_link_speed = 4;
	if (is_phb5() && (p->index == 0 || p->index == 3))
		hw_max_link_speed = 5;

	/* Priority order: NVRAM -> dt -> GEN3 dd2.00 -> hw default */
	max_link_speed = hw_max_link_speed;
	if (p->rev == PHB4_REV_NIMBUS_DD20 &&
	    ((0xf & chip->ec_level) == 0) && chip->ec_rev == 0)
		max_link_speed = 3;
	if (np) {
		if (dt_has_node_property(np, "ibm,max-link-speed", NULL)) {
			max_link_speed = dt_prop_get_u32(np, "ibm,max-link-speed");
			p->dt_max_link_speed = max_link_speed;
		}
		else {
			p->dt_max_link_speed = 0;
		}
	}
	else {
		if (p->dt_max_link_speed > 0) {
			max_link_speed = p->dt_max_link_speed;
		}
	}
	if (pcie_max_link_speed)
		max_link_speed = pcie_max_link_speed;
	if (max_link_speed > hw_max_link_speed)
		max_link_speed = hw_max_link_speed;

	return max_link_speed;
}

static unsigned int __phb4_get_max_link_width(struct phb4 *p)
{
	uint64_t addr, reg;
	unsigned int lane_config, width = 16;

	/*
	 * On P9, only PEC2 is configurable (no-/bi-/tri-furcation)
	 */
	switch (p->pec) {
	case 0:
		width = 16;
		break;
	case 1:
		width = 8;
		break;
	case 2:
		addr = XPEC_P9_PCI_CPLT_CONF1 + 2 * XPEC_PCI_CPLT_OFFSET;
		xscom_read(p->chip_id, addr, &reg);
		lane_config = GETFIELD(XPEC_P9_PCI_LANE_CFG, reg);

		if (lane_config == 0b10 && p->index >= 4)
			width = 4;
		else
			width = 8;
	}
	return width;
}

static unsigned int __phb5_get_max_link_width(struct phb4 *p)
{
	uint64_t addr, reg;
	unsigned int lane_config, width = 16;

	/*
	 * On P10, the 2 PECs are identical and each can have a
	 * different furcation, so we always need to check the PEC
	 * config
	 */
	addr = XPEC_P10_PCI_CPLT_CONF1 + p->pec * XPEC_PCI_CPLT_OFFSET;
	xscom_read(p->chip_id, addr, &reg);
	lane_config = GETFIELD(XPEC_P10_PCI_LANE_CFG, reg);

	switch (lane_config) {
	case 0b00:
		width = 16;
		break;
	case 0b01:
		width = 8;
		break;
	case 0b10:
		if (p->index == 0 || p->index == 3)
			width = 8;
		else
			width = 4;
		break;
	default:
		PHBERR(p, "Unexpected PEC lane config value %#x\n",
		       lane_config);
	}
	return width;
}

static unsigned int phb4_get_max_link_width(struct phb4 *p)
{
	if (is_phb5())
		return __phb5_get_max_link_width(p);
	else
		return __phb4_get_max_link_width(p);
}

static void phb4_assert_perst(struct pci_slot *slot, bool assert)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	uint16_t linkctl;
	uint64_t reg;

	/*
	 * Disable the link before asserting PERST. The Cursed RAID card
	 * in ozrom1 (9005:028c) has problems coming back if PERST is asserted
	 * while link is active. To work around the problem we assert the link
	 * disable bit before asserting PERST. Asserting the secondary reset
	 * bit in the btctl register also works.
	 */
	phb4_pcicfg_read16(&p->phb, 0, p->ecap + PCICAP_EXP_LCTL, &linkctl);
	reg = phb4_read_reg(p, PHB_PCIE_CRESET);

	if (assert) {
		linkctl |= PCICAP_EXP_LCTL_LINK_DIS;
		reg &= ~PHB_PCIE_CRESET_PERST_N;
	} else {
		linkctl &= ~PCICAP_EXP_LCTL_LINK_DIS;
		reg |= PHB_PCIE_CRESET_PERST_N;
	}

	phb4_write_reg(p, PHB_PCIE_CRESET, reg);
	phb4_pcicfg_write16(&p->phb, 0, p->ecap + PCICAP_EXP_LCTL, linkctl);
}

static void set_sys_disable_detect(struct phb4 *p, bool set)
{
	uint64_t val;

	val = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
	if (set)
		val |= PHB_PCIE_DLP_SYS_DISABLEDETECT;
	else
		val &= ~PHB_PCIE_DLP_SYS_DISABLEDETECT;
	out_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL, val);
}

static int64_t phb4_hreset(struct pci_slot *slot)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	uint16_t brctl;
	uint8_t presence = 1;

	switch (slot->state) {
	case PHB4_SLOT_NORMAL:
		PHBDBG(p, "HRESET: Starts\n");
		if (slot->ops.get_presence_state)
			slot->ops.get_presence_state(slot, &presence);
		if (!presence) {
			PHBDBG(p, "HRESET: No device\n");
			return OPAL_SUCCESS;
		}

		/* circumvention for HW551382 */
		if (is_phb5()) {
			PHBINF(p, "HRESET: Workaround for HW551382\n");
			set_sys_disable_detect(p, true);
		}

		PHBDBG(p, "HRESET: Prepare for link down\n");
		phb4_prepare_link_change(slot, false);
		/* fall through */
	case PHB4_SLOT_HRESET_START:
		PHBDBG(p, "HRESET: Assert\n");

		phb4_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl |= PCI_CFG_BRCTL_SECONDARY_RESET;
		phb4_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);
		pci_slot_set_state(slot, PHB4_SLOT_HRESET_DELAY);

		return pci_slot_set_sm_timeout(slot, secs_to_tb(1));
	case PHB4_SLOT_HRESET_DELAY:
		PHBDBG(p, "HRESET: Deassert\n");

		/* Clear link errors before we deassert reset */
		phb4_err_clear_regb(p);

		phb4_pcicfg_read16(&p->phb, 0, PCI_CFG_BRCTL, &brctl);
		brctl &= ~PCI_CFG_BRCTL_SECONDARY_RESET;
		phb4_pcicfg_write16(&p->phb, 0, PCI_CFG_BRCTL, brctl);

		/*
		 * Due to some oddball adapters bouncing the link
		 * training a couple of times, we wait for a full second
		 * before we start checking the link status, otherwise
		 * we can get a spurrious link down interrupt which
		 * causes us to EEH immediately.
		 */
		pci_slot_set_state(slot, PHB4_SLOT_HRESET_DELAY2);
		return pci_slot_set_sm_timeout(slot, secs_to_tb(1));
	case PHB4_SLOT_HRESET_DELAY2:
		if (is_phb5())
			set_sys_disable_detect(p, false);
		pci_slot_set_state(slot, PHB4_SLOT_LINK_START);
		return slot->ops.poll_link(slot);
	default:
		PHBERR(p, "Unexpected slot state %08x\n", slot->state);
	}

	pci_slot_set_state(slot, PHB4_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static int64_t phb4_freset(struct pci_slot *slot)
{
	struct phb4 *p = phb_to_phb4(slot->phb);

	switch(slot->state) {
	case PHB4_SLOT_NORMAL:
	case PHB4_SLOT_FRESET_START:
		PHBDBG(p, "FRESET: Starts\n");

		/* Reset max link speed for training */
		p->max_link_speed = phb4_get_max_link_speed(p, NULL);

		PHBDBG(p, "FRESET: Prepare for link down\n");
		phb4_prepare_link_change(slot, false);

		if (!p->skip_perst) {
			/* circumvention for HW551382 */
			if (is_phb5()) {
				PHBINF(p, "FRESET: Workaround for HW551382\n");
				set_sys_disable_detect(p, true);
			}

			PHBDBG(p, "FRESET: Assert\n");
			phb4_assert_perst(slot, true);
			pci_slot_set_state(slot, PHB4_SLOT_FRESET_ASSERT_DELAY);

			/* 250ms assert time aligns with powernv */
			return pci_slot_set_sm_timeout(slot, msecs_to_tb(250));
		}

		/* To skip the assert during boot time */
		PHBDBG(p, "FRESET: Assert skipped\n");
		pci_slot_set_state(slot, PHB4_SLOT_FRESET_ASSERT_DELAY);
		p->skip_perst = false;
		/* fall through */
	case PHB4_SLOT_FRESET_ASSERT_DELAY:
		/* Clear link errors before we deassert PERST */
		phb4_err_clear_regb(p);

		PHBDBG(p, "FRESET: Deassert\n");
		phb4_assert_perst(slot, false);

		if (pci_tracing)
			phb4_link_trace(p, PHB_PCIE_DLP_LTSSM_L0, 3000);

		if (is_phb5())
			set_sys_disable_detect(p, false);

		pci_slot_set_state(slot, PHB4_SLOT_LINK_START);
		return slot->ops.poll_link(slot);
	default:
		PHBERR(p, "Unexpected slot state %08x\n", slot->state);
	}

	pci_slot_set_state(slot, PHB4_SLOT_NORMAL);
	return OPAL_HARDWARE;
}

static int64_t load_capp_ucode(struct phb4 *p)
{
	int64_t rc;

	if (p->index != CAPP0_PHB_INDEX && p->index != CAPP1_PHB_INDEX)
		return OPAL_HARDWARE;

	/* 0x434150504c494448 = 'CAPPLIDH' in ASCII */
	rc = capp_load_ucode(p->chip_id, p->phb.opal_id, p->index,
			0x434150504c494448UL, PHB4_CAPP_REG_OFFSET(p),
			CAPP_APC_MASTER_ARRAY_ADDR_REG,
			CAPP_APC_MASTER_ARRAY_WRITE_REG,
			CAPP_SNP_ARRAY_ADDR_REG,
			CAPP_SNP_ARRAY_WRITE_REG);
	return rc;
}

static int do_capp_recovery_scoms(struct phb4 *p)
{
	uint64_t rc, reg, end;
	uint64_t offset = PHB4_CAPP_REG_OFFSET(p);


	/* Get the status of CAPP recovery */
	xscom_read(p->chip_id, CAPP_ERR_STATUS_CTRL + offset, &reg);

	/* No recovery in progress ignore */
	if ((reg & PPC_BIT(0)) == 0) {
		PHBDBG(p, "CAPP: No recovery in progress\n");
		return OPAL_SUCCESS;
	}

	PHBDBG(p, "CAPP: Waiting for recovery to complete\n");
	/* recovery timer failure period 168ms */
	end = mftb() + msecs_to_tb(168);
	while ((reg & (PPC_BIT(1) | PPC_BIT(5) | PPC_BIT(9))) == 0) {

		time_wait_ms(5);
		xscom_read(p->chip_id, CAPP_ERR_STATUS_CTRL + offset, &reg);

		if (tb_compare(mftb(), end) != TB_ABEFOREB) {
			PHBERR(p, "CAPP: Capp recovery Timed-out.\n");
			end = 0;
			break;
		}
	}

	/* Check if the recovery failed or passed */
	if (reg & PPC_BIT(1)) {
		uint64_t act0, act1, mask, fir;

		/* Use the Action0/1 and mask to only clear the bits
		 * that cause local checkstop. Other bits needs attention
		 * of the PRD daemon.
		 */
		xscom_read(p->chip_id, CAPP_FIR_ACTION0 + offset, &act0);
		xscom_read(p->chip_id, CAPP_FIR_ACTION1 + offset, &act1);
		xscom_read(p->chip_id, CAPP_FIR_MASK + offset, &mask);
		xscom_read(p->chip_id, CAPP_FIR + offset, &fir);

		fir = ~(fir & ~mask & act0 & act1);
		PHBDBG(p, "Doing CAPP recovery scoms\n");

		/* update capp fir clearing bits causing local checkstop */
		PHBDBG(p, "Resetting CAPP Fir with mask 0x%016llX\n", fir);
		xscom_write(p->chip_id, CAPP_FIR_CLEAR + offset, fir);

		/* disable snoops */
		xscom_write(p->chip_id, SNOOP_CAPI_CONFIG + offset, 0);
		load_capp_ucode(p);

		/* clear err rpt reg*/
		xscom_write(p->chip_id, CAPP_ERR_RPT_CLR + offset, 0);

		/* clear capp fir */
		xscom_write(p->chip_id, CAPP_FIR + offset, 0);

		/* Just reset Bit-0,1 and dont touch any other bit */
		xscom_read(p->chip_id, CAPP_ERR_STATUS_CTRL + offset, &reg);
		reg &= ~(PPC_BIT(0) | PPC_BIT(1));
		xscom_write(p->chip_id, CAPP_ERR_STATUS_CTRL + offset, reg);

		PHBDBG(p, "CAPP recovery complete\n");
		rc = OPAL_SUCCESS;

	} else {
		/* Most likely will checkstop here due to FIR ACTION for
		 * failed recovery. So this message would never be logged.
		 * But if we still enter here then return an error forcing a
		 * fence of the PHB.
		 */
		if (reg  & PPC_BIT(5))
			PHBERR(p, "CAPP: Capp recovery Failed\n");
		else if (reg  & PPC_BIT(9))
			PHBERR(p, "CAPP: Capp recovery hang detected\n");
		else if (end != 0)
			PHBERR(p, "CAPP: Unknown recovery failure\n");

		PHBDBG(p, "CAPP: Err/Status-reg=0x%016llx\n", reg);
		rc = OPAL_HARDWARE;
	}

	return rc;
}

/*
 * Disable CAPI mode on a PHB. Must be done while PHB is fenced and
 * not in recovery.
 */
static void disable_capi_mode(struct phb4 *p)
{
	uint64_t reg;
	struct capp *capp = p->capp;

	PHBINF(p, "CAPP: Deactivating\n");

	/* Check if CAPP attached to the PHB and active */
	if (!capp || capp->phb != &p->phb) {
		PHBDBG(p, "CAPP: Not attached to this PHB!\n");
		return;
	}

	xscom_read(p->chip_id, p->pe_xscom + XPEC_NEST_CAPP_CNTL, &reg);
	if (!(reg & PPC_BIT(0))) {
		/* Not in CAPI mode, no action required */
		PHBERR(p, "CAPP: Not enabled!\n");
		return;
	}

	/* CAPP should already be out of recovery in this function */
	capp_xscom_read(capp, CAPP_ERR_STATUS_CTRL, &reg);
	if (reg & PPC_BIT(0)) {
		PHBERR(p, "CAPP: Can't disable while still in recovery!\n");
		return;
	}

	PHBINF(p, "CAPP: Disabling CAPI mode\n");

	/* First Phase Reset CAPP Registers */
	/* CAPP about to be disabled mark TLBI_FENCED and tlbi_psl_is_dead */
	capp_xscom_write(capp, CAPP_ERR_STATUS_CTRL, PPC_BIT(3) | PPC_BIT(4));

	/* Flush SUE uOP1 Register */
	if (p->rev != PHB4_REV_NIMBUS_DD10)
		capp_xscom_write(capp, FLUSH_SUE_UOP1, 0);

	/* Release DMA/STQ engines */
	capp_xscom_write(capp, APC_FSM_READ_MASK, 0ull);
	capp_xscom_write(capp, XPT_FSM_RMM, 0ull);

	/* Disable snoop */
	capp_xscom_write(capp, SNOOP_CAPI_CONFIG, 0);

	/* Clear flush SUE state map register */
	capp_xscom_write(capp, FLUSH_SUE_STATE_MAP, 0);

	/* Disable epoch timer */
	capp_xscom_write(capp, EPOCH_RECOVERY_TIMERS_CTRL, 0);

	/* CAPP Transport Control Register */
	capp_xscom_write(capp, TRANSPORT_CONTROL, PPC_BIT(15));

	/* Disable snooping */
	capp_xscom_write(capp, SNOOP_CONTROL, 0);
	capp_xscom_write(capp, SNOOP_CAPI_CONFIG, 0);

	/* APC Master PB Control Register - disable examining cResps */
	capp_xscom_write(capp, APC_MASTER_PB_CTRL, 0);

	/* APC Master Config Register - de-select PHBs */
	xscom_write_mask(p->chip_id, capp->capp_xscom_offset +
			 APC_MASTER_CAPI_CTRL, 0, PPC_BITMASK(2, 3));

	/* Clear all error registers */
	capp_xscom_write(capp, CAPP_ERR_RPT_CLR, 0);
	capp_xscom_write(capp, CAPP_FIR, 0);
	capp_xscom_write(capp, CAPP_FIR_ACTION0, 0);
	capp_xscom_write(capp, CAPP_FIR_ACTION1, 0);
	capp_xscom_write(capp, CAPP_FIR_MASK, 0);

	/* Second Phase Reset PEC/PHB Registers */

	/* Reset the stack overrides if any */
	xscom_write(p->chip_id, p->pci_xscom + XPEC_PCI_PRDSTKOVR, 0);
	xscom_write(p->chip_id, p->pe_xscom +
		    XPEC_NEST_READ_STACK_OVERRIDE, 0);

	/* PE Bus AIB Mode Bits. Disable Tracing. Leave HOL Blocking as it is */
	if (!(p->rev == PHB4_REV_NIMBUS_DD10) && p->index == CAPP1_PHB_INDEX)
		xscom_write_mask(p->chip_id,
				 p->pci_xscom + XPEC_PCI_PBAIB_HW_CONFIG, 0,
				 PPC_BIT(30));

	/* Reset for PCI to PB data movement */
	xscom_write_mask(p->chip_id, p->pe_xscom + XPEC_NEST_PBCQ_HW_CONFIG,
			 0, XPEC_NEST_PBCQ_HW_CONFIG_PBINIT);

	/* Disable CAPP mode in PEC CAPP Control Register */
	xscom_write(p->chip_id, p->pe_xscom + XPEC_NEST_CAPP_CNTL, 0ull);
}

static int64_t phb4_creset(struct pci_slot *slot)
{
	struct phb4 *p = phb_to_phb4(slot->phb);
	struct capp *capp = p->capp;
	uint64_t pbcq_status;
	uint64_t creset_time, wait_time;

	/* Don't even try fixing a broken PHB */
	if (p->broken)
		return OPAL_HARDWARE;

	switch (slot->state) {
	case PHB4_SLOT_NORMAL:
	case PHB4_SLOT_CRESET_START:
		PHBDBG(p, "CRESET: Starts\n");

		p->creset_start_time = mftb();

		/* circumvention for HW551382 */
		if (is_phb5()) {
			PHBINF(p, "CRESET: Workaround for HW551382\n");
			set_sys_disable_detect(p, true);
		}

		phb4_prepare_link_change(slot, false);
		/* Clear error inject register, preventing recursive errors */
		xscom_write(p->chip_id, p->pe_xscom + 0x2, 0x0);

		/* Prevent HMI when PHB gets fenced as we are disabling CAPP */
		if (p->flags & PHB4_CAPP_DISABLE &&
		    capp && capp->phb == slot->phb) {
			/* Since no HMI, So set the recovery flag manually. */
			p->flags |= PHB4_CAPP_RECOVERY;
			xscom_write_mask(p->chip_id, capp->capp_xscom_offset +
					 CAPP_FIR_MASK,
					 PPC_BIT(31), PPC_BIT(31));
		}

		/* Force fence on the PHB to work around a non-existent PE */
		if (!phb4_fenced(p))
			xscom_write(p->chip_id, p->pe_stk_xscom + 0x2,
				    0x0000002000000000UL);

		/*
		 * Force use of ASB for register access until the PHB has
		 * been fully reset.
		 */
		p->flags |= PHB4_CFG_USE_ASB | PHB4_AIB_FENCED;

		/* Assert PREST before clearing errors */
		phb4_assert_perst(slot, true);

		/* Clear errors, following the proper sequence */
		phb4_err_clear(p);

		/* Actual reset */
		p->flags |= PHB4_ETU_IN_RESET;
		xscom_write(p->chip_id, p->pci_stk_xscom + XPEC_PCI_STK_ETU_RESET,
			    0x8000000000000000UL);

		/* Read errors in PFIR and NFIR */
		xscom_read(p->chip_id, p->pci_stk_xscom + 0x0, &p->pfir_cache);
		xscom_read(p->chip_id, p->pe_stk_xscom + 0x0, &p->nfir_cache);

		pci_slot_set_state(slot, PHB4_SLOT_CRESET_WAIT_CQ);
		slot->retries = 500;
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(10));
	case PHB4_SLOT_CRESET_WAIT_CQ:

		// Wait until operations are complete
		xscom_read(p->chip_id, p->pe_stk_xscom + 0xc, &pbcq_status);
		if (!(pbcq_status & 0xC000000000000000UL)) {
			PHBDBG(p, "CRESET: No pending transactions\n");

			/* capp recovery */
			if ((p->flags & PHB4_CAPP_RECOVERY) &&
			    (do_capp_recovery_scoms(p) != OPAL_SUCCESS))
				goto error;

			if (p->flags & PHB4_CAPP_DISABLE)
				disable_capi_mode(p);

			/* Clear errors in PFIR and NFIR */
			xscom_write(p->chip_id, p->pci_stk_xscom + 0x1,
				    ~p->pfir_cache);
			xscom_write(p->chip_id, p->pe_stk_xscom + 0x1,
				    ~p->nfir_cache);

			/* Re-read errors in PFIR and NFIR and reset any new
			 * error reported.
			 */
			xscom_read(p->chip_id, p->pci_stk_xscom +
				   XPEC_PCI_STK_PCI_FIR, &p->pfir_cache);
			xscom_read(p->chip_id, p->pe_stk_xscom +
				   XPEC_NEST_STK_PCI_NFIR, &p->nfir_cache);

			if (p->pfir_cache || p->nfir_cache) {
				PHBERR(p, "CRESET: PHB still fenced !!\n");
				phb4_dump_pec_err_regs(p);

				/* Reset the PHB errors */
				xscom_write(p->chip_id, p->pci_stk_xscom +
					    XPEC_PCI_STK_PCI_FIR, 0);
				xscom_write(p->chip_id, p->pe_stk_xscom +
					    XPEC_NEST_STK_PCI_NFIR, 0);
			}

			/* Clear PHB from reset */
			xscom_write(p->chip_id,
				    p->pci_stk_xscom + XPEC_PCI_STK_ETU_RESET, 0x0);
			p->flags &= ~PHB4_ETU_IN_RESET;

			pci_slot_set_state(slot, PHB4_SLOT_CRESET_REINIT);
			/* After lifting PHB reset, wait while logic settles */
			return pci_slot_set_sm_timeout(slot, msecs_to_tb(10));
		}

		if (slot->retries-- == 0) {
			PHBERR(p, "Timeout waiting for pending transaction\n");
			goto error;
		}
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(100));
	case PHB4_SLOT_CRESET_REINIT:
		PHBDBG(p, "CRESET: Reinitialization\n");
		p->flags &= ~PHB4_AIB_FENCED;
		p->flags &= ~PHB4_CAPP_RECOVERY;
		p->flags &= ~PHB4_CFG_USE_ASB;
		phb4_init_hw(p);
		pci_slot_set_state(slot, PHB4_SLOT_CRESET_FRESET);

		/*
		 * The PERST is sticky across resets, but LINK_DIS isn't.
		 * Re-assert it here now that we've reset the PHB.
		 */
		phb4_assert_perst(slot, true);

		/*
		 * wait either 100ms (for the ETU logic) or until we've had
		 * PERST asserted for 250ms.
		 */
		creset_time = tb_to_msecs(mftb() - p->creset_start_time);
		if (creset_time < 250)
			wait_time = MAX(100, 250 - creset_time);
		else
			wait_time = 100;
		PHBDBG(p, "CRESET: wait_time = %lld\n", wait_time);
		return pci_slot_set_sm_timeout(slot, msecs_to_tb(wait_time));

	case PHB4_SLOT_CRESET_FRESET:
		/*
		 * We asserted PERST at the beginning of the CRESET and we
		 * have waited long enough, so we can skip it in the freset
		 * procedure.
		 */
		p->skip_perst = true;
		pci_slot_set_state(slot, PHB4_SLOT_NORMAL);
		return slot->ops.freset(slot);
	default:
		PHBERR(p, "CRESET: Unexpected slot state %08x, resetting...\n",
		       slot->state);
		pci_slot_set_state(slot, PHB4_SLOT_NORMAL);
		return slot->ops.creset(slot);

	}

error:
	/* Mark the PHB as dead and expect it to be removed */
	p->broken = true;
	return OPAL_HARDWARE;
}

/*
 * Initialize root complex slot, which is mainly used to
 * do fundamental reset before PCI enumeration in PCI core.
 * When probing root complex and building its real slot,
 * the operations will be copied over.
 */
static struct pci_slot *phb4_slot_create(struct phb *phb)
{
	struct pci_slot *slot;

	slot = pci_slot_alloc(phb, NULL);
	if (!slot)
		return slot;

	/* Elementary functions */
	slot->ops.get_presence_state  = phb4_get_presence_state;
	slot->ops.get_link_state      = phb4_get_link_state;
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
	slot->ops.prepare_link_change	= phb4_prepare_link_change;
	slot->ops.poll_link		= phb4_poll_link;
	slot->ops.hreset		= phb4_hreset;
	slot->ops.freset		= phb4_freset;
	slot->ops.creset		= phb4_creset;
	slot->ops.completed_sm_run	= phb4_slot_sm_run_completed;
	slot->link_retries		= PHB4_LINK_LINK_RETRIES;

	return slot;
}

static void phb4_int_unmask_all(struct phb4 *p)
{
	/* Init_126..130 - Re-enable error interrupts */
	out_be64(p->regs + PHB_ERR_IRQ_ENABLE,         0xca8880cc00000000ull);

	if (is_phb5())
		out_be64(p->regs + PHB_TXE_ERR_IRQ_ENABLE, 0x200850be08200020ull);
	else
		out_be64(p->regs + PHB_TXE_ERR_IRQ_ENABLE, 0x2008400e08200000ull);
	out_be64(p->regs + PHB_RXE_ARB_ERR_IRQ_ENABLE, 0xc40038fc01804070ull);
	out_be64(p->regs + PHB_RXE_MRG_ERR_IRQ_ENABLE, 0x00006100008000a8ull);
	out_be64(p->regs + PHB_RXE_TCE_ERR_IRQ_ENABLE, 0x60510050c0000000ull);
}

/*
 * Mask the IRQ for any currently set error bits. This prevents the PHB's ERR
 * and INF interrupts from being re-fired before the kernel can handle the
 * underlying condition.
 */
static void phb4_int_mask_active(struct phb4 *p)
{
	const uint64_t error_regs[] = {
		PHB_ERR_STATUS,
		PHB_TXE_ERR_STATUS,
		PHB_RXE_ARB_ERR_STATUS,
		PHB_RXE_MRG_ERR_STATUS,
		PHB_RXE_TCE_ERR_STATUS
	};
	int i;

	for (i = 0; i < ARRAY_SIZE(error_regs); i++) {
		uint64_t stat, mask;

		/* The IRQ mask reg is always offset 0x20 from the status reg */
		stat = phb4_read_reg(p, error_regs[i]);
		mask = phb4_read_reg(p, error_regs[i] + 0x20);

		phb4_write_reg(p, error_regs[i] + 0x20, mask & ~stat);
	}
}

static uint64_t phb4_get_pesta(struct phb4 *p, uint64_t pe_number)
{
	uint64_t pesta;

	phb4_ioda_sel(p, IODA3_TBL_PESTA, pe_number, false);
	pesta = phb4_read_reg(p, PHB_IODA_DATA0);
	if (pesta & IODA3_PESTA_MMIO_FROZEN)
		pesta |= be64_to_cpu(p->tbl_pest[2*pe_number]);

	return pesta;
}

/* Check if the chip requires escalating a freeze to fence on MMIO loads */
static bool phb4_escalation_required(void)
{
	uint64_t pvr = mfspr(SPR_PVR);

	/* Only on Power9 */
	if (proc_gen != proc_gen_p9)
		return false;

	/*
	 * Escalation is required on the following chip versions:
	 * - Cumulus DD1.0
	 * - Nimbus DD2.0, DD2.1 (and DD1.0, but it is unsupported so no check).
	 */
	if (pvr & PVR_POWER9_CUMULUS) {
		if (PVR_VERS_MAJ(pvr) == 1 && PVR_VERS_MIN(pvr) == 0)
			return true;
	} else { /* Nimbus */
		if (PVR_VERS_MAJ(pvr) == 2 && PVR_VERS_MIN(pvr) < 2)
			return true;
	}

	return false;
}

static bool phb4_freeze_escalate(uint64_t pesta)
{
	if ((GETFIELD(IODA3_PESTA_TRANS_TYPE, pesta) ==
	     IODA3_PESTA_TRANS_TYPE_MMIOLOAD) &&
	    (pesta & (IODA3_PESTA_CA_CMPLT_TMT | IODA3_PESTA_UR)))
		return true;
	return false;
}

static int64_t phb4_eeh_freeze_status(struct phb *phb, uint64_t pe_number,
				      uint8_t *freeze_state,
				      uint16_t *pci_error_type,
				      uint16_t *severity)
{
	struct phb4 *p = phb_to_phb4(phb);
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
	if (phb4_fenced(p) || (p->flags & PHB4_CAPP_RECOVERY)) {
		*freeze_state = OPAL_EEH_STOPPED_MMIO_DMA_FREEZE;
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		if (severity)
			*severity = OPAL_EEH_SEV_PHB_FENCED;
		return OPAL_SUCCESS;
	}

	/* Check the PEEV */
	phb4_ioda_sel(p, IODA3_TBL_PEEV, pe_number / 64, false);
	peev = in_be64(p->regs + PHB_IODA_DATA0);
	if (!(peev & peev_bit))
		return OPAL_SUCCESS;

	/* Indicate that we have an ER pending */
	phb4_set_err_pending(p, true);
	if (severity)
		*severity = OPAL_EEH_SEV_PE_ER;

	/* Read the full PESTA */
	pesta = phb4_get_pesta(p, pe_number);
	/* Check if we need to escalate to fence */
	if (phb4_escalation_required() && phb4_freeze_escalate(pesta)) {
		PHBERR(p, "Escalating freeze to fence PESTA[%lli]=%016llx\n",
		       pe_number, pesta);
		*severity = OPAL_EEH_SEV_PHB_FENCED;
		*pci_error_type = OPAL_EEH_PHB_ERROR;
	}

	/* Read the PESTB in the PHB */
	phb4_ioda_sel(p, IODA3_TBL_PESTB, pe_number, false);
	pestb = phb4_read_reg(p, PHB_IODA_DATA0);

	/* Convert PESTA/B to freeze_state */
	if (pesta & IODA3_PESTA_MMIO_FROZEN)
		*freeze_state |= OPAL_EEH_STOPPED_MMIO_FREEZE;
	if (pestb & IODA3_PESTB_DMA_STOPPED)
		*freeze_state |= OPAL_EEH_STOPPED_DMA_FREEZE;

	return OPAL_SUCCESS;
}

static int64_t phb4_eeh_freeze_clear(struct phb *phb, uint64_t pe_number,
				     uint64_t eeh_action_token)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t err, peev;
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
		if (phb4_fenced(p)) {
			PHBERR(p, "eeh_freeze_clear on fenced PHB\n");
			return OPAL_HARDWARE;
		}
	}
	if (err != 0)
		phb4_err_clear(p);

	/*
	 * We have PEEV in system memory. It would give more performance
	 * to access that directly.
	 */
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_MMIO) {
		phb4_ioda_sel(p, IODA3_TBL_PESTA, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}
	if (eeh_action_token & OPAL_EEH_ACTION_CLEAR_FREEZE_DMA) {
		phb4_ioda_sel(p, IODA3_TBL_PESTB, pe_number, false);
		out_be64(p->regs + PHB_IODA_DATA0, 0);
	}


	/* Update ER pending indication */
	phb4_ioda_sel(p, IODA3_TBL_PEEV, 0, true);
	for (i = 0; i < p->num_pes/64; i++) {
		peev = in_be64(p->regs + PHB_IODA_DATA0);
		if (peev) {
			frozen_pe = true;
			break;
		}
	}
	if (frozen_pe) {
		p->err.err_src	 = PHB4_ERR_SRC_PHB;
		p->err.err_class = PHB4_ERR_CLASS_ER;
		p->err.err_bit   = -1;
		phb4_set_err_pending(p, true);
	} else
		phb4_set_err_pending(p, false);

	return OPAL_SUCCESS;
}

static int64_t phb4_eeh_freeze_set(struct phb *phb, uint64_t pe_number,
				   uint64_t eeh_action_token)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t data;

	if (p->broken)
		return OPAL_HARDWARE;

	if (pe_number >= p->num_pes)
		return OPAL_PARAMETER;

	if (eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_MMIO &&
	    eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_DMA &&
	    eeh_action_token != OPAL_EEH_ACTION_SET_FREEZE_ALL)
		return OPAL_PARAMETER;

	if (eeh_action_token & OPAL_EEH_ACTION_SET_FREEZE_MMIO) {
		phb4_ioda_sel(p, IODA3_TBL_PESTA, pe_number, false);
		data = in_be64(p->regs + PHB_IODA_DATA0);
		data |= IODA3_PESTA_MMIO_FROZEN;
		out_be64(p->regs + PHB_IODA_DATA0, data);
	}

	if (eeh_action_token & OPAL_EEH_ACTION_SET_FREEZE_DMA) {
		phb4_ioda_sel(p, IODA3_TBL_PESTB, pe_number, false);
		data = in_be64(p->regs + PHB_IODA_DATA0);
		data |= IODA3_PESTB_DMA_STOPPED;
		out_be64(p->regs + PHB_IODA_DATA0, data);
	}

	return OPAL_SUCCESS;
}

static int64_t phb4_eeh_next_error(struct phb *phb,
				   uint64_t *first_frozen_pe,
				   uint16_t *pci_error_type,
				   uint16_t *severity)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t peev, pesta;
	uint32_t peev_size = p->num_pes/64;
	int32_t i, j;

	/* If the PHB is broken, we needn't go forward */
	if (p->broken) {
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_DEAD;
		return OPAL_SUCCESS;
	}

	if ((p->flags & PHB4_CAPP_RECOVERY)) {
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_FENCED;
		return OPAL_SUCCESS;
	}

	/*
	 * Check if we already have pending errors. If that's
	 * the case, then to get more information about the
	 * pending errors. Here we try PBCQ prior to PHB.
	 */
	if (phb4_err_pending(p) /*&&
	    !phb4_err_check_pbcq(p) &&
	    !phb4_err_check_lem(p) */)
		phb4_set_err_pending(p, false);

	/* Clear result */
	*pci_error_type  = OPAL_EEH_NO_ERROR;
	*severity	 = OPAL_EEH_SEV_NO_ERROR;
	*first_frozen_pe = (uint64_t)-1;

	/* Check frozen PEs */
	if (!phb4_err_pending(p)) {
		phb4_ioda_sel(p, IODA3_TBL_PEEV, 0, true);
		for (i = 0; i < peev_size; i++) {
			peev = in_be64(p->regs + PHB_IODA_DATA0);
			if (peev) {
				p->err.err_src	 = PHB4_ERR_SRC_PHB;
				p->err.err_class = PHB4_ERR_CLASS_ER;
				p->err.err_bit	 = -1;
				phb4_set_err_pending(p, true);
				break;
			}
		}
	}

	if (!phb4_err_pending(p))
		return OPAL_SUCCESS;
	/*
	 * If the frozen PE is caused by a malfunctioning TLP, we
	 * need reset the PHB. So convert ER to PHB-fatal error
	 * for the case.
	 */
	if (p->err.err_class == PHB4_ERR_CLASS_ER) {
		for (i = peev_size - 1; i >= 0; i--) {
			phb4_ioda_sel(p, IODA3_TBL_PEEV, i, false);
			peev = in_be64(p->regs + PHB_IODA_DATA0);
			for (j = 0; j < 64; j++) {
				if (peev & PPC_BIT(j)) {
					*first_frozen_pe = i * 64 + j;
					break;
				}
			}
			if (*first_frozen_pe != (uint64_t)(-1))
				break;
		}
	}

	if (*first_frozen_pe != (uint64_t)(-1)) {
		pesta = phb4_get_pesta(p, *first_frozen_pe);
		if (phb4_escalation_required() && phb4_freeze_escalate(pesta)) {
			PHBINF(p, "Escalating freeze to fence. PESTA[%lli]=%016llx\n",
			       *first_frozen_pe, pesta);
			p->err.err_class = PHB4_ERR_CLASS_FENCED;
		}
	}

	switch (p->err.err_class) {
	case PHB4_ERR_CLASS_DEAD:
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_DEAD;
		break;
	case PHB4_ERR_CLASS_FENCED:
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_PHB_FENCED;
		break;
	case PHB4_ERR_CLASS_ER:
		*pci_error_type = OPAL_EEH_PE_ERROR;
		*severity = OPAL_EEH_SEV_PE_ER;

		/* No frozen PE ? */
		if (*first_frozen_pe == (uint64_t)-1) {
			*pci_error_type = OPAL_EEH_NO_ERROR;
			*severity = OPAL_EEH_SEV_NO_ERROR;
			phb4_set_err_pending(p, false);
		}

		break;
	case PHB4_ERR_CLASS_INF:
		*pci_error_type = OPAL_EEH_PHB_ERROR;
		*severity = OPAL_EEH_SEV_INF;
		break;
	default:
		*pci_error_type = OPAL_EEH_NO_ERROR;
		*severity = OPAL_EEH_SEV_NO_ERROR;
		phb4_set_err_pending(p, false);
	}

	/*
	 * Unmask all our error interrupts once all pending errors
	 * have been handled.
	 */
	if (!phb4_err_pending(p))
		phb4_int_unmask_all(p);

	return OPAL_SUCCESS;
}

static int64_t phb4_err_inject_finalize(struct phb4 *phb, uint64_t addr,
					uint64_t mask, uint64_t ctrl,
					bool is_write)
{
	if (is_write)
		ctrl |= PHB_PAPR_ERR_INJ_CTL_WR;
	else
		ctrl |= PHB_PAPR_ERR_INJ_CTL_RD;

	out_be64(phb->regs + PHB_PAPR_ERR_INJ_ADDR, addr);
	out_be64(phb->regs + PHB_PAPR_ERR_INJ_MASK, mask);
	out_be64(phb->regs + PHB_PAPR_ERR_INJ_CTL, ctrl);

	return OPAL_SUCCESS;
}

static int64_t phb4_err_inject_mem32(struct phb4 *phb __unused,
				     uint64_t pe_number __unused,
				     uint64_t addr __unused,
				     uint64_t mask __unused,
				     bool is_write __unused)
{
	return OPAL_UNSUPPORTED;
}

static int64_t phb4_err_inject_mem64(struct phb4 *phb __unused,
				     uint64_t pe_number __unused,
				     uint64_t addr __unused,
				     uint64_t mask __unused,
				     bool is_write __unused)
{
	return OPAL_UNSUPPORTED;
}

static int64_t phb4_err_inject_cfg(struct phb4 *phb, uint64_t pe_number,
				   uint64_t addr, uint64_t mask,
				   bool is_write)
{
	uint64_t a, m, prefer, ctrl;
	int bdfn;
	bool is_bus_pe = false;

	a = 0xffffull;
	prefer = 0xffffull;
	m = PHB_PAPR_ERR_INJ_MASK_CFG_ALL;
	ctrl = PHB_PAPR_ERR_INJ_CTL_CFG;

	for (bdfn = 0; bdfn < RTT_TABLE_ENTRIES; bdfn++) {
		if (be16_to_cpu(phb->tbl_rtt[bdfn]) != pe_number)
			continue;

		/* The PE can be associated with PCI bus or device */
		is_bus_pe = false;
		if ((bdfn + 8) < RTT_TABLE_ENTRIES &&
		    be16_to_cpu(phb->tbl_rtt[bdfn + 8]) == pe_number)
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

	return phb4_err_inject_finalize(phb, a, m, ctrl, is_write);
}

static int64_t phb4_err_inject_dma(struct phb4 *phb __unused,
				   uint64_t pe_number __unused,
				   uint64_t addr __unused,
				   uint64_t mask __unused,
				   bool is_write __unused,
				   bool is_64bits __unused)
{
	return OPAL_UNSUPPORTED;
}

static int64_t phb4_err_inject_dma32(struct phb4 *phb, uint64_t pe_number,
				     uint64_t addr, uint64_t mask,
				     bool is_write)
{
	return phb4_err_inject_dma(phb, pe_number, addr, mask, is_write, false);
}

static int64_t phb4_err_inject_dma64(struct phb4 *phb, uint64_t pe_number,
				     uint64_t addr, uint64_t mask,
				     bool is_write)
{
	return phb4_err_inject_dma(phb, pe_number, addr, mask, is_write, true);
}


static int64_t phb4_err_inject(struct phb *phb, uint64_t pe_number,
			       uint32_t type, uint32_t func,
			       uint64_t addr, uint64_t mask)
{
	struct phb4 *p = phb_to_phb4(phb);
	int64_t (*handler)(struct phb4 *p, uint64_t pe_number,
			   uint64_t addr, uint64_t mask, bool is_write);
	bool is_write;

	/* We can't inject error to the reserved PE */
	if (pe_number == PHB4_RESERVED_PE_NUM(p) || pe_number >= p->num_pes)
		return OPAL_PARAMETER;

	/* Clear leftover from last time */
	out_be64(p->regs + PHB_PAPR_ERR_INJ_CTL, 0x0ul);

	switch (func) {
	case OPAL_ERR_INJECT_FUNC_IOA_LD_MEM_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_LD_MEM_DATA:
		is_write = false;
		if (type == OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
			handler = phb4_err_inject_mem64;
		else
			handler = phb4_err_inject_mem32;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_ST_MEM_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_ST_MEM_DATA:
		is_write = true;
		if (type == OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
			handler = phb4_err_inject_mem64;
		else
			handler = phb4_err_inject_mem32;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_LD_CFG_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_LD_CFG_DATA:
		is_write = false;
		handler = phb4_err_inject_cfg;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_ST_CFG_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_ST_CFG_DATA:
		is_write = true;
		handler = phb4_err_inject_cfg;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_DATA:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_MASTER:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_RD_TARGET:
		is_write = false;
		if (type == OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
			handler = phb4_err_inject_dma64;
		else
			handler = phb4_err_inject_dma32;
		break;
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_ADDR:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_DATA:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_MASTER:
	case OPAL_ERR_INJECT_FUNC_IOA_DMA_WR_TARGET:
		is_write = true;
		if (type == OPAL_ERR_INJECT_TYPE_IOA_BUS_ERR64)
			handler = phb4_err_inject_dma64;
		else
			handler = phb4_err_inject_dma32;
		break;
	default:
		return OPAL_PARAMETER;
	}

	return handler(p, pe_number, addr, mask, is_write);
}

static int64_t phb4_get_diag_data(struct phb *phb,
				  void *diag_buffer,
				  uint64_t diag_buffer_len)
{
	bool fenced;
	struct phb4 *p = phb_to_phb4(phb);
	struct OpalIoPhb4ErrorData *data = diag_buffer;

	if (diag_buffer_len < sizeof(struct OpalIoPhb4ErrorData))
		return OPAL_PARAMETER;
	if (p->broken)
		return OPAL_HARDWARE;

	/*
	 * Dummy check for fence so that phb4_read_phb_status knows
	 * whether to use ASB or AIB
	 */
	fenced = phb4_fenced(p);
	phb4_read_phb_status(p, data);

	if (!fenced)
		phb4_eeh_dump_regs(p);

	/*
	 * We're running to here probably because of errors
	 * (INF class). For that case, we need clear the error
	 * explicitly.
	 */
	if (phb4_err_pending(p) &&
	    p->err.err_class == PHB4_ERR_CLASS_INF &&
	    p->err.err_src == PHB4_ERR_SRC_PHB) {
		phb4_err_clear(p);
		phb4_set_err_pending(p, false);
	}

	return OPAL_SUCCESS;
}

static uint64_t tve_encode_50b_noxlate(uint64_t start_addr, uint64_t end_addr)
{
	uint64_t tve;

	/*
	 * Put start address bits 49:24 into TVE[52:53]||[0:23]
	 * and end address bits 49:24 into TVE[54:55]||[24:47]
	 * and set TVE[51]
	 */
	tve  = (start_addr << 16) & (0xffffffull << 40);
	tve |= (start_addr >> 38) & (3ull << 10);
	tve |= (end_addr >>  8) & (0xfffffful << 16);
	tve |= (end_addr >> 40) & (3ull << 8);
	tve |= PPC_BIT(51) | IODA3_TVT_NON_TRANSLATE_50;
	return tve;
}

static bool phb4_is_dd20(struct phb4 *p)
{
	struct proc_chip *chip = get_chip(p->chip_id);

	if (p->rev == PHB4_REV_NIMBUS_DD20 && ((0xf & chip->ec_level) == 0))
		return true;
	return false;
}

static int64_t phb4_get_capp_info(int chip_id, struct phb *phb,
				  struct capp_info *info)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint32_t offset;

	/* Not even supposed to be here on P10, but doesn't hurt */
	if (is_phb5())
		return OPAL_UNSUPPORTED;

	if (chip_id != p->chip_id)
		return OPAL_PARAMETER;

	/* Check is CAPP is attached to the PHB */
	if (p->capp == NULL || p->capp->phb != phb)
		return OPAL_PARAMETER;

	offset = PHB4_CAPP_REG_OFFSET(p);

	if (p->index == CAPP0_PHB_INDEX)
		info->capp_index = 0;
	if (p->index == CAPP1_PHB_INDEX)
		info->capp_index = 1;
	info->phb_index = p->index;
	info->capp_fir_reg = CAPP_FIR + offset;
	info->capp_fir_mask_reg = CAPP_FIR_MASK + offset;
	info->capp_fir_action0_reg = CAPP_FIR_ACTION0 + offset;
	info->capp_fir_action1_reg = CAPP_FIR_ACTION1 + offset;
	info->capp_err_status_ctrl_reg = CAPP_ERR_STATUS_CTRL + offset;

	return OPAL_SUCCESS;
}

static void phb4_init_capp_regs(struct phb4 *p, uint32_t capp_eng)
{
	uint64_t addr, reg;
	uint32_t offset;
	uint8_t link_width_x16 = 1;

	offset = PHB4_CAPP_REG_OFFSET(p);

	/* Calculate the phb link width if card is attached to PEC2 */
	if (p->index == CAPP1_PHB_INDEX) {
		/* Check if PEC2 is in x8 or x16 mode.
		 * PEC0 is always in x16
		 */
		addr = XPEC_P9_PCI_CPLT_CONF1 + 2 * XPEC_PCI_CPLT_OFFSET;
		xscom_read(p->chip_id, addr, &reg);
		link_width_x16 = ((reg & XPEC_P9_PCI_IOVALID_MASK) ==
				  XPEC_P9_PCI_IOVALID_X16);
	}

	/* APC Master PowerBus Control Register */
	xscom_read(p->chip_id, APC_MASTER_PB_CTRL + offset, &reg);
	reg |= PPC_BIT(0); /* enable cResp exam */
	reg |= PPC_BIT(3); /* disable vg not sys */
	reg |= PPC_BIT(12);/* HW417025: disable capp virtual machines */
	reg |= PPC_BIT(2); /* disable nn rn */
	reg |= PPC_BIT(4); /* disable g */
	reg |= PPC_BIT(5); /* disable ln */
	xscom_write(p->chip_id, APC_MASTER_PB_CTRL + offset, reg);

	/* Set PHB mode, HPC Dir State and P9 mode */
	xscom_write(p->chip_id, APC_MASTER_CAPI_CTRL + offset,
		    0x1772000000000000UL);
	PHBINF(p, "CAPP: port attached\n");

	/* Set snoop ttype decoding , dir size to 512K */
	xscom_write(p->chip_id, SNOOP_CAPI_CONFIG + offset, 0x9000000000000000UL);

	/* Use Read Epsilon Tier2 for all scopes.
	 * Set Tier2 Read Epsilon.
	 */
	xscom_read(p->chip_id, SNOOP_CONTROL + offset, &reg);
	reg |= PPC_BIT(0);
	reg |= PPC_BIT(35);
	reg |= PPC_BIT(45);
	reg |= PPC_BIT(46);
	reg |= PPC_BIT(47);
	reg |= PPC_BIT(50);
	xscom_write(p->chip_id, SNOOP_CONTROL + offset, reg);

	/* Transport Control Register */
	xscom_read(p->chip_id, TRANSPORT_CONTROL + offset, &reg);
	if (p->index == CAPP0_PHB_INDEX) {
		reg |= PPC_BIT(1); /* Send Packet Timer Value */
		reg |= PPC_BITMASK(10, 13); /* Send Packet Timer Value */
		reg &= ~PPC_BITMASK(14, 17); /* Set Max LPC CI store buffer to zeros */
		reg &= ~PPC_BITMASK(18, 21); /* Set Max tlbi divider */
		if (capp_eng & CAPP_MIN_STQ_ENGINES) {
			/* 2 CAPP msg engines */
			reg |= PPC_BIT(58);
			reg |= PPC_BIT(59);
			reg |= PPC_BIT(60);
		}
		if (capp_eng & CAPP_MAX_STQ_ENGINES) {
			/* 14 CAPP msg engines */
			reg |= PPC_BIT(60);
		}
		reg |= PPC_BIT(62);
	}
	if (p->index == CAPP1_PHB_INDEX) {
		reg |= PPC_BIT(4); /* Send Packet Timer Value */
		reg &= ~PPC_BIT(10); /* Set CI Store Buffer Threshold=5 */
		reg |= PPC_BIT(11);  /* Set CI Store Buffer Threshold=5 */
		reg &= ~PPC_BIT(12); /* Set CI Store Buffer Threshold=5 */
		reg |= PPC_BIT(13);  /* Set CI Store Buffer Threshold=5 */
		reg &= ~PPC_BITMASK(14, 17); /* Set Max LPC CI store buffer to zeros */
		reg &= ~PPC_BITMASK(18, 21); /* Set Max tlbi divider */
		if (capp_eng & CAPP_MIN_STQ_ENGINES) {
			/* 2 CAPP msg engines */
			reg |= PPC_BIT(59);
			reg |= PPC_BIT(60);

		} else if (capp_eng & CAPP_MAX_STQ_ENGINES) {

			if (link_width_x16)
				/* 14 CAPP msg engines */
				reg |= PPC_BIT(60) | PPC_BIT(62);
			else
				/* 6 CAPP msg engines */
				reg |= PPC_BIT(60);
		}
	}
	xscom_write(p->chip_id, TRANSPORT_CONTROL + offset, reg);

	/* The transport control register needs to be loaded in two
	 * steps. Once the register values have been set, we have to
	 * write bit 63 to a '1', which loads the register values into
	 * the ci store buffer logic.
	 */
	xscom_read(p->chip_id, TRANSPORT_CONTROL + offset, &reg);
	reg |= PPC_BIT(63);
	xscom_write(p->chip_id, TRANSPORT_CONTROL + offset, reg);

	/* Enable epoch timer */
	xscom_write(p->chip_id, EPOCH_RECOVERY_TIMERS_CTRL + offset,
		    0xC0000000FFF8FFE0UL);

	/* Flush SUE State Map Register */
	xscom_write(p->chip_id, FLUSH_SUE_STATE_MAP + offset,
		    0x08020A0000000000UL);

	/* Flush SUE uOP1 Register */
	xscom_write(p->chip_id, FLUSH_SUE_UOP1 + offset,
		    0xDCE0280428000000);

	/* capp owns PHB read buffers */
	if (p->index == CAPP0_PHB_INDEX) {
		/* max PHB read buffers 0-47 */
		reg = 0xFFFFFFFFFFFF0000UL;
		if (capp_eng & CAPP_MAX_DMA_READ_ENGINES)
			reg = 0xF000000000000000UL;
		xscom_write(p->chip_id, APC_FSM_READ_MASK + offset, reg);
		xscom_write(p->chip_id, XPT_FSM_RMM + offset, reg);
	}
	if (p->index == CAPP1_PHB_INDEX) {

		if (capp_eng & CAPP_MAX_DMA_READ_ENGINES) {
			reg = 0xF000000000000000ULL;
		} else if (link_width_x16) {
			/* 0-47 (Read machines) are available for
			 * capp use
			 */
			reg = 0x0000FFFFFFFFFFFFULL;
		} else {
			/* Set 30 Read machines for CAPP Minus
			 * 20-27 for DMA
			 */
			reg = 0xFFFFF00E00000000ULL;
		}
		xscom_write(p->chip_id, APC_FSM_READ_MASK + offset, reg);
		xscom_write(p->chip_id, XPT_FSM_RMM + offset, reg);
	}

	/* CAPP FIR Action 0 */
	xscom_write(p->chip_id, CAPP_FIR_ACTION0 + offset, 0x0b1c000104060000UL);

	/* CAPP FIR Action 1 */
	xscom_write(p->chip_id, CAPP_FIR_ACTION1 + offset, 0x2b9c0001240E0000UL);

	/* CAPP FIR MASK */
	xscom_write(p->chip_id, CAPP_FIR_MASK + offset, 0x80031f98d8717000UL);

	/* Mask the CAPP PSL Credit Timeout Register error */
	xscom_write_mask(p->chip_id, CAPP_FIR_MASK + offset,
			 PPC_BIT(46), PPC_BIT(46));

	/* Deassert TLBI_FENCED and tlbi_psl_is_dead */
	xscom_write(p->chip_id, CAPP_ERR_STATUS_CTRL + offset, 0);
}

/* override some inits with CAPI defaults */
static void phb4_init_capp_errors(struct phb4 *p)
{
	/* Init_77: TXE Error AIB Fence Enable Register */
	if (phb4_is_dd20(p))
		out_be64(p->regs + 0x0d30,	0xdfffbf0ff7ddfff0ull);
	else
		out_be64(p->regs + 0x0d30,	0xdff7bf0ff7ddfff0ull);
	/* Init_86: RXE_ARB Error AIB Fence Enable Register */
	out_be64(p->regs + 0x0db0,	0xfbffd7bbfb7fbfefull);

	/* Init_95: RXE_MRG Error AIB Fence Enable Register */
	out_be64(p->regs + 0x0e30,	0xfffffeffff7fff57ull);

	/* Init_104: RXE_TCE Error AIB Fence Enable Register */
	out_be64(p->regs + 0x0eb0,	0xffaeffafffffffffull);

	/* Init_113: PHB Error AIB Fence Enable Register */
	out_be64(p->regs + 0x0cb0,	0x35777073ff000000ull);
}

/*
 * The capi, NBW and ASN indicators are used only on P9 to flag some
 * types of incoming traffic for the PHB and have been removed on P10.
 *
 * The capi indicator is over the 8 most significant bits (and
 * not 16). We stay away from bits 59 (TVE select), 60 and 61 (MSI)
 *
 * For the mask, we keep bit 59 in, as capi messages must hit TVE#0.
 * Bit 56 is not part of the mask, so that a NBW message (see below)
 * is also considered a capi message.
 */
#define CAPIIND		0x0200
#define CAPIMASK	0xFE00

/*
 * Non-Blocking Write messages are a subset of capi messages, so the
 * indicator is the same as capi + an extra bit (56) to differentiate.
 * Mask is the same as capi + the extra bit
 */
#define NBWIND		0x0300
#define NBWMASK		0xFF00

/*
 * The ASN indicator is used for tunneled operations (as_notify and
 * atomics).  Tunneled operation messages can be sent in PCI mode as
 * well as CAPI mode.
 *
 * The format of those messages is specific and, for as_notify
 * messages, the address field is hijacked to encode the LPID/PID/TID
 * of the target thread, so those messages should not go through
 * translation. They must hit TVE#1. Therefore bit 59 is part of the
 * indicator.
 */
#define ASNIND		0x0C00
#define ASNMASK		0xFF00

/* Power Bus Common Queue Registers
 * All PBCQ and PBAIB registers are accessed via SCOM
 * NestBase = 4010C00 for PEC0
 *            4011000 for PEC1
 *            4011400 for PEC2
 * PCIBase  = D010800 for PE0
 *            E010800 for PE1
 *            F010800 for PE2
 *
 * Some registers are shared amongst all of the stacks and will only
 * have 1 copy. Other registers are implemented one per stack.
 * Registers that are duplicated will have an additional offset
 * of “StackBase” so that they have a unique address.
 * Stackoffset = 00000040 for Stack0
 *             = 00000080 for Stack1
 *             = 000000C0 for Stack2
 */
static int64_t enable_capi_mode(struct phb4 *p, uint64_t pe_number,
				uint32_t capp_eng)
{
	uint64_t addr, reg, start_addr, end_addr, stq_eng, dma_eng;
	uint64_t mbt0, mbt1;
	int i, window_num = -1;

	/* CAPP Control Register */
	xscom_read(p->chip_id, p->pe_xscom + XPEC_NEST_CAPP_CNTL, &reg);
	if (reg & PPC_BIT(0)) {
		PHBDBG(p, "Already in CAPP mode\n");
	}

	for (i = 0; i < 500000; i++) {
		/* PBCQ General Status Register */
		xscom_read(p->chip_id,
			   p->pe_stk_xscom + XPEC_NEST_STK_PBCQ_STAT,
			   &reg);
		if (!(reg & 0xC000000000000000UL))
			break;
		time_wait_us(10);
	}
	if (reg & 0xC000000000000000UL) {
		PHBERR(p, "CAPP: Timeout waiting for pending transaction\n");
		return OPAL_HARDWARE;
	}

	stq_eng = 0x0000000000000000ULL;
	dma_eng = 0x0000000000000000ULL;
	if (p->index == CAPP0_PHB_INDEX) {
		/* PBCQ is operating as a x16 stack
		 * - The maximum number of engines give to CAPP will be
		 * 14 and will be assigned in the order of STQ 15 to 2.
		 * - 0-47 (Read machines) are available for capp use.
		 */
		stq_eng = 0x000E000000000000ULL; /* 14 CAPP msg engines */
		dma_eng = 0x0000FFFFFFFFFFFFULL; /* 48 CAPP Read machines */
	}

	if (p->index == CAPP1_PHB_INDEX) {
		/* Check if PEC is in x8 or x16 mode */
		addr = XPEC_P9_PCI_CPLT_CONF1 + 2 * XPEC_PCI_CPLT_OFFSET;
		xscom_read(p->chip_id, addr, &reg);
		if ((reg & XPEC_P9_PCI_IOVALID_MASK) == XPEC_P9_PCI_IOVALID_X16) {
			/* PBCQ is operating as a x16 stack
			 * - The maximum number of engines give to CAPP will be
			 * 14 and will be assigned in the order of STQ 15 to 2.
			 * - 0-47 (Read machines) are available for capp use.
			 */
			stq_eng = 0x000E000000000000ULL;
			dma_eng = 0x0000FFFFFFFFFFFFULL;
		} else {

			/* PBCQ is operating as a x8 stack
			 * - The maximum number of engines given to CAPP should
			 * be 6 and will be assigned in the order of 7 to 2.
			 * - 0-30 (Read machines) are available for capp use.
			 */
			stq_eng = 0x0006000000000000ULL;
			/* 30 Read machines for CAPP Minus 20-27 for DMA */
			dma_eng = 0x0000FFFFF00E0000ULL;
		}
	}

	if (capp_eng & CAPP_MIN_STQ_ENGINES)
		stq_eng = 0x0002000000000000ULL; /* 2 capp msg engines */

	/* CAPP Control Register. Enable CAPP Mode */
	reg = 0x8000000000000000ULL; /* PEC works in CAPP Mode */
	reg |= stq_eng;
	if (capp_eng & CAPP_MAX_DMA_READ_ENGINES)
		dma_eng = 0x0000F00000000000ULL; /* 4 CAPP Read machines */
	reg |= dma_eng;
	xscom_write(p->chip_id, p->pe_xscom + XPEC_NEST_CAPP_CNTL, reg);

	/* PEC2 has 3 ETU's + 16 pci lanes that can operate as x16,
	 * x8+x8 (bifurcated) or x8+x4+x4 (trifurcated) mode. When
	 * Mellanox CX5 card is attached to stack0 of this PEC, indicated by
	 * request to allocate CAPP_MAX_DMA_READ_ENGINES; we tweak the default
	 * dma-read engines allocations to maximize the DMA read performance
	 */
	if ((p->index == CAPP1_PHB_INDEX) &&
	    (capp_eng & CAPP_MAX_DMA_READ_ENGINES))
		phb4_pec2_dma_engine_realloc(p);

	/* PCI to PB data movement ignores the PB init signal. */
	xscom_write_mask(p->chip_id, p->pe_xscom + XPEC_NEST_PBCQ_HW_CONFIG,
			 XPEC_NEST_PBCQ_HW_CONFIG_PBINIT,
			 XPEC_NEST_PBCQ_HW_CONFIG_PBINIT);

	/* If pump mode is enabled don't do nodal broadcasts.
	 */
	xscom_read(p->chip_id, PB_CENT_HP_MODE_CURR, &reg);
	if (reg & PB_CFG_PUMP_MODE) {
		reg = XPEC_NEST_PBCQ_HW_CONFIG_DIS_NODAL;
		reg |= XPEC_NEST_PBCQ_HW_CONFIG_DIS_RNNN;
		xscom_write_mask(p->chip_id,
				 p->pe_xscom + XPEC_NEST_PBCQ_HW_CONFIG,
				 reg, reg);
	}

	/* PEC Phase 4 (PHB) registers adjustment
	 * Inbound CAPP traffic: The CAPI can send both CAPP packets and
	 * I/O packets. A PCIe packet is indentified as a CAPP packet in
	 * the PHB if the PCIe address matches either the CAPI
	 * Compare/Mask register or its NBW Compare/Mask register.
	 */

	/*
	 * Bit [0:7] XSL_DSNCTL[capiind]
	 * Init_26 - CAPI Compare/Mask
	 */
	out_be64(p->regs + PHB_CAPI_CMPM,
		 ((u64)CAPIIND << 48) |
		 ((u64)CAPIMASK << 32) | PHB_CAPI_CMPM_ENABLE);

	/* PB AIB Hardware Control Register
	 * Wait 32 PCI clocks for a credit to become available
	 * before rejecting.
	 */
	xscom_read(p->chip_id, p->pci_xscom + XPEC_PCI_PBAIB_HW_CONFIG, &reg);
	reg |= PPC_BITMASK(40, 42);
	if (p->index == CAPP1_PHB_INDEX)
		reg |= PPC_BIT(30);
	xscom_write(p->chip_id, p->pci_xscom + XPEC_PCI_PBAIB_HW_CONFIG, reg);

	/* non-translate/50-bit mode */
	out_be64(p->regs + PHB_NXLATE_PREFIX, 0x0000000000000000Ull);

	/* set tve no translate mode allow mmio window */
	memset(p->tve_cache, 0x0, sizeof(p->tve_cache));

	/*
	 * In 50-bit non-translate mode, the fields of the TVE are
	 * used to perform an address range check. In this mode TCE
	 * Table Size(0) must be a '1' (TVE[51] = 1)
	 *      PCI Addr(49:24) >= TVE[52:53]+TVE[0:23] and
	 *      PCI Addr(49:24) < TVE[54:55]+TVE[24:47]
	 *
	 * TVE[51] = 1
	 * TVE[56] = 1: 50-bit Non-Translate Mode Enable
	 * TVE[0:23] = 0x000000
	 * TVE[24:47] = 0xFFFFFF
	 *
	 * capi dma mode: CAPP DMA mode needs access to all of memory
	 * capi mode: Allow address range (bit 14 = 1)
	 *            0x0002000000000000: 0x0002FFFFFFFFFFFF
	 *            TVE[52:53] = '10' and TVE[54:55] = '10'
	 */

	/* TVT#0: CAPI window + DMA, all memory */
	start_addr = 0ull;
	end_addr   = 0x0003ffffffffffffull;
	p->tve_cache[pe_number * 2] =
		tve_encode_50b_noxlate(start_addr, end_addr);

	/* TVT#1: CAPI window + DMA, all memory, in bypass mode */
	start_addr = (1ull << 59);
	end_addr   = start_addr + 0x0003ffffffffffffull;
	p->tve_cache[pe_number * 2 + 1] =
		tve_encode_50b_noxlate(start_addr, end_addr);

	phb4_ioda_sel(p, IODA3_TBL_TVT, 0, true);
	for (i = 0; i < p->tvt_size; i++)
		out_be64(p->regs + PHB_IODA_DATA0, p->tve_cache[i]);

	/*
	 * Since TVT#0 is in by-pass mode, disable 32-bit MSI, as a
	 * DMA write targeting 0x00000000FFFFxxxx would be interpreted
	 * as a 32-bit MSI
	 */
	reg = in_be64(p->regs + PHB_PHB4_CONFIG);
	reg &= ~PHB_PHB4C_32BIT_MSI_EN;
	out_be64(p->regs + PHB_PHB4_CONFIG, reg);

	/* set mbt bar to pass capi mmio window and keep the other
	 * mmio values
	 */
	mbt0 = IODA3_MBT0_ENABLE | IODA3_MBT0_TYPE_M64 |
	       SETFIELD(IODA3_MBT0_MODE, 0ull, IODA3_MBT0_MODE_SINGLE_PE) |
	       SETFIELD(IODA3_MBT0_MDT_COLUMN, 0ull, 0) |
	       (0x0002000000000000ULL & IODA3_MBT0_BASE_ADDR);

	mbt1 = IODA3_MBT1_ENABLE |
	       (0x00ff000000000000ULL & IODA3_MBT1_MASK) |
	       SETFIELD(IODA3_MBT1_SINGLE_PE_NUM, 0ull, pe_number);

	for (i = 0; i < p->mbt_size; i++) {
		/* search if the capi mmio window is already present */
		if ((p->mbt_cache[i][0] == mbt0) &&
		    (p->mbt_cache[i][1] == mbt1))
			break;

		/* search a free entry */
		if ((window_num == -1) &&
		   ((!(p->mbt_cache[i][0] & IODA3_MBT0_ENABLE)) &&
		    (!(p->mbt_cache[i][1] & IODA3_MBT1_ENABLE))))
			window_num = i;
	}

	if (window_num >= 0 && i == p->mbt_size) {
		/* no capi mmio window found, so add it */
		p->mbt_cache[window_num][0] = mbt0;
		p->mbt_cache[window_num][1] = mbt1;

		phb4_ioda_sel(p, IODA3_TBL_MBT, window_num << 1, true);
		out_be64(p->regs + PHB_IODA_DATA0, mbt0);
		out_be64(p->regs + PHB_IODA_DATA0, mbt1);
	} else if (i == p->mbt_size) {
		/* mbt cache full, this case should never happen */
		PHBERR(p, "CAPP: Failed to add CAPI mmio window\n");
	} else {
		/* duplicate entry. Nothing to do */
	}

	phb4_init_capp_errors(p);

	phb4_init_capp_regs(p, capp_eng);

	if (!chiptod_capp_timebase_sync(p->chip_id, CAPP_TFMR,
					CAPP_TB,
					PHB4_CAPP_REG_OFFSET(p)))
		PHBERR(p, "CAPP: Failed to sync timebase\n");

	/* set callbacks to handle HMI events */
	capi_ops.get_capp_info = &phb4_get_capp_info;

	return OPAL_SUCCESS;
}


static int64_t phb4_init_capp(struct phb4 *p)
{
	struct capp *capp;
	int rc;

	if (p->index != CAPP0_PHB_INDEX &&
	    p->index != CAPP1_PHB_INDEX)
		return OPAL_UNSUPPORTED;

	capp = zalloc(sizeof(struct capp));
	if (capp == NULL)
		return OPAL_NO_MEM;

	if (p->index == CAPP0_PHB_INDEX) {
		capp->capp_index = 0;
		capp->capp_xscom_offset = 0;

	} else if (p->index == CAPP1_PHB_INDEX) {
		capp->capp_index = 1;
		capp->capp_xscom_offset = CAPP1_REG_OFFSET;
	}

	capp->attached_pe = phb4_get_reserved_pe_number(&p->phb);
	capp->chip_id = p->chip_id;

	/* Load capp microcode into the capp unit */
	rc = load_capp_ucode(p);

	if (rc == OPAL_SUCCESS)
		p->capp = capp;
	else
		free(capp);

	return rc;
}

static int64_t phb4_set_capi_mode(struct phb *phb, uint64_t mode,
				  uint64_t pe_number)
{
	struct phb4 *p = phb_to_phb4(phb);
	struct proc_chip *chip = get_chip(p->chip_id);
	struct capp *capp = p->capp;
	uint64_t reg, ret;

	/* No CAPI on P10. OpenCAPI only */
	if (is_phb5())
		return OPAL_UNSUPPORTED;

	/* cant do a mode switch when capp is in recovery mode */
	ret = capp_xscom_read(capp, CAPP_ERR_STATUS_CTRL, &reg);
	if (ret != OPAL_SUCCESS)
		return ret;

	if ((reg & PPC_BIT(0)) && (!(reg & PPC_BIT(1)))) {
		PHBDBG(p, "CAPP: recovery in progress\n");
		return OPAL_BUSY;
	}


	switch (mode) {

	case OPAL_PHB_CAPI_MODE_DMA: /* Enabled by default on p9 */
	case OPAL_PHB_CAPI_MODE_SNOOP_ON:
		/* nothing to do on P9 if CAPP is already enabled */
		ret = p->capp->phb ? OPAL_SUCCESS : OPAL_UNSUPPORTED;
		break;

	case OPAL_PHB_CAPI_MODE_SNOOP_OFF:
		ret = p->capp->phb ? OPAL_UNSUPPORTED : OPAL_SUCCESS;
		break;

	case OPAL_PHB_CAPI_MODE_PCIE:
		if (p->flags & PHB4_CAPP_DISABLE) {
			/* We are in middle of a CAPP disable */
			ret = OPAL_BUSY;

		} else if (capp->phb) {
			/* Kick start a creset */
			p->flags |= PHB4_CAPP_DISABLE;
			PHBINF(p, "CAPP: PCIE mode needs a cold-reset\n");
			/* Kick off the pci state machine */
			ret = phb4_creset(phb->slot);
			ret = ret > 0 ? OPAL_BUSY : ret;

		} else {
			/* PHB already in PCI mode */
			ret = OPAL_SUCCESS;
		}
		break;

	case OPAL_PHB_CAPI_MODE_CAPI: /* Fall Through */
	case OPAL_PHB_CAPI_MODE_DMA_TVT1:
		/* Make sure that PHB is not disabling CAPP */
		if (p->flags & PHB4_CAPP_DISABLE) {
			PHBERR(p, "CAPP: Disable in progress\n");
			ret = OPAL_BUSY;
			break;
		}

		/* Check if ucode is available */
		if (!capp_ucode_loaded(chip, p->index)) {
			PHBERR(p, "CAPP: ucode not loaded\n");
			ret = OPAL_RESOURCE;
			break;
		}

		/*
		 * Mark the CAPP attached to the PHB right away so that
		 * if a MCE happens during CAPP init we can handle it.
		 * In case of an error in CAPP init we remove the PHB
		 * from the attached_mask later.
		 */
		capp->phb = phb;
		capp->attached_pe = pe_number;

		if (mode == OPAL_PHB_CAPI_MODE_DMA_TVT1)
			ret = enable_capi_mode(p, pe_number,
					       CAPP_MIN_STQ_ENGINES |
					       CAPP_MAX_DMA_READ_ENGINES);

		else
			ret = enable_capi_mode(p, pe_number,
					       CAPP_MAX_STQ_ENGINES |
					       CAPP_MIN_DMA_READ_ENGINES);
		if (ret == OPAL_SUCCESS) {
			/* register notification on system shutdown */
			opal_add_host_sync_notifier(&phb4_host_sync_reset, p);

		} else {
			/* In case of an error mark the PHB detached */
			capp->phb = NULL;
			capp->attached_pe = phb4_get_reserved_pe_number(phb);
		}
		break;

	default:
		ret = OPAL_UNSUPPORTED;
		break;
	};

	return ret;
}

static void phb4_p2p_set_initiator(struct phb4 *p, uint16_t pe_number)
{
	uint64_t tve;
	uint16_t window_id = (pe_number << 1) + 1;

	/*
	 * Initiator needs access to the MMIO space of the target,
	 * which is well beyond the 'normal' memory area. Set its TVE
	 * with no range checking.
	 */
	PHBDBG(p, "Setting TVE#1 for peer-to-peer for pe %d\n", pe_number);
	tve = PPC_BIT(51);
	phb4_ioda_sel(p, IODA3_TBL_TVT, window_id, false);
	out_be64(p->regs + PHB_IODA_DATA0, tve);
	p->tve_cache[window_id] = tve;
}

static void phb4_p2p_set_target(struct phb4 *p, bool enable)
{
	uint64_t val;

	/*
	 * Enabling p2p on a target PHB reserves an outbound (as seen
	 * from the CPU) store queue for p2p
	 */
	PHBDBG(p, "%s peer-to-peer\n", (enable ? "Enabling" : "Disabling"));
	xscom_read(p->chip_id,
		p->pe_stk_xscom + XPEC_NEST_STK_PBCQ_MODE, &val);
	if (enable)
		val |= XPEC_NEST_STK_PBCQ_MODE_P2P;
	else
		val &= ~XPEC_NEST_STK_PBCQ_MODE_P2P;
	xscom_write(p->chip_id,
		p->pe_stk_xscom + XPEC_NEST_STK_PBCQ_MODE, val);
}

static void phb4_set_p2p(struct phb *phb, uint64_t mode, uint64_t flags,
			uint16_t pe_number)
{
	struct phb4 *p = phb_to_phb4(phb);

	switch (mode) {
	case OPAL_PCI_P2P_INITIATOR:
		if (flags & OPAL_PCI_P2P_ENABLE)
			phb4_p2p_set_initiator(p, pe_number);
		/*
		 * When disabling p2p on the initiator, we should
		 * reset the TVE to its default bypass setting, but it
		 * is more easily done from the OS, as it knows the
		 * the start and end address and there's already an
		 * opal call for it, so let linux handle it.
		 */
		break;
	case OPAL_PCI_P2P_TARGET:
		phb4_p2p_set_target(p, !!(flags & OPAL_PCI_P2P_ENABLE));
		break;
	default:
		assert(0);
	}
}

static int64_t phb4_set_capp_recovery(struct phb *phb)
{
	struct phb4 *p = phb_to_phb4(phb);

	if (p->flags & PHB4_CAPP_RECOVERY)
		return 0;

	/* set opal event flag to indicate eeh condition */
	opal_update_pending_evt(OPAL_EVENT_PCI_ERROR,
				OPAL_EVENT_PCI_ERROR);

	p->flags |= PHB4_CAPP_RECOVERY;

	return 0;
}

/*
 * Return the address out of a PBCQ Tunnel Bar register.
 */
static void phb4_get_tunnel_bar(struct phb *phb, uint64_t *addr)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t val;

	xscom_read(p->chip_id, p->pe_stk_xscom + XPEC_NEST_STK_TUNNEL_BAR,
		   &val);
	*addr = val >> 8;
}

/*
 * Set PBCQ Tunnel Bar register.
 * Store addr bits [8:50] in PBCQ Tunnel Bar register bits [0:42].
 * Note that addr bits [8:50] must also match PSL_TNR_ADDR[8:50].
 * Reset register if val == 0.
 *
 * This interface is required to let device drivers set the Tunnel Bar
 * value of their choice.
 *
 * Compatibility with older versions of linux, that do not set the
 * Tunnel Bar with phb4_set_tunnel_bar(), is ensured by enable_capi_mode(),
 * that will set the default value that used to be assumed.
 */
static int64_t phb4_set_tunnel_bar(struct phb *phb, uint64_t addr)
{
	struct phb4 *p = phb_to_phb4(phb);
	uint64_t mask = 0x00FFFFFFFFFFE000ULL;

	if (!addr) {
		/* Reset register */
		xscom_write(p->chip_id,
			    p->pe_stk_xscom + XPEC_NEST_STK_TUNNEL_BAR, addr);
		return OPAL_SUCCESS;
	}
	if ((addr & ~mask))
		return OPAL_PARAMETER;
	if (!(addr & mask))
		return OPAL_PARAMETER;

	xscom_write(p->chip_id, p->pe_stk_xscom + XPEC_NEST_STK_TUNNEL_BAR,
		    (addr & mask) << 8);
	return OPAL_SUCCESS;
}

static const struct phb_ops phb4_ops = {
	.cfg_read8		= phb4_pcicfg_read8,
	.cfg_read16		= phb4_pcicfg_read16,
	.cfg_read32		= phb4_pcicfg_read32,
	.cfg_write8		= phb4_pcicfg_write8,
	.cfg_write16		= phb4_pcicfg_write16,
	.cfg_write32		= phb4_pcicfg_write32,
	.get_reserved_pe_number	= phb4_get_reserved_pe_number,
	.device_init		= phb4_device_init,
	.device_remove		= NULL,
	.ioda_reset		= phb4_ioda_reset,
	.papr_errinjct_reset	= phb4_papr_errinjct_reset,
	.pci_reinit		= phb4_pci_reinit,
	.set_phb_mem_window	= phb4_set_phb_mem_window,
	.phb_mmio_enable	= phb4_phb_mmio_enable,
	.map_pe_mmio_window	= phb4_map_pe_mmio_window,
	.map_pe_dma_window	= phb4_map_pe_dma_window,
	.map_pe_dma_window_real = phb4_map_pe_dma_window_real,
	.set_option		= phb4_set_option,
	.get_option		= phb4_get_option,
	.set_xive_pe		= phb4_set_ive_pe,
	.get_msi_32		= phb4_get_msi_32,
	.get_msi_64		= phb4_get_msi_64,
	.set_pe			= phb4_set_pe,
	.set_peltv		= phb4_set_peltv,
	.eeh_freeze_status	= phb4_eeh_freeze_status,
	.eeh_freeze_clear	= phb4_eeh_freeze_clear,
	.eeh_freeze_set		= phb4_eeh_freeze_set,
	.next_error		= phb4_eeh_next_error,
	.err_inject		= phb4_err_inject,
	.get_diag_data2		= phb4_get_diag_data,
	.tce_kill		= phb4_tce_kill,
	.set_capi_mode		= phb4_set_capi_mode,
	.set_p2p		= phb4_set_p2p,
	.set_capp_recovery	= phb4_set_capp_recovery,
	.get_tunnel_bar         = phb4_get_tunnel_bar,
	.set_tunnel_bar         = phb4_set_tunnel_bar,
};

static void phb4_init_ioda3(struct phb4 *p)
{
	if (is_phb5()) {
		/*
		 * When ABT is on, the MSIs on the PHB use the PQ state bits
		 * of the IC and MSI triggers from the PHB are forwarded
		 * directly to the IC ESB page. However, the LSIs are still
		 * controlled locally on the PHB and LSI triggers use a
		 * special offset for trigger injection.
		 */
		if (phb_abt_mode(p)) {
			uint64_t mmio_base = xive2_get_esb_base(p->base_msi);

			PHBDBG(p, "Using ABT mode. ESB: 0x%016llx\n", mmio_base);

			/* Init_18 - Interrupt Notify Base Address */
			out_be64(p->regs + PHB_INT_NOTIFY_ADDR,
				 PHB_INT_NOTIFY_ADDR_64K | mmio_base);

			/* Interrupt Notify Base Index is unused */
		} else {
			p->irq_port = xive2_get_notify_port(p->chip_id,
						XIVE_HW_SRC_PHBn(p->index));

			PHBDBG(p, "Using IC notif page at 0x%016llx\n",
						p->irq_port);

			/* Init_18 - Interrupt Notify Base Address */
			out_be64(p->regs + PHB_INT_NOTIFY_ADDR, p->irq_port);

			/* Init_19 - Interrupt Notify Base Index */
			out_be64(p->regs + PHB_INT_NOTIFY_INDEX,
				 xive2_get_notify_base(p->base_msi));
		}

	} else { /* p9 */
		p->irq_port = xive_get_notify_port(p->chip_id,
						   XIVE_HW_SRC_PHBn(p->index));
		/* Init_18 - Interrupt Notify Base Address */
		out_be64(p->regs + PHB_INT_NOTIFY_ADDR, p->irq_port);

		/* Init_19 - Interrupt Notify Base Index */
		out_be64(p->regs + PHB_INT_NOTIFY_INDEX,
			 xive_get_notify_base(p->base_msi));
	}

	/* Init_19x - Not in spec: Initialize source ID */
	PHBDBG(p, "Reset state SRC_ID: %016llx\n",
	       in_be64(p->regs + PHB_LSI_SOURCE_ID));
	out_be64(p->regs + PHB_LSI_SOURCE_ID,
		 SETFIELD(PHB_LSI_SRC_ID, 0ull, (p->num_irqs - 1) >> 3));

	/* Init_20 - RTT BAR */
	out_be64(p->regs + PHB_RTT_BAR, (u64) p->tbl_rtt | PHB_RTT_BAR_ENABLE);

	/* Init_21 - PELT-V BAR */
	out_be64(p->regs + PHB_PELTV_BAR,
		 (u64) p->tbl_peltv | PHB_PELTV_BAR_ENABLE);

	/* Init_22 - Setup M32 starting address */
	out_be64(p->regs + PHB_M32_START_ADDR, M32_PCI_START);

	/* Init_23 - Setup PEST BAR */
	out_be64(p->regs + PHB_PEST_BAR,
		 (u64)p->tbl_pest | PHB_PEST_BAR_ENABLE);

	/* Init_24 - CRW Base Address Reg */
	/* See enable_capi_mode() */

	if (is_phb4()) {
		/* Init_25 - ASN Compare/Mask - P9 only */
		out_be64(p->regs + PHB_ASN_CMPM, ((u64)ASNIND << 48) |
			 ((u64)ASNMASK << 32) | PHB_ASN_CMPM_ENABLE);
	}

	/* Init_26 - CAPI Compare/Mask */
	/* See enable_capi_mode() */
	/* if CAPP being disabled then reset CAPI Compare/Mask Register */
	if (p->flags & PHB4_CAPP_DISABLE)
		out_be64(p->regs + PHB_CAPI_CMPM, 0);

	/* Init_27 - PCIE Outbound upper address */
	out_be64(p->regs + PHB_M64_UPPER_BITS, 0);

	/* Init_28 - PHB4 Configuration */
	out_be64(p->regs + PHB_PHB4_CONFIG,
		 PHB_PHB4C_32BIT_MSI_EN |
		 PHB_PHB4C_64BIT_MSI_EN);

	/* Init_29 - At least 256ns delay according to spec. Do a dummy
	 * read first to flush posted writes
	 */
	in_be64(p->regs + PHB_PHB4_CONFIG);
	time_wait_us(2);

	/* Init_30..41 - On-chip IODA tables init */
	phb4_ioda_reset(&p->phb, false);
}

/* phb4_init_rc - Initialize the Root Complex config space
 */
static bool phb4_init_rc_cfg(struct phb4 *p)
{
	int64_t ecap, aercap;

	/* XXX Handle errors ? */

	/* Init_46:
	 *
	 * Set primary bus to 0, secondary to 1 and subordinate to 0xff
	 */
	phb4_pcicfg_write32(&p->phb, 0, PCI_CFG_PRIMARY_BUS, 0x00ff0100);

	/* Init_47 - Clear errors */
	/* see phb4_rc_err_clear() called below */

	/* Init_48
	 *
	 * PCIE Device control/status, enable error reporting, disable relaxed
	 * ordering, set MPS to 128 (see note), clear errors.
	 *
	 * Note: The doc recommends to set MPS to 512. This has proved to have
	 * some issues as it requires specific clamping of MRSS on devices and
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

	phb4_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DEVCTL,
			     PCICAP_EXP_DEVCTL_CE_REPORT	|
			     PCICAP_EXP_DEVCTL_NFE_REPORT	|
			     PCICAP_EXP_DEVCTL_FE_REPORT	|
			     PCICAP_EXP_DEVCTL_UR_REPORT	|
			     SETFIELD(PCICAP_EXP_DEVCTL_MPS, 0, PCIE_MPS_128B));

	/* Init_49 - Device Control/Status 2 */
	phb4_pcicfg_write16(&p->phb, 0, ecap + PCICAP_EXP_DCTL2,
			     SETFIELD(PCICAP_EXP_DCTL2_CMPTOUT, 0, 0x5) |
			     PCICAP_EXP_DCTL2_ARI_FWD);

	/* Init_50..54
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

	/* Disable some error reporting as per the PHB4 spec */
	phb4_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_UE_MASK,
			     PCIECAP_AER_UE_POISON_TLP		|
			     PCIECAP_AER_UE_COMPL_TIMEOUT	|
			     PCIECAP_AER_UE_COMPL_ABORT);

	/* Enable ECRC generation & checking */
	phb4_pcicfg_write32(&p->phb, 0, aercap + PCIECAP_AER_CAPCTL,
			     PCIECAP_AER_CAPCTL_ECRCG_EN	|
			     PCIECAP_AER_CAPCTL_ECRCC_EN);

	phb4_rc_err_clear(p);

	return true;
}

static void phb4_init_errors(struct phb4 *p)
{
	/* Init_55..63 - PBL errors */
	out_be64(p->regs + 0x1900,	0xffffffffffffffffull);
	out_be64(p->regs + 0x1908,	0x0000000000000000ull);
	out_be64(p->regs + 0x1920,	0x000000004d1780f8ull);
	out_be64(p->regs + 0x1928,	0x0000000000000000ull);
	out_be64(p->regs + 0x1930,	0xffffffffb2f87f07ull);
	out_be64(p->regs + 0x1940,	0x0000000000000000ull);
	out_be64(p->regs + 0x1948,	0x0000000000000000ull);
	out_be64(p->regs + 0x1950,	0x0000000000000000ull);
	out_be64(p->regs + 0x1958,	0x0000000000000000ull);

	/* Init_64..72 - REGB errors */
	out_be64(p->regs + 0x1c00,	0xffffffffffffffffull);
	out_be64(p->regs + 0x1c08,	0x0000000000000000ull);
	/* Enable/disable error status indicators that trigger irqs */
	if (p->has_link) {
		out_be64(p->regs + 0x1c20,	0x2130006efca8bc00ull);
		out_be64(p->regs + 0x1c30,	0xde1fff91035743ffull);
	} else {
		out_be64(p->regs + 0x1c20,	0x0000000000000000ull);
		out_be64(p->regs + 0x1c30,	0x0000000000000000ull);
	}
	out_be64(p->regs + 0x1c28,	0x0080000000000000ull);
	out_be64(p->regs + 0x1c40,	0x0000000000000000ull);
	out_be64(p->regs + 0x1c48,	0x0000000000000000ull);
	out_be64(p->regs + 0x1c50,	0x0000000000000000ull);
	out_be64(p->regs + 0x1c58,	0x0040000000000000ull);

	/* Init_73..81 - TXE errors */
	out_be64(p->regs + 0x0d08,	0x0000000000000000ull);

	/* Errata: Clear bit 17, otherwise a CFG write UR/CA will incorrectly
	 * freeze a "random" PE (whatever last PE did an MMIO)
	 */
	if (is_phb5()) {
		out_be64(p->regs + 0x0d28,	0x0000500a00000000ull);
		out_be64(p->regs + 0x0d00,	0xffffffffffffffffull);
		out_be64(p->regs + 0x0d18,	0xffffff0fffffffffull);
		out_be64(p->regs + 0x0d30,	0xdff7af41f7ddffdfull);
	} else {
		out_be64(p->regs + 0x0d28,	0x0000000a00000000ull);
		if (phb4_is_dd20(p)) {
			out_be64(p->regs + 0x0d00,	0xf3acff0ff7ddfff0ull);
			out_be64(p->regs + 0x0d18,	0xf3acff0ff7ddfff0ull);
			out_be64(p->regs + 0x0d30,	0xdfffbd05f7ddfff0ull); /* XXX CAPI has diff. value */
		} else  {
			out_be64(p->regs + 0x0d00,	0xffffffffffffffffull);
			out_be64(p->regs + 0x0d18,	0xffffff0fffffffffull);
			out_be64(p->regs + 0x0d30,	0xdff7bd05f7ddfff0ull);
		}
	}

	out_be64(p->regs + 0x0d40,	0x0000000000000000ull);
	out_be64(p->regs + 0x0d48,	0x0000000000000000ull);
	out_be64(p->regs + 0x0d50,	0x0000000000000000ull);
	out_be64(p->regs + 0x0d58,	0x0000000000000000ull);

	/* Init_82..90 - RXE_ARB errors */
	out_be64(p->regs + 0x0d80,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0d88,	0x0000000000000000ull);
	out_be64(p->regs + 0x0d98,	0xfffffffffbffffffull);
	out_be64(p->regs + 0x0da8,	0xc00018b801000060ull);
	/*
	 * Errata ER20161123 says we should set the top two bits in
	 * 0x0db0 but this causes config space accesses which don't
	 * get a response to fence the PHB. This breaks probing,
	 * hence we don't set them here.
	 */
	out_be64(p->regs + 0x0db0,	0x3bffd703fa7fbf8full); /* XXX CAPI has diff. value */
	out_be64(p->regs + 0x0dc0,	0x0000000000000000ull);
	out_be64(p->regs + 0x0dc8,	0x0000000000000000ull);
	out_be64(p->regs + 0x0dd0,	0x0000000000000000ull);
	out_be64(p->regs + 0x0dd8,	0x0000000004000000ull);

	/* Init_91..99 - RXE_MRG errors */
	out_be64(p->regs + 0x0e00,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0e08,	0x0000000000000000ull);
	out_be64(p->regs + 0x0e18,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0e28,	0x0000600000000000ull);
	out_be64(p->regs + 0x0e30,	0xfffffeffff7fff57ull);
	out_be64(p->regs + 0x0e40,	0x0000000000000000ull);
	out_be64(p->regs + 0x0e48,	0x0000000000000000ull);
	out_be64(p->regs + 0x0e50,	0x0000000000000000ull);
	out_be64(p->regs + 0x0e58,	0x0000000000000000ull);

	/* Init_100..108 - RXE_TCE errors */
	out_be64(p->regs + 0x0e80,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0e88,	0x0000000000000000ull);
	out_be64(p->regs + 0x0e98,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0ea8,	0x60000000c0000000ull);
	out_be64(p->regs + 0x0eb0,	0x9faeffaf3fffffffull); /* XXX CAPI has diff. value */
	out_be64(p->regs + 0x0ec0,	0x0000000000000000ull);
	out_be64(p->regs + 0x0ec8,	0x0000000000000000ull);
	out_be64(p->regs + 0x0ed0,	0x0000000000000000ull);
	out_be64(p->regs + 0x0ed8,	0x0000000000000000ull);

	/* Init_109..117 - RXPHB errors */
	out_be64(p->regs + 0x0c80,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0c88,	0x0000000000000000ull);
	out_be64(p->regs + 0x0c98,	0xffffffffffffffffull);
	out_be64(p->regs + 0x0ca8,	0x0000004000000000ull);
	out_be64(p->regs + 0x0cb0,	0x35777033ff000000ull); /* XXX CAPI has diff. value */
	out_be64(p->regs + 0x0cc0,	0x0000000000000000ull);
	out_be64(p->regs + 0x0cc8,	0x0000000000000000ull);
	out_be64(p->regs + 0x0cd0,	0x0000000000000000ull);
	out_be64(p->regs + 0x0cd8,	0x0000000000000000ull);

	/* Init_118..121 - LEM */
	out_be64(p->regs + 0x0c00,	0x0000000000000000ull);
	if (phb4_is_dd20(p)) {
		out_be64(p->regs + 0x0c30,	0xf3ffffffffffffffull);
		out_be64(p->regs + 0x0c38,	0xf3ffffffffffffffull);
	} else {
		out_be64(p->regs + 0x0c30,	0xffffffffffffffffull);
		out_be64(p->regs + 0x0c38,	0xffffffffffffffffull);
	}
	out_be64(p->regs + 0x0c40,	0x0000000000000000ull);
}


static bool phb4_wait_dlp_reset(struct phb4 *p)
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
#define DLP_RESET_ATTEMPTS	200

	PHBDBG(p, "Waiting for DLP PG reset to complete...\n");
	for (i = 0; i < DLP_RESET_ATTEMPTS; i++) {
		val = in_be64(p->regs + PHB_PCIE_DLP_TRAIN_CTL);
		if (!(val & PHB_PCIE_DLP_DL_PGRESET))
			break;
		time_wait_ms(1);
	}
	if (val & PHB_PCIE_DLP_DL_PGRESET) {
		PHBERR(p, "Timeout waiting for DLP PG reset !\n");
		return false;
	}
	return true;
}
static void phb4_init_hw(struct phb4 *p)
{
	uint64_t val, creset;

	PHBDBG(p, "Initializing PHB...\n");

	/* Init_1 - Sync reset
	 *
	 * At this point we assume the PHB has already been reset.
	 */

	/* Init_2 - Mask FIRs */
	out_be64(p->regs + PHB_LEM_ERROR_MASK,			0xffffffffffffffffull);

	/* Init_3 - TCE tag enable */
	out_be64(p->regs + PHB_TCE_TAG_ENABLE,			0xffffffffffffffffull);

	/* Init_4 - PCIE System Configuration Register
	 *
	 * Adjust max speed based on system config
	 */
	val = in_be64(p->regs + PHB_PCIE_SCR);
	PHBDBG(p, "Default system config: 0x%016llx\n", val);
	val = SETFIELD(PHB_PCIE_SCR_MAXLINKSPEED, val, p->max_link_speed);
	out_be64(p->regs + PHB_PCIE_SCR, val);
	PHBDBG(p, "New system config    : 0x%016llx\n",
	       in_be64(p->regs + PHB_PCIE_SCR));

	/* Init_5 - deassert CFG reset */
	creset = in_be64(p->regs + PHB_PCIE_CRESET);
	PHBDBG(p, "Initial PHB CRESET is 0x%016llx\n", creset);
	creset &= ~PHB_PCIE_CRESET_CFG_CORE;
	out_be64(p->regs + PHB_PCIE_CRESET,			creset);

	/* Init_6..13 - PCIE DLP Lane EQ control */
	if (p->lane_eq) {
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL0, be64_to_cpu(p->lane_eq[0]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL1, be64_to_cpu(p->lane_eq[1]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL2, be64_to_cpu(p->lane_eq[2]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL3, be64_to_cpu(p->lane_eq[3]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL40, be64_to_cpu(p->lane_eq[4]));
		out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL41, be64_to_cpu(p->lane_eq[5]));
		if (is_phb5()) {
			out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL50, be64_to_cpu(p->lane_eq[6]));
			out_be64(p->regs + PHB_PCIE_LANE_EQ_CNTL51, be64_to_cpu(p->lane_eq[7]));
		}
	}
	if (!p->lane_eq_en) {
		/* Read modify write and set to 2 bits */
		PHBDBG(p, "LINK: Disabling Lane EQ\n");
		val = in_be64(p->regs + PHB_PCIE_DLP_CTL);
		val |= PHB_PCIE_DLP_CTL_BYPASS_PH2 | PHB_PCIE_DLP_CTL_BYPASS_PH3;
		out_be64(p->regs + PHB_PCIE_DLP_CTL, val);
	}

	if (is_phb5()) {
		/* disable scaled flow control for now. SW527785 */
		PHBDBG(p, "LINK: Disabling scaled flow control\n");
		val = in_be64(p->regs + PHB_PCIE_DLP_CTL);
		val |= PHB_PCIE_DLP_CTL_SFC_DISABLE;
		out_be64(p->regs + PHB_PCIE_DLP_CTL, val);

		/* lane equalization settings need to be tuned on P10 */
		out_be64(p->regs + PHB_PCIE_PDL_PHY_EQ_CNTL,
			 0x80F4FFFFFF0F9C00);
	}

	/* Init_14 - Clear link training */
	phb4_pcicfg_write32(&p->phb, 0, 0x78,
			    0x07FE0000 | p->max_link_speed);

	/* Init_15 - deassert cores reset */
	/*
	 * Lift the PHB resets but not PERST, this will be lifted
	 * later by the initial PERST state machine
	 */
	creset &= ~(PHB_PCIE_CRESET_TLDLP | PHB_PCIE_CRESET_PBL);
	creset |= PHB_PCIE_CRESET_PIPE_N;
	out_be64(p->regs + PHB_PCIE_CRESET,			   creset);

	/* Init_16 - Wait for DLP PGRESET to clear */
	if (!phb4_wait_dlp_reset(p))
		goto failed;

	/* Init_17 - PHB Control */
	val = PHB_CTRLR_IRQ_PGSZ_64K;
	val |= PHB_CTRLR_TCE_CLB_DISABLE; // HW557787 circumvention
	val |= SETFIELD(PHB_CTRLR_TVT_ADDR_SEL, 0ull, TVT_2_PER_PE);
	if (phb_pq_disable(p))
		val |= PHB_CTRLR_IRQ_PQ_DISABLE;
	if (phb_abt_mode(p))
		val |= PHB_CTRLR_IRQ_ABT_MODE;
	if (phb_can_store_eoi(p)) {
		val |= PHB_CTRLR_IRQ_STORE_EOI;
		PHBDBG(p, "store EOI is enabled\n");
	}

	if (!pci_eeh_mmio)
		val |= PHB_CTRLR_MMIO_EEH_DISABLE;

	out_be64(p->regs + PHB_CTRLR, val);

	/* Init_18..41 - Architected IODA3 inits */
	phb4_init_ioda3(p);

	/* Init_42..45 - Clear DLP error logs */
	out_be64(p->regs + 0x1aa0,			0xffffffffffffffffull);
	out_be64(p->regs + 0x1aa8,			0xffffffffffffffffull);
	out_be64(p->regs + 0x1ab0,			0xffffffffffffffffull);
	out_be64(p->regs + 0x1ab8,			0x0);


	/* Init_46..54 : Init root complex config space */
	if (!phb4_init_rc_cfg(p))
		goto failed;

	/* Init_55..121  : Setup error registers */
	phb4_init_errors(p);

	/* Init_122..123 : Wait for link
	 * NOTE: At this point the spec waits for the link to come up. We
	 * don't bother as we are doing a PERST soon.
	 */

	/* Init_124 :  NBW. XXX TODO */
	/* See enable_capi_mode() */

	/* Init_125 : Setup PCI command/status on root complex
	 * I don't know why the spec does this now and not earlier, so
	 * to be sure to get it right we might want to move it to the freset
	 * state machine, though the generic PCI layer will probably do
	 * this anyway (ie, enable MEM, etc... in the RC)

	 */
	phb4_pcicfg_write16(&p->phb, 0, PCI_CFG_CMD,
			    PCI_CFG_CMD_MEM_EN |
			    PCI_CFG_CMD_BUS_MASTER_EN);

	/* Clear errors */
	phb4_pcicfg_write16(&p->phb, 0, PCI_CFG_STAT,
			    PCI_CFG_STAT_SENT_TABORT |
			    PCI_CFG_STAT_RECV_TABORT |
			    PCI_CFG_STAT_RECV_MABORT |
			    PCI_CFG_STAT_SENT_SERR |
			    PCI_CFG_STAT_RECV_PERR);

	/* Init_126..130 - Re-enable error interrupts */
	phb4_int_unmask_all(p);

	/* Init_131 - Re-enable LEM error mask */
	out_be64(p->regs + PHB_LEM_ERROR_MASK,			0x0000000000000000ull);


	/* Init_132 - Enable DMA address speculation */
	out_be64(p->regs + PHB_TCE_SPEC_CTL,			0x0000000000000000ull);

	/* Init_133 - Timeout Control Register 1 */
	out_be64(p->regs + PHB_TIMEOUT_CTRL1,			0x0015150000150000ull);

	/* Init_134 - Timeout Control Register 2 */
	out_be64(p->regs + PHB_TIMEOUT_CTRL2,			0x0000151500000000ull);

	/* Init_135 - PBL Timeout Control Register */
	out_be64(p->regs + PHB_PBL_TIMEOUT_CTRL,		0x2013000000000000ull);

	/* Mark the PHB as functional which enables all the various sequences */
	p->broken = false;

	PHBDBG(p, "Initialization complete\n");

	return;

 failed:
	PHBERR(p, "Initialization failed\n");
	p->broken = true;
}

/* FIXME: Use scoms rather than MMIO incase we are fenced */
static bool phb4_read_capabilities(struct phb4 *p)
{
	uint64_t val;

	/* XXX Should make sure ETU is out of reset ! */

	/* Grab version and fit it in an int */
	val = phb4_read_reg_asb(p, PHB_VERSION);
	if (val == 0 || val == 0xffffffffffffffffUL) {
		PHBERR(p, "Failed to read version, PHB appears broken\n");
		return false;
	}

	p->rev = ((val >> 16) & 0x00ff0000) | (val & 0xffff);
	PHBDBG(p, "Core revision 0x%x\n", p->rev);

	/* Read EEH capabilities */
	val = in_be64(p->regs + PHB_PHB4_EEH_CAP);
	if (val == 0xffffffffffffffffUL) {
		PHBERR(p, "Failed to read EEH cap, PHB appears broken\n");
		return false;
	}
	p->max_num_pes = val >> 52;
	if (p->max_num_pes >= 512) {
		p->mrt_size = 16;
		p->mbt_size = 32;
		p->tvt_size = 1024;
	} else {
		p->mrt_size = 8;
		p->mbt_size = 16;
		p->tvt_size = 512;
	}

	val = in_be64(p->regs + PHB_PHB4_IRQ_CAP);
	if (val == 0xffffffffffffffffUL) {
		PHBERR(p, "Failed to read IRQ cap, PHB appears broken\n");
		return false;
	}
	p->num_irqs = val & 0xffff;

	/* This works for 512 PEs.  FIXME calculate for any hardware
	 * size returned above
	 */
	p->tbl_peltv_size = PELTV_TABLE_SIZE_MAX;

	p->tbl_pest_size = p->max_num_pes*16;

	PHBDBG(p, "Found %d max PEs and %d IRQs \n",
	       p->max_num_pes, p->num_irqs);

	return true;
}

static void phb4_allocate_tables(struct phb4 *p)
{
	uint32_t i;

	/* XXX Our current memalign implementation sucks,
	 *
	 * It will do the job, however it doesn't support freeing
	 * the memory and wastes space by always allocating twice
	 * as much as requested (size + alignment)
	 */
	p->tbl_rtt = local_alloc(p->chip_id, RTT_TABLE_SIZE, RTT_TABLE_SIZE);
	assert(p->tbl_rtt);
	for (i = 0; i < RTT_TABLE_ENTRIES; i++)
		p->tbl_rtt[i] = cpu_to_be16(PHB4_RESERVED_PE_NUM(p));

	p->tbl_peltv = local_alloc(p->chip_id, p->tbl_peltv_size, p->tbl_peltv_size);
	assert(p->tbl_peltv);
	memset(p->tbl_peltv, 0, p->tbl_peltv_size);

	p->tbl_pest = local_alloc(p->chip_id, p->tbl_pest_size, p->tbl_pest_size);
	assert(p->tbl_pest);
	memset(p->tbl_pest, 0, p->tbl_pest_size);
}

static void phb4_add_properties(struct phb4 *p)
{
	struct dt_node *np = p->phb.dt_node;
	uint32_t lsibase, icsp = get_ics_phandle();
	uint64_t m32b, m64b, m64s;

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

	/* "ranges", we only expose M32 (PHB4 doesn't do IO)
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
	dt_add_property_cells(np, "ibm,opal-num-pes", p->num_pes);
	dt_add_property_cells(np, "ibm,opal-reserved-pe",
			      PHB4_RESERVED_PE_NUM(p));
	dt_add_property_cells(np, "ibm,opal-msi-ranges",
			      p->base_msi, p->num_irqs - 8);
	/* M64 ranges start at 1 as MBT0 is used for M32 */
	dt_add_property_cells(np, "ibm,opal-available-m64-ranges",
			      1, p->mbt_size - 1);
	dt_add_property_cells(np, "ibm,supported-tce-sizes",
			      12, // 4K
			      16, // 64K
			      21, // 2M
			      30); // 1G

	/* Tell Linux about alignment limits for segment splits.
	 *
	 * XXX We currently only expose splits of 1 and "num PEs",
	 */
	dt_add_property_cells(np, "ibm,opal-m64-segment-splits",
			      /* Full split, number of segments: */
			      p->num_pes,
			      /* Encoding passed to the enable call */
			      OPAL_ENABLE_M64_SPLIT,
			      /* Alignement/size restriction in #bits*/
			      /* XXX VERIFY VALUE */
			      12,
			      /* Unused */
			      0,
			      /* single PE, number of segments: */
			      1,
			      /* Encoding passed to the enable call */
			      OPAL_ENABLE_M64_NON_SPLIT,
			      /* Alignement/size restriction in #bits*/
			      /* XXX VERIFY VALUE */
			      12,
			      /* Unused */
			      0);

	/* The interrupt maps will be generated in the RC node by the
	 * PCI code based on the content of this structure:
	 */
	lsibase = p->base_lsi;
	p->phb.lstate.int_size = 2;
	p->phb.lstate.int_val[0][0] = lsibase + PHB4_LSI_PCIE_INTA;
	p->phb.lstate.int_val[0][1] = 1;
	p->phb.lstate.int_val[1][0] = lsibase + PHB4_LSI_PCIE_INTB;
	p->phb.lstate.int_val[1][1] = 1;
	p->phb.lstate.int_val[2][0] = lsibase + PHB4_LSI_PCIE_INTC;
	p->phb.lstate.int_val[2][1] = 1;
	p->phb.lstate.int_val[3][0] = lsibase + PHB4_LSI_PCIE_INTD;
	p->phb.lstate.int_val[3][1] = 1;
	p->phb.lstate.int_parent[0] = icsp;
	p->phb.lstate.int_parent[1] = icsp;
	p->phb.lstate.int_parent[2] = icsp;
	p->phb.lstate.int_parent[3] = icsp;

	/* Indicators for variable tables */
	dt_add_property_cells(np, "ibm,opal-rtt-table",
		hi32((u64) p->tbl_rtt), lo32((u64) p->tbl_rtt), RTT_TABLE_SIZE);

	dt_add_property_cells(np, "ibm,opal-peltv-table",
		hi32((u64) p->tbl_peltv), lo32((u64) p->tbl_peltv),
		p->tbl_peltv_size);

	dt_add_property_cells(np, "ibm,opal-pest-table",
		hi32((u64)p->tbl_pest), lo32((u64)p->tbl_pest), p->tbl_pest_size);

	dt_add_property_cells(np, "ibm,phb-diag-data-size",
			      sizeof(struct OpalIoPhb4ErrorData));

	if (is_phb4()) {
		/* Indicate to Linux that CAPP timebase sync is supported */
		dt_add_property_string(np, "ibm,capp-timebase-sync", NULL);

		/* Tell Linux Compare/Mask indication values */
		dt_add_property_cells(np, "ibm,phb-indications", CAPIIND, ASNIND,
				      NBWIND);
	}
}

static bool phb4_calculate_windows(struct phb4 *p)
{
	const struct dt_property *prop;

	/* Get PBCQ MMIO windows from device-tree */
	prop = dt_require_property(p->phb.dt_node,
				   "ibm,mmio-windows", -1);
	assert(prop->len >= (2 * sizeof(uint64_t)));

	p->mm0_base = dt_property_get_u64(prop, 0);
	p->mm0_size = dt_property_get_u64(prop, 1);
	if (prop->len > 16) {
		p->mm1_base = dt_property_get_u64(prop, 2);
		p->mm1_size = dt_property_get_u64(prop, 3);
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

static void phb4_err_interrupt(struct irq_source *is, uint32_t isn)
{
	struct phb4 *p = is->data;

	PHBDBG(p, "Got interrupt 0x%08x\n", isn);

	/* mask the interrupt conditions to prevent it from re-firing */
	phb4_int_mask_active(p);

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
	phb4_set_err_pending(p, true);
}

static uint64_t phb4_lsi_attributes(struct irq_source *is __unused,
				uint32_t isn __unused)
{
#ifndef DISABLE_ERR_INTS
	struct phb4 *p = is->data;
	uint32_t idx = isn - p->base_lsi;

	if (idx == PHB4_LSI_PCIE_INF || idx == PHB4_LSI_PCIE_ER)
		return IRQ_ATTR_TARGET_OPAL | IRQ_ATTR_TARGET_RARE | IRQ_ATTR_TYPE_LSI;
#endif
	return IRQ_ATTR_TARGET_LINUX;
}

static char *phb4_lsi_name(struct irq_source *is, uint32_t isn)
{
	struct phb4 *p = is->data;
	uint32_t idx = isn - p->base_lsi;
	char buf[32];

	if (idx == PHB4_LSI_PCIE_INF)
		snprintf(buf, 32, "phb#%04x-inf", p->phb.opal_id);
	else if (idx == PHB4_LSI_PCIE_ER)
		snprintf(buf, 32, "phb#%04x-err", p->phb.opal_id);
	else
		assert(0); /* PCIe LSIs should never be directed to OPAL */

	return strdup(buf);
}

static const struct irq_source_ops phb4_lsi_ops = {
	.interrupt = phb4_err_interrupt,
	.attributes = phb4_lsi_attributes,
	.name = phb4_lsi_name,
};

static __be64 lane_eq_default[8] = {
	CPU_TO_BE64(0x5454545454545454UL), CPU_TO_BE64(0x5454545454545454UL),
	CPU_TO_BE64(0x5454545454545454UL), CPU_TO_BE64(0x5454545454545454UL),
	CPU_TO_BE64(0x7777777777777777UL), CPU_TO_BE64(0x7777777777777777UL),
	CPU_TO_BE64(0x7777777777777777UL), CPU_TO_BE64(0x7777777777777777UL),
};

static __be64 lane_eq_phb5_default[8] = {
	CPU_TO_BE64(0x4444444444444444UL), CPU_TO_BE64(0x4444444444444444UL),
	CPU_TO_BE64(0x4444444444444444UL), CPU_TO_BE64(0x4444444444444444UL),
	CPU_TO_BE64(0x4444444444444444UL), CPU_TO_BE64(0x4444444444444444UL),
	CPU_TO_BE64(0x9999999999999999UL), CPU_TO_BE64(0x9999999999999999UL),
};

static void phb4_create(struct dt_node *np)
{
	const struct dt_property *prop;
	struct phb4 *p;
	struct pci_slot *slot;
	size_t lane_eq_len, lane_eq_len_req;
	struct dt_node *iplp;
	char *path;
	uint32_t irq_base, irq_flags;
	int i, eq_reg_count;
	int chip_id;

	chip_id = dt_prop_get_u32(np, "ibm,chip-id");
	p = local_alloc(chip_id, sizeof(struct phb4), 8);
	assert(p);
	memset(p, 0x0, sizeof(struct phb4));

	/* Populate base stuff */
	p->index = dt_prop_get_u32(np, "ibm,phb-index");
	p->chip_id = chip_id;
	p->pec = dt_prop_get_u32(np, "ibm,phb-pec-index");
	p->regs = (void *)dt_get_address(np, 0, NULL);
	p->int_mmio = (void *)dt_get_address(np, 1, NULL);
	p->phb.dt_node = np;
	p->phb.ops = &phb4_ops;
	p->phb.phb_type = phb_type_pcie_v4;
	p->phb.scan_map = 0x1; /* Only device 0 to scan */

	if (!phb4_calculate_windows(p))
		return;

	/* Get the various XSCOM register bases from the device-tree */
	prop = dt_require_property(np, "ibm,xscom-bases", 5 * sizeof(uint32_t));
	p->pe_xscom = dt_property_get_cell(prop, 0);
	p->pe_stk_xscom = dt_property_get_cell(prop, 1);
	p->pci_xscom = dt_property_get_cell(prop, 2);
	p->pci_stk_xscom = dt_property_get_cell(prop, 3);
	p->etu_xscom = dt_property_get_cell(prop, 4);

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
	 * get a useful OPAL ID for it
	 */
	pci_register_phb(&p->phb, phb4_get_opal_id(p->chip_id, p->index));

	/* Create slot structure */
	slot = phb4_slot_create(&p->phb);
	if (!slot)
		PHBERR(p, "Cannot create PHB slot\n");

	/* Hello ! */
	path = dt_get_path(np);
	PHBINF(p, "Found %s @%p\n", path, p->regs);
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

	/* Obtain informatin about the PHB from the hardware directly */
	if (!phb4_read_capabilities(p))
		goto failed;

	p->max_link_speed = phb4_get_max_link_speed(p, np);
	p->max_link_width = phb4_get_max_link_width(p);
	PHBINF(p, "Max link speed: GEN%i, max link width %i\n",
	       p->max_link_speed, p->max_link_width);

	/* Check for lane equalization values from HB or HDAT */
	p->lane_eq_en = true;
	p->lane_eq = dt_prop_get_def_size(np, "ibm,lane-eq", NULL, &lane_eq_len);
	if (is_phb5())
		eq_reg_count = 8;
	else
		eq_reg_count = 6;
	lane_eq_len_req = eq_reg_count * 8;
	if (p->lane_eq) {
		if (lane_eq_len < lane_eq_len_req) {
			PHBERR(p, "Device-tree has ibm,lane-eq too short: %ld"
			       " (want %ld)\n", lane_eq_len, lane_eq_len_req);
			p->lane_eq = NULL;
		}
	} else {
		PHBDBG(p, "Using default lane equalization settings\n");
		if (is_phb5())
			p->lane_eq = lane_eq_phb5_default;
		else
			p->lane_eq = lane_eq_default;
	}
	if (p->lane_eq) {
		PHBDBG(p, "Override lane equalization settings:\n");
		for (i = 0 ; i < lane_eq_len_req/(8 * 2) ; i++)
			PHBDBG(p, "  0x%016llx 0x%016llx\n",
			       be64_to_cpu(p->lane_eq[2 * i]),
			       be64_to_cpu(p->lane_eq[2 * i + 1]));
	}

	/* Allocate a block of interrupts. We need to know if it needs
	 * 2K or 4K interrupts ... for now we just use 4K but that
	 * needs to be fixed
	 */
	if (is_phb5())
		irq_base = xive2_alloc_hw_irqs(p->chip_id, p->num_irqs, p->num_irqs);
	else
		irq_base = xive_alloc_hw_irqs(p->chip_id, p->num_irqs, p->num_irqs);
	if (irq_base == XIVE_IRQ_ERROR) {
		PHBERR(p, "Failed to allocate %d interrupt sources\n",
		       p->num_irqs);
		goto failed;
	}
	p->base_msi = irq_base;
	p->base_lsi = irq_base + p->num_irqs - 8;
	p->num_pes = p->max_num_pes;

	/* Allocate the SkiBoot internal in-memory tables for the PHB */
	phb4_allocate_tables(p);

	phb4_add_properties(p);

	/* Clear IODA3 cache */
	phb4_init_ioda_cache(p);

	/* Get the HW up and running */
	phb4_init_hw(p);

	/* init capp that might get attached to the phb */
	if (is_phb4())
		phb4_init_capp(p);

	/* Compute XIVE source flags depending on PHB revision */
	irq_flags = 0;
	if (phb_can_store_eoi(p))
		irq_flags |= XIVE_SRC_STORE_EOI;
	else
		irq_flags |= XIVE_SRC_TRIGGER_PAGE;

	if (is_phb5()) {
		/*
		 * Register sources with XIVE. If offloading is on, use the
		 * ESB pages of the XIVE IC for the MSI sources instead of the
		 * ESB pages of the PHB.
		 */
		if (phb_pq_disable(p) || phb_abt_mode(p)) {
			xive2_register_esb_source(p->base_msi, p->num_irqs - 8);
		} else {
			xive2_register_hw_source(p->base_msi,
						 p->num_irqs - 8, 16,
						 p->int_mmio, irq_flags,
						 NULL, NULL);
		}

		/*
		 * LSI sources always use the ESB pages of the PHB.
		 */
		xive2_register_hw_source(p->base_lsi, 8, 16,
					 p->int_mmio + ((p->num_irqs - 8) << 16),
					 XIVE_SRC_LSI | irq_flags, p, &phb4_lsi_ops);
	} else {
		/* Register all interrupt sources with XIVE */
		xive_register_hw_source(p->base_msi, p->num_irqs - 8, 16,
					p->int_mmio, irq_flags, NULL, NULL);

		xive_register_hw_source(p->base_lsi, 8, 16,
					p->int_mmio + ((p->num_irqs - 8) << 16),
					XIVE_SRC_LSI, p, &phb4_lsi_ops);
	}

	/* Platform additional setup */
	if (platform.pci_setup_phb)
		platform.pci_setup_phb(&p->phb, p->index);

	dt_add_property_string(np, "status", "okay");

	return;

 failed:
	p->broken = true;

	/* Tell Linux it's broken */
	dt_add_property_string(np, "status", "error");
}

static void phb4_probe_stack(struct dt_node *stk_node, uint32_t pec_index,
			     uint32_t nest_base, uint32_t pci_base)
{
	enum phys_map_type phys_mmio64, phys_mmio32, phys_xive_esb, phys_reg_spc;
	uint32_t pci_stack, nest_stack, etu_base, gcid, phb_num, stk_index;
	uint64_t val, phb_bar = 0, irq_bar = 0, bar_en;
	uint64_t mmio0_bar = 0, mmio0_bmask, mmio0_sz;
	uint64_t mmio1_bar = 0, mmio1_bmask, mmio1_sz;
	void *foo;
	__be64 mmio_win[4];
	unsigned int mmio_win_sz;
	struct dt_node *np;
	char *path;
	uint64_t capp_ucode_base;
	unsigned int max_link_speed;
	int rc;

	assert(is_phb5() || is_phb4()); /* Sanity check */

	gcid = dt_get_chip_id(stk_node);
	stk_index = dt_prop_get_u32(stk_node, "reg");
	phb_num = dt_prop_get_u32(stk_node, "ibm,phb-index");
	path = dt_get_path(stk_node);
	if (is_phb5()) {
		phys_mmio64 = PHB5_64BIT_MMIO;
		phys_mmio32 = PHB5_32BIT_MMIO;
		phys_xive_esb = PHB5_XIVE_ESB;
		phys_reg_spc = PHB5_REG_SPC;
		prlog(PR_INFO, "PHB: Chip %d Found PHB5 PBCQ%d Stack %d at %s\n",
		      gcid, pec_index, stk_index, path);
	} else {
		phys_mmio64 = PHB4_64BIT_MMIO;
		phys_mmio32 = PHB4_32BIT_MMIO;
		phys_xive_esb = PHB4_XIVE_ESB;
		phys_reg_spc = PHB4_REG_SPC;
		prlog(PR_INFO, "PHB: Chip %d Found PHB4 PBCQ%d Stack %d at %s\n",
		      gcid, pec_index, stk_index, path);
	}
	free(path);

	pci_stack = pci_base + 0x40 * (stk_index + 1);
	nest_stack = nest_base + 0x40 * (stk_index + 1);
	etu_base = pci_base + 0x100 + 0x40 * stk_index;

	prlog(PR_DEBUG, "PHB[%d:%d] X[PE]=0x%08x/0x%08x X[PCI]=0x%08x/0x%08x X[ETU]=0x%08x\n",
	      gcid, phb_num, nest_base, nest_stack, pci_base, pci_stack, etu_base);

	/* Default BAR enables */
	bar_en = 0;

	/* Initialize PHB register BAR */
	phys_map_get(gcid, phys_reg_spc, phb_num, &phb_bar, NULL);
	rc = xscom_write(gcid, nest_stack + XPEC_NEST_STK_PHB_REG_BAR,
			 phb_bar << 8);

	/* A scom error here probably indicates a defective/garded PHB */
	if (rc != OPAL_SUCCESS) {
		prerror("PHB[%d:%d] Unable to set PHB BAR. Error=%d\n",
		      gcid, phb_num, rc);
		return;
	}

	bar_en |= XPEC_NEST_STK_BAR_EN_PHB;

	/* Same with INT BAR (ESB) */
	phys_map_get(gcid, phys_xive_esb, phb_num, &irq_bar, NULL);
	xscom_write(gcid, nest_stack + XPEC_NEST_STK_IRQ_BAR, irq_bar << 8);
	bar_en |= XPEC_NEST_STK_BAR_EN_INT;


	/* Same with MMIO windows */
	phys_map_get(gcid, phys_mmio64, phb_num, &mmio0_bar, &mmio0_sz);
	mmio0_bmask =  (~(mmio0_sz - 1)) & 0x00FFFFFFFFFFFFFFULL;
	xscom_write(gcid, nest_stack + XPEC_NEST_STK_MMIO_BAR0, mmio0_bar << 8);
	xscom_write(gcid, nest_stack + XPEC_NEST_STK_MMIO_BAR0_MASK, mmio0_bmask << 8);

	phys_map_get(gcid, phys_mmio32, phb_num, &mmio1_bar, &mmio1_sz);
	mmio1_bmask =  (~(mmio1_sz - 1)) & 0x00FFFFFFFFFFFFFFULL;
	xscom_write(gcid, nest_stack + XPEC_NEST_STK_MMIO_BAR1, mmio1_bar << 8);
	xscom_write(gcid, nest_stack + XPEC_NEST_STK_MMIO_BAR1_MASK, mmio1_bmask << 8);

	/* Build MMIO windows list */
	mmio_win_sz = 0;
	if (mmio0_bar) {
		mmio_win[mmio_win_sz++] = cpu_to_be64(mmio0_bar);
		mmio_win[mmio_win_sz++] = cpu_to_be64(mmio0_sz);
		bar_en |= XPEC_NEST_STK_BAR_EN_MMIO0;
	}
	if (mmio1_bar) {
		mmio_win[mmio_win_sz++] = cpu_to_be64(mmio1_bar);
		mmio_win[mmio_win_sz++] = cpu_to_be64(mmio1_sz);
		bar_en |= XPEC_NEST_STK_BAR_EN_MMIO1;
	}

	/* Set the appropriate enables */
	xscom_read(gcid, nest_stack + XPEC_NEST_STK_BAR_EN, &val);
	val |= bar_en;
	xscom_write(gcid, nest_stack + XPEC_NEST_STK_BAR_EN, val);

	/* No MMIO windows ? Barf ! */
	if (mmio_win_sz == 0) {
		prerror("PHB[%d:%d] No MMIO windows enabled !\n", gcid, phb_num);
		return;
	}

	/* Clear errors in PFIR and NFIR */
	xscom_write(gcid, pci_stack + XPEC_PCI_STK_PCI_FIR, 0);
	xscom_write(gcid, nest_stack + XPEC_NEST_STK_PCI_NFIR, 0);

	/* Check ETU reset */
	xscom_read(gcid, pci_stack + XPEC_PCI_STK_ETU_RESET, &val);
	prlog_once(PR_DEBUG, "ETU reset: %llx\n", val);
	xscom_write(gcid, pci_stack + XPEC_PCI_STK_ETU_RESET, 0);
	time_wait_ms(1);

	// show we can read phb mmio space
	foo = (void *)(phb_bar + 0x800); // phb version register
	prlog_once(PR_DEBUG, "Version reg: 0x%016llx\n", in_be64(foo));

	/* Create PHB node */
	np = dt_new_addr(dt_root, "pciex", phb_bar);
	if (!np)
		return;

	if (is_phb5())
		dt_add_property_strings(np, "compatible", "ibm,power10-pciex", "ibm,ioda3-phb");
	else
		dt_add_property_strings(np, "compatible", "ibm,power9-pciex", "ibm,ioda3-phb");
	dt_add_property_strings(np, "device_type", "pciex");
	dt_add_property_u64s(np, "reg",
				phb_bar, 0x1000,
				irq_bar, 0x10000000);

	/* Everything else is handled later by skiboot, we just
	 * stick a few hints here
	 */
	dt_add_property_cells(np, "ibm,xscom-bases",
			      nest_base, nest_stack, pci_base, pci_stack, etu_base);
	dt_add_property(np, "ibm,mmio-windows", mmio_win, 8 * mmio_win_sz);
	dt_add_property_cells(np, "ibm,phb-index", phb_num);
	dt_add_property_cells(np, "ibm,phb-pec-index", pec_index);
	dt_add_property_cells(np, "ibm,phb-stack", stk_node->phandle);
	dt_add_property_cells(np, "ibm,phb-stack-index", stk_index);
	dt_add_property_cells(np, "ibm,chip-id", gcid);

	/* read the hub-id out of the pbcq node */
	if (dt_has_node_property(stk_node->parent, "ibm,hub-id", NULL)) {
		uint32_t hub_id;

		hub_id = dt_prop_get_u32(stk_node->parent, "ibm,hub-id");
		dt_add_property_cells(np, "ibm,hub-id", hub_id);
	}

	if (dt_has_node_property(stk_node->parent, "ibm,loc-code", NULL)) {
		const char *lc = dt_prop_get(stk_node->parent, "ibm,loc-code");
		dt_add_property_string(np, "ibm,loc-code", lc);
	}
	if (dt_has_node_property(stk_node, "ibm,lane-eq", NULL)) {
		size_t leq_size;
		const void *leq = dt_prop_get_def_size(stk_node, "ibm,lane-eq",
						       NULL, &leq_size);
		if (leq != NULL && leq_size >= 6 * 8)
			dt_add_property(np, "ibm,lane-eq", leq, leq_size);
	}
	if (dt_has_node_property(stk_node, "ibm,capp-ucode", NULL)) {
		capp_ucode_base = dt_prop_get_u32(stk_node, "ibm,capp-ucode");
		dt_add_property_cells(np, "ibm,capp-ucode", capp_ucode_base);
	}
	if (dt_has_node_property(stk_node, "ibm,max-link-speed", NULL)) {
		max_link_speed = dt_prop_get_u32(stk_node, "ibm,max-link-speed");
		dt_add_property_cells(np, "ibm,max-link-speed", max_link_speed);
	}
	if (is_phb4())
		dt_add_property_cells(np, "ibm,capi-flags",
				      OPAL_PHB_CAPI_FLAG_SNOOP_CONTROL);

	add_chip_dev_associativity(np);
}

static void phb4_probe_pbcq(struct dt_node *pbcq)
{
	uint32_t nest_base, pci_base, pec_index;
	struct dt_node *stk;

	/* REMOVEME: force this for now until we stabalise PCIe */
	verbose_eeh = 1;

	nest_base = dt_get_address(pbcq, 0, NULL);
	pci_base = dt_get_address(pbcq, 1, NULL);
	pec_index = dt_prop_get_u32(pbcq, "ibm,pec-index");

	dt_for_each_child(pbcq, stk) {
		if (dt_node_is_enabled(stk))
			phb4_probe_stack(stk, pec_index, nest_base, pci_base);
	}
}

void probe_phb4(void)
{
	struct dt_node *np;
	const char *s;

	pci_eeh_mmio = !nvram_query_eq_dangerous("pci-eeh-mmio", "disabled");
	pci_retry_all = nvram_query_eq_dangerous("pci-retry-all", "true");
	s = nvram_query_dangerous("phb-rx-err-max");
	if (s) {
		rx_err_max = atoi(s);

		/* Clip to uint8_t used by hardware */
		rx_err_max = MAX(rx_err_max, 0);
		rx_err_max = MIN(rx_err_max, 255);
	}

	if (is_phb5()) {
		prlog(PR_DEBUG, "PHB5: Maximum RX errors during training: %d\n", rx_err_max);
		/* Look for PBCQ XSCOM nodes */
		dt_for_each_compatible(dt_root, np, "ibm,power10-pbcq")
			phb4_probe_pbcq(np);

		/* Look for newly created PHB nodes */
		dt_for_each_compatible(dt_root, np, "ibm,power10-pciex")
			phb4_create(np);
	} else {
		prlog(PR_DEBUG, "PHB4: Maximum RX errors during training: %d\n", rx_err_max);
		/* Look for PBCQ XSCOM nodes */
		dt_for_each_compatible(dt_root, np, "ibm,power9-pbcq")
			phb4_probe_pbcq(np);

		/* Look for newly created PHB nodes */
		dt_for_each_compatible(dt_root, np, "ibm,power9-pciex")
			phb4_create(np);
	}
}
