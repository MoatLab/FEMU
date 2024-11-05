// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
/*
 * Base PCI support
 *
 * Copyright 2013-2019 IBM Corp.
 */

#include <skiboot.h>
#include <cpu.h>
#include <pci.h>
#include <pci-cfg.h>
#include <pci-slot.h>
#include <pci-quirk.h>
#include <timebase.h>
#include <device.h>

#define MAX_PHB_ID	256
static struct phb *phbs[MAX_PHB_ID];
int last_phb_id = 0;

/*
 * Generic PCI utilities
 */

static int64_t __pci_find_cap(struct phb *phb, uint16_t bdfn,
			      uint8_t want, bool check_cap_indicator)
{
	int64_t rc;
	uint16_t stat, cap;
	uint8_t pos, next;

	rc = pci_cfg_read16(phb, bdfn, PCI_CFG_STAT, &stat);
	if (rc)
		return rc;
	if (check_cap_indicator && !(stat & PCI_CFG_STAT_CAP))
		return OPAL_UNSUPPORTED;
	rc = pci_cfg_read8(phb, bdfn, PCI_CFG_CAP, &pos);
	if (rc)
		return rc;
	pos &= 0xfc;
	while(pos) {
		rc = pci_cfg_read16(phb, bdfn, pos, &cap);
		if (rc)
			return rc;
		if ((cap & 0xff) == want)
			return pos;
		next = (cap >> 8) & 0xfc;
		if (next == pos) {
			PCIERR(phb, bdfn, "pci_find_cap hit a loop !\n");
			break;
		}
		pos = next;
	}
	return OPAL_UNSUPPORTED;
}

/* pci_find_cap - Find a PCI capability in a device config space
 *
 * This will return a config space offset (positive) or a negative
 * error (OPAL error codes).
 *
 * OPAL_UNSUPPORTED is returned if the capability doesn't exist
 */
int64_t pci_find_cap(struct phb *phb, uint16_t bdfn, uint8_t want)
{
	return __pci_find_cap(phb, bdfn, want, true);
}

/* pci_find_ecap - Find a PCIe extended capability in a device
 *                 config space
 *
 * This will return a config space offset (positive) or a negative
 * error (OPAL error code). Additionally, if the "version" argument
 * is non-NULL, the capability version will be returned there.
 *
 * OPAL_UNSUPPORTED is returned if the capability doesn't exist
 */
int64_t pci_find_ecap(struct phb *phb, uint16_t bdfn, uint16_t want,
		      uint8_t *version)
{
	int64_t rc;
	uint32_t cap;
	uint16_t off, prev = 0;

	for (off = 0x100; off && off < 0x1000; off = (cap >> 20) & 0xffc ) {
		if (off == prev) {
			PCIERR(phb, bdfn, "pci_find_ecap hit a loop !\n");
			break;
		}
		prev = off;
		rc = pci_cfg_read32(phb, bdfn, off, &cap);
		if (rc)
			return rc;

		/* no ecaps supported */
		if (cap == 0 || (cap & 0xffff) == 0xffff)
			return OPAL_UNSUPPORTED;

		if ((cap & 0xffff) == want) {
			if (version)
				*version = (cap >> 16) & 0xf;
			return off;
		}
	}
	return OPAL_UNSUPPORTED;
}

static void pci_init_pcie_cap(struct phb *phb, struct pci_device *pd)
{
	int64_t ecap = 0;
	uint16_t reg;
	uint32_t val;

	/* On the upstream port of PLX bridge 8724 (rev ba), PCI_STATUS
	 * register doesn't have capability indicator though it support
	 * various PCI capabilities. So we need ignore that bit when
	 * looking for PCI capabilities on the upstream port, which is
	 * limited to one that seats directly under root port.
	 */
	if (pd->vdid == 0x872410b5 && pd->parent && !pd->parent->parent) {
		uint8_t rev;

		pci_cfg_read8(phb, pd->bdfn, PCI_CFG_REV_ID, &rev);
		if (rev == 0xba)
			ecap = __pci_find_cap(phb, pd->bdfn,
					      PCI_CFG_CAP_ID_EXP, false);
		else
			ecap = pci_find_cap(phb, pd->bdfn, PCI_CFG_CAP_ID_EXP);
	} else {
		ecap = pci_find_cap(phb, pd->bdfn, PCI_CFG_CAP_ID_EXP);
	}

	if (ecap <= 0) {
		pd->dev_type = PCIE_TYPE_LEGACY;
		return;
	}

	pci_set_cap(pd, PCI_CFG_CAP_ID_EXP, ecap, NULL, NULL, false);

	/*
	 * XXX We observe a problem on some PLX switches where one
	 * of the downstream ports appears as an upstream port, we
	 * fix that up here otherwise, other code will misbehave
	 */
	pci_cfg_read16(phb, pd->bdfn, ecap + PCICAP_EXP_CAPABILITY_REG, &reg);
	pd->dev_type = GETFIELD(PCICAP_EXP_CAP_TYPE, reg);
	if (pd->parent && pd->parent->dev_type == PCIE_TYPE_SWITCH_UPPORT &&
	    pd->vdid == 0x874810b5 && pd->dev_type == PCIE_TYPE_SWITCH_UPPORT) {
		PCIDBG(phb, pd->bdfn, "Fixing up bad PLX downstream port !\n");
		pd->dev_type = PCIE_TYPE_SWITCH_DNPORT;
	}

	/* XXX Handle ARI */
	if (pd->dev_type == PCIE_TYPE_SWITCH_DNPORT ||
	    pd->dev_type == PCIE_TYPE_ROOT_PORT)
		pd->scan_map = 0x1;

	/* Read MPS capability, whose maximal size is 4096 */
	pci_cfg_read32(phb, pd->bdfn, ecap + PCICAP_EXP_DEVCAP, &val);
	pd->mps = (128 << GETFIELD(PCICAP_EXP_DEVCAP_MPSS, val));
	if (pd->mps > 4096)
		pd->mps = 4096;
}

static void pci_init_aer_cap(struct phb *phb, struct pci_device *pd)
{
	int64_t pos;

	if (!pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false))
		return;

	pos = pci_find_ecap(phb, pd->bdfn, PCIECAP_ID_AER, NULL);
	if (pos > 0)
		pci_set_cap(pd, PCIECAP_ID_AER, pos, NULL, NULL, true);
}

static void pci_init_pm_cap(struct phb *phb, struct pci_device *pd)
{
	int64_t pos;

	pos = pci_find_cap(phb, pd->bdfn, PCI_CFG_CAP_ID_PM);
	if (pos > 0)
		pci_set_cap(pd, PCI_CFG_CAP_ID_PM, pos, NULL, NULL, false);
}

void pci_init_capabilities(struct phb *phb, struct pci_device *pd)
{
	pci_init_pcie_cap(phb, pd);
	pci_init_aer_cap(phb, pd);
	pci_init_pm_cap(phb, pd);
}

bool pci_wait_crs(struct phb *phb, uint16_t bdfn, uint32_t *out_vdid)
{
	uint32_t retries, vdid;
	int64_t rc;
	bool had_crs = false;

	for (retries = 0; retries < 40; retries++) {
		rc = pci_cfg_read32(phb, bdfn, PCI_CFG_VENDOR_ID, &vdid);
		if (rc)
			return false;
		if (vdid == 0xffffffff || vdid == 0x00000000)
			return false;
		if (vdid != 0xffff0001)
			break;
		had_crs = true;
		time_wait_ms(100);
	}
	if (vdid == 0xffff0001) {
		PCIERR(phb, bdfn, "CRS timeout !\n");
		return false;
	}
	if (had_crs)
		PCIDBG(phb, bdfn, "Probe success after %d CRS\n", retries);

	if (out_vdid)
		*out_vdid = vdid;
	return true;
}

static struct pci_device *pci_scan_one(struct phb *phb, struct pci_device *parent,
				       uint16_t bdfn)
{
	struct pci_device *pd = NULL;
	uint32_t vdid;
	int64_t rc;
	uint8_t htype;

	if (!pci_wait_crs(phb, bdfn, &vdid))
		return NULL;

	/* Perform a dummy write to the device in order for it to
	 * capture it's own bus number, so any subsequent error
	 * messages will be properly tagged
	 */
	pci_cfg_write32(phb, bdfn, PCI_CFG_VENDOR_ID, vdid);

	pd = zalloc(sizeof(struct pci_device));
	if (!pd) {
		PCIERR(phb, bdfn,"Failed to allocate structure pci_device !\n");
		goto fail;
	}
	pd->phb = phb;
	pd->bdfn = bdfn;
	pd->vdid = vdid;
	pci_cfg_read32(phb, bdfn, PCI_CFG_SUBSYS_VENDOR_ID, &pd->sub_vdid);
	pci_cfg_read32(phb, bdfn, PCI_CFG_REV_ID, &pd->class);
	pd->class >>= 8;

	pd->parent = parent;
	list_head_init(&pd->pcrf);
	list_head_init(&pd->children);
	rc = pci_cfg_read8(phb, bdfn, PCI_CFG_HDR_TYPE, &htype);
	if (rc) {
		PCIERR(phb, bdfn, "Failed to read header type !\n");
		goto fail;
	}
	pd->is_multifunction = !!(htype & 0x80);
	pd->is_bridge = (htype & 0x7f) != 0;
	pd->is_vf = false;
	pd->scan_map = 0xffffffff; /* Default */
	pd->primary_bus = PCI_BUS_NUM(bdfn);

	pci_init_capabilities(phb, pd);

	/* If it's a bridge, sanitize the bus numbers to avoid forwarding
	 *
	 * This will help when walking down those bridges later on
	 */
	if (pd->is_bridge) {
		pci_cfg_write8(phb, bdfn, PCI_CFG_PRIMARY_BUS, pd->primary_bus);
		pci_cfg_write8(phb, bdfn, PCI_CFG_SECONDARY_BUS, 0);
		pci_cfg_write8(phb, bdfn, PCI_CFG_SUBORDINATE_BUS, 0);
	}

	/* XXX Need to do some basic setups, such as MPSS, MRS,
	 * RCB, etc...
	 */

	PCIDBG(phb, bdfn, "Found VID:%04x DEV:%04x TYP:%d MF%s BR%s EX%s\n",
	       vdid & 0xffff, vdid >> 16, pd->dev_type,
	       pd->is_multifunction ? "+" : "-",
	       pd->is_bridge ? "+" : "-",
	       pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false) ? "+" : "-");

	/* Try to get PCI slot behind the device */
	if (platform.pci_get_slot_info)
		platform.pci_get_slot_info(phb, pd);

	/* Put it to the child device of list of PHB or parent */
	if (!parent)
		list_add_tail(&phb->devices, &pd->link);
	else
		list_add_tail(&parent->children, &pd->link);

	/*
	 * Call PHB hook
	 */
	if (phb->ops->device_init)
		phb->ops->device_init(phb, pd, NULL);

	return pd;
 fail:
	if (pd)
		free(pd);
	return NULL;
}

/* pci_check_clear_freeze - Probing empty slot will result in an EEH
 *                          freeze. Currently we have a single PE mapping
 *                          everything (default state of our backend) so
 *                          we just check and clear the state of PE#0
 *
 *                          returns true if a freeze was detected
 *
 * NOTE: We currently only handle simple PE freeze, not PHB fencing
 *       (or rather our backend does)
 */
bool pci_check_clear_freeze(struct phb *phb)
{
	uint8_t freeze_state;
	uint16_t pci_error_type, sev;
	int64_t pe_number, rc;

	/* Retrieve the reserved PE number */
	pe_number = OPAL_PARAMETER;
	if (phb->ops->get_reserved_pe_number)
		pe_number = phb->ops->get_reserved_pe_number(phb);
	if (pe_number < 0)
		return false;

	/* Retrieve the frozen state */
	rc = phb->ops->eeh_freeze_status(phb, pe_number, &freeze_state,
					 &pci_error_type, &sev);
	if (rc)
		return true; /* phb fence? */

	if (freeze_state == OPAL_EEH_STOPPED_NOT_FROZEN)
		return false;
	/* We can't handle anything worse than an ER here */
	if (sev > OPAL_EEH_SEV_NO_ERROR &&
	    sev < OPAL_EEH_SEV_PE_ER) {
		PCIERR(phb, 0, "Fatal probe in %s error !\n", __func__);
		return true;
	}

	phb->ops->eeh_freeze_clear(phb, pe_number,
				   OPAL_EEH_ACTION_CLEAR_FREEZE_ALL);
	return true;
}

/*
 * Turn off slot's power supply if there are nothing connected for
 * 2 purposes: power saving obviously and initialize the slot to
 * to initial power-off state for hotplug.
 *
 * The power should be turned on if the downstream link of the slot
 * isn't up.
 */
static void pci_slot_set_power_state(struct phb *phb,
				     struct pci_device *pd,
				     uint8_t state)
{
	struct pci_slot *slot;
	uint8_t cur_state;
	int32_t wait = 100;
	int64_t rc;

	if (!pd || !pd->slot)
		return;

	slot = pd->slot;
	if (!slot->pluggable ||
	    !slot->ops.get_power_state ||
	    !slot->ops.set_power_state)
		return;

	if (state == PCI_SLOT_POWER_OFF) {
		/* Bail if there're something connected */
		if (!list_empty(&pd->children)) {
			PCIERR(phb, pd->bdfn, "Attempted to power off slot with attached devices!\n");
			return;
		}

		pci_slot_add_flags(slot, PCI_SLOT_FLAG_BOOTUP);
		rc = slot->ops.get_power_state(slot, &cur_state);
		if (rc != OPAL_SUCCESS) {
			PCINOTICE(phb, pd->bdfn, "Error %lld getting slot power state\n", rc);
			cur_state = PCI_SLOT_POWER_OFF;
		}

		pci_slot_remove_flags(slot, PCI_SLOT_FLAG_BOOTUP);
		if (cur_state == PCI_SLOT_POWER_OFF)
			return;
	}

	pci_slot_add_flags(slot,
		(PCI_SLOT_FLAG_BOOTUP | PCI_SLOT_FLAG_ENFORCE));
	rc = slot->ops.set_power_state(slot, state);
	if (rc == OPAL_SUCCESS)
		goto success;
	if (rc != OPAL_ASYNC_COMPLETION) {
		PCINOTICE(phb, pd->bdfn, "Error %lld powering %s slot\n",
			  rc, state == PCI_SLOT_POWER_ON ? "on" : "off");
		goto error;
	}

	/* Wait until the operation is completed */
	do {
		if (slot->state == PCI_SLOT_STATE_SPOWER_DONE)
			break;

		check_timers(false);
		time_wait_ms(10);
	} while (--wait >= 0);

	if (wait < 0) {
		PCINOTICE(phb, pd->bdfn, "Timeout powering %s slot\n",
			  state == PCI_SLOT_POWER_ON ? "on" : "off");
		goto error;
	}

success:
	PCIDBG(phb, pd->bdfn, "Powering %s hotpluggable slot\n",
	       state == PCI_SLOT_POWER_ON ? "on" : "off");
error:
	pci_slot_remove_flags(slot,
		(PCI_SLOT_FLAG_BOOTUP | PCI_SLOT_FLAG_ENFORCE));
	pci_slot_set_state(slot, PCI_SLOT_STATE_NORMAL);
}

static bool pci_bridge_power_on(struct phb *phb, struct pci_device *pd)
{
	int32_t ecap;
	uint16_t pcie_cap, slot_sts, slot_ctl, link_ctl;
	uint32_t slot_cap;
	int64_t rc;

	/*
	 * If there is a PCI slot associated with the bridge, to use
	 * the PCI slot's facality to power it on.
	 */
	if (pd->slot) {
		struct pci_slot *slot = pd->slot;
		uint8_t presence;

		/*
		 * We assume the presence state is OPAL_PCI_SLOT_PRESENT
		 * by default. In this way, we won't miss anything when
		 * the operation isn't supported or hitting error upon
		 * retrieving it.
		 */
		if (slot->ops.get_presence_state) {
			rc = slot->ops.get_presence_state(slot, &presence);
			if (rc == OPAL_SUCCESS &&
			    presence == OPAL_PCI_SLOT_EMPTY)
				return false;
		}

		/* To power it on */
		pci_slot_set_power_state(phb, pd, PCI_SLOT_POWER_ON);
		return true;
	}

	if (!pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false))
		return true;

	/* Check if slot is supported */
	ecap = pci_cap(pd, PCI_CFG_CAP_ID_EXP, false);
	pci_cfg_read16(phb, pd->bdfn,
		       ecap + PCICAP_EXP_CAPABILITY_REG, &pcie_cap);
	if (!(pcie_cap & PCICAP_EXP_CAP_SLOT))
		return true;

	/* Check presence */
	pci_cfg_read16(phb, pd->bdfn,
		       ecap + PCICAP_EXP_SLOTSTAT, &slot_sts);
        if (!(slot_sts & PCICAP_EXP_SLOTSTAT_PDETECTST))
		return false;

	/* Ensure that power control is supported */
	pci_cfg_read32(phb, pd->bdfn,
		       ecap + PCICAP_EXP_SLOTCAP, &slot_cap);
	if (!(slot_cap & PCICAP_EXP_SLOTCAP_PWCTRL))
		return true;


	/* Read the slot control register, check if the slot is off */
	pci_cfg_read16(phb, pd->bdfn, ecap + PCICAP_EXP_SLOTCTL, &slot_ctl);
	PCITRACE(phb, pd->bdfn, " SLOT_CTL=%04x\n", slot_ctl);
	if (slot_ctl & PCICAP_EXP_SLOTCTL_PWRCTLR) {
		PCIDBG(phb, pd->bdfn, "Bridge power is off, turning on ...\n");
		slot_ctl &= ~PCICAP_EXP_SLOTCTL_PWRCTLR;
		slot_ctl |= SETFIELD(PCICAP_EXP_SLOTCTL_PWRI, 0, PCIE_INDIC_ON);
		pci_cfg_write16(phb, pd->bdfn,
				ecap + PCICAP_EXP_SLOTCTL, slot_ctl);

		/* Wait a couple of seconds */
		time_wait_ms(2000);
	}

	/* Enable link */
	pci_cfg_read16(phb, pd->bdfn, ecap + PCICAP_EXP_LCTL, &link_ctl);
	PCITRACE(phb, pd->bdfn, " LINK_CTL=%04x\n", link_ctl);
	link_ctl &= ~PCICAP_EXP_LCTL_LINK_DIS;
	pci_cfg_write16(phb, pd->bdfn, ecap + PCICAP_EXP_LCTL, link_ctl);

	return true;
}

static bool pci_bridge_wait_link(struct phb *phb,
				 struct pci_device *pd,
				 bool was_reset)
{
	int32_t ecap = 0;
	uint32_t link_cap = 0, retries = 100;
	uint16_t link_sts;

	if (pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false)) {
		ecap = pci_cap(pd, PCI_CFG_CAP_ID_EXP, false);
		pci_cfg_read32(phb, pd->bdfn, ecap + PCICAP_EXP_LCAP, &link_cap);
	}

	/*
	 * If link state reporting isn't supported, wait 1 second
	 * if the downstream link was ever resetted.
	 */
	if (!(link_cap & PCICAP_EXP_LCAP_DL_ACT_REP)) {
		if (was_reset)
			time_wait_ms(1000);

		return true;
	}

	/*
	 * Link state reporting is supported, wait for the link to
	 * come up until timeout.
	 */
	PCIDBG(phb, pd->bdfn, "waiting for link... \n");
	while (retries--) {
		pci_cfg_read16(phb, pd->bdfn,
			       ecap + PCICAP_EXP_LSTAT, &link_sts);
		if (link_sts & PCICAP_EXP_LSTAT_DLLL_ACT)
			break;

		time_wait_ms(100);
	}

	if (!(link_sts & PCICAP_EXP_LSTAT_DLLL_ACT)) {
		PCIERR(phb, pd->bdfn, "Timeout waiting for downstream link\n");
		return false;
	}

	/* Need another 100ms before touching the config space */
	time_wait_ms(100);
	PCIDBG(phb, pd->bdfn, "link is up\n");

	return true;
}

/* pci_enable_bridge - Called before scanning a bridge
 *
 * Ensures error flags are clean, disable master abort, and
 * check if the subordinate bus isn't reset, the slot is enabled
 * on PCIe, etc...
 */
static bool pci_enable_bridge(struct phb *phb, struct pci_device *pd)
{
	uint16_t bctl;
	bool was_reset = false;

	/* Disable master aborts, clear errors */
	pci_cfg_read16(phb, pd->bdfn, PCI_CFG_BRCTL, &bctl);
	bctl &= ~PCI_CFG_BRCTL_MABORT_REPORT;
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_BRCTL, bctl);


	/* PCI-E bridge, check the slot state. We don't do that on the
	 * root complex as this is handled separately and not all our
	 * RCs implement the standard register set.
	 */
	if ((pd->dev_type == PCIE_TYPE_ROOT_PORT && pd->primary_bus > 0) ||
	    pd->dev_type == PCIE_TYPE_SWITCH_DNPORT) {
		if (pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false)) {
			int32_t ecap;
			uint32_t link_cap = 0;
			uint16_t link_sts = 0;

			ecap = pci_cap(pd, PCI_CFG_CAP_ID_EXP, false);
			pci_cfg_read32(phb, pd->bdfn,
				       ecap + PCICAP_EXP_LCAP, &link_cap);

			/*
			 * No need to touch the power supply if the PCIe link has
			 * been up. Further more, the slot presence bit is lost while
			 * the PCIe link is up on the specific PCI topology. In that
			 * case, we need ignore the slot presence bit and go ahead for
			 * probing. Otherwise, the NVMe adapter won't be probed.
			 *
			 * PHB3 root port, PLX switch 8748 (10b5:8748), PLX swich 9733
			 * (10b5:9733), PMC 8546 swtich (11f8:8546), NVMe adapter
			 * (1c58:0023).
			 */
			ecap = pci_cap(pd, PCI_CFG_CAP_ID_EXP, false);
			pci_cfg_read32(phb, pd->bdfn,
				       ecap + PCICAP_EXP_LCAP, &link_cap);
			pci_cfg_read16(phb, pd->bdfn,
				       ecap + PCICAP_EXP_LSTAT, &link_sts);
			if ((link_cap & PCICAP_EXP_LCAP_DL_ACT_REP) &&
			    (link_sts & PCICAP_EXP_LSTAT_DLLL_ACT))
				return true;
		}

		/* Power on the downstream slot or link */
		if (!pci_bridge_power_on(phb, pd))
			return false;
	}

	/* Clear secondary reset */
	if (bctl & PCI_CFG_BRCTL_SECONDARY_RESET) {
		PCIDBG(phb, pd->bdfn,
		       "Bridge secondary reset is on, clearing it ...\n");
		bctl &= ~PCI_CFG_BRCTL_SECONDARY_RESET;
		pci_cfg_write16(phb, pd->bdfn, PCI_CFG_BRCTL, bctl);
		time_wait_ms(1000);
		was_reset = true;
	}

	/* PCI-E bridge, wait for link */
	if (pd->dev_type == PCIE_TYPE_ROOT_PORT ||
	    pd->dev_type == PCIE_TYPE_SWITCH_DNPORT) {
		if (!pci_bridge_wait_link(phb, pd, was_reset))
			return false;
	}

	/* Clear error status */
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_STAT, 0xffff);
	return true;
}

/* Clear up bridge resources */
static void pci_cleanup_bridge(struct phb *phb, struct pci_device *pd)
{
	uint16_t cmd;

	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_IO_BASE_U16, 0xffff);
	pci_cfg_write8(phb, pd->bdfn, PCI_CFG_IO_BASE, 0xf0);
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_IO_LIMIT_U16, 0);
	pci_cfg_write8(phb, pd->bdfn, PCI_CFG_IO_LIMIT, 0);
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_MEM_BASE, 0xfff0);
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_MEM_LIMIT, 0);
	pci_cfg_write32(phb, pd->bdfn, PCI_CFG_PREF_MEM_BASE_U32, 0xffffffff);
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_PREF_MEM_BASE, 0xfff0);
	pci_cfg_write32(phb, pd->bdfn, PCI_CFG_PREF_MEM_LIMIT_U32, 0);
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_PREF_MEM_LIMIT, 0);

	/* Note: This is a bit fishy but since we have closed all the
	 * bridge windows above, it shouldn't be a problem. Basically
	 * we enable Memory, IO and Bus Master on the bridge because
	 * some versions of Linux will fail to do it themselves.
	 */
	pci_cfg_read16(phb, pd->bdfn, PCI_CFG_CMD, &cmd);
	cmd |= PCI_CFG_CMD_IO_EN | PCI_CFG_CMD_MEM_EN;
	cmd |= PCI_CFG_CMD_BUS_MASTER_EN;
	pci_cfg_write16(phb, pd->bdfn, PCI_CFG_CMD, cmd);	
}

/* Remove all subordinate PCI devices leading from the indicated
 * PCI bus. It's used to remove all PCI devices behind one PCI
 * slot at unplugging time
 */
void pci_remove_bus(struct phb *phb, struct list_head *list)
{
	struct pci_device *pd, *tmp;

	list_for_each_safe(list, pd, tmp, link) {
		pci_remove_bus(phb, &pd->children);

		if (phb->ops->device_remove)
			phb->ops->device_remove(phb, pd);

		/* Release device node and PCI slot */
		if (pd->dn)
			dt_free(pd->dn);
		if (pd->slot)
			free(pd->slot);

		/* Remove from parent list and release itself */
		list_del(&pd->link);
		free(pd);
	}
}

static void pci_set_power_limit(struct pci_device *pd)
{
	uint32_t offset, val;
	uint16_t caps;

	offset = pci_cap(pd, PCI_CFG_CAP_ID_EXP, false);
	if (!offset)
		return; /* legacy dev */

	pci_cfg_read16(pd->phb, pd->bdfn,
			offset + PCICAP_EXP_CAPABILITY_REG, &caps);

	if (!(caps & PCICAP_EXP_CAP_SLOT))
		return; /* bridge has no slot capabilities */
	if (!pd->slot || !pd->slot->power_limit)
		return;

	pci_cfg_read32(pd->phb, pd->bdfn, offset + PCICAP_EXP_SLOTCAP, &val);

	val = SETFIELD(PCICAP_EXP_SLOTCAP_SPLSC, val, 0); /* 1W scale */
	val = SETFIELD(PCICAP_EXP_SLOTCAP_SPLVA, val, pd->slot->power_limit);

	pci_cfg_write32(pd->phb, pd->bdfn, offset + PCICAP_EXP_SLOTCAP, val);

	/* update the cached copy in the slot */
	pd->slot->slot_cap = val;

	PCIDBG(pd->phb, pd->bdfn, "Slot power limit set to %dW\n",
		pd->slot->power_limit);
}

/* Perform a recursive scan of the bus at bus_number populating
 * the list passed as an argument. This also performs the bus
 * numbering, so it returns the largest bus number that was
 * assigned.
 *
 * Note: Eventually this might want to access some VPD information
 *       in order to know what slots to scan and what not etc..
 *
 * XXX NOTE: We might want to enable ARI along the way...
 *
 * XXX NOTE: We might also want to setup the PCIe MPS/MRSS properly
 *           here as Linux may or may not do it
 */
uint8_t pci_scan_bus(struct phb *phb, uint8_t bus, uint8_t max_bus,
		     struct list_head *list, struct pci_device *parent,
		     bool scan_downstream)
{
	struct pci_device *pd = NULL, *rc = NULL;
	uint8_t dev, fn, next_bus, max_sub;
	uint32_t scan_map;

	/* Decide what to scan  */
	scan_map = parent ? parent->scan_map : phb->scan_map;

	/* Do scan */
	for (dev = 0; dev < 32; dev++) {
		if (!(scan_map & (1ul << dev)))
			continue;

		/* Scan the device */
		pd = pci_scan_one(phb, parent, (bus << 8) | (dev << 3));
		pci_check_clear_freeze(phb);
		if (!pd)
			continue;

		/* Record RC when its downstream link is down */
		if (!scan_downstream && dev == 0 && !rc)
			rc = pd;

		/* XXX Handle ARI */
		if (!pd->is_multifunction)
			continue;
		for (fn = 1; fn < 8; fn++) {
			pd = pci_scan_one(phb, parent,
					  ((uint16_t)bus << 8) | (dev << 3) | fn);
			pci_check_clear_freeze(phb);
		}
	}

	/* Reserve all possible buses if RC's downstream link is down
	 * if PCI hotplug is supported.
	 */
	if (rc && rc->slot && rc->slot->pluggable) {
		next_bus = bus + 1;
		rc->secondary_bus = next_bus;
		rc->subordinate_bus = max_bus;
		pci_cfg_write8(phb, rc->bdfn, PCI_CFG_SECONDARY_BUS,
			       rc->secondary_bus);
		pci_cfg_write8(phb, rc->bdfn, PCI_CFG_SUBORDINATE_BUS,
			       rc->subordinate_bus);
	}

	/* set the power limit for any downstream slots while we're here */
	list_for_each(list, pd, link) {
		if (pd->is_bridge)
			pci_set_power_limit(pd);
	}

	/*
	 * We only scan downstream if instructed to do so by the
	 * caller. Typically we avoid the scan when we know the
	 * link is down already, which happens for the top level
	 * root complex, and avoids a long secondary timeout
	 */
	if (!scan_downstream) {
		list_for_each(list, pd, link)
			pci_slot_set_power_state(phb, pd, PCI_SLOT_POWER_OFF);

		return bus;
	}

	next_bus = bus + 1;
	max_sub = bus;

	/* Scan down bridges */
	list_for_each(list, pd, link) {
		bool do_scan;

		if (!pd->is_bridge)
			continue;

		/* Configure the bridge with the returned values */
		if (next_bus <= bus) {
			PCIERR(phb, pd->bdfn, "Out of bus numbers !\n");
			max_bus = next_bus = 0; /* Failure case */
		}

		pd->secondary_bus = next_bus;
		pd->subordinate_bus = max_bus;
		pci_cfg_write8(phb, pd->bdfn, PCI_CFG_SECONDARY_BUS, next_bus);
		pci_cfg_write8(phb, pd->bdfn, PCI_CFG_SUBORDINATE_BUS, max_bus);
		if (!next_bus)
			break;

		PCIDBG(phb, pd->bdfn, "Bus %02x..%02x scanning...\n",
		       next_bus, max_bus);

		/* Clear up bridge resources */
		pci_cleanup_bridge(phb, pd);

		/* Configure the bridge. This will enable power to the slot
		 * if it's currently disabled, lift reset, etc...
		 *
		 * Return false if we know there's nothing behind the bridge
		 */
		do_scan = pci_enable_bridge(phb, pd);

		/* Perform recursive scan */
		if (do_scan) {
			max_sub = pci_scan_bus(phb, next_bus, max_bus,
					       &pd->children, pd, true);
		} else {
			/* Empty bridge. We leave room for hotplug
			 * slots if the downstream port is pluggable.
			 */
			if (pd->slot && !pd->slot->pluggable)
				max_sub = next_bus;
			else {
				max_sub = next_bus + 4;
				if (max_sub > max_bus)
					max_sub = max_bus;
			}
		}

		pd->subordinate_bus = max_sub;
		pci_cfg_write8(phb, pd->bdfn, PCI_CFG_SUBORDINATE_BUS, max_sub);
		next_bus = max_sub + 1;

		/* power off the slot if there's nothing below it */
		if (list_empty(&pd->children))
			pci_slot_set_power_state(phb, pd, PCI_SLOT_POWER_OFF);
	}

	return max_sub;
}

static int pci_get_mps(struct phb *phb,
		       struct pci_device *pd, void *userdata)
{
	uint32_t *mps = (uint32_t *)userdata;

	/* Only check PCI device that had MPS capacity */
	if (phb && pd && pd->mps && *mps > pd->mps)
		*mps = pd->mps;

	return 0;
}

static int pci_configure_mps(struct phb *phb,
			     struct pci_device *pd,
			     void *userdata __unused)
{
	uint32_t ecap, aercap, mps;
	uint16_t val;

	assert(phb);
	assert(pd);

	/* If the MPS isn't acceptable one, bail immediately */
	mps = phb->mps;
	if (mps < 128 || mps > 4096)
		return 1;

	/* Retrieve PCIe and AER capability */
	ecap = pci_cap(pd, PCI_CFG_CAP_ID_EXP, false);
	aercap = pci_cap(pd, PCIECAP_ID_AER, true);

	/* PCIe device always has MPS capacity */
	if (pd->mps) {
		mps = ilog2(mps) - 7;

		pci_cfg_read16(phb, pd->bdfn, ecap + PCICAP_EXP_DEVCTL, &val);
		val = SETFIELD(PCICAP_EXP_DEVCTL_MPS, val, mps);
		pci_cfg_write16(phb, pd->bdfn, ecap + PCICAP_EXP_DEVCTL, val);
	}

	/* Changing MPS on upstream PCI bridge might cause some error
	 * bits in PCIe and AER capability. To clear them to avoid
	 * confusion.
	 */
	if (aercap) {
		pci_cfg_write32(phb, pd->bdfn, aercap + PCIECAP_AER_UE_STATUS,
				0xffffffff);
		pci_cfg_write32(phb, pd->bdfn, aercap + PCIECAP_AER_CE_STATUS,
				0xffffffff);
	}
	if (ecap)
		pci_cfg_write16(phb, pd->bdfn, ecap + PCICAP_EXP_DEVSTAT, 0xf);

	return 0;
}

static void pci_disable_completion_timeout(struct phb *phb, struct pci_device *pd)
{
	uint32_t ecap, val;
	uint16_t pcie_cap;

	/* PCIE capability required */
	if (!pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false))
		return;

	/* Check PCIe capability version */
	ecap = pci_cap(pd, PCI_CFG_CAP_ID_EXP, false);
	pci_cfg_read16(phb, pd->bdfn,
		       ecap + PCICAP_EXP_CAPABILITY_REG, &pcie_cap);
	if ((pcie_cap & PCICAP_EXP_CAP_VERSION) <= 1)
		return;

	/* Check if it has capability to disable completion timeout */
	pci_cfg_read32(phb, pd->bdfn, ecap + PCIECAP_EXP_DCAP2, &val);
	if (!(val & PCICAP_EXP_DCAP2_CMPTOUT_DIS))
		return;

	/* Disable completion timeout without more check */
	pci_cfg_read32(phb, pd->bdfn, ecap + PCICAP_EXP_DCTL2, &val);
	val |= PCICAP_EXP_DCTL2_CMPTOUT_DIS;
	pci_cfg_write32(phb, pd->bdfn, ecap + PCICAP_EXP_DCTL2, val);
}

void pci_device_init(struct phb *phb, struct pci_device *pd)
{
	pci_configure_mps(phb, pd, NULL);
	pci_disable_completion_timeout(phb, pd);
}

static void pci_reset_phb(void *data)
{
	struct phb *phb = data;
	struct pci_slot *slot = phb->slot;
	int64_t rc;

	if (!slot || !slot->ops.run_sm) {
		PCINOTICE(phb, 0, "Cannot issue reset\n");
		return;
	}

	pci_slot_add_flags(slot, PCI_SLOT_FLAG_BOOTUP);
	rc = slot->ops.run_sm(slot);
	while (rc > 0) {
		PCITRACE(phb, 0, "Waiting %ld ms\n", tb_to_msecs(rc));
		time_wait(rc);
		rc = slot->ops.run_sm(slot);
	}
	pci_slot_remove_flags(slot, PCI_SLOT_FLAG_BOOTUP);
	if (rc < 0)
		PCIDBG(phb, 0, "Error %lld resetting\n", rc);
}

static void pci_scan_phb(void *data)
{
	struct phb *phb = data;
	struct pci_slot *slot = phb->slot;
	uint8_t link;
	uint32_t mps = 0xffffffff;
	int64_t rc;

	if (!slot || !slot->ops.get_link_state) {
		PCIERR(phb, 0, "Cannot query link status\n");
		link = 0;
	} else {
		rc = slot->ops.get_link_state(slot, &link);
		if (rc != OPAL_SUCCESS) {
			PCIERR(phb, 0, "Error %lld querying link status\n",
			       rc);
			link = 0;
		}
	}

	if (!link)
		PCIDBG(phb, 0, "Link down\n");
	else
		PCIDBG(phb, 0, "Link up at x%d width\n", link);

	/* Scan root port and downstream ports if applicable */
	PCIDBG(phb, 0, "Scanning (upstream%s)...\n",
	       link ? "+downsteam" : " only");
	pci_scan_bus(phb, 0, 0xff, &phb->devices, NULL, link);

	/* Configure MPS (Max Payload Size) for PCIe domain */
	pci_walk_dev(phb, NULL, pci_get_mps, &mps);
	phb->mps = mps;
	pci_walk_dev(phb, NULL, pci_configure_mps, NULL);
}

int64_t pci_register_phb(struct phb *phb, int opal_id)
{
	/* The user didn't specify an opal_id, allocate one */
	if (opal_id == OPAL_DYNAMIC_PHB_ID) {
		/* This is called at init time in non-concurrent way, so no lock needed */
		for (opal_id = 0; opal_id < ARRAY_SIZE(phbs); opal_id++)
			if (!phbs[opal_id])
				break;
		if (opal_id >= ARRAY_SIZE(phbs)) {
			prerror("PHB: Failed to find a free ID slot\n");
			return OPAL_RESOURCE;
		}
	} else {
		if (opal_id >= ARRAY_SIZE(phbs)) {
			prerror("PHB: ID %x out of range !\n", opal_id);
			return OPAL_PARAMETER;
		}
		/* The user did specify an opal_id, check it's free */
		if (phbs[opal_id]) {
			prerror("PHB: Duplicate registration of ID %x\n", opal_id);
			return OPAL_PARAMETER;
		}
	}

	phbs[opal_id] = phb;
	phb->opal_id = opal_id;
	if (opal_id > last_phb_id)
		last_phb_id = opal_id;
	dt_add_property_cells(phb->dt_node, "ibm,opal-phbid", 0, phb->opal_id);
	PCIDBG(phb, 0, "PCI: Registered PHB\n");

	init_lock(&phb->lock);
	list_head_init(&phb->devices);

	phb->filter_map = zalloc(BITMAP_BYTES(0x10000));
	assert(phb->filter_map);

	return OPAL_SUCCESS;
}

int64_t pci_unregister_phb(struct phb *phb)
{
	/* XXX We want some kind of RCU or RWlock to make things
	 * like that happen while no OPAL callback is in progress,
	 * that way we avoid taking a lock in each of them.
	 *
	 * Right now we don't unregister so we are fine
	 */
	phbs[phb->opal_id] = phb;

	return OPAL_SUCCESS;
}

struct phb *pci_get_phb(uint64_t phb_id)
{
	if (phb_id >= ARRAY_SIZE(phbs))
		return NULL;

	/* XXX See comment in pci_unregister_phb() about locking etc... */
	return phbs[phb_id];
}

static const char *pci_class_name(uint32_t class_code)
{
	uint8_t class = class_code >> 16;
	uint8_t sub = (class_code >> 8) & 0xff;
	uint8_t pif = class_code & 0xff;

	switch(class) {
	case 0x00:
		switch(sub) {
		case 0x00: return "device";
		case 0x01: return "vga";
		}
		break;
	case 0x01:
		switch(sub) {
		case 0x00: return "scsi";
		case 0x01: return "ide";
		case 0x02: return "fdc";
		case 0x03: return "ipi";
		case 0x04: return "raid";
		case 0x05: return "ata";
		case 0x06: return "sata";
		case 0x07: return "sas";
		default:   return "mass-storage";
		}
	case 0x02:
		switch(sub) {
		case 0x00: return "ethernet";
		case 0x01: return "token-ring";
		case 0x02: return "fddi";
		case 0x03: return "atm";
		case 0x04: return "isdn";
		case 0x05: return "worldfip";
		case 0x06: return "picmg";
		default:   return "network";
		}
	case 0x03:
		switch(sub) {
		case 0x00: return "vga";
		case 0x01: return "xga";
		case 0x02: return "3d-controller";
		default:   return "display";
		}
	case 0x04:
		switch(sub) {
		case 0x00: return "video";
		case 0x01: return "sound";
		case 0x02: return "telephony";
		default:   return "multimedia-device";
		}
	case 0x05:
		switch(sub) {
		case 0x00: return "memory";
		case 0x01: return "flash";
		default:   return "memory-controller";
		}
	case 0x06:
		switch(sub) {
		case 0x00: return "host";
		case 0x01: return "isa";
		case 0x02: return "eisa";
		case 0x03: return "mca";
		case 0x04: return "pci";
		case 0x05: return "pcmcia";
		case 0x06: return "nubus";
		case 0x07: return "cardbus";
		case 0x08: return "raceway";
		case 0x09: return "semi-transparent-pci";
		case 0x0a: return "infiniband";
		default:   return "unknown-bridge";
		}
	case 0x07:
		switch(sub) {
		case 0x00:
			switch(pif) {
			case 0x01: return "16450-serial";
			case 0x02: return "16550-serial";
			case 0x03: return "16650-serial";
			case 0x04: return "16750-serial";
			case 0x05: return "16850-serial";
			case 0x06: return "16950-serial";
			default:   return "serial";
			}
		case 0x01:
			switch(pif) {
			case 0x01: return "bi-directional-parallel";
			case 0x02: return "ecp-1.x-parallel";
			case 0x03: return "ieee1284-controller";
			case 0xfe: return "ieee1284-device";
			default:   return "parallel";
			}
		case 0x02: return "multiport-serial";
		case 0x03:
			switch(pif) {
			case 0x01: return "16450-modem";
			case 0x02: return "16550-modem";
			case 0x03: return "16650-modem";
			case 0x04: return "16750-modem";
			default:   return "modem";
			}
		case 0x04: return "gpib";
		case 0x05: return "smart-card";
		default:   return "communication-controller";
		}
	case 0x08:
		switch(sub) {
		case 0x00:
			switch(pif) {
			case 0x01: return "isa-pic";
			case 0x02: return "eisa-pic";
			case 0x10: return "io-apic";
			case 0x20: return "iox-apic";
			default:   return "interrupt-controller";
			}
		case 0x01:
			switch(pif) {
			case 0x01: return "isa-dma";
			case 0x02: return "eisa-dma";
			default:   return "dma-controller";
			}
		case 0x02:
			switch(pif) {
			case 0x01: return "isa-system-timer";
			case 0x02: return "eisa-system-timer";
			default:   return "timer";
			}
		case 0x03:
			switch(pif) {
			case 0x01: return "isa-rtc";
			default:   return "rtc";
			}
		case 0x04: return "hotplug-controller";
		case 0x05: return "sd-host-controller";
		default:   return "system-peripheral";
		}
	case 0x09:
		switch(sub) {
		case 0x00: return "keyboard";
		case 0x01: return "pen";
		case 0x02: return "mouse";
		case 0x03: return "scanner";
		case 0x04: return "gameport";
		default:   return "input-controller";
		}
	case 0x0a:
		switch(sub) {
		case 0x00: return "clock";
		default:   return "docking-station";
		}
	case 0x0b:
		switch(sub) {
		case 0x00: return "386";
		case 0x01: return "486";
		case 0x02: return "pentium";
		case 0x10: return "alpha";
		case 0x20: return "powerpc";
		case 0x30: return "mips";
		case 0x40: return "co-processor";
		default:   return "cpu";
		}
	case 0x0c:
		switch(sub) {
		case 0x00: return "firewire";
		case 0x01: return "access-bus";
		case 0x02: return "ssa";
		case 0x03:
			switch(pif) {
			case 0x00: return "usb-uhci";
			case 0x10: return "usb-ohci";
			case 0x20: return "usb-ehci";
			case 0x30: return "usb-xhci";
			case 0xfe: return "usb-device";
			default:   return "usb";
			}
		case 0x04: return "fibre-channel";
		case 0x05: return "smb";
		case 0x06: return "infiniband";
		case 0x07:
			switch(pif) {
			case 0x00: return "impi-smic";
			case 0x01: return "impi-kbrd";
			case 0x02: return "impi-bltr";
			default:   return "impi";
			}
		case 0x08: return "secos";
		case 0x09: return "canbus";
		default:   return "serial-bus";
		}
	case 0x0d:
		switch(sub) {
		case 0x00: return "irda";
		case 0x01: return "consumer-ir";
		case 0x10: return "rf-controller";
		case 0x11: return "bluetooth";
		case 0x12: return "broadband";
		case 0x20: return "enet-802.11a";
		case 0x21: return "enet-802.11b";
		default:   return "wireless-controller";
		}
	case 0x0e: return "intelligent-controller";
	case 0x0f:
		switch(sub) {
		case 0x01: return "satellite-tv";
		case 0x02: return "satellite-audio";
		case 0x03: return "satellite-voice";
		case 0x04: return "satellite-data";
		default:   return "satellite-device";
		}
	case 0x10:
		switch(sub) {
		case 0x00: return "network-encryption";
		case 0x01: return "entertainment-encryption";
		default:   return "encryption";
		}
	case 0x011:
		switch(sub) {
		case 0x00: return "dpio";
		case 0x01: return "counter";
		case 0x10: return "measurement";
		case 0x20: return "management-card";
		default:   return "data-processing";
		}
	}
	return "device";
}

void pci_std_swizzle_irq_map(struct dt_node *np,
			     struct pci_device *pd,
			     struct pci_lsi_state *lstate,
			     uint8_t swizzle)
{
	__be32 *p, *map;
	int dev, irq, esize, edevcount;
	size_t map_size;

	/* Some emulated setups don't use standard interrupts
	 * representation
	 */
	if (lstate->int_size == 0)
		return;

	/* Calculate the size of a map entry:
	 *
	 * 3 cells : PCI Address
	 * 1 cell  : PCI IRQ
	 * 1 cell  : PIC phandle
	 * n cells : PIC irq (n = lstate->int_size)
	 *
	 * Assumption: PIC address is 0-size
	 */
	esize = 3 + 1 + 1 + lstate->int_size;

	/* Number of map "device" entries
	 *
	 * A PCI Express root or downstream port needs only one
	 * entry for device 0. Anything else will get a full map
	 * for all possible 32 child device numbers
	 *
	 * If we have been passed a host bridge (pd == NULL) we also
	 * do a simple per-pin map
	 */
	if (!pd || (pd->dev_type == PCIE_TYPE_ROOT_PORT ||
		    pd->dev_type == PCIE_TYPE_SWITCH_DNPORT)) {
		edevcount = 1;
		dt_add_property_cells(np, "interrupt-map-mask", 0, 0, 0, 7);
	} else {
		edevcount = 32;
		dt_add_property_cells(np, "interrupt-map-mask",
				      0xf800, 0, 0, 7);
	}
	map_size = esize * edevcount * 4 * sizeof(u32);
	map = p = zalloc(map_size);
	if (!map) {
		prerror("Failed to allocate interrupt-map-mask !\n");
		return;
	}

	for (dev = 0; dev < edevcount; dev++) {
		for (irq = 0; irq < 4; irq++) {
			/* Calculate pin */
			size_t i;
			uint32_t new_irq = (irq + dev + swizzle) % 4;

			/* PCI address portion */
			*(p++) = cpu_to_be32(dev << (8 + 3));
			*(p++) = 0;
			*(p++) = 0;

			/* PCI interrupt portion */
			*(p++) = cpu_to_be32(irq + 1);

			/* Parent phandle */
			*(p++) = cpu_to_be32(lstate->int_parent[new_irq]);

			/* Parent desc */
			for (i = 0; i < lstate->int_size; i++)
				*(p++) = cpu_to_be32(lstate->int_val[new_irq][i]);
		}
	}

	dt_add_property(np, "interrupt-map", map, map_size);
	free(map);
}

static void pci_add_loc_code(struct dt_node *np)
{
	struct dt_node *p;
	const char *lcode = NULL;

	for (p = np->parent; p; p = p->parent) {
		/* prefer slot-label by default */
		lcode = dt_prop_get_def(p, "ibm,slot-label", NULL);
		if (lcode)
			break;

		/* otherwise use the fully qualified location code */
		lcode = dt_prop_get_def(p, "ibm,slot-location-code", NULL);
		if (lcode)
			break;
	}

	if (!lcode)
		lcode = dt_prop_get_def(np, "ibm,slot-location-code", NULL);

	if (!lcode) {
		/* Fall back to finding a ibm,loc-code */
		for (p = np->parent; p; p = p->parent) {
			lcode = dt_prop_get_def(p, "ibm,loc-code", NULL);
			if (lcode)
				break;
		}
	}

	if (!lcode)
		return;

	dt_add_property_string(np, "ibm,loc-code", lcode);
}

static void pci_print_summary_line(struct phb *phb, struct pci_device *pd,
				   struct dt_node *np, u32 rev_class,
				   const char *cname)
{
	const char *label, *dtype, *s;
#define MAX_SLOTSTR 80
	char slotstr[MAX_SLOTSTR  + 1] = { 0, };

	/* If it's a slot, it has a slot-label */
	label = dt_prop_get_def(np, "ibm,slot-label", NULL);
	if (label) {
		u32 lanes = dt_prop_get_u32_def(np, "ibm,slot-wired-lanes", 0);
		static const char *lanestrs[] = {
			"", " x1", " x2", " x4", " x8", "x16", "x32", "32b", "64b"
		};
		const char *lstr = lanes > PCI_SLOT_WIRED_LANES_PCIX_64 ? "" : lanestrs[lanes];
		snprintf(slotstr, MAX_SLOTSTR, "SLOT=%3s %s", label, lstr);
		/* XXX Add more slot info */
	} else {
		/*
		 * No label, ignore downstream switch legs and root complex,
		 * Those would essentially be non-populated
		 */
		if (pd->dev_type != PCIE_TYPE_ROOT_PORT &&
		    pd->dev_type != PCIE_TYPE_SWITCH_DNPORT) {
			/* It's a mere device, get loc code */
			s = dt_prop_get_def(np, "ibm,loc-code", NULL);
			if (s)
				snprintf(slotstr, MAX_SLOTSTR, "LOC_CODE=%s", s);
		}
	}

	if (pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false)) {
		static const char *pcie_types[] = {
			"EP  ", "LGCY", "????", "????", "ROOT", "SWUP", "SWDN",
			"ETOX", "XTOE", "RINT", "EVTC" };
		if (pd->dev_type >= ARRAY_SIZE(pcie_types))
			dtype = "????";
		else
			dtype = pcie_types[pd->dev_type];
	} else
		dtype = pd->is_bridge ? "PCIB" : "PCID";

	if (pd->is_bridge)
		PCINOTICE(phb, pd->bdfn,
			  "[%s] %04x %04x R:%02x C:%06x B:%02x..%02x %s\n",
			  dtype, PCI_VENDOR_ID(pd->vdid),
			  PCI_DEVICE_ID(pd->vdid),
			  rev_class & 0xff, rev_class >> 8, pd->secondary_bus,
			  pd->subordinate_bus, slotstr);
	else
		PCINOTICE(phb, pd->bdfn,
			  "[%s] %04x %04x R:%02x C:%06x (%14s) %s\n",
			  dtype, PCI_VENDOR_ID(pd->vdid),
			  PCI_DEVICE_ID(pd->vdid),
			  rev_class & 0xff, rev_class >> 8, cname, slotstr);
}

static void __noinline pci_add_one_device_node(struct phb *phb,
					       struct pci_device *pd,
					       struct dt_node *parent_node,
					       struct pci_lsi_state *lstate,
					       uint8_t swizzle)
{
	struct dt_node *np;
	const char *cname;
#define MAX_NAME 256
	char name[MAX_NAME];
	char compat[MAX_NAME];
	uint32_t rev_class;
	uint8_t intpin;
	bool is_pcie;

	pci_cfg_read32(phb, pd->bdfn, PCI_CFG_REV_ID, &rev_class);
	pci_cfg_read8(phb, pd->bdfn, PCI_CFG_INT_PIN, &intpin);
	is_pcie = pci_has_cap(pd, PCI_CFG_CAP_ID_EXP, false);

	/*
	 * Some IBM PHBs (p7ioc?) have an invalid PCI class code. Linux
	 * uses prefers to read the class code from the DT rather than
	 * re-reading config space we can hack around it here.
	 */
	if (is_pcie && pd->dev_type == PCIE_TYPE_ROOT_PORT)
		rev_class = (rev_class & 0xff) | 0x6040000;
	cname = pci_class_name(rev_class >> 8);

	if (PCI_FUNC(pd->bdfn))
		snprintf(name, MAX_NAME - 1, "%s@%x,%x",
			 cname, PCI_DEV(pd->bdfn), PCI_FUNC(pd->bdfn));
	else
		snprintf(name, MAX_NAME - 1, "%s@%x",
			 cname, PCI_DEV(pd->bdfn));
	pd->dn = np = dt_new(parent_node, name);

	/*
	 * NB: ibm,pci-config-space-type is the PAPR way of indicating the
	 * device has a 4KB config space. It's got nothing to do with the
	 * standard Type 0/1 config spaces defined by PCI.
	 */
	if (is_pcie ||
		(phb->phb_type == phb_type_npu_v2_opencapi) ||
		(phb->phb_type == phb_type_pau_opencapi)) {
		snprintf(compat, MAX_NAME, "pciex%x,%x",
			 PCI_VENDOR_ID(pd->vdid), PCI_DEVICE_ID(pd->vdid));
		dt_add_property_cells(np, "ibm,pci-config-space-type", 1);
	} else {
		snprintf(compat, MAX_NAME, "pci%x,%x",
			 PCI_VENDOR_ID(pd->vdid), PCI_DEVICE_ID(pd->vdid));
		dt_add_property_cells(np, "ibm,pci-config-space-type", 0);
	}
	dt_add_property_cells(np, "class-code", rev_class >> 8);
	dt_add_property_cells(np, "revision-id", rev_class & 0xff);
	dt_add_property_cells(np, "vendor-id", PCI_VENDOR_ID(pd->vdid));
	dt_add_property_cells(np, "device-id", PCI_DEVICE_ID(pd->vdid));
	if (intpin)
		dt_add_property_cells(np, "interrupts", intpin);

	pci_handle_quirk(phb, pd);

	/* XXX FIXME: Add a few missing ones such as
	 *
	 *  - devsel-speed (!express)
	 *  - max-latency
	 *  - min-grant
	 *  - subsystem-id
	 *  - subsystem-vendor-id
	 *  - ...
	 */

	/* Add slot properties if needed and iff this is a bridge */
	if (pd->slot)
		pci_slot_add_dt_properties(pd->slot, np);

	/*
	 * Use the phb base location code for root ports if the platform
	 * doesn't provide one via slot->add_properties() operation.
	 */
	if (pd->dev_type == PCIE_TYPE_ROOT_PORT && phb->base_loc_code &&
	    !dt_has_node_property(np, "ibm,slot-location-code", NULL))
		dt_add_property_string(np, "ibm,slot-location-code",
				       phb->base_loc_code);

	/* Make up location code */
	if (platform.pci_add_loc_code)
		platform.pci_add_loc_code(np, pd);
	else
		pci_add_loc_code(np);

	/* XXX FIXME: We don't look for BARs, we only put the config space
	 * entry in the "reg" property. That's enough for Linux and we might
	 * even want to make this legit in future ePAPR
	 */
	dt_add_property_cells(np, "reg", pd->bdfn << 8, 0, 0, 0, 0);

	/* Print summary info about the device */
	pci_print_summary_line(phb, pd, np, rev_class, cname);
	if (!pd->is_bridge)
		return;

	dt_add_property_cells(np, "#address-cells", 3);
	dt_add_property_cells(np, "#size-cells", 2);
	dt_add_property_cells(np, "#interrupt-cells", 1);

	/* We want "device_type" for bridges */
	if (is_pcie)
		dt_add_property_string(np, "device_type", "pciex");
	else
		dt_add_property_string(np, "device_type", "pci");

	/* Update the current interrupt swizzling level based on our own
	 * device number
	 */
	swizzle = (swizzle + PCI_DEV(pd->bdfn)) & 3;

	/* We generate a standard-swizzling interrupt map. This is pretty
	 * big, we *could* try to be smarter for things that aren't hotplug
	 * slots at least and only populate those entries for which there's
	 * an actual children (especially on PCI Express), but for now that
	 * will do
	 */
	pci_std_swizzle_irq_map(np, pd, lstate, swizzle);

	/* Parts of the OF address translation in the kernel will fail to
	 * correctly translate a PCI address if translating a 1:1 mapping
	 * (ie. an empty ranges property).
	 * Instead add a ranges property that explicitly translates 1:1.
	 */
	dt_add_property_cells(np, "ranges",
				/* 64-bit direct mapping. We know the bridges
				 * don't cover the entire address space so
				 * use 0xf00... as a good compromise. */
				0x02000000, 0x0, 0x0,
				0x02000000, 0x0, 0x0,
				0xf0000000, 0x0);
}

void __noinline pci_add_device_nodes(struct phb *phb,
				     struct list_head *list,
				     struct dt_node *parent_node,
				     struct pci_lsi_state *lstate,
				     uint8_t swizzle)
{
	struct pci_device *pd;

	/* Add all child devices */
	list_for_each(list, pd, link) {
		pci_add_one_device_node(phb, pd, parent_node,
					lstate, swizzle);
		if (list_empty(&pd->children))
			continue;

		pci_add_device_nodes(phb, &pd->children,
				     pd->dn, lstate, swizzle);
	}
}

static void pci_do_jobs(void (*fn)(void *))
{
	struct cpu_job **jobs;
	int i;

	jobs = zalloc(sizeof(struct cpu_job *) * ARRAY_SIZE(phbs));
	assert(jobs);
	for (i = 0; i < ARRAY_SIZE(phbs); i++) {
		if (!phbs[i]) {
			jobs[i] = NULL;
			continue;
		}

		jobs[i] = __cpu_queue_job(NULL, phbs[i]->dt_node->name,
					  fn, phbs[i], false);
		assert(jobs[i]);

	}

	/* If no secondary CPUs, do everything sync */
	cpu_process_local_jobs();

	/* Wait until all tasks are done */
	for (i = 0; i < ARRAY_SIZE(phbs); i++) {
		if (!jobs[i])
			continue;

		cpu_wait_job(jobs[i], true);
	}
	free(jobs);
}

static void __pci_init_slots(void)
{
	unsigned int i;

	/* Some PHBs may need that long to debounce the presence detect
	 * after HW initialization.
	 */
	for (i = 0; i < ARRAY_SIZE(phbs); i++) {
		if (phbs[i]) {
			time_wait_ms(20);
			break;
		}
	}

	if (platform.pre_pci_fixup)
		platform.pre_pci_fixup();

	prlog(PR_NOTICE, "PCI: Resetting PHBs and training links...\n");
	pci_do_jobs(pci_reset_phb);

	prlog(PR_NOTICE, "PCI: Probing slots...\n");
	pci_do_jobs(pci_scan_phb);

	if (platform.pci_probe_complete)
		platform.pci_probe_complete();

	prlog(PR_NOTICE, "PCI Summary:\n");

	for (i = 0; i < ARRAY_SIZE(phbs); i++) {
		if (!phbs[i])
			continue;

		pci_add_device_nodes(phbs[i], &phbs[i]->devices,
				     phbs[i]->dt_node, &phbs[i]->lstate, 0);
	}

	/* PHB final fixup */
	for (i = 0; i < ARRAY_SIZE(phbs); i++) {
		if (!phbs[i] || !phbs[i]->ops || !phbs[i]->ops->phb_final_fixup)
			continue;

		phbs[i]->ops->phb_final_fixup(phbs[i]);
	}
}

static void __pci_reset(struct list_head *list)
{
	struct pci_device *pd;
	struct pci_cfg_reg_filter *pcrf;
	int i;

	while ((pd = list_pop(list, struct pci_device, link)) != NULL) {
		__pci_reset(&pd->children);
		dt_free(pd->dn);
		free(pd->slot);
		while((pcrf = list_pop(&pd->pcrf, struct pci_cfg_reg_filter, link)) != NULL) {
			free(pcrf);
		}
		for(i=0; i < 64; i++)
			if (pd->cap[i].free_func)
				pd->cap[i].free_func(pd->cap[i].data);
		free(pd);
	}
}

int64_t pci_reset(void)
{
	unsigned int i;

	prlog(PR_NOTICE, "PCI: Clearing all devices...\n");

	for (i = 0; i < ARRAY_SIZE(phbs); i++) {
		struct phb *phb = phbs[i];
		if (!phb)
			continue;
		__pci_reset(&phb->devices);

		pci_slot_set_state(phb->slot, PCI_SLOT_STATE_CRESET_START);
	}

	/* Do init and discovery of PCI slots in parallel */
	__pci_init_slots();

	return 0;
}

void pci_init_slots(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(phbs); i++) {
		struct phb *phb = phbs[i];
		if (!phb)
			continue;
		pci_slot_set_state(phb->slot, PCI_SLOT_STATE_FRESET_POWER_OFF);
	}
	__pci_init_slots();
}

/*
 * Complete iteration on current level before switching to
 * child level, which is the proper order for restoring
 * PCI bus range on bridges.
 */
static struct pci_device *__pci_walk_dev(struct phb *phb,
					 struct list_head *l,
					 int (*cb)(struct phb *,
						   struct pci_device *,
						   void *),
					 void *userdata)
{
	struct pci_device *pd, *child;

	if (list_empty(l))
		return NULL;

	list_for_each(l, pd, link) {
		if (cb && cb(phb, pd, userdata))
			return pd;
	}

	list_for_each(l, pd, link) {
		child = __pci_walk_dev(phb, &pd->children, cb, userdata);
		if (child)
			return child;
	}

	return NULL;
}

struct pci_device *pci_walk_dev(struct phb *phb,
				struct pci_device *pd,
				int (*cb)(struct phb *,
					  struct pci_device *,
					  void *),
				void *userdata)
{
	if (pd)
		return __pci_walk_dev(phb, &pd->children, cb, userdata);

	return __pci_walk_dev(phb, &phb->devices, cb, userdata);
}

static int __pci_find_dev(struct phb *phb,
			  struct pci_device *pd, void *userdata)
{
	uint16_t bdfn = *((uint16_t *)userdata);

	if (!phb || !pd)
		return 0;

	if (pd->bdfn == bdfn)
		return 1;

	return 0;
}

struct pci_device *pci_find_dev(struct phb *phb, uint16_t bdfn)
{
	return pci_walk_dev(phb, NULL, __pci_find_dev, &bdfn);
}

static int __pci_restore_bridge_buses(struct phb *phb,
				      struct pci_device *pd,
				      void *data __unused)
{
	uint32_t vdid;

	/* If the device is behind a switch, wait for the switch */
	if (!pd->is_vf && !(pd->bdfn & 7) && pd->parent != NULL &&
	    pd->parent->dev_type == PCIE_TYPE_SWITCH_DNPORT) {
		if (!pci_bridge_wait_link(phb, pd->parent, true)) {
			PCIERR(phb, pd->bdfn, "Timeout waiting for switch\n");
			return -1;
		}
	}

	/* Wait for config space to stop returning CRS */
	if (!pci_wait_crs(phb, pd->bdfn, &vdid))
		return -1;

	/* Make all devices below a bridge "re-capture" the bdfn */
	pci_cfg_write32(phb, pd->bdfn, PCI_CFG_VENDOR_ID, vdid);

	if (!pd->is_bridge)
		return 0;

	pci_cfg_write8(phb, pd->bdfn, PCI_CFG_PRIMARY_BUS,
		       pd->primary_bus);
	pci_cfg_write8(phb, pd->bdfn, PCI_CFG_SECONDARY_BUS,
		       pd->secondary_bus);
	pci_cfg_write8(phb, pd->bdfn, PCI_CFG_SUBORDINATE_BUS,
		       pd->subordinate_bus);
	return 0;
}

void pci_restore_bridge_buses(struct phb *phb, struct pci_device *pd)
{
	pci_walk_dev(phb, pd, __pci_restore_bridge_buses, NULL);
}

void pci_restore_slot_bus_configs(struct pci_slot *slot)
{
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

struct pci_cfg_reg_filter *pci_find_cfg_reg_filter(struct pci_device *pd,
						   uint32_t start, uint32_t len)
{
	struct pci_cfg_reg_filter *pcrf;

	/* Check on the cached range, which contains holes */
	if ((start + len) <= pd->pcrf_start ||
	    pd->pcrf_end <= start)
		return NULL;

	list_for_each(&pd->pcrf, pcrf, link) {
		if (start >= pcrf->start &&
		    (start + len) <= (pcrf->start + pcrf->len))
			return pcrf;
	}

	return NULL;
}

static bool pci_device_has_cfg_reg_filters(struct phb *phb, uint16_t bdfn)
{
       return bitmap_tst_bit(*phb->filter_map, bdfn);
}

int64_t pci_handle_cfg_filters(struct phb *phb, uint32_t bdfn,
			       uint32_t offset, uint32_t len,
			       uint32_t *data, bool write)
{
	struct pci_device *pd;
	struct pci_cfg_reg_filter *pcrf;
	uint32_t flags;

	if (!pci_device_has_cfg_reg_filters(phb, bdfn))
		return OPAL_PARTIAL;
	pd = pci_find_dev(phb, bdfn);
	pcrf = pd ? pci_find_cfg_reg_filter(pd, offset, len) : NULL;
	if (!pcrf || !pcrf->func)
		return OPAL_PARTIAL;

	flags = write ? PCI_REG_FLAG_WRITE : PCI_REG_FLAG_READ;
	if ((pcrf->flags & flags) != flags)
		return OPAL_PARTIAL;

	return pcrf->func(pd, pcrf, offset, len, data, write);
}

struct pci_cfg_reg_filter *pci_add_cfg_reg_filter(struct pci_device *pd,
						  uint32_t start, uint32_t len,
						  uint32_t flags,
						  pci_cfg_reg_func func)
{
	struct pci_cfg_reg_filter *pcrf;

	pcrf = pci_find_cfg_reg_filter(pd, start, len);
	if (pcrf)
		return pcrf;

	pcrf = zalloc(sizeof(*pcrf) + ((len + 0x4) & ~0x3));
	if (!pcrf)
		return NULL;

	/* Don't validate the flags so that the private flags
	 * can be supported for debugging purpose.
	 */
	pcrf->flags = flags;
	pcrf->start = start;
	pcrf->len = len;
	pcrf->func = func;
	pcrf->data = (uint8_t *)(pcrf + 1);

	if (start < pd->pcrf_start)
		pd->pcrf_start = start;
	if (pd->pcrf_end < (start + len))
		pd->pcrf_end = start + len;
	list_add_tail(&pd->pcrf, &pcrf->link);
	bitmap_set_bit(*pd->phb->filter_map, pd->bdfn);

	return pcrf;
}
